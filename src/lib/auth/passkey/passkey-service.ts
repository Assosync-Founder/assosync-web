import 'server-only';

import {
	generateAuthenticationOptions,
	generateRegistrationOptions,
	verifyAuthenticationResponse,
	verifyRegistrationResponse
} from '@simplewebauthn/server';
import authConfig from '@/config/auth';
import AuthError from '@/lib/auth/shared/auth-error';
import {
	secureTokenGenerator,
	sha256TokenHasher,
	systemClock
} from '@/lib/auth/shared/runtime-server';
import type {
	Clock,
	TokenGenerator,
	TokenHasher
} from '@/types/auth';
import type {
	AccountPasskey,
	IssuedPasskeyAuthenticationOptions,
	IssuedPasskeyRegistrationOptions,
	Passkey,
	PasskeyChallengeRepository,
	PasskeyRepository,
	PasskeyRelyingParty,
	VerifyPasskeyAuthenticationInput,
	VerifyPasskeyRegistrationInput
} from '@/types/passkey';

const isAuthenticatorTransport = (
	value: string
): value is 'ble' | 'hybrid' | 'internal' | 'nfc' | 'usb' => {
	return (
		value === 'ble' ||
		value === 'hybrid' ||
		value === 'internal' ||
		value === 'nfc' ||
		value === 'usb'
	);
};

const toAccountPasskey = (passkey: Passkey): AccountPasskey => {
	return {
		id: passkey.id,
		displayName: passkey.displayName,
		deviceType: passkey.deviceType,
		backedUp: passkey.backedUp,
		lastUsedAt: passkey.lastUsedAt?.toISOString() ?? null,
		createdAt: passkey.createdAt.toISOString()
	};
};

/** Coordinates WebAuthn registration and authentication. */
class PasskeyService {
	/** Creates the passkey service.
	 * @param passkeys - Persistent credential repository.
	 * @param challenges - One-time challenge repository.
	 * @param clock - Current-time provider.
	 * @param tokens - Secure token generator.
	 * @param hasher - Browser-token hashing adapter.
	 */
	constructor(
		private readonly passkeys: PasskeyRepository,
		private readonly challenges: PasskeyChallengeRepository,
		private readonly clock: Clock = systemClock,
		private readonly tokens: TokenGenerator = secureTokenGenerator,
		private readonly hasher: TokenHasher = sha256TokenHasher
	) {}

	/** Lists public passkey metadata for Account security settings.
	 * @param userId - Firebase account owner.
	 * @returns Passkeys without credential identifiers or public keys.
	 */
	readonly list = async (
		userId: string
	): Promise<readonly AccountPasskey[]> => {
		const passkeys = await this.passkeys.listByUser(userId);

		return passkeys.map(toAccountPasskey);
	};

	/** Renames an account-owned passkey.
	 * @param userId - Firebase account owner.
	 * @param passkeyId - Passkey document identifier.
	 * @param displayName - New user-facing name.
	 * @returns Updated public passkey metadata.
	 * @throws {AuthError} When the passkey does not belong to the account.
	 */
	readonly rename = async (
		userId: string,
		passkeyId: string,
		displayName: string
	): Promise<AccountPasskey> => {
		const passkey = await this.passkeys.findById(userId, passkeyId);

		if (!passkey) {
			throw new AuthError(
				'webauthn_credential_invalid',
				'The passkey credential is invalid.'
			);
		}

		await this.passkeys.updateDisplayName(
			userId,
			passkeyId,
			displayName
		);

		return toAccountPasskey({
			...passkey,
			displayName
		});
	};

	/** Deletes an account-owned passkey.
	 * @param userId - Firebase account owner.
	 * @param passkeyId - Passkey document identifier.
	 * @returns A promise resolved after permanent deletion.
	 * @throws {AuthError} When the passkey does not belong to the account.
	 */
	readonly delete = async (
		userId: string,
		passkeyId: string
	): Promise<void> => {
		const passkey = await this.passkeys.findById(userId, passkeyId);

		if (!passkey) {
			throw new AuthError(
				'webauthn_credential_invalid',
				'The passkey credential is invalid.'
			);
		}

		await this.passkeys.delete(userId, passkeyId);
	};

	/** Generates passkey registration options for an authenticated account.
	 * @param userId - Firebase user identifier.
	 * @param email - Verified account email.
	 * @param browserToken - Current authenticated session token.
	 * @param relyingParty - Exact trusted WebAuthn relying party.
	 * @returns Registration options and one-time challenge identifier.
	 */
	readonly createRegistrationOptions = async (
		userId: string,
		email: string,
		browserToken: string,
		relyingParty: PasskeyRelyingParty
	): Promise<IssuedPasskeyRegistrationOptions> => {
		const existing = await this.passkeys.listByUser(userId);
		const webauthnUserId = existing[0]?.webauthnUserId ??
			this.tokens.generate();
		const options = await generateRegistrationOptions({
			rpName: authConfig.passkey.rpName,
			rpID: relyingParty.id,
			userName: email,
			userID: Buffer.from(webauthnUserId, 'base64url'),
			attestationType: 'none',
			excludeCredentials: existing.map((passkey) => ({
				id: passkey.credentialId,
				transports: [...passkey.transports]
			})),
			authenticatorSelection: {
				authenticatorAttachment: 'platform',
				residentKey: 'required',
				requireResidentKey: true,
				userVerification: 'required'
			},
			preferredAuthenticatorType: 'localDevice'
		});
		const challengeId = this.tokens.generate();

		await this.challenges.create({
			id: challengeId,
			purpose: 'registration',
			challenge: options.challenge,
			userId,
			authorizationId: null,
			browserTokenHash: this.hasher.hash(browserToken),
			webauthnUserId,
			expiresAt: this.expiresAt()
		});

		return { challengeId, options };
	};

	/** Verifies and persists a new passkey.
	 * @param input - Browser response and account binding.
	 * @param relyingParty - Exact trusted WebAuthn relying party.
	 * @returns The persisted credential.
	 */
	readonly verifyRegistration = async (
		input: VerifyPasskeyRegistrationInput,
		relyingParty: PasskeyRelyingParty
	) => {
		const challenge = await this.challenges.consume(
			input.challengeId,
			this.hasher.hash(input.browserToken),
			'registration',
			this.clock.now()
		);

		if (
			!challenge ||
			challenge.userId !== input.userId ||
			!challenge.webauthnUserId
		) {
			throw new AuthError(
				'webauthn_challenge_invalid',
				'The passkey registration challenge is invalid.'
			);
		}

		const verification = await verifyRegistrationResponse({
			response: input.response,
			expectedChallenge: challenge.challenge,
			expectedOrigin: relyingParty.origin,
			expectedRPID: relyingParty.id,
			requireUserVerification: true
		});

		if (!verification.verified || !verification.registrationInfo) {
			throw new AuthError(
				'webauthn_credential_invalid',
				'The passkey registration response is invalid.'
			);
		}

		const info = verification.registrationInfo;
		const duplicate = await this.passkeys.findByCredentialIdGlobally(
			info.credential.id
		);

		if (duplicate) {
			throw new AuthError(
				'webauthn_credential_invalid',
				'The passkey is already registered.'
			);
		}

		return this.passkeys.create({
			userId: input.userId,
			credentialId: info.credential.id,
			publicKey: Buffer.from(info.credential.publicKey).toString('base64url'),
			webauthnUserId: challenge.webauthnUserId,
			counter: info.credential.counter,
			deviceType: info.credentialDeviceType,
			backedUp: info.credentialBackedUp,
			transports: (info.credential.transports ?? [])
				.filter(isAuthenticatorTransport),
			displayName: input.displayName,
			lastUsedAt: null
		});
	};

	/** Generates discoverable authentication options for a browser-bound SSO request.
	 * @param authorizationId - Active Web authorization identifier.
	 * @param browserToken - Web authorization browser token.
	 * @param relyingParty - Exact trusted WebAuthn relying party.
	 * @returns Authentication options and challenge identifier.
	 */
	readonly createAuthenticationOptions = async (
		authorizationId: string,
		browserToken: string,
		relyingParty: PasskeyRelyingParty
	): Promise<IssuedPasskeyAuthenticationOptions> => {
		const options = await generateAuthenticationOptions({
			rpID: relyingParty.id,
			userVerification: 'required'
		});
		const challengeId = this.tokens.generate();

		await this.challenges.create({
			id: challengeId,
			purpose: 'authentication',
			challenge: options.challenge,
			userId: null,
			authorizationId,
			browserTokenHash: this.hasher.hash(browserToken),
			webauthnUserId: null,
			expiresAt: this.expiresAt()
		});

		return { challengeId, options };
	};

	/** Verifies a passkey assertion and updates its signature counter.
	 * @param input - Browser assertion and authorization binding.
	 * @param relyingParty - Exact trusted WebAuthn relying party.
	 * @returns Verified Firebase user identifier.
	 */
	readonly verifyAuthentication = async (
		input: VerifyPasskeyAuthenticationInput,
		relyingParty: PasskeyRelyingParty
	): Promise<string> => {
		const challenge = await this.challenges.consume(
			input.challengeId,
			this.hasher.hash(input.browserToken),
			'authentication',
			this.clock.now()
		);

		if (
			!challenge ||
			challenge.authorizationId !== input.authorizationId
		) {
			throw new AuthError(
				'webauthn_challenge_invalid',
				'The passkey authentication challenge is invalid.'
			);
		}

		const passkey = await this.passkeys.findByCredentialIdGlobally(
			input.response.id
		);

		if (!passkey) {
			throw new AuthError(
				'webauthn_credential_invalid',
				'The passkey credential is invalid.'
			);
		}

		const verification = await verifyAuthenticationResponse({
			response: input.response,
			expectedChallenge: challenge.challenge,
			expectedOrigin: relyingParty.origin,
			expectedRPID: relyingParty.id,
			requireUserVerification: true,
			credential: {
				id: passkey.credentialId,
				publicKey: new Uint8Array(
					Buffer.from(passkey.publicKey, 'base64url')
				),
				counter: passkey.counter,
				transports: [...passkey.transports]
			}
		});

		if (!verification.verified) {
			throw new AuthError(
				'webauthn_credential_invalid',
				'The passkey assertion is invalid.'
			);
		}

		await this.passkeys.updateCounter(
			passkey.userId,
			passkey.id,
			verification.authenticationInfo.newCounter,
			this.clock.now()
		);

		return passkey.userId;
	};

	private readonly expiresAt = (): Date => {
		return new Date(
			this.clock.now().getTime() + authConfig.passkey.challengeLifetimeMs
		);
	};
}

export default PasskeyService;
