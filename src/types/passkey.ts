import type { Rest } from '@assosync/firestore';
import type {
	AuthenticationResponseJSON,
	AuthenticatorTransport,
	CredentialDeviceType,
	PublicKeyCredentialCreationOptionsJSON,
	PublicKeyCredentialRequestOptionsJSON,
	RegistrationResponseJSON
} from '@simplewebauthn/server';

/** Exact relying-party values for one trusted Account WebAuthn origin. */
export type PasskeyRelyingParty = {
	/** WebAuthn relying-party identifier. */
	readonly id: string;

	/** WebAuthn relying-party origin. */
	readonly origin: string;
};

/** Persisted passkey owned by an Assosync account. */
export type Passkey = {
	/** Internal Firestore identifier. */
	readonly id: string;

	/** Firebase account owner. */
	readonly userId: string;

	/** WebAuthn credential identifier. */
	readonly credentialId: string;

	/** Base64url-encoded credential public key. */
	readonly publicKey: string;

	/** Stable WebAuthn user identifier. */
	readonly webauthnUserId: string;

	/** Authenticator signature counter. */
	readonly counter: number;

	/** Credential synchronization category. */
	readonly deviceType: CredentialDeviceType;

	/** Whether the credential is backed up. */
	readonly backedUp: boolean;

	/** Authenticator transports reported by the browser. */
	readonly transports: readonly AuthenticatorTransport[];

	/** Optional user-facing name. */
	readonly displayName: string | null;

	/** Last successful use. */
	readonly lastUsedAt: Date | null;

	/** Creation time. */
	readonly createdAt: Date;

	/** Last update time. */
	readonly updatedAt: Date;
};

/** Firestore representation of a passkey. */
export type StoredPasskey = Rest & {
	readonly userId: string;
	readonly credentialId: string;
	readonly publicKey: string;
	readonly webauthnUserId: string;
	readonly counter: number;
	readonly deviceType: CredentialDeviceType;
	readonly backedUp: boolean;
	readonly transports: readonly AuthenticatorTransport[];
	readonly displayName: string | null;
	readonly lastUsed: Date | null;
};

/** Temporary WebAuthn challenge purpose. */
export type PasskeyChallengePurpose = 'authentication' | 'registration';

/** Temporary browser-bound WebAuthn challenge. */
export type PasskeyChallenge = {
	readonly id: string;
	readonly purpose: PasskeyChallengePurpose;
	readonly challenge: string;
	readonly userId: string | null;
	readonly authorizationId: string | null;
	readonly browserTokenHash: string;
	readonly webauthnUserId: string | null;
	readonly expiresAt: Date;
};

/** Passkey persistence contract. */
export type PasskeyRepository = {
	readonly create: (
		passkey: Omit<Passkey, 'id' | 'createdAt' | 'updatedAt'>
	) => Promise<Passkey>;
	readonly listByUser: (userId: string) => Promise<readonly Passkey[]>;
	readonly findByCredentialIdGlobally: (
		credentialId: string
	) => Promise<Passkey | null>;
	readonly findById: (
		userId: string,
		passkeyId: string
	) => Promise<Passkey | null>;
	readonly updateDisplayName: (
		userId: string,
		passkeyId: string,
		displayName: string
	) => Promise<void>;
	readonly updateCounter: (
		userId: string,
		passkeyId: string,
		counter: number,
		lastUsedAt: Date
	) => Promise<void>;
	readonly delete: (
		userId: string,
		passkeyId: string
	) => Promise<void>;
};

/** Passkey metadata safe to expose in Account security settings. */
export type AccountPasskey = {
	/** Internal identifier used by future management actions. */
	readonly id: string;

	/** Optional user-facing passkey name. */
	readonly displayName: string | null;

	/** Whether the credential is local or synchronized. */
	readonly deviceType: CredentialDeviceType;

	/** Whether the authenticator reports a credential backup. */
	readonly backedUp: boolean;

	/** Last successful authentication time as an ISO string. */
	readonly lastUsedAt: string | null;

	/** Registration time as an ISO string. */
	readonly createdAt: string;
};

/** Redis persistence contract for one-time WebAuthn challenges. */
export type PasskeyChallengeRepository = {
	readonly create: (challenge: PasskeyChallenge) => Promise<void>;
	readonly consume: (
		id: string,
		browserTokenHash: string,
		purpose: PasskeyChallengePurpose,
		consumedAt: Date
	) => Promise<PasskeyChallenge | null>;
};

/** Generated registration options and their transaction identifier. */
export type IssuedPasskeyRegistrationOptions = {
	readonly challengeId: string;
	readonly options: PublicKeyCredentialCreationOptionsJSON;
};

/** Generated authentication options and their transaction identifier. */
export type IssuedPasskeyAuthenticationOptions = {
	readonly challengeId: string;
	readonly options: PublicKeyCredentialRequestOptionsJSON;
};

/** Input used to verify a passkey registration. */
export type VerifyPasskeyRegistrationInput = {
	readonly userId: string;
	readonly challengeId: string;
	readonly browserToken: string;
	readonly displayName: string;
	readonly response: RegistrationResponseJSON;
};

/** Input used to verify a passkey authentication. */
export type VerifyPasskeyAuthenticationInput = {
	readonly authorizationId: string;
	readonly challengeId: string;
	readonly browserToken: string;
	readonly response: AuthenticationResponseJSON;
};

/** Props for the Account passkey authentication view. */
export type PasskeyAuthenticationViewProps = {
	readonly authorizationId: string;

	/** Trusted product endpoint receiving failed passkey ceremonies. */
	readonly failureUri: string;
};

/** Props received by the Account passkey route. */
export type PasskeyPageProps = {
	readonly searchParams: Promise<
		Record<string, string | readonly string[] | undefined>
	>;
};

/** Next.js context supplied to one Account passkey route. */
export type PasskeyRouteContext = {
	/** Dynamic route parameters. */
	readonly params: Promise<{
		/** Passkey identifier extracted from the URL. */
		readonly passkeyId: string;
	}>;
};
