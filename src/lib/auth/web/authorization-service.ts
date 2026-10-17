import 'server-only';

import {
	createHash,
	timingSafeEqual
} from 'node:crypto';
import AuthError from '@/lib/auth/shared/auth-error';
import {
	secureTokenGenerator,
	sha256TokenHasher,
	systemClock
} from '@/lib/auth/shared/runtime-server';
import type {
	BeginWebAuthorizationInput,
	Clock,
	CompletedWebAuthorization,
	CompleteWebAuthorizationInput,
	ExchangeWebAuthorizationInput,
	IssuedSession,
	IssuedWebAuthorizationIdentityTicket,
	IssuedWebAuthorizationRequest,
	IssueWebAuthorizationIdentityInput,
	IssuePasskeyWebAuthorizationIdentityInput,
	StoredIssuedSession,
	TokenGenerator,
	TokenHasher,
	WebAuthorizationRepository,
	WebAuthorizationRequest,
	WebSsoClient,
	WebSsoServiceOptions
} from '@/types/auth';

const PKCE_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const PKCE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/u;
const MAXIMUM_STATE_LENGTH = 256;

/** Converts issued session credentials into their Redis representation.
 * @param issued - Issued application session.
 * @returns Serializable session credentials.
 */
const toStoredIssuedSession = (
	issued: IssuedSession
): StoredIssuedSession => {
	return {
		session: {
			...issued.session,
			createdAt: issued.session.createdAt.toISOString(),
			expiresAt: issued.session.expiresAt.toISOString(),
			lastSeenAt: issued.session.lastSeenAt.toISOString(),
			revokedAt:
				issued.session.revokedAt?.toISOString() ?? null
		},
		sessionToken: issued.sessionToken,
		firebaseSessionCookie: issued.firebaseSessionCookie
	};
};

/** Parses a valid ISO date.
 * @param value - ISO date value.
 * @returns Parsed date.
 * @throws {AuthError} When the value is invalid.
 */
const parseSessionDate = (
	value: string
): Date => {
	const date = new Date(value);

	if (Number.isNaN(date.getTime())) {
		throw new AuthError(
			'authorization_invalid',
			'The Web authorization session is invalid.'
		);
	}

	return date;
};

/** Converts stored session credentials into their domain representation.
 * @param stored - Stored session credentials.
 * @returns Issued application session.
 */
const fromStoredIssuedSession = (
	stored: StoredIssuedSession
): IssuedSession => {
	return {
		session: {
			...stored.session,
			createdAt: parseSessionDate(stored.session.createdAt),
			expiresAt: parseSessionDate(stored.session.expiresAt),
			lastSeenAt: parseSessionDate(stored.session.lastSeenAt),
			revokedAt: stored.session.revokedAt
				? parseSessionDate(stored.session.revokedAt)
				: null
		},
		sessionToken: stored.sessionToken,
		firebaseSessionCookie: stored.firebaseSessionCookie
	};
};

/** Derives an S256 PKCE challenge.
 * @param verifier - PKCE verifier.
 * @returns Base64url-encoded SHA-256 challenge.
 */
const createCodeChallenge = (
	verifier: string
): string => {
	return createHash('sha256')
		.update(verifier, 'ascii')
		.digest('base64url');
};

/** Compares two secrets without content-dependent timing.
 * @param actual - Untrusted supplied secret.
 * @param expected - Configured secret.
 * @returns Whether both secrets match.
 */
const secretsMatch = (
	actual: string,
	expected: string
): boolean => {
	const actualDigest = createHash('sha256')
		.update(actual, 'utf8')
		.digest();
	const expectedDigest = createHash('sha256')
		.update(expected, 'utf8')
		.digest();

	return timingSafeEqual(actualDigest, expectedDigest);
};

/** Coordinates browser authorization and confidential code exchange. */
class WebAuthorizationService {
	/** Creates the Web SSO service.
	 * @param repository - Temporary Redis persistence.
	 * @param options - Registered clients and lifetimes.
	 * @param clock - Current-time provider.
	 * @param tokenGenerator - Opaque token generator.
	 * @param tokenHasher - Secret hashing adapter.
	 */
	constructor(
		private readonly repository: WebAuthorizationRepository,
		private readonly options: WebSsoServiceOptions,
		private readonly clock: Clock = systemClock,
		private readonly tokenGenerator: TokenGenerator = secureTokenGenerator,
		private readonly tokenHasher: TokenHasher = sha256TokenHasher
	) {
		if (
			!Number.isSafeInteger(options.requestLifetimeMs) ||
			options.requestLifetimeMs <= 0 ||
			!Number.isSafeInteger(options.codeLifetimeMs) ||
			options.codeLifetimeMs <= 0
		) {
			throw new RangeError(
				'Web authorization lifetimes must be positive integers.'
			);
		}

		for (const client of options.clients) {
			if (
				client.clientSecret !== undefined &&
				Buffer.byteLength(client.clientSecret, 'utf8') < 32
			) {
				throw new TypeError(
					`The ${ client.id } Web SSO secret must contain at least 32 bytes.`
				);
			}
		}
	}

	/** Authenticates a confidential Web client before expensive identity work.
	 * @param applicationId - Registered Web client identifier.
	 * @param redirectUri - Exact registered callback URL.
	 * @param clientSecret - Supplied server-side client secret.
	 * @returns Nothing after successful client authentication.
	 */
	readonly authenticateClient = (
		applicationId: string,
		redirectUri: string,
		clientSecret: string
	): void => {
		this.resolveConfidentialClient(
			applicationId,
			redirectUri,
			clientSecret
		);
	};

	/** Creates a short-lived identity handoff for an authenticated Web client.
	 * @param input - Confidential client and verified Firebase identity.
	 * @returns An opaque single-use identity ticket.
	 */
	readonly issueIdentityTicket = async (
		input: IssueWebAuthorizationIdentityInput
	): Promise<IssuedWebAuthorizationIdentityTicket> => {
		const client = this.resolveConfidentialClient(
			input.applicationId,
			input.redirectUri,
			input.clientSecret
		);

		if (
			!input.idToken.trim() ||
			!input.userId.trim() ||
			!input.state ||
			input.state.length > MAXIMUM_STATE_LENGTH ||
			!PKCE_CHALLENGE_PATTERN.test(input.codeChallenge)
		) {
			throw new AuthError(
				'identity_invalid',
				'The Firebase identity is invalid.'
			);
		}

		const now = this.clock.now();
		const expiresAt = new Date(
			now.getTime() + this.options.requestLifetimeMs
		);
		const ticket = this.tokenGenerator.generate();
		const ticketHash = this.tokenHasher.hash(ticket);

		await this.repository.createIdentityTicket({
			ticketHash,
			applicationId: client.id,
			redirectUri: input.redirectUri,
			state: input.state,
			codeChallenge: input.codeChallenge,
			identity: {
				userId: input.userId,
				idToken: input.idToken
			},
			createdAt: now.toISOString(),
			expiresAt: expiresAt.toISOString()
		});

		return {
			ticket,
			expiresAt
		};
	};

	/** Creates a one-time handoff for a discoverable-passkey Web flow.
	 * @param input - Confidential client and PKCE transaction.
	 * @returns An opaque single-use identity ticket.
	 */
	readonly issuePasskeyIdentityTicket = async (
		input: IssuePasskeyWebAuthorizationIdentityInput
	): Promise<IssuedWebAuthorizationIdentityTicket> => {
		const client = this.resolveConfidentialClient(
			input.applicationId,
			input.redirectUri,
			input.clientSecret
		);

		if (
			!input.state ||
			input.state.length > MAXIMUM_STATE_LENGTH ||
			!PKCE_CHALLENGE_PATTERN.test(input.codeChallenge)
		) {
			throw new AuthError(
				'identity_invalid',
				'The passkey identity is invalid.'
			);
		}

		const now = this.clock.now();
		const expiresAt = new Date(
			now.getTime() + this.options.requestLifetimeMs
		);
		const ticket = this.tokenGenerator.generate();

		await this.repository.createIdentityTicket({
			ticketHash: this.tokenHasher.hash(ticket),
			applicationId: client.id,
			redirectUri: input.redirectUri,
			state: input.state,
			codeChallenge: input.codeChallenge,
			identity: {
				userId: null,
				idToken: null
			},
			createdAt: now.toISOString(),
			expiresAt: expiresAt.toISOString()
		});

		return { ticket, expiresAt };
	};

	/** Binds the account discovered after successful passkey verification.
	 * @param requestId - Active authorization request.
	 * @param browserToken - Raw browser continuation token.
	 * @param userId - Firebase user owning the verified passkey.
	 * @returns Nothing after the request is updated.
	 */
	readonly bindPasskeyUser = async (
		requestId: string,
		browserToken: string,
		userId: string
	): Promise<void> => {
		const updated = await this.repository.bindPasskeyUser(
			requestId,
			this.tokenHasher.hash(browserToken),
			userId,
			this.clock.now().toISOString()
		);

		if (!updated) {
			throw new AuthError(
				'authorization_invalid',
				'The passkey authorization is invalid or expired.'
			);
		}
	};

	/** Binds the Firebase token obtained after a verified passkey assertion.
	 * @param requestId - Active authorization request.
	 * @param browserToken - Raw browser continuation token.
	 * @param userId - Verified Firebase user identifier.
	 * @param idToken - Fresh Firebase ID token.
	 * @returns Nothing after the request is updated.
	 */
	readonly bindPasskeyIdentityToken = async (
		requestId: string,
		browserToken: string,
		userId: string,
		idToken: string
	): Promise<void> => {
		const updated = await this.repository.bindIdentityToken(
			requestId,
			this.tokenHasher.hash(browserToken),
			userId,
			idToken,
			this.clock.now().toISOString()
		);

		if (!updated) {
			throw new AuthError(
				'authorization_invalid',
				'The passkey authorization is invalid or expired.'
			);
		}
	};

	/** Begins a browser-bound Web authorization request.
	 * @param input - Validated public authorization parameters.
	 * @returns Issued request and browser continuation token.
	 */
	readonly begin = async (
		input: BeginWebAuthorizationInput
	): Promise<IssuedWebAuthorizationRequest> => {
		if (!input.identityTicket.trim()) {
			throw new AuthError(
				'authorization_invalid',
				'The Web authorization request is invalid.'
			);
		}

		const now = this.clock.now();
		const identityTicket =
			await this.repository.consumeIdentityTicket({
				ticketHash: this.tokenHasher.hash(
					input.identityTicket
				),
				consumedAt: now.toISOString()
			});

		if (!identityTicket) {
			throw new AuthError(
				'authorization_invalid',
				'The Web identity ticket is invalid or expired.'
			);
		}

		const client = this.resolveClient(
			identityTicket.applicationId,
			identityTicket.redirectUri
		);

		const browserToken = this.tokenGenerator.generate();
		const request: WebAuthorizationRequest = {
			id: this.tokenGenerator.generate(),
			applicationId: client.id,
			redirectUri: identityTicket.redirectUri,
			state: identityTicket.state,
			codeChallenge: identityTicket.codeChallenge,
			browserTokenHash: this.tokenHasher.hash(browserToken),
			identity: identityTicket.identity,
			createdAt: now,
			expiresAt: new Date(identityTicket.expiresAt)
		};

		await this.repository.createRequest(request);

		return {
			request,
			browserToken
		};
	};

	/** Resolves an active request bound to the Account browser.
	 * @param requestId - Opaque request identifier.
	 * @param browserToken - Raw continuation cookie.
	 * @returns Active authorization request.
	 * @throws {AuthError} When the request is absent or expired.
	 */
	readonly resolve = async (
		requestId: string,
		browserToken: string
	): Promise<WebAuthorizationRequest> => {
		const request = await this.repository.findRequest(
			requestId,
			this.tokenHasher.hash(browserToken),
			this.clock.now()
		);

		if (!request) {
			throw new AuthError(
				'authorization_invalid',
				'The Web authorization request is invalid or expired.'
			);
		}

		return request;
	};

	/** Finalizes authentication into a short-lived callback grant.
	 * @param input - Browser-bound request and issued application session.
	 * @returns The registered callback destination.
	 */
	readonly complete = async (
		input: CompleteWebAuthorizationInput
	): Promise<CompletedWebAuthorization> => {
		const request = await this.resolve(
			input.requestId,
			input.browserToken
		);

		if (
			input.issuedSession.session.applicationId !==
				request.applicationId ||
			input.issuedSession.session.userId !==
				request.identity.userId
		) {
			throw new AuthError(
				'authorization_invalid',
				'The application session does not match the authorization request.'
			);
		}

		const now = this.clock.now();
		const expiresAt = new Date(
			now.getTime() + this.options.codeLifetimeMs
		);

		const completed = await this.repository.completeRequest({
			requestId: request.id,
			browserTokenHash:
				this.tokenHasher.hash(input.browserToken),
			completedAt: now.toISOString(),
			grant: {
				applicationId: request.applicationId,
				redirectUri: request.redirectUri,
				codeChallenge: request.codeChallenge,
				state: request.state,
				issuedSession:
					toStoredIssuedSession(input.issuedSession),
				createdAt: now.toISOString(),
				expiresAt: expiresAt.toISOString()
			},
			grantLifetimeMs: this.options.codeLifetimeMs
		});

		if (!completed) {
			throw new AuthError(
				'authorization_invalid',
				'The Web authorization request could not be completed.'
			);
		}

		return {
			redirectUri: request.redirectUri
		};
	};

	/** Exchanges one callback grant from a confidential Web server.
	 * @param input - Client authentication, callback, state, and PKCE verifier.
	 * @returns One-time application session credentials.
	 */
	readonly exchange = async (
		input: ExchangeWebAuthorizationInput
	): Promise<IssuedSession> => {
		const client = this.resolveConfidentialClient(
			input.applicationId,
			input.redirectUri,
			input.clientSecret
		);

		if (!PKCE_VERIFIER_PATTERN.test(input.codeVerifier)) {
			throw new AuthError(
				'authorization_invalid',
				'The PKCE verifier is invalid.'
			);
		}

		const codeChallenge = createCodeChallenge(
			input.codeVerifier
		);
		const grant = await this.repository.consumeGrant({
			applicationId: client.id,
			redirectUri: input.redirectUri,
			codeChallenge,
			state: input.state,
			consumedAt: this.clock.now().toISOString()
		});

		if (!grant) {
			throw new AuthError(
				'authorization_invalid',
				'The Web authorization grant is invalid or expired.'
			);
		}

		return fromStoredIssuedSession(grant.issuedSession);
	};

	/** Resolves a registered client and exact callback URI.
	 * @param applicationId - Requested client identifier.
	 * @param redirectUri - Requested callback URL.
	 * @returns Matching client.
	 * @throws {AuthError} When the client or callback is not registered.
	 */
	private readonly resolveClient = (
		applicationId: string,
		redirectUri: string
	): WebSsoClient => {
		const client = this.options.clients.find((candidate) => {
			return candidate.id === applicationId;
		});

		if (
			!client ||
			!client.redirectUris.includes(redirectUri)
		) {
			throw new AuthError(
				'authorization_invalid',
				'The Web client or callback URI is invalid.'
			);
		}

		return client;
	};

	/** Resolves and authenticates a confidential Web client.
	 * @param applicationId - Requested client identifier.
	 * @param redirectUri - Requested callback URL.
	 * @param clientSecret - Supplied server-side secret.
	 * @returns Authenticated client.
	 * @throws {AuthError} When the client authentication is invalid.
	 */
	private readonly resolveConfidentialClient = (
		applicationId: string,
		redirectUri: string,
		clientSecret: string
	): WebSsoClient => {
		const client = this.resolveClient(
			applicationId,
			redirectUri
		);

		if (
			!client.clientSecret ||
			!secretsMatch(clientSecret, client.clientSecret)
		) {
			throw new AuthError(
				'client_invalid',
				'The Web client authentication is invalid.'
			);
		}

		return client;
	};
}

export default WebAuthorizationService;
