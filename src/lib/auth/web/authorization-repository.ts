import 'server-only';

import type { Redis } from '@upstash/redis';
import { bindWebAuthorizationIdentityTokenScript, bindWebAuthorizationPasskeyUserScript, completeWebAuthorizationScript, consumeWebAuthorizationGrantScript, consumeWebAuthorizationHandoffScript, consumeWebAuthorizationIdentityTicketScript } from '@/lib/auth/web/authorization-scripts';
import type {
	StoredIssuedSession,
	StoredWebAuthorizationGrant,
	StoredWebAuthorizationHandoff,
	StoredWebAuthorizationIdentityTicket,
	StoredWebAuthorizationRequest,
	WebAuthorizationIdentity,
	WebAuthorizationRepository,
	WebAuthorizationRequest
} from '@/types/auth';

/** Determines whether an unknown value is a plain record.
 * @param value - Value to inspect.
 * @returns Whether the value is a string-keyed record.
 */
const isRecord = (value: unknown): value is Record<string, unknown> => {
	return (
		typeof value === 'object' &&
		value !== null &&
		!Array.isArray(value)
	);
};

/** Parses an ISO date.
 * @param value - ISO date string.
 * @returns A valid date.
 * @throws {TypeError} When the date is invalid.
 */
const parseDate = (value: string): Date => {
	const date = new Date(value);

	if (Number.isNaN(date.getTime())) {
		throw new TypeError('The stored Web authorization date is invalid.');
	}

	return date;
};

/** Converts a Web authorization request to its Redis representation.
 * @param request - Domain request.
 * @returns Serializable request.
 */
const toStoredRequest = (request: WebAuthorizationRequest): StoredWebAuthorizationRequest => {
	return {
		...request,
		createdAt: request.createdAt.toISOString(),
		expiresAt: request.expiresAt.toISOString()
	};
};

/**
 * Normalizes a JSON value returned by Redis.
 * @param value - Serialized or automatically deserialized Redis value.
 * @returns The normalized value.
 * @throws {SyntaxError} When a serialized value contains invalid JSON.
 */
const parseRedisJson = (value: unknown): unknown => {
	if (typeof value === 'string') {
		return JSON.parse(value);
	}

	return value;
};

/** Parses a Firebase identity stored in a temporary authorization value.
 * @param value - Unknown stored identity.
 * @returns Validated Firebase identity.
 * @throws {TypeError} When the identity is invalid.
 */
const parseIdentity = (value: unknown): WebAuthorizationIdentity => {
	if (!isRecord(value)) {
		throw new TypeError('The stored Web authorization identity is invalid.');
	}

	const { userId, idToken } = value;
	const normalizedIdToken = idToken === undefined &&
		typeof userId === 'string' &&
		userId
			? null
			: idToken;

	if ((userId !== null &&
			(typeof userId !== 'string' || !userId)) ||
		(normalizedIdToken !== null &&
			(typeof normalizedIdToken !== 'string' || !normalizedIdToken)) ||
		(normalizedIdToken !== null && userId === null)) {
		throw new TypeError('The stored Web authorization identity is invalid.');
	}

	return {
		userId,
		idToken: normalizedIdToken
	};
};

/** Parses and validates a stored Web authorization request.
 * @param value - Unknown Redis value.
 * @returns Validated request.
 * @throws {TypeError} When the value is invalid.
 */
const parseRequest = (value: unknown): WebAuthorizationRequest => {
	if (!isRecord(value)) {
		throw new TypeError('The stored Web authorization request is invalid.');
	}

	const {
		id,
		applicationId,
		redirectUri,
		state,
		codeChallenge,
		browserTokenHash,
		identity,
		createdAt,
		expiresAt
	} = value;

	if (typeof id !== 'string' ||
		!id ||
		(applicationId !== 'calendis' &&
			applicationId !== 'collectineo') ||
		typeof redirectUri !== 'string' ||
		!redirectUri ||
		typeof state !== 'string' ||
		!state ||
		typeof codeChallenge !== 'string' ||
		!codeChallenge ||
		typeof browserTokenHash !== 'string' ||
		!browserTokenHash ||
		typeof createdAt !== 'string' ||
		typeof expiresAt !== 'string') {
		throw new TypeError('The stored Web authorization request is invalid.');
	}

	return {
		id,
		applicationId,
		redirectUri,
		state,
		codeChallenge,
		browserTokenHash,
		identity: parseIdentity(identity),
		createdAt: parseDate(createdAt),
		expiresAt: parseDate(expiresAt)
	};
};

/** Parses a stored one-time identity handoff.
 * @param value - Serialized Redis value.
 * @returns Validated identity ticket.
 * @throws {TypeError} When the ticket is malformed.
 */
const parseIdentityTicket = (value: unknown): StoredWebAuthorizationIdentityTicket => {
	const parsed = parseRedisJson(value);

	if (!isRecord(parsed)) {
		throw new TypeError('The stored Web authorization identity ticket is invalid.');
	}

	const {
		ticketHash,
		applicationId,
		redirectUri,
		state,
		codeChallenge,
		identity,
		createdAt,
		expiresAt
	} = parsed;

	if (typeof ticketHash !== 'string' ||
		!ticketHash ||
		(applicationId !== 'calendis' && applicationId !== 'collectineo') ||
		typeof redirectUri !== 'string' ||
		!redirectUri ||
		typeof state !== 'string' ||
		!state ||
		typeof codeChallenge !== 'string' ||
		!codeChallenge ||
		typeof createdAt !== 'string' ||
		typeof expiresAt !== 'string') {
		throw new TypeError('The stored Web authorization identity ticket is invalid.');
	}

	parseDate(createdAt);
	parseDate(expiresAt);

	return {
		ticketHash,
		applicationId,
		redirectUri,
		state,
		codeChallenge,
		identity: parseIdentity(identity),
		createdAt,
		expiresAt
	};
};

/** Parses a stored one-time browser handoff.
 * @param value - Serialized Redis value.
 * @returns Validated browser handoff.
 * @throws {TypeError} When the handoff is malformed.
 */
const parseHandoff = (value: unknown): StoredWebAuthorizationHandoff => {
	const parsed = parseRedisJson(value);

	if (!isRecord(parsed)) {
		throw new TypeError('The stored Web authorization handoff is invalid.');
	}

	const { ticketHash, requestId, browserToken, expiresAt } = parsed;

	if (typeof ticketHash !== 'string' || !ticketHash || typeof requestId !== 'string' || !requestId || typeof browserToken !== 'string' || !browserToken || typeof expiresAt !== 'string') {
		throw new TypeError('The stored Web authorization handoff is invalid.');
	}

	parseDate(expiresAt);

	return {
		ticketHash,
		requestId,
		browserToken,
		expiresAt
	};
};

/** Parses stored one-time session credentials.
 * @param value - Unknown Redis value.
 * @returns Validated serializable session credentials.
 * @throws {TypeError} When the credentials are malformed.
 */
const parseIssuedSession = (value: unknown): StoredIssuedSession => {
	if (!isRecord(value) || !isRecord(value.session)) {
		throw new TypeError('The stored Web authorization session is invalid.');
	}

	const {
		id,
		tokenHash,
		userId,
		deviceId,
		applicationId,
		createdAt,
		expiresAt,
		lastSeenAt,
		revokedAt
	} = value.session;

	if (typeof id !== 'string' ||
		!id ||
		typeof tokenHash !== 'string' ||
		!tokenHash ||
		typeof userId !== 'string' ||
		!userId ||
		typeof deviceId !== 'string' ||
		!deviceId ||
		typeof applicationId !== 'string' ||
		!applicationId ||
		typeof createdAt !== 'string' ||
		typeof expiresAt !== 'string' ||
		typeof lastSeenAt !== 'string' ||
		(revokedAt !== null && typeof revokedAt !== 'string') ||
		typeof value.sessionToken !== 'string' ||
		!value.sessionToken ||
		typeof value.firebaseSessionCookie !== 'string' ||
		!value.firebaseSessionCookie) {
		throw new TypeError('The stored Web authorization session is invalid.');
	}

	parseDate(createdAt);
	parseDate(expiresAt);
	parseDate(lastSeenAt);

	if (revokedAt !== null) {
		parseDate(revokedAt);
	}

	return {
		session: {
			id,
			tokenHash,
			userId,
			deviceId,
			applicationId,
			createdAt,
			expiresAt,
			lastSeenAt,
			revokedAt
		},
		sessionToken: value.sessionToken,
		firebaseSessionCookie: value.firebaseSessionCookie
	};
};

/** Parses a stored Web authorization grant.
 * @param value - Serialized Redis value.
 * @returns Validated grant container.
 * @throws {TypeError} When the grant is malformed.
 */
const parseGrant = (value: unknown): StoredWebAuthorizationGrant => {
	const parsed = parseRedisJson(value);

	if (!isRecord(parsed)) {
		throw new TypeError('The stored Web authorization grant is invalid.');
	}

	const {
		applicationId,
		redirectUri,
		codeChallenge,
		state,
		issuedSession,
		createdAt,
		expiresAt
	} = parsed;

	if ((applicationId !== 'calendis' &&
			applicationId !== 'collectineo') ||
		typeof redirectUri !== 'string' ||
		!redirectUri ||
		typeof codeChallenge !== 'string' ||
		!codeChallenge ||
		typeof state !== 'string' ||
		!state ||
		typeof createdAt !== 'string' ||
		typeof expiresAt !== 'string') {
		throw new TypeError('The stored Web authorization grant is invalid.');
	}

	parseDate(createdAt);
	parseDate(expiresAt);

	return {
		applicationId,
		redirectUri,
		codeChallenge,
		state,
		issuedSession: parseIssuedSession(issuedSession),
		createdAt,
		expiresAt
	};
};

/** Encodes an opaque Redis key component.
 * @param value - Raw component.
 * @returns Encoded component.
 */
const encodeKeyPart = (value: string): string => {
	if (!value) {
		throw new TypeError('The Web authorization key component is required.');
	}

	return encodeURIComponent(value);
};

/** Creates the Redis repository used by the Web SSO bridge.
 * @param redis - Initialized Redis client.
 * @returns Web authorization repository.
 */
const createWebAuthorizationRepository = (redis: Redis): WebAuthorizationRepository => {
	const getRequestKey = (requestId: string): string => {
		return `auth:web:requests:${ encodeKeyPart(requestId) }`;
	};

	const getIdentityTicketKey = (ticketHash: string): string => {
		return `auth:web:identities:${ encodeKeyPart(ticketHash) }`;
	};

	const getHandoffKey = (ticketHash: string): string => {
		return `auth:web:handoffs:${ encodeKeyPart(ticketHash) }`;
	};

	const getGrantKey = (codeChallenge: string): string => {
		return `auth:web:grants:${ encodeKeyPart(codeChallenge) }`;
	};

	return {
		createIdentityTicket: async (ticket) => {
			const lifetimeMs = new Date(ticket.expiresAt).getTime() - Date.now();

			if (lifetimeMs <= 0) {
				throw new RangeError('Cannot persist an expired Web identity ticket.');
			}

			const result = await redis.set(getIdentityTicketKey(ticket.ticketHash), JSON.stringify(ticket), { px: lifetimeMs, nx: true });

			if (result !== 'OK') {
				throw new Error('The Web identity ticket already exists.');
			}
		},

		consumeIdentityTicket: async (input) => {
			const result = await redis.eval<string[], unknown>(consumeWebAuthorizationIdentityTicketScript, [getIdentityTicketKey(input.ticketHash)], [input.consumedAt]);

			return result ? parseIdentityTicket(result) : null;
		},

		createHandoff: async (handoff) => {
			const lifetimeMs = new Date(handoff.expiresAt).getTime() - Date.now();

			if (lifetimeMs <= 0) {
				throw new RangeError('Cannot persist an expired Web authorization handoff.');
			}

			const result = await redis.set(getHandoffKey(handoff.ticketHash), JSON.stringify(handoff), { px: lifetimeMs, nx: true });

			if (result !== 'OK') {
				throw new Error('The Web authorization handoff already exists.');
			}
		},

		consumeHandoff: async (input) => {
			const result = await redis.eval<string[], unknown>(consumeWebAuthorizationHandoffScript, [getHandoffKey(input.ticketHash)], [input.consumedAt]);

			return result ? parseHandoff(result) : null;
		},

		createRequest: async (request) => {
			const lifetimeMs = request.expiresAt.getTime() - Date.now();

			if (lifetimeMs <= 0) {
				throw new RangeError('Cannot persist an expired Web authorization request.');
			}

			const result = await redis.set(getRequestKey(request.id), JSON.stringify(toStoredRequest(request)), { px: lifetimeMs, nx: true });

			if (result !== 'OK') {
				throw new Error('The Web authorization request already exists.');
			}
		},

		findRequest: async (requestId, browserTokenHash, resolvedAt) => {
			const stored = await redis.get<unknown>(getRequestKey(requestId));

			if (!stored) {
				return null;
			}

			const request = parseRequest(stored);

			if (request.browserTokenHash !== browserTokenHash || request.expiresAt.getTime() <= resolvedAt.getTime()) {
				return null;
			}

			return request;
		},

		bindIdentityToken: async (requestId, browserTokenHash, userId, idToken, updatedAt) => {
			const result = await redis.eval<string[], number>(
				bindWebAuthorizationIdentityTokenScript,
				[getRequestKey(requestId)],
				[
					browserTokenHash,
					userId,
					idToken,
					updatedAt
				]
			);

			return result === 1;
		},

		bindPasskeyUser: async (requestId, browserTokenHash, userId, updatedAt) => {
			const result = await redis.eval<string[], number>(bindWebAuthorizationPasskeyUserScript, [getRequestKey(requestId)], [browserTokenHash, userId, updatedAt]);

			return result === 1;
		},

		completeRequest: async (input) => {
			const result = await redis.eval<string[], number>(
				completeWebAuthorizationScript,
				[
					getRequestKey(input.requestId),
					getGrantKey(input.grant.codeChallenge)
				],
				[
					input.browserTokenHash,
					input.completedAt,
					JSON.stringify(input.grant),
					input.grantLifetimeMs.toString()
				]
			);

			return result === 1;
		},

		consumeGrant: async (input) => {
			const result = await redis.eval<string[], unknown>(
				consumeWebAuthorizationGrantScript,
				[getGrantKey(input.codeChallenge)],
				[
					input.applicationId,
					input.redirectUri,
					input.codeChallenge,
					input.state,
					input.consumedAt
				]
			);

			return result ? parseGrant(result) : null;
		}
	};
};

export default createWebAuthorizationRepository;
