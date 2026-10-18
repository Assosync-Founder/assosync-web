import 'server-only';

import { createHash, randomBytes } from 'node:crypto';
import redis from '@/services/redis/redis.server';
import type { WebSsoClient } from '@/types/auth';

const FLASH_TICKET_LIFETIME_MILLISECONDS = 60_000;

const MAXIMUM_FLASH_TICKET_LIFETIME_MILLISECONDS = 5 * 60_000;

/** Creates an opaque single-use browser redirect ticket. */
const createTicket = (): string => {
	return randomBytes(32).toString('base64url');
};

/** Hashes an opaque ticket before persistence. */
const createTicketHash = (ticket: string): string => {
	return createHash('sha256')
		.update(ticket, 'utf8')
		.digest('base64url');
};

/** Creates the Redis key used by a temporary product flash relay. */
const createRedisKey = (ticket: string): string => {
	return `auth:web:flash:${ createTicketHash(ticket) }`;
};

/** Creates a one-time product flash endpoint URL.
 * @param client - Trusted target product client.
 * @param flashCode - Product error code to display after redirection.
 * @param lifetimeMs - Lifetime of the opaque ticket in milliseconds.
 * @param authenticationFlashUri - Trusted product flash endpoint for this authorization.
 * @returns Opaque product endpoint URL.
 * @throws When the lifetime is invalid or Redis cannot persist the one-time ticket.
 */
const createAuthenticationFlashRelayUri = async (client: WebSsoClient, flashCode: string, lifetimeMs = FLASH_TICKET_LIFETIME_MILLISECONDS, authenticationFlashUri = client.authenticationFlashUri): Promise<string> => {
	if (!Number.isSafeInteger(lifetimeMs) || lifetimeMs <= 0 || lifetimeMs > MAXIMUM_FLASH_TICKET_LIFETIME_MILLISECONDS) {
		throw new TypeError('The authentication flash ticket lifetime is invalid.');
	}

	const ticket = createTicket();

	const result = await redis.set(
		createRedisKey(ticket),
		JSON.stringify({
			applicationId: client.id,
			flashCode
		}),
		{
			px: lifetimeMs,
			nx: true
		}
	);

	if (result !== 'OK') {
		throw new Error('The authentication flash relay could not be created.');
	}

	return new URL(ticket, `${ authenticationFlashUri }/`).toString();
};

export default createAuthenticationFlashRelayUri;
