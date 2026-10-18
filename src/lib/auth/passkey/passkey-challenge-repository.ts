import 'server-only';

import type { Redis } from '@upstash/redis';
import type { PasskeyChallenge, PasskeyChallengeRepository, PasskeyChallengePurpose } from '@/types/passkey';

const parseChallenge = (value: unknown): PasskeyChallenge | null => {
	if (typeof value !== 'object' || value === null) {
		return null;
	}

	const record: Record<string, unknown> = Object.fromEntries(Object.entries(value));
	const purpose = record.purpose;
	const expiresAt = typeof record.expiresAt === 'string'
		? new Date(record.expiresAt)
		: null;

	if (typeof record.id !== 'string' ||
		(purpose !== 'authentication' && purpose !== 'registration') ||
		typeof record.challenge !== 'string' ||
		typeof record.relyingPartyId !== 'string' ||
		typeof record.relyingPartyOrigin !== 'string' ||
		(record.userId !== null &&
			typeof record.userId !== 'string') ||
		(record.authorizationId !== null &&
			typeof record.authorizationId !== 'string') ||
		typeof record.browserTokenHash !== 'string' ||
		(record.webauthnUserId !== null &&
			typeof record.webauthnUserId !== 'string') ||
		!expiresAt ||
		Number.isNaN(expiresAt.getTime())) {
		return null;
	}

	return {
		id: record.id,
		purpose,
		challenge: record.challenge,
		relyingPartyId: record.relyingPartyId,
		relyingPartyOrigin: record.relyingPartyOrigin,
		userId: record.userId,
		authorizationId: record.authorizationId,
		browserTokenHash: record.browserTokenHash,
		webauthnUserId: record.webauthnUserId,
		expiresAt
	};
};

/** Creates the Redis-backed one-time WebAuthn challenge repository.
 * @param redis - Shared Redis client.
 * @returns Challenge persistence contract.
 */
const createPasskeyChallengeRepository = (redis: Redis): PasskeyChallengeRepository => {
	const getKey = (purpose: PasskeyChallengePurpose, id: string): string => {
		return `auth:passkey:${purpose}:${encodeURIComponent(id)}`;
	};

	return {
		create: async (challenge) => {
			const lifetimeMs = challenge.expiresAt.getTime() - Date.now();

			if (lifetimeMs <= 0) {
				throw new RangeError('Cannot persist an expired passkey challenge.');
			}

			const result = await redis.set(
				getKey(challenge.purpose, challenge.id),
				JSON.stringify({
					...challenge,
					expiresAt: challenge.expiresAt.toISOString()
				}),
				{ px: lifetimeMs, nx: true }
			);

			if (result !== 'OK') {
				throw new Error('The passkey challenge already exists.');
			}
		},
		consume: async (id, browserTokenHash, purpose, consumedAt) => {
			const stored = await redis.getdel<unknown>(getKey(purpose, id));
			const challenge = parseChallenge(stored);

			if (!challenge || challenge.browserTokenHash !== browserTokenHash || challenge.expiresAt.getTime() <= consumedAt.getTime()) {
				return null;
			}

			return challenge;
		}
	};
};

export default createPasskeyChallengeRepository;
