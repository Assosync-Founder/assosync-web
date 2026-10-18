import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Clock, TokenGenerator, TokenHasher } from '@/types/auth';
import type { PasskeyChallenge, PasskeyChallengeRepository, PasskeyRepository } from '@/types/passkey';

vi.mock('server-only', () => {
	return {};
});

vi.mock('@simplewebauthn/server', () => {
	return {
		generateAuthenticationOptions: async () => {
			return { challenge: 'generated-challenge' };
		},
		generateRegistrationOptions: vi.fn(),
		verifyAuthenticationResponse: vi.fn(),
		verifyRegistrationResponse: vi.fn()
	};
});

const { default: PasskeyService } = await import('@/lib/auth/passkey/passkey-service');

const now = new Date('2026-10-18T12:00:00.000Z');
const clock: Clock = {
	now: () => {
		return now;
	}
};
const tokenGenerator: TokenGenerator = {
	generate: () => {
		return 'challenge-id';
	}
};
const hasher: TokenHasher = {
	hash: (value) => {
		return `hashed:${value}`;
	}
};
const passkeys: PasskeyRepository = {
	create: async () => {
		throw new Error('Unexpected passkey creation.');
	},
	listByUser: async () => {
		return [];
	},
	findByCredentialIdGlobally: async () => {
		return null;
	},
	findById: async () => {
		return null;
	},
	updateDisplayName: async () => {},
	updateCounter: async () => {},
	delete: async () => {}
};

let storedChallenge: PasskeyChallenge | null;

const challenges: PasskeyChallengeRepository = {
	create: async (challenge) => {
		storedChallenge = challenge;
	},
	consume: async (id, browserTokenHash, purpose, consumedAt) => {
		if (!storedChallenge || storedChallenge.id !== id || storedChallenge.browserTokenHash !== browserTokenHash || storedChallenge.purpose !== purpose || storedChallenge.expiresAt <= consumedAt) {
			return null;
		}

		const challenge = storedChallenge;

		storedChallenge = null;

		return challenge;
	}
};

beforeEach(() => {
	storedChallenge = null;
});

describe('PasskeyService relying-party binding', () => {
	it('rejects verification when the origin differs from the issued challenge', async () => {
		const service = new PasskeyService(passkeys, challenges, clock, tokenGenerator, hasher);

		await service.createAuthenticationOptions('authorization-id', 'browser-token', {
			id: 'account.assosync.fr',
			origin: 'https://app.calendis.fr'
		});

		await expect(service.verifyAuthentication(
			{
				authorizationId: 'authorization-id',
				challengeId: 'challenge-id',
				browserToken: 'browser-token',
				response: {
					id: 'credential-id',
					rawId: 'credential-id',
					type: 'public-key',
					clientExtensionResults: {},
					response: {
						clientDataJSON: 'client-data',
						authenticatorData: 'authenticator-data',
						signature: 'signature'
					}
				}
			},
			{
				id: 'account.assosync.fr',
				origin: 'https://app.collectineo.fr'
			}
		)).rejects.toMatchObject({ code: 'webauthn_challenge_invalid' });
	});
});
