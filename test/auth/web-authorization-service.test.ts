import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Clock, StoredWebAuthorizationHandoff, TokenGenerator, TokenHasher, WebAuthorizationRepository, WebAuthorizationRequest, WebSsoServiceOptions } from '@/types/auth';

vi.mock('server-only', () => {
	return {};
});

const { default: WebAuthorizationService } = await import('@/lib/auth/web/authorization-service');

const now = new Date('2026-10-18T12:00:00.000Z');
const clock: Clock = {
	now: () => {
		return now;
	}
};
const hasher: TokenHasher = {
	hash: (value) => {
		return `hashed:${value}`;
	}
};
const options: WebSsoServiceOptions = {
	requestLifetimeMs: 10 * 60_000,
	codeLifetimeMs: 60_000,
	clients: [
		{
			id: 'calendis',
			loginUri: 'https://app.calendis.fr/login',
			authenticationFlashUri: 'https://app.calendis.fr/api/auth/flash',
			redirectUris: ['https://app.calendis.fr/api/auth/callback'],
			passkeyOrigins: ['https://app.calendis.fr'],
			clientSecret: 'c'.repeat(32)
		}
	]
};

let persistedRequest: WebAuthorizationRequest | null;
let persistedHandoff: StoredWebAuthorizationHandoff | null;

const repository: WebAuthorizationRepository = {
	createIdentityTicket: async () => {},
	consumeIdentityTicket: async () => {
		return null;
	},
	createHandoff: async (handoff) => {
		persistedHandoff = handoff;
	},
	consumeHandoff: async (input) => {
		if (!persistedHandoff || persistedHandoff.ticketHash !== input.ticketHash || persistedHandoff.expiresAt <= input.consumedAt) {
			return null;
		}

		const handoff = persistedHandoff;

		persistedHandoff = null;

		return handoff;
	},
	createRequest: async (request) => {
		persistedRequest = request;
	},
	findRequest: async (requestId, browserTokenHash, resolvedAt) => {
		if (!persistedRequest || persistedRequest.id !== requestId || persistedRequest.browserTokenHash !== browserTokenHash || persistedRequest.expiresAt <= resolvedAt) {
			return null;
		}

		return persistedRequest;
	},
	bindIdentityToken: async () => {
		return false;
	},
	bindPasskeyUser: async () => {
		return false;
	},
	completeRequest: async () => {
		return false;
	},
	consumeGrant: async () => {
		return null;
	}
};

beforeEach(() => {
	persistedRequest = null;
	persistedHandoff = null;
});

describe('WebAuthorizationService product-hosted passkeys', () => {
	it('binds a direct passkey authorization to the registered product origin', async () => {
		const values = ['browser-token', 'authorization-id'];
		const tokenGenerator: TokenGenerator = {
			generate: () => {
				return values.shift() ?? 'unexpected-token';
			}
		};
		const service = new WebAuthorizationService(repository, options, clock, tokenGenerator, hasher);

		const issued = await service.beginPasskey({
			applicationId: 'calendis',
			clientSecret: 'c'.repeat(32),
			redirectUri: 'https://app.calendis.fr/api/auth/callback',
			passkeyOrigin: 'https://app.calendis.fr',
			state: 'state',
			codeChallenge: 'a'.repeat(43)
		});

		expect(issued.passkeyOrigin).toBe('https://app.calendis.fr');
		expect(issued.browserToken).toBe('browser-token');
		expect(issued.request.id).toBe('authorization-id');
		expect(persistedRequest?.browserTokenHash).toBe('hashed:browser-token');
	});

	it('rejects an origin that is not registered for the confidential client', async () => {
		const tokenGenerator: TokenGenerator = {
			generate: () => {
				return 'unused-token';
			}
		};
		const service = new WebAuthorizationService(repository, options, clock, tokenGenerator, hasher);

		await expect(service.beginPasskey({
			applicationId: 'calendis',
			clientSecret: 'c'.repeat(32),
			redirectUri: 'https://app.calendis.fr/api/auth/callback',
			passkeyOrigin: 'https://attacker.example',
			state: 'state',
			codeChallenge: 'a'.repeat(43)
		})).rejects.toMatchObject({ code: 'authorization_invalid' });
	});

	it('transfers the server token through a single-use handoff', async () => {
		const values = ['browser-token', 'authorization-id', 'handoff-ticket'];
		const tokenGenerator: TokenGenerator = {
			generate: () => {
				return values.shift() ?? 'unexpected-token';
			}
		};
		const service = new WebAuthorizationService(repository, options, clock, tokenGenerator, hasher);
		const issued = await service.beginPasskey({
			applicationId: 'calendis',
			clientSecret: 'c'.repeat(32),
			redirectUri: 'https://app.calendis.fr/api/auth/callback',
			passkeyOrigin: 'https://app.calendis.fr',
			state: 'state',
			codeChallenge: 'a'.repeat(43)
		});

		const handoff = await service.issueHandoff(issued.request.id, issued.browserToken);
		const resumed = await service.consumeHandoff(handoff.ticket);

		expect(resumed.request.id).toBe(issued.request.id);
		expect(resumed.browserToken).toBe(issued.browserToken);
		await expect(service.consumeHandoff(handoff.ticket)).rejects.toMatchObject({ code: 'authorization_invalid' });
	});
});
