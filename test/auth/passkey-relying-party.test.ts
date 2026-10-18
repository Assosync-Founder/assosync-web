import { describe, expect, it, vi } from 'vitest';

vi.mock('server-only', () => {
	return {};
});

const { default: resolveProductPasskeyRelyingPartyId } = await import('@/lib/auth/passkey/passkey-relying-party');

describe('product passkey relying party', () => {
	it('uses app.localhost for a Calendis development ceremony', () => {
		expect(resolveProductPasskeyRelyingPartyId('development', 'http://app.localhost:3001', 'account.localhost')).toBe('app.localhost');
	});

	it('shares app.localhost with Collectineo on a different development port', () => {
		expect(resolveProductPasskeyRelyingPartyId('development', 'http://app.localhost:3002', 'account.localhost')).toBe('app.localhost');
	});

	it('preserves the Account RP ID outside development', () => {
		expect(resolveProductPasskeyRelyingPartyId('production', 'https://app.calendis.fr', 'account.assosync.fr')).toBe('account.assosync.fr');
	});
});
