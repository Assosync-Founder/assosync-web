import 'server-only';

/** Selects the RP ID used by one trusted product-hosted ceremony.
 * @param environment - Current deployment environment.
 * @param origin - Exact registered browser origin.
 * @param defaultRelyingPartyId - Account RP ID used outside local development.
 * @returns Product-local RP ID in development, otherwise the configured Account RP ID.
 */
const resolveProductPasskeyRelyingPartyId = (environment: string | undefined, origin: string, defaultRelyingPartyId: string): string => {
	const originUrl = new URL(origin);

	if (environment === 'development' && originUrl.hostname === 'app.localhost') {
		return 'app.localhost';
	}

	return defaultRelyingPartyId;
};

export default resolveProductPasskeyRelyingPartyId;
