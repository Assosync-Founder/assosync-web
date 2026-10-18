import 'server-only';

import authConfig from '@/config/auth';
import Env from '@/config/env';
import { AuthHttpError, readAuthenticationIdentifier, readRequiredString } from '@/lib/auth/http/auth-http';
import resolveProductPasskeyRelyingPartyId from '@/lib/auth/passkey/passkey-relying-party';
import webAuthorizationService from '@/lib/auth/web/authorization-server';
import type { PasskeyRelyingParty, PasskeyWebAuthorizationContext, PasskeyWebClientInput } from '@/types/passkey';

/** Reads confidential passkey client credentials from a validated JSON body.
 * @param body - Validated request body.
 * @returns Parsed client credentials and exact browser origin.
 */
const readPasskeyWebClient = (body: Record<string, unknown>): PasskeyWebClientInput => {
	return {
		clientId: readRequiredString(body, 'clientId', 64),
		clientSecret: readRequiredString(body, 'clientSecret', 512),
		redirectUri: readRequiredString(body, 'redirectUri', 2_048),
		passkeyOrigin: readRequiredString(body, 'passkeyOrigin', 2_048)
	};
};

/** Authenticates a product client and resolves its exact WebAuthn scope.
 * @param client - Confidential client fields read from the request.
 * @returns Trusted RP ID and browser origin.
 */
const resolvePasskeyWebRelyingParty = (client: PasskeyWebClientInput): PasskeyRelyingParty => {
	const origin = webAuthorizationService.authenticatePasskeyClient(client.clientId, client.redirectUri, client.clientSecret, client.passkeyOrigin);
	const relyingPartyId = resolveProductPasskeyRelyingPartyId(Env.public.environment, origin, authConfig.passkey.rpId);

	return {
		id: relyingPartyId,
		origin
	};
};

/** Resolves a server-bound passkey authorization and its trusted relying party.
 * @param body - Validated request body.
 * @returns Authenticated client and active authorization context.
 */
const resolvePasskeyWebAuthorization = async (body: Record<string, unknown>): Promise<PasskeyWebAuthorizationContext> => {
	const client = readPasskeyWebClient(body);
	const relyingParty = resolvePasskeyWebRelyingParty(client);
	const authorizationId = readAuthenticationIdentifier(body.authorizationId);
	const browserToken = readRequiredString(body, 'browserToken', 512);
	const authorization = await webAuthorizationService.resolve(authorizationId, browserToken);

	if (authorization.applicationId !== client.clientId || authorization.redirectUri !== client.redirectUri) {
		throw new AuthHttpError(400, 'authorization_invalid');
	}

	return {
		client,
		authorizationId,
		browserToken,
		authorization,
		relyingParty
	};
};

export { readPasskeyWebClient, resolvePasskeyWebAuthorization, resolvePasskeyWebRelyingParty };
