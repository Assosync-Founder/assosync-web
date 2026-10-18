import { type NextRequest, NextResponse } from 'next/server';
import { assertAccountHostname, createAuthErrorResponse, readJsonBody, readRequiredString } from '@/lib/auth/http/auth-http';
import { readPasskeyWebClient, resolvePasskeyWebRelyingParty } from '@/lib/auth/passkey/passkey-web-http';
import passkeyService from '@/lib/auth/passkey/passkey-server';
import webAuthorizationService from '@/lib/auth/web/authorization-server';

/** Starts a product-hosted passkey ceremony for a confidential Web client.
 * @param request - Authenticated server-to-server request.
 * @returns Server-bound authorization and public WebAuthn options.
 */
export const POST = async (request: NextRequest): Promise<Response> => {
	try {
		assertAccountHostname(request);

		const body = await readJsonBody(request);
		const client = readPasskeyWebClient(body);
		const relyingParty = resolvePasskeyWebRelyingParty(client);
		const issuedAuthorization = await webAuthorizationService.beginPasskey({
			applicationId: client.clientId,
			clientSecret: client.clientSecret,
			redirectUri: client.redirectUri,
			passkeyOrigin: client.passkeyOrigin,
			state: readRequiredString(body, 'state', 256),
			codeChallenge: readRequiredString(body, 'codeChallenge', 128)
		});
		const issuedPasskey = await passkeyService.createAuthenticationOptions(
			issuedAuthorization.request.id,
			issuedAuthorization.browserToken,
			relyingParty
		);

		return NextResponse.json(
			{
				authorizationId: issuedAuthorization.request.id,
				browserToken: issuedAuthorization.browserToken,
				challengeId: issuedPasskey.challengeId,
				options: issuedPasskey.options,
				expiresAt: issuedAuthorization.request.expiresAt.toISOString()
			},
			{ headers: { 'Cache-Control': 'no-store' } }
		);
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request, 'passkey_web_options');
	}
};
