import { type NextRequest, NextResponse } from 'next/server';
import { assertAccountHostname, createAuthErrorResponse, readJsonBody, readRequiredString } from '@/lib/auth/http/auth-http';
import webAuthorizationService from '@/lib/auth/web/authorization-server';

/** Starts a confidential Web SSO flow whose primary proof is a passkey.
 * @param request - Server-to-server request from a registered product.
 * @returns Opaque identity ticket for the Account browser redirect.
 */
export const POST = async (request: NextRequest): Promise<Response> => {
	try {
		assertAccountHostname(request);

		const body = await readJsonBody(request);
		const applicationId = readRequiredString(body, 'clientId', 64);
		const clientSecret = readRequiredString(body, 'clientSecret', 512);
		const redirectUri = readRequiredString(body, 'redirectUri', 2_048);
		const state = readRequiredString(body, 'state', 256);
		const codeChallenge = readRequiredString(body, 'codeChallenge', 128);

		webAuthorizationService.authenticateClient(applicationId, redirectUri, clientSecret);

		const issued = await webAuthorizationService.issuePasskeyIdentityTicket({
			applicationId,
			clientSecret,
			redirectUri,
			state,
			codeChallenge
		});

		return NextResponse.json({ identityTicket: issued.ticket, expiresAt: issued.expiresAt.toISOString() }, { headers: { 'Cache-Control': 'no-store' } });
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request, 'passkey_web_identity');
	}
};
