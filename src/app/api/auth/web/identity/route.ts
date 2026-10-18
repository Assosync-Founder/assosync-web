import { type NextRequest, NextResponse } from 'next/server';
import authenticationService from '@/lib/auth/authentication/authentication-server';
import { assertAccountHostname, createAuthErrorResponse, readJsonBody, readRequiredString } from '@/lib/auth/http/auth-http';
import webAuthorizationService from '@/lib/auth/web/authorization-server';

/** Creates a one-time identity handoff for a confidential Web application.
 * @param request - Server-to-server request containing a Firebase ID token.
 * @returns The opaque ticket required by the browser authorization redirect.
 */
export const POST = async (request: NextRequest): Promise<Response> => {
	try {
		assertAccountHostname(request);

		const body = await readJsonBody(request);
		const applicationId = readRequiredString(body, 'clientId', 64);
		const clientSecret = readRequiredString(body, 'clientSecret', 512);
		const redirectUri = readRequiredString(body, 'redirectUri', 2_048);
		const idToken = readRequiredString(body, 'idToken');
		const state = readRequiredString(body, 'state', 256);
		const codeChallenge = readRequiredString(body, 'codeChallenge', 128);

		webAuthorizationService.authenticateClient(applicationId, redirectUri, clientSecret);

		const identity = await authenticationService.verifyIdentity(idToken);

		const issued = await webAuthorizationService.issueIdentityTicket({
				applicationId,
				clientSecret,
				redirectUri,
				state,
				codeChallenge,
				idToken,
				userId: identity.userId
			});

		return NextResponse.json(
			{
				identityTicket: issued.ticket,
				expiresAt: issued.expiresAt.toISOString()
			},
			{
				headers: { 'Cache-Control': 'no-store' }
			}
		);
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};
