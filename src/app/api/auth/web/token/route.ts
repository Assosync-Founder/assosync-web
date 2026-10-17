import { type NextRequest, NextResponse } from 'next/server';
import {
	assertAccountHostname,
	createAuthErrorResponse,
	readJsonBody,
	readRequiredString
} from '@/lib/auth/http/auth-http';
import webAuthorizationService from '@/lib/auth/web/authorization-server';

/** Exchanges a completed authorization from a confidential Web server.
 * @param request - Server-to-server exchange request.
 * @returns One-time application session credentials.
 */
export const POST = async (
	request: NextRequest
): Promise<Response> => {
	try {
		assertAccountHostname(request);

		const body = await readJsonBody(request);
		const issuedSession =
			await webAuthorizationService.exchange({
				applicationId: readRequiredString(
					body,
					'clientId',
					64
				),
				clientSecret: readRequiredString(
					body,
					'clientSecret',
					512
				),
				codeVerifier: readRequiredString(
					body,
					'codeVerifier',
					128
				),
				state: readRequiredString(
					body,
					'state',
					256
				),
				redirectUri: readRequiredString(
					body,
					'redirectUri',
					2_048
				)
			});

		return NextResponse.json(
			{
				firebaseSessionCookie:
					issuedSession.firebaseSessionCookie,
				sessionToken: issuedSession.sessionToken,
				expiresAt:
					issuedSession.session.expiresAt.toISOString()
			},
			{
				headers: {
					'Cache-Control': 'no-store'
				}
			}
		);
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};
