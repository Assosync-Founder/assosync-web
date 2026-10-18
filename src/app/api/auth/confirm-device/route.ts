import { cookies } from 'next/headers';
import { NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import authenticationService from '@/lib/auth/authentication/authentication-server';
import { clearDeviceVerificationCookie, clearWebAuthorizationCookie, setSessionCookies } from '@/lib/auth/http/auth-cookies';
import {
	assertSameOrigin,
	AuthHttpError,
	createAuthErrorResponse,
	readAuthenticationIdentifier,
	readJsonBody,
	readOptionalString,
	readRequiredAuthCookie,
	readRequiredString
} from '@/lib/auth/http/auth-http';
import resolveAuthenticationRequestContext, { resolveAuthenticationIdToken } from '@/lib/auth/web/authorization-http';
import finalizeWebAuthorization from '@/lib/auth/web/authorization-finalization';

/** Confirms an email code and creates the authenticated session.
 * @param request - Incoming device confirmation request.
 * @returns The completed authentication result.
 */
export const POST = async (request: NextRequest): Promise<Response> => {
	try {
		assertSameOrigin(request);

		const cookieStore = await cookies();
		const body = await readJsonBody(request);

		const authorizationValue = readOptionalString(body, 'authorizationId', 128);
		const authorizationId = authorizationValue ? readAuthenticationIdentifier(authorizationValue) : null;

		const authenticationContext = await resolveAuthenticationRequestContext(request, authorizationId);
		const applicationId = authenticationContext.applicationId;
		const idToken = resolveAuthenticationIdToken(body, authenticationContext);
		const deviceId = readAuthenticationIdentifier(body.deviceId);
		const verificationId = readAuthenticationIdentifier(body.verificationId);
		const code = readRequiredString(body, 'code', 6);

		const deviceToken = cookieStore.get(authConfig.cookieNames.device)?.value;
		const browserToken = cookieStore.get(authConfig.cookieNames.deviceVerification)?.value;

		if (!deviceToken || !browserToken) {
			return createAuthErrorResponse(new AuthHttpError(400, 'verification_invalid'), request);
		}

		const issuedSession = await authenticationService.completeEmail({
			idToken,
			applicationId,
			deviceId,
			deviceToken,
			verificationId,
			browserToken,
			code
		});

		if (authenticationContext.webAuthorization) {
			const authorizationBrowserToken = readRequiredAuthCookie(cookieStore.get(authConfig.cookieNames.webAuthorization)?.value, 'authorization_invalid');
			const resolvedAuthorizationId = readAuthenticationIdentifier(authorizationId);

			const completed = await finalizeWebAuthorization({
				requestId: resolvedAuthorizationId,
				browserToken: authorizationBrowserToken,
				issuedSession,
				idToken,
				deviceToken
			});

			const response = NextResponse.json({ status: 'authorization_ready', redirectUri: completed.redirectUri });

			setSessionCookies(response, completed.accountSession);

			clearDeviceVerificationCookie(response);
			clearWebAuthorizationCookie(response);

			return response;
		}

		const response = NextResponse.json({
			status: 'session_ready',
			expiresAt: issuedSession.session.expiresAt.toISOString()
		});

		setSessionCookies(response, issuedSession);

		clearDeviceVerificationCookie(response);

		return response;
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request, 'confirm_device');
	}
};
