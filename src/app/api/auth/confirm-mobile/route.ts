import { cookies } from 'next/headers';
import { type NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import authenticationService from '@/lib/auth/authentication/authentication-server';
import {
	clearDeviceVerificationCookie,
	setSessionCookies
} from '@/lib/auth/http/auth-cookies';
import {
	assertSameOrigin,
	createAuthErrorResponse,
	readAuthenticationIdentifier,
	readJsonBody,
	readRequiredAuthCookie,
	readRequiredString,
	resolveApplicationId
} from '@/lib/auth/http/auth-http';

/** Completes an approved mobile verification and creates the browser session.
 * @param request - Incoming browser polling request.
 * @returns The completed session or a stable pending/rejected error.
 */
export const POST = async (
	request: NextRequest
): Promise<Response> => {
	try {
		assertSameOrigin(request);

		const cookieStore = await cookies();
		const applicationId = resolveApplicationId(request);
		const body = await readJsonBody(request);
		const idToken = readRequiredString(body, 'idToken');
		const deviceId = readAuthenticationIdentifier(
			body.deviceId
		);

		const verificationId = readAuthenticationIdentifier(
			body.verificationId
		);

		const deviceToken = readRequiredAuthCookie(
			cookieStore.get(
				authConfig.cookieNames.device
			)?.value,
			'verification_invalid'
		);

		const browserToken = readRequiredAuthCookie(
			cookieStore.get(
				authConfig.cookieNames.deviceVerification
			)?.value,
			'verification_invalid'
		);

		const issuedSession = await authenticationService.completeMobile({
			idToken,
			applicationId,
			deviceId,
			deviceToken,
			verificationId,
			browserToken
		});

		const response = NextResponse.json({
			status: 'session_ready',
			expiresAt: issuedSession.session.expiresAt.toISOString()
		});

		setSessionCookies(response, issuedSession);
		clearDeviceVerificationCookie(response);

		return response;
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};
