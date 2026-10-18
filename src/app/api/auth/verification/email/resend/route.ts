import { cookies } from 'next/headers';
import { type NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import authenticationService from '@/lib/auth/authentication/authentication-server';
import { setDeviceVerificationCookie } from '@/lib/auth/http/auth-cookies';
import { assertSameOrigin, createAuthErrorResponse, readAuthenticationIdentifier, readJsonBody, readOptionalString, readRequiredAuthCookie } from '@/lib/auth/http/auth-http';
import resolveAuthenticationRequestContext, { resolveAuthenticationIdToken } from '@/lib/auth/web/authorization-http';

/** Replaces and sends an email device verification code.
 * @param request - Incoming browser resend request.
 * @returns The renewed verification expiration and resend count.
 */
export const POST = async (request: NextRequest): Promise<Response> => {
	try {
		assertSameOrigin(request);

		const cookieStore = await cookies();
		const body = await readJsonBody(request);
		const authorizationValue = readOptionalString(body, 'authorizationId', 128);
		const authorizationId = authorizationValue
			? readAuthenticationIdentifier(authorizationValue)
			: null;
		const authenticationContext = await resolveAuthenticationRequestContext(request, authorizationId);
		const idToken = resolveAuthenticationIdToken(body, authenticationContext);
		const deviceId = readAuthenticationIdentifier(body.deviceId);

		const verificationId = readAuthenticationIdentifier(body.verificationId);

		const browserToken = readRequiredAuthCookie(cookieStore.get(authConfig.cookieNames.deviceVerification)?.value, 'verification_invalid');

		const verification = await authenticationService.resendEmailVerification({
				idToken,
				applicationId: authenticationContext.applicationId,
				deviceId,
				verificationId,
				browserToken
			});

		const response = NextResponse.json({
			status: 'resent',
			expiresAt: verification.expiresAt.toISOString(),
			resendCount: verification.emailResendCount,
			resendLimitReached: verification.emailResendCount >= authConfig.deviceVerification.maxEmailResends,
			retryAfterSeconds: Math.ceil(authConfig.deviceVerification.emailResendCooldownMs / 1_000)
		});

		setDeviceVerificationCookie(response, browserToken);

		return response;
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};
