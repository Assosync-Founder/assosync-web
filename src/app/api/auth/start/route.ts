import { cookies, headers } from 'next/headers';
import { type NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import authenticationService from '@/lib/auth/authentication/authentication-server';
import detectDeviceInformation from '@/lib/auth/device/device-detection';
import {
	clearDeviceVerificationCookie,
	clearWebAuthorizationCookie,
	setDeviceCookie,
	setDeviceVerificationCookie,
	setSessionCookies
} from '@/lib/auth/http/auth-cookies';
import {
	assertSameOrigin,
	createAuthErrorResponse,
	readAuthenticationIdentifier,
	readJsonBody,
	readOptionalDeviceVerificationMode,
	readOptionalString,
	readRequiredAuthCookie
} from '@/lib/auth/http/auth-http';
import resolveAuthenticationRequestContext, {
	resolveAuthenticationIdToken
} from '@/lib/auth/web/authorization-http';
import finalizeWebAuthorization from '@/lib/auth/web/authorization-finalization';

/** Starts authentication after Firebase client sign-in.
 * @param request - Incoming authentication request.
 * @returns The authentication decision.
 */
export const POST = async (
	request: NextRequest
): Promise<Response> => {
	try {
		assertSameOrigin(request);

		const [cookieStore, headerStore] = await Promise.all([
			cookies(),
			headers()
		]);
		const body = await readJsonBody(request);
		const authorizationValue = readOptionalString(
			body,
			'authorizationId',
			128
		);
		const authorizationId = authorizationValue
			? readAuthenticationIdentifier(authorizationValue)
			: null;
		const authenticationContext =
			await resolveAuthenticationRequestContext(
				request,
				authorizationId
			);
		const applicationId =
			authenticationContext.applicationId;
		const idToken = resolveAuthenticationIdToken(
			body,
			authenticationContext
		);

		const deviceDisplayName =
			readOptionalString(
				body,
				'deviceDisplayName',
				120
			);

		const verificationMode =
			authenticationContext.webAuthorization
				? 'email_code'
				: readOptionalDeviceVerificationMode(
					body,
					'verificationMode'
				);

		const detectedDeviceInformation =
			detectDeviceInformation(headerStore);

		const deviceToken =
			cookieStore.get(
				authConfig.cookieNames.device
			)?.value ?? null;

		const result =
			await authenticationService.start({
				idToken,
				applicationId,
				deviceToken,
				deviceDisplayName,
				detectedDeviceInformation,
				verificationMode
			});

		if (result.status === 'session_ready') {
			if (authenticationContext.webAuthorization) {
				const browserToken = readRequiredAuthCookie(
					cookieStore.get(
						authConfig.cookieNames.webAuthorization
					)?.value,
					'authorization_invalid'
				);
				const resolvedAuthorizationId =
					readAuthenticationIdentifier(authorizationId);

				const completed =
					await finalizeWebAuthorization({
						requestId: resolvedAuthorizationId,
						browserToken,
						issuedSession: result.issuedSession,
						idToken,
						deviceToken: readRequiredAuthCookie(
							deviceToken ?? undefined,
							'device_not_verified'
						)
					});

				const response = NextResponse.json({
					status: 'authorization_ready',
					redirectUri: completed.redirectUri
				});

				setSessionCookies(response, completed.accountSession);

				clearDeviceVerificationCookie(response);
				clearWebAuthorizationCookie(response);

				return response;
			}

			const response = NextResponse.json({
				status: 'session_ready',
				expiresAt:
					result.issuedSession.session
						.expiresAt.toISOString()
			});

			setSessionCookies(
				response,
				result.issuedSession
			);

			clearDeviceVerificationCookie(response);

			return response;
		}

		const response = NextResponse.json({
			status: 'verification_required',
			deviceId: result.deviceId,
			verificationId: result.verificationId,
			expiresAt:
				result.expiresAt.toISOString(),
			verificationMode: result.verificationMode
		});

		if (result.issuedDeviceToken) {
			setDeviceCookie(
				response,
				result.issuedDeviceToken
			);
		}

		setDeviceVerificationCookie(
			response,
			result.browserToken
		);

		return response;
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};
