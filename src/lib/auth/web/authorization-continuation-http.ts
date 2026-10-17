import 'server-only';

import { type NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import authenticationService from '@/lib/auth/authentication/authentication-server';
import detectDeviceInformation from '@/lib/auth/device/device-detection';
import AuthError from '@/lib/auth/shared/auth-error';
import {
	clearDeviceVerificationCookie,
	clearWebAuthorizationCookie,
	setDeviceCookie,
	setDeviceVerificationCookie,
	setSessionCookies
} from '@/lib/auth/http/auth-cookies';
import {
	assertAccountHostname,
	createAuthErrorResponse,
	readAuthenticationIdentifier,
	readRequiredAuthCookie,
	resolveRequestOrigin
} from '@/lib/auth/http/auth-http';
import resolveAuthenticationRequestContext, {
	requireWebAuthorization
} from '@/lib/auth/web/authorization-http';
import finalizeWebAuthorization from '@/lib/auth/web/authorization-finalization';
import createAuthenticationFlashRelayUri from '@/lib/auth/web/authentication-flash-relay';
import webAuthorizationService from '@/lib/auth/web/authorization-server';

/** Resolves a trusted product error endpoint for an active authorization.
 * @param request - Browser request received by Account.
 * @param error - Failure produced while continuing the authorization.
 * @returns Product error endpoint, or null when no safe redirect is available.
 */
const resolveProductFailureUri = async (
	request: NextRequest,
	error: unknown
): Promise<string | null> => {
	if (!(error instanceof AuthError)) {
		return null;
	}

	const authorizationValue = request.nextUrl.searchParams.get(
		'authorization'
	);
	const browserToken = request.cookies.get(
		authConfig.cookieNames.webAuthorization
	)?.value;

	if (!authorizationValue || !browserToken) {
		return null;
	}

	try {
		const authorizationId = readAuthenticationIdentifier(
			authorizationValue
		);
		const authorization = await webAuthorizationService.resolve(
			authorizationId,
			browserToken
		);
		const client = authConfig.webSso.clients.find((candidate) => {
			return candidate.id === authorization.applicationId;
		});

		if (!client) {
			return null;
		}

		const createFlashUri = async (
			flashCode: string
		): Promise<string> => {
			const authenticationFlashUri = new URL(
				'/api/auth/flash',
				authorization.redirectUri
			).toString();

			return createAuthenticationFlashRelayUri(
				client,
				flashCode,
				undefined,
				authenticationFlashUri
			);
		};

		if (
			error.code === 'verification_rate_limited' ||
			error.code === 'verification_locked' ||
			error.code === 'verification_resend_limit' ||
			error.code === 'verification_resend_too_soon'
		) {
			const retryAfterSeconds = error.retryAfterSeconds;

			if (retryAfterSeconds === null) {
				return await createFlashUri('authentication_failed');
			}

			if (retryAfterSeconds <= 15 * 60) {
				return await createFlashUri(
					'email_code_rate_limited_15_minutes'
				);
			}

			if (retryAfterSeconds <= 60 * 60) {
				return await createFlashUri(
					'email_code_rate_limited_1_hour'
				);
			}

			if (retryAfterSeconds <= 6 * 60 * 60) {
				return await createFlashUri(
					'email_code_rate_limited_6_hours'
				);
			}

			return await createFlashUri(
				'email_code_rate_limited_24_hours'
			);
		}

		return await createFlashUri('authentication_failed');
	} catch (caught: unknown) {
		console.error(JSON.stringify({
			event: 'product_authentication_failure_uri_resolution_failure',
			errorName: caught instanceof Error
				? caught.name
				: 'UnknownError'
		}));

		return null;
	}
};

/** Resolves the Firebase identity token attached to an authenticated authorization.
 * @param idToken - Optional identity token from the temporary authorization.
 * @returns The bound Firebase ID token.
 * @throws {AuthError} When the authorization was not authenticated.
 */
const requireIdentityToken = (
	idToken: string | null
): string => {
	if (!idToken) {
		throw new AuthError(
			'authorization_invalid',
			'The passkey authorization is not authenticated.'
		);
	}

	return idToken;
};

/** Processes a Web authorization continuation on the Account server.
 * @param request - Incoming browser request bound to an authorization cookie.
 * @returns A callback or device-confirmation redirect.
 */
const handleWebAuthorizationContinuation = async (
	request: NextRequest
): Promise<Response> => {
	try {
		assertAccountHostname(request);

		const authorizationId = readAuthenticationIdentifier(
			request.nextUrl.searchParams.get('authorization')
		);
		const authenticationContext =
			await resolveAuthenticationRequestContext(
				request,
				authorizationId
			);

		const webAuthorization = requireWebAuthorization(authenticationContext);

		const idToken = requireIdentityToken(
			webAuthorization.identity.idToken
		);

		const deviceToken = request.cookies.get(
			authConfig.cookieNames.device
		)?.value ?? null;
		const result = await authenticationService.start({
			idToken,
			applicationId: authenticationContext.applicationId,
			deviceToken,
			detectedDeviceInformation:
				detectDeviceInformation(request.headers),
			verificationMode: 'email_code'
		});

		if (result.status === 'session_ready') {
			const browserToken = readRequiredAuthCookie(
				request.cookies.get(
					authConfig.cookieNames.webAuthorization
				)?.value,
				'authorization_invalid'
			);

			const completed = await finalizeWebAuthorization({
				requestId: authorizationId,
				browserToken,
				issuedSession: result.issuedSession,
				idToken,
				deviceToken: readRequiredAuthCookie(
					deviceToken ?? undefined,
					'device_not_verified'
				)
			});
			const response = NextResponse.redirect(
				completed.redirectUri,
				303
			);

			response.headers.set('Cache-Control', 'no-store');

			setSessionCookies(response, completed.accountSession);

			clearDeviceVerificationCookie(response);
			clearWebAuthorizationCookie(response);

			return response;
		}

		const confirmationUrl = new URL(
			'/confirm-device',
			resolveRequestOrigin(request)
		);

		confirmationUrl.searchParams.set(
			'authorization',
			authorizationId
		);
		confirmationUrl.searchParams.set(
			'device',
			result.deviceId
		);
		confirmationUrl.searchParams.set(
			'verification',
			result.verificationId
		);

		const response = NextResponse.redirect(
			confirmationUrl,
			303
		);

		response.headers.set('Cache-Control', 'no-store');

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
		const failureUri = await resolveProductFailureUri(
			request,
			error
		);

		if (failureUri) {
			return NextResponse.redirect(failureUri, 303);
		}

		return createAuthErrorResponse(error, request);
	}
};

export default handleWebAuthorizationContinuation;
