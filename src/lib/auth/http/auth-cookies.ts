import 'server-only';

import type { NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import Env from '@/config/env';
import {
	clearAuthCookie,
	createAuthCookie
} from '@/lib/auth/cookies/auth-cookie';
import type {
	AuthCookie,
	IssuedSession
} from '@/types/auth';

const MILLISECONDS_IN_SECOND = 1_000;
const cookiesAreSecure = Env.public.environment !== 'development';

/**
 * Converts milliseconds into whole cookie seconds.
 * @param lifetimeMs - Lifetime in milliseconds.
 * @returns The rounded-up lifetime in seconds.
 */
const toCookieSeconds = (
	lifetimeMs: number
): number => {
	return Math.ceil(
		lifetimeMs / MILLISECONDS_IN_SECOND
	);
};

/**
 * Writes a framework-neutral authentication cookie.
 * @param response - Mutable Next.js response.
 * @param cookie - Authentication cookie descriptor.
 */
const applyAuthCookie = (
	response: NextResponse,
	cookie: AuthCookie
): void => {
	response.cookies.set({
		name: cookie.name,
		value: cookie.value,
		httpOnly: cookie.httpOnly,
		secure: cookiesAreSecure,
		sameSite: cookie.sameSite,
		path: cookie.path,
		maxAge: cookie.maxAge
	});
};

/**
 * Writes a persistent trusted-device cookie.
 * @param response - Mutable Next.js response.
 * @param deviceToken - Raw trusted-device token.
 */
const setDeviceCookie = (
	response: NextResponse,
	deviceToken: string
): void => {
	applyAuthCookie(
		response,
		createAuthCookie(
			authConfig.cookieNames.device,
			deviceToken,
			toCookieSeconds(
				authConfig.device.trustedLifetimeMs
			)
		)
	);
};

/**
 * Writes the temporary browser verification token.
 * @param response - Mutable Next.js response.
 * @param browserToken - Raw verification continuation token.
 */
const setDeviceVerificationCookie = (
	response: NextResponse,
	browserToken: string
): void => {
	applyAuthCookie(
		response,
		createAuthCookie(
			authConfig.cookieNames.deviceVerification,
			browserToken,
			toCookieSeconds(
				authConfig.deviceVerification
					.lifetimeMs
			)
		)
	);
};

/** Writes the temporary Web SSO browser binding cookie.
 * @param response - Mutable Next.js response.
 * @param browserToken - Raw authorization continuation token.
 */
const setWebAuthorizationCookie = (
	response: NextResponse,
	browserToken: string
): void => {
	applyAuthCookie(
		response,
		createAuthCookie(
			authConfig.cookieNames.webAuthorization,
			browserToken,
			toCookieSeconds(
				authConfig.webSso.requestLifetimeMs
			)
		)
	);
};

/**
 * Writes the Firebase and application session cookies.
 * @param response - Mutable Next.js response.
 * @param issued - Issued application session.
 */
const setSessionCookies = (
	response: NextResponse,
	issued: IssuedSession
): void => {
	const maxAge = toCookieSeconds(
		authConfig.session.lifetimeMs
	);

	applyAuthCookie(
		response,
		createAuthCookie(
			authConfig.cookieNames.session,
			issued.firebaseSessionCookie,
			maxAge
		)
	);

	applyAuthCookie(
		response,
		createAuthCookie(
			authConfig.cookieNames.connection,
			issued.sessionToken,
			maxAge
		)
	);
};

/**
 * Removes the temporary device verification cookie.
 * @param response - Mutable Next.js response.
 */
const clearDeviceVerificationCookie = (
	response: NextResponse
): void => {
	applyAuthCookie(
		response,
		clearAuthCookie(
			authConfig.cookieNames.deviceVerification
		)
	);
};

/** Removes the temporary Web SSO browser binding cookie.
 * @param response - Mutable Next.js response.
 */
const clearWebAuthorizationCookie = (
	response: NextResponse
): void => {
	applyAuthCookie(
		response,
		clearAuthCookie(
			authConfig.cookieNames.webAuthorization
		)
	);
};

/**
 * Removes all authenticated session cookies.
 * @param response - Mutable Next.js response.
 */
const clearSessionCookies = (
	response: NextResponse
): void => {
	applyAuthCookie(
		response,
		clearAuthCookie(
			authConfig.cookieNames.session
		)
	);

	applyAuthCookie(
		response,
		clearAuthCookie(
			authConfig.cookieNames.connection
		)
	);

	applyAuthCookie(
		response,
		clearAuthCookie(
			authConfig.cookieNames.deviceVerification
		)
	);

	applyAuthCookie(
		response,
		clearAuthCookie(
			authConfig.cookieNames.approval
		)
	);
};

export {
	clearDeviceVerificationCookie,
	clearSessionCookies,
	clearWebAuthorizationCookie,
	setDeviceCookie,
	setDeviceVerificationCookie,
	setSessionCookies,
	setWebAuthorizationCookie
};
