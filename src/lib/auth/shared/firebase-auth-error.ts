import 'server-only';

import AuthError from '@/lib/auth/shared/auth-error';
import type { FirebaseAuthErrorContext } from '@/types/auth';

const ACCOUNT_DISABLED_CODES = new Set([
	'auth/user-disabled',
	'user-disabled'
]);

const SESSION_EXPIRED_CODES = new Set([
	'auth/session-cookie-expired',
	'session-cookie-expired'
]);

const SESSION_REVOKED_CODES = new Set([
	'auth/session-cookie-revoked',
	'session-cookie-revoked'
]);

const INVALID_CREDENTIAL_CODES = new Set([
	'auth/argument-error',
	'argument-error',
	'auth/id-token-expired',
	'id-token-expired',
	'auth/id-token-revoked',
	'id-token-revoked',
	'auth/invalid-id-token',
	'invalid-id-token',
	'auth/invalid-session-cookie',
	'invalid-session-cookie',
	'auth/user-not-found',
	'user-not-found'
]);

/**
 * Reads a Firebase error code without trusting the caught value.
 * @param error - Unknown value thrown by Firebase Admin.
 * @returns The normalized provider code or null.
 */
const getFirebaseErrorCode = (
	error: unknown
): string | null => {
	if (
		typeof error !== 'object' ||
		error === null ||
		!('code' in error) ||
		typeof error.code !== 'string'
	) {
		return null;
	}

	return error.code.toLowerCase();
};

/**
 * Converts an unknown Firebase Admin failure into a safe domain error.
 * @param error - Unknown value thrown by Firebase Admin.
 * @param context - Authentication operation that failed.
 * @returns A stable authentication error.
 */
const toFirebaseAuthError = (
	error: unknown,
	context: FirebaseAuthErrorContext
): AuthError => {
	if (error instanceof AuthError) {
		return error;
	}

	const code = getFirebaseErrorCode(error);

	if (code && ACCOUNT_DISABLED_CODES.has(code)) {
		return new AuthError(
			'account_disabled',
			'The authenticated account is disabled.'
		);
	}

	if (code && SESSION_EXPIRED_CODES.has(code)) {
		return new AuthError(
			'session_expired',
			'The Firebase session has expired.'
		);
	}

	if (code && SESSION_REVOKED_CODES.has(code)) {
		return new AuthError(
			'session_revoked',
			'The Firebase session was revoked.'
		);
	}

	if (code && INVALID_CREDENTIAL_CODES.has(code)) {
		const errorCode = context === 'session'
			? 'session_invalid'
			: 'identity_invalid';

		return new AuthError(
			errorCode,
			'The Firebase authentication credential is invalid.'
		);
	}

	return new AuthError(
		'firebase_unavailable',
		'The Firebase Authentication service is temporarily unavailable.'
	);
};

export default toFirebaseAuthError;
