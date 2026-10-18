import 'server-only';

import AuthError from '@/lib/auth/shared/auth-error';
import toFirebaseAuthError from '@/lib/auth/shared/firebase-auth-error';
import { systemClock } from '@/lib/auth/shared/runtime-server';
import type {
	Clock,
	FirebaseAdminSessionProvider,
	FirebaseAuthErrorContext,
	FirebaseDecodedSession,
	FirebaseSessionAdapter,
	FirebaseSessionAdapterOptions,
	VerifiedFirebaseSession
} from '@/types/auth';

/**
 * Executes a Firebase operation and normalizes provider failures.
 * @template Result - Successful operation result.
 * @param operation - Firebase operation to execute.
 * @param context - Authentication operation being performed.
 * @returns The Firebase operation result.
 * @throws {AuthError} When Firebase rejects or cannot process the operation.
 */
const executeFirebaseOperation = async <Result>(operation: () => Promise<Result>, context: FirebaseAuthErrorContext): Promise<Result> => {
	try {
		return await operation();
	} catch (error: unknown) {
		throw toFirebaseAuthError(error, context);
	}
};

/**
 * Converts a decoded Firebase session into the authentication identity.
 * @param decoded - Decoded Firebase token.
 * @returns The verified Firebase identity.
 * @throws {AuthError} When the decoded token is invalid.
 */
const toVerifiedFirebaseSession = (decoded: FirebaseDecodedSession): VerifiedFirebaseSession => {
	if (!decoded.uid.trim() || !Number.isSafeInteger(decoded.exp) || decoded.exp <= 0) {
		throw new AuthError('session_invalid', 'The Firebase session is invalid.');
	}

	const expiresAt = new Date(decoded.exp * 1_000);

	if (Number.isNaN(expiresAt.getTime())) {
		throw new AuthError('session_invalid', 'The Firebase session expiration is invalid.');
	}

	return {
		userId: decoded.uid,
		expiresAt
	};
};

/**
 * Creates the Firebase Admin session adapter.
 * @param auth - Initialized Firebase Admin Authentication service.
 * @param options - Firebase session security settings.
 * @param clock - Time provider.
 * @returns The Firebase session adapter.
 */
const createFirebaseSessionAdapter = (auth: FirebaseAdminSessionProvider, options: FirebaseSessionAdapterOptions, clock: Clock = systemClock): FirebaseSessionAdapter => {
	if (!Number.isSafeInteger(options.maxAuthenticationAgeMs) || options.maxAuthenticationAgeMs <= 0) {
		throw new RangeError('Maximum authentication age must be a positive integer.');
	}

	return {
		create: async (idToken, expiresInMs) => {
			if (!idToken.trim()) {
				throw new AuthError('session_invalid', 'The Firebase ID token is required.');
			}

			const decodedIdToken = await executeFirebaseOperation(async () => auth.verifyIdToken(idToken, true), 'identity');

			if (!Number.isSafeInteger(decodedIdToken.auth_time) || !decodedIdToken.auth_time) {
				throw new AuthError('session_invalid', 'The Firebase authentication time is invalid.');
			}

			const authenticationTime = decodedIdToken.auth_time * 1_000;
			const authenticationAge = clock.now().getTime() - authenticationTime;

			if (authenticationAge <0 || authenticationAge > options.maxAuthenticationAgeMs) {
				throw new AuthError('session_expired', 'A recent authentication is required.');
			}

			const cookie = await executeFirebaseOperation(async () => auth.createSessionCookie(idToken, { expiresIn: expiresInMs }), 'session_creation');
			const decodedSession = await executeFirebaseOperation(async () => auth.verifySessionCookie(cookie, false), 'session');

			return {
				cookie,
				identity: toVerifiedFirebaseSession(decodedSession)
			};
		},

		verify: async (sessionCookie, checkRevoked) => {
			if (!sessionCookie.trim()) {
				throw new AuthError('session_invalid', 'The Firebase session cookie is required.');
			}

			const decoded = await executeFirebaseOperation(async () => auth.verifySessionCookie(sessionCookie, checkRevoked), 'session');

			return toVerifiedFirebaseSession(decoded);
		}
	};
};

export default createFirebaseSessionAdapter;
