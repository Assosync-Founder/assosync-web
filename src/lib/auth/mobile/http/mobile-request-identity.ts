import 'server-only';

import type { DecodedIdToken } from 'firebase-admin/auth';
import type { NextRequest } from 'next/server';
import { AuthHttpError } from '@/lib/auth/http/auth-http';
import toFirebaseAuthError from '@/lib/auth/shared/firebase-auth-error';
import firebaseAdmin from '@/services/firebase/firebase-server';

const MAXIMUM_FIREBASE_ID_TOKEN_LENGTH = 8_192;
const BEARER_AUTHORIZATION_PATTERN = /^Bearer\s+([^\s]+)$/iu;

/**
 * Resolves a Firebase user from a mobile bearer token.
 * @param request - Authenticated mobile request.
 * @returns The verified Firebase user identifier.
 * @throws {AuthHttpError} When the authorization header is invalid.
 */
const resolveMobileRequestUserId = async (
	request: NextRequest
): Promise<string> => {
	const authorization = request.headers.get('authorization');
	const match = authorization
		? BEARER_AUTHORIZATION_PATTERN.exec(authorization.trim())
		: null;

	const idToken = match?.[1];

	if (
		!idToken ||
		idToken.length > MAXIMUM_FIREBASE_ID_TOKEN_LENGTH
	) {
		throw new AuthHttpError(401, 'identity_invalid');
	}

	let decodedToken: DecodedIdToken;

	try {
		decodedToken = await firebaseAdmin.auth.verifyIdToken(
			idToken,
			true
		);
	} catch (error: unknown) {
		throw toFirebaseAuthError(error, 'identity');
	}

	if (!decodedToken.uid.trim()) {
		throw new AuthHttpError(401, 'identity_invalid');
	}

	return decodedToken.uid;
};

export default resolveMobileRequestUserId;
