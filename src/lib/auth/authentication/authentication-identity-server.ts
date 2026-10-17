import 'server-only';

import AuthError from '@/lib/auth/shared/auth-error';
import toFirebaseAuthError from '@/lib/auth/shared/firebase-auth-error';
import firebaseAdmin from '@/services/firebase/firebase-server';
import type {
	AuthenticationIdentity,
	AuthenticationIdentityProvider,
	AuthWarningIdentityProvider,
	FirebaseDecodedSession
} from '@/types/auth';

/**
 * Verifies a Firebase token while hiding provider-specific failures.
 * @param idToken - Firebase ID token supplied by the client.
 * @returns The decoded Firebase identity.
 * @throws {AuthError} When Firebase rejects the token.
 */
const verifyFirebaseIdToken = async (
	idToken: string
): Promise<FirebaseDecodedSession> => {
	try {
		return await firebaseAdmin.auth.verifyIdToken(
			idToken,
			true
		);
	} catch (error: unknown) {
		throw toFirebaseAuthError(error, 'identity');
	}
};

/**
 * Resolves a Firebase user while hiding provider-specific failures.
 * @param userId - Verified Firebase user identifier.
 * @returns The Firebase user record.
 * @throws {AuthError} When the account cannot be resolved.
 */
const getFirebaseUser = async (
	userId: string
) => {
	try {
		return await firebaseAdmin.auth.getUser(userId);
	} catch (error: unknown) {
		throw toFirebaseAuthError(error, 'user');
	}
};

/**
 * Extracts a bounded first name from a Firebase display name.
 * @param displayName - Firebase user display name.
 * @returns A first name suitable for transactional emails.
 */
const getFirstname = (
	displayName: string | undefined
): string | undefined => {
	const normalizedDisplayName = displayName?.trim();

	if (!normalizedDisplayName) {
		return undefined;
	}

	const [firstname] = normalizedDisplayName.split(/\s+/u);

	return firstname?.slice(0, 80) || undefined;
};

/**
 * Converts an enabled Firebase user into a safe authentication identity.
 * @param userId - Firebase user identifier.
 * @returns The enabled account identity and its email state.
 * @throws {AuthError} When the account cannot receive authentication email.
 */
const resolveAuthenticationIdentity = async (
	userId: string
): Promise<AuthenticationIdentity> => {
	if (!userId.trim()) {
		throw new AuthError(
			'identity_invalid',
			'The Firebase user identifier is required.'
		);
	}

	const user = await getFirebaseUser(userId);

	if (user.disabled) {
		throw new AuthError(
			'account_disabled',
			'The authenticated account is disabled.'
		);
	}

	if (!user.email) {
		throw new AuthError(
			'identity_invalid',
			'An email address is required.'
		);
	}

	return {
		userId: user.uid,
		email: user.email,
		emailVerified: user.emailVerified,
		firstname: getFirstname(user.displayName)
	};
};

/**
 * Marks a Firebase account email as verified after an email-code proof.
 * @param userId - Firebase user identifier.
 * @returns A promise resolved after the account update.
 * @throws {AuthError} When Firebase cannot update the account.
 */
const markEmailVerified = async (
	userId: string
): Promise<void> => {
	if (!userId.trim()) {
		throw new AuthError(
			'identity_invalid',
			'The Firebase user identifier is required.'
		);
	}

	try {
		await firebaseAdmin.auth.updateUser(
			userId,
			{
				emailVerified: true
			}
		);
	} catch (error: unknown) {
		throw toFirebaseAuthError(error, 'user');
	}
};

/** Shared Firebase identity provider for authentication and warning emails. */
const authenticationIdentityProvider:
	AuthenticationIdentityProvider & AuthWarningIdentityProvider = {
		verify: async (
			idToken
		): Promise<AuthenticationIdentity> => {
			if (!idToken.trim()) {
				throw new AuthError(
					'identity_invalid',
					'The Firebase ID token is required.'
				);
			}

			const decoded = await verifyFirebaseIdToken(idToken);

			if (!decoded.uid.trim()) {
				throw new AuthError(
					'identity_invalid',
					'The Firebase identity is invalid.'
				);
			}

			return resolveAuthenticationIdentity(decoded.uid);
		},
		markEmailVerified,
		resolve: resolveAuthenticationIdentity
	};

export default authenticationIdentityProvider;
