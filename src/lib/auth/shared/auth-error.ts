import type { AuthErrorCode } from '@/types/auth';

/**
 * Represents an expected authentication failure.
 */
class AuthError extends Error {
	/**
	 * Creates an authentication error.
	 * @param code - Stable machine-readable error code.
	 * @param message - Safe diagnostic message.
	 * @param retryAfterSeconds - Optional client retry delay in seconds.
	 */
	constructor(public readonly code: AuthErrorCode, message: string, public readonly retryAfterSeconds: number | null = null) {
		super(message);

		this.name = 'AuthError';
	}
}

export default AuthError;
