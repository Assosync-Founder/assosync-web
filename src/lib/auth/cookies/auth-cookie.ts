import type { AuthCookie } from '@/types/auth';

/**
 * Creates a secure server-only authentication cookie.
 * @param name - Cookie name.
 * @param value - Cookie value.
 * @param maxAge - Cookie lifetime in seconds.
 * @param path - Cookie request path.
 * @returns A secure cookie descriptor.
 * @throws {TypeError} When the cookie name or path is invalid.
 * @throws {RangeError} When the lifetime is invalid.
 */
export const createAuthCookie = (
	name: string,
	value: string,
	maxAge: number,
	path = '/'
): AuthCookie => {
	if (!name.trim()) {
		throw new TypeError('The authentication cookie name is required.');
	}

	if (!path.startsWith('/')) {
		throw new TypeError(
			'The authentication cookie path must start with a slash.'
		);
	}

	if (!Number.isInteger(maxAge) || maxAge < 0) {
		throw new RangeError(
			'The authentication cookie lifetime must be a non-negative integer.'
		);
	}

	return {
		name,
		value,
		httpOnly: true,
		secure: true,
		sameSite: 'lax',
		path,
		maxAge
	};
};

/**
 * Creates a descriptor that immediately expires an authentication cookie.
 * @param name - Cookie name.
 * @param path - Cookie request path.
 * @returns An expired cookie descriptor.
 */
export const clearAuthCookie = (
	name: string,
	path = '/'
): AuthCookie => {
	return createAuthCookie(name, '', 0, path);
};