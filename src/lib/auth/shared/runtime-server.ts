import 'server-only';

import {
	createHash,
	createHmac,
	randomBytes,
	randomInt
} from 'node:crypto';
import type {
	Clock,
	TokenGenerator,
	TokenHasher,
	VerificationCodeGenerator,
	VerificationCodeHasher
} from '@/types/auth';

/** Uses the system clock. */
export const systemClock: Clock = {
	now: () => new Date()
};

/** Generates 256-bit URL-safe opaque values. */
export const secureTokenGenerator: TokenGenerator = {
	generate: () => randomBytes(32).toString('base64url')
};

/** Hashes opaque values with SHA-256 before persistence. */
export const sha256TokenHasher: TokenHasher = {
	hash: (value) => {
		return createHash('sha256')
			.update(value, 'utf8')
			.digest('base64url');
	}
};

/** Generates six-digit verification codes with a CSPRNG. */
export const secureVerificationCodeGenerator: VerificationCodeGenerator = {
	generate: () => {
		return randomInt(0, 1_000_000)
			.toString()
			.padStart(6, '0');
	}
};

/**
 * Creates a keyed hasher for short verification codes.
 * @param secret - Server-only secret containing at least 32 bytes.
 * @returns A verification code hasher.
 * @throws {TypeError} When the secret contains fewer than 32 bytes.
 */
export const createHmacVerificationCodeHasher = (
	secret: string | Uint8Array
): VerificationCodeHasher => {
	const secretLength = typeof secret === 'string'
		? Buffer.byteLength(secret, 'utf8')
		: secret.byteLength;

	if (secretLength < 32) {
		throw new TypeError(
			'The verification code secret must contain at least 32 bytes.'
		);
	}

	return {
		hash: (code, verificationId) => {
			return createHmac('sha256', secret)
				.update(verificationId, 'utf8')
				.update('\0', 'utf8')
				.update(code, 'utf8')
				.digest('base64url');
		}
	};
};