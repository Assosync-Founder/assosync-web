import 'server-only';

import { randomUUID } from 'node:crypto';
import AuthError from '@/lib/auth/shared/auth-error';

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

/**
 * Resolves a safe correlation identifier for an authentication request.
 * @param request - Incoming request when available.
 * @returns A trusted correlation identifier.
 */
const resolveAuthRequestId = (
	request?: Request
): string => {
	const suppliedRequestId = request?.headers
		.get('x-request-id')
		?.trim();

	if (
		suppliedRequestId &&
		REQUEST_ID_PATTERN.test(suppliedRequestId)
	) {
		return suppliedRequestId;
	}

	return randomUUID();
};

/**
 * Records a sanitized authentication infrastructure failure.
 * @param error - Unknown server failure.
 * @param operation - Stable operation identifier.
 * @param request - Incoming request when available.
 * @param requestId - Existing correlation identifier when already resolved.
 */
const logAuthServerError = (
	error: unknown,
	operation: string,
	request?: Request,
	requestId = resolveAuthRequestId(request)
): void => {
	const errorName = error instanceof Error
		? error.name
		: 'UnknownError';

	const authErrorCode = error instanceof AuthError
		? error.code
		: null;
	const diagnosticMessage = (
		error instanceof TypeError ||
		error instanceof SyntaxError ||
		error instanceof RangeError
	)
		? error.message
		: null;
	const diagnosticStack = (
		process.env.NODE_ENV === 'development' &&
		error instanceof Error
	)
		? error.stack?.slice(0, 4_000) ?? null
		: null;

	let method: string | null = null;
	let pathname: string | null = null;

	if (request) {
		method = request.method;

		try {
			pathname = new URL(request.url).pathname;
		} catch {
			pathname = null;
		}
	}

	console.error(JSON.stringify({
		level: 'error',
		event: 'authentication_server_failure',
		operation,
		requestId,
		method,
		pathname,
		errorName,
		authErrorCode,
		diagnosticMessage,
		diagnosticStack
	}));
};

export {
	logAuthServerError,
	resolveAuthRequestId
};
