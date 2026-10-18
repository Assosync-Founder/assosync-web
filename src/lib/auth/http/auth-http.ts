import 'server-only';

import { NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import { clearSessionCookies } from '@/lib/auth/http/auth-cookies';
import { logAuthServerError, resolveAuthRequestId } from '@/lib/auth/shared/auth-logger';
import AuthError from '@/lib/auth/shared/auth-error';
import type { DeviceVerificationMode } from '@/types/auth';
import type { PasskeyRelyingParty } from '@/types/passkey';

const MAXIMUM_BODY_LENGTH = 16_384;
const MAXIMUM_REQUIRED_STRING_LENGTH = 8_192;
const AUTHENTICATION_IDENTIFIER_PATTERN = /^[A-Za-z0-9_-]{1,128}$/u;
const ACCOUNT_HOSTNAMES = new Set([
	'account.assosync.fr',
	'preview.assosync.fr',
	'account.localhost'
]);

/** Resolves the externally visible host through trusted proxy headers.
 * @param request - Incoming request.
 * @returns Host value including its optional port.
 * @throws {AuthHttpError} When no valid host can be resolved.
 */
const resolveRequestHost = (request: Request): string => {
	const requestUrl = new URL(request.url);
	const forwardedHost = request.headers
		.get('x-forwarded-host')
		?.split(',')[0]
		?.trim();
	const host = forwardedHost ??
		request.headers.get('host')?.trim() ??
		requestUrl.host;

	let parsedHost: URL;

	try {
		parsedHost = new URL(`http://${ host }`);
	} catch {
		throw new AuthHttpError(403, 'origin_invalid');
	}

	if (parsedHost.username || parsedHost.password || parsedHost.pathname !== '/') {
		throw new AuthHttpError(403, 'origin_invalid');
	}

	return parsedHost.host;
};

/** Reads a required authentication cookie value.
 * @param value - Optional cookie value supplied by Next.js.
 * @param errorCode - Stable public error used when the cookie is absent.
 * @returns The non-empty cookie value.
 * @throws {AuthHttpError} When the cookie is absent.
 */
const readRequiredAuthCookie = (value: string | undefined, errorCode: string): string => {
	if (!value) {
		throw new AuthHttpError(400, errorCode);
	}

	return value;
};

/** Resolves the externally visible request origin.
 * @param request - Incoming request.
 * @returns Normalized public origin.
 * @throws {AuthHttpError} When proxy values are invalid.
 */
const resolveRequestOrigin = (request: Request): string => {
	const requestUrl = new URL(request.url);
	const forwardedProtocol = request.headers
		.get('x-forwarded-proto')
		?.split(',')[0]
		?.trim();
	const protocol = forwardedProtocol === 'http' ||
		forwardedProtocol === 'https'
		? forwardedProtocol
		: requestUrl.protocol.slice(0, -1);

	try {
		return new URL(`${ protocol }://${ resolveRequestHost(request) }`).origin;
	} catch {
		throw new AuthHttpError(403, 'origin_invalid');
	}
};

/** Resolves the externally visible request hostname.
 * @param request - Incoming request.
 * @returns Lowercase hostname without its port.
 */
const resolveRequestHostname = (request: Request): string => {
	return new URL(`http://${ resolveRequestHost(request) }`).hostname.toLowerCase();
};

/** Represents a safe error produced by the authentication HTTP boundary. */
class AuthHttpError extends Error {
	/**
	 * Creates an authentication HTTP error.
	 * @param status - HTTP response status.
	 * @param code - Stable public error code.
	 */
	constructor(public readonly status: number, public readonly code: string) {
		super(code);

		this.name = 'AuthHttpError';
	}
}

/**
 * Determines whether an unknown value is a plain record.
 * @param value - Value to inspect.
 * @returns Whether the value is a string-keyed record.
 */
const isRecord = (value: unknown): value is Record<string, unknown> => {
	return (
		typeof value === 'object' &&
		value !== null &&
		!Array.isArray(value)
	);
};

/**
 * Reads and validates a bounded JSON request body.
 * @param request - Incoming HTTP request.
 * @returns The parsed object.
 * @throws {AuthHttpError} When the request body is invalid.
 */
const readJsonBody = async (request: Request): Promise<Record<string, unknown>> => {
	const contentType = request.headers.get('content-type');

	if (!contentType?.toLowerCase().includes('application/json')) {
		throw new AuthHttpError(415, 'content_type_invalid');
	}

	const rawBody = await request.text();

	if (!rawBody || rawBody.length > MAXIMUM_BODY_LENGTH) {
		throw new AuthHttpError(400, 'request_invalid');
	}

	let parsedBody: unknown;

	try {
		parsedBody = JSON.parse(rawBody);
	} catch {
		throw new AuthHttpError(400, 'request_invalid');
	}

	if (!isRecord(parsedBody)) {
		throw new AuthHttpError(400, 'request_invalid');
	}

	return parsedBody;
};

/**
 * Reads a required non-empty string property.
 * @param record - Parsed request object.
 * @param property - Property to read.
 * @param maximumLength - Maximum accepted string length.
 * @returns The validated string.
 * @throws {AuthHttpError} When the property is missing or invalid.
 */
const readRequiredString = (record: Record<string, unknown>, property: string, maximumLength = MAXIMUM_REQUIRED_STRING_LENGTH): string => {
	const value = record[property];

	if (typeof value !== 'string' || !value.trim() || value.length > maximumLength) {
		throw new AuthHttpError(400, 'request_invalid');
	}

	return value;
};

/**
 * Reads an opaque authentication identifier from an untrusted value.
 * @param value - Identifier value to validate.
 * @returns The validated base64url-compatible identifier.
 * @throws {AuthHttpError} When the identifier is invalid.
 */
const readAuthenticationIdentifier = (value: unknown): string => {
	if (typeof value !== 'string' || !AUTHENTICATION_IDENTIFIER_PATTERN.test(value)) {
		throw new AuthHttpError(400, 'request_invalid');
	}

	return value;
};

/**
 * Reads an optional bounded string property.
 * @param record - Parsed request object.
 * @param property - Property to read.
 * @param maximumLength - Maximum accepted string length.
 * @returns The normalized value or null.
 * @throws {AuthHttpError} When the property is invalid.
 */
const readOptionalString = (record: Record<string, unknown>, property: string, maximumLength: number): string | null => {
	const value = record[property];

	if (value === undefined || value === null) {
		return null;
	}

	if (typeof value !== 'string') {
		throw new AuthHttpError(400, 'request_invalid');
	}

	const normalizedValue = value.trim();

	if (!normalizedValue || normalizedValue.length > maximumLength) {
		throw new AuthHttpError(400, 'request_invalid');
	}

	return normalizedValue;
};

/**
 * Reads an optional device verification mode.
 * @param record - Parsed request object.
 * @param property - Property to read.
 * @returns The selected verification mode when supplied.
 * @throws {AuthHttpError} When the mode is unsupported.
 */
const readOptionalDeviceVerificationMode = (record: Record<string, unknown>, property: string): DeviceVerificationMode | undefined => {
	const value = record[property];

	if (value === undefined) {
		return undefined;
	}

	if (value === 'email_code' || value === 'mobile_approval') {
		return value;
	}

	throw new AuthHttpError(400, 'request_invalid');
};

/**
 * Reads a required nullable and bounded string property.
 * @param record - Parsed request object.
 * @param property - Property to read.
 * @param maximumLength - Maximum accepted string length.
 * @returns The normalized string or null.
 * @throws {AuthHttpError} When the property is missing or invalid.
 */
const readRequiredNullableString = (record: Record<string, unknown>, property: string, maximumLength: number): string | null => {
	if (!Object.hasOwn(record, property)) {
		throw new AuthHttpError(400, 'request_invalid');
	}

	const value = record[property];

	if (value === null) {
		return null;
	}

	if (typeof value !== 'string') {
		throw new AuthHttpError(400, 'request_invalid');
	}

	const normalizedValue = value.trim();

	if (!normalizedValue || normalizedValue.length > maximumLength) {
		throw new AuthHttpError(400, 'request_invalid');
	}

	return normalizedValue;
};

/**
 * Enforces a same-origin mutation request.
 * @param request - Incoming mutation request.
 * @throws {AuthHttpError} When the origin is missing or differs.
 */
const assertSameOrigin = (request: Request): void => {
	const origin = request.headers.get('origin');

	if (!origin) {
		throw new AuthHttpError(403, 'origin_invalid');
	}

	let originUrl: URL;

	try {
		originUrl = new URL(origin);
	} catch {
		throw new AuthHttpError(403, 'origin_invalid');
	}

	if (originUrl.origin !== resolveRequestOrigin(request)) {
		throw new AuthHttpError(403, 'origin_invalid');
	}
};

/**
 * Restricts an endpoint to the Assosync account application.
 * @param request - Incoming account request.
 * @throws {AuthHttpError} When the hostname is not an account hostname.
 */
const assertAccountHostname = (request: Request): void => {
	const hostname = resolveRequestHostname(request);

	if (!ACCOUNT_HOSTNAMES.has(hostname)) {
		throw new AuthHttpError(403, 'application_invalid');
	}
};

/** Resolves the WebAuthn relying party for one trusted Account origin.
 * @param request - Incoming Account request.
 * @returns Exact relying-party values for the current origin.
 * @throws {AuthHttpError} When the origin is not an allowed Account origin.
 */
const resolvePasskeyRelyingParty = (request: Request): PasskeyRelyingParty => {
	assertAccountHostname(request);

	const hostname = resolveRequestHostname(request);
	const origin = resolveRequestOrigin(request);

	if (hostname === authConfig.passkey.rpId && origin === authConfig.passkey.expectedOrigin) {
		return {
			id: authConfig.passkey.rpId,
			origin: authConfig.passkey.expectedOrigin
		};
	}

	throw new AuthHttpError(403, 'origin_invalid');
};

/**
 * Resolves the trusted application from the request hostname.
 * @param request - Incoming request.
 * @returns The trusted application identifier.
 * @throws {AuthHttpError} When the hostname is unsupported.
 */
const resolveApplicationId = (request: Request): string => {
	const hostname = resolveRequestHostname(request);

	const application = authConfig.applications.find((candidate) => {
			return candidate.hostnames.some(
				(candidateHostname) => {
					return (
						candidateHostname === hostname
					);
				}
			);
		});

	if (!application) {
		throw new AuthHttpError(403, 'application_invalid');
	}

	return application.id;
};

/**
 * Converts an expected authentication error into an HTTP status.
 * @param error - Authentication error.
 * @returns The associated HTTP status.
 */
const getAuthErrorStatus = (error: AuthError): number => {
	switch (error.code) {
		case 'account_disabled':
		case 'approval_rejected':
		case 'device_user_mismatch':
			return 403;

		case 'identity_invalid':
		case 'client_invalid':
		case 'session_expired':
		case 'session_invalid':
		case 'session_revoked':
			return 401;

		case 'firebase_unavailable':
			return 503;

		case 'verification_locked':
		case 'verification_rate_limited':
		case 'verification_resend_limit':
		case 'verification_resend_too_soon':
			return 429;

		case 'approval_not_ready':
			return 409;

		default:
			return 400;
	}
};

/**
 * Creates a safe JSON error response.
 * @param error - Unknown route failure.
 * @param request - Incoming request when available.
 * @param operation - Stable server operation used for diagnostics.
 * @returns A response containing no private diagnostic value.
 */
const createAuthErrorResponse = (error: unknown, request?: Request, operation = 'auth_http_response'): NextResponse => {
	const requestId = resolveAuthRequestId(request);
	const headers = new Headers({ 'Cache-Control': 'no-store', 'X-Request-Id': requestId });

	if (error instanceof AuthHttpError) {
		const response = NextResponse.json(
			{
				error: error.code
			},
			{
				status: error.status,
				headers
			}
		);

		if (error.code === 'session_invalid') {
			clearSessionCookies(response);
		}

		return response;
	}

	if (error instanceof AuthError) {
		const status = getAuthErrorStatus(error);
		const retryAfterSeconds = error.retryAfterSeconds;

		if (retryAfterSeconds !== null) {
			headers.set('Retry-After', retryAfterSeconds.toString());
		} else if (status === 503) {
			headers.set('Retry-After', '5');
		}

		if (status >= 500) {
			logAuthServerError(error, operation, request, requestId);
		}

		const response = NextResponse.json(
			{
				error: error.code,
				...(retryAfterSeconds !== null
					? { retryAfterSeconds }
					: {})
			},
			{
				status,
				headers
			}
		);

		if (error.code === 'session_expired' || error.code === 'session_invalid' || error.code === 'session_revoked') {
			clearSessionCookies(response);
		}

		return response;
	}

	logAuthServerError(error, operation, request, requestId);

	return NextResponse.json(
		{
			error: 'internal_error'
		},
		{
			status: 500,
			headers
		}
	);
};

export {
	assertAccountHostname,
	assertSameOrigin,
	AuthHttpError,
	createAuthErrorResponse,
	readAuthenticationIdentifier,
	readJsonBody,
	readOptionalDeviceVerificationMode,
	readOptionalString,
	readRequiredAuthCookie,
	readRequiredNullableString,
	readRequiredString,
	resolveApplicationId,
	resolvePasskeyRelyingParty,
	resolveRequestOrigin
};
