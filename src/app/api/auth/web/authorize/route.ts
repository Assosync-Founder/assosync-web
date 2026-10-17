import { type NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import {
	assertAccountHostname,
	AuthHttpError,
	createAuthErrorResponse,
	resolveRequestOrigin
} from '@/lib/auth/http/auth-http';
import {
	setWebAuthorizationCookie
} from '@/lib/auth/http/auth-cookies';
import webAuthorizationService from '@/lib/auth/web/authorization-server';

const MAXIMUM_QUERY_VALUE_LENGTH = 2_048;

/** Reads a required and bounded authorization query parameter.
 * @param searchParams - Incoming URL parameters.
 * @param name - Parameter name.
 * @returns Validated parameter value.
 * @throws {AuthHttpError} When the value is absent or oversized.
 */
const readQueryParameter = (
	searchParams: URLSearchParams,
	name: string
): string => {
	const value = searchParams.get(name);

	if (
		!value ||
		value.length > MAXIMUM_QUERY_VALUE_LENGTH
	) {
		throw new AuthHttpError(400, 'authorization_invalid');
	}

	return value;
};

/** Consumes an identity ticket and redirects to the Account continuation route.
 * @param request - Browser authorization request.
 * @returns Redirect response bound to a secure Account cookie.
 */
export const GET = async (
	request: NextRequest
): Promise<Response> => {
	try {
		assertAccountHostname(request);

		const searchParams = request.nextUrl.searchParams;
		const issued = await webAuthorizationService.begin({
			identityTicket: readQueryParameter(
				searchParams,
				'identity_ticket'
			)
		});

		const continuationPath = issued.request.identity.idToken
			? '/api/auth/web/continue'
			: authConfig.routes.accountPasskey;
		const continuationUrl = new URL(
			continuationPath,
			resolveRequestOrigin(request)
		);

		continuationUrl.searchParams.set(
			'authorization',
			issued.request.id
		);

		const response = NextResponse.redirect(
			continuationUrl,
			303
		);

		response.headers.set('Cache-Control', 'no-store');

		setWebAuthorizationCookie(
			response,
			issued.browserToken
		);

		return response;
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};
