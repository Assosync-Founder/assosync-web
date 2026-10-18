import { type NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import { assertAccountHostname, AuthHttpError, createAuthErrorResponse } from '@/lib/auth/http/auth-http';
import { setWebAuthorizationCookie } from '@/lib/auth/http/auth-cookies';
import webAuthorizationService from '@/lib/auth/web/authorization-server';

/** Reads one bounded handoff ticket from the browser URL.
 * @param request - Incoming browser request.
 * @returns Validated opaque ticket.
 * @throws {AuthHttpError} When the ticket is absent or oversized.
 */
const readHandoffTicket = (request: NextRequest): string => {
	const ticket = request.nextUrl.searchParams.get('ticket');

	if (!ticket || ticket.length > 512) {
		throw new AuthHttpError(400, 'authorization_invalid');
	}

	return ticket;
};

/** Consumes a product-issued handoff and restores the Account browser context.
 * @param request - Browser request carrying a one-time handoff ticket.
 * @returns Redirect to passkey fallback or device continuation.
 */
export const GET = async (request: NextRequest): Promise<Response> => {
	try {
		assertAccountHostname(request);

		const issued = await webAuthorizationService.consumeHandoff(readHandoffTicket(request));
		const continuationPath = issued.request.identity.idToken
			? '/api/auth/web/continue'
			: authConfig.routes.accountPasskey;
		const continuationUrl = new URL(continuationPath, authConfig.passkey.expectedOrigin);

		continuationUrl.searchParams.set('authorization', issued.request.id);

		const response = NextResponse.redirect(continuationUrl, 303);

		response.headers.set('Cache-Control', 'no-store');
		response.headers.set('Referrer-Policy', 'no-referrer');

		setWebAuthorizationCookie(response, issued.browserToken);

		return response;
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request, 'web_authorization_resume');
	}
};
