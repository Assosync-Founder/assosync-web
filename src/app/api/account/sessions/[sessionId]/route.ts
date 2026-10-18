import { NextRequest, NextResponse } from 'next/server';
import { clearSessionCookies } from '@/lib/auth/http/auth-cookies';
import { assertSameOrigin, createAuthErrorResponse, readAuthenticationIdentifier } from '@/lib/auth/http/auth-http';
import resolveAccountRequestSession from '@/lib/auth/http/auth-request-session';
import sessionManagementService from '@/lib/auth/session/session-management-server';
import type { SessionRouteContext } from '@/types/auth';

/** Revokes one session owned by the authenticated account.
 * @param request - Incoming session revocation request.
 * @param context - Dynamic session route context.
 * @returns The revoked public session.
 */
export const DELETE = async (request: NextRequest, context: SessionRouteContext): Promise<Response> => {
	try {
		assertSameOrigin(request);

		const [currentSession, parameters] = await Promise.all([
			resolveAccountRequestSession(request),
			context.params
		]);

		const sessionId = readAuthenticationIdentifier(parameters.sessionId);

		const session = await sessionManagementService.revoke(currentSession.userId, sessionId, currentSession.id);

		const response = NextResponse.json({ session });

		if (session.isCurrent) {
			clearSessionCookies(response);
		}

		return response;
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};
