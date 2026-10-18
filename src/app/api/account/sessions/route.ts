import { NextRequest, NextResponse } from 'next/server';
import { assertSameOrigin, createAuthErrorResponse } from '@/lib/auth/http/auth-http';
import resolveAccountRequestSession from '@/lib/auth/http/auth-request-session';
import sessionManagementService from '@/lib/auth/session/session-management-server';

/** Lists the sessions owned by the authenticated account.
 * @param request - Incoming account session request.
 * @returns The public account sessions.
 */
export const GET = async (request: NextRequest): Promise<Response> => {
	try {
		const session = await resolveAccountRequestSession(request);

		const sessions = await sessionManagementService.list(session.userId, session.id);

		return NextResponse.json({ sessions });
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};

/** Revokes every other active session of the authenticated account.
 * @param request - Incoming account session revocation request.
 * @returns The number of sessions revoked.
 */
export const DELETE = async (request: NextRequest): Promise<Response> => {
	try {
		assertSameOrigin(request);

		const session = await resolveAccountRequestSession(request);

		const revokedSessionCount = await sessionManagementService.revokeOthers(session.userId, session.id);

		return NextResponse.json({ revokedSessionCount });
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};
