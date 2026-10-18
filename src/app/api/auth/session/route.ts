import { cookies } from 'next/headers';
import { NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import { clearSessionCookies } from '@/lib/auth/http/auth-cookies';
import { createAuthErrorResponse, resolveApplicationId } from '@/lib/auth/http/auth-http';
import sessionService from '@/lib/auth/session/session-server';

/** Verifies the current authenticated session.
 * @param request - Incoming session request.
 * @returns Public information about the active session.
 */
export const GET = async (request: NextRequest): Promise<Response> => {
	try {
		const applicationId = resolveApplicationId(request);
		const cookieStore = await cookies();

		const firebaseSessionCookie = cookieStore.get(authConfig.cookieNames.session)?.value;
		const sessionToken = cookieStore.get(authConfig.cookieNames.connection)?.value;

		if (!firebaseSessionCookie || !sessionToken) {
			const response = NextResponse.json({ error: 'session_invalid' }, { status: 401 });

			clearSessionCookies(response);

			return response;
		}

		const session = await sessionService.verify({
			firebaseSessionCookie,
			sessionToken,
			applicationId
		});

		return NextResponse.json({
			authenticated: true,
			userId: session.userId,
			sessionId: session.id,
			deviceId: session.deviceId,
			expiresAt: session.expiresAt.toISOString()
		});
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};
