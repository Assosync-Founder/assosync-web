import { cookies } from 'next/headers';
import {
	NextRequest,
	NextResponse
} from 'next/server';
import authConfig from '@/config/auth';
import {
	clearSessionCookies
} from '@/lib/auth/http/auth-cookies';
import {
	assertSameOrigin,
	createAuthErrorResponse,
	resolveApplicationId
} from '@/lib/auth/http/auth-http';
import AuthError from '@/lib/auth/shared/auth-error';
import sessionService from '@/lib/auth/session/session-server';
import type { Session } from '@/types/auth';

/**
 * Resolves the current session when its authentication cookies remain valid.
 * @param firebaseSessionCookie - Signed Firebase session cookie.
 * @param sessionToken - Raw application session token.
 * @param applicationId - Expected application identifier.
 * @returns The verified session, or null for an expected authentication failure.
 */
const resolveCurrentSession = async (
	firebaseSessionCookie: string,
	sessionToken: string,
	applicationId: string
): Promise<Session | null> => {
	try {
		return await sessionService.verify({
			firebaseSessionCookie,
			sessionToken,
			applicationId
		});
	} catch (error: unknown) {
		if (error instanceof AuthError) {
			return null;
		}

		return Promise.reject(error);
	}
};

/** Revokes the current application session and clears its cookies.
 * @param request - Incoming logout request.
 * @returns An empty successful response.
 */
export const POST = async (
	request: NextRequest
): Promise<Response> => {
	try {
		assertSameOrigin(request);

		const applicationId = resolveApplicationId(request);
		const cookieStore = await cookies();

		const firebaseSessionCookie = cookieStore.get(authConfig.cookieNames.session)?.value;
		const sessionToken = cookieStore.get(authConfig.cookieNames.connection)?.value;

		if (firebaseSessionCookie && sessionToken) {
			const session = await resolveCurrentSession(
				firebaseSessionCookie,
				sessionToken,
				applicationId
			);

			if (session) {
				await sessionService.revoke({
					userId: session.userId,
					sessionId: session.id,
					applicationId
				});
			}
		}

		const response = new NextResponse(null, { status: 204 });

		clearSessionCookies(response);

		return response;
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};
