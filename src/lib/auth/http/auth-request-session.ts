import 'server-only';

import type { NextRequest } from 'next/server';
import authConfig from '@/config/auth';
import {
	assertAccountHostname,
	AuthHttpError,
	resolveApplicationId
} from '@/lib/auth/http/auth-http';
import sessionService from '@/lib/auth/session/session-server';
import type { Session } from '@/types/auth';

/**
 * Resolves the authenticated session of an account request.
 * @param request - Incoming account request.
 * @returns The verified application session.
 * @throws {AuthHttpError} When authentication cookies are missing.
 */
const resolveAccountRequestSession = async (
	request: NextRequest
): Promise<Session> => {
	assertAccountHostname(request);

	const applicationId = resolveApplicationId(request);

	const firebaseSessionCookie = request.cookies.get(
		authConfig.cookieNames.session
	)?.value;

	const sessionToken = request.cookies.get(
		authConfig.cookieNames.connection
	)?.value;

	if (!firebaseSessionCookie || !sessionToken) {
		throw new AuthHttpError(
			401,
			'session_invalid'
		);
	}

	return sessionService.verify({
		firebaseSessionCookie,
		sessionToken,
		applicationId
	});
};

export default resolveAccountRequestSession;
