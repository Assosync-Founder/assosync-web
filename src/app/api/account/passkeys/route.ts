import { type NextRequest, NextResponse } from 'next/server';
import resolveAccountRequestSession from '@/lib/auth/http/auth-request-session';
import {
	createAuthErrorResponse
} from '@/lib/auth/http/auth-http';
import passkeyService from '@/lib/auth/passkey/passkey-server';

/** Lists passkeys owned by the authenticated Account user.
 * @param request - Incoming Account passkey request.
 * @returns Public passkey metadata without WebAuthn secrets.
 */
export const GET = async (
	request: NextRequest
): Promise<Response> => {
	try {
		const session = await resolveAccountRequestSession(request);
		const passkeys = await passkeyService.list(session.userId);

		return NextResponse.json({ passkeys });
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};
