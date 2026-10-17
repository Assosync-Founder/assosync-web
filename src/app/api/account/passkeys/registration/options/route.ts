import { cookies } from 'next/headers';
import { type NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import AuthError from '@/lib/auth/shared/auth-error';
import {
	assertSameOrigin,
	createAuthErrorResponse,
	readRequiredAuthCookie,
	resolvePasskeyRelyingParty
} from '@/lib/auth/http/auth-http';
import resolveAccountRequestSession from '@/lib/auth/http/auth-request-session';
import passkeyService from '@/lib/auth/passkey/passkey-server';
import firebaseAdmin from '@/services/firebase/firebase-server';

/** Ensures the current Account session is recent enough for passkey enrollment.
 * @param createdAt - Authenticated session creation time.
 * @throws {AuthError} When the authentication is too old.
 */
const assertRecentAuthentication = (
	createdAt: Date
): void => {
	if (
		Date.now() - createdAt.getTime() >
		authConfig.session.maxAuthenticationAgeMs
	) {
		throw new AuthError(
			'session_expired',
			'A recent authentication is required to add a passkey.'
		);
	}
};

/** Creates passkey registration options for the authenticated account.
 * @param request - Authenticated Account request.
 * @returns Registration challenge and WebAuthn options.
 */
export const POST = async (request: NextRequest): Promise<Response> => {
	try {
		assertSameOrigin(request);
		const relyingParty = resolvePasskeyRelyingParty(request);

		const cookieStore = await cookies();
		const session = await resolveAccountRequestSession(request);

		assertRecentAuthentication(session.createdAt);

		const browserToken = readRequiredAuthCookie(
			cookieStore.get(authConfig.cookieNames.connection)?.value,
			'session_invalid'
		);
		const user = await firebaseAdmin.auth.getUser(session.userId);

		if (!user.email) {
			return NextResponse.json({ error: 'identity_invalid' }, { status: 400 });
		}

		const issued = await passkeyService.createRegistrationOptions(
			session.userId,
			user.email,
			browserToken,
			relyingParty
		);

		return NextResponse.json(issued, {
			headers: { 'Cache-Control': 'no-store' }
		});
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request, 'passkey_registration_options');
	}
};
