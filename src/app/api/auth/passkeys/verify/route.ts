import { cookies } from 'next/headers';
import { type NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import {
	assertAccountHostname,
	assertSameOrigin,
	createAuthErrorResponse,
	readAuthenticationIdentifier,
	readJsonBody,
	readRequiredAuthCookie,
	resolvePasskeyRelyingParty
} from '@/lib/auth/http/auth-http';
import { readAuthenticationResponse } from '@/lib/auth/passkey/passkey-http';
import passkeyService from '@/lib/auth/passkey/passkey-server';
import resolveAuthenticationRequestContext, {
	requireWebAuthorization
} from '@/lib/auth/web/authorization-http';
import webAuthorizationService from '@/lib/auth/web/authorization-server';
import firebaseAdmin from '@/services/firebase/firebase-server';

/** Verifies a passkey assertion and returns a Firebase custom token.
 * @param request - Browser assertion request.
 * @returns Short-lived Firebase custom token.
 */
export const POST = async (request: NextRequest): Promise<Response> => {
	try {
		assertAccountHostname(request);
		const relyingParty = resolvePasskeyRelyingParty(request);

		assertSameOrigin(request);

		const cookieStore = await cookies();
		const body = await readJsonBody(request);
		const authorizationId = readAuthenticationIdentifier(body.authorizationId);
		const challengeId = readAuthenticationIdentifier(body.challengeId);
		const context = await resolveAuthenticationRequestContext(
			request,
			authorizationId
		);
		requireWebAuthorization(context);
		const browserToken = readRequiredAuthCookie(
			cookieStore.get(authConfig.cookieNames.webAuthorization)?.value,
			'authorization_invalid'
		);
		const userId = await passkeyService.verifyAuthentication(
			{
				authorizationId,
				challengeId,
				browserToken,
				response: readAuthenticationResponse(body.response)
			},
			relyingParty
		);

		const user = await firebaseAdmin.auth.getUser(userId);

		if (user.disabled) {
			return NextResponse.json(
				{ error: 'authentication_failed' },
				{ status: 401, headers: { 'Cache-Control': 'no-store' } }
			);
		}

		const customToken = await firebaseAdmin.auth.createCustomToken(userId);

		await webAuthorizationService.bindPasskeyUser(
			authorizationId,
			browserToken,
			userId
		);

		return NextResponse.json({ customToken }, {
			headers: { 'Cache-Control': 'no-store' }
		});
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request, 'passkey_verify');
	}
};
