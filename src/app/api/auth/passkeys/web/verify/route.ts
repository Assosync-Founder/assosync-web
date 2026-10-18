import { type NextRequest, NextResponse } from 'next/server';
import { assertAccountHostname, createAuthErrorResponse, readAuthenticationIdentifier, readJsonBody } from '@/lib/auth/http/auth-http';
import { readAuthenticationResponse } from '@/lib/auth/passkey/passkey-http';
import { resolvePasskeyWebAuthorization } from '@/lib/auth/passkey/passkey-web-http';
import passkeyService from '@/lib/auth/passkey/passkey-server';
import webAuthorizationService from '@/lib/auth/web/authorization-server';
import firebaseAdmin from '@/services/firebase/firebase-server';

/** Verifies an assertion created on a registered product origin.
 * @param request - Authenticated server-to-server assertion request.
 * @returns A short-lived Firebase custom token for identity binding.
 */
export const POST = async (request: NextRequest): Promise<Response> => {
	try {
		assertAccountHostname(request);

		const body = await readJsonBody(request);
		const context = await resolvePasskeyWebAuthorization(body);
		const challengeId = readAuthenticationIdentifier(body.challengeId);
		const userId = await passkeyService.verifyAuthentication(
			{
				authorizationId: context.authorizationId,
				challengeId,
				browserToken: context.browserToken,
				response: readAuthenticationResponse(body.response)
			},
			context.relyingParty
		);
		const user = await firebaseAdmin.auth.getUser(userId);

		if (user.disabled) {
			return NextResponse.json({ error: 'authentication_failed' }, { status: 401, headers: { 'Cache-Control': 'no-store' } });
		}

		const customToken = await firebaseAdmin.auth.createCustomToken(userId);

		await webAuthorizationService.bindPasskeyUser(context.authorizationId, context.browserToken, userId);

		return NextResponse.json({ customToken }, { headers: { 'Cache-Control': 'no-store' } });
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request, 'passkey_web_verify');
	}
};
