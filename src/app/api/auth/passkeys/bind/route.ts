import { cookies } from 'next/headers';
import { type NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import authenticationService from '@/lib/auth/authentication/authentication-server';
import {
	assertAccountHostname,
	assertSameOrigin,
	createAuthErrorResponse,
	readAuthenticationIdentifier,
	readJsonBody,
	readRequiredAuthCookie,
	readRequiredString,
	resolveRequestOrigin
} from '@/lib/auth/http/auth-http';
import resolveAuthenticationRequestContext, {
	requireWebAuthorization
} from '@/lib/auth/web/authorization-http';
import webAuthorizationService from '@/lib/auth/web/authorization-server';

/** Binds the Firebase ID token obtained from a verified passkey to SSO.
 * @param request - Same-origin Account browser request.
 * @returns Continuation URL for the existing device-trust flow.
 */
export const POST = async (request: NextRequest): Promise<Response> => {
	try {
		assertAccountHostname(request);

		assertSameOrigin(request);

		const cookieStore = await cookies();
		const body = await readJsonBody(request);
		const authorizationId = readAuthenticationIdentifier(body.authorizationId);
		const idToken = readRequiredString(body, 'idToken');
		const context = await resolveAuthenticationRequestContext(
			request,
			authorizationId
		);
		const authorization = requireWebAuthorization(context);
		const identity = await authenticationService.verifyIdentity(idToken);

		if (identity.userId !== authorization.identity.userId) {
			return NextResponse.json({ error: 'authentication_failed' }, { status: 401 });
		}

		const browserToken = readRequiredAuthCookie(
			cookieStore.get(authConfig.cookieNames.webAuthorization)?.value,
			'authorization_invalid'
		);

		await webAuthorizationService.bindPasskeyIdentityToken(
			authorizationId,
			browserToken,
			identity.userId,
			idToken
		);

		const continuationUrl = new URL(
			'/api/auth/web/continue',
			resolveRequestOrigin(request)
		);
		continuationUrl.searchParams.set('authorization', authorizationId);

		return NextResponse.json({ continuationUrl: continuationUrl.toString() });
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request, 'passkey_bind');
	}
};
