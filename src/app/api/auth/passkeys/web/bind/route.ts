import { type NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import { assertAccountHostname, createAuthErrorResponse, readJsonBody, readRequiredString } from '@/lib/auth/http/auth-http';
import { resolvePasskeyWebAuthorization } from '@/lib/auth/passkey/passkey-web-http';
import authenticationService from '@/lib/auth/authentication/authentication-server';
import webAuthorizationService from '@/lib/auth/web/authorization-server';

/** Binds the fresh Firebase identity created after a product-hosted assertion.
 * @param request - Authenticated server-to-server identity request.
 * @returns One-time Account continuation URL.
 */
export const POST = async (request: NextRequest): Promise<Response> => {
	try {
		assertAccountHostname(request);

		const body = await readJsonBody(request);
		const context = await resolvePasskeyWebAuthorization(body);
		const idToken = readRequiredString(body, 'idToken');
		const identity = await authenticationService.verifyIdentity(idToken);

		if (identity.userId !== context.authorization.identity.userId) {
			return NextResponse.json({ error: 'authentication_failed' }, { status: 401, headers: { 'Cache-Control': 'no-store' } });
		}

		const handoff = await webAuthorizationService.issueHandoff(context.authorizationId, context.browserToken);

		await webAuthorizationService.bindPasskeyIdentityToken(context.authorizationId, context.browserToken, identity.userId, idToken);

		const continuationUrl = new URL('/api/auth/web/resume', authConfig.passkey.expectedOrigin);

		continuationUrl.searchParams.set('ticket', handoff.ticket);

		return NextResponse.json({ continuationUrl: continuationUrl.toString() }, { headers: { 'Cache-Control': 'no-store' } });
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request, 'passkey_web_bind');
	}
};
