import { cookies } from 'next/headers';
import { type NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import {
	assertAccountHostname,
	createAuthErrorResponse,
	readAuthenticationIdentifier,
	readRequiredAuthCookie,
	resolvePasskeyRelyingParty
} from '@/lib/auth/http/auth-http';
import passkeyService from '@/lib/auth/passkey/passkey-server';
import resolveAuthenticationRequestContext, {
	requireWebAuthorization
} from '@/lib/auth/web/authorization-http';

/** Generates WebAuthn assertion options for an active SSO request.
 * @param request - Account browser request.
 * @returns One-time challenge and browser options.
 */
export const GET = async (request: NextRequest): Promise<Response> => {
	try {
		assertAccountHostname(request);
		const relyingParty = resolvePasskeyRelyingParty(request);

		const cookieStore = await cookies();
		const authorizationId = readAuthenticationIdentifier(
			request.nextUrl.searchParams.get('authorization')
		);
		const context = await resolveAuthenticationRequestContext(
			request,
			authorizationId
		);
		requireWebAuthorization(context);
		const browserToken = readRequiredAuthCookie(
			cookieStore.get(authConfig.cookieNames.webAuthorization)?.value,
			'authorization_invalid'
		);
		const issued = await passkeyService.createAuthenticationOptions(
			authorizationId,
			browserToken,
			relyingParty
		);

		return NextResponse.json(issued, {
			headers: { 'Cache-Control': 'no-store' }
		});
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request, 'passkey_options');
	}
};
