import { type NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import { assertAccountHostname, createAuthErrorResponse, readJsonBody } from '@/lib/auth/http/auth-http';
import { resolvePasskeyWebAuthorization } from '@/lib/auth/passkey/passkey-web-http';
import webAuthorizationService from '@/lib/auth/web/authorization-server';

/** Moves an unsupported related-origin ceremony to the Account origin.
 * @param request - Authenticated server-to-server fallback request.
 * @returns One-time Account continuation URL.
 */
export const POST = async (request: NextRequest): Promise<Response> => {
	try {
		assertAccountHostname(request);

		const body = await readJsonBody(request);
		const context = await resolvePasskeyWebAuthorization(body);
		const handoff = await webAuthorizationService.issueHandoff(context.authorizationId, context.browserToken);
		const continuationUrl = new URL('/api/auth/web/resume', authConfig.passkey.expectedOrigin);

		continuationUrl.searchParams.set('ticket', handoff.ticket);

		return NextResponse.json({ continuationUrl: continuationUrl.toString() }, { headers: { 'Cache-Control': 'no-store' } });
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request, 'passkey_web_fallback');
	}
};
