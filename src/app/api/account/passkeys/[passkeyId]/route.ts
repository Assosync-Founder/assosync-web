import { type NextRequest, NextResponse } from 'next/server';
import {
	assertSameOrigin,
	createAuthErrorResponse,
	readAuthenticationIdentifier,
	readJsonBody,
	readRequiredString
} from '@/lib/auth/http/auth-http';
import resolveAccountRequestSession from '@/lib/auth/http/auth-request-session';
import passkeyService from '@/lib/auth/passkey/passkey-server';
import type { PasskeyRouteContext } from '@/types/passkey';

/** Renames one passkey owned by the authenticated account.
 * @param request - Incoming Account passkey update request.
 * @param context - Dynamic passkey route context.
 * @returns Updated public passkey metadata.
 */
export const PATCH = async (
	request: NextRequest,
	context: PasskeyRouteContext
): Promise<Response> => {
	try {
		assertSameOrigin(request);

		const [session, parameters, body] = await Promise.all([
			resolveAccountRequestSession(request),
			context.params,
			readJsonBody(request)
		]);
		const passkeyId = readAuthenticationIdentifier(
			parameters.passkeyId
		);
		const displayName = readRequiredString(
			body,
			'displayName',
			80
		).trim();
		const passkey = await passkeyService.rename(
			session.userId,
			passkeyId,
			displayName
		);

		return NextResponse.json({ passkey });
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};

/** Deletes one passkey owned by the authenticated account.
 * @param request - Incoming Account passkey deletion request.
 * @param context - Dynamic passkey route context.
 * @returns An empty successful response.
 */
export const DELETE = async (
	request: NextRequest,
	context: PasskeyRouteContext
): Promise<Response> => {
	try {
		assertSameOrigin(request);

		const [session, parameters] = await Promise.all([
			resolveAccountRequestSession(request),
			context.params
		]);
		const passkeyId = readAuthenticationIdentifier(
			parameters.passkeyId
		);

		await passkeyService.delete(session.userId, passkeyId);

		return new NextResponse(null, { status: 204 });
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};
