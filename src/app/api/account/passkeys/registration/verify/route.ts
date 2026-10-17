import { cookies, headers } from 'next/headers';
import { type NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import detectDeviceInformation from '@/lib/auth/device/device-detection';
import AuthError from '@/lib/auth/shared/auth-error';
import {
	assertSameOrigin,
	createAuthErrorResponse,
	readAuthenticationIdentifier,
	readJsonBody,
	readRequiredAuthCookie,
	resolvePasskeyRelyingParty
} from '@/lib/auth/http/auth-http';
import resolveAccountRequestSession from '@/lib/auth/http/auth-request-session';
import { readRegistrationResponse } from '@/lib/auth/passkey/passkey-http';
import passkeyService from '@/lib/auth/passkey/passkey-server';

const MAXIMUM_PASSKEY_NAME_LENGTH = 80;

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

/** Creates a safe default passkey name from server-detected browser data.
 * @param headers - Registration request headers.
 * @returns Browser-specific French passkey label.
 */
const createDefaultPasskeyName = (headers: Headers): string => {
	const browserName = detectDeviceInformation(headers).browserName;
	const displayName = browserName
		? `Clé d’accès ${browserName}`
		: 'Clé d’accès';

	return displayName.slice(0, MAXIMUM_PASSKEY_NAME_LENGTH);
};

/** Verifies and stores a passkey for the authenticated account.
 * @param request - Authenticated registration response.
 * @returns Public identifier of the registered passkey.
 */
export const POST = async (request: NextRequest): Promise<Response> => {
	try {
		assertSameOrigin(request);
		const relyingParty = resolvePasskeyRelyingParty(request);

		const [cookieStore, headerStore, session, body] = await Promise.all([
			cookies(),
			headers(),
			resolveAccountRequestSession(request),
			readJsonBody(request)
		]);
		const browserToken = readRequiredAuthCookie(
			cookieStore.get(authConfig.cookieNames.connection)?.value,
			'session_invalid'
		);

		assertRecentAuthentication(session.createdAt);

		const passkey = await passkeyService.verifyRegistration(
			{
				userId: session.userId,
				challengeId: readAuthenticationIdentifier(body.challengeId),
				browserToken,
				displayName: createDefaultPasskeyName(headerStore),
				response: readRegistrationResponse(body.response)
			},
			relyingParty
		);

		return NextResponse.json({ passkeyId: passkey.id }, { status: 201 });
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request, 'passkey_registration_verify');
	}
};
