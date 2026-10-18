import { type NextRequest, NextResponse } from 'next/server';
import authenticationService from '@/lib/auth/authentication/authentication-server';
import { assertSameOrigin, createAuthErrorResponse, readAuthenticationIdentifier, readJsonBody, readOptionalString } from '@/lib/auth/http/auth-http';
import resolveAuthenticationRequestContext, { resolveAuthenticationIdToken } from '@/lib/auth/web/authorization-http';

/** Returns device verification channels available to a Firebase identity.
 * @param request - Incoming authenticated browser request.
 * @returns The available verification modes.
 */
export const POST = async (request: NextRequest): Promise<Response> => {
	try {
		assertSameOrigin(request);

		const body = await readJsonBody(request);
		const authorizationValue = readOptionalString(body, 'authorizationId', 128);
		const authorizationId = authorizationValue
			? readAuthenticationIdentifier(authorizationValue)
			: null;
		const authenticationContext = await resolveAuthenticationRequestContext(request, authorizationId);
		const idToken = resolveAuthenticationIdToken(body, authenticationContext);
		const verificationModes = await authenticationService.getAvailableVerificationModes(idToken, authenticationContext.applicationId);

		if (authenticationContext.webAuthorization) {
			return NextResponse.json({
				verificationModes: verificationModes.filter((mode) => {
					return mode === 'email_code';
				})
			});
		}

		return NextResponse.json({ verificationModes });
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};
