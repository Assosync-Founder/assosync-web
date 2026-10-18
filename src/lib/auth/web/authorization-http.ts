import 'server-only';

import type { NextRequest } from 'next/server';
import authConfig from '@/config/auth';
import { AuthHttpError, readRequiredString, resolveApplicationId } from '@/lib/auth/http/auth-http';
import webAuthorizationService from '@/lib/auth/web/authorization-server';
import type { AuthenticationRequestContext, WebAuthorizationRequest } from '@/types/auth';

/** Resolves a trusted local or Web SSO authentication context.
 * @param request - Incoming Account request.
 * @param authorizationId - Optional Web authorization request identifier.
 * @returns Trusted application context.
 */
const resolveAuthenticationRequestContext = async (request: NextRequest, authorizationId: string | null): Promise<AuthenticationRequestContext> => {
	if (!authorizationId) {
		return {
			applicationId: resolveApplicationId(request),
			webAuthorization: null
		};
	}

	const browserToken = request.cookies.get(authConfig.cookieNames.webAuthorization)?.value;

	if (!browserToken) {
		throw new AuthHttpError(400, 'authorization_invalid');
	}

	const webAuthorization = await webAuthorizationService.resolve(authorizationId, browserToken);

	return {
		applicationId: webAuthorization.applicationId,
		webAuthorization
	};
};

/** Resolves the Firebase ID token from a local body or a bound Web authorization.
 * @param body - Validated JSON request body.
 * @param context - Trusted authentication request context.
 * @returns A fresh Firebase ID token.
 */
const resolveAuthenticationIdToken = (body: Record<string, unknown>, context: AuthenticationRequestContext): string => {
	if (context.webAuthorization) {
		const idToken = context.webAuthorization.identity.idToken;

		if (!idToken) {
			throw new AuthHttpError(400, 'authorization_invalid');
		}

		return idToken;
	}

	return readRequiredString(body, 'idToken');
};

/** Requires an active Web authorization from a resolved request context.
 * @param context - Trusted authentication request context.
 * @returns The active Web authorization.
 * @throws {AuthHttpError} When the request is not a Web authorization.
 */
const requireWebAuthorization = (context: AuthenticationRequestContext): WebAuthorizationRequest => {
	if (!context.webAuthorization) {
		throw new AuthHttpError(400, 'authorization_invalid');
	}

	return context.webAuthorization;
};

export default resolveAuthenticationRequestContext;

export {
	requireWebAuthorization,
	resolveAuthenticationIdToken
};
