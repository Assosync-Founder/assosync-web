import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import authConfig from '@/config/auth';
import PasskeyAuthenticationView from '@/core/auth/views/PasskeyAuthenticationView';
import createAuthenticationFlashRelayUri from '@/lib/auth/web/authentication-flash-relay';
import webAuthorizationService from '@/lib/auth/web/authorization-server';
import type { PasskeyPageProps } from '@/types/passkey';

/** Resolves the trusted product failure endpoint for an SSO authorization.
 * @param authorizationId - Active Web authorization identifier.
 * @param browserToken - Browser-bound authorization secret.
 * @returns Configured failure endpoint, or null for an invalid authorization.
 */
const resolveFailureUri = async (
	authorizationId: string,
	browserToken: string
): Promise<string | null> => {
	try {
		const authorization = await webAuthorizationService.resolve(
			authorizationId,
			browserToken
		);
		const client = authConfig.webSso.clients.find((candidate) => {
			return candidate.id === authorization.applicationId;
		});

		if (!client) {
			return null;
		}

		const authenticationFlashUri = new URL(
			'/api/auth/flash',
			authorization.redirectUri
		).toString();

		return await createAuthenticationFlashRelayUri(
			client,
			'passkey_authentication_failed',
			authConfig.passkey.challengeLifetimeMs,
			authenticationFlashUri
		);
	} catch (error: unknown) {
		console.error(JSON.stringify({
			event: 'passkey_failure_uri_resolution_failure',
			errorName: error instanceof Error ? error.name : 'UnknownError'
		}));

		return null;
	}
};

/** Renders the Account-hosted WebAuthn ceremony.
 * @param searchParams - Passkey authorization query parameters.
 * @returns Transitional passkey authentication page.
 */
const PasskeyPage = async ({ searchParams }: PasskeyPageProps) => {
	const parameters = await searchParams;
	const authorizationId = parameters.authorization;

	if (
		typeof authorizationId !== 'string' ||
		!/^[A-Za-z0-9_-]{1,128}$/u.test(authorizationId)
	) {
		redirect('/login');
	}

	const cookieStore = await cookies();
	const browserToken = cookieStore.get(
		authConfig.cookieNames.webAuthorization
	)?.value;

	if (!browserToken) {
		redirect('/login');
	}

	const failureUri = await resolveFailureUri(
		authorizationId,
		browserToken
	);

	if (!failureUri) {
		redirect('/login');
	}

	return (
		<PasskeyAuthenticationView
			authorizationId={authorizationId}
			failureUri={failureUri}
		/>
	);
};

export default PasskeyPage;
