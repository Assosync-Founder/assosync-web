import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import authConfig from '@/config/auth';
import ConfirmDeviceView from '@/components/account/device/ConfirmDeviceView';
import webAuthorizationService from '@/lib/auth/web/authorization-server';
import type { WebAuthorizationRequest } from '@/types/auth';

const AUTHENTICATION_IDENTIFIER_PATTERN =
	/^[A-Za-z0-9_-]{1,128}$/u;

/**
 * Validates an authentication identifier received through the URL.
 * @param value - Query parameter value.
 * @returns The validated identifier or null.
 */
const readIdentifier = (
	value: string | string[] | undefined
): string | null => {
	if (
		typeof value !== 'string' ||
		!AUTHENTICATION_IDENTIFIER_PATTERN.test(value)
	) {
		return null;
	}

	return value;
};

/**
 * Resolves an authorization active and bound to the browser.
 * @param authorizationId - Web authorization identifier.
 * @param browserToken - Browser authorization secret.
 * @returns The active authorization or null.
 */
const resolveActiveAuthorization = async (
	authorizationId: string,
	browserToken: string
): Promise<WebAuthorizationRequest | null> => {
	try {
		return await webAuthorizationService.resolve(
			authorizationId,
			browserToken
		);
	} catch (error: unknown) {
		console.warn(
			'Rejected access to the device confirmation page.',
			error instanceof Error
				? error.name
				: 'UnknownError'
		);

		return null;
	}
};

const ConfirmDevicePage = async ({
	searchParams
}: PageProps<'/account/confirm-device'>) => {
	const parameters = await searchParams;

	const authorizationId = readIdentifier(parameters.authorization);
	const deviceId = readIdentifier(parameters.device);
	const verificationId = readIdentifier(parameters.verification);

	if (!authorizationId || !deviceId || !verificationId) {
		redirect(authConfig.routes.accountLogin);
	}

	const cookieStore = await cookies();

	const authorizationToken = cookieStore.get(authConfig.cookieNames.webAuthorization)?.value;
	const verificationToken = cookieStore.get(authConfig.cookieNames.deviceVerification)?.value;
	const deviceToken = cookieStore.get(authConfig.cookieNames.device)?.value;

	if (!authorizationToken || !verificationToken || !deviceToken) {
		redirect(authConfig.routes.accountLogin);
	}

	const authorization = await resolveActiveAuthorization(
		authorizationId,
		authorizationToken
	);

	if (!authorization) {
		redirect(authConfig.routes.accountLogin);
	}

	const client = authConfig.webSso.clients.find((candidate) => {
		return candidate.id === authorization.applicationId;
	});

	if (!client) {
		redirect(authConfig.routes.accountLogin);
	}

	return (
		<ConfirmDeviceView
			authorizationId={authorizationId}
			deviceId={deviceId}
			verificationId={verificationId}
			restartUri={client.loginUri}
		/>
	);
};

export default ConfirmDevicePage;
