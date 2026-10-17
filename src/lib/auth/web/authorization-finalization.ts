import 'server-only';

import sessionService from '@/lib/auth/session/session-server';
import { logAuthServerError } from '@/lib/auth/shared/auth-logger';
import webAuthorizationService from '@/lib/auth/web/authorization-server';
import type {
	FinalizedWebAuthorization,
	FinalizeWebAuthorizationInput
} from '@/types/auth';

/** Finalizes Web authorization and establishes the parallel Account session.
 * @param input - Browser-bound request and newly issued session.
 * @returns The registered callback destination and Account session.
 */
const finalizeWebAuthorization = async (
	input: FinalizeWebAuthorizationInput
): Promise<FinalizedWebAuthorization> => {
	let accountSession:
		FinalizedWebAuthorization['accountSession'] | null = null;

	try {
		accountSession = await sessionService.issue({
			idToken: input.idToken,
			deviceId: input.issuedSession.session.deviceId,
			deviceToken: input.deviceToken,
			applicationId: 'assosync'
		});

		const completed = await webAuthorizationService.complete(input);

		return {
			...completed,
			accountSession
		};
	} catch (error: unknown) {
		const sessions = accountSession
			? [input.issuedSession, accountSession]
			: [input.issuedSession];

		for (const issuedSession of sessions) {
			try {
				await sessionService.revoke({
					userId: issuedSession.session.userId,
					sessionId: issuedSession.session.id,
					applicationId:
						issuedSession.session.applicationId
				});
			} catch (cleanupError: unknown) {
				logAuthServerError(
					cleanupError,
					'web_authorization_session_cleanup'
				);
			}
		}

		throw error;
	}
};

export default finalizeWebAuthorization;
