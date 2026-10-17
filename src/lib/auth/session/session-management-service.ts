import 'server-only';

import { systemClock } from '@/lib/auth/shared/runtime-server';
import SessionService from '@/lib/auth/session/session-service';
import type {
	AccountSession,
	Clock,
	Session
} from '@/types/auth';

/** Provides account-facing session management without exposing token hashes. */
class SessionManagementService {
	/**
	 * Creates an account session management service.
	 * @param sessions - Application session service.
	 * @param clock - Time provider used to derive active state.
	 */
	constructor(
		private readonly sessions: SessionService,
		private readonly clock: Clock = systemClock
	) {}

	/**
	 * Lists sessions without exposing their owner or token hash.
	 * @param userId - Firebase user owning the sessions.
	 * @param currentSessionId - Session making the request.
	 * @returns Public account sessions.
	 */
	readonly list = async (
		userId: string,
		currentSessionId: string
	): Promise<readonly AccountSession[]> => {
		const sessions = await this.sessions.list(userId);
		const now = this.clock.now();

		return sessions.map((session) => {
			return this.toAccountSession(
				session,
				currentSessionId,
				now
			);
		});
	};

	/**
	 * Revokes one account-owned session.
	 * @param userId - Firebase user owning the session.
	 * @param sessionId - Session to revoke.
	 * @param currentSessionId - Session making the request.
	 * @returns The revoked public session.
	 */
	readonly revoke = async (
		userId: string,
		sessionId: string,
		currentSessionId: string
	): Promise<AccountSession> => {
		const session = await this.sessions.revokeOwned(
			userId,
			sessionId
		);

		return this.toAccountSession(
			session,
			currentSessionId,
			this.clock.now()
		);
	};

	/**
	 * Revokes all other active sessions while retaining the current one.
	 * @param userId - Firebase user owning the sessions.
	 * @param currentSessionId - Session that must remain active.
	 * @returns The number of sessions revoked.
	 */
	readonly revokeOthers = async (
		userId: string,
		currentSessionId: string
	): Promise<number> => {
		return this.sessions.revokeOthers(
			userId,
			currentSessionId
		);
	};

	/**
	 * Removes private fields and derives account-facing session state.
	 * @param session - Internal application session.
	 * @param currentSessionId - Session making the request.
	 * @param now - Time used to evaluate expiration.
	 * @returns The public account session.
	 */
	private readonly toAccountSession = (
		session: Session,
		currentSessionId: string,
		now: Date
	): AccountSession => {
		return {
			id: session.id,
			deviceId: session.deviceId,
			applicationId: session.applicationId,
			createdAt: session.createdAt,
			expiresAt: session.expiresAt,
			lastSeenAt: session.lastSeenAt,
			revokedAt: session.revokedAt,
			isCurrent: session.id === currentSessionId,
			isActive:
				session.revokedAt === null &&
				session.expiresAt.getTime() > now.getTime()
		};
	};
}

export default SessionManagementService;
