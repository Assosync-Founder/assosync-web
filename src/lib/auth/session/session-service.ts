import 'server-only';

import SecurityEventService from '@/lib/auth/audit/security-event-service';
import DeviceService from '@/lib/auth/device/device-service';
import AuthError from '@/lib/auth/shared/auth-error';
import {
	secureTokenGenerator,
	sha256TokenHasher,
	systemClock
} from '@/lib/auth/shared/runtime-server';
import type {
	Clock,
	CreateSessionInput,
	FirebaseSessionAdapter,
	IssuedSession,
	IssueSessionInput,
	RevokeSessionInput,
	Session,
	SessionRepository,
	SessionServiceOptions,
	TokenGenerator,
	TokenHasher,
	VerifySessionInput
} from '@/types/auth';

/** Coordinates Firebase sessions with revocable application sessions. */
class SessionService {
	/**
	 * Creates an application session service.
	 * @param repository - Account-scoped session repository.
	 * @param firebase - Firebase session cookie adapter.
	 * @param devices - Trusted device service.
	 * @param securityEvents - Secret-free security event recorder.
	 * @param options - Session security settings.
	 * @param clock - Time provider.
	 * @param tokenGenerator - Opaque token generator.
	 * @param tokenHasher - Token hashing adapter.
	 */
	constructor(
		private readonly repository: SessionRepository,
		private readonly firebase: FirebaseSessionAdapter,
		private readonly devices: DeviceService,
		private readonly securityEvents: SecurityEventService,
		private readonly options: SessionServiceOptions,
		private readonly clock: Clock = systemClock,
		private readonly tokenGenerator: TokenGenerator =
		secureTokenGenerator,
		private readonly tokenHasher: TokenHasher =
		sha256TokenHasher
	) {
		if (
			!Number.isSafeInteger(options.lifetimeMs) ||
			options.lifetimeMs <= 0
		) {
			throw new RangeError(
				'Session lifetime must be a positive integer.'
			);
		}
	}

	/**
	 * Issues matching Firebase and application sessions.
	 * @param input - Authenticated session issuance input.
	 * @returns The signed Firebase cookie and application session token.
	 * @throws {AuthError} When the device or Firebase identity is invalid.
	 */
	readonly issue = async (
		input: IssueSessionInput
	): Promise<IssuedSession> => {
		this.assertRequiredValue(
			input.idToken,
			'The Firebase ID token is required.'
		);

		this.assertRequiredValue(
			input.deviceId,
			'The device identifier is required.'
		);

		this.assertRequiredValue(
			input.deviceToken,
			'The device token is required.'
		);

		this.assertRequiredValue(
			input.applicationId,
			'The application identifier is required.'
		);

		const firebaseSession = await this.firebase.create(
			input.idToken,
			this.options.lifetimeMs
		);

		const device = await this.devices.recognize(
			firebaseSession.identity.userId,
			input.deviceToken
		);

		if (
			device.id !== input.deviceId ||
			device.status !== 'verified'
		) {
			throw new AuthError(
				'device_not_verified',
				'The browser device is not verified.'
			);
		}

		const now = this.clock.now();

		if (
			firebaseSession.identity.expiresAt.getTime() <=
			now.getTime()
		) {
			throw new AuthError(
				'session_expired',
				'The Firebase session has expired.'
			);
		}

		const sessionToken =
			this.tokenGenerator.generate();

		const session: CreateSessionInput = {
			tokenHash: this.tokenHasher.hash(sessionToken),
			userId: firebaseSession.identity.userId,
			deviceId: device.id,
			applicationId: input.applicationId,
			createdAt: now,
			expiresAt: firebaseSession.identity.expiresAt,
			lastSeenAt: now,
			revokedAt: null
		};

		const persistedSession =
			await this.repository.create(session);

		await this.securityEvents.record({
			userId: persistedSession.userId,
			type: 'session_created',
			applicationId: persistedSession.applicationId,
			deviceId: persistedSession.deviceId,
			sessionId: persistedSession.id,
			affectedCount: 1
		});

		return {
			session: persistedSession,
			sessionToken,
			firebaseSessionCookie: firebaseSession.cookie
		};
	};

	/**
	 * Verifies Firebase, application session, and trusted device state.
	 * @param input - Authentication cookies and expected application.
	 * @returns The verified and refreshed application session.
	 * @throws {AuthError} When the session is invalid, expired, or revoked.
	 */
	readonly verify = async (
		input: VerifySessionInput
	): Promise<Session> => {
		this.assertRequiredValue(
			input.firebaseSessionCookie,
			'The Firebase session cookie is required.'
		);

		this.assertRequiredValue(
			input.sessionToken,
			'The application session token is required.'
		);

		this.assertRequiredValue(
			input.applicationId,
			'The application identifier is required.'
		);

		const identity = await this.firebase.verify(
			input.firebaseSessionCookie,
			input.checkFirebaseRevocation ?? true
		);

		const session =
			await this.repository.findByTokenHash(
				identity.userId,
				this.tokenHasher.hash(
					input.sessionToken
				),
				input.applicationId
			);

		if (!session) {
			throw new AuthError(
				'session_invalid',
				'The application session is invalid.'
			);
		}

		if (session.userId !== identity.userId) {
			throw new AuthError(
				'session_invalid',
				'The Firebase and application sessions differ.'
			);
		}

		if (session.revokedAt !== null) {
			throw new AuthError(
				'session_revoked',
				'The application session was revoked.'
			);
		}

		const now = this.clock.now();

		if (
			session.expiresAt.getTime() <=
			now.getTime() ||
			identity.expiresAt.getTime() <=
			now.getTime()
		) {
			throw new AuthError(
				'session_expired',
				'The authenticated session has expired.'
			);
		}

		const device = await this.devices.findById(
			session.userId,
			session.deviceId
		);

		if (
			device.status !== 'verified'
		) {
			throw new AuthError(
				'session_revoked',
				'The session device is no longer trusted.'
			);
		}

		const updatedSession =
			await this.repository.touchActive(
				session.userId,
				session.id,
				session.applicationId,
				now
			);

		if (!updatedSession) {
			throw new AuthError(
				'session_revoked',
				'The application session is no longer active.'
			);
		}

		return updatedSession;
	};

	/**
	 * Revokes one application session.
	 * @param input - Account-scoped session identity.
	 * @returns The revoked session.
	 * @throws {AuthError} When the session does not exist.
	 */
	readonly revoke = async (
		input: RevokeSessionInput
	): Promise<Session> => {
		this.assertRequiredValue(
			input.userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			input.sessionId,
			'The session identifier is required.'
		);

		this.assertRequiredValue(
			input.applicationId,
			'The application identifier is required.'
		);

		const session = await this.repository.revoke(
			input.userId,
			input.sessionId,
			input.applicationId,
			this.clock.now()
		);

		if (!session) {
			throw new AuthError(
				'session_invalid',
				'The application session does not exist.'
			);
		}

		await this.securityEvents.record({
			userId: session.userId,
			type: 'session_revoked',
			applicationId: session.applicationId,
			deviceId: session.deviceId,
			sessionId: session.id,
			affectedCount: 1
		});

		return session;
	};

	/**
	 * Revokes every application session associated with a device.
	 * @param userId - Firebase user owning the sessions.
	 * @param deviceId - Device whose sessions must be revoked.
	 * @returns The number of sessions revoked.
	 */
	readonly revokeByDevice = async (
		userId: string,
		deviceId: string
	): Promise<number> => {
		this.assertRequiredValue(
			userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			deviceId,
			'The device identifier is required.'
		);

		const revokedSessionCount = await this.repository.revokeByDevice(
			userId,
			deviceId,
			this.clock.now()
		);

		if (revokedSessionCount > 0) {
			await this.securityEvents.record({
				userId,
				type: 'sessions_revoked',
				applicationId: null,
				deviceId,
				sessionId: null,
				affectedCount: revokedSessionCount
			});
		}

		return revokedSessionCount;
	};

	/**
	 * Lists every application session owned by an account.
	 * @param userId - Firebase user owning the sessions.
	 * @returns The account sessions.
	 */
	readonly list = async (
		userId: string
	): Promise<readonly Session[]> => {
		this.assertRequiredValue(
			userId,
			'The Firebase user identifier is required.'
		);

		return this.repository.listByUser(userId);
	};

	/**
	 * Revokes one account-owned application session.
	 * @param userId - Firebase user owning the session.
	 * @param sessionId - Session identifier.
	 * @returns The revoked session.
	 * @throws {AuthError} When the session does not exist.
	 */
	readonly revokeOwned = async (
		userId: string,
		sessionId: string
	): Promise<Session> => {
		this.assertRequiredValue(
			userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			sessionId,
			'The session identifier is required.'
		);

		const session = await this.repository.revokeOwned(
			userId,
			sessionId,
			this.clock.now()
		);

		if (!session) {
			throw new AuthError(
				'session_invalid',
				'The application session does not exist.'
			);
		}

		await this.securityEvents.record({
			userId: session.userId,
			type: 'session_revoked',
			applicationId: session.applicationId,
			deviceId: session.deviceId,
			sessionId: session.id,
			affectedCount: 1
		});

		return session;
	};

	/**
	 * Revokes every active account session except the current one.
	 * @param userId - Firebase user owning the sessions.
	 * @param currentSessionId - Session that must remain active.
	 * @returns The number of sessions revoked.
	 */
	readonly revokeOthers = async (
		userId: string,
		currentSessionId: string
	): Promise<number> => {
		this.assertRequiredValue(
			userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			currentSessionId,
			'The current session identifier is required.'
		);

		const revokedSessionCount = await this.repository.revokeOthers(
			userId,
			currentSessionId,
			this.clock.now()
		);

		if (revokedSessionCount > 0) {
			await this.securityEvents.record({
				userId,
				type: 'sessions_revoked',
				applicationId: null,
				deviceId: null,
				sessionId: currentSessionId,
				affectedCount: revokedSessionCount
			});
		}

		return revokedSessionCount;
	};

	/**
	 * Rejects an empty public service argument.
	 * @param value - Value to validate.
	 * @param message - Safe diagnostic message.
	 * @throws {TypeError} When the value is empty.
	 */
	private readonly assertRequiredValue = (
		value: string,
		message: string
	): void => {
		if (!value.trim()) {
			throw new TypeError(message);
		}
	};
}

export default SessionService;
