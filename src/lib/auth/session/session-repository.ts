import 'server-only';

import type { BatchUpdateOperation, FirestoreRepository } from '@assosync/firestore';
import type { Session, SessionRepository, StoredSession } from '@/types/auth';

const ACCOUNT_COLLECTION = 'account';
const SESSION_COLLECTION = 'sessions';
const MAXIMUM_DOCUMENT_ID_LENGTH = 128;

/**
 * Ensures a value is a valid Firestore document identifier.
 * @param value - Identifier to validate.
 * @param label - Identifier label used in the error message.
 * @throws {TypeError} When the identifier is invalid.
 */
const assertDocumentId = (value: string, label: string): void => {
	if (!value.trim() || value.length > MAXIMUM_DOCUMENT_ID_LENGTH || value.includes('/')) {
		throw new TypeError(`${label} is invalid.`);
	}
};

/**
 * Resolves the session collection owned by an account.
 * @param userId - Firebase user identifier.
 * @returns The account session collection path.
 */
const getSessionCollectionPath = (userId: string): string => {
	assertDocumentId(userId, 'The Firebase user identifier');

	return `${ACCOUNT_COLLECTION}/${userId}/${SESSION_COLLECTION}`;
};

/**
 * Resolves one session document owned by an account.
 * @param userId - Firebase user identifier.
 * @param sessionId - Session document identifier.
 * @returns The session document path.
 */
const getSessionPath = (userId: string, sessionId: string): string => {
	assertDocumentId(sessionId, 'The session identifier');

	return `${getSessionCollectionPath(userId)}/${sessionId}`;
};

/**
 * Determines whether an unknown value is a plain record.
 * @param value - Value to inspect.
 * @returns Whether the value is a string-keyed record.
 */
const isRecord = (value: unknown): value is Record<string, unknown> => {
	return (
		typeof value === 'object' &&
		value !== null &&
		!Array.isArray(value)
	);
};

/**
 * Determines whether an unknown value is a valid date.
 * @param value - Value to inspect.
 * @returns Whether the value is a valid JavaScript date.
 */
const isValidDate = (value: unknown): value is Date => {
	return (
		value instanceof Date &&
		!Number.isNaN(value.getTime())
	);
};

/**
 * Converts and validates an external Firestore value.
 * @param value - Value returned by Firestore.
 * @returns The validated application session.
 * @throws {TypeError} When the stored session is invalid.
 */
const toSession = (value: unknown): Session => {
	if (!isRecord(value)) {
		throw new TypeError('The stored authentication session is invalid.');
	}

	const {
		uid,
		tokenHash,
		userId,
		deviceId,
		applicationId,
		expires,
		lastSeen,
		revoked,
		created,
		updated
	} = value;

	if (typeof uid !== 'string' ||
		!uid ||
		typeof tokenHash !== 'string' ||
		!tokenHash ||
		typeof userId !== 'string' ||
		!userId ||
		typeof deviceId !== 'string' ||
		!deviceId ||
		typeof applicationId !== 'string' ||
		!applicationId ||
		!isValidDate(expires) ||
		!isValidDate(lastSeen) ||
		(
			revoked !== null &&
			!isValidDate(revoked)
		) ||
		!isValidDate(created) ||
		!isValidDate(updated)) {
		throw new TypeError('The stored authentication session is invalid.');
	}

	return {
		id: uid,
		tokenHash,
		userId,
		deviceId,
		applicationId,
		createdAt: created,
		expiresAt: expires,
		lastSeenAt: lastSeen,
		revokedAt: revoked
	};
};

/**
 * Enforces the ownership of an account-scoped session.
 * @param value - Value returned by Firestore.
 * @param userId - Account owning the queried collection.
 * @returns The validated account session.
 * @throws {TypeError} When ownership is inconsistent.
 */
const toOwnedSession = (value: unknown, userId: string): Session => {
	const session = toSession(value);

	if (session.userId !== userId) {
		throw new TypeError('The stored authentication session owner is invalid.');
	}

	return session;
};

/**
 * Creates an account-scoped Firestore session repository.
 * @param firestore - Shared Firestore repository.
 * @returns The application session repository.
 */
const createSessionRepository = (firestore: FirestoreRepository): SessionRepository => {
	return {
		create: async (session) => {
			const storedSession = await firestore.create<StoredSession>(
				getSessionCollectionPath(session.userId),
				{
					tokenHash: session.tokenHash,
					userId: session.userId,
					deviceId: session.deviceId,
					applicationId: session.applicationId,
					expires: session.expiresAt,
					lastSeen: session.lastSeenAt,
					revoked: session.revokedAt
				}
			);

			return toOwnedSession(storedSession, session.userId);
		},

		findByTokenHash: async (userId, tokenHash, applicationId) => {
			const result = await firestore.search<StoredSession>({
					col: getSessionCollectionPath(userId),
					where: [
						[
							'tokenHash',
							'==',
							tokenHash
						],
						[
							'applicationId',
							'==',
							applicationId
						]
					],
					limit: 1
				});

			const storedSession = result.rows[0];

			if (!storedSession) {
				return null;
			}

			return toOwnedSession(storedSession, userId);
		},

		listByUser: async (userId) => {
			const sessions: Session[] = [];
			let startAfterDocId: string | undefined;

			do {
				const result = await firestore.search<StoredSession>({
					col: getSessionCollectionPath(userId),
					orderBy: [['lastSeen', 'desc']],
					limit: 100,
					...(startAfterDocId
						? { startAfterDocId }
						: {})
				});

				sessions.push(
					...result.rows.map((storedSession) => {
						return toOwnedSession(storedSession, userId);
					})
				);

				startAfterDocId = result.lastDocId ?? undefined;
			} while (startAfterDocId);

			return sessions;
		},

		touchActive: async (userId, sessionId, applicationId, seenAt) => {
			return firestore.transaction(
				async (transaction) => {
					const path = getSessionPath(userId, sessionId);

					const storedSession = await transaction.get<StoredSession>(path);

					if (!storedSession) {
						return null;
					}

					const session = toOwnedSession(storedSession, userId);

					if (session.applicationId !== applicationId || session.revokedAt !== null || session.expiresAt.getTime() <= seenAt.getTime()) {
						return null;
					}

					const updatedSession: Session = {
						...session,
						lastSeenAt: seenAt
					};

					transaction.update<StoredSession>(path, { lastSeen: seenAt });

					return updatedSession;
				}
			);
		},

		revoke: async (userId, sessionId, applicationId, revokedAt) => {
			return firestore.transaction(
				async (transaction) => {
					const path = getSessionPath(userId, sessionId);

					const storedSession = await transaction.get<StoredSession>(path);

					if (!storedSession) {
						return null;
					}

					const session = toOwnedSession(storedSession, userId);

					if (session.applicationId !== applicationId) {
						return null;
					}

					if (session.revokedAt !== null) {
						return session;
					}

					const revokedSession: Session = {
						...session,
						revokedAt
					};

					transaction.update<StoredSession>(path, { revoked: revokedAt });

					return revokedSession;
				}
			);
		},

		revokeByDevice: async (userId, deviceId, revokedAt) => {
			let revokedSessionCount = 0;
			let startAfterDocId: string | undefined;

			do {
				const result = await firestore.search<StoredSession>({
					col: getSessionCollectionPath(userId),
					where: [
						['deviceId', '==', deviceId],
						['revoked', '==', null]
					],
					limit: 500,
					...(startAfterDocId
						? { startAfterDocId }
						: {})
				});

				const updates: BatchUpdateOperation<StoredSession>[] = result.rows.map((storedSession) => {
						const session = toOwnedSession(storedSession, userId);

						return {
							path: getSessionPath(userId, session.id),
							data: { revoked: revokedAt }
						};
					});

				if (updates.length > 0) {
					await firestore.batch<StoredSession>({ update: updates });

					revokedSessionCount += updates.length;
				}

				startAfterDocId = result.lastDocId ?? undefined;
			} while (startAfterDocId);

			return revokedSessionCount;
		},

		revokeOwned: async (userId, sessionId, revokedAt) => {
			return firestore.transaction(
				async (transaction) => {
					const path = getSessionPath(userId, sessionId);

					const storedSession = await transaction.get<StoredSession>(path);

					if (!storedSession) {
						return null;
					}

					const session = toOwnedSession(storedSession, userId);

					if (session.revokedAt !== null) {
						return session;
					}

					const revokedSession: Session = {
						...session,
						revokedAt
					};

					transaction.update<StoredSession>(path, { revoked: revokedAt });

					return revokedSession;
				}
			);
		},

		revokeOthers: async (userId, currentSessionId, revokedAt) => {
			let revokedSessionCount = 0;
			let startAfterDocId: string | undefined;

			do {
				const result = await firestore.search<StoredSession>({
					col: getSessionCollectionPath(userId),
					where: [['revoked', '==', null]],
					limit: 500,
					...(startAfterDocId
						? { startAfterDocId }
						: {})
				});

				const updates: BatchUpdateOperation<StoredSession>[] = [];

				for (const storedSession of result.rows) {
					const session = toOwnedSession(storedSession, userId);

					if (session.id === currentSessionId || session.expiresAt.getTime() <= revokedAt.getTime()) {
						continue;
					}

					updates.push({ path: getSessionPath(userId, session.id), data: { revoked: revokedAt } });
				}

				if (updates.length > 0) {
					await firestore.batch<StoredSession>({ update: updates });

					revokedSessionCount += updates.length;
				}

				startAfterDocId = result.lastDocId ?? undefined;
			} while (startAfterDocId);

			return revokedSessionCount;
		}
	};
};

export default createSessionRepository;
