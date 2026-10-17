import 'server-only';

import type { FirestoreRepository } from '@assosync/firestore';
import type {
	SecurityEventRepository,
	StoredSecurityEvent
} from '@/types/auth';

const ACCOUNT_COLLECTION = 'account';
const SECURITY_EVENT_COLLECTION = 'securityEvents';
const MAXIMUM_DOCUMENT_ID_LENGTH = 128;

/**
 * Ensures a value can safely identify a Firestore document.
 * @param value - Identifier to validate.
 * @param label - Diagnostic label.
 * @throws {TypeError} When the identifier is invalid.
 */
const assertDocumentId = (
	value: string,
	label: string
): void => {
	if (
		!value.trim() ||
		value.length > MAXIMUM_DOCUMENT_ID_LENGTH ||
		value.includes('/')
	) {
		throw new TypeError(`${ label } is invalid.`);
	}
};

/**
 * Resolves the append-only event collection owned by an account.
 * @param userId - Firebase user identifier.
 * @returns The account security-event collection path.
 */
const getSecurityEventCollectionPath = (
	userId: string
): string => {
	assertDocumentId(userId, 'The Firebase user identifier');

	return `${ ACCOUNT_COLLECTION }/${ userId }/${ SECURITY_EVENT_COLLECTION }`;
};

/**
 * Creates a Firestore security-event repository.
 * @param firestore - Shared Firestore repository.
 * @returns The append-only security-event repository.
 */
const createSecurityEventRepository = (
	firestore: FirestoreRepository
): SecurityEventRepository => {
	return {
		create: async (event) => {
			await firestore.create<StoredSecurityEvent>(
				getSecurityEventCollectionPath(event.userId),
				{
					userId: event.userId,
					type: event.type,
					applicationId: event.applicationId,
					deviceId: event.deviceId,
					sessionId: event.sessionId,
					affectedCount: event.affectedCount,
					occurred: event.occurredAt,
					expires: event.expiresAt
				}
			);
		}
	};
};

export default createSecurityEventRepository;
