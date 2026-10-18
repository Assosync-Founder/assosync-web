import 'server-only';

import type { FirestoreRepository } from '@assosync/firestore';
import type { AuthenticatorTransport, CredentialDeviceType } from '@simplewebauthn/server';
import type { Passkey, PasskeyRepository, StoredPasskey } from '@/types/passkey';

const ACCOUNT_COLLECTION = 'account';
const PASSKEY_COLLECTION = 'passkeys';

const getCollectionPath = (userId: string): string => {
	if (!userId.trim() || userId.includes('/')) {
		throw new TypeError('The passkey owner is invalid.');
	}

	return `${ACCOUNT_COLLECTION}/${userId}/${PASSKEY_COLLECTION}`;
};

const isDate = (value: unknown): value is Date => {
	return value instanceof Date && !Number.isNaN(value.getTime());
};

const isDeviceType = (value: unknown): value is CredentialDeviceType => {
	return value === 'singleDevice' || value === 'multiDevice';
};

const isTransport = (value: unknown): value is AuthenticatorTransport => {
	return (
		value === 'ble' ||
		value === 'hybrid' ||
		value === 'internal' ||
		value === 'nfc' ||
		value === 'usb'
	);
};

const toPasskey = (value: unknown): Passkey => {
	if (typeof value !== 'object' || value === null) {
		throw new TypeError('The stored passkey is invalid.');
	}

	const record: Record<string, unknown> = Object.fromEntries(Object.entries(value));
	const transports = record.transports;

	if (typeof record.uid !== 'string' ||
		typeof record.userId !== 'string' ||
		typeof record.credentialId !== 'string' ||
		typeof record.publicKey !== 'string' ||
		typeof record.webauthnUserId !== 'string' ||
		typeof record.counter !== 'number' ||
		!Number.isSafeInteger(record.counter) ||
		!isDeviceType(record.deviceType) ||
		typeof record.backedUp !== 'boolean' ||
		!Array.isArray(transports) ||
		!transports.every(isTransport) ||
		(record.displayName !== null &&
			typeof record.displayName !== 'string') ||
		(record.lastUsed !== null && !isDate(record.lastUsed)) ||
		!isDate(record.created) ||
		!isDate(record.updated)) {
		throw new TypeError('The stored passkey is invalid.');
	}

	return {
		id: record.uid,
		userId: record.userId,
		credentialId: record.credentialId,
		publicKey: record.publicKey,
		webauthnUserId: record.webauthnUserId,
		counter: record.counter,
		deviceType: record.deviceType,
		backedUp: record.backedUp,
		transports,
		displayName: record.displayName,
		lastUsedAt: record.lastUsed,
		createdAt: record.created,
		updatedAt: record.updated
	};
};

/** Creates the account-scoped Firestore passkey repository.
 * @param firestore - Shared Firestore repository.
 * @returns Passkey persistence contract.
 */
const createPasskeyRepository = (firestore: FirestoreRepository): PasskeyRepository => {
	return {
		create: async (passkey) => {
			const stored = await firestore.create<StoredPasskey>(
				getCollectionPath(passkey.userId),
				{
					userId: passkey.userId,
					credentialId: passkey.credentialId,
					publicKey: passkey.publicKey,
					webauthnUserId: passkey.webauthnUserId,
					counter: passkey.counter,
					deviceType: passkey.deviceType,
					backedUp: passkey.backedUp,
					transports: passkey.transports,
					displayName: passkey.displayName,
					lastUsed: passkey.lastUsedAt
				}
			);

			return toPasskey(stored);
		},
		listByUser: async (userId) => {
			const result = await firestore.search<StoredPasskey>({
				col: getCollectionPath(userId),
				orderBy: [['created', 'desc']],
				limit: 100
			});

			return result.rows.map(toPasskey);
		},
		findByCredentialIdGlobally: async (credentialId) => {
			const result = await firestore.search<StoredPasskey>({
				col: PASSKEY_COLLECTION,
				group: true,
				where: [['credentialId', '==', credentialId]],
				limit: 2
			});

			if (result.rows.length !== 1) {
				return null;
			}

			return toPasskey(result.rows[0]);
		},
		findById: async (userId, passkeyId) => {
			const stored = await firestore.get<StoredPasskey>(`${getCollectionPath(userId)}/${passkeyId}`);

			return stored ? toPasskey(stored) : null;
		},
		updateDisplayName: async (userId, passkeyId, displayName) => {
			await firestore.update<StoredPasskey>(`${getCollectionPath(userId)}/${passkeyId}`, { displayName });
		},
		updateCounter: async (userId, passkeyId, counter, lastUsedAt) => {
			await firestore.update<StoredPasskey>(`${getCollectionPath(userId)}/${passkeyId}`, { counter, lastUsed: lastUsedAt });
		},
		delete: async (userId, passkeyId) => {
			await firestore.delete(`${getCollectionPath(userId)}/${passkeyId}`);
		}
	};
};

export default createPasskeyRepository;
