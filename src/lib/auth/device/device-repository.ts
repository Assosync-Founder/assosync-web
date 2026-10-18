import 'server-only';

import type { FirestoreRepository } from '@assosync/firestore';
import type { Device, DeviceCategory, DeviceRepository, DeviceStatus, StoredDevice } from '@/types/auth';

const ACCOUNT_COLLECTION = 'account';
const DEVICE_COLLECTION = 'devices';
const MAXIMUM_DOCUMENT_ID_LENGTH = 128;

/**
 * Ensures a value can safely be used as a Firestore document identifier.
 * @param value - Identifier to validate.
 * @param label - Identifier label used in the diagnostic message.
 * @throws {TypeError} When the identifier is empty or contains a path separator.
 */
const assertDocumentId = (value: string, label: string): void => {
	if (!value.trim() || value.length > MAXIMUM_DOCUMENT_ID_LENGTH || value.includes('/')) {
		throw new TypeError(`${ label } is invalid.`);
	}
};

/**
 * Resolves the device collection owned by one account.
 * @param userId - Firebase user identifier.
 * @returns The account device collection path.
 */
const getDeviceCollectionPath = (userId: string): string => {
	assertDocumentId(userId, 'The Firebase user identifier');

	return `${ ACCOUNT_COLLECTION }/${ userId }/${ DEVICE_COLLECTION }`;
};

/**
 * Resolves one device document owned by an account.
 * @param userId - Firebase user identifier.
 * @param deviceId - Device document identifier.
 * @returns The account device document path.
 */
const getDevicePath = (userId: string, deviceId: string): string => {
	assertDocumentId(deviceId, 'The device identifier');

	return `${ getDeviceCollectionPath(userId) }/${ deviceId }`;
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
 * Determines whether a value is a valid date.
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
 * Determines whether a value is a supported device status.
 * @param value - Value to inspect.
 * @returns Whether the value is a device status.
 */
const isDeviceStatus = (value: unknown): value is DeviceStatus => {
	return (
		value === 'pending' ||
		value === 'verified' ||
		value === 'revoked'
	);
};

/**
 * Determines whether a value is a supported device category.
 * @param value - Value to inspect.
 * @returns Whether the value is a device category.
 */
const isDeviceCategory = (value: unknown): value is DeviceCategory => {
	return (
		value === 'desktop' ||
		value === 'mobile' ||
		value === 'tablet' ||
		value === 'unknown'
	);
};

/**
 * Determines whether a value is a nullable string.
 * @param value - Value to inspect.
 * @returns Whether the value is a string or null.
 */
const isNullableString = (value: unknown): value is string | null => {
	return value === null || typeof value === 'string';
};

/**
 * Converts and validates an external Firestore value.
 * @param value - Value returned by Firestore.
 * @returns A validated device.
 * @throws {TypeError} When the stored document is invalid.
 */
const toDevice = (value: unknown): Device => {
	if (!isRecord(value)) {
		throw new TypeError('The stored authentication device is invalid.');
	}

	const {
		uid,
		tokenHash,
		userId,
		applicationId,
		displayName,
		category = 'unknown',
		browserName = null,
		browserVersion = null,
		operatingSystemName = null,
		operatingSystemVersion = null,
		deviceBrand = null,
		deviceModel = null,
		status,
		expires,
		lastSeen,
		verified,
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
		typeof applicationId !== 'string' ||
		!applicationId ||
		(displayName !== null && typeof displayName !== 'string') ||
		!isDeviceCategory(category) ||
		!isNullableString(browserName) ||
		!isNullableString(browserVersion) ||
		!isNullableString(operatingSystemName) ||
		!isNullableString(operatingSystemVersion) ||
		!isNullableString(deviceBrand) ||
		!isNullableString(deviceModel) ||
		!isDeviceStatus(status) ||
		!isValidDate(expires) ||
		!isValidDate(lastSeen) ||
		(verified !== null && !isValidDate(verified)) ||
		(revoked !== null && !isValidDate(revoked)) ||
		!isValidDate(created) ||
		!isValidDate(updated)) {
		throw new TypeError('The stored authentication device is invalid.');
	}

	if (status === 'verified' && (verified === null || revoked !== null)) {
		throw new TypeError('The stored verified device state is inconsistent.');
	}

	if (status === 'pending' && (verified !== null || revoked !== null)) {
		throw new TypeError('The stored pending device state is inconsistent.');
	}

	if (status === 'revoked' && revoked === null) {
		throw new TypeError('The stored revoked device state is inconsistent.');
	}

	return {
		id: uid,
		tokenHash,
		userId,
		applicationId,
		displayName,
		category,
		browserName,
		browserVersion,
		operatingSystemName,
		operatingSystemVersion,
		deviceBrand,
		deviceModel,
		status,
		createdAt: created,
		expiresAt: expires,
		lastSeenAt: lastSeen,
		verifiedAt: verified,
		revokedAt: revoked
	};
};

/**
 * Converts a stored device and enforces its account ownership.
 * @param value - Value returned by Firestore.
 * @param userId - Account owning the collection that was queried.
 * @returns A validated account device.
 * @throws {TypeError} When the stored owner does not match the account path.
 */
const toOwnedDevice = (value: unknown, userId: string): Device => {
	const device = toDevice(value);

	if (device.userId !== userId) {
		throw new TypeError('The stored authentication device owner is invalid.');
	}

	return device;
};

/**
 * Creates a device repository backed by the shared Firestore repository.
 * @param firestore - Shared platform-independent Firestore repository.
 * @returns A repository handling device persistence and transitions.
 */
const createDeviceRepository = (firestore: FirestoreRepository): DeviceRepository => {
	return {
		create: async (device) => {
			const storedDevice = await firestore.create<StoredDevice>(
				getDeviceCollectionPath(device.userId),
				{
					tokenHash: device.tokenHash,
					userId: device.userId,
					applicationId: device.applicationId,
					displayName: device.displayName,
					category: device.category,
					browserName: device.browserName,
					browserVersion: device.browserVersion,
					operatingSystemName: device.operatingSystemName,
					operatingSystemVersion: device.operatingSystemVersion,
					deviceBrand: device.deviceBrand,
					deviceModel: device.deviceModel,
					status: device.status,
					expires: device.expiresAt,
					lastSeen: device.lastSeenAt,
					verified: device.verifiedAt,
					revoked: device.revokedAt
				}
			);

			return toOwnedDevice(storedDevice, device.userId);
		},

		findByTokenHash: async (userId, tokenHash) => {
			const result = await firestore.search<StoredDevice>({
				col: getDeviceCollectionPath(userId),
				where: [['tokenHash', '==', tokenHash]],
				limit: 1
			});

			const storedDevice = result.rows[0];

			if (!storedDevice) {
				return null;
			}

			return toOwnedDevice(storedDevice, userId);
		},

		findById: async (userId, deviceId) => {
			const storedDevice = await firestore.get<StoredDevice>(getDevicePath(userId, deviceId));

			if (!storedDevice) {
				return null;
			}

			return toOwnedDevice(storedDevice, userId);
		},

		listByUser: async (userId) => {
			const devices: Device[] = [];
			let startAfterDocId: string | undefined;

			do {
				const result = await firestore.search<StoredDevice>({
					col: getDeviceCollectionPath(userId),
					orderBy: [['created', 'desc']],
					limit: 100,
					...(startAfterDocId
						? { startAfterDocId }
						: {})
				});

				devices.push(
					...result.rows.map((storedDevice) => {
						return toOwnedDevice(storedDevice, userId);
					})
				);

				startAfterDocId = result.lastDocId ?? undefined;
			} while (startAfterDocId);

			return devices;
		},

		update: async (device) => {
			await firestore.update<StoredDevice>(
				getDevicePath(device.userId, device.id),
				{
					tokenHash: device.tokenHash,
					userId: device.userId,
					applicationId: device.applicationId,
					displayName: device.displayName,
					category: device.category,
					browserName: device.browserName,
					browserVersion: device.browserVersion,
					operatingSystemName: device.operatingSystemName,
					operatingSystemVersion: device.operatingSystemVersion,
					deviceBrand: device.deviceBrand,
					deviceModel: device.deviceModel,
					status: device.status,
					expires: device.expiresAt,
					lastSeen: device.lastSeenAt,
					verified: device.verifiedAt,
					revoked: device.revokedAt
				}
			);

			return device;
		},

		verifyPending: async (userId, deviceId, applicationId, verifiedAt, expiresAt) => {
			if (expiresAt.getTime() <= verifiedAt.getTime()) {
				throw new RangeError('The verified device expiration must follow its verification time.');
			}

			return firestore.transaction(async (transaction) => {
				const path = getDevicePath(userId, deviceId);
				const storedDevice = await transaction.get<StoredDevice>(path);

				if (!storedDevice) {
					return null;
				}

				const device = toOwnedDevice(storedDevice, userId);

				if (device.status === 'verified' && device.revokedAt === null && device.applicationId === applicationId && device.expiresAt.getTime() > verifiedAt.getTime()) {
					return device;
				}

				if (device.status !== 'pending' || device.revokedAt !== null || device.applicationId !== applicationId || device.expiresAt.getTime() <= verifiedAt.getTime()) {
					return null;
				}

				const verifiedDevice: Device = {
					...device,
					status: 'verified',
					expiresAt,
					lastSeenAt: verifiedAt,
					verifiedAt
				};

				transaction.update<StoredDevice>(
					path,
					{
						status: 'verified',
						expires: expiresAt,
						lastSeen: verifiedAt,
						verified: verifiedAt
					}
				);

				return verifiedDevice;
			});
		},

		touchVerified: async (userId, deviceId, seenAt) => {
			return firestore.transaction(async (transaction) => {
				const path = getDevicePath(userId, deviceId);
				const storedDevice = await transaction.get<StoredDevice>(path);

				if (!storedDevice) {
					return null;
				}

				const device = toOwnedDevice(storedDevice, userId);

				if (device.status !== 'verified' || device.revokedAt !== null || device.expiresAt.getTime() <= seenAt.getTime()) {
					return null;
				}

				const updatedDevice: Device = {
					...device,
					lastSeenAt: seenAt
				};

				transaction.update<StoredDevice>(path, { lastSeen: seenAt });

				return updatedDevice;
			});
		},

		rename: async (userId, deviceId, displayName) => {
			return firestore.transaction(async (transaction) => {
				const path = getDevicePath(userId, deviceId);
				const storedDevice = await transaction.get<StoredDevice>(path);

				if (!storedDevice) {
					return null;
				}

				const device = toOwnedDevice(storedDevice, userId);

				if (device.status === 'revoked' || device.revokedAt !== null) {
					return null;
				}

				const renamedDevice: Device = {
					...device,
					displayName
				};

				transaction.update<StoredDevice>(path, { displayName });

				return renamedDevice;
			});
		},

		revoke: async (userId, deviceId, revokedAt) => {
			return firestore.transaction(async (transaction) => {
				const path = getDevicePath(userId, deviceId);
				const storedDevice = await transaction.get<StoredDevice>(path);

				if (!storedDevice) {
					return null;
				}

				const device = toOwnedDevice(storedDevice, userId);

				if (device.status === 'revoked') {
					return device;
				}

				const revokedDevice: Device = {
					...device,
					status: 'revoked',
					revokedAt
				};

				transaction.update<StoredDevice>(path, { status: 'revoked', revoked: revokedAt });

				return revokedDevice;
			});
		}
	};
};

export default createDeviceRepository;
