import 'server-only';

import type { FirestoreRepository } from '@assosync/firestore';
import type {
	MobileApplicationId,
	MobileInstallation,
	MobileInstallationRepository,
	MobileInstallationStatus,
	MobilePlatform,
	StoredMobileInstallation
} from '@/types/auth';

const ACCOUNT_COLLECTION = 'account';
const MOBILE_COLLECTION = 'mobiles';
const MAXIMUM_DOCUMENT_ID_LENGTH = 128;

/**
 * Ensures a value can safely be used as a Firestore document identifier.
 * @param value - Identifier to validate.
 * @param label - Identifier label used in the diagnostic message.
 * @throws {TypeError} When the identifier is empty or contains a path separator.
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
		throw new TypeError(`${label} is invalid.`);
	}
};

/**
 * Resolves the mobile installation collection owned by one account.
 * @param userId - Firebase user identifier.
 * @returns The account mobile installation collection path.
 */
const getMobileInstallationCollectionPath = (
	userId: string
): string => {
	assertDocumentId(userId, 'The Firebase user identifier');

	return `${ACCOUNT_COLLECTION}/${userId}/${MOBILE_COLLECTION}`;
};

/**
 * Resolves one mobile installation document owned by an account.
 * @param userId - Firebase user identifier.
 * @param mobileInstallationId - Mobile installation identifier.
 * @returns The account mobile installation document path.
 */
const getMobileInstallationPath = (
	userId: string,
	mobileInstallationId: string
): string => {
	assertDocumentId(
		mobileInstallationId,
		'The mobile installation identifier'
	);

	return `${getMobileInstallationCollectionPath(userId)}/${mobileInstallationId}`;
};

/**
 * Determines whether an unknown value is a plain record.
 * @param value - Value to inspect.
 * @returns Whether the value is a string-keyed record.
 */
const isRecord = (
	value: unknown
): value is Record<string, unknown> => {
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
const isValidDate = (
	value: unknown
): value is Date => {
	return (
		value instanceof Date &&
		!Number.isNaN(value.getTime())
	);
};

/**
 * Determines whether a value is a supported mobile application identifier.
 * @param value - Value to inspect.
 * @returns Whether the value is a mobile application identifier.
 */
const isMobileApplicationId = (
	value: unknown
): value is MobileApplicationId => {
	return value === 'calendis' || value === 'collectineo';
};

/**
 * Determines whether a value is a supported mobile platform.
 * @param value - Value to inspect.
 * @returns Whether the value is a mobile platform.
 */
const isMobilePlatform = (
	value: unknown
): value is MobilePlatform => {
	return value === 'android' || value === 'ios';
};

/**
 * Determines whether a value is a mobile installation status.
 * @param value - Value to inspect.
 * @returns Whether the value is a mobile installation status.
 */
const isMobileInstallationStatus = (
	value: unknown
): value is MobileInstallationStatus => {
	return value === 'active' || value === 'disabled';
};

/**
 * Converts and validates an external Firestore value.
 * @param value - Value returned by Firestore.
 * @returns A validated mobile installation.
 * @throws {TypeError} When the stored document is invalid.
 */
const toMobileInstallation = (
	value: unknown
): MobileInstallation => {
	if (!isRecord(value)) {
		throw new TypeError(
			'The stored mobile authentication installation is invalid.'
		);
	}

	const {
		uid,
		userId,
		mobileApplicationId,
		platform,
		mobileDeviceName,
		mobileApplicationVersion,
		pushToken,
		pushTokenHash,
		status,
		lastSeen,
		pushTokenUpdated,
		disabled,
		created,
		updated
	} = value;

	if (
		typeof uid !== 'string' ||
		!uid ||
		typeof userId !== 'string' ||
		!userId ||
		!isMobileApplicationId(mobileApplicationId) ||
		!isMobilePlatform(platform) ||
		(
			mobileDeviceName !== null &&
			typeof mobileDeviceName !== 'string'
		) ||
		(
			mobileApplicationVersion !== null &&
			typeof mobileApplicationVersion !== 'string'
		) ||
		typeof pushToken !== 'string' ||
		!pushToken ||
		typeof pushTokenHash !== 'string' ||
		!pushTokenHash ||
		!isMobileInstallationStatus(status) ||
		!isValidDate(lastSeen) ||
		!isValidDate(pushTokenUpdated) ||
		(disabled !== null && !isValidDate(disabled)) ||
		!isValidDate(created) ||
		!isValidDate(updated)
	) {
		throw new TypeError(
			'The stored mobile authentication installation is invalid.'
		);
	}

	if (
		(status === 'active' && disabled !== null) ||
		(status === 'disabled' && disabled === null)
	) {
		throw new TypeError(
			'The stored mobile authentication installation state is inconsistent.'
		);
	}

	return {
		id: uid,
		userId,
		mobileApplicationId,
		platform,
		mobileDeviceName,
		mobileApplicationVersion,
		pushToken,
		pushTokenHash,
		status,
		createdAt: created,
		lastSeenAt: lastSeen,
		pushTokenUpdatedAt: pushTokenUpdated,
		disabledAt: disabled
	};
};

/**
 * Converts a stored mobile installation and enforces account ownership.
 * @param value - Value returned by Firestore.
 * @param userId - Account owning the collection that was queried.
 * @returns A validated account mobile installation.
 * @throws {TypeError} When the stored owner does not match its account path.
 */
const toOwnedMobileInstallation = (
	value: unknown,
	userId: string
): MobileInstallation => {
	const mobileInstallation = toMobileInstallation(value);

	if (mobileInstallation.userId !== userId) {
		throw new TypeError(
			'The stored mobile authentication installation owner is invalid.'
		);
	}

	return mobileInstallation;
};

/**
 * Creates an account-scoped Firestore mobile installation repository.
 * @param firestore - Shared Firestore repository.
 * @returns The mobile installation repository.
 */
const createMobileInstallationRepository = (
	firestore: FirestoreRepository
): MobileInstallationRepository => {
	return {
		upsert: async (mobileInstallation) => {
			return firestore.transaction(async (transaction) => {
				const path = getMobileInstallationPath(
					mobileInstallation.userId,
					mobileInstallation.id
				);

				const storedMobileInstallation =
					await transaction.get<StoredMobileInstallation>(path);

				if (!storedMobileInstallation) {
					transaction.set<StoredMobileInstallation>(
						getMobileInstallationCollectionPath(
							mobileInstallation.userId
						),
						{
							uid: mobileInstallation.id,
							userId: mobileInstallation.userId,
							mobileApplicationId:
								mobileInstallation.mobileApplicationId,
							platform: mobileInstallation.platform,
							mobileDeviceName:
								mobileInstallation.mobileDeviceName,
							mobileApplicationVersion:
								mobileInstallation.mobileApplicationVersion,
							pushToken: mobileInstallation.pushToken,
							pushTokenHash:
								mobileInstallation.pushTokenHash,
							status: mobileInstallation.status,
							lastSeen: mobileInstallation.lastSeenAt,
							pushTokenUpdated:
								mobileInstallation.pushTokenUpdatedAt,
							disabled: mobileInstallation.disabledAt
						}
					);

					return mobileInstallation;
				}

				const currentMobileInstallation =
					toOwnedMobileInstallation(
						storedMobileInstallation,
						mobileInstallation.userId
					);

				if (
					currentMobileInstallation.mobileApplicationId !==
						mobileInstallation.mobileApplicationId ||
					currentMobileInstallation.platform !==
						mobileInstallation.platform
				) {
					throw new TypeError(
						'The mobile authentication installation identity cannot change.'
					);
				}

				const refreshedMobileInstallation: MobileInstallation = {
					...mobileInstallation,
					createdAt: currentMobileInstallation.createdAt,
					pushTokenUpdatedAt:
						currentMobileInstallation.pushTokenHash ===
						mobileInstallation.pushTokenHash
							? currentMobileInstallation.pushTokenUpdatedAt
							: mobileInstallation.pushTokenUpdatedAt
				};

				transaction.update<StoredMobileInstallation>(
					path,
					{
						mobileApplicationId:
							refreshedMobileInstallation.mobileApplicationId,
						platform: refreshedMobileInstallation.platform,
						mobileDeviceName:
							refreshedMobileInstallation.mobileDeviceName,
						mobileApplicationVersion:
							refreshedMobileInstallation.mobileApplicationVersion,
						pushToken: refreshedMobileInstallation.pushToken,
						pushTokenHash:
							refreshedMobileInstallation.pushTokenHash,
						status: 'active',
						lastSeen: refreshedMobileInstallation.lastSeenAt,
						pushTokenUpdated:
							refreshedMobileInstallation.pushTokenUpdatedAt,
						disabled: null
					}
				);

				return refreshedMobileInstallation;
			});
		},

		findById: async (userId, mobileInstallationId) => {
			const storedMobileInstallation =
				await firestore.get<StoredMobileInstallation>(
					getMobileInstallationPath(
						userId,
						mobileInstallationId
					)
				);

			if (!storedMobileInstallation) {
				return null;
			}

			return toOwnedMobileInstallation(
				storedMobileInstallation,
				userId
			);
		},

		listActiveByUser: async (userId) => {
			const mobileInstallations: MobileInstallation[] = [];
			let startAfterDocId: string | undefined;

			do {
				const result =
					await firestore.search<StoredMobileInstallation>({
						col: getMobileInstallationCollectionPath(userId),
						where: [['status', '==', 'active']],
						orderBy: [['lastSeen', 'desc']],
						limit: 100,
						...(startAfterDocId
							? { startAfterDocId }
							: {})
					});

				mobileInstallations.push(
					...result.rows.map((storedMobileInstallation) => {
						return toOwnedMobileInstallation(
							storedMobileInstallation,
							userId
						);
					})
				);

				startAfterDocId = result.lastDocId ?? undefined;
			} while (startAfterDocId);

			return mobileInstallations;
		},

		disable: async (
			userId,
			mobileInstallationId,
			disabledAt
		) => {
			return firestore.transaction(async (transaction) => {
				const path = getMobileInstallationPath(
					userId,
					mobileInstallationId
				);

				const storedMobileInstallation =
					await transaction.get<StoredMobileInstallation>(path);

				if (!storedMobileInstallation) {
					return null;
				}

				const mobileInstallation = toOwnedMobileInstallation(
					storedMobileInstallation,
					userId
				);

				if (mobileInstallation.status === 'disabled') {
					return mobileInstallation;
				}

				const disabledMobileInstallation: MobileInstallation = {
					...mobileInstallation,
					status: 'disabled',
					disabledAt
				};

				transaction.update<StoredMobileInstallation>(
					path,
					{
						status: 'disabled',
						disabled: disabledAt
					}
				);

				return disabledMobileInstallation;
			});
		}
	};
};

export default createMobileInstallationRepository;
