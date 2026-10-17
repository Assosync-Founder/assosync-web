import 'server-only';

import type { Redis } from '@upstash/redis';
import {
	approveMobileScript,
	attemptEmailCodeScript,
	beginFinalizationScript,
	cancelEmailVerificationScript,
	completeEmailCodeResendScript,
	completeFinalizationScript,
	createVerificationScript,
	rejectMobileScript,
	rollbackEmailCodeResendScript,
	resendEmailCodeScript,
	resolveBrowserMobileVerificationScript,
	resolveMobileApprovalScript
} from '@/lib/auth/verification/verification-scripts';
import type {
	BeginDeviceVerificationFinalizationInput,
	CancelEmailVerificationRepositoryInput,
	CompleteDeviceVerificationFinalizationInput,
	DeviceVerification,
	DeviceVerificationMode,
	DeviceVerificationRepository,
	DeviceVerificationStatus,
	EmailCodeAttemptInput,
	EmailCodeAttemptResult,
	MobileApprovalInput,
	RejectMobileApprovalInput,
	ResendEmailCodeInput,
	ResendEmailCodeResult,
	ResolveBrowserMobileVerificationInput,
	ResolveMobileApprovalInput,
	StoredDeviceVerification
} from '@/types/auth';

/**
 * Normalizes a JSON value returned by Redis.
 * @param value - Serialized or automatically deserialized Redis value.
 * @returns The normalized unknown value.
 * @throws {SyntaxError} When a serialized value contains invalid JSON.
 */
const parseJson = (
	value: unknown
): unknown => {
	if (typeof value === 'string') {
		return JSON.parse(value);
	}

	return value;
};

/**
 * Determines whether a value is a plain record.
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
 * Determines whether a value is a verification mode.
 * @param value - Value to inspect.
 * @returns Whether the value is a supported verification mode.
 */
const isDeviceVerificationMode = (
	value: unknown
): value is DeviceVerificationMode => {
	return (
		value === 'email_code' ||
		value === 'mobile_approval'
	);
};

/**
 * Determines whether a value is a verification status.
 * @param value - Value to inspect.
 * @returns Whether the value is a supported verification status.
 */
const isDeviceVerificationStatus = (
	value: unknown
): value is DeviceVerificationStatus => {
	return (
		value === 'pending' ||
		value === 'approved' ||
		value === 'rejected' ||
		value === 'finalizing' ||
		value === 'consumed'
	);
};

/**
 * Reads a nullable string.
 * @param value - Value to inspect.
 * @returns Whether the value is a string or null.
 */
const isNullableString = (
	value: unknown
): value is string | null => {
	return (
		value === null ||
		typeof value === 'string'
	);
};

/**
 * Parses a valid ISO date.
 * @param value - ISO date value.
 * @returns The parsed JavaScript date.
 * @throws {TypeError} When the date is invalid.
 */
const parseDate = (
	value: string
): Date => {
	const date = new Date(value);

	if (Number.isNaN(date.getTime())) {
		throw new TypeError(
			'The stored device verification date is invalid.'
		);
	}

	return date;
};

/**
 * Converts an unknown Redis value into a stored verification.
 * @param value - Parsed Redis value.
 * @returns The validated stored verification.
 * @throws {TypeError} When the value is invalid.
 */
const parseStoredVerification = (
	value: unknown
): StoredDeviceVerification => {
	if (!isRecord(value)) {
		throw new TypeError(
			'The stored device verification is invalid.'
		);
	}

	const {
		id,
		userId,
		applicationId,
		deviceId,
		mode,
		browserTokenHash,
		codeHash = null,
		approvalTokenHash = null,
		status,
		failedAttempts,
		maxAttempts,
		emailResendCount = 0,
		emailLastSentAt = null,
		createdAt,
		expiresAt,
		approvedAt = null,
		rejectedAt = null,
		finalizingAt = null,
		consumedAt = null
	} = value;

	if (
		typeof id !== 'string' ||
		!id ||
		typeof userId !== 'string' ||
		!userId ||
		typeof applicationId !== 'string' ||
		!applicationId ||
		typeof deviceId !== 'string' ||
		!deviceId ||
		!isDeviceVerificationMode(mode) ||
		typeof browserTokenHash !== 'string' ||
		!browserTokenHash ||
		!isNullableString(codeHash) ||
		!isNullableString(approvalTokenHash) ||
		!isDeviceVerificationStatus(status) ||
		typeof failedAttempts !== 'number' ||
		!Number.isInteger(failedAttempts) ||
		failedAttempts < 0 ||
		typeof maxAttempts !== 'number' ||
		!Number.isInteger(maxAttempts) ||
		maxAttempts <= 0 ||
		typeof emailResendCount !== 'number' ||
		!Number.isInteger(emailResendCount) ||
		emailResendCount < 0 ||
		typeof createdAt !== 'string' ||
		typeof expiresAt !== 'string' ||
		!isNullableString(approvedAt) ||
		!isNullableString(emailLastSentAt) ||
		!isNullableString(rejectedAt) ||
		!isNullableString(finalizingAt) ||
		!isNullableString(consumedAt)
	) {
		throw new TypeError(
			'The stored device verification is invalid.'
		);
	}

	if (
		status === 'pending' &&
		(
			approvedAt !== null ||
			rejectedAt !== null ||
			finalizingAt !== null ||
			consumedAt !== null
		)
	) {
		throw new TypeError(
			'The stored pending verification state is inconsistent.'
		);
	}

	if (
		status === 'approved' &&
		(
			approvedAt === null ||
			rejectedAt !== null ||
			finalizingAt !== null ||
			consumedAt !== null
		)
	) {
		throw new TypeError(
			'The stored approved verification state is inconsistent.'
		);
	}

	if (
		status === 'rejected' &&
		(
			approvedAt !== null ||
			rejectedAt === null ||
			finalizingAt !== null ||
			consumedAt !== null
		)
	) {
		throw new TypeError(
			'The stored rejected verification state is inconsistent.'
		);
	}

	if (
		status === 'finalizing' &&
		(
			approvedAt === null ||
			rejectedAt !== null ||
			finalizingAt === null ||
			consumedAt !== null
		)
	) {
		throw new TypeError(
			'The stored finalizing verification state is inconsistent.'
		);
	}

	if (
		status === 'consumed' &&
		(
			approvedAt === null ||
			rejectedAt !== null ||
			finalizingAt === null ||
			consumedAt === null
		)
	) {
		throw new TypeError(
			'The stored consumed verification state is inconsistent.'
		);
	}

	return {
		id,
		userId,
		applicationId,
		deviceId,
		mode,
		browserTokenHash,
		codeHash,
		approvalTokenHash,
		status,
		failedAttempts,
		maxAttempts,
		emailResendCount,
		emailLastSentAt,
		createdAt,
		expiresAt,
		approvedAt,
		rejectedAt,
		finalizingAt,
		consumedAt
	};
};

/**
 * Converts a stored Redis verification into the domain representation.
 * @param stored - Stored Redis verification.
 * @returns The domain verification.
 */
const fromStored = (
	stored: StoredDeviceVerification
): DeviceVerification => {
	return {
		...stored,
		createdAt: parseDate(stored.createdAt),
		expiresAt: parseDate(stored.expiresAt),
		emailLastSentAt: stored.emailLastSentAt
			? parseDate(stored.emailLastSentAt)
			: null,
		approvedAt: stored.approvedAt
			? parseDate(stored.approvedAt)
			: null,
		rejectedAt: stored.rejectedAt
			? parseDate(stored.rejectedAt)
			: null,
		finalizingAt: stored.finalizingAt
			? parseDate(stored.finalizingAt)
			: null,
		consumedAt: stored.consumedAt
			? parseDate(stored.consumedAt)
			: null
	};
};

/**
 * Converts a domain verification into its Redis representation.
 * @param verification - Domain verification.
 * @returns The serializable Redis representation.
 */
const toStored = (
	verification: DeviceVerification
): StoredDeviceVerification => {
	return {
		...verification,
		createdAt: verification.createdAt.toISOString(),
		expiresAt: verification.expiresAt.toISOString(),
		emailLastSentAt:
			verification.emailLastSentAt?.toISOString() ?? null,
		approvedAt: verification.approvedAt?.toISOString() ?? null,
		rejectedAt: verification.rejectedAt?.toISOString() ?? null,
		finalizingAt:
			verification.finalizingAt?.toISOString() ?? null,
		consumedAt: verification.consumedAt?.toISOString() ?? null
	};
};

/**
 * Parses a stored verification returned by Redis.
 * @param value - Serialized or automatically deserialized verification.
 * @returns The validated domain verification.
 */
const parseVerification = (
	value: unknown
): DeviceVerification => {
	return fromStored(
		parseStoredVerification(
			parseJson(value)
		)
	);
};

/**
 * Encodes one safe Redis key component.
 * @param value - Raw key component.
 * @returns The encoded key component.
 */
const encodeKeyPart = (
	value: string
): string => {
	if (!value) {
		throw new TypeError(
			'The Redis key component is required.'
		);
	}

	return encodeURIComponent(value);
};

/**
 * Creates a Redis repository for temporary device verifications.
 * @param redis - Initialized Upstash Redis client.
 * @returns The device verification repository.
 */
const createDeviceVerificationRepository = (
	redis: Redis
): DeviceVerificationRepository => {
	const getAccountPrefix = (
		userId: string
	): string => {
		const encodedUserId = encodeKeyPart(userId);

		return `account:{${ encodedUserId }}`;
	};

	const getVerificationKey = (
		userId: string,
		verificationId: string
	): string => {
		return [
			getAccountPrefix(userId),
			'device-verifications',
			encodeKeyPart(verificationId)
		].join(':');
	};

	const getApprovalKey = (
		userId: string,
		approvalTokenHash: string
	): string => {
		return [
			getAccountPrefix(userId),
			'device-verification-approvals',
			encodeKeyPart(approvalTokenHash)
		].join(':');
	};

	const getEmailResendBackupKey = (
		userId: string,
		verificationId: string
	): string => {
		return [
			getAccountPrefix(userId),
			'device-verification-email-resends',
			encodeKeyPart(verificationId)
		].join(':');
	};

	return {
		create: async (verification) => {
			const lifetimeMs = (
				verification.expiresAt.getTime() -
				Date.now()
			);

			if (lifetimeMs <= 0) {
				throw new RangeError(
					'Cannot persist an expired device verification.'
				);
			}

			const verificationKey = getVerificationKey(
				verification.userId,
				verification.id
			);

			const approvalKey = verification.approvalTokenHash
				? getApprovalKey(
					verification.userId,
					verification.approvalTokenHash
				)
				: verificationKey;

			const result = await redis.eval<string[], number>(
				createVerificationScript,
				[
					verificationKey,
					approvalKey
				],
				[
					JSON.stringify(toStored(verification)),
					lifetimeMs.toString(),
					verification.id,
					verification.approvalTokenHash ? '1' : '0'
				]
			);

			if (result !== 1) {
				throw new Error(
					'This device verification already exists.'
				);
			}

			return verification;
		},

		attemptEmailCode: async (
			input: EmailCodeAttemptInput
		): Promise<EmailCodeAttemptResult> => {
			const result = await redis.eval<string[], unknown>(
				attemptEmailCodeScript,
				[
					getVerificationKey(
						input.userId,
						input.verificationId
					)
				],
				[
					input.userId,
					input.applicationId,
					input.browserTokenHash,
					input.codeHash,
					input.attemptedAt.toISOString()
				]
			);

			const parsedResult = parseJson(result);

			if (!isRecord(parsedResult)) {
				throw new TypeError(
					'The email verification result is invalid.'
				);
			}

			if (
				parsedResult.outcome === 'approved'
			) {
				return {
					outcome: 'approved',
					verification: fromStored(
						parseStoredVerification(
							parsedResult.verification
						)
					)
				};
			}

			if (
				parsedResult.outcome === 'invalid' &&
				typeof parsedResult.remainingAttempts === 'number'
			) {
				return {
					outcome: 'invalid',
					remainingAttempts:
					parsedResult.remainingAttempts
				};
			}

			if (
				parsedResult.outcome === 'locked' &&
				typeof parsedResult.newlyLocked === 'boolean'
			) {
				return {
					outcome: 'locked',
					newlyLocked: parsedResult.newlyLocked
				};
			}

			if (
				parsedResult.outcome === 'not_found' ||
				parsedResult.outcome === 'expired'
			) {
				return {
					outcome: parsedResult.outcome
				};
			}

			throw new TypeError(
				'The email verification result is invalid.'
			);
		},

		resendEmailCode: async (
			input: ResendEmailCodeInput
		): Promise<ResendEmailCodeResult> => {
			const cooldownBoundaryAt = new Date(
				input.sentAt.getTime() - input.cooldownMs
			);

			const lifetimeMs =
				input.expiresAt.getTime() - input.sentAt.getTime();

			const result = await redis.eval<string[], unknown>(
				resendEmailCodeScript,
				[
					getVerificationKey(
						input.userId,
						input.verificationId
					),
					getEmailResendBackupKey(
						input.userId,
						input.verificationId
					)
				],
				[
					input.userId,
					input.applicationId,
					input.deviceId,
					input.browserTokenHash,
					input.codeHash,
					input.sentAt.toISOString(),
					cooldownBoundaryAt.toISOString(),
					input.cooldownMs.toString(),
					input.maxResends.toString(),
					input.expiresAt.toISOString(),
					lifetimeMs.toString()
				]
			);

			const parsedResult = parseJson(result);

			if (!isRecord(parsedResult)) {
				throw new TypeError(
					'The email verification resend result is invalid.'
				);
			}

			if (parsedResult.outcome === 'resent') {
				return {
					outcome: 'resent',
					verification: fromStored(
						parseStoredVerification(
							parsedResult.verification
						)
					)
				};
			}

			if (
				parsedResult.outcome === 'cooldown' &&
				typeof parsedResult.retryAfterMs === 'number'
			) {
				return {
					outcome: 'cooldown',
					retryAfterMs: parsedResult.retryAfterMs
				};
			}

			if (
				parsedResult.outcome === 'limit_reached' ||
				parsedResult.outcome === 'not_found'
			) {
				return { outcome: parsedResult.outcome };
			}

			throw new TypeError(
				'The email verification resend result is invalid.'
			);
		},

		completeEmailCodeResend: async (input) => {
			const result = await redis.eval<string[], number>(
				completeEmailCodeResendScript,
				[
					getVerificationKey(
						input.userId,
						input.verificationId
					),
					getEmailResendBackupKey(
						input.userId,
						input.verificationId
					)
				],
				[
					input.userId,
					input.applicationId,
					input.deviceId,
					input.browserTokenHash,
					input.codeHash
				]
			);

			return result === 1;
		},

		rollbackEmailCodeResend: async (input) => {
			const result = await redis.eval<string[], number>(
				rollbackEmailCodeResendScript,
				[
					getVerificationKey(
						input.userId,
						input.verificationId
					),
					getEmailResendBackupKey(
						input.userId,
						input.verificationId
					)
				],
				[
					input.userId,
					input.applicationId,
					input.deviceId,
					input.browserTokenHash,
					input.codeHash
				]
			);

			return result === 1;
		},

		cancelEmail: async (
			input: CancelEmailVerificationRepositoryInput
		): Promise<boolean> => {
			const result = await redis.eval<string[], number>(
				cancelEmailVerificationScript,
				[
					getVerificationKey(
						input.userId,
						input.verificationId
					)
				],
				[
					input.userId,
					input.applicationId,
					input.deviceId,
					input.browserTokenHash
				]
			);

			return result === 1;
		},

		approveMobile: async (
			input: MobileApprovalInput
		): Promise<DeviceVerification | null> => {
			const result = await redis.eval<string[], unknown>(
				approveMobileScript,
				[
					getVerificationKey(
						input.userId,
						input.verificationId
					),
					getApprovalKey(
						input.userId,
						input.approvalTokenHash
					)
				],
				[
					input.verificationId,
					input.userId,
					input.applicationId,
					input.approvalTokenHash,
					input.approvedAt.toISOString()
				]
			);

			if (!result) {
				return null;
			}

			return parseVerification(result);
		},

		resolveMobileApproval: async (
			input: ResolveMobileApprovalInput
		): Promise<DeviceVerification | null> => {
			const result = await redis.eval<string[], unknown>(
				resolveMobileApprovalScript,
				[
					getVerificationKey(
						input.userId,
						input.verificationId
					)
				],
				[
					input.userId,
					input.approvalTokenHash,
					input.resolvedAt.toISOString()
				]
			);

			if (!result) {
				return null;
			}

			return parseVerification(result);
		},

		resolveBrowserMobileVerification: async (
			input: ResolveBrowserMobileVerificationInput
		): Promise<DeviceVerification | null> => {
			const result = await redis.eval<string[], unknown>(
				resolveBrowserMobileVerificationScript,
				[
					getVerificationKey(
						input.userId,
						input.verificationId
					)
				],
				[
					input.userId,
					input.applicationId,
					input.deviceId,
					input.browserTokenHash,
					input.resolvedAt.toISOString()
				]
			);

			if (!result) {
				return null;
			}

			return parseVerification(result);
		},

		rejectMobile: async (
			input: RejectMobileApprovalInput
		): Promise<DeviceVerification | null> => {
			const result = await redis.eval<string[], unknown>(
				rejectMobileScript,
				[
					getVerificationKey(
						input.userId,
						input.verificationId
					),
					getApprovalKey(
						input.userId,
						input.approvalTokenHash
					)
				],
				[
					input.verificationId,
					input.userId,
					input.approvalTokenHash,
					input.rejectedAt.toISOString()
				]
			);

			if (!result) {
				return null;
			}

			return parseVerification(result);
		},

		beginFinalization: async (
			input: BeginDeviceVerificationFinalizationInput
		): Promise<DeviceVerification | null> => {
			const result = await redis.eval<string[], unknown>(
				beginFinalizationScript,
				[
					getVerificationKey(
						input.userId,
						input.verificationId
					)
				],
				[
					input.userId,
					input.applicationId,
					input.deviceId,
					input.browserTokenHash,
					input.finalizingAt.toISOString(),
					input.recoveryLifetimeMs.toString()
				]
			);

			if (!result) {
				return null;
			}

			return parseVerification(result);
		},

		completeFinalization: async (
			input: CompleteDeviceVerificationFinalizationInput
		): Promise<DeviceVerification | null> => {
			const result = await redis.eval<string[], unknown>(
				completeFinalizationScript,
				[
					getVerificationKey(
						input.userId,
						input.verificationId
					)
				],
				[
					input.userId,
					input.applicationId,
					input.deviceId,
					input.browserTokenHash,
					input.consumedAt.toISOString(),
					input.recoveryLifetimeMs.toString()
				]
			);

			if (!result) {
				return null;
			}

			return parseVerification(result);
		}
	};
};

export default createDeviceVerificationRepository;
