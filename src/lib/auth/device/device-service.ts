import 'server-only';

import SecurityEventService from '@/lib/auth/audit/security-event-service';
import AuthError from '@/lib/auth/shared/auth-error';
import {
	secureTokenGenerator,
	sha256TokenHasher,
	systemClock
} from '@/lib/auth/shared/runtime-server';
import type {
	Clock,
	CreateDeviceInput,
	DetectedDeviceInformation,
	Device,
	DeviceLoginDecision,
	DeviceRepository,
	DeviceServiceOptions,
	IssuedDevice,
	PrepareDeviceLoginInput,
	TokenGenerator,
	TokenHasher
} from '@/types/auth';

/** Manages persistent browser recognition and trusted-device transitions. */
class DeviceService {
	/**
	 * Creates a device service.
	 * @param repository - Device persistence adapter.
	 * @param options - Trusted-device security settings.
	 * @param securityEvents - Secret-free security event recorder.
	 * @param clock - Time provider.
	 * @param tokenGenerator - Opaque token generator.
	 * @param tokenHasher - Token hashing adapter.
	 */
	constructor(
		private readonly repository: DeviceRepository,
		private readonly options: DeviceServiceOptions,
		private readonly securityEvents: SecurityEventService,
		private readonly clock: Clock = systemClock,
		private readonly tokenGenerator: TokenGenerator = secureTokenGenerator,
		private readonly tokenHasher: TokenHasher = sha256TokenHasher
	) {
		if (
			!Number.isSafeInteger(options.pendingLifetimeMs) ||
			options.pendingLifetimeMs <= 0
		) {
			throw new RangeError(
				'Pending device lifetime must be a positive integer.'
			);
		}

		if (
			!Number.isSafeInteger(options.trustedLifetimeMs) ||
			options.trustedLifetimeMs <= 0
		) {
			throw new RangeError(
				'Trusted device lifetime must be a positive integer.'
			);
		}

		if (
			options.pendingLifetimeMs >=
			options.trustedLifetimeMs
		) {
			throw new RangeError(
				'Pending device lifetime must be shorter than trusted device lifetime.'
			);
		}
	}

	/**
	 * Issues a new pending browser device.
	 * @param userId - Firebase user owning the device.
	 * @param applicationId - Application owning the device.
	 * @param displayName - Optional user-facing device label.
	 * @param detectedInformation - Information derived from request headers.
	 * @returns The persisted device and its raw cookie token.
	 */
	readonly issue = async (
		userId: string,
		applicationId: string,
		displayName: string | null,
		detectedInformation: DetectedDeviceInformation
	): Promise<IssuedDevice> => {
		this.assertRequiredValue(
			userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			applicationId,
			'The application identifier is required.'
		);

		const now = this.clock.now();
		const token = this.tokenGenerator.generate();

		const device: CreateDeviceInput = {
			tokenHash: this.tokenHasher.hash(token),
			userId,
			applicationId,
			displayName: this.createDisplayName(
				detectedInformation,
				displayName
			),
			category: detectedInformation.category,
			browserName: detectedInformation.browserName,
			browserVersion: detectedInformation.browserVersion,
			operatingSystemName:
				detectedInformation.operatingSystemName,
			operatingSystemVersion:
				detectedInformation.operatingSystemVersion,
			deviceBrand: detectedInformation.deviceBrand,
			deviceModel: detectedInformation.deviceModel,
			status: 'pending',
			createdAt: now,
			expiresAt: new Date(
				now.getTime() + this.options.pendingLifetimeMs
			),
			lastSeenAt: now,
			verifiedAt: null,
			revokedAt: null
		};

		const persistedDevice = await this.repository.create(device);

		return {
			device: persistedDevice,
			token
		};
	};

	/**
	 * Resolves a valid browser device cookie.
	 * @param userId - Firebase user owning the device collection.
	 * @param token - Raw device cookie value.
	 * @returns The recognized device.
	 * @throws {AuthError} When the device is unknown or revoked.
	 */
	readonly recognize = async (
		userId: string,
		token: string
	): Promise<Device> => {
		this.assertRequiredValue(
			userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			token,
			'The device token is required.'
		);

		const device = await this.findRecognizedDevice(
			userId,
			token
		);

		if (!device) {
			throw new AuthError(
				'device_invalid',
				'The browser device is unknown, expired, or revoked.'
			);
		}

		return device;
	};

	/**
	 * Resolves a valid device from its internal identifier.
	 * @param userId - Firebase user owning the device collection.
	 * @param deviceId - Internal device identifier.
	 * @returns The recognized device.
	 * @throws {AuthError} When the device is unknown or revoked.
	 */
	readonly findById = async (
		userId: string,
		deviceId: string
	): Promise<Device> => {
		this.assertRequiredValue(
			userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			deviceId,
			'The device identifier is required.'
		);

		const device = await this.repository.findById(
			userId,
			deviceId
		);

		if (
			!device ||
			device.status === 'revoked' ||
			device.revokedAt ||
			this.isExpired(device)
		) {
			throw new AuthError(
				'device_invalid',
				'The browser device is unknown, expired, or revoked.'
			);
		}

		this.assertDeviceOwner(device, userId);

		return device;
	};

	/**
	 * Ensures a pending or already verified device is verified.
	 * @param userId - Expected Firebase user identifier.
	 * @param deviceId - Pending device identifier.
	 * @param applicationId - Expected application identifier.
	 * @returns The verified device.
	 * @throws {AuthError} When the transition is invalid.
	 */
	readonly verifyPending = async (
		userId: string,
		deviceId: string,
		applicationId: string
	): Promise<Device> => {
		this.assertRequiredValue(
			userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			deviceId,
			'The device identifier is required.'
		);

		this.assertRequiredValue(
			applicationId,
			'The application identifier is required.'
		);

		const verifiedAt = this.clock.now();
		const expiresAt = new Date(
			verifiedAt.getTime() +
			this.options.trustedLifetimeMs
		);

		const verifiedDevice = await this.repository.verifyPending(
			userId,
			deviceId,
			applicationId,
			verifiedAt,
			expiresAt
		);

		if (!verifiedDevice) {
			throw new AuthError(
				'device_invalid',
				'The pending device could not be verified.'
			);
		}

		await this.securityEvents.record({
			userId,
			type: 'device_verified',
			applicationId,
			deviceId: verifiedDevice.id,
			sessionId: null,
			affectedCount: 1
		});

		return verifiedDevice;
	};

	/**
	 * Lists every device owned by an account.
	 * @param userId - Firebase user owning the devices.
	 * @returns The account devices.
	 */
	readonly list = async (
		userId: string
	): Promise<readonly Device[]> => {
		this.assertRequiredValue(
			userId,
			'The Firebase user identifier is required.'
		);

		return this.repository.listByUser(userId);
	};

	/**
	 * Renames an active browser device.
	 * @param userId - Firebase user owning the device.
	 * @param deviceId - Device identifier.
	 * @param displayName - New optional user-facing label.
	 * @returns The renamed device.
	 * @throws {AuthError} When the device cannot be changed.
	 */
	readonly rename = async (
		userId: string,
		deviceId: string,
		displayName: string | null
	): Promise<Device> => {
		this.assertRequiredValue(
			userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			deviceId,
			'The device identifier is required.'
		);

		const renamedDevice = await this.repository.rename(
			userId,
			deviceId,
			this.normalizeDisplayName(displayName)
		);

		if (!renamedDevice) {
			throw new AuthError(
				'device_invalid',
				'The browser device cannot be renamed.'
			);
		}

		return renamedDevice;
	};

	/**
	 * Revokes a browser device.
	 * @param userId - Firebase user owning the device.
	 * @param deviceId - Device identifier.
	 * @returns The revoked device.
	 * @throws {AuthError} When the device does not exist.
	 */
	readonly revoke = async (
		userId: string,
		deviceId: string
	): Promise<Device> => {
		this.assertRequiredValue(
			userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			deviceId,
			'The device identifier is required.'
		);

		const revokedDevice = await this.repository.revoke(
			userId,
			deviceId,
			this.clock.now()
		);

		if (!revokedDevice) {
			throw new AuthError(
				'device_invalid',
				'The browser device does not exist.'
			);
		}

		await this.securityEvents.record({
			userId,
			type: 'device_revoked',
			applicationId: revokedDevice.applicationId,
			deviceId: revokedDevice.id,
			sessionId: null,
			affectedCount: 1
		});

		return revokedDevice;
	};

	/**
	 * Applies the trusted-device gate after primary authentication.
	 * @param input - Authenticated login and optional device cookie.
	 * @returns A session-ready or verification-required decision.
	 * @throws {AuthError} When the device does not belong to the user.
	 */
	readonly prepareLogin = async (
		input: PrepareDeviceLoginInput
	): Promise<DeviceLoginDecision> => {
		this.assertRequiredValue(
			input.userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			input.applicationId,
			'The application identifier is required.'
		);

		if (!input.deviceToken) {
			const issuedDevice = await this.issue(
				input.userId,
				input.applicationId,
				input.displayName ?? null,
				input.detectedInformation
			);

			return {
				status: 'verification_required',
				device: issuedDevice.device,
				issuedDeviceToken: issuedDevice.token
			};
		}

		const device = await this.findRecognizedDevice(
			input.userId,
			input.deviceToken
		);

		if (!device) {
			const issuedDevice = await this.issue(
				input.userId,
				input.applicationId,
				input.displayName ?? null,
				input.detectedInformation
			);

			return {
				status: 'verification_required',
				device: issuedDevice.device,
				issuedDeviceToken: issuedDevice.token
			};
		}

		if (device.status === 'verified') {
			return this.prepareVerifiedDevice(
				device,
				input.userId
			);
		}

		if (device.applicationId !== input.applicationId) {
			const issuedDevice = await this.issue(
				input.userId,
				input.applicationId,
				input.displayName ?? null,
				input.detectedInformation
			);

			return {
				status: 'verification_required',
				device: issuedDevice.device,
				issuedDeviceToken: issuedDevice.token
			};
		}

		return {
			status: 'verification_required',
			device,
			issuedDeviceToken: null
		};
	};

	/**
	 * Resolves a usable device without treating stale cookies as fatal errors.
	 * @param userId - Firebase user owning the device.
	 * @param token - Raw device cookie value.
	 * @returns The usable device or null.
	 * @throws {AuthError} When the stored owner does not match.
	 */
	private readonly findRecognizedDevice = async (
		userId: string,
		token: string
	): Promise<Device | null> => {
		const tokenHash = this.tokenHasher.hash(token);
		const device = await this.repository.findByTokenHash(
			userId,
			tokenHash
		);

		if (
			!device ||
			device.status === 'revoked' ||
			device.revokedAt ||
			this.isExpired(device)
		) {
			return null;
		}

		this.assertDeviceOwner(device, userId);

		return device;
	};

	/**
	 * Determines whether a device has reached its fixed server-side expiry.
	 * @param device - Device to inspect.
	 * @returns Whether the device is expired.
	 */
	private readonly isExpired = (
		device: Device
	): boolean => {
		return device.expiresAt.getTime() <= this.clock.now().getTime();
	};

	/**
	 * Validates and refreshes a previously verified device.
	 * @param device - Verified device.
	 * @param userId - Expected Firebase user identifier.
	 * @returns A session-ready decision.
	 * @throws {AuthError} When the device is no longer trusted.
	 */
	private readonly prepareVerifiedDevice = async (
		device: Device,
		userId: string
	): Promise<DeviceLoginDecision> => {
		if (device.userId !== userId) {
			throw new AuthError(
				'device_user_mismatch',
				'The verified device owner is invalid.'
			);
		}

		const updatedDevice = await this.repository.touchVerified(
			userId,
			device.id,
			this.clock.now()
		);

		if (!updatedDevice) {
			throw new AuthError(
				'device_invalid',
				'The verified device is no longer trusted.'
			);
		}

		return {
			status: 'session_ready',
			device: updatedDevice,
			issuedDeviceToken: null
		};
	};

	/**
	 * Normalizes an optional device label before persistence.
	 * @param displayName - Untrusted device label.
	 * @returns A bounded label or null.
	 */
	private readonly normalizeDisplayName = (
		displayName: string | null
	): string | null => {
		if (!displayName) {
			return null;
		}

		const normalizedDisplayName = displayName.trim();

		if (!normalizedDisplayName) {
			return null;
		}

		return normalizedDisplayName.slice(0, 120);
	};

	/**
	 * Creates a useful default label from server-detected information.
	 * @param information - Information derived from request headers.
	 * @param fallbackDisplayName - Optional client-provided fallback label.
	 * @returns A bounded user-facing label or null.
	 */
	private readonly createDisplayName = (
		information: DetectedDeviceInformation,
		fallbackDisplayName: string | null
	): string | null => {
		const deviceName =
			information.deviceModel ??
			information.operatingSystemName;

		if (information.browserName && deviceName) {
			return this.normalizeDisplayName(
				`${information.browserName} sur ${deviceName}`
			);
		}

		if (information.browserName) {
			return this.normalizeDisplayName(information.browserName);
		}

		if (deviceName) {
			return this.normalizeDisplayName(deviceName);
		}

		return this.normalizeDisplayName(fallbackDisplayName);
	};

	/**
	 * Ensures a device belongs to the expected Firebase user.
	 * @param device - Device returned by the persistence repository.
	 * @param userId - Expected Firebase user identifier.
	 * @throws {AuthError} When the device owner does not match.
	 */
	private readonly assertDeviceOwner = (
		device: Device,
		userId: string
	): void => {
		if (device.userId !== userId) {
			throw new AuthError(
				'device_user_mismatch',
				'The device belongs to another user.'
			);
		}
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

export default DeviceService;
