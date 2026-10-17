import 'server-only';

import {
	sha256TokenHasher,
	systemClock
} from '@/lib/auth/shared/runtime-server';
import type {
	Clock,
	MobileInstallation,
	MobileInstallationRepository,
	PublicMobileInstallation,
	RegisterMobileInstallationInput,
	TokenHasher
} from '@/types/auth';

const MAX_PUSH_TOKEN_LENGTH = 4096;
const MAX_MOBILE_DEVICE_NAME_LENGTH = 120;
const MAX_MOBILE_APPLICATION_VERSION_LENGTH = 50;

/** Manages mobile application installations used by authentication. */
class MobileInstallationService {
	/**
	 * Creates a mobile installation service.
	 * @param repository - Mobile installation persistence adapter.
	 * @param clock - Time provider.
	 * @param tokenHasher - Push-token hashing adapter.
	 */
	constructor(
		private readonly repository: MobileInstallationRepository,
		private readonly clock: Clock = systemClock,
		private readonly tokenHasher: TokenHasher = sha256TokenHasher
	) {}

	/**
	 * Creates or refreshes an authenticated mobile application installation.
	 * @param input - Trusted user identity and mobile registration values.
	 * @returns The persisted mobile installation without its push token.
	 * @throws {TypeError} When a registration value is invalid.
	 */
	readonly register = async (
		input: RegisterMobileInstallationInput
	): Promise<PublicMobileInstallation> => {
		this.assertRequiredValue(
			input.userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			input.mobileInstallationId,
			'The mobile installation identifier is required.'
		);

		this.assertPushToken(input.pushToken);
		this.assertMobileApplicationId(input.mobileApplicationId);
		this.assertMobilePlatform(input.platform);

		const now = this.clock.now();
		const mobileInstallation: MobileInstallation = {
			id: input.mobileInstallationId,
			userId: input.userId,
			mobileApplicationId: input.mobileApplicationId,
			platform: input.platform,
			mobileDeviceName: this.normalizeOptionalValue(
				input.mobileDeviceName ?? null,
				MAX_MOBILE_DEVICE_NAME_LENGTH
			),
			mobileApplicationVersion: this.normalizeOptionalValue(
				input.mobileApplicationVersion ?? null,
				MAX_MOBILE_APPLICATION_VERSION_LENGTH
			),
			pushToken: input.pushToken.trim(),
			pushTokenHash: this.tokenHasher.hash(input.pushToken.trim()),
			status: 'active',
			createdAt: now,
			lastSeenAt: now,
			pushTokenUpdatedAt: now,
			disabledAt: null
		};

		const persistedMobileInstallation =
			await this.repository.upsert(mobileInstallation);

		return this.toPublicMobileInstallation(
			persistedMobileInstallation
		);
	};

	/**
	 * Lists active mobile installations including tokens for push delivery.
	 * @param userId - Firebase user owning the mobile installations.
	 * @returns Active mobile installations available for notification delivery.
	 */
	readonly listActiveForDelivery = async (
		userId: string
	): Promise<readonly MobileInstallation[]> => {
		this.assertRequiredValue(
			userId,
			'The Firebase user identifier is required.'
		);

		return this.repository.listActiveByUser(userId);
	};

	/**
	 * Reports whether an account has a mobile approval channel available.
	 * @param userId - Firebase user owning the mobile installations.
	 * @returns Whether at least one active mobile installation is registered.
	 */
	readonly hasActiveMobileInstallation = async (
		userId: string
	): Promise<boolean> => {
		const mobileInstallations =
			await this.listActiveForDelivery(userId);

		return mobileInstallations.length > 0;
	};

	/**
	 * Resolves an active mobile installation allowed to answer approvals.
	 * @param userId - Firebase user owning the mobile installation.
	 * @param mobileInstallationId - Registered mobile installation identifier.
	 * @returns The active mobile installation or null.
	 */
	readonly findActiveForApproval = async (
		userId: string,
		mobileInstallationId: string
	): Promise<MobileInstallation | null> => {
		this.assertRequiredValue(
			userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			mobileInstallationId,
			'The mobile installation identifier is required.'
		);

		const mobileInstallation = await this.repository.findById(
			userId,
			mobileInstallationId
		);

		if (
			!mobileInstallation ||
			mobileInstallation.status !== 'active' ||
			mobileInstallation.disabledAt !== null
		) {
			return null;
		}

		return mobileInstallation;
	};

	/**
	 * Disables a mobile installation and its push-delivery capability.
	 * @param userId - Firebase user owning the mobile installation.
	 * @param mobileInstallationId - Mobile installation identifier.
	 * @returns The disabled mobile installation without its push token, or null.
	 */
	readonly disable = async (
		userId: string,
		mobileInstallationId: string
	): Promise<PublicMobileInstallation | null> => {
		this.assertRequiredValue(
			userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			mobileInstallationId,
			'The mobile installation identifier is required.'
		);

		const mobileInstallation = await this.repository.disable(
			userId,
			mobileInstallationId,
			this.clock.now()
		);

		if (!mobileInstallation) {
			return null;
		}

		return this.toPublicMobileInstallation(mobileInstallation);
	};

	/**
	 * Removes server-only values from a mobile installation.
	 * @param mobileInstallation - Internal mobile installation state.
	 * @returns A safe mobile installation representation.
	 */
	private readonly toPublicMobileInstallation = (
		mobileInstallation: MobileInstallation
	): PublicMobileInstallation => {
		return {
			id: mobileInstallation.id,
			mobileApplicationId: mobileInstallation.mobileApplicationId,
			platform: mobileInstallation.platform,
			mobileDeviceName: mobileInstallation.mobileDeviceName,
			mobileApplicationVersion:
				mobileInstallation.mobileApplicationVersion,
			status: mobileInstallation.status,
			createdAt: mobileInstallation.createdAt,
			lastSeenAt: mobileInstallation.lastSeenAt,
			pushTokenUpdatedAt: mobileInstallation.pushTokenUpdatedAt,
			disabledAt: mobileInstallation.disabledAt
		};
	};

	/**
	 * Validates an authentication-capable mobile application identifier.
	 * @param mobileApplicationId - Mobile application identifier to validate.
	 * @throws {TypeError} When the application is not supported.
	 */
	private readonly assertMobileApplicationId = (
		mobileApplicationId: string
	): void => {
		if (
			mobileApplicationId !== 'calendis' &&
			mobileApplicationId !== 'collectineo'
		) {
			throw new TypeError(
				'The mobile application identifier is invalid.'
			);
		}
	};

	/**
	 * Validates a mobile operating system identifier.
	 * @param platform - Mobile platform to validate.
	 * @throws {TypeError} When the platform is not supported.
	 */
	private readonly assertMobilePlatform = (
		platform: string
	): void => {
		if (platform !== 'android' && platform !== 'ios') {
			throw new TypeError(
				'The mobile platform is invalid.'
			);
		}
	};

	/**
	 * Normalizes an optional bounded mobile metadata value.
	 * @param value - Untrusted optional metadata value.
	 * @param maximumLength - Maximum persisted character count.
	 * @returns The normalized value or null.
	 */
	private readonly normalizeOptionalValue = (
		value: string | null,
		maximumLength: number
	): string | null => {
		if (!value) {
			return null;
		}

		const normalizedValue = value.trim();

		if (!normalizedValue) {
			return null;
		}

		return normalizedValue.slice(0, maximumLength);
	};

	/**
	 * Validates a Firebase Cloud Messaging registration token.
	 * @param pushToken - Token supplied by the authenticated mobile application.
	 * @throws {TypeError} When the token is empty or unreasonably large.
	 */
	private readonly assertPushToken = (
		pushToken: string
	): void => {
		const normalizedPushToken = pushToken.trim();

		if (
			!normalizedPushToken ||
			normalizedPushToken.length > MAX_PUSH_TOKEN_LENGTH
		) {
			throw new TypeError(
				'The mobile push token is invalid.'
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

export default MobileInstallationService;
