import 'server-only';

import SecurityEventService from '@/lib/auth/audit/security-event-service';
import DeviceService from '@/lib/auth/device/device-service';
import { logAuthServerError } from '@/lib/auth/shared/auth-logger';
import AuthError from '@/lib/auth/shared/auth-error';
import {
	secureTokenGenerator,
	secureVerificationCodeGenerator,
	sha256TokenHasher,
	systemClock
} from '@/lib/auth/shared/runtime-server';
import type {
	ApproveMobileVerificationInput,
	AuthWarningNotifier,
	CancelEmailVerificationInput,
	Clock,
	CompleteDeviceVerificationInput,
	ConfirmEmailCodeInput,
	Device,
	DeviceVerification,
	DeviceVerificationMode,
	DeviceVerificationModePolicy,
	DeviceVerificationRepository,
	DeviceVerificationServiceOptions,
	EmailCodeResendTransitionInput,
	IssuedEmailDeviceVerification,
	IssuedMobileDeviceVerification,
	GetBrowserMobileVerificationInput,
	GetMobileApprovalRequestInput,
	ResolveDeviceVerificationModesInput,
	ResendEmailVerificationInput,
	StartDeviceVerificationInput,
	TokenGenerator,
	TokenHasher,
	VerificationCodeGenerator,
	VerificationCodeHasher
} from '@/types/auth';
import type VerificationRateLimitService from '@/lib/auth/verification/verification-rate-limit-service';

const VERIFICATION_CODE_PATTERN = /^\d{6}$/;

/** Enables email confirmation until a mobile policy is configured. */
const emailOnlyVerificationPolicy: DeviceVerificationModePolicy = {
	getAvailableModes: async () => ['email_code']
};

/** Coordinates short-lived confirmation of pending browser devices. */
class VerificationService {
	/**
	 * Creates a device verification service.
	 * @param repository - Temporary Redis verification repository.
	 * @param devices - Persistent device service.
	 * @param codeHasher - Keyed hasher for short email codes.
	 * @param options - Verification security settings.
	 * @param rateLimits - Verification rate limit.
	 * @param securityEvents - Secret-free security event recorder.
	 * @param authWarnings - Best-effort suspicious-authentication notifier.
	 * @param modePolicy - Per-user confirmation mode policy.
	 * @param clock - Time provider.
	 * @param tokenGenerator - Opaque token generator.
	 * @param tokenHasher - High-entropy token hashing adapter.
	 * @param codeGenerator - Short verification code generator.
	 */
	constructor(
		private readonly repository: DeviceVerificationRepository,
		private readonly devices: DeviceService,
		private readonly codeHasher: VerificationCodeHasher,
		private readonly options: DeviceVerificationServiceOptions,
		private readonly rateLimits: VerificationRateLimitService,
		private readonly securityEvents: SecurityEventService,
		private readonly authWarnings: AuthWarningNotifier,
		private readonly modePolicy: DeviceVerificationModePolicy =
		emailOnlyVerificationPolicy,
		private readonly clock: Clock = systemClock,
		private readonly tokenGenerator: TokenGenerator = secureTokenGenerator,
		private readonly tokenHasher: TokenHasher = sha256TokenHasher,
		private readonly codeGenerator: VerificationCodeGenerator =
		secureVerificationCodeGenerator
	) {
		if (
			!Number.isSafeInteger(options.lifetimeMs) ||
			options.lifetimeMs <= 0
		) {
			throw new RangeError(
				'Device verification lifetime must be a positive integer.'
			);
		}

		if (
			!Number.isSafeInteger(options.maxEmailAttempts) ||
			options.maxEmailAttempts <= 0
		) {
			throw new RangeError(
				'Maximum email attempts must be a positive integer.'
			);
		}

		if (
			!Number.isSafeInteger(options.maxEmailResends) ||
			options.maxEmailResends <= 0
		) {
			throw new RangeError(
				'Maximum email resends must be a positive integer.'
			);
		}

		if (
			!Number.isSafeInteger(options.emailResendCooldownMs) ||
			options.emailResendCooldownMs <= 0
		) {
			throw new RangeError(
				'Email resend cooldown must be a positive integer.'
			);
		}

		if (
			!Number.isSafeInteger(
				options.finalizationRecoveryMs
			) ||
			options.finalizationRecoveryMs <= 0
		) {
			throw new RangeError(
				'Finalization recovery lifetime must be a positive integer.'
			);
		}
	}

	/**
	 * Starts verification using an email code.
	 * @param input - Pending device identity.
	 * @returns Browser secret and code to send by email.
	 * @throws {AuthError} When email verification is unavailable.
	 */
	readonly startEmail = async (
		input: StartDeviceVerificationInput
	): Promise<IssuedEmailDeviceVerification> => {
		await this.assertModeAvailable(
			input,
			'email_code'
		);

		await this.assertPendingDevice(input);

		const verificationId = this.tokenGenerator.generate();
		const browserToken = this.tokenGenerator.generate();
		const emailCode = this.codeGenerator.generate();

		if (!VERIFICATION_CODE_PATTERN.test(emailCode)) {
			throw new Error(
				'The verification code generator returned an invalid code.'
			);
		}

		const requestedAt = this.clock.now();

		await this.rateLimits.reserveInitialEmail({
			userId: input.userId,
			applicationId: input.applicationId,
			deviceId: input.deviceId,
			requestedAt
		});

		const verification = await this.repository.create(
			this.createVerification(
				verificationId,
				browserToken,
				input,
				'email_code',
				this.codeHasher.hash(
					emailCode,
					verificationId
				),
				null
			)
		);

		return {
			verification,
			browserToken,
			emailCode
		};
	};

	/**
	 * Starts verification using an authenticated mobile approval.
	 * @param input - Pending device identity.
	 * @returns Browser and mobile approval secrets.
	 * @throws {AuthError} When mobile approval is unavailable.
	 */
	readonly startMobile = async (
		input: StartDeviceVerificationInput
	): Promise<IssuedMobileDeviceVerification> => {
		await this.assertModeAvailable(
			input,
			'mobile_approval'
		);

		await this.assertPendingDevice(input);

		const verificationId = this.tokenGenerator.generate();
		const browserToken = this.tokenGenerator.generate();
		const approvalToken = this.tokenGenerator.generate();

		const verification = await this.repository.create(
			this.createVerification(
				verificationId,
				browserToken,
				input,
				'mobile_approval',
				null,
				this.tokenHasher.hash(approvalToken)
			)
		);

		return {
			verification,
			browserToken,
			approvalToken
		};
	};

	/**
	 * Confirms a verification using an email code.
	 * @param input - Bound email code attempt.
	 * @returns The approved verification.
	 * @throws {AuthError} When the verification cannot be approved.
	 */
	readonly confirmEmail = async (
		input: ConfirmEmailCodeInput
	): Promise<DeviceVerification> => {
		this.assertRequiredValue(
			input.userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			input.verificationId,
			'The verification identifier is required.'
		);

		this.assertRequiredValue(
			input.browserToken,
			'The browser verification token is required.'
		);

		this.assertRequiredValue(
			input.applicationId,
			'The application identifier is required.'
		);

		this.assertRequiredValue(
			input.deviceId,
			'The device identifier is required.'
		);

		if (!VERIFICATION_CODE_PATTERN.test(input.code)) {
			throw new AuthError(
				'verification_invalid',
				'The verification code is invalid.'
			);
		}

		const result = await this.repository.attemptEmailCode({
			userId: input.userId,
			verificationId: input.verificationId,
			browserTokenHash: this.tokenHasher.hash(
				input.browserToken
			),
			codeHash: this.codeHasher.hash(
				input.code,
				input.verificationId
			),
			applicationId: input.applicationId,
			attemptedAt: this.clock.now()
		});

		switch (result.outcome) {
			case 'approved':
				return result.verification;

			case 'expired': {
				await this.securityEvents.record({
					userId: input.userId,
					type: 'device_verification_expired',
					applicationId: input.applicationId,
					deviceId: null,
					sessionId: null,
					affectedCount: 1
				});

				throw new AuthError(
					'verification_expired',
					'The device verification has expired.'
				);
			}

			case 'locked': {
				if (result.newlyLocked) {
					const occurredAt = this.clock.now();

					await this.securityEvents.record({
						userId: input.userId,
						type: 'device_verification_locked',
						applicationId: input.applicationId,
						deviceId: input.deviceId,
						sessionId: null,
						affectedCount:
							this.options.maxEmailAttempts
					});

					await this.authWarnings.notify({
						userId: input.userId,
						applicationId: input.applicationId,
						deviceId: input.deviceId,
						verificationId: input.verificationId,
						trigger: 'verification_locked',
						occurredAt,
						penaltyLevel: null
					});
				}

				throw new AuthError(
					'verification_locked',
					'Too many invalid verification attempts.'
				);
			}

			case 'invalid':
				throw new AuthError(
					'verification_invalid',
					`The verification code is invalid. ${result.remainingAttempts} attempts remain.`
				);

			case 'not_found':
				throw new AuthError(
					'verification_expired',
					'The device verification is no longer available.'
				);
		}
	};

	/**
	 * Replaces an existing email verification code.
	 * @param input - Browser-bound email verification identity.
	 * @returns The updated verification and replacement code.
	 * @throws {AuthError} When resending is unavailable or throttled.
	 */
	readonly resendEmail = async (
		input: ResendEmailVerificationInput
	): Promise<IssuedEmailDeviceVerification> => {
		this.assertEmailManagementInput(input);

		const emailCode = this.codeGenerator.generate();

		if (!VERIFICATION_CODE_PATTERN.test(emailCode)) {
			throw new Error(
				'The verification code generator returned an invalid code.'
			);
		}

		const sentAt = this.clock.now();

		await this.rateLimits.assertResendAllowed({
			userId: input.userId,
			applicationId: input.applicationId,
			deviceId: input.deviceId,
			requestedAt: sentAt
		});

		const result = await this.repository.resendEmailCode({
			userId: input.userId,
			verificationId: input.verificationId,
			applicationId: input.applicationId,
			deviceId: input.deviceId,
			browserTokenHash: this.tokenHasher.hash(
				input.browserToken
			),
			codeHash: this.codeHasher.hash(
				emailCode,
				input.verificationId
			),
			sentAt,
			expiresAt: new Date(
				sentAt.getTime() + this.options.lifetimeMs
			),
			cooldownMs: this.options.emailResendCooldownMs,
			maxResends: this.options.maxEmailResends
		});

		switch (result.outcome) {
			case 'resent':
				return {
					verification: result.verification,
					browserToken: input.browserToken,
					emailCode
				};

			case 'cooldown':
				throw new AuthError(
					'verification_resend_too_soon',
					`A new verification email can be requested in ${result.retryAfterMs} milliseconds.`,
					Math.ceil(result.retryAfterMs / 1_000)
				);

			case 'limit_reached':
				const retryAfterMs = await this.rateLimits.penalize({
					userId: input.userId,
					applicationId: input.applicationId,
					deviceId: input.deviceId,
					requestedAt: sentAt
				});

				throw new AuthError(
					'verification_rate_limited',
					'Verification email delivery is temporarily limited.',
					Math.ceil(retryAfterMs / 1_000)
				);

			case 'not_found':
				throw new AuthError(
					'verification_expired',
					'The email verification is no longer available.'
				);
		}
	};

	/**
	 * Commits a replacement code after successful email delivery.
	 * @param input - Browser-bound email verification identity.
	 * @param issued - Reserved verification and replacement code.
	 * @returns A promise resolved after the reservation cleanup attempt.
	 */
	readonly completeEmailResend = async (
		input: ResendEmailVerificationInput,
		issued: IssuedEmailDeviceVerification
	): Promise<void> => {
		const completed =
			await this.repository.completeEmailCodeResend(
				this.createEmailResendTransition(input, issued)
			);

		if (!completed) {
			logAuthServerError(
				new Error(
					'The email resend reservation could not be completed.'
				),
				'email_resend_completion'
			);

			return;
		}

		if (
			issued.verification.emailResendCount >=
			this.options.maxEmailResends
		) {
			await this.rateLimits.penalize({
				userId: input.userId,
				applicationId: input.applicationId,
				deviceId: input.deviceId,
				requestedAt: this.clock.now()
			});
		}
	};

	/**
	 * Restores the previous code after email delivery failure.
	 * @param input - Browser-bound email verification identity.
	 * @param issued - Reserved verification and replacement code.
	 * @returns A promise resolved after the rollback attempt.
	 */
	readonly rollbackEmailResend = async (
		input: ResendEmailVerificationInput,
		issued: IssuedEmailDeviceVerification
	): Promise<void> => {
		const rolledBack =
			await this.repository.rollbackEmailCodeResend(
				this.createEmailResendTransition(input, issued)
			);

		if (!rolledBack) {
			logAuthServerError(
				new Error(
					'The email resend reservation could not be rolled back.'
				),
				'email_resend_rollback'
			);
		}
	};

	/**
	 * Cancels an existing browser-bound email verification.
	 * @param input - Browser-bound email verification identity.
	 * @returns A promise resolved after cancellation.
	 */
	readonly cancelEmail = async (
		input: CancelEmailVerificationInput
	): Promise<void> => {
		this.assertEmailManagementInput(input);

		const cancelled = await this.repository.cancelEmail({
			userId: input.userId,
			verificationId: input.verificationId,
			applicationId: input.applicationId,
			deviceId: input.deviceId,
			browserTokenHash: this.tokenHasher.hash(
				input.browserToken
			)
		});

		if (!cancelled) {
			return;
		}

		await this.securityEvents.record({
			userId: input.userId,
			type: 'device_verification_cancelled',
			applicationId: input.applicationId,
			deviceId: input.deviceId,
			sessionId: null,
			affectedCount: 1
		});
	};

	/**
	 * Creates the secret-bound transition used to finish an email resend.
	 * @param input - Browser-bound resend identity.
	 * @param issued - Reserved verification and replacement code.
	 * @returns The hashed resend transition.
	 */
	private readonly createEmailResendTransition = (
		input: ResendEmailVerificationInput,
		issued: IssuedEmailDeviceVerification
	): EmailCodeResendTransitionInput => {
		return {
			userId: input.userId,
			verificationId: input.verificationId,
			applicationId: input.applicationId,
			deviceId: input.deviceId,
			browserTokenHash: this.tokenHasher.hash(
				input.browserToken
			),
			codeHash: this.codeHasher.hash(
				issued.emailCode,
				input.verificationId
			)
		};
	};

	/**
	 * Approves a verification from an authenticated mobile application.
	 * @param input - Bound mobile approval.
	 * @returns The approved verification.
	 * @throws {AuthError} When the approval is invalid or expired.
	 */
	readonly approveMobile = async (
		input: ApproveMobileVerificationInput
	): Promise<DeviceVerification> => {
		this.assertRequiredValue(
			input.userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			input.verificationId,
			'The verification identifier is required.'
		);

		this.assertRequiredValue(
			input.approvalToken,
			'The mobile approval token is required.'
		);

		this.assertRequiredValue(
			input.applicationId,
			'The application identifier is required.'
		);

		const verification = await this.repository.approveMobile({
			userId: input.userId,
			verificationId: input.verificationId,
			approvalTokenHash: this.tokenHasher.hash(
				input.approvalToken
			),
			applicationId: input.applicationId,
			approvedAt: this.clock.now()
		});

		if (!verification) {
			throw new AuthError(
				'verification_invalid',
				'The mobile approval is invalid or expired.'
			);
		}

		return verification;
	};

	/**
	 * Resolves a mobile approval request from its notification secret.
	 * @param input - Authenticated mobile approval identity.
	 * @returns The matching verification.
	 * @throws {AuthError} When the request is invalid or expired.
	 */
	readonly getMobileApproval = async (
		input: GetMobileApprovalRequestInput
	): Promise<DeviceVerification> => {
		this.assertRequiredValue(
			input.userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			input.verificationId,
			'The verification identifier is required.'
		);

		this.assertRequiredValue(
			input.approvalToken,
			'The mobile approval token is required.'
		);

		const verification =
			await this.repository.resolveMobileApproval({
				userId: input.userId,
				verificationId: input.verificationId,
				approvalTokenHash: this.tokenHasher.hash(
					input.approvalToken
				),
				resolvedAt: this.clock.now()
			});

		if (!verification) {
			throw new AuthError(
				'verification_invalid',
				'The mobile approval is invalid or expired.'
			);
		}

		return verification;
	};

	/**
	 * Resolves mobile verification state from its browser secret.
	 * @param input - Browser-bound mobile verification identity.
	 * @returns The matching verification.
	 * @throws {AuthError} When the request is invalid or expired.
	 */
	readonly getBrowserMobileVerification = async (
		input: GetBrowserMobileVerificationInput
	): Promise<DeviceVerification> => {
		const verification =
			await this.repository.resolveBrowserMobileVerification({
				userId: input.userId,
				verificationId: input.verificationId,
				applicationId: input.applicationId,
				deviceId: input.deviceId,
				browserTokenHash: this.tokenHasher.hash(
					input.browserToken
				),
				resolvedAt: this.clock.now()
			});

		if (!verification) {
			throw new AuthError(
				'verification_invalid',
				'The mobile verification is invalid or expired.'
			);
		}

		return verification;
	};

	/**
	 * Rejects a pending verification from an authenticated mobile application.
	 * @param input - Bound mobile approval identity.
	 * @returns The rejected verification.
	 * @throws {AuthError} When the rejection is invalid or too late.
	 */
	readonly rejectMobile = async (
		input: ApproveMobileVerificationInput
	): Promise<DeviceVerification> => {
		const approvalTokenHash = this.tokenHasher.hash(
			input.approvalToken
		);

		const verification = await this.repository.rejectMobile({
			userId: input.userId,
			verificationId: input.verificationId,
			approvalTokenHash,
			rejectedAt: this.clock.now()
		});

		if (!verification) {
			throw new AuthError(
				'verification_invalid',
				'The mobile rejection is invalid or expired.'
			);
		}

		return verification;
	};

	/**
	 * Consumes an approval and marks its device as verified.
	 * @param input - Bound verification completion.
	 * @returns The verified device.
	 * @throws {AuthError} When the verification is not ready.
	 */
	readonly complete = async (
		input: CompleteDeviceVerificationInput
	): Promise<Device> => {
		this.assertRequiredValue(
			input.userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			input.verificationId,
			'The verification identifier is required.'
		);

		this.assertRequiredValue(
			input.browserToken,
			'The browser verification token is required.'
		);

		this.assertRequiredValue(
			input.applicationId,
			'The application identifier is required.'
		);

		this.assertRequiredValue(
			input.deviceId,
			'The device identifier is required.'
		);

		const browserTokenHash = this.tokenHasher.hash(
			input.browserToken
		);

		const finalizingVerification =
			await this.repository.beginFinalization({
			userId: input.userId,
			verificationId: input.verificationId,
			browserTokenHash,
			applicationId: input.applicationId,
			deviceId: input.deviceId,
			finalizingAt: this.clock.now(),
			recoveryLifetimeMs:
				this.options.finalizationRecoveryMs
		});

		if (!finalizingVerification) {
			throw new AuthError(
				'verification_not_ready',
				'The device verification is not approved.'
			);
		}

		const device = await this.devices.verifyPending(
			input.userId,
			input.deviceId,
			input.applicationId
		);

		const completedVerification =
			await this.repository.completeFinalization({
				userId: input.userId,
				verificationId: input.verificationId,
				browserTokenHash,
				applicationId: input.applicationId,
				deviceId: input.deviceId,
				consumedAt: this.clock.now(),
				recoveryLifetimeMs:
					this.options.finalizationRecoveryMs
			});

		if (!completedVerification) {
			throw new AuthError(
				'verification_not_ready',
				'The device verification could not be finalized.'
			);
		}

		return device;
	};

	/**
	 * Resolves the confirmation modes available to a user.
	 * @param input - Pending device identity.
	 * @returns The available confirmation modes.
	 */
	readonly getAvailableModes = async (
		input: ResolveDeviceVerificationModesInput
	): Promise<readonly DeviceVerificationMode[]> => {
		const modes = await this.modePolicy.getAvailableModes(
			input
		);

		return [...modes];
	};

	/**
	 * Rejects a disabled confirmation mode.
	 * @param input - Pending device identity.
	 * @param mode - Requested confirmation mode.
	 * @throws {AuthError} When the mode is unavailable.
	 */
	private readonly assertModeAvailable = async (
		input: ResolveDeviceVerificationModesInput,
		mode: DeviceVerificationMode
	): Promise<void> => {
		const availableModes = await this.getAvailableModes(
			input
		);

		if (!availableModes.includes(mode)) {
			throw new AuthError(
				'verification_mode_unavailable',
				'The requested device verification mode is unavailable.'
			);
		}
	};

	/**
	 * Resolves and validates the pending device binding.
	 * @param input - Pending device identity.
	 * @returns The validated pending device.
	 * @throws {AuthError} When the device binding is invalid.
	 */
	private readonly assertPendingDevice = async (
		input: StartDeviceVerificationInput
	): Promise<Device> => {
		const device = await this.devices.findById(
			input.userId,
			input.deviceId
		);

		if (
			device.userId !== input.userId ||
			device.applicationId !== input.applicationId ||
			device.status !== 'pending'
		) {
			throw new AuthError(
				'device_invalid',
				'The pending device binding is invalid.'
			);
		}

		return device;
	};

	/**
	 * Creates a bound temporary verification.
	 * @param id - Verification identifier.
	 * @param browserToken - Raw browser continuation token.
	 * @param input - Pending device identity.
	 * @param mode - Selected verification mode.
	 * @param codeHash - Keyed email code hash.
	 * @param approvalTokenHash - Mobile approval token hash.
	 * @returns The temporary verification state.
	 */
	private readonly createVerification = (
		id: string,
		browserToken: string,
		input: StartDeviceVerificationInput,
		mode: DeviceVerificationMode,
		codeHash: string | null,
		approvalTokenHash: string | null
	): DeviceVerification => {
		const now = this.clock.now();

		return {
			id,
			userId: input.userId,
			applicationId: input.applicationId,
			deviceId: input.deviceId,
			mode,
			browserTokenHash: this.tokenHasher.hash(
				browserToken
			),
			codeHash,
			approvalTokenHash,
			status: 'pending',
			failedAttempts: 0,
			maxAttempts: this.options.maxEmailAttempts,
			emailResendCount: 0,
			emailLastSentAt: mode === 'email_code' ? now : null,
			createdAt: now,
			expiresAt: new Date(
				now.getTime() + this.options.lifetimeMs
			),
			approvedAt: null,
			rejectedAt: null,
			finalizingAt: null,
			consumedAt: null
		};
	};

	/**
	 * Validates values binding an email verification management request.
	 * @param input - Email verification request to validate.
	 * @throws {TypeError} When a required value is empty.
	 */
	private readonly assertEmailManagementInput = (
		input: ResendEmailVerificationInput
	): void => {
		this.assertRequiredValue(
			input.userId,
			'The Firebase user identifier is required.'
		);

		this.assertRequiredValue(
			input.verificationId,
			'The verification identifier is required.'
		);

		this.assertRequiredValue(
			input.browserToken,
			'The browser verification token is required.'
		);

		this.assertRequiredValue(
			input.applicationId,
			'The application identifier is required.'
		);

		this.assertRequiredValue(
			input.deviceId,
			'The device identifier is required.'
		);
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

export default VerificationService;
