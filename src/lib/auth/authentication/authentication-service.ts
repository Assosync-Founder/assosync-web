import 'server-only';

import DeviceService from '@/lib/auth/device/device-service';
import MobileApprovalService from '@/lib/auth/mobile/approval/approval-service';
import { logAuthServerError } from '@/lib/auth/shared/auth-logger';
import AuthError from '@/lib/auth/shared/auth-error';
import SessionService from '@/lib/auth/session/session-service';
import VerificationEmailService from '@/lib/auth/verification/verification-email-service';
import VerificationService from '@/lib/auth/verification/verification-service';
import type {
	AuthenticationIdentity,
	AuthenticationIdentityProvider,
	CompleteEmailAuthenticationInput,
	CompleteMobileAuthenticationInput,
	DeviceVerification,
	DeviceVerificationMode,
	IssuedSession,
	ManageEmailAuthenticationVerificationInput,
	StartAuthenticationInput,
	StartAuthenticationResult
} from '@/types/auth';

/**
 * Records the exact authentication stage that rejected an operation.
 * @template Result
 * @param operation - Stable authentication operation identifier.
 * @param action - Asynchronous operation to observe.
 * @returns The operation result.
 */
const observeAuthenticationOperation = async <Result>(
	operation: string,
	action: () => Promise<Result>
): Promise<Result> => {
	try {
		return await action();
	} catch (error: unknown) {
		logAuthServerError(error, operation);

		return Promise.reject(error);
	}
};

/** Coordinates primary authentication, devices, verification, and sessions. */
class AuthenticationService {
	/**
	 * Creates the authentication workflow.
	 * @param identities - Firebase identity verifier.
	 * @param devices - Trusted browser device service.
	 * @param verifications - Temporary device verification service.
	 * @param verificationEmails - Verification email service.
	 * @param mobileApprovals - Mobile approval notification workflow.
	 * @param sessions - Application session service.
	 */
	constructor(
		private readonly identities: AuthenticationIdentityProvider,
		private readonly devices: DeviceService,
		private readonly verifications: VerificationService,
		private readonly verificationEmails: VerificationEmailService,
		private readonly mobileApprovals: MobileApprovalService,
		private readonly sessions: SessionService
	) {}

	/** Verifies a fresh Firebase identity before starting an authentication flow.
	 * @param idToken - Firebase ID token obtained after product sign-in.
	 * @returns The verified and enabled Firebase identity.
	 */
	readonly verifyIdentity = async (
		idToken: string
	): Promise<AuthenticationIdentity> => {
		this.assertRequiredValue(
			idToken,
			'The Firebase ID token is required.'
		);

		return this.identities.verify(idToken);
	};

	/**
	 * Starts authentication after a successful Firebase client sign-in.
	 * @param input - Firebase token, application, and optional device token.
	 * @returns A ready session or a required device verification.
	 */
	readonly start = async (
		input: StartAuthenticationInput
	): Promise<StartAuthenticationResult> => {
		this.assertRequiredValue(
			input.idToken,
			'The Firebase ID token is required.'
		);

		this.assertRequiredValue(
			input.applicationId,
			'The application identifier is required.'
		);

		const identity = await observeAuthenticationOperation(
			'authentication_identity_verification',
			async () => this.verifyIdentity(input.idToken)
		);

		const decision = await observeAuthenticationOperation(
			'authentication_device_preparation',
			async () => this.devices.prepareLogin({
				userId: identity.userId,
				applicationId: input.applicationId,
				deviceToken: input.deviceToken,
				displayName: input.deviceDisplayName ?? null,
				detectedInformation: input.detectedDeviceInformation
			})
		);

		if (decision.status === 'session_ready') {
			if (!input.deviceToken) {
				throw new AuthError(
					'device_invalid',
					'The recognized device token is missing.'
				);
			}

			const issuedSession =
				await this.sessions.issue({
					idToken: input.idToken,
					deviceId: decision.device.id,
					deviceToken: input.deviceToken,
					applicationId: input.applicationId
				});

			return {
				status: 'session_ready',
				issuedSession
			};
		}

		const verificationInput = {
			userId: identity.userId,
			applicationId: input.applicationId,
			deviceId: decision.device.id
		};

		if (input.verificationMode === 'mobile_approval') {
			try {
				const issuedMobileVerification =
					await this.mobileApprovals.start(
						verificationInput
					);

				return {
					status: 'verification_required',
					deviceId: decision.device.id,
					verificationId:
						issuedMobileVerification.verification.id,
					browserToken:
						issuedMobileVerification.browserToken,
					issuedDeviceToken:
						decision.issuedDeviceToken,
					expiresAt:
						issuedMobileVerification.verification.expiresAt,
					verificationMode: 'mobile_approval'
				};
			} catch (error: unknown) {
				if (
					!(error instanceof AuthError) ||
					error.code !== 'verification_mode_unavailable'
				) {
					throw error;
				}
			}
		}

		const issuedVerification =
			await observeAuthenticationOperation(
				'authentication_email_verification_start',
				async () => this.verifications.startEmail(
					verificationInput
				)
			);

		let deliveryFailed = false;
		let deliveryError: unknown;

		try {
			await this.verificationEmails.send({
				issued: issuedVerification,
				to: identity.email,
				firstname: identity.firstname
			});
		} catch (error: unknown) {
			deliveryFailed = true;
			deliveryError = error;

			logAuthServerError(
				error,
				'authentication_email_delivery'
			);
		}

		if (deliveryFailed) {
			try {
				await this.verifications.cancelEmail({
					userId: identity.userId,
					verificationId: issuedVerification.verification.id,
					browserToken: issuedVerification.browserToken,
					applicationId: input.applicationId,
					deviceId: decision.device.id
				});
			} catch (error: unknown) {
				logAuthServerError(
					error,
					'email_verification_cleanup'
				);
			}

			return Promise.reject(deliveryError);
		}

		return {
			status: 'verification_required',
			deviceId: decision.device.id,
			verificationId:
				issuedVerification.verification.id,
			browserToken:
				issuedVerification.browserToken,
			issuedDeviceToken:
				decision.issuedDeviceToken,
			expiresAt:
				issuedVerification.verification.expiresAt,
			verificationMode: 'email_code'
		};
	};

	/**
	 * Resolves confirmation channels available to a Firebase identity.
	 * @param idToken - Fresh Firebase ID token.
	 * @param applicationId - Application requesting authentication.
	 * @returns Available device verification channels.
	 */
	readonly getAvailableVerificationModes = async (
		idToken: string,
		applicationId: string
	): Promise<readonly DeviceVerificationMode[]> => {
		this.assertRequiredValue(
			idToken,
			'The Firebase ID token is required.'
		);

		this.assertRequiredValue(
			applicationId,
			'The application identifier is required.'
		);

		const identity = await this.identities.verify(idToken);

		return this.verifications.getAvailableModes({
			userId: identity.userId,
			applicationId
		});
	};

	/**
	 * Confirms an email code, verifies the device, and creates its session.
	 * @param input - Bound verification and Firebase authentication values.
	 * @returns The newly issued authenticated session.
	 */
	readonly completeEmail = async (
		input: CompleteEmailAuthenticationInput
	): Promise<IssuedSession> => {
		this.assertRequiredValue(
			input.idToken,
			'The Firebase ID token is required.'
		);

		this.assertRequiredValue(
			input.applicationId,
			'The application identifier is required.'
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
			input.verificationId,
			'The verification identifier is required.'
		);

		this.assertRequiredValue(
			input.browserToken,
			'The browser verification token is required.'
		);

		const identity = await this.identities.verify(
			input.idToken
		);

		await this.verifications.confirmEmail({
			userId: identity.userId,
			verificationId: input.verificationId,
			browserToken: input.browserToken,
			code: input.code,
			applicationId: input.applicationId,
			deviceId: input.deviceId
		});

		if (!identity.emailVerified) {
			await this.identities.markEmailVerified(
				identity.userId
			);
		}

		await this.verifications.complete({
			userId: identity.userId,
			verificationId: input.verificationId,
			browserToken: input.browserToken,
			applicationId: input.applicationId,
			deviceId: input.deviceId
		});

		return this.sessions.issue({
			idToken: input.idToken,
			deviceId: input.deviceId,
			deviceToken: input.deviceToken,
			applicationId: input.applicationId
		});
	};

	/**
	 * Completes an approved mobile verification and creates its session.
	 * @param input - Browser-bound verification and Firebase identity values.
	 * @returns The newly issued authenticated session.
	 * @throws {AuthError} When approval is pending, rejected, or invalid.
	 */
	readonly completeMobile = async (
		input: CompleteMobileAuthenticationInput
	): Promise<IssuedSession> => {
		this.assertRequiredValue(
			input.idToken,
			'The Firebase ID token is required.'
		);

		this.assertRequiredValue(
			input.applicationId,
			'The application identifier is required.'
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
			input.verificationId,
			'The verification identifier is required.'
		);

		this.assertRequiredValue(
			input.browserToken,
			'The browser verification token is required.'
		);

		const identity = await this.identities.verify(input.idToken);

		const verification =
			await this.verifications.getBrowserMobileVerification({
				userId: identity.userId,
				verificationId: input.verificationId,
				browserToken: input.browserToken,
				applicationId: input.applicationId,
				deviceId: input.deviceId
			});

		if (verification.status === 'rejected') {
			throw new AuthError(
				'approval_rejected',
				'The mobile authentication approval was rejected.'
			);
		}

		if (verification.status === 'pending') {
			throw new AuthError(
				'approval_not_ready',
				'The mobile authentication approval is still pending.'
			);
		}

		await this.verifications.complete({
			userId: identity.userId,
			verificationId: input.verificationId,
			browserToken: input.browserToken,
			applicationId: input.applicationId,
			deviceId: input.deviceId
		});

		return this.sessions.issue({
			idToken: input.idToken,
			deviceId: input.deviceId,
			deviceToken: input.deviceToken,
			applicationId: input.applicationId
		});
	};

	/**
	 * Replaces and sends an email verification code.
	 * @param input - Browser-bound verification and Firebase identity values.
	 * @returns The updated verification state.
	 */
	readonly resendEmailVerification = async (
		input: ManageEmailAuthenticationVerificationInput
	): Promise<DeviceVerification> => {
		const identity = await this.identities.verify(input.idToken);
		const issued = await this.verifications.resendEmail({
			userId: identity.userId,
			verificationId: input.verificationId,
			browserToken: input.browserToken,
			applicationId: input.applicationId,
			deviceId: input.deviceId
		});

		let deliveryFailed = false;
		let deliveryError: unknown;

		try {
			await this.verificationEmails.send({
				issued,
				to: identity.email,
				firstname: identity.firstname
			});
		} catch (error: unknown) {
			deliveryFailed = true;
			deliveryError = error;
		}

		if (deliveryFailed) {
			await this.verifications.rollbackEmailResend(
				{
					userId: identity.userId,
					verificationId: input.verificationId,
					browserToken: input.browserToken,
					applicationId: input.applicationId,
					deviceId: input.deviceId
				},
				issued
			);

			return Promise.reject(deliveryError);
		}

		await this.verifications.completeEmailResend(
			{
				userId: identity.userId,
				verificationId: input.verificationId,
				browserToken: input.browserToken,
				applicationId: input.applicationId,
				deviceId: input.deviceId
			},
			issued
		);

		return issued.verification;
	};

	/**
	 * Cancels an email verification owned by a Firebase identity.
	 * @param input - Browser-bound verification and Firebase identity values.
	 * @returns A promise resolved after cancellation.
	 */
	readonly cancelEmailVerification = async (
		input: ManageEmailAuthenticationVerificationInput
	): Promise<void> => {
		const identity = await this.identities.verify(input.idToken);

		await this.verifications.cancelEmail({
			userId: identity.userId,
			verificationId: input.verificationId,
			browserToken: input.browserToken,
			applicationId: input.applicationId,
			deviceId: input.deviceId
		});
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

export default AuthenticationService;
