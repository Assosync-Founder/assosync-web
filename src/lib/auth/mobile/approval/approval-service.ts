import 'server-only';

import SecurityEventService from '@/lib/auth/audit/security-event-service';
import DeviceService from '@/lib/auth/device/device-service';
import MobileInstallationService from '@/lib/auth/mobile/installation/installation-service';
import MobileNotificationService from '@/lib/auth/mobile/notification/notification-service';
import { logAuthServerError } from '@/lib/auth/shared/auth-logger';
import AuthError from '@/lib/auth/shared/auth-error';
import VerificationService from '@/lib/auth/verification/verification-service';
import type {
	AuthWarningNotifier,
	DeviceVerification,
	GetMobileApprovalRequestInput,
	IssuedMobileDeviceVerification,
	MobileApprovalRequest,
	RespondMobileApprovalInput,
	StartDeviceVerificationInput
} from '@/types/auth';

/** Coordinates mobile approval notifications and authenticated responses. */
class MobileApprovalService {
	/**
	 * Creates a mobile approval service.
	 * @param verifications - Temporary device verification service.
	 * @param devices - Persistent browser device service.
	 * @param mobileInstallations - Registered mobile installation service.
	 * @param mobileNotifications - Mobile push-notification service.
	 * @param securityEvents - Secret-free security event recorder.
	 * @param authWarnings - Best-effort suspicious-authentication notifier.
	 */
	constructor(
		private readonly verifications: VerificationService,
		private readonly devices: DeviceService,
		private readonly mobileInstallations: MobileInstallationService,
		private readonly mobileNotifications: MobileNotificationService,
		private readonly securityEvents: SecurityEventService,
		private readonly authWarnings: AuthWarningNotifier
	) {}

	/**
	 * Starts a mobile approval and notifies every active mobile installation.
	 * @param input - Pending browser device identity.
	 * @returns The issued browser and mobile approval secrets.
	 * @throws {AuthError} When no notification can be delivered.
	 */
	readonly start = async (input: StartDeviceVerificationInput): Promise<IssuedMobileDeviceVerification> => {
		const issued = await this.verifications.startMobile(input);

		let deliverySucceeded = false;

		try {
			const delivery = await this.mobileNotifications.sendToActiveMobileInstallations({
					userId: input.userId,
					notification: {
						title: 'Nouvelle demande de connexion',
						body: 'Confirmez ou refusez cette connexion dans votre application.'
					},
					data: {
						type: 'authentication_approval',
						verificationId: issued.verification.id,
						approvalToken: issued.approvalToken
					}
				});

			deliverySucceeded = delivery.successCount > 0;
		} catch (error: unknown) {
			logAuthServerError(error, 'mobile_approval_notification');
		}

		if (!deliverySucceeded) {
			try {
				await this.verifications.rejectMobile({
					userId: input.userId,
					verificationId: issued.verification.id,
					approvalToken: issued.approvalToken,
					applicationId: input.applicationId
				});
			} catch (error: unknown) {
				logAuthServerError(error, 'mobile_approval_cleanup');
			}

			throw new AuthError('verification_mode_unavailable', 'No registered mobile installation accepted the notification.');
		}

		return issued;
	};

	/**
	 * Resolves safe information for the future mobile BottomSheet.
	 * @param input - Authenticated mobile installation and approval secret.
	 * @returns The safe browser authentication context.
	 * @throws {AuthError} When the installation or approval is invalid.
	 */
	readonly getRequest = async (input: GetMobileApprovalRequestInput): Promise<MobileApprovalRequest> => {
		await this.assertActiveMobileInstallation(input);

		const verification = await this.verifications.getMobileApproval(input);

		if (verification.status === 'finalizing' || verification.status === 'consumed') {
			throw new AuthError('verification_invalid', 'The mobile approval can no longer be displayed.');
		}

		const device = await this.devices.findById(input.userId, verification.deviceId);

		return {
			verificationId: verification.id,
			applicationId: verification.applicationId,
			deviceId: device.id,
			deviceDisplayName: device.displayName,
			deviceCategory: device.category,
			browserName: device.browserName,
			browserVersion: device.browserVersion,
			operatingSystemName: device.operatingSystemName,
			operatingSystemVersion: device.operatingSystemVersion,
			deviceBrand: device.deviceBrand,
			deviceModel: device.deviceModel,
			status: verification.status,
			createdAt: verification.createdAt,
			expiresAt: verification.expiresAt
		};
	};

	/**
	 * Applies an explicit accept or reject response from a mobile installation.
	 * @param input - Authenticated mobile decision.
	 * @returns The resulting verification state.
	 * @throws {AuthError} When the installation or approval is invalid.
	 */
	readonly respond = async (input: RespondMobileApprovalInput): Promise<DeviceVerification> => {
		await this.assertActiveMobileInstallation(input);

		const currentVerification = await this.verifications.getMobileApproval(input);

		if (input.decision === 'approve') {
			const approvedVerification = await this.verifications.approveMobile({
				userId: input.userId,
				verificationId: input.verificationId,
				approvalToken: input.approvalToken,
				applicationId: currentVerification.applicationId
			});

			await this.securityEvents.record({
				userId: input.userId,
				type: 'mobile_approval_approved',
				applicationId: approvedVerification.applicationId,
				deviceId: approvedVerification.deviceId,
				sessionId: null,
				affectedCount: 1
			});

			return approvedVerification;
		}

		const rejectedVerification = await this.verifications.rejectMobile({
			userId: input.userId,
			verificationId: input.verificationId,
			approvalToken: input.approvalToken,
			applicationId: currentVerification.applicationId
		});

		await this.securityEvents.record({
			userId: input.userId,
			type: 'mobile_approval_rejected',
			applicationId: rejectedVerification.applicationId,
			deviceId: rejectedVerification.deviceId,
			sessionId: null,
			affectedCount: 1
		});

		await this.authWarnings.notify({
			userId: input.userId,
			applicationId: rejectedVerification.applicationId,
			deviceId: rejectedVerification.deviceId,
			verificationId: rejectedVerification.id,
			trigger: 'mobile_approval_rejected',
			occurredAt: rejectedVerification.rejectedAt ?? new Date(),
			penaltyLevel: null
		});

		return rejectedVerification;
	};

	/**
	 * Ensures the response comes from an active account-owned installation.
	 * @param input - Authenticated mobile installation identity.
	 * @throws {AuthError} When the installation is not registered and active.
	 */
	private readonly assertActiveMobileInstallation = async (input: GetMobileApprovalRequestInput): Promise<void> => {
		const mobileInstallation = await this.mobileInstallations.findActiveForApproval(input.userId, input.mobileInstallationId);

		if (!mobileInstallation) {
			throw new AuthError('verification_invalid', 'The mobile installation cannot answer authentication approvals.');
		}
	};
}

export default MobileApprovalService;
