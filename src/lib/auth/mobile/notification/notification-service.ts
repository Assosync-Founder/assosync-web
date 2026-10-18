import 'server-only';

import MobileInstallationService from '@/lib/auth/mobile/installation/installation-service';
import { logAuthServerError } from '@/lib/auth/shared/auth-logger';
import FirebaseCloudMessagingService from '@/services/firebase/messaging-service';
import type { SendMobilePushNotificationInput, SendMobilePushNotificationResult } from '@/types/auth';

/** Sends authentication notifications to registered mobile installations. */
class MobileNotificationService {
	/**
	 * Creates a mobile authentication notification service.
	 * @param mobileInstallationService - Mobile installation registry.
	 * @param firebaseCloudMessagingService - Firebase push-delivery service.
	 */
	constructor(
		private readonly mobileInstallationService:
			MobileInstallationService,
		private readonly firebaseCloudMessagingService:
			FirebaseCloudMessagingService
	) {}

	/**
	 * Notifies every active mobile installation owned by an account.
	 * @param input - Account identity and localized notification payload.
	 * @returns Delivery results without Firebase registration tokens.
	 */
	readonly sendToActiveMobileInstallations = async (input: SendMobilePushNotificationInput): Promise<SendMobilePushNotificationResult> => {
		const mobileInstallations = await this.mobileInstallationService.listActiveForDelivery(input.userId);

		const result = await this.firebaseCloudMessagingService.sendEach(
			mobileInstallations.map((mobileInstallation) => {
				return {
					recipientId: mobileInstallation.id,
					token: mobileInstallation.pushToken,
					notification: input.notification,
					data: input.data
				};
			})
		);

		const invalidMobileInstallationIds = result.results.flatMap(
			(deliveryResult) => {
				if (deliveryResult.status === 'failed' && deliveryResult.isInvalidToken) {
					return [deliveryResult.recipientId];
				}

				return [];
			}
		);

		await Promise.all(
			invalidMobileInstallationIds.map(
				async (mobileInstallationId) => {
					try {
						await this.mobileInstallationService.disable(input.userId, mobileInstallationId);
					} catch (error: unknown) {
						logAuthServerError(error, 'mobile_installation_disable');
					}
				}
			)
		);

		return result;
	};
}

export default MobileNotificationService;
