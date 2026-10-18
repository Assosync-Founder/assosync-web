import 'server-only';

import authConfig from '@/config/auth';
import Env from '@/config/env';
import securityEventService from '@/lib/auth/audit/security-event-server';
import deviceService from '@/lib/auth/device/device-server';
import mobileInstallationService from '@/lib/auth/mobile/installation/installation-server';
import { createHmacVerificationCodeHasher } from '@/lib/auth/shared/runtime-server';
import createDeviceVerificationRepository from '@/lib/auth/verification/verification-repository';
import VerificationEmailService from '@/lib/auth/verification/verification-email-service';
import authWarningService from '@/lib/auth/verification/auth-warning-server';
import createEmailVerificationRateLimitRepository from '@/lib/auth/verification/verification-rate-limit-repository';
import VerificationRateLimitService from '@/lib/auth/verification/verification-rate-limit-service';
import VerificationService from '@/lib/auth/verification/verification-service';
import redis from '@/services/redis/redis.server';
import resend from '@/services/resend/resend.server';
import type { DeviceVerificationModePolicy } from '@/types/auth';

const verificationRepository = createDeviceVerificationRepository(redis);

const verificationRateLimitRepository = createEmailVerificationRateLimitRepository(redis, authConfig.deviceVerification);

const verificationRateLimitService = new VerificationRateLimitService(verificationRateLimitRepository, securityEventService, authWarningService);

const verificationCodeHasher = createHmacVerificationCodeHasher(Env.private.authEmail.challengeSecret ?? '');

const mobileAwareVerificationPolicy: DeviceVerificationModePolicy = {
	getAvailableModes: async (input) => {
		const hasActiveMobileInstallation = await mobileInstallationService.hasActiveMobileInstallation(input.userId);

		if (hasActiveMobileInstallation) {
			return ['email_code', 'mobile_approval'];
		}

		return ['email_code'];
	}
};

const verificationService = new VerificationService(
	verificationRepository,
	deviceService,
	verificationCodeHasher,
	authConfig.deviceVerification,
	verificationRateLimitService,
	securityEventService,
	authWarningService,
	mobileAwareVerificationPolicy
);

const verificationEmailService = new VerificationEmailService(
		resend,
		{
			brands: [
				{
					applicationId: 'assosync',
					emailType: 'assosync',
					displayName: 'Assosync',
					from: Env.private.authEmail.noReplyFrom ?? ''
				},
				{
					applicationId: 'calendis',
					emailType: 'calendis',
					displayName: 'Calendis',
					from: Env.private.authEmail.from.noReplyCalendis ?? ''
				},
				{
					applicationId: 'collectineo',
					emailType: 'collectineo',
					displayName: 'Collectineo',
					from: Env.private.authEmail.from.noReplyCollectineo ?? ''
				}
			]
		}
	);

export {
	verificationEmailService,
	verificationService
};
