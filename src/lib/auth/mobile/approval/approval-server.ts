import 'server-only';

import deviceService from '@/lib/auth/device/device-server';
import securityEventService from '@/lib/auth/audit/security-event-server';
import MobileApprovalService from '@/lib/auth/mobile/approval/approval-service';
import mobileInstallationService from '@/lib/auth/mobile/installation/installation-server';
import mobileNotificationService from '@/lib/auth/mobile/notification/notification-server';
import { verificationService } from '@/lib/auth/verification/verification-server';
import authWarningService from '@/lib/auth/verification/auth-warning-server';

/** Shared server-side mobile authentication approval service. */
const mobileApprovalService = new MobileApprovalService(
	verificationService,
	deviceService,
	mobileInstallationService,
	mobileNotificationService,
	securityEventService,
	authWarningService
);

export default mobileApprovalService;
