import 'server-only';

import authenticationIdentityProvider from '@/lib/auth/authentication/authentication-identity-server';
import AuthenticationService from '@/lib/auth/authentication/authentication-service';
import deviceService from '@/lib/auth/device/device-server';
import mobileApprovalService from '@/lib/auth/mobile/approval/approval-server';
import sessionService from '@/lib/auth/session/session-server';
import {
	verificationEmailService,
	verificationService
} from '@/lib/auth/verification/verification-server';

/** Shared server-side authentication workflow. */
const authenticationService =
	new AuthenticationService(
		authenticationIdentityProvider,
		deviceService,
		verificationService,
		verificationEmailService,
		mobileApprovalService,
		sessionService
	);

export default authenticationService;
