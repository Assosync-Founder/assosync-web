import 'server-only';

import authConfig from '@/config/auth';
import Env from '@/config/env';
import authenticationIdentityProvider from '@/lib/auth/authentication/authentication-identity-server';
import deviceService from '@/lib/auth/device/device-server';
import AuthWarningService from '@/lib/auth/verification/auth-warning-service';
import resend from '@/services/resend/resend.server';

/** Shared server-side suspicious-authentication warning service. */
const authWarningService = new AuthWarningService(
	resend,
	authenticationIdentityProvider,
	deviceService,
	{
		securityUrl: authConfig.authWarning.securityUrl,
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

export default authWarningService;
