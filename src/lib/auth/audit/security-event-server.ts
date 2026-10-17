import 'server-only';

import authConfig from '@/config/auth';
import createSecurityEventRepository from '@/lib/auth/audit/security-event-repository';
import SecurityEventService from '@/lib/auth/audit/security-event-service';
import firestoreServer from '@/services/firestore/firestore-server';

const securityEventRepository =
	createSecurityEventRepository(firestoreServer);

/** Shared server-side security-event recorder. */
const securityEventService = new SecurityEventService(
	securityEventRepository,
	{
		retentionMs: authConfig.securityEvent.retentionMs
	}
);

export default securityEventService;
