import 'server-only';

import SessionManagementService from '@/lib/auth/session/session-management-service';
import sessionService from '@/lib/auth/session/session-server';

/** Shared server-side account session management service. */
const sessionManagementService = new SessionManagementService(sessionService);

export default sessionManagementService;
