import 'server-only';

import DeviceManagementService from '@/lib/auth/device/device-management-service';
import deviceService from '@/lib/auth/device/device-server';
import sessionService from '@/lib/auth/session/session-server';

/** Shared server-side account device management service. */
const deviceManagementService = new DeviceManagementService(
	deviceService,
	sessionService
);

export default deviceManagementService;
