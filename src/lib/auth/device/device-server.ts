import 'server-only';

import authConfig from '@/config/auth';
import securityEventService from '@/lib/auth/audit/security-event-server';
import createDeviceRepository from '@/lib/auth/device/device-repository';
import DeviceService from '@/lib/auth/device/device-service';
import firestoreServer from '@/services/firestore/firestore-server';

const deviceRepository = createDeviceRepository(firestoreServer);

/** Shared server-side trusted-device service. */
const deviceService = new DeviceService(deviceRepository, { pendingLifetimeMs: authConfig.device.pendingLifetimeMs, trustedLifetimeMs: authConfig.device.trustedLifetimeMs }, securityEventService);

export default deviceService;
