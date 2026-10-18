import 'server-only';

import mobileInstallationService from '@/lib/auth/mobile/installation/installation-server';
import MobileNotificationService from '@/lib/auth/mobile/notification/notification-service';
import firebaseCloudMessagingService from '@/services/firebase/messaging-server';

/** Shared server-side mobile authentication notification service. */
const mobileNotificationService = new MobileNotificationService(mobileInstallationService, firebaseCloudMessagingService);

export default mobileNotificationService;
