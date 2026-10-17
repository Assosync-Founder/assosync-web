import 'server-only';

import { getMessaging } from 'firebase-admin/messaging';
import firebaseAdmin from '@/services/firebase/firebase-server';
import FirebaseCloudMessagingService from '@/services/firebase/messaging-service';

const firebaseCloudMessaging = getMessaging(firebaseAdmin.app);

/** Shared server-side Firebase Cloud Messaging service. */
const firebaseCloudMessagingService = new FirebaseCloudMessagingService(
	firebaseCloudMessaging
);

export default firebaseCloudMessagingService;
