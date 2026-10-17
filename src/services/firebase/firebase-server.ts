import 'server-only';

import { createFirebaseAdmin } from '@assosync/firebase/admin';
import { emulatorHost } from '@/config/app';
import Env from '@/config/env';

const firebaseAdmin = createFirebaseAdmin({
	credential: {
		projectId: Env.private.firebase.projectId,
		clientEmail: Env.private.firebase.clientEmail,
		privateKey: Env.private.firebase.privateKey
	},
	storageBucket: Env.public.firebase.storageBucket,
	emulator: {
		enabled: Env.public.environment === 'development',
		host: emulatorHost,
		ports: {
			firestore: 8080,
			storage: 9199
		}
	}
});

export default firebaseAdmin;