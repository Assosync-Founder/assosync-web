import { createFirebaseClient } from '@assosync/firebase/client';
import { emulatorHost } from '@/config/app';
import firebaseConfig from '@/config/firebase';
import Env from '@/config/env';

const firebaseClient = createFirebaseClient({
	firebase: firebaseConfig,
	emulator: {
		enabled: Env.public.environment === 'development',
		host: emulatorHost,
		ports: {
			firestore: 8080,
			storage: 9199
		}
	}
});

export default firebaseClient;