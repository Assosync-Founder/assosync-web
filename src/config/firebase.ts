import Env from '@/config/env';

const firebaseConfig = {
	apiKey: Env.public.firebase.apiKey,
	authDomain: Env.public.firebase.authDomain,
	projectId: Env.public.firebase.projectId,
	storageBucket: Env.public.firebase.storageBucket,
	messagingSenderId: Env.public.firebase.messagingSenderId,
	appId: Env.public.firebase.appId
};

export default firebaseConfig;