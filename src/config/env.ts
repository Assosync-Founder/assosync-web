/**
 * Provides the application's public and server-side environment variables.
 *
 * Private values must only be accessed from server-side modules.
 */
const Env = {
	public: {
		environment: process.env.NEXT_PUBLIC_ENVIRONMENT,
		serverUrl: process.env.NEXT_PUBLIC_SERVER_URL,
		firebase: {
			apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
			authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN,
			projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
			storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET,
			messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID,
			appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID,
			functionUrl: process.env.NEXT_PUBLIC_FIREBASE_FUNCTION_URL
		},
		stripe: {
			publishableKey: process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY
		}
	},
	private: {
		firebase: {
			projectId: process.env.FIREBASE_PROJECT_ID,
			clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
			privateKey: process.env.FIREBASE_PRIVATE_KEY
		},
		stripe: {
			secretKey: process.env.STRIPE_SECRET_KEY,
		},
		authEmail: {
			challengeSecret: process.env.AUTH_EMAIL_CHALLENGE_SECRET,
			noReplyFrom: process.env.EMAIL_NOREPLY_FROM,
			from: {
				assosync: process.env.EMAIL_FROM_ASSOSYNC,
				calendis: process.env.EMAIL_FROM_CALENDIS,
				noReplyCalendis: process.env.EMAIL_NOREPLY_FROM_CALENDIS,
				collectineo: process.env.EMAIL_FROM_COLLECTINEO,
				noReplyCollectineo: process.env.EMAIL_NOREPLY_FROM_COLLECTINEO,
			}
		},
		webSso: {
			calendisClientSecret: process.env.AUTH_WEB_CALENDIS_CLIENT_SECRET,
			collectineoClientSecret: process.env.AUTH_WEB_COLLECTINEO_CLIENT_SECRET
		},
		resend: {
			apiKey: process.env.RESEND_API_KEY
		},
		upstashRedis: {
			restUrl: process.env.UPSTASH_REDIS_REST_URL,
			restToken: process.env.UPSTASH_REDIS_REST_TOKEN
		}
	}
} as const;

export default Env;
