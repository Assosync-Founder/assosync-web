import AuthCookieNames from '@assosync/contracts/auth/cookies';
import Env from '@/config/env';

const MINUTE_IN_MILLISECONDS = 60_000;
const DAY_IN_MILLISECONDS = 24 * 60 * MINUTE_IN_MILLISECONDS;
const HOUR_IN_MILLISECONDS = 60 * MINUTE_IN_MILLISECONDS;
const isDevelopment = Env.public.environment === 'development';

const cookiePrefix = isDevelopment
	? ''
	: '__Host-';

const authConfig = {
	cookieNames: {
		session: `${ cookiePrefix }${ AuthCookieNames.session }`,
		connection: `${ cookiePrefix }${ AuthCookieNames.connection }`,
		device: `${ cookiePrefix }${ AuthCookieNames.device }`,
		approval: `${ cookiePrefix }${ AuthCookieNames.approval }`,
		deviceVerification: `${ cookiePrefix }${ AuthCookieNames.deviceVerification }`,
		webAuthorization: `${ cookiePrefix }${ AuthCookieNames.webAuthorization }`,
	},
	device: {
		pendingLifetimeMs: 24 * HOUR_IN_MILLISECONDS,
		trustedLifetimeMs: 365 * DAY_IN_MILLISECONDS
	},
	deviceVerification: {
		lifetimeMs: 10 * MINUTE_IN_MILLISECONDS,
		maxEmailAttempts: 5,
		maxEmailResends: 3,
		emailResendCooldownMs: MINUTE_IN_MILLISECONDS,
		finalizationRecoveryMs: 5 * MINUTE_IN_MILLISECONDS,
		initialEmailWindowMs: 15 * MINUTE_IN_MILLISECONDS,
		maxInitialEmailsPerWindow: 3,
		penaltyResetMs: DAY_IN_MILLISECONDS,
		penaltyDurationsMs: [
			15 * MINUTE_IN_MILLISECONDS,
			HOUR_IN_MILLISECONDS,
			6 * HOUR_IN_MILLISECONDS,
			DAY_IN_MILLISECONDS
		]
	},
	session: {
		lifetimeMs: 7 * DAY_IN_MILLISECONDS,
		maxAuthenticationAgeMs: 15 * MINUTE_IN_MILLISECONDS
	},
	securityEvent: {
		retentionMs: 90 * DAY_IN_MILLISECONDS
	},
	authWarning: {
		securityUrl: isDevelopment
			? 'http://account.localhost:3000/security'
			: 'https://account.assosync.fr/security'
	},
	passkey: {
		rpName: 'Assosync Account',
		rpId: isDevelopment
			? 'account.localhost'
			: 'account.assosync.fr',
		expectedOrigin: isDevelopment
			? 'http://account.localhost:3000'
			: 'https://account.assosync.fr',
		challengeLifetimeMs: 5 * MINUTE_IN_MILLISECONDS
	},
	webSso: {
		requestLifetimeMs: 10 * MINUTE_IN_MILLISECONDS,
		codeLifetimeMs: MINUTE_IN_MILLISECONDS,
		clients: [
			{
				id: 'calendis',
				loginUri: isDevelopment
					? 'http://app.localhost:3001/login'
					: 'https://app.calendis.fr/login',
				authenticationFlashUri: isDevelopment
					? 'http://app.localhost:3001/api/auth/flash'
					: 'https://app.calendis.fr/api/auth/flash',
				redirectUris: [
					isDevelopment
						? 'http://app.localhost:3001/api/auth/callback'
						: 'https://app.calendis.fr/api/auth/callback'
				],
				clientSecret: Env.private.webSso.calendisClientSecret
			},
			{
				id: 'collectineo',
				loginUri: isDevelopment
					? 'http://app.localhost:3002/login'
					: 'https://app.collectineo.fr/login',
				authenticationFlashUri: isDevelopment
					? 'http://app.localhost:3002/api/auth/flash'
					: 'https://app.collectineo.fr/api/auth/flash',
				redirectUris: [
					isDevelopment
						? 'http://app.localhost:3002/api/auth/callback'
						: 'https://app.collectineo.fr/api/auth/callback'
				],
				clientSecret: Env.private.webSso.collectineoClientSecret
			}
		]
	},
	applications: [
		{
			id: 'assosync',
			hostnames: [
				'account.assosync.fr',
				'console.assosync.fr',
				'account.localhost',
				'console.localhost'
			]
		},
		{
			id: 'calendis',
			hostnames: [
				'app.calendis.fr',
				'app.calendis.localhost'
			]
		},
		{
			id: 'collectineo',
			hostnames: [
				'app.collectineo.fr',
				'app.collectineo.localhost'
			]
		}
	]
} as const;

export default authConfig;
