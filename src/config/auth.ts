import AuthCookieNames from '@assosync/contracts/auth/cookies';
import Env from '@/config/env';

const MINUTE_IN_MILLISECONDS = 60_000;
const DAY_IN_MILLISECONDS = 24 * 60 * MINUTE_IN_MILLISECONDS;
const HOUR_IN_MILLISECONDS = 60 * MINUTE_IN_MILLISECONDS;
const isDevelopment = Env.public.environment === 'development';
const isPreview = Env.public.environment === 'preview';

const resolveUrl = (developmentUrl: string, previewUrl: string, productionUrl: string): string => {
	if (isDevelopment) {
		return developmentUrl;
	}

	if (isPreview) {
		return previewUrl;
	}

	return productionUrl;
};

const resolveHostname = (developmentHostname: string, previewHostname: string, productionHostname: string): string => {
	if (isDevelopment) {
		return developmentHostname;
	}

	if (isPreview) {
		return previewHostname;
	}

	return productionHostname;
};

const cookiePrefix = isDevelopment
	? ''
	: '__Host-';

const authConfig = {
	routes: {
		accountConfirmDevice: isPreview ? '/account/confirm-device': '/confirm-device',
		accountLogin: isPreview ? '/account/login': '/login',
		accountPasskey: isPreview ? '/account/passkey': '/passkey'
	},
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
		securityUrl: resolveUrl('http://account.localhost:3000/security', 'https://preview.assosync.fr/account/security', 'https://account.assosync.fr/security')
	},
	passkey: {
		rpName: 'Assosync Account',
		rpId: resolveHostname('account.localhost', 'preview.assosync.fr', 'account.assosync.fr'),
		expectedOrigin: resolveUrl('http://account.localhost:3000', 'https://preview.assosync.fr', 'https://account.assosync.fr'),
		challengeLifetimeMs: 5 * MINUTE_IN_MILLISECONDS
	},
	webSso: {
		requestLifetimeMs: 10 * MINUTE_IN_MILLISECONDS,
		codeLifetimeMs: MINUTE_IN_MILLISECONDS,
		clients: [
			{
				id: 'calendis',
				loginUri: resolveUrl('http://app.localhost:3001/login', 'https://preview.calendis.fr/app/login', 'https://app.calendis.fr/login'),
				authenticationFlashUri: resolveUrl('http://app.localhost:3001/api/auth/flash', 'https://preview.calendis.fr/api/auth/flash', 'https://app.calendis.fr/api/auth/flash'),
				redirectUris: [
					resolveUrl('http://app.localhost:3001/api/auth/callback', 'https://preview.calendis.fr/api/auth/callback', 'https://app.calendis.fr/api/auth/callback')
				],
				passkeyOrigins: [
					resolveUrl('http://app.localhost:3001', 'https://preview.calendis.fr', 'https://app.calendis.fr')
				],
				clientSecret: Env.private.webSso.calendisClientSecret
			},
			{
				id: 'collectineo',
				loginUri: resolveUrl('http://app.localhost:3002/login', 'https://preview.collectineo.fr/app/login', 'https://app.collectineo.fr/login'),
				authenticationFlashUri: resolveUrl('http://app.localhost:3002/api/auth/flash', 'https://preview.collectineo.fr/api/auth/flash', 'https://app.collectineo.fr/api/auth/flash'),
				redirectUris: [
					resolveUrl('http://app.localhost:3002/api/auth/callback', 'https://preview.collectineo.fr/api/auth/callback', 'https://app.collectineo.fr/api/auth/callback')
				],
				passkeyOrigins: [
					resolveUrl('http://app.localhost:3002', 'https://preview.collectineo.fr', 'https://app.collectineo.fr')
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
				'preview.assosync.fr',
				'account.localhost',
				'console.localhost'
			]
		},
		{
			id: 'calendis',
			hostnames: [
				'app.calendis.fr',
				'preview.calendis.fr',
				'app.calendis.localhost'
			]
		},
		{
			id: 'collectineo',
			hostnames: [
				'app.collectineo.fr',
				'preview.collectineo.fr',
				'app.collectineo.localhost'
			]
		}
	]
} as const;

export default authConfig;
