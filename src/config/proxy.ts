import { defineProxyConfig } from '@assosync/proxy';
import authConfig from '@/config/auth';
import Env from '@/config/env';

const isDevelopment = Env.public.environment === 'development';
const isPreview = Env.public.environment === 'preview';
const previewHostname = 'preview.assosync.fr';

const resolveHostname = (developmentHostname: string, productionHostname: string): string => {
	if (isDevelopment) {
		return developmentHostname;
	}

	if (isPreview) {
		return previewHostname;
	}

	return productionHostname;
};

const resolveUrl = (developmentUrl: string, previewUrl: string, productionUrl: string): string => {
	if (isDevelopment) {
		return developmentUrl;
	}

	if (isPreview) {
		return previewUrl;
	}

	return productionUrl;
};

const accountPublicRoutes = [
	'/.well-known/webauthn',
	isPreview ? '/account/login' : '/login',
	isPreview ? '/account/confirm-device' : '/confirm-device',
	isPreview ? '/account/passkey' : '/passkey',
	isPreview ? '/account/reset-password' : '/reset-password'
] as const;

const consolePublicRoutes = [
	isPreview ? '/console/login' : '/login'
] as const;

const proxyConfig = defineProxyConfig({
	scopes: {
		www: {
			hostname: resolveHostname('www.localhost', 'www.assosync.fr'),
			rewritePrefix: '/www'
		},

		account: {
			hostname: resolveHostname('account.localhost', 'account.assosync.fr'),
			rewritePrefix: '/account',
			authentication: {
				publicPaths: accountPublicRoutes,
				loginUrl: resolveUrl('http://account.localhost:3000/login', 'https://preview.assosync.fr/account/login', 'https://account.assosync.fr/login')
			}
		},

		console: {
			hostname: resolveHostname('console.localhost', 'console.assosync.fr'),
			rewritePrefix: '/console',
			authentication: {
				publicPaths: consolePublicRoutes,
				loginUrl: resolveUrl('http://console.localhost:3000/login', 'https://preview.assosync.fr/console/login', 'https://console.assosync.fr/login')
			}
		}
	},

	forbiddenByScope: {
		www: [
			...accountPublicRoutes,
			'/console',
			'/account',
			'/onboarding'
		]
	},

	session: {
		cookieName: authConfig.cookieNames.session,
		projectId: Env.public.firebase.projectId ?? ''
	},

	rateLimit: {
		enabled: !isDevelopment,
		key: 'assosync',
		url: Env.private.upstashRedis.restUrl ?? '',
		token: Env.private.upstashRedis.restToken ?? '',
		rules: [
			{
				name: 'auth',
				paths: ['/api/auth'],
				requests: 20,
				window: '1 m'
			},
			{
				name: 'api',
				paths: ['/api'],
				requests: 100,
				window: '1 m'
			}
		]
	}
});

export default proxyConfig
