import { defineProxyConfig } from '@assosync/proxy';
import authConfig from '@/config/auth';
import Env from '@/config/env';

const isDevelopment = Env.public.environment === 'development';

const accountPublicRoutes = [
	'/login',
	'/confirm-device',
	'/passkey',
	'/reset-password'
] as const;

const consolePublicRoutes = [
	'/login'
] as const;

const proxyConfig = defineProxyConfig({
	scopes: {
		www: {
			hostname: isDevelopment
				? 'www.localhost'
				: 'www.assosync.fr',
			rewritePrefix: '/www'
		},

		account: {
			hostname: isDevelopment
				? 'account.localhost'
				: 'account.assosync.fr',
			rewritePrefix: '/account',
			authentication: {
				publicPaths: accountPublicRoutes,
				loginUrl: isDevelopment
					? 'http://account.localhost:3000/login'
					: 'https://account.assosync.fr/login'
			}
		},

		console: {
			hostname: isDevelopment
				? 'console.localhost'
				: 'console.assosync.fr',
			rewritePrefix: '/console',
			authentication: {
				publicPaths: consolePublicRoutes,
				loginUrl: isDevelopment
					? 'http://console.localhost:3000/login'
					: 'https://console.assosync.fr/login'
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
