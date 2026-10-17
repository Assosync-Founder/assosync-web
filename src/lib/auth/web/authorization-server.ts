import 'server-only';

import authConfig from '@/config/auth';
import Env from '@/config/env';
import createWebAuthorizationRepository from '@/lib/auth/web/authorization-repository';
import WebAuthorizationService from '@/lib/auth/web/authorization-service';
import redis from '@/services/redis/redis.server';

const webAuthorizationRepository = createWebAuthorizationRepository(redis);

const clients = authConfig.webSso.clients.map((client) => {
	const clientSecret = client.id === 'calendis'
		? Env.private.webSso.calendisClientSecret
		: Env.private.webSso.collectineoClientSecret;

	return {
		...client,
		clientSecret
	};
});

/** Shared server-side Web SSO authorization service. */
const webAuthorizationService =
	new WebAuthorizationService(
		webAuthorizationRepository,
		{
			...authConfig.webSso,
			clients
		}
	);

export default webAuthorizationService;
