import 'server-only';

import { Redis } from '@upstash/redis';
import Env from '@/config/env';

const redisUrl = Env.private.upstashRedis.restUrl;
const redisToken = Env.private.upstashRedis.restToken;

if (!redisUrl || !redisToken) {
	throw new Error('The Upstash Redis server configuration is incomplete.');
}

/** Shared server-side Redis client used by authentication services. */
const redis = new Redis({ url: redisUrl, token: redisToken });

export default redis;
