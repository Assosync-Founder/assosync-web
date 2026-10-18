import 'server-only';

import createPasskeyChallengeRepository from '@/lib/auth/passkey/passkey-challenge-repository';
import createPasskeyRepository from '@/lib/auth/passkey/passkey-repository';
import PasskeyService from '@/lib/auth/passkey/passkey-service';
import firestoreServer from '@/services/firestore/firestore-server';
import redis from '@/services/redis/redis.server';

const passkeyRepository = createPasskeyRepository(firestoreServer);
const passkeyChallengeRepository = createPasskeyChallengeRepository(redis);

/** Shared server-side passkey service. */
const passkeyService = new PasskeyService(passkeyRepository, passkeyChallengeRepository);

export default passkeyService;
