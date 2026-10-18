import 'server-only';

import authConfig from '@/config/auth';
import securityEventService from '@/lib/auth/audit/security-event-server';
import deviceService from '@/lib/auth/device/device-server';
import createFirebaseSessionAdapter from '@/lib/auth/session/session-firebase';
import createSessionRepository from '@/lib/auth/session/session-repository';
import SessionService from '@/lib/auth/session/session-service';
import firebaseAdmin from '@/services/firebase/firebase-server';
import firestoreServer from '@/services/firestore/firestore-server';

const sessionRepository = createSessionRepository(firestoreServer);

const firebaseSession = createFirebaseSessionAdapter(firebaseAdmin.auth, { maxAuthenticationAgeMs: authConfig.session.maxAuthenticationAgeMs });

/** Shared server-side application session service. */
const sessionService = new SessionService(sessionRepository, firebaseSession, deviceService, securityEventService, { lifetimeMs: authConfig.session.lifetimeMs });

export default sessionService;
