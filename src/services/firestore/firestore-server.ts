import 'server-only';

import { createAdminRepository } from '@assosync/firestore/admin';
import firebaseAdmin from '@/services/firebase/firebase-server';

/** Shared server-side Firestore repository. */
const firestoreServer = createAdminRepository(firebaseAdmin.db);

export default firestoreServer;