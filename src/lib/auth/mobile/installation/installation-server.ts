import 'server-only';

import createMobileInstallationRepository from '@/lib/auth/mobile/installation/installation-repository';
import MobileInstallationService from '@/lib/auth/mobile/installation/installation-service';
import firestoreServer from '@/services/firestore/firestore-server';

const mobileInstallationRepository =
	createMobileInstallationRepository(firestoreServer);

/** Shared server-side mobile authentication installation service. */
const mobileInstallationService = new MobileInstallationService(
	mobileInstallationRepository
);

export default mobileInstallationService;
