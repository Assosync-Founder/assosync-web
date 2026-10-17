import 'server-only';

import { createMailer } from '@assosync/email';
import Env from '@/config/env';

/** Shared server-side mailer configured for Resend. */
const resend = createMailer(Env.private.resend.apiKey ?? '');

export default resend;

