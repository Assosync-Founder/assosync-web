import type { NextRequest } from 'next/server';
import handleWebAuthorizationContinuation from '@/lib/auth/web/authorization-continuation-http';

/** Continues an authenticated product login through the Account device check.
 * @param request - Incoming browser authorization request.
 * @returns A server-side redirect to confirmation or the product callback.
 */
export const GET = async (
	request: NextRequest
): Promise<Response> => {
	return handleWebAuthorizationContinuation(request);
};
