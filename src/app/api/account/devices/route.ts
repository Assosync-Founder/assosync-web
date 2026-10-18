import { NextRequest, NextResponse } from 'next/server';
import deviceManagementService from '@/lib/auth/device/device-management-server';
import { createAuthErrorResponse } from '@/lib/auth/http/auth-http';
import resolveAccountRequestSession from '@/lib/auth/http/auth-request-session';

/** Lists the devices owned by the authenticated account.
 * @param request - Incoming account device request.
 * @returns The public account devices.
 */
export const GET = async (request: NextRequest): Promise<Response> => {
	try {
		const session = await resolveAccountRequestSession(request);

		const devices = await deviceManagementService.list(session.userId, session.deviceId);

		return NextResponse.json({ devices });
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};
