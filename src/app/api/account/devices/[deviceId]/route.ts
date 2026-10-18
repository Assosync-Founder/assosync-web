import { NextRequest, NextResponse } from 'next/server';
import deviceManagementService from '@/lib/auth/device/device-management-server';
import { clearSessionCookies } from '@/lib/auth/http/auth-cookies';
import { assertSameOrigin, createAuthErrorResponse, readAuthenticationIdentifier, readJsonBody, readRequiredNullableString } from '@/lib/auth/http/auth-http';
import resolveAccountRequestSession from '@/lib/auth/http/auth-request-session';
import type { DeviceRouteContext } from '@/types/auth';

/** Renames a device owned by the authenticated account.
 * @param request - Incoming device update request.
 * @param context - Dynamic device route context.
 * @returns The renamed public device.
 */
export const PATCH = async (request: NextRequest, context: DeviceRouteContext): Promise<Response> => {
	try {
		assertSameOrigin(request);

		const [session, body, parameters] = await Promise.all([
			resolveAccountRequestSession(request),
			readJsonBody(request),
			context.params
		]);

		const displayName = readRequiredNullableString(body, 'displayName', 120);

		const deviceId = readAuthenticationIdentifier(parameters.deviceId);

		const device = await deviceManagementService.rename(session.userId, deviceId, displayName, session.deviceId);

		return NextResponse.json({ device });
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};

/** Revokes a device and every application session attached to it.
 * @param request - Incoming device revocation request.
 * @param context - Dynamic device route context.
 * @returns The revoked device and affected session count.
 */
export const DELETE = async (request: NextRequest, context: DeviceRouteContext): Promise<Response> => {
	try {
		assertSameOrigin(request);

		const [session, parameters] = await Promise.all([
			resolveAccountRequestSession(request),
			context.params
		]);

		const deviceId = readAuthenticationIdentifier(parameters.deviceId);

		const result = await deviceManagementService.revoke(session.userId, deviceId, session.deviceId);

		const response = NextResponse.json(result);

		if (result.device.isCurrent) {
			clearSessionCookies(response);
		}

		return response;
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};
