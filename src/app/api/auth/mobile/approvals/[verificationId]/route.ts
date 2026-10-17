import { headers } from 'next/headers';
import { type NextRequest, NextResponse } from 'next/server';
import {
	assertAccountHostname,
	AuthHttpError,
	createAuthErrorResponse,
	readAuthenticationIdentifier,
	readJsonBody
} from '@/lib/auth/http/auth-http';
import mobileApprovalService from '@/lib/auth/mobile/approval/approval-server';
import resolveMobileRequestUserId from '@/lib/auth/mobile/http/mobile-request-identity';
import type {
	MobileApprovalDecision,
	MobileApprovalRouteContext
} from '@/types/auth';

const MOBILE_INSTALLATION_HEADER = 'x-mobile-installation-id';
const MOBILE_APPROVAL_HEADER = 'x-mobile-approval-token';
const MAXIMUM_MOBILE_AUTH_HEADER_LENGTH = 512;

/**
 * Reads a required mobile authentication header.
 * @param headerStore - Incoming mobile request headers.
 * @param header - Header name to read.
 * @returns The validated header value.
 * @throws {AuthHttpError} When the header is missing.
 */
const readRequiredHeader = (
	headerStore: Headers,
	header: string
): string => {
	const value = headerStore.get(header)?.trim();

	if (
		!value ||
		value.length > MAXIMUM_MOBILE_AUTH_HEADER_LENGTH
	) {
		throw new AuthHttpError(400, 'request_invalid');
	}

	return value;
};

/**
 * Reads an explicit mobile approval decision.
 * @param value - Untrusted decision value.
 * @returns The validated approval decision.
 * @throws {AuthHttpError} When the decision is unsupported.
 */
const readMobileApprovalDecision = (
	value: unknown
): MobileApprovalDecision => {
	if (value === 'approve' || value === 'reject') {
		return value;
	}

	throw new AuthHttpError(400, 'request_invalid');
};

/** Returns safe context for the future mobile approval BottomSheet.
 * @param request - Authenticated mobile request.
 * @param context - Dynamic verification route context.
 * @returns The pending authentication context.
 */
export const GET = async (
	request: NextRequest,
	context: MobileApprovalRouteContext
): Promise<Response> => {
	try {
		assertAccountHostname(request);

		const headerStore = await headers();
		const userId = await resolveMobileRequestUserId(request);
		const parameters = await context.params;
		const verificationId = readAuthenticationIdentifier(
			parameters.verificationId
		);

		const mobileInstallationId = readAuthenticationIdentifier(
			readRequiredHeader(
				headerStore,
				MOBILE_INSTALLATION_HEADER
			)
		);

		const approvalToken = readAuthenticationIdentifier(
			readRequiredHeader(
				headerStore,
				MOBILE_APPROVAL_HEADER
			)
		);

		const approvalRequest = await mobileApprovalService.getRequest({
			userId,
			mobileInstallationId,
			verificationId,
			approvalToken
		});

		return NextResponse.json(
			{
				verificationId: approvalRequest.verificationId,
				applicationId: approvalRequest.applicationId,
				deviceId: approvalRequest.deviceId,
				deviceDisplayName: approvalRequest.deviceDisplayName,
				deviceCategory: approvalRequest.deviceCategory,
				browserName: approvalRequest.browserName,
				browserVersion: approvalRequest.browserVersion,
				operatingSystemName:
					approvalRequest.operatingSystemName,
				operatingSystemVersion:
					approvalRequest.operatingSystemVersion,
				deviceBrand: approvalRequest.deviceBrand,
				deviceModel: approvalRequest.deviceModel,
				status: approvalRequest.status,
				createdAt: approvalRequest.createdAt.toISOString(),
				expiresAt: approvalRequest.expiresAt.toISOString()
			},
			{
				headers: {
					'Cache-Control': 'no-store'
				}
			}
		);
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};

/** Applies an explicit approval or rejection from a mobile installation.
 * @param request - Authenticated mobile request.
 * @param context - Dynamic verification route context.
 * @returns The resulting mobile approval status.
 */
export const POST = async (
	request: NextRequest,
	context: MobileApprovalRouteContext
): Promise<Response> => {
	try {
		assertAccountHostname(request);

		const headerStore = await headers();
		const userId = await resolveMobileRequestUserId(request);
		const parameters = await context.params;
		const verificationId = readAuthenticationIdentifier(
			parameters.verificationId
		);

		const mobileInstallationId = readAuthenticationIdentifier(
			readRequiredHeader(
				headerStore,
				MOBILE_INSTALLATION_HEADER
			)
		);

		const approvalToken = readAuthenticationIdentifier(
			readRequiredHeader(
				headerStore,
				MOBILE_APPROVAL_HEADER
			)
		);

		const body = await readJsonBody(request);
		const decision = readMobileApprovalDecision(body.decision);

		const verification = await mobileApprovalService.respond({
			userId,
			mobileInstallationId,
			verificationId,
			approvalToken,
			decision
		});

		return NextResponse.json({
			status: verification.status,
			respondedAt:
				verification.approvedAt?.toISOString() ??
				verification.rejectedAt?.toISOString() ??
				null
		});
	} catch (error: unknown) {
		return createAuthErrorResponse(error, request);
	}
};
