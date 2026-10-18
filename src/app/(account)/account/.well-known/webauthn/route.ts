import { NextResponse } from 'next/server';
import authConfig from '@/config/auth';

/** Publishes the exact product origins allowed to reuse the Account RP ID.
 * @returns Related Origin Requests configuration.
 */
export const GET = (): Response => {
	const origins = authConfig.webSso.clients.flatMap((client) => {
		return client.passkeyOrigins;
	});

	return NextResponse.json(
		{ origins },
		{
			headers: {
				'Cache-Control': 'public, max-age=300',
				'Content-Type': 'application/json'
			}
		}
	);
};
