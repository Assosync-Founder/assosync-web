import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { Proxy } from '@assosync/proxy';
import proxyConfig from '@/config/proxy';

const WEBAUTHN_CONFIGURATION_PATH = '/.well-known/webauthn';

/** Routes requests through the hostname-aware application proxy.
 * @param request - Incoming Next.js request.
 * @returns Scoped response or the root WebAuthn configuration rewrite.
 */
export const proxy = (request: NextRequest) => {
	if (request.nextUrl.pathname === WEBAUTHN_CONFIGURATION_PATH) {
		const destination = request.nextUrl.clone();

		destination.pathname = `/account${ WEBAUTHN_CONFIGURATION_PATH }`;

		return NextResponse.rewrite(destination);
	}

	return new Proxy(request, proxyConfig).handle();
};

// noinspection JSUnusedGlobalSymbols
export const config = {
	matcher: [
		'/api/:path*',
		'/((?!_next/|static/|manifest\\.webmanifest|robots\\.txt|sitemap\\.xml).*)'
	]
};
