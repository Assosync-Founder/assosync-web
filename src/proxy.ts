import type { NextRequest } from 'next/server';
import { Proxy } from '@assosync/proxy';
import proxyConfig from '@/config/proxy';

export const proxy = (req: NextRequest) => {
	return new Proxy(req, proxyConfig).handle();
}

// noinspection JSUnusedGlobalSymbols
export const config = {
	matcher: [
		'/api/:path*',
		'/((?!_next/|static/|manifest\\.webmanifest|robots\\.txt|sitemap\\.xml).*)'
	]
};