import type { NextConfig } from 'next';

/**
 * Returns the HTTP headers applied by Next.js.
 * @returns The application security and cache-control headers.
 */
const headers: NonNullable<NextConfig['headers']> = async () => {
	const securityHeaders = [
		{
			key: 'Content-Security-Policy',
			value: "frame-ancestors 'none'"
		},
		{
			key: 'Permissions-Policy',
			value: 'camera=(), geolocation=(), microphone=()'
		},
		{
			key: 'Referrer-Policy',
			value: 'strict-origin-when-cross-origin'
		},
		{
			key: 'X-Content-Type-Options',
			value: 'nosniff'
		},
		{
			key: 'X-Frame-Options',
			value: 'DENY'
		}
	];

	if (process.env.NODE_ENV === 'production') {
		securityHeaders.push({
			key: 'Strict-Transport-Security',
			value: 'max-age=31536000; includeSubDomains'
		});
	}

	const privateApiHeaders = [
		{
			key: 'Cache-Control',
			value: 'private, no-store, max-age=0'
		}
	];

	return [
		{
			source: '/(.*)',
			headers: securityHeaders
		},
		{
			source: '/api/auth/:path*',
			headers: privateApiHeaders
		},
		{
			source: '/api/account/:path*',
			headers: privateApiHeaders
		}
	];
};

export default headers;