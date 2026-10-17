import type { NextConfig } from 'next';
import headers from '@/config/headers';

const nextConfig: NextConfig = {
	distDir: 'dist',
	reactCompiler: true,
	devIndicators: false,
	headers
};

export default nextConfig;
