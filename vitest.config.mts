import { fileURLToPath, URL } from 'node:url';
import { defineConfig } from 'vitest/config';

const vitestConfig = defineConfig({
	resolve: {
		alias: {
			'@': fileURLToPath(new URL('./src', import.meta.url))
		}
	}
});

export default vitestConfig;
