import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({ resolve: { alias: {
  'cloudflare:workers': fileURLToPath(new URL('./tests/cloudflare-workers.stub.js', import.meta.url)),
} } });
