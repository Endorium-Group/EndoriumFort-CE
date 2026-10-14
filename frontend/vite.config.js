import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';

// Open-core `@pro` overlay resolution:
//  - EE build: src/pro/ is present  → premium UI is bundled.
//  - CE build: src/pro/ is absent   → falls back to the no-op src/pro-stub/.
// `EF_EDITION=community` forces the stub even when src/pro/ exists, so a CE
// artifact built from the private monorepo never ships premium UI.
const proReal = fileURLToPath(new URL('./src/pro/index.jsx', import.meta.url));
const proStub = fileURLToPath(new URL('./src/pro-stub/index.jsx', import.meta.url));
const forceStub = process.env.EF_EDITION === 'community';
const proEntry = !forceStub && existsSync(proReal) ? proReal : proStub;
// Build-time edition flag for core UI that must not offer Enterprise-only
// flows in the Community build (e.g. the SSO login button).
const edition = proEntry === proStub ? 'community' : 'enterprise';

export default defineConfig({
  plugins: [react()],
  define: {
    __EF_EDITION__: JSON.stringify(edition)
  },
  resolve: {
    alias: {
      '@pro': proEntry
    }
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        ws: true
      },
      '/ws': {
        target: 'http://localhost:8080',
        ws: true
      },
      '/proxy': {
        target: 'http://localhost:8080'
      }
    }
  }
});
