import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './test/e2e',
  timeout: 30_000,
  retries: 1,
  // The specs share one backend and its seeded admin, so run them in order.
  workers: 1,
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://127.0.0.1:5173',
    headless: true,
    trace: 'retain-on-failure'
  },
  projects: [
    { name: 'login', testMatch: /auth-login\.spec\.mjs/ },
    {
      // Rotates the bootstrap password and enrols MFA: must run after the
      // login spec, and cannot be retried against the already-mutated admin.
      name: 'bootstrap',
      testMatch: /auth-bootstrap-mfa\.spec\.mjs/,
      dependencies: ['login'],
      retries: 0
    }
  ]
});
