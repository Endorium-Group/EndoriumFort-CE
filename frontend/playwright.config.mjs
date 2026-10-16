// End-to-end tests (Playwright): the real interface against a throwaway
// bastion. See e2e/README.md. The tests share that bastion's state, so they
// run one at a time.
import { defineConfig } from '@playwright/test';

const devPort = Number(process.env.E2E_UI_PORT) || 5175;
const api = process.env.E2E_API || 'http://localhost:8095';
const wantedChannel = process.env.E2E_BROWSER_CHANNEL || (process.platform === 'win32' ? 'msedge' : 'chrome');

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.spec.mjs',
  globalSetup: './e2e/global-setup.mjs',
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [['list'], ['html', { open: 'never', outputFolder: 'playwright-report' }]],
  use: {
    baseURL: `http://localhost:${devPort}`,
    // An installed browser (no download): Edge on Windows, Chrome elsewhere.
    // E2E_BROWSER_CHANNEL=chromium uses Playwright's own build instead.
    channel: wantedChannel === 'chromium' ? undefined : wantedChannel,
    locale: 'fr-FR',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure'
  },
  webServer: {
    command: 'npx vite',
    port: devPort,
    reuseExistingServer: false,
    env: { EF_API_TARGET: api, EF_DEV_PORT: String(devPort) }
  }
});
