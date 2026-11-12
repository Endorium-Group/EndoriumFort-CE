// Full-text search in recordings (Enterprise): a hit opens the replay at the
// moment the line was on screen. The license, one ended SSH session, its
// recording and the search answer are served by the test; the rest is real.
import { test, expect } from '@playwright/test';
import { readState, signedIn } from './support.mjs';

const SESSION_ID = 990002;
const RECORDING_ID = 9077;

const cast = [
  JSON.stringify({ version: 2, width: 80, height: 24, timestamp: 1793869200 }),
  JSON.stringify([0.5, 'o', 'root@prod:~# ']),
  JSON.stringify([12.0, 'o', 'rm -rf /var/lib/app\r\n']),
  JSON.stringify([12.2, 'o', 'root@prod:~# ']),
  JSON.stringify([30.0, 'o', 'exit\r\n'])
].join('\n');

test('a search hit opens the replay where the line was on screen', async ({ page }) => {
  const { admin } = readState();
  const searches = [];

  await page.route('**/api/license/status', (route) => route.fulfill({
    json: { edition: 'enterprise', state: 'valid', tier: 'enterprise', daysRemaining: 300, features: [] }
  }));
  await page.route('**/api/sessions', async (route) => {
    if (route.request().method() !== 'GET') return route.continue();
    const response = await route.fetch();
    const body = await response.json();
    const items = Array.isArray(body) ? body : body.items || [];
    items.unshift({
      id: SESSION_ID, resourceId: 1, target: 'prod', user: 'root', protocol: 'ssh', port: 22,
      status: 'terminated', operator: 'op1', createdAt: '2026-11-05T09:00:00Z', terminatedAt: '2026-11-05T09:10:00Z'
    });
    await route.fulfill({ response, json: Array.isArray(body) ? items : { ...body, items } });
  });
  await page.route(/\/api\/recordings(\?.*)?$/, (route) => route.fulfill({
    json: { status: 'ok', items: [{ id: RECORDING_ID, sessionId: SESSION_ID, createdAt: '2026-11-05T09:00:00Z', closedAt: '2026-11-05T09:10:00Z', durationMs: 30000, fileSize: 4096, kind: 'terminal' }] }
  }));
  await page.route(`**/api/recordings/${RECORDING_ID}/cast`, (route) => route.fulfill({ body: cast, contentType: 'application/x-asciicast' }));
  await page.route('**/api/recordings/search?*', (route) => {
    searches.push(new URL(route.request().url()).searchParams.get('q'));
    return route.fulfill({
      json: {
        status: 'ok', truncated: false,
        items: [{ recordingId: RECORDING_ID, sessionId: SESSION_ID, operator: 'op1', resourceId: 1, recordedAt: '2026-11-05T09:00:00Z', total: 1,
          hits: [{ offset: 12.0, snippet: 'root@prod:~# \u0002rm -rf\u0003 /var/lib/app' }] }]
      }
    });
  });

  // The license is faked for this page only: other premium calls of the real
  // (unlicensed) bastion still answer "license required" and raise the upsell.
  await page.addLocatorHandler(page.getByRole('dialog', { name: 'Non inclus dans votre édition' }), async (dialog) => {
    await dialog.getByText('Fermer', { exact: true }).click();
  });
  await signedIn(page, admin.login, '/preuves');
  const search = page.getByRole('region', { name: 'Rechercher dans les enregistrements' });
  await expect(search).toBeVisible();
  await search.getByLabel('Rechercher dans les enregistrements').fill('rm -rf');
  await search.getByRole('button', { name: 'Rechercher', exact: true }).click();

  await expect(search).toContainText('1 occurrences dans 1 enregistrements');
  await expect(search.locator('mark')).toHaveText('rm -rf');
  expect(searches).toEqual(['rm -rf']);

  await search.getByTitle('Ouvrir la relecture à 00:12').click();
  // The replay shows the screen as it was at that moment: the command is there.
  await expect(page.locator('.xterm-rows')).toContainText('rm -rf /var/lib/app', { timeout: 10_000 });
  await expect(page.locator('.xterm-rows')).not.toContainText('exit');
  await expect(page.locator('.ef-player__mark[title="Résultat de recherche"]')).toHaveCount(1);
  if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/recording-search.png` });
});
