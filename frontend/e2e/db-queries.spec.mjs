// The SQL of a database-proxy session: list, filters and replay. A PostgreSQL
// session needs a real database and the agent, so this test adds one session
// to the bastion's answer and serves its journal; everything else is real.
import { test, expect } from '@playwright/test';
import { readState, signedIn } from './support.mjs';

const SESSION_ID = 990001;

const event = (type, createdAt, payload) => ({
  key: `${type}-${createdAt}`,
  id: 0,
  type,
  actor: 'op1',
  role: 'operator',
  createdAt,
  payloadIsJson: true,
  payloadRaw: JSON.stringify({ sessionId: SESSION_ID, resourceId: 1, database: 'app', dbUser: 'ef_1a2b3c4d', ...payload })
});

// Newest first, as /api/audit answers.
const journal = [
  event('db.query', '2026-11-05T10:00:06Z', { mode: 'simple', sql: 'SELECT * FROM missing', error: 'relation "missing" does not exist', sqlstate: '42P01', durationMs: 1, rows: 0 }),
  event('db.query.blocked', '2026-11-05T10:00:04Z', { mode: 'simple', sql: 'DROP TABLE items', rule: 'drop' }),
  event('db.query', '2026-11-05T10:00:02Z', { mode: 'extended', sql: 'SELECT name FROM items WHERE id = $1', parameters: 1, durationMs: 3, rows: 1, command: 'SELECT' }),
  event('db.query', '2026-11-05T10:00:01Z', { mode: 'simple', sql: 'SELECT count(*) FROM items', durationMs: 2, rows: 1, command: 'SELECT' }),
  event('db.connect', '2026-11-05T10:00:00Z', { tls: true })
];

test('a PostgreSQL session lists, filters and replays its queries', async ({ page }) => {
  const { admin } = readState();

  await page.route('**/api/sessions', async (route) => {
    if (route.request().method() !== 'GET') return route.continue();
    const response = await route.fetch();
    const body = await response.json();
    const items = Array.isArray(body) ? body : body.items || [];
    items.unshift({
      id: SESSION_ID, resourceId: 1, target: 'db.internal', user: 'app', protocol: 'postgres', port: 5432,
      status: 'active', operator: 'op1', createdAt: new Date().toISOString(), maxDurationSeconds: 3600
    });
    await route.fulfill({ response, json: Array.isArray(body) ? items : { ...body, items } });
  });
  await page.route('**/api/audit?*', async (route) => {
    const url = new URL(route.request().url());
    if (url.searchParams.get('sessionId') !== String(SESSION_ID)) return route.continue();
    await route.fulfill({ json: { status: 'ok', items: url.searchParams.get('family') === 'db' ? journal : [] } });
  });

  await signedIn(page, admin.login, '/sessions');
  await page.locator('tr', { hasText: String(SESSION_ID) }).first().click();
  await page.getByRole('button', { name: 'Requêtes SQL' }).click();

  const dialog = page.getByRole('dialog');
  await expect(dialog).toContainText('4 requêtes');
  await expect(dialog).toContainText('1 en échec');
  await expect(dialog).toContainText('1 refusées');
  const rows = dialog.locator('.ef-dblog__q');
  await expect(rows).toHaveCount(4);
  // Oldest first, as they ran.
  await expect(rows.first()).toContainText('SELECT count(*) FROM items');
  await expect(rows.nth(1)).toContainText('protocole étendu · 1 valeurs liées (non enregistrées)');
  await expect(rows.first()).toContainText(/\d{2}:\d{2}:\d{2}/);  // to the second
  await expect(rows.nth(2)).toContainText('Refusée par la règle du garde-fou SQL « drop »');
  await expect(rows.nth(3)).toContainText('42P01');

  await dialog.getByRole('button', { name: 'Refusées', exact: true }).click();
  await expect(rows).toHaveCount(1);
  await dialog.getByRole('button', { name: 'Toutes', exact: true }).click();
  await dialog.getByLabel('Rechercher dans le SQL').fill('items');
  await expect(rows).toHaveCount(3);
  await dialog.getByLabel('Rechercher dans le SQL').fill('');

  // Replay at 60×: the queries come back one by one, then it stops by itself.
  await dialog.getByLabel('Vitesse de relecture').selectOption('60');
  await dialog.getByRole('button', { name: 'Rejouer', exact: true }).click();
  await expect(dialog).toContainText('/4');
  await expect(dialog.locator('.ef-dblog__q.is-on')).toHaveCount(1);
  await expect(dialog).toContainText('4/4', { timeout: 5000 });
  if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/db-queries-replay.png` });
  await expect(dialog.getByRole('button', { name: 'Reprendre' })).toBeVisible();
  await dialog.getByRole('button', { name: 'Arrêter' }).click();
  await expect(rows).toHaveCount(4);
});
