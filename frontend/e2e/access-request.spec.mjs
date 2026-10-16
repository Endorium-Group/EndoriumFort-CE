// Access under a JIT policy (Pro): zone:e2e needs a reason and an approval.
import { test, expect } from '@playwright/test';
import { api, readState, signedIn } from './support.mjs';

test.beforeEach(() => {
  test.skip(!readState().licensed, 'needs a Pro license (JIT policies): set E2E_LICENSE_FILE');
});

test('critical resource: request with a reason, approval, then the purpose at connection', async ({ page }) => {
  const { op1, admin, resources } = readState();
  await signedIn(page, op1.login, '/carte');

  // 1. The request asks for the reason, not the purpose (that is for the session).
  await page.locator('button.ef-node', { hasText: 'secured-e2e' }).click();
  await page.getByRole('button', { name: 'Se connecter', exact: true }).first().click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toContainText('Demander l’accès');
  await expect(dialog.locator('#access-purpose')).toHaveCount(0);
  await dialog.locator('#access-reason').fill('e2e: maintenance');
  await dialog.getByRole('button', { name: 'Envoyer la demande' }).click();
  await expect(page).toHaveURL(/\/demandes/);

  // 2. An administrator approves it.
  const requests = await api(admin.login.token, '/api/access-requests');
  const request = (requests.items || requests).find((r) => r.requester === 'op1' && r.resourceId === resources.securedSsh && r.status === 'pending');
  expect(request, 'pending request of op1').toBeTruthy();
  await api(admin.login.token, `/api/access-requests/${request.id}/approve`, { method: 'POST', body: { comment: 'e2e' } });

  // 3. Connecting now asks for the session purpose, the reason is carried over.
  await page.goto('/carte');
  await page.locator('button.ef-node', { hasText: 'secured-e2e' }).click();
  await page.getByRole('button', { name: 'Se connecter', exact: true }).first().click();
  await expect(dialog).toContainText(`n° ${request.id}`);
  await expect(dialog.locator('#access-reason')).toHaveValue('e2e: maintenance');
  const purpose = dialog.locator('#access-purpose');
  await expect(purpose).toHaveAttribute('required', '');
  await purpose.fill('e2e: check the service');
  await dialog.getByRole('button', { name: 'Se connecter', exact: true }).click();
  await expect(page.locator('.xterm-rows')).toContainText('toy shell', { timeout: 20_000 });
  const input = page.getByRole('textbox', { name: 'Terminal input' });
  await input.focus();
  await page.keyboard.type('exit');
  await page.keyboard.press('Enter');
});

test('web resource under a policy asks for the reason before opening', async ({ page }) => {
  const { admin } = readState();
  await signedIn(page, admin.login, '/carte');
  await page.locator('button.ef-node', { hasText: 'web-e2e' }).click();
  await page.getByRole('button', { name: 'Se connecter', exact: true }).first().click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toContainText('HTTPS');
  await expect(dialog.locator('#access-reason')).toHaveAttribute('required', '');
  await dialog.getByRole('button', { name: 'Annuler' }).click();
  await expect(dialog).toHaveCount(0);
});
