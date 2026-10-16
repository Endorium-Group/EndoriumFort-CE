// Administration › Appearance (Pro): tab title and pre-sign-in message.
import { test, expect } from '@playwright/test';
import { api, readState, signedIn } from './support.mjs';

test.beforeEach(() => {
  test.skip(!readState().licensed, 'needs a Pro license (branding): set E2E_LICENSE_FILE');
});

test('tab title and login message set in Appearance show on the login page', async ({ page, browser }) => {
  const { admin } = readState();
  await signedIn(page, admin.login, '/admin/appearance');
  await page.getByRole('textbox', { name: 'Titre de l’onglet' }).fill('E2E Bastion');
  await page.locator('.ef-appearance__message').fill('Accès réservé (e2e)\nSessions enregistrées.');
  await page.getByRole('button', { name: 'Enregistrer' }).click();
  await expect(page.getByRole('status')).toContainText('Apparence enregistrée');
  await expect(page).toHaveTitle('E2E Bastion');

  try {
    const visitor = await browser.newContext();
    const login = await visitor.newPage();
    await login.goto('/login');
    await expect(login).toHaveTitle('E2E Bastion');
    await expect(login.getByRole('note')).toContainText('Accès réservé (e2e)');
    await visitor.close();
  } finally {
    await api(admin.login.token, '/api/branding', { method: 'PUT', body: { tabTitle: '', blur: 0, dim: false, loginMessage: '' } });
  }
});
