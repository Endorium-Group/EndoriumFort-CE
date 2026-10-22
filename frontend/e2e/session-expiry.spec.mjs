// The sign-in token has a fixed lifetime: a banner warns during its last
// minutes, and signing in again (before or after it ends) comes back to the
// page that was open. Each test signs op1 in on its own: signing out revokes
// that token, and the other specs keep using the one from global-setup.
import { test, expect } from '@playwright/test';
import { apiLogin, readState, signedIn } from './support.mjs';

async function signInWithForm(page, user, password) {
  await page.locator('input[name="user"]').fill(user);
  await page.locator('input[name="password"]').fill(password);
  await page.getByRole('button', { name: 'Connexion', exact: true }).click();
}

test('a banner warns before the session ends, signing in again comes back here', async ({ page }) => {
  const { op1 } = readState();
  const login = await apiLogin('op1', op1.password);
  await signedIn(page, login, '/sessions', { expiresAt: new Date(Date.now() + 2 * 60_000).toISOString() });

  const banner = page.getByRole('status').filter({ hasText: 'Votre session se termine dans' });
  await expect(banner).toContainText(/[12]:\d\d/);
  await banner.getByRole('button', { name: 'Se reconnecter' }).click();

  await expect(page).toHaveURL(/\/login/);
  await signInWithForm(page, 'op1', op1.password);
  await expect(page).toHaveURL(/\/sessions$/);
});

test('when the session ends, signing in again comes back to the page', async ({ page }) => {
  const { op1 } = readState();
  const login = await apiLogin('op1', op1.password);
  await signedIn(page, login, '/demandes', { expiresAt: new Date(Date.now() + 4_000).toISOString() });
  await expect(page).toHaveURL(/\/demandes$/);

  await expect(page).toHaveURL(/\/login/, { timeout: 15_000 });
  await expect(page.getByRole('alert')).toContainText('Session expirée');
  await signInWithForm(page, 'op1', op1.password);
  await expect(page).toHaveURL(/\/demandes$/);
});

test('server errors are shown in French', async ({ page }) => {
  await page.goto('/login');
  await signInWithForm(page, 'op1', 'not-the-password');
  await expect(page.getByRole('alert')).toContainText('Identifiant ou mot de passe incorrect.');
});
