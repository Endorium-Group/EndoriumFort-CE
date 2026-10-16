// Signing in: password, then the two-factor code.
import { test, expect } from '@playwright/test';
import { readState, totp } from './support.mjs';

async function fillCredentials(page, user, password) {
  await page.goto('/login');
  await page.locator('input[name="user"]').fill(user);
  await page.locator('input[name="password"]').fill(password);
  await page.getByRole('button', { name: 'Connexion', exact: true }).click();
}

test('admin signs in with password and two-factor code', async ({ page }) => {
  const { admin } = readState();
  await fillCredentials(page, 'admin', admin.password);
  const code = page.getByRole('textbox', { name: /Code authenticator/ });
  await expect(code).toBeVisible();
  // A code already used in this 30 s window is refused: then wait for the next one.
  for (let attempt = 0; attempt < 2; attempt++) {
    await code.fill(totp(admin.totpSecret));
    await code.press('Enter');
    try {
      await expect(page).not.toHaveURL(/\/login/, { timeout: 4000 });
      break;
    } catch (error) {
      if (attempt === 1) throw error;
      await page.waitForTimeout(30_000 - (Date.now() % 30_000) + 500);
    }
  }
  await expect(page.getByRole('link', { name: 'Administration' })).toBeVisible();
});

test('a wrong two-factor code is refused', async ({ page }) => {
  const { admin } = readState();
  await fillCredentials(page, 'admin', admin.password);
  const code = page.getByRole('textbox', { name: /Code authenticator/ });
  await code.fill('000000');
  await code.press('Enter');
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page).toHaveURL(/\/login/);
});
