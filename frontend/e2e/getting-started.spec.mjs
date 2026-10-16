// The getting-started guide on the map reflects the bastion's real state.
// After global-setup: a resource, an operator and two-factor sign-in exist;
// only the license may be missing.
import { test, expect } from '@playwright/test';
import { api, readState, signedIn } from './support.mjs';

test('the guide lists only what is left to do', async ({ page }) => {
  const { admin } = readState();
  const license = await api(admin.login.token, '/api/license/status');
  await signedIn(page, admin.login, '/carte');
  await expect(page.locator('button.ef-node').first()).toBeVisible();
  const guide = page.locator('.ef-start');
  if (license.edition === 'enterprise' && license.state !== 'valid') {
    await expect(guide).toBeVisible();
    await expect(guide).toContainText('3 sur 4 faites');
    await expect(guide.locator('li.is-next')).toContainText('Importer la licence');
  } else {
    // Licensed, or Community where the license is optional: nothing left.
    await expect(guide).toHaveCount(0);
  }
});

test('operators never see the guide', async ({ page }) => {
  const { op1 } = readState();
  await signedIn(page, op1.login, '/carte');
  await expect(page.locator('button.ef-node').first()).toBeVisible();
  await expect(page.locator('.ef-start')).toHaveCount(0);
});
