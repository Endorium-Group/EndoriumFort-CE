import crypto from 'node:crypto';
import { test, expect } from '@playwright/test';

function base32Decode(value) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of String(value || '').toUpperCase().replace(/=+$/g, '')) {
    const index = alphabet.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid base32 character: ${char}`);
    }
    bits += index.toString(2).padStart(5, '0');
  }

  const bytes = [];
  for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
    bytes.push(Number.parseInt(bits.slice(offset, offset + 8), 2));
  }
  return Buffer.from(bytes);
}

function computeTotp(secret, nowMs = Date.now()) {
  const key = base32Decode(secret);
  const counter = Math.floor(nowMs / 1000 / 30);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', key).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, '0');
}

// One ordered flow: it mutates the seeded admin (password rotation, then MFA
// enrolment), so it runs once against a fresh backend, after auth-login (see
// the projects in playwright.config.mjs).
test('bootstrap admin rotates password, sees passkey option, enables TOTP MFA', async ({ page }) => {
  const username = process.env.E2E_BOOTSTRAP_USER || 'admin';
  const password = process.env.E2E_BOOTSTRAP_PASSWORD || 'Admin123';
  // Must satisfy the backend password policy (ENDORIUMFORT_PASSWORD_MIN_LENGTH, default 12).
  const newPassword = process.env.E2E_BOOTSTRAP_NEW_PASSWORD || 'Admin-E2E-rotated-1';

  await page.goto('/');
  await page.getByLabel('User').fill(username);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();

  const bootstrapHeading = page.getByRole('heading', {
    name: 'Secure the default admin account'
  });
  await expect(bootstrapHeading).toBeVisible();
  await expect(page.getByText(/Change the default password/i)).toBeVisible();

  await page.getByLabel('Current password').fill(password);
  await page.getByLabel('New admin password').fill(newPassword);
  await page.getByLabel('Confirm new password').fill(newPassword);
  await page.getByRole('button', { name: /Save new password/i }).click();

  // Step 2: MFA enrolment offers both TOTP and passkeys.
  await expect(page.getByText(/Enable MFA with TOTP or passkey/i)).toBeVisible();
  await expect(page.getByRole('button', { name: /Use passkey \/ security key/i })).toBeVisible();

  await page.getByRole('button', { name: /Start MFA setup/i }).click();
  const secretLocator = page.locator('.inline-secret');
  await expect(secretLocator).toBeVisible();
  const secret = (await secretLocator.textContent())?.trim();
  expect(secret).toBeTruthy();

  await page.getByLabel('Authenticator code').fill(computeTotp(secret));
  await page.getByRole('button', { name: /Verify and enable MFA/i }).click();

  // Bootstrap is complete: the overlay closes and the console is usable.
  await expect(bootstrapHeading).toBeHidden();
  await expect(page.getByRole('button', { name: /Sign out/i })).toBeVisible();

  // The rotated password and TOTP are now enforced: signing back in asks for
  // the authenticator code.
  await page.getByRole('button', { name: /Sign out/i }).click();
  await page.getByLabel('User').fill(username);
  await page.getByLabel('Password').fill(newPassword);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Verify & Sign in' })).toBeVisible();
});
