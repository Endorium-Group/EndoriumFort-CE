// An SSH session survives a page reload: the terminal comes back on the same
// shell, with what was printed meanwhile (backend: ssh.cc grace period).
import { test, expect } from '@playwright/test';
import { readState, signedIn } from './support.mjs';

const terminalText = (page) => page.locator('.xterm-rows');
async function run(page, command) {
  const input = page.getByRole('textbox', { name: 'Terminal input' });
  await input.focus();
  await page.keyboard.type(command);
  await page.keyboard.press('Enter');
}

test('reloading the page resumes the same SSH shell', async ({ page }) => {
  const { op1 } = readState();
  await signedIn(page, op1.login, '/carte');
  await page.locator('button.ef-node', { hasText: 'ssh-e2e' }).click();
  await page.getByRole('button', { name: 'Se connecter', exact: true }).first().click();

  await expect(terminalText(page)).toContainText('toy shell', { timeout: 20_000 });
  await run(page, 'who');
  await expect(terminalText(page)).toContainText('shell-id=');
  const shellId = (await terminalText(page).innerText()).match(/shell-id=(\S+)/)[1];

  // Output produced while the page reloads must not be lost.
  await run(page, 'later');
  await page.reload();

  await expect(page.getByText(/Session reprise/)).toBeVisible({ timeout: 20_000 });
  // What was on screen before the reload comes back, then what came meanwhile.
  await expect(terminalText(page)).toContainText('toy shell');
  await expect(terminalText(page)).toContainText(`shell-id=${shellId}`);
  await expect(terminalText(page)).toContainText('delayed-output');
  await run(page, 'who');
  await expect.poll(async () => (await terminalText(page).innerText()).split(`shell-id=${shellId}`).length - 1).toBe(2);

  await run(page, 'exit');
});
