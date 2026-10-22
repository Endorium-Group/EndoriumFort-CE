// An SSH session survives a page reload: the terminal comes back on the same
// shell, with what was printed meanwhile (backend: ssh.cc grace period).
import { test, expect } from '@playwright/test';
import { API, readState, signedIn } from './support.mjs';

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

// A shell that ends on its own while its page is gone used to leave the
// reader thread unjoined: when the grace timer dropped the connection, the
// bastion aborted (std::terminate). The e2e bastion uses a 10 s grace.
test('a shell ending while its page is gone does not take the bastion down', async ({ browser }) => {
  test.setTimeout(60_000);
  const { op1 } = readState();
  const context = await browser.newContext();
  const page = await context.newPage();
  await signedIn(page, op1.login, '/carte');
  await page.locator('button.ef-node', { hasText: 'ssh-e2e' }).click();
  await page.getByRole('button', { name: 'Se connecter', exact: true }).first().click();
  await expect(terminalText(page)).toContainText('toy shell', { timeout: 20_000 });

  await run(page, 'exit-later');
  await expect(terminalText(page)).toContainText('exit-later');
  await page.waitForTimeout(300); // let the Enter reach the shell
  await context.close(); // the shell is detached, then exits 1 s later

  await new Promise((resolve) => setTimeout(resolve, 14_000)); // grace (10 s) + margin
  const health = await fetch(`${API}/api/health`).then((r) => r.json());
  expect(health.status).toBe('ok');
});

// Sends `start` for a session over the terminal WebSocket from `page` (so with
// that user's session cookie) and returns the first text message back.
const startOverWebSocket = (page, sessionId) => page.evaluate((id) => new Promise((resolve, reject) => {
  const socket = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/api/ws/ssh`);
  const timer = setTimeout(() => reject(new Error('no answer')), 10_000);
  socket.onopen = () => socket.send(JSON.stringify({ type: 'start', sessionId: id, cols: 80, rows: 24 }));
  socket.onmessage = (event) => {
    if (typeof event.data !== 'string') return;
    clearTimeout(timer);
    const message = JSON.parse(event.data);
    if (message.message === 'Session resumed') socket.send(JSON.stringify({ type: 'input', data: 'exit\r' }));
    else socket.close();
    resolve(message);
  };
  socket.onerror = () => reject(new Error('websocket error'));
}), sessionId);

// Only the owner drives a session, administrators included: they get a
// refusal, whether the owner's terminal is open or detached after a reload
// (and can still observe or end it).
test('only the owner can drive a session, open or detached', async ({ browser }) => {
  const { op1, admin } = readState();
  const ownerContext = await browser.newContext();
  const ownerPage = await ownerContext.newPage();
  await signedIn(ownerPage, op1.login, '/carte');
  await ownerPage.locator('button.ef-node', { hasText: 'ssh-e2e' }).click();
  await ownerPage.getByRole('button', { name: 'Se connecter', exact: true }).first().click();
  await expect(terminalText(ownerPage)).toContainText('toy shell', { timeout: 20_000 });
  const sessionId = Number(await ownerPage.evaluate(() => sessionStorage.getItem('endoriumfort_open_terminal')));
  expect(sessionId).toBeGreaterThan(0);
  const notYours = { type: 'error', message: 'This session belongs to another user: use Observe to follow it' };

  const adminContext = await browser.newContext();
  const adminPage = await adminContext.newPage();
  await signedIn(adminPage, admin.login, '/sessions');
  // While the owner's terminal is open: no second shell for the admin.
  expect(await startOverWebSocket(adminPage, sessionId)).toMatchObject(notYours);

  await ownerContext.close(); // the shell is now detached (10 s grace)
  expect(await startOverWebSocket(adminPage, sessionId)).toMatchObject(notYours);
  await adminContext.close();

  // The owner still can.
  const backContext = await browser.newContext();
  const backPage = await backContext.newPage();
  await signedIn(backPage, op1.login, '/sessions');
  const resumed = await startOverWebSocket(backPage, sessionId);
  expect(resumed).toMatchObject({ type: 'status', message: 'Session resumed' });
  await backContext.close();
});
