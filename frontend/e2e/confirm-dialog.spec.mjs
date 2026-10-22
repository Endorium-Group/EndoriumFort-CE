// Sensitive actions ask for confirmation in a dialog (ui/ConfirmButton.jsx):
// a double click or Enter never confirms, Escape cancels, an error keeps the
// dialog open, and the heaviest actions ask to type the name.
import { test, expect } from '@playwright/test';
import { api, readState, signedIn } from './support.mjs';

test('deleting a resource: typed name, Escape, error kept in the dialog', async ({ page }) => {
  const { admin } = readState();
  const resource = await api(admin.login.token, '/api/resources', {
    method: 'POST',
    body: { name: 'confirm-e2e', target: '10.9.9.9', port: 22, protocol: 'ssh', riskLevel: 'low' }
  });
  const exists = async () => {
    const list = await api(admin.login.token, '/api/resources');
    return (list.items || list).some((r) => r.id === resource.id);
  };

  await signedIn(page, admin.login, '/admin/resources');
  await page.locator('tr', { hasText: 'confirm-e2e' }).click();
  const remove = page.locator('.ef-upanel__foot').getByRole('button', { name: 'Supprimer', exact: true });
  const dialog = page.getByRole('dialog', { name: 'Supprimer la ressource confirm-e2e ?' });
  const confirm = dialog.getByRole('button', { name: 'Confirmer la suppression' });

  // A double click only opens the dialog.
  await remove.dblclick();
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText('Cette action est définitive');
  expect(await exists()).toBe(true);

  // The name must be typed; the field has the focus.
  const field = dialog.getByLabel('Tapez confirm-e2e pour confirmer.');
  await expect(field).toBeFocused();
  await expect(confirm).toBeDisabled();
  await field.fill('confirm');
  await expect(confirm).toBeDisabled();

  // Escape closes the dialog only, the editor stays open.
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  await expect(remove).toBeVisible();
  expect(await exists()).toBe(true);

  // A refusal from the server stays in the dialog.
  await page.route(`**/api/resources/${resource.id}`, (route) =>
    route.request().method() === 'DELETE'
      ? route.fulfill({ status: 500, body: 'Failed to delete resource (e2e)' })
      : route.continue());
  await remove.click();
  await dialog.getByLabel('Tapez confirm-e2e pour confirmer.').fill('confirm-e2e');
  await confirm.click();
  await expect(dialog.getByRole('alert')).toContainText('Failed to delete resource (e2e)');
  await expect(dialog).toBeVisible();
  expect(await exists()).toBe(true);

  // Then it goes through.
  await page.unroute(`**/api/resources/${resource.id}`);
  await confirm.click();
  await expect(dialog).toHaveCount(0);
  await expect.poll(exists).toBe(false);
});

test('ending a session: says which one, Cancel has the focus', async ({ page }) => {
  const { admin, op1, resources } = readState();
  const list = await api(op1.login.token, '/api/resources');
  const ssh = (list.items || list).find((r) => r.id === resources.plainSsh);
  const session = await api(op1.login.token, '/api/sessions', {
    method: 'POST',
    body: { resourceId: ssh.id, target: ssh.target, port: ssh.port, user: 'tester', protocol: 'ssh' }
  });
  const status = async () => {
    const list = await api(admin.login.token, '/api/sessions');
    return (list.items || list).find((s) => s.id === session.id)?.status;
  };
  expect(await status()).toBe('active');

  await signedIn(page, admin.login, '/sessions');
  const row = page.locator('tr', { hasText: 'ssh-e2e' }).filter({ hasText: 'op1' }).first();
  await row.getByRole('button', { name: 'Terminer', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: `Terminer la session n° ${session.id} ?` });
  await expect(dialog).toContainText('La connexion de op1 sur ssh-e2e est coupée immédiatement.');

  // Enter on the focused Cancel button does not end anything.
  await expect(dialog.getByRole('button', { name: 'Annuler' })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(dialog).toHaveCount(0);
  expect(await status()).toBe('active');

  await row.getByRole('button', { name: 'Terminer', exact: true }).click();
  await dialog.getByRole('button', { name: 'Terminer', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await expect.poll(status).not.toBe('active');
});
