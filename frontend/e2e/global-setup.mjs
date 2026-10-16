// Turns a brand-new bastion (see e2e/start-backend.sh) into a known test
// state, through its API: the factory admin finishes its first login (new
// password + TOTP), an operator and a few resources are created, and when the
// license allows it a JIT policy (reason + approval) covers the zone:e2e
// resources. Also starts the fake SSH server the resources point to.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { API, STATE_FILE, api, apiLogin, totp } from './support.mjs';
import { startFakeSsh } from './fake-ssh.mjs';

const SSH_HOST = process.env.E2E_SSH_HOST || '127.0.0.1'; // as seen from the bastion
const SSH_PORT = Number(process.env.E2E_SSH_PORT) || 2222;
const secret = (prefix) => `${prefix}${crypto.randomBytes(9).toString('base64url')}9a`;

export default async function globalSetup() {
  try {
    await api('', '/api/health');
  } catch (error) {
    throw new Error(`No bastion at ${API}. Start a fresh one first (npm run e2e:backend), see e2e/README.md. ${error.message}`);
  }

  // 1. Factory admin: first login, new password, two-factor sign-in.
  let first;
  try {
    first = await apiLogin('admin', 'Admin123');
  } catch {
    throw new Error(`The bastion at ${API} is not fresh (the factory admin password was already changed). Restart it with npm run e2e:backend.`);
  }
  const adminPassword = secret('Ad');
  await api(first.token, '/api/auth/change-password', { method: 'POST', body: { currentPassword: 'Admin123', newPassword: adminPassword, keepCurrentSession: true } });
  const setup = await api(first.token, '/api/auth/setup-2fa', { method: 'POST' });
  await api(first.token, '/api/auth/verify-2fa', { method: 'POST', body: { code: totp(setup.secret) } });
  const admin = await apiLogin('admin', adminPassword, setup.secret);

  const license = await api(admin.token, '/api/license/status').catch(() => ({}));
  const licensed = license?.state === 'valid' && license?.edition === 'enterprise';

  // 2. An operator, and resources on the fake SSH server.
  const operatorPassword = secret('Op');
  const operator = await api(admin.token, '/api/users', { method: 'POST', body: { username: 'op1', password: operatorPassword, role: 'operator', forcePasswordRotation: false } });
  const sshPassword = secret('Ssh');
  const resource = (fields) => api(admin.token, '/api/resources', { method: 'POST', body: { riskLevel: 'low', ...fields } });
  const plainSsh = await resource({ name: 'ssh-e2e', target: SSH_HOST, port: SSH_PORT, protocol: 'ssh', sshUsername: 'tester', sshPassword });
  const securedSsh = await resource({ name: 'secured-e2e', target: SSH_HOST, port: SSH_PORT, protocol: 'ssh', sshUsername: 'tester', sshPassword, riskLevel: 'high', tagsCsv: 'zone:e2e' });
  const web = await resource({ name: 'web-e2e', target: 'example.invalid', port: 443, protocol: 'https', tagsCsv: 'zone:e2e' });
  for (const r of [plainSsh, securedSsh, web]) await api(admin.token, `/api/users/${operator.id}/resources/${r.id}`, { method: 'POST', body: {} });

  // 3. JIT policy on zone:e2e (Pro): a reason and an approval are required.
  if (licensed) {
    await api(admin.token, '/api/access-policies', {
      method: 'POST',
      body: {
        name: 'zone-e2e', description: 'End-to-end tests', enabled: true, resourceTagsCsv: 'zone:e2e',
        identityPattern: '*', role: '', groupName: '', riskLevel: 'any', requireJustification: true,
        ticketRequired: false, approvalMode: 'required', mfaRequirement: 'any', timeWindow: 'any',
        routingConstraint: 'any', maxDurationSeconds: 3600
      }
    });
  }

  const op1 = await apiLogin('op1', operatorPassword);
  fs.writeFileSync(STATE_FILE, JSON.stringify({
    licensed,
    admin: { password: adminPassword, totpSecret: setup.secret, login: admin },
    op1: { password: operatorPassword, login: op1, id: operator.id },
    resources: { plainSsh: plainSsh.id, securedSsh: securedSsh.id, web: web.id }
  }, null, 2), { mode: 0o600 });

  const stopSsh = await startFakeSsh({ port: SSH_PORT, user: 'tester', password: sshPassword });
  return async () => {
    await stopSsh();
    fs.rmSync(STATE_FILE, { force: true });
  };
}
