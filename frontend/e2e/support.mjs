// Shared helpers for the end-to-end tests: the throwaway bastion's API, TOTP
// codes, and the state written by global-setup (accounts, ids).
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const API = process.env.E2E_API || 'http://localhost:8095';
export const STATE_FILE = path.join(os.tmpdir(), 'endoriumfort-e2e-state.json');

export const readState = () => JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));

// RFC 6238 code for a base32 secret; `offset` shifts by 30 s steps.
export function totp(secret, offset = 0) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const ch of secret.replace(/=+$/, '')) bits += alphabet.indexOf(ch).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + offset));
  const h = crypto.createHmac('sha1', key).update(counter).digest();
  return String((h.readUInt32BE(h[19] & 15) & 0x7fffffff) % 1e6).padStart(6, '0');
}

export async function api(token, route, { method = 'GET', body } = {}) {
  const response = await fetch(`${API}${route}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const text = await response.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* plain-text answer */ }
  if (!response.ok) {
    const error = new Error(`${method} ${route} → ${response.status} ${text.slice(0, 200)}`);
    error.status = response.status;
    throw error;
  }
  return json ?? text;
}

// Signs in through the API (TOTP when a secret is given). A code already used
// in this 30 s window can be refused, so the next window is tried too.
export async function apiLogin(user, password, secret) {
  for (const offset of secret ? [0, 1] : [0]) {
    try {
      return await api('', '/api/auth/login', { method: 'POST', body: { user, password, ...(secret ? { totpCode: totp(secret, offset) } : {}) } });
    } catch (error) {
      if (!secret || offset === 1) throw error;
    }
  }
  throw new Error(`login ${user} failed`);
}

// What the app keeps in localStorage after signing in (see App.jsx onLogin).
// `expiresAt` overrides when the app believes the token ends (the server's
// own expiry is unchanged), to exercise the expiry warning.
export const storedAuth = (login, expiresAt = login.expiresAt) => JSON.stringify({
  token: login.token,
  user: login.user,
  role: login.role,
  permissions: Array.isArray(login.permissions) ? login.permissions : [],
  expiresAt: expiresAt || ''
});

// Opens the app already signed in as `login` (an apiLogin result). The
// terminal WebSocket authenticates with the session cookie the login sets
// (utils.h), so it is added next to the localStorage entry.
export async function signedIn(page, login, route = '/carte', { expiresAt } = {}) {
  const ui = `http://localhost:${process.env.E2E_UI_PORT || 5175}`;
  await page.context().addCookies([
    { name: 'endoriumfort_token', value: login.token, url: ui, httpOnly: true, sameSite: 'Strict' }
  ]);
  await page.addInitScript((value) => {
    if (!sessionStorage.getItem('__e2e_auth_set')) {
      localStorage.setItem('endoriumfort_auth', value);
      sessionStorage.setItem('__e2e_auth_set', '1');
    }
  }, storedAuth(login, expiresAt));
  await page.goto(route);
}
