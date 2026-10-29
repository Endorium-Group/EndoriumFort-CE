// Client of the file share service (fileshare/, served under /files/ by the
// reverse proxy). It is a separate service from the bastion: it only knows the
// session cookie it set in exchange for a bastion-signed ticket, scoped to one
// resource (Path=/files/api/r/<id>/). Every state change carries X-EF-Files,
// which a cross-site form cannot send.
import { translateServerMessage } from './serverMessages.js';

const base = (resourceId) => `/files/api/r/${encodeURIComponent(resourceId)}`;

export class FileshareError extends Error {
  constructor(message, status) {
    super(translateServerMessage(message));
    this.serverMessage = message;
    this.status = status;
  }
}

async function check(response, fallback) {
  if (response.ok) return response;
  let message = fallback;
  try {
    const text = await response.text();
    try {
      message = JSON.parse(text).error || message;
    } catch (_) {
      if (text && text.length < 300 && !text.trim().startsWith('<')) message = text;
    }
  } catch (_) {}
  throw new FileshareError(message, response.status);
}

const send = (resourceId, route, { method = 'GET', body, query } = {}) => {
  const url = new URL(`${base(resourceId)}/${route}`, window.location.origin);
  Object.entries(query || {}).forEach(([key, value]) => {
    if (value !== undefined && value !== null) url.searchParams.set(key, value);
  });
  const headers = { 'X-EF-Files': '1' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  return fetch(url, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body)
  });
};

const json = async (promise, fallback) => (await check(await promise, fallback)).json();

export const openFileshareSession = (resourceId, ticket) =>
  json(send(resourceId, 'session', { method: 'POST', body: { ticket } }), 'Unable to open the drive');

export const closeFileshareSession = (resourceId) =>
  send(resourceId, 'session', { method: 'DELETE' }).catch(() => {});

export const fetchDriveInfo = (resourceId) => json(send(resourceId, 'me'), 'Unable to read the drive');

export const listFolder = (resourceId, root, path) =>
  json(send(resourceId, 'list', { query: { root, path } }), 'Unable to list the folder');

export const makeFolder = (resourceId, root, path, name) =>
  json(send(resourceId, 'mkdir', { method: 'POST', body: { root, path, name } }), 'Unable to create the folder');

export const renameItem = (resourceId, root, path, newName) =>
  json(send(resourceId, 'rename', { method: 'POST', body: { root, path, newName } }), 'Unable to rename');

export const deleteItem = (resourceId, root, path) =>
  json(send(resourceId, 'delete', { method: 'POST', body: { root, path } }), 'Unable to delete');

export const fetchShares = (resourceId) => json(send(resourceId, 'shares'), 'Unable to read the shares');

export const createShare = (resourceId, payload) =>
  json(send(resourceId, 'shares', { method: 'POST', body: payload }), 'Unable to share');

export const revokeShare = (resourceId, shareId) =>
  json(send(resourceId, `shares/${encodeURIComponent(shareId)}`, { method: 'DELETE' }), 'Unable to revoke the share');

// A plain link: the session cookie rides along, the answer is an attachment.
export const downloadUrl = (resourceId, root, path) => {
  const url = new URL(`${base(resourceId)}/download`, window.location.origin);
  url.searchParams.set('root', root);
  url.searchParams.set('path', path);
  return url.toString();
};

// Upload with progress (fetch has no upload progress). Resolves on 201,
// rejects with a FileshareError (status 409 = the name is taken).
export function uploadFile(resourceId, root, dir, file, { overwrite = false, onProgress } = {}) {
  const url = new URL(`${base(resourceId)}/upload`, window.location.origin);
  url.searchParams.set('root', root);
  url.searchParams.set('path', dir);
  url.searchParams.set('name', file.name);
  if (overwrite) url.searchParams.set('overwrite', '1');
  const xhr = new XMLHttpRequest();
  const done = new Promise((resolve, reject) => {
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable && onProgress) onProgress(event.loaded / event.total);
    };
    xhr.onload = () => {
      if (xhr.status === 201) {
        resolve();
        return;
      }
      let message = 'Upload failed';
      try {
        message = JSON.parse(xhr.responseText).error || message;
      } catch (_) {}
      reject(new FileshareError(message, xhr.status));
    };
    xhr.onerror = () => reject(new FileshareError('Upload failed', 0));
    xhr.onabort = () => reject(new FileshareError('Upload cancelled', 0));
  });
  xhr.open('PUT', url.toString());
  xhr.withCredentials = true;
  xhr.setRequestHeader('X-EF-Files', '1');
  xhr.setRequestHeader('Content-Type', 'application/octet-stream');
  xhr.send(file);
  return { promise: done, abort: () => xhr.abort() };
}
