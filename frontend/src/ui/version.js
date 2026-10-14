import { version as uiVersion } from '../../package.json';

// Version of this interface build (frontend/package.json).
export const UI_VERSION = uiVersion;

// "1.0.32", or "1.0.32 (interface 1.0.31)" when the interface was built from
// another version than the server it talks to — useful when reporting a bug.
export function versionText(t, serverVersion) {
  if (!serverVersion) return UI_VERSION;
  if (serverVersion === UI_VERSION) return serverVersion;
  return `${serverVersion} ${t('about.uiDiffers', { version: UI_VERSION })}`;
}
