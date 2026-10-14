// Appearance chosen in Administration › Appearance (Pro): browser tab title and
// icon, login page background. `branding` is the GET /api/branding payload, or
// null for the stock look (Community build, no license, nothing configured).

const DEFAULT_TITLE = document.title;
const DEFAULT_ICON = document.querySelector('link[rel="icon"]')?.getAttribute('href') || '';

export const BLUR_MAX = 20;

// `v` busts the browser cache when an image is replaced.
export const brandingImageUrl = (kind, branding) =>
  `/api/branding/${kind}?v=${branding?.updatedAt || 0}`;

export function applyBranding(branding) {
  document.title = branding?.tabTitle || DEFAULT_TITLE;
  let link = document.querySelector('link[rel="icon"]');
  if (!link) {
    link = document.createElement('link');
    link.rel = 'icon';
    document.head.appendChild(link);
  }
  if (branding?.hasFavicon) {
    link.removeAttribute('type');
    link.href = brandingImageUrl('favicon', branding);
  } else {
    link.type = 'image/png';
    link.href = DEFAULT_ICON;
  }
}
