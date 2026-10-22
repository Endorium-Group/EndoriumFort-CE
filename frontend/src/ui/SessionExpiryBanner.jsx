import React from 'react';
import { useI18n } from '../i18n.jsx';
import { useNow } from './sessions.js';

// The sign-in token has a fixed lifetime (ENDORIUMFORT_TOKEN_TTL_SECONDS, no
// renewal: a new sign-in is the only way to extend it). Shown during its last
// minutes so nobody is cut off mid-task; "Sign in again" comes back to the
// same page afterwards.
export const EXPIRY_WARNING_MS = 5 * 60 * 1000;

export default function SessionExpiryBanner({ expiresAt, onReconnect }) {
  const { t } = useI18n();
  const now = useNow(1000);
  const end = expiresAt ? new Date(expiresAt).getTime() : NaN;
  const remaining = end - now;
  if (!Number.isFinite(remaining) || remaining > EXPIRY_WARNING_MS || remaining <= 0) return null;

  const seconds = Math.ceil(remaining / 1000);
  const time = `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
  return (
    <div className="ef ef-alert ef-alert--warn ef-expiry" role="status">
      <span>{t('auth.expiresSoon', { time })}</span>
      <button type="button" className="ef-btn ef-btn--sm" onClick={onReconnect}>
        {t('auth.reconnectNow')}
      </button>
    </div>
  );
}
