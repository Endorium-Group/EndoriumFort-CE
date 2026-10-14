import React from 'react';
import { useI18n } from '../i18n.jsx';

export const LockIcon = ({ size = 12 }) => (
  <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true" style={{ width: size, height: size }}>
    <rect x="5" y="11" width="14" height="10" rx="2" />
    <path d="M8 11V7a4 4 0 0 1 8 0v4" />
  </svg>
);

// Shown wherever a route would appear when the edition does not include relays:
// the real route is unknown then, so we neither claim "direct" nor hide the field.
export default function RelayLock({ onUnlock }) {
  const { t } = useI18n();
  return (
    <button
      type="button"
      className="ef-lock"
      title={t('relayLock.hint')}
      onClick={(event) => {
        event.stopPropagation();
        onUnlock?.();
      }}
    >
      <LockIcon />
      {t('relayLock.label')}
    </button>
  );
}
