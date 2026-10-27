import React from 'react';
import { useI18n } from '../i18n.jsx';

// Thin strip above the header: license expired, revoked or refused (invalid),
// expiring within a week, or missing altogether (premium locked, free tier).
export default function LicenseBar({ state, daysRemaining, reason, canManage, onOpenLicense, onDismiss }) {
  const { t } = useI18n();
  const blocked = state === 'expired' || state === 'revoked' || state === 'invalid';
  let message;
  if (state === 'invalid') {
    message = t('live.license.invalid', { reason: reason || t('live.license.invalidUnknown') });
  } else if (state === 'none') {
    message = t('live.license.none');
  } else if (blocked) {
    message = t(state === 'revoked' ? 'live.license.revoked' : 'live.license.expired');
  } else {
    message = t(daysRemaining <= 1 ? 'live.license.soonOne' : 'live.license.soon', { days: daysRemaining });
  }
  return (
    <div className={`ef ef-licbar ${blocked ? 'is-danger' : 'is-warn'}`} role={blocked ? 'alert' : 'status'}>
      <span>{message}</span>
      {canManage && (
        <button type="button" className="ef-btn ef-btn--sm" onClick={onOpenLicense}>{t('live.license.open')}</button>
      )}
      {!blocked && (
        <button type="button" className="ef-btn ef-btn--link ef-btn--sm" onClick={onDismiss}>{t('live.license.dismiss')}</button>
      )}
    </div>
  );
}
