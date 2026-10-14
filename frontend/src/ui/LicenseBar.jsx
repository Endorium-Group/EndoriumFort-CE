import React from 'react';
import { useI18n } from '../i18n.jsx';

// Thin strip above the header: license expired/revoked, or expiring within a week.
export default function LicenseBar({ state, daysRemaining, canManage, onOpenLicense, onDismiss }) {
  const { t } = useI18n();
  const blocked = state === 'expired' || state === 'revoked';
  return (
    <div className={`ef ef-licbar ${blocked ? 'is-danger' : 'is-warn'}`} role={blocked ? 'alert' : 'status'}>
      <span>
        {blocked
          ? t(state === 'revoked' ? 'live.license.revoked' : 'live.license.expired')
          : t(daysRemaining <= 1 ? 'live.license.soonOne' : 'live.license.soon', { days: daysRemaining })}
      </span>
      {canManage && (
        <button type="button" className="ef-btn ef-btn--sm" onClick={onOpenLicense}>{t('live.license.open')}</button>
      )}
      {!blocked && (
        <button type="button" className="ef-btn ef-btn--link ef-btn--sm" onClick={onDismiss}>{t('live.license.dismiss')}</button>
      )}
    </div>
  );
}
