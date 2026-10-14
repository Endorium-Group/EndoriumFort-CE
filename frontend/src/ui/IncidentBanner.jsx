import React from 'react';
import { useI18n } from '../i18n.jsx';
import { formatAgo, useNow } from './sessions.js';

// Shown above every page when several critical signals arrive within 5 minutes.
export default function IncidentBanner({
  incident,
  incidentCase,
  containment,
  suspects,
  activeSuspectCount,
  strictProfile,
  canManage,
  canOperate,
  busy,
  onInvestigate,
  onOpenSession,
  onStrict,
  onOpenCase,
  onCloseCase,
  onContainment,
  onTerminateSuspects,
  onDismiss
}) {
  const { t, locale } = useI18n();
  const now = useNow(30000);
  const caseOpen = !!(incidentCase?.active && incidentCase?.incident?.id > 0);

  return (
    <section className="ef ef-incident" role="alert" aria-live="assertive">
      <div className="ef-incident__main">
        <div className="ef-incident__title">
          <span className="ef-dot" style={{ background: 'var(--ef-danger)' }} />
          <strong>{t('live.incident.title')}</strong>
          <span className="ef-muted">
            {t('live.incident.signals', { count: incident.criticalCount })} · {formatAgo(incident.createdAt, now, locale)}
          </span>
        </div>
        <p>{t('live.incident.hint')}</p>
        <div className="ef-incident__state">
          {caseOpen && (
            <span className="ef-badge">
              {t('live.incident.case', { id: incidentCase.incident.id })}
              {incidentCase.incident.openedBy ? ` · ${incidentCase.incident.openedBy}` : ''}
            </span>
          )}
          {containment.enabled && (
            <span className="ef-badge ef-badge--high">
              {t('live.incident.containmentOn')}
              {containment.updatedBy ? ` · ${containment.updatedBy}` : ''}
            </span>
          )}
          {suspects.map((session) => (
            <button key={session.id} type="button" className="ef-btn ef-btn--sm" onClick={() => onOpenSession(session.id)}>
              {t('live.incident.suspect', { id: session.id, score: session.score })}
              {session.status !== 'active' ? ` · ${t('live.incident.ended')}` : ''}
            </button>
          ))}
        </div>
      </div>
      <div className="ef-incident__actions">
        <button type="button" className="ef-btn ef-btn--primary ef-btn--sm" onClick={onInvestigate}>{t('live.incident.investigate')}</button>
        {canOperate && activeSuspectCount > 0 && (
          <button type="button" className="ef-btn ef-btn--danger ef-btn--sm" onClick={onTerminateSuspects}>
            {t('live.incident.terminate', { count: activeSuspectCount })}
          </button>
        )}
        {!caseOpen && (
          <button type="button" className="ef-btn ef-btn--sm" onClick={onOpenCase} disabled={busy.case}>{t('live.incident.openCase')}</button>
        )}
        {canManage && caseOpen && (
          <button type="button" className="ef-btn ef-btn--sm" onClick={onCloseCase} disabled={busy.case}>{t('live.incident.closeCase')}</button>
        )}
        {canManage && (
          <button type="button" className="ef-btn ef-btn--sm" onClick={() => onContainment(!containment.enabled)} disabled={busy.containment}>
            {containment.enabled ? t('live.incident.containmentStop') : t('live.incident.containmentStart')}
          </button>
        )}
        {!strictProfile && (
          <button type="button" className="ef-btn ef-btn--sm" onClick={onStrict}>{t('live.incident.strict')}</button>
        )}
        <button type="button" className="ef-btn ef-btn--link ef-btn--sm" onClick={onDismiss}>{t('live.incident.dismiss')}</button>
      </div>
    </section>
  );
}
