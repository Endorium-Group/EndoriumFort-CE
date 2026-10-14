import React from 'react';
import { useI18n } from '../i18n.jsx';
import { formatAgo, useNow } from './sessions.js';

// Same order as the server's classify_security_alert_type (security_center.cc):
// the first match wins, so the more specific patterns come first.
const KINDS = [
  ['security.incident.opened', 'incidentOpened'],
  ['security.incident.closed', 'incidentClosed'],
  ['security.containment.enabled', 'containmentOn'],
  ['auth.login.failure', 'authAnomaly'],
  ['auth.login.rate_limited', 'authAnomaly'],
  ['auth.rate_limit', 'authAnomaly'],
  ['behavior.anomaly.auth_failure_burst', 'bruteForce'],
  ['behavior.anomaly.stale_session', 'staleSession'],
  ['behavior.anomaly', 'anomaly'],
  ['access.denied.time_window', 'outsideHours'],
  ['session.create.unjustified', 'unjustified'],
  ['security.alerts.throttled', 'grouped']
];

export const alertKind = (eventType) => {
  const type = String(eventType || '').toLowerCase();
  if (type.includes('session.dna') && type.includes('mismatch')) return 'dnaMismatch';
  const hit = KINDS.find(([pattern]) => type.includes(pattern));
  return hit ? hit[1] : '';
};

// Title and explanation in the interface language; the server's English text is
// only a fallback for alert types this list does not know yet.
export const alertText = (t, alert) => {
  const kind = alertKind(alert.eventType);
  if (!kind) return { title: alert.title, hint: alert.hint };
  return {
    title: t(`live.kinds.${kind}.title`, { count: alert.count || 0 }),
    hint: t(`live.kinds.${kind}.hint`)
  };
};

const SEVERITY_CLASS = { critical: 'is-critical', warning: 'is-warning', ok: 'is-ok' };

// Security signals pushed by the server, stacked in the bottom-right corner.
export default function LiveAlerts({ alerts, onDismiss, onOpenJournal }) {
  const { t, locale } = useI18n();
  const now = useNow(30000);
  if (!alerts.length) return null;
  return (
    <div className="ef ef-toasts" role="status" aria-live="polite">
      {alerts.map((alert) => {
        const text = alertText(t, alert);
        const severity = String(alert.severity || 'warning').toLowerCase();
        return (
          <article key={alert.key} className={`ef-toast ${SEVERITY_CLASS[severity] || 'is-warning'}`}>
            <div className="ef-toast__head">
              <strong>{text.title}</strong>
              <button type="button" className="ef-btn ef-btn--sm ef-toast__close" onClick={() => onDismiss(alert.key)} aria-label={t('common.close')}>
                <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" /></svg>
              </button>
            </div>
            {text.hint && <p>{text.hint}</p>}
            <div className="ef-toast__foot">
              <span className="ef-muted">
                {t(`live.severity.${severity}`)} · {formatAgo(alert.createdAt, now, locale)}
              </span>
              {alert.eventType !== 'security.alerts.throttled' && (
                <button type="button" className="ef-btn ef-btn--link" onClick={() => onOpenJournal(alert.sessionId || null)}>
                  {alert.sessionId ? t('live.openSession', { id: alert.sessionId }) : t('live.openJournal')}
                </button>
              )}
            </div>
          </article>
        );
      })}
    </div>
  );
}
