// Journal page strip: is the audit log file still the one the bastion wrote?
// GET /api/audit/verify recomputes the hash chain over the whole file (not just
// the 50 events shown). Lines from before the chain existed are counted apart.
import React, { useEffect, useState } from 'react';
import { useI18n } from '../i18n.jsx';
import { verifyAuditChain } from '../api.js';

export default function AuditIntegrity({ refreshKey }) {
  const { t, locale } = useI18n();
  const [state, setState] = useState({ status: 'checking' });

  const run = async () => {
    setState((current) => ({ ...current, status: 'checking' }));
    try {
      const result = await verifyAuditChain();
      setState({ status: result.intact ? 'intact' : 'broken', result, at: new Date() });
    } catch (err) {
      setState({ status: 'error', message: err.message });
    }
  };
  useEffect(() => { run(); }, [refreshKey]);

  const { status, result, at } = state;
  const lines = Number(result?.lines) || 0;
  const legacy = Number(result?.legacyLines) || 0;
  const checked = Math.max(0, lines - legacy);
  const time = at ? at.toLocaleTimeString(locale === 'fr' ? 'fr-FR' : 'en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '';
  const seal = result?.keyed ? t('journal.integrity.keyed') : t('journal.integrity.unkeyed');

  return (
    <div className={`ef-integrity is-${status}`} role={status === 'broken' ? 'alert' : 'status'}>
      <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true">
        {status === 'broken'
          ? <><path d="M12 3l9 16H3z" /><path d="M12 10v4M12 17v.5" /></>
          : <><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z" />{status === 'intact' && <path d="M9 12l2 2 4-4" />}</>}
      </svg>
      <div className="ef-integrity__text">
        {status === 'checking' && <strong>{t('journal.integrity.checking')}</strong>}
        {status === 'error' && (
          <>
            <strong>{t('journal.integrity.error')}</strong>
            <span>{state.message}</span>
          </>
        )}
        {status === 'intact' && (
          <>
            <strong>{lines ? t('journal.integrity.intact') : t('journal.integrity.emptyLog')}</strong>
            {lines > 0 && (
              <span>
                {t('journal.integrity.checked', { count: checked })}
                {legacy > 0 && ` · ${t('journal.integrity.legacy', { count: legacy })}`}
                {` · ${seal}`}
              </span>
            )}
          </>
        )}
        {status === 'broken' && (
          <>
            <strong>{t('journal.integrity.broken', { line: result.firstBrokenLine })}</strong>
            <span>{t('journal.integrity.brokenHelp')}</span>
          </>
        )}
      </div>
      {time && status !== 'checking' && <span className="ef-integrity__time">{t('journal.integrity.at', { time })}</span>}
      <button type="button" className="ef-btn ef-btn--sm" onClick={run} disabled={status === 'checking'}>
        {t('journal.integrity.verify')}
      </button>
    </div>
  );
}
