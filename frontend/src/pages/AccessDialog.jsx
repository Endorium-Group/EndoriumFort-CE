import React from 'react';
import { useI18n } from '../i18n.jsx';
import Dialog from '../ui/Dialog.jsx';

const RISK_BADGE = { critical: 'ef-badge--critical', high: 'ef-badge--high', low: 'ef-badge--low' };

// Asked before opening a session (or sending an access request) when the server
// needs a reason, a ticket or a purpose. Only the fields it asks for are mandatory.
export default function AccessDialog({
  resource,
  mode,
  containment,
  values,
  setValue,
  required,
  preview,
  playbook,
  error,
  busy,
  approvedRequestId,
  onSubmit,
  onClose
}) {
  const { t, locale } = useI18n();
  const isRequest = mode === 'request';
  const risk = String(resource.riskLevel || 'low').toLowerCase();
  const protocol = String(resource.protocol || '').toUpperCase();

  const field = (id, label, isRequired, input, hint) => (
    <div className="ef-rfield">
      <label htmlFor={`access-${id}`}>
        {label}
        {isRequired ? <span className="ef-dlg__req">{t('dlg.access.required')}</span> : <span className="ef-dlg__opt">{t('dlg.access.optional')}</span>}
      </label>
      {input}
      {hint && <span className="ef-hint">{hint}</span>}
    </div>
  );

  const previewNeeds = preview?.data
    ? [
        preview.data.justificationRequired && t('dlg.access.needReason'),
        preview.data.ticketRequired && t('dlg.access.needTicket'),
        preview.data.purposeRequired && t('dlg.access.needPurpose'),
        preview.data.approvalRequired && t('dlg.access.needApproval'),
        preview.data.mfaRequirement && preview.data.mfaRequirement !== 'any' && t('dlg.access.needMfa', { value: preview.data.mfaRequirement }),
        preview.data.routingConstraint === 'relay' && t('dlg.access.needRelay'),
        preview.data.maxDurationSeconds > 0 && t('dlg.access.maxDuration', { minutes: Math.round(preview.data.maxDurationSeconds / 60) })
      ].filter(Boolean)
    : [];
  const effectiveRisk = String(preview?.data?.effectiveRiskLevel || '').toLowerCase();

  return (
    <Dialog
      kicker={t(isRequest ? 'dlg.access.kickerRequest' : 'dlg.access.kicker', { protocol })}
      title={t(isRequest ? 'dlg.access.titleRequest' : 'dlg.access.title', { name: resource.name })}
      subtitle={
        <>
          <span className="ef-mono">{resource.target}{resource.port ? `:${resource.port}` : ''}</span>
          <span className={`ef-badge ${RISK_BADGE[risk] || ''}`.trim()}>{t('dlg.access.risk', { level: t(`map.risk.${risk}`) })}</span>
        </>
      }
      onClose={onClose}
      width={520}
      footer={
        <>
          <span className="ef-dlg__spacer" />
          <button type="button" className="ef-btn" onClick={onClose}>{t('common.cancel')}</button>
          <button type="submit" form="ef-access-form" className="ef-btn ef-btn--primary" disabled={busy}>
            {isRequest ? t('dlg.access.sendRequest') : t('dlg.access.connect')}
          </button>
        </>
      }
    >
      {error && <div className="ef-alert ef-alert--danger ef-dlg__error">{error}</div>}
      {containment?.enabled && !isRequest && (
        <div className="ef-alert ef-alert--warn ef-dlg__error">
          {t('dlg.access.containment')}{containment.reason ? ` ${t('dlg.access.containmentWhy', { reason: containment.reason })}` : ''}
        </div>
      )}
      {approvedRequestId && !isRequest && (
        <div className="ef-alert ef-dlg__error">{t('dlg.access.approved', { id: approvedRequestId })}</div>
      )}
      <p className="ef-hint" style={{ margin: '0 0 10px' }}>
        {isRequest ? t('dlg.access.introRequest') : t('dlg.access.intro')}
      </p>

      {preview && (
        <div className="ef-dlg__section">
          <strong>{t('dlg.access.policyTitle')}</strong>
          {preview.loading && !preview.data && <p>{t('dlg.access.policyLoading')}</p>}
          {preview.error && <p style={{ color: 'var(--ef-danger)' }}>{preview.error}</p>}
          {preview.data && (
            <>
              <p>
                {t('dlg.access.score', { score: preview.data.score ?? '—', level: effectiveRisk ? t(`map.risk.${effectiveRisk}`) : '—' })}
                {previewNeeds.length > 0 ? ` · ${previewNeeds.join(' · ')}` : ` · ${t('dlg.access.nothingMore')}`}
              </p>
              {Array.isArray(preview.data.factors) && preview.data.factors.length > 0 && (
                <details>
                  <summary>{t('dlg.access.factors')}</summary>
                  <span className="ef-mono" style={{ fontSize: 11.5 }}>{preview.data.factors.join(', ')}</span>
                </details>
              )}
            </>
          )}
        </div>
      )}

      <form id="ef-access-form" className="ef-dlg__fields" onSubmit={onSubmit}>
        {field('reason', t('dlg.access.reason'), required.reason, (
          <input id="access-reason" className="ef-input" autoFocus value={values.reason} onChange={(e) => setValue('reason', e.target.value)} required={required.reason} placeholder={t('dlg.access.reasonPlaceholder')} />
        ))}
        {field('ticket', t('dlg.access.ticket'), required.ticket, (
          <input id="access-ticket" className="ef-input ef-mono" value={values.ticket} onChange={(e) => setValue('ticket', e.target.value)} required={required.ticket} placeholder="INC-1234" />
        ))}
        {!isRequest && field('purpose', t('dlg.access.purpose'), required.purpose, (
          <input id="access-purpose" className="ef-input" value={values.purpose} onChange={(e) => setValue('purpose', e.target.value)} required={required.purpose} placeholder={t('dlg.access.purposePlaceholder')} />
        ), required.purpose ? t('dlg.access.purposeHint') : '')}
        {!isRequest && (values.purpose || required.purpose) && field('evidence', t('dlg.access.evidence'), false, (
          <input id="access-evidence" className="ef-input" value={values.evidence} onChange={(e) => setValue('evidence', e.target.value)} placeholder={t('dlg.access.evidencePlaceholder')} />
        ))}
      </form>

      <div className="ef-dlg__memo">
        {playbook.current ? (
          <>
            <span>{t('dlg.access.memoSaved', { when: new Date(playbook.current.updatedAt || Date.now()).toLocaleString(locale === 'fr' ? 'fr-FR' : 'en-GB', { dateStyle: 'short', timeStyle: 'short' }) })}</span>
            <button type="button" className="ef-btn ef-btn--link" onClick={playbook.onApply}>{t('dlg.access.memoApply')}</button>
            <button type="button" className="ef-btn ef-btn--link" onClick={playbook.onSave}>{t('dlg.access.memoUpdate')}</button>
            <button type="button" className="ef-btn ef-btn--link" onClick={playbook.onDelete}>{t('dlg.access.memoForget')}</button>
          </>
        ) : (
          <button type="button" className="ef-btn ef-btn--link" onClick={playbook.onSave}>{t('dlg.access.memoSave')}</button>
        )}
      </div>
    </Dialog>
  );
}
