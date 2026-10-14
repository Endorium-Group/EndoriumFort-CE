import React from 'react';
import { useI18n } from '../../i18n.jsx';
import Dialog from '../../ui/Dialog.jsx';
import CopyButton from '../../ui/CopyButton.jsx';

// Mandatory first sign-in steps, as the server reports them: replace the initial
// password, then (when required for this account) add a second factor.
export default function FirstLoginDialog({ user, passwordStep, mfaStep, password, mfa, onLogout }) {
  const { t } = useI18n();
  const steps = [
    passwordStep !== null && { id: 'password', label: t('dlg.first.stepPassword'), done: !passwordStep },
    mfaStep && { id: 'mfa', label: t('dlg.first.stepMfa'), done: false }
  ].filter(Boolean);
  const current = passwordStep ? 'password' : 'mfa';
  const digits = (value) => value.replace(/\D/g, '').slice(0, 6);

  return (
    <Dialog
      kicker={t('dlg.first.kicker', { user })}
      title={t('dlg.first.title')}
      width={500}
      footer={
        <>
          <button type="button" className="ef-btn ef-btn--link" onClick={onLogout}>{t('dlg.first.logout')}</button>
          <span className="ef-dlg__spacer" />
          {current === 'password' && (
            <button type="submit" form="ef-first-pw" className="ef-btn ef-btn--primary">{t('dlg.first.savePassword')}</button>
          )}
        </>
      }
    >
      <p className="ef-hint" style={{ margin: '0 0 12px' }}>{mfaStep ? t('dlg.first.introMfa') : t('dlg.first.intro')}</p>

      {steps.length > 1 && (
        <ol className="ef-dlg__steps">
          {steps.map((step, index) => (
            <li key={step.id} className={step.done ? 'is-done' : step.id === current ? 'is-current' : undefined}>
              <span className="ef-dlg__num">{step.done ? '✓' : index + 1}</span>
              <span>{step.label}</span>
              <span className="ef-muted">{step.done ? t('dlg.first.done') : step.id === current ? t('dlg.first.now') : t('dlg.first.later')}</span>
            </li>
          ))}
        </ol>
      )}

      {current === 'password' ? (
        <form id="ef-first-pw" className="ef-dlg__fields" onSubmit={password.onSubmit}>
          {password.error && <div className="ef-alert ef-alert--danger">{password.error}</div>}
          <div className="ef-rfield">
            <label htmlFor="first-current">{t('dlg.first.current')}</label>
            <input id="first-current" className="ef-input" type="password" autoComplete="current-password" required value={password.current} onChange={(e) => password.setCurrent(e.target.value)} />
            <span className="ef-hint">{t('dlg.first.currentHint')}</span>
          </div>
          <div className="ef-rfield">
            <label htmlFor="first-next">{t('dlg.first.newPassword')}</label>
            <input id="first-next" className="ef-input" type="password" autoComplete="new-password" required value={password.next} onChange={(e) => password.setNext(e.target.value)} />
            <span className="ef-hint">{t('dlg.first.rule')}</span>
          </div>
          <div className="ef-rfield">
            <label htmlFor="first-confirm">{t('dlg.first.confirm')}</label>
            <input id="first-confirm" className="ef-input" type="password" autoComplete="new-password" required value={password.confirm} onChange={(e) => password.setConfirm(e.target.value)} />
          </div>
        </form>
      ) : (
        <div>
          {mfa.error && <div className="ef-alert ef-alert--danger ef-dlg__error">{mfa.error}</div>}
          {!mfa.setupData ? (
            <>
              <div className="ef-dlg__choices">
                <button type="button" className="ef-btn ef-dlg__choice" onClick={mfa.onSetupApp}>
                  <strong>{t('dlg.first.appTitle')}</strong>
                  <span>{t('dlg.first.appText')}</span>
                </button>
                <button type="button" className="ef-btn ef-dlg__choice" onClick={mfa.onAddKey} disabled={mfa.keyBusy || !mfa.keySupported}>
                  <strong>{mfa.keyBusy ? t('dlg.first.keyBusy') : t('dlg.first.keyTitle')}</strong>
                  <span>{mfa.keySupported ? t('dlg.first.keyText') : t('dlg.first.keyUnsupported')}</span>
                </button>
              </div>
            </>
          ) : (
            <div className="ef-mfa__setup">
              <ol className="ef-mfa__steps">
                <li>
                  <span>{t('mfa.step1')}</span>
                  {mfa.qrDataUrl && <img className="ef-mfa__qr" src={mfa.qrDataUrl} alt={t('mfa.qrAlt')} width={168} height={168} />}
                  <details className="ef-mfa__manual">
                    <summary>{t('mfa.manual')}</summary>
                    <code className="ef-mono">{mfa.setupData.secret}</code>
                    <span className="ef-mfa__row">
                      <CopyButton text={mfa.setupData.secret} label={t('mfa.copySecret')} />
                      <CopyButton text={mfa.setupData.otpauthUri} label={t('mfa.copyUri')} />
                    </span>
                  </details>
                </li>
                <li>
                  <span>{t('mfa.step2')}</span>
                  <form className="ef-mfa__row" onSubmit={(e) => { e.preventDefault(); mfa.onVerify(); }}>
                    <input
                      className="ef-input ef-mono ef-mfa__code"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      autoFocus
                      value={mfa.code}
                      onChange={(e) => mfa.setCode(digits(e.target.value))}
                      placeholder="123456"
                      aria-label={t('mfa.code')}
                    />
                    <button type="submit" className="ef-btn ef-btn--primary" disabled={mfa.code.length !== 6}>{t('mfa.verify')}</button>
                    <button type="button" className="ef-btn" onClick={mfa.onCancel}>{t('common.cancel')}</button>
                  </form>
                </li>
              </ol>
            </div>
          )}
        </div>
      )}
    </Dialog>
  );
}
