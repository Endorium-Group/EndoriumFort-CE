import React from 'react';
import { useI18n } from '../../i18n.jsx';
import ConfirmButton from '../../ui/ConfirmButton.jsx';
import CopyButton from '../../ui/CopyButton.jsx';
import { formatAgo, useNow } from '../../ui/sessions.js';

// The signed-in person's own second factors: authenticator app (TOTP), security
// keys (passkeys) and the preferred method at sign-in.
export default function MfaCard({
  isAdmin,
  totpEnabled,
  webauthnEnabled,
  preferredMfaMethod,
  onUpdateMfaPreference,
  totpSetupData,
  totpQrDataUrl,
  totpSetupCode,
  setTotpSetupCode,
  onSetup2FA,
  onVerify2FA,
  onCancelSetup,
  totpError,
  totpDisableCode,
  setTotpDisableCode,
  onDisable2FA,
  webauthnSupported,
  webauthnBusy,
  webauthnLabel,
  setWebauthnLabel,
  webauthnCredentials,
  onRegisterPasskey,
  onDeletePasskey
}) {
  const { t, locale } = useI18n();
  const now = useNow(60000);
  const keys = webauthnCredentials || [];
  const anyFactor = totpEnabled || webauthnEnabled;
  // An administrator must always keep at least one factor.
  const lastKeyLocked = isAdmin && !totpEnabled && keys.length <= 1;
  const totpLocked = isAdmin && !webauthnEnabled;
  const summary = [totpEnabled && t('mfa.app'), keys.length > 0 && t('mfa.keyCount', { count: keys.length })].filter(Boolean).join(' + ');
  const digits = (value) => value.replace(/\D/g, '').slice(0, 6);

  return (
    <section className="ef-card ef-mfa">
      <div className="ef-enroll__head">
        <h2 className="ef-sectitle">{t('mfa.title')}</h2>
        <span className="ef-muted">{t('mfa.yourAccount')}</span>
        <span style={{ flex: 1 }} />
        {anyFactor
          ? <span className="ef-badge ef-badge--low">{t('mfa.on', { what: summary })}</span>
          : <span className={isAdmin ? 'ef-badge ef-badge--critical' : 'ef-badge'}>{t('mfa.off')}</span>}
      </div>
      {totpError && <div className="ef-alert ef-alert--danger" style={{ margin: '12px 16px 0' }}>{totpError}</div>}

      <div className="ef-mfa__grid">
        <div className="ef-mfa__block">
          <h3>{t('mfa.appTitle')}</h3>
          <p className="ef-hint">{t('mfa.appText')}</p>
          {totpEnabled && !totpSetupData && (
            <>
              <p className="ef-mfa__state"><span className="ef-dot" style={{ background: 'var(--ef-ok)' }} />{t('mfa.appOn')}</p>
              <div className="ef-mfa__row">
                <input
                  className="ef-input ef-mono ef-mfa__code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={totpDisableCode}
                  onChange={(e) => setTotpDisableCode(digits(e.target.value))}
                  placeholder="123456"
                  aria-label={t('mfa.currentCode')}
                />
                <ConfirmButton
                  confirmLabel={t('mfa.confirmDisable')}
                  disabled={totpLocked || totpDisableCode.length !== 6}
                  onConfirm={onDisable2FA}
                >
                  {t('mfa.disableApp')}
                </ConfirmButton>
              </div>
              <span className="ef-hint">{totpLocked ? t('mfa.addKeyFirst') : t('mfa.disableHint')}</span>
            </>
          )}
          {!totpEnabled && !totpSetupData && (
            <button type="button" className="ef-btn ef-btn--primary" onClick={onSetup2FA}>{t('mfa.setupApp')}</button>
          )}
          {totpSetupData && (
            <div className="ef-mfa__setup">
              <ol className="ef-mfa__steps">
                <li>
                  <span>{t('mfa.step1')}</span>
                  {totpQrDataUrl && <img className="ef-mfa__qr" src={totpQrDataUrl} alt={t('mfa.qrAlt')} width={168} height={168} />}
                  <details className="ef-mfa__manual">
                    <summary>{t('mfa.manual')}</summary>
                    <code className="ef-mono">{totpSetupData.secret}</code>
                    <span className="ef-mfa__row">
                      <CopyButton text={totpSetupData.secret} label={t('mfa.copySecret')} />
                      <CopyButton text={totpSetupData.otpauthUri} label={t('mfa.copyUri')} />
                    </span>
                  </details>
                </li>
                <li>
                  <span>{t('mfa.step2')}</span>
                  <form
                    className="ef-mfa__row"
                    onSubmit={(e) => { e.preventDefault(); onVerify2FA(); }}
                  >
                    <input
                      className="ef-input ef-mono ef-mfa__code"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      autoFocus
                      value={totpSetupCode}
                      onChange={(e) => setTotpSetupCode(digits(e.target.value))}
                      placeholder="123456"
                      aria-label={t('mfa.code')}
                    />
                    <button type="submit" className="ef-btn ef-btn--primary" disabled={totpSetupCode.length !== 6}>{t('mfa.verify')}</button>
                    <button type="button" className="ef-btn" onClick={onCancelSetup}>{t('common.cancel')}</button>
                  </form>
                </li>
              </ol>
            </div>
          )}
        </div>

        <div className="ef-mfa__block">
          <h3>{t('mfa.keysTitle')}</h3>
          <p className="ef-hint">{t('mfa.keysText')}</p>
          {keys.length > 0 && (
            <ul className="ef-mfa__keys">
              {keys.map((key) => (
                <li key={key.id}>
                  <div>
                    <strong>{key.label || t('mfa.key')}</strong>
                    <span className="ef-muted ef-small">
                      {t('mfa.added', { when: formatAgo(key.createdAt, now, locale) })}
                      {key.lastUsedAt ? ` · ${t('mfa.used', { when: formatAgo(key.lastUsedAt, now, locale) })}` : ''}
                    </span>
                  </div>
                  <ConfirmButton
                    className="ef-btn ef-btn--sm ef-btn--danger"
                    confirmLabel={t('mfa.confirmRemove')}
                    disabled={webauthnBusy || lastKeyLocked}
                    onConfirm={() => onDeletePasskey(key.id)}
                  >
                    {t('mfa.remove')}
                  </ConfirmButton>
                </li>
              ))}
            </ul>
          )}
          {lastKeyLocked && keys.length > 0 && <span className="ef-hint">{t('mfa.keepOne')}</span>}
          {webauthnSupported ? (
            <form className="ef-mfa__row" style={{ marginTop: 10 }} onSubmit={(e) => { e.preventDefault(); onRegisterPasskey(webauthnLabel); }}>
              <input
                className="ef-input"
                value={webauthnLabel}
                onChange={(e) => setWebauthnLabel(e.target.value)}
                placeholder={t('mfa.keyNamePlaceholder')}
                aria-label={t('mfa.keyName')}
              />
              <button type="submit" className="ef-btn" disabled={webauthnBusy}>{webauthnBusy ? t('mfa.waitingKey') : t('mfa.addKey')}</button>
            </form>
          ) : <p className="ef-zwarn">{t('mfa.unsupported')}</p>}
        </div>

        <div className="ef-mfa__block">
          <h3>{t('mfa.prefTitle')}</h3>
          <p className="ef-hint">{t('mfa.prefText')}</p>
          <div className="ef-seg" role="group" aria-label={t('mfa.prefTitle')}>
            {[
              ['any', t('mfa.prefAny'), true],
              ['totp', t('mfa.prefApp'), totpEnabled],
              ['webauthn', t('mfa.prefKey'), webauthnEnabled]
            ].map(([value, label, allowed]) => (
              <button
                key={value}
                type="button"
                className={preferredMfaMethod === value ? 'is-on' : ''}
                aria-pressed={preferredMfaMethod === value}
                disabled={!allowed}
                onClick={() => onUpdateMfaPreference(value)}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
