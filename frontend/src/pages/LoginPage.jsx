import React from 'react';
import { useI18n } from '../i18n.jsx';
import { brandingImageUrl } from '../ui/branding.js';

function KeyIcon() {
  return (
    <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="8" cy="15" r="4" />
      <path d="M11 12l9-9M17 6l3 3" />
    </svg>
  );
}

export default function LoginPage({
  auth,
  onAuthChange,
  onLogin,
  onStartSsoLogin,
  onLoginWithPasskey,
  onCancelMfa,
  twoFARequired,
  availableMfaMethods,
  totpCode,
  onTotpChange,
  webauthnBusy,
  webauthnLoginOptions,
  authError,
  darkMode,
  onToggleDarkMode,
  branding
}) {
  const { t, locale, setLocale } = useI18n();
  const hasTotp = availableMfaMethods.includes('totp');
  const hasPasskey = availableMfaMethods.includes('webauthn');

  return (
    <div className={`ef ef-login${branding?.hasBackground ? ' ef-login--image' : ''}`}>
      {branding?.hasBackground && (
        <>
          <div
            className="ef-login__bg"
            aria-hidden="true"
            style={{
              backgroundImage: `url("${brandingImageUrl('background', branding)}")`,
              filter: branding.blur ? `blur(${branding.blur}px)` : undefined
            }}
          />
          {branding.dim && <div className="ef-login__dim" aria-hidden="true" />}
        </>
      )}
      <div className="ef-login__brand">
        {branding?.hasLogo
          ? <img src={brandingImageUrl('logo', branding)} alt="" className="ef-login__logo" />
          : <img src="/assets/logo-mark.png" alt="" width="64" height="64" className="ef-logo" />}
        EndoriumFort
      </div>

      <form className="ef-card ef-login__card" onSubmit={onLogin}>
        {!twoFARequired ? (
          <>
            <div>
              <h1 className="ef-login__title">{t('auth.signIn')}</h1>
              <p className="ef-login__sub">{window.location.host}</p>
            </div>
            <label className="ef-field">
              {t('auth.user')}
              <input
                className="ef-input ef-input--lg"
                name="user"
                value={auth.user}
                onChange={onAuthChange}
                autoComplete="username"
                autoFocus
              />
            </label>
            <label className="ef-field">
              {t('auth.password')}
              <input
                className="ef-input ef-input--lg"
                name="password"
                type="password"
                value={auth.password}
                onChange={onAuthChange}
                autoComplete="current-password"
              />
            </label>
            {authError && <div className="ef-alert ef-alert--danger" role="alert">{authError}</div>}
            <button type="submit" className="ef-btn ef-btn--primary ef-btn--lg ef-btn--block">
              {t('auth.signIn')}
            </button>
            {onStartSsoLogin && (
              <>
                <div className="ef-sep">{t('auth.or')}</div>
                <button type="button" className="ef-btn ef-btn--lg ef-btn--block" onClick={onStartSsoLogin}>
                  {t('auth.ssoSignIn')}
                </button>
              </>
            )}
          </>
        ) : (
          <>
            <div>
              <div className="ef-login__step">{t('auth.stepTwoOfTwo')}</div>
              <h1 className="ef-login__title">{t('auth.verification')}</h1>
              <p className="ef-login__sub">
                {hasTotp ? t('auth.enterTotpHint') : t('auth.usePasskeyHint')}
              </p>
            </div>
            {hasTotp && (
              <input
                className="ef-input ef-login__otp"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                value={totpCode}
                onChange={(event) => onTotpChange(event.target.value.replace(/\D/g, ''))}
                aria-label={t('auth.authenticatorCode6Digits')}
                placeholder="••••••"
                autoFocus
              />
            )}
            {authError && <div className="ef-alert ef-alert--danger" role="alert">{authError}</div>}
            {hasTotp && (
              <button type="submit" className="ef-btn ef-btn--primary ef-btn--lg ef-btn--block">
                {t('auth.verifyAndSignIn')}
              </button>
            )}
            {hasPasskey && (
              <button
                type="button"
                className={hasTotp ? 'ef-btn ef-btn--lg ef-btn--block' : 'ef-btn ef-btn--primary ef-btn--lg ef-btn--block'}
                onClick={onLoginWithPasskey}
                disabled={webauthnBusy || !webauthnLoginOptions}
              >
                <KeyIcon />
                {webauthnBusy ? t('auth.waitingForSecurityKey') : t('auth.usePasskey')}
              </button>
            )}
            <button type="button" className="ef-btn ef-btn--link" onClick={onCancelMfa}>
              {t('common.back')}
            </button>
          </>
        )}
      </form>

      {branding?.loginMessage && (
        <p className="ef-login__notice" role="note">{branding.loginMessage}</p>
      )}

      <div className="ef-login__foot">
        <select aria-label={t('common.language')} value={locale} onChange={(event) => setLocale(event.target.value)}>
          <option value="fr">{t('common.french')}</option>
          <option value="en">{t('common.english')}</option>
        </select>
        <button type="button" className="ef-btn ef-btn--link" onClick={onToggleDarkMode} style={{ fontSize: 12 }}>
          {darkMode ? t('auth.lightMode') : t('auth.darkMode')}
        </button>
      </div>
    </div>
  );
}
