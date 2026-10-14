import React, { useMemo, useState } from 'react';
import { useI18n } from '../../i18n.jsx';
import { formatWhen, initialsOf } from '../../ui/sessions.js';
import MfaCard from './MfaCard.jsx';

const MAP_VIEW_KEY = 'endoriumfort_map_view';

const readMapView = () => {
  try {
    return localStorage.getItem(MAP_VIEW_KEY) === 'liste' ? 'liste' : 'carte';
  } catch (_) {
    return 'carte';
  }
};

function Seg({ label, value, options, onChange }) {
  return (
    <div className="ef-seg" role="group" aria-label={label}>
      {options.map(([id, text]) => (
        <button key={id} type="button" className={value === id ? 'is-on' : ''} aria-pressed={value === id} onClick={() => onChange(id)}>{text}</button>
      ))}
    </div>
  );
}

// The signed-in person's own settings: second factors, preferences, password.
export default function AccountPage({
  user,
  roleName,
  auditItems,
  mfa,
  password,
  darkMode,
  onSetDarkMode,
  alertProfile,
  onSetAlertProfile,
  showAlerts
}) {
  const { t, locale, setLocale } = useI18n();
  const [mapView, setMapView] = useState(readMapView);

  // Current sign-in, when the journal is visible to this person.
  const lastLogin = useMemo(() => {
    const item = (auditItems || []).find((e) => e.actor === user && /^auth\.login\..*success/.test(e.type));
    if (!item) return null;
    let ip = '';
    try { ip = JSON.parse(item.payloadRaw || '{}').ip || ''; } catch (_) { /* no detail */ }
    return { at: item.createdAt, ip };
  }, [auditItems, user]);

  const chooseMapView = (value) => {
    setMapView(value);
    try { localStorage.setItem(MAP_VIEW_KEY, value); } catch (_) { /* preference not kept */ }
  };

  const mismatch = password.next && password.confirm && password.next !== password.confirm;

  return (
    <div className="ef ef-adminpage ef-account">
      <div className="ef-reqpage__head">
        <span className="ef-avatar ef-avatar--lg ef-avatar--priv">{initialsOf(user)}</span>
        <div>
          <h1>{t('account.title')}</h1>
          <p>
            <span className="ef-mono">{user}</span> · {roleName}
            {lastLogin && <> · {t('account.signedIn', { when: formatWhen(lastLogin.at, locale) })}{lastLogin.ip && <> {t('account.from', { ip: lastLogin.ip })}</>}</>}
          </p>
        </div>
      </div>

      <MfaCard {...mfa} />

      <div className="ef-account__grid">
        <section className="ef-card">
          <div className="ef-enroll__head"><h2 className="ef-sectitle">{t('account.preferences')}</h2></div>
          <div className="ef-zform ef-account__prefs">
            <span className="ef-zform__label">{t('account.mapView')}</span>
            <Seg label={t('account.mapView')} value={mapView} onChange={chooseMapView} options={[['carte', t('map.viewMap')], ['liste', t('map.viewList')]]} />
            <span className="ef-zform__label">{t('account.theme')}</span>
            <Seg label={t('account.theme')} value={darkMode ? 'dark' : 'light'} onChange={(v) => onSetDarkMode(v === 'dark')} options={[['light', t('account.light')], ['dark', t('account.dark')]]} />
            <label className="ef-zform__label" htmlFor="acc-lang">{t('common.language')}</label>
            <select id="acc-lang" className="ef-input" style={{ width: 'auto' }} value={locale} onChange={(e) => setLocale(e.target.value)}>
              <option value="fr">Français</option>
              <option value="en">English</option>
            </select>
            {showAlerts && (
              <>
                <span className="ef-zform__label">{t('account.alerts')}</span>
                <div>
                  <Seg label={t('account.alerts')} value={alertProfile} onChange={onSetAlertProfile} options={[['strict', t('account.alertsFew')], ['normal', t('account.alertsNormal')], ['permissive', t('account.alertsMany')]]} />
                  <span className="ef-hint" style={{ display: 'block', marginTop: 6 }}>{t('account.alertsHint')}</span>
                </div>
              </>
            )}
          </div>
          <p className="ef-hint" style={{ margin: 0, padding: '0 16px 14px' }}>{t('account.prefsHint')}</p>
        </section>

        <section className="ef-card">
          <div className="ef-enroll__head"><h2 className="ef-sectitle">{t('account.password')}</h2></div>
          <form className="ef-zform ef-account__pw" onSubmit={password.onSubmit}>
            <label className="ef-zform__label" htmlFor="pw-cur">{t('auth.currentPassword')}</label>
            <input id="pw-cur" className="ef-input" type="password" autoComplete="current-password" value={password.current} onChange={(e) => password.setCurrent(e.target.value)} required />
            <label className="ef-zform__label" htmlFor="pw-new">{t('auth.newPassword')}</label>
            <input id="pw-new" className="ef-input" type="password" autoComplete="new-password" value={password.next} onChange={(e) => password.setNext(e.target.value)} required />
            <label className="ef-zform__label" htmlFor="pw-conf">{t('auth.confirmNewPassword')}</label>
            <input id="pw-conf" className="ef-input" type="password" autoComplete="new-password" value={password.confirm} onChange={(e) => password.setConfirm(e.target.value)} required />
            <span />
            <span className="ef-account__pwfoot">
              {mismatch && <span className="ef-small" style={{ color: 'var(--ef-danger)' }}>{t('account.mismatch')}</span>}
              {password.error && <span className="ef-small" style={{ color: 'var(--ef-danger)' }}>{password.error}</span>}
              {password.success && <span className="ef-small" style={{ color: 'var(--ef-ok)' }}>{password.success}</span>}
              <button type="submit" className="ef-btn ef-btn--primary" disabled={mismatch || !password.current || !password.next}>{t('account.update')}</button>
            </span>
          </form>
          <p className="ef-hint" style={{ margin: 0, padding: '0 16px 14px' }}>{t('account.passwordHint')}</p>
        </section>
      </div>
    </div>
  );
}
