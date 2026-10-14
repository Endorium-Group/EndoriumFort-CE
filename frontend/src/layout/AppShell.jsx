import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useI18n } from '../i18n.jsx';
import { formatClock, formatRemaining, initialsOf, privilegeWindow, useNow } from '../ui/sessions.js';

// Top-level sections, in display order. `path` is the canonical URL.
export const SHELL_TABS = [
  { id: 'carte', path: '/carte', labelKey: 'shell.map' },
  { id: 'sessions', path: '/sessions', labelKey: 'shell.sessions' },
  { id: 'demandes', path: '/demandes', labelKey: 'shell.requests' },
  { id: 'journal', path: '/journal', labelKey: 'shell.journal' },
  { id: 'preuves', path: '/preuves', labelKey: 'shell.evidence' },
  { id: 'zones', path: '/zones', labelKey: 'shell.zones' },
  { id: 'admin', path: '/admin', labelKey: 'shell.admin' }
];

export function tabForPath(pathname) {
  const path = pathname === '/' ? '/carte' : pathname;
  return SHELL_TABS.find((tab) => path === tab.path || path.startsWith(`${tab.path}/`)) || null;
}

// Active sessions of the signed-in user that carry a time limit, nearest expiry first.
function usePrivileges(sessions, username) {
  const now = useNow(30000);
  return useMemo(() => {
    return (sessions || [])
      .filter((s) => s.status === 'active' && (s.operator || s.user) === username)
      .map((s) => {
        const span = privilegeWindow(s, now);
        return span ? { session: s, ...span } : null;
      })
      .filter((p) => p && p.remaining > 0)
      .sort((a, b) => a.remaining - b.remaining);
  }, [sessions, username, now]);
}

function UserMenu({ user, roleName, version, darkMode, onToggleDarkMode, onOpenAccount, onLogout }) {
  const { t, locale, setLocale } = useI18n();
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const onDown = (event) => {
      if (ref.current && !ref.current.contains(event.target)) setOpen(false);
    };
    const onKey = (event) => { if (event.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <div className="ef-usermenu" ref={ref}>
      <button
        type="button"
        className="ef-usermenu__trigger"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
      >
        <span className="ef-avatar">{initialsOf(user)}</span>
        <span>{user}</span>
        <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true" style={{ width: 14, height: 14 }}><path d="M6 9l6 6 6-6" /></svg>
      </button>
      {open && (
        <div className="ef-usermenu__panel" role="menu">
          <div className="ef-usermenu__head">
            <span className="ef-avatar ef-avatar--lg">{initialsOf(user)}</span>
            <div>
              <div style={{ fontWeight: 600 }}>{user}</div>
              <div className="ef-muted" style={{ fontSize: 12 }}>{roleName}</div>
            </div>
          </div>
          <button type="button" role="menuitem" className="ef-usermenu__item" onClick={() => { setOpen(false); onOpenAccount(); }}>
            {t('account.title')}
          </button>
          <button type="button" role="menuitem" className="ef-usermenu__item" onClick={onToggleDarkMode}>
            {darkMode ? t('auth.lightMode') : t('auth.darkMode')}
          </button>
          <label className="ef-usermenu__item ef-usermenu__row">
            {t('common.language')}
            <select value={locale} onChange={(event) => setLocale(event.target.value)}>
              <option value="fr">{t('common.french')}</option>
              <option value="en">{t('common.english')}</option>
            </select>
          </label>
          <div className="ef-usermenu__sep" />
          <button type="button" role="menuitem" className="ef-usermenu__item ef-usermenu__item--danger" onClick={onLogout}>
            {t('auth.signOut')}
          </button>
          {version && <div className="ef-usermenu__version">{t('about.bastionVersion', { version })}</div>}
        </div>
      )}
    </div>
  );
}

export default function AppShell({
  route,
  onNavigate,
  visibleTabs,
  counts,
  user,
  roleName,
  sessions,
  onOpenSession,
  onTerminateSession,
  darkMode,
  onToggleDarkMode,
  onOpenAccount,
  onLogout,
  version,
  children
}) {
  const { t, locale } = useI18n();
  const current = tabForPath(route);
  const privileges = usePrivileges(sessions, user);
  const nearest = privileges[0];

  const go = (event, path) => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button === 1) return;
    event.preventDefault();
    onNavigate(path);
  };

  return (
    <div className="ef-shell">
      <header className="ef ef-hdr">
        <a className="ef-hdr__brand" href="/carte" onClick={(event) => go(event, '/carte')}>
          <img src="/assets/logo-mark.png" alt="" width="28" height="28" className="ef-logo" />
          EndoriumFort
        </a>
        <nav className="ef-tabs" aria-label={t('shell.sections')}>
          {SHELL_TABS.filter((tab) => visibleTabs.includes(tab.id)).map((tab) => (
            <a
              key={tab.id}
              href={tab.path}
              className={current?.id === tab.id ? 'ef-tab is-active' : 'ef-tab'}
              aria-current={current?.id === tab.id ? 'page' : undefined}
              onClick={(event) => go(event, tab.path)}
            >
              {t(tab.labelKey)}
              {counts[tab.id] > 0 && (
                <span className={tab.id === 'demandes' ? 'ef-count ef-count--priv' : 'ef-count'}>{counts[tab.id]}</span>
              )}
            </a>
          ))}
        </nav>
        <span style={{ flex: 1 }} />
        <UserMenu
          user={user}
          roleName={roleName}
          version={version}
          darkMode={darkMode}
          onToggleDarkMode={onToggleDarkMode}
          onOpenAccount={onOpenAccount}
          onLogout={onLogout}
        />
      </header>

      {nearest && (
        <div className="ef ef-priv" role="status">
          <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true" style={{ color: 'var(--ef-priv)' }}>
            <circle cx="12" cy="13" r="8" /><path d="M12 9v4l2.5 1.5M9 2h6" />
          </svg>
          <span>
            {t('shell.privilegeOn')} <span className="ef-mono" style={{ fontWeight: 500 }}>{nearest.session.target}</span>
            {' · '}{t('shell.expiresAt', { time: formatClock(nearest.expiresAt, locale) })}
          </span>
          <span className="ef-priv__timer">
            <span className="ef-progress" aria-hidden="true">
              <span style={{ width: `${Math.round(Math.min(1, Math.max(0, nearest.ratio)) * 100)}%` }} />
            </span>
            <span className="ef-mono">{formatRemaining(nearest.remaining)}</span>
          </span>
          {privileges.length > 1 && (
            <span className="ef-muted">{t('shell.otherPrivileges', { count: privileges.length - 1 })}</span>
          )}
          <span style={{ flex: 1 }} />
          <button type="button" className="ef-priv__link" onClick={() => onOpenSession(nearest.session)}>
            {t('shell.openSession')}
          </button>
          <button type="button" className="ef-priv__link" onClick={() => onTerminateSession(nearest.session.id)}>
            {t('shell.endSession')}
          </button>
        </div>
      )}

      <div className="ef-shell__body">{children}</div>
    </div>
  );
}
