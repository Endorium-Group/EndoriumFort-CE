import React, { useEffect, useState } from 'react';
import { useI18n } from '../i18n.jsx';
import { LockIcon } from '../ui/RelayLock.jsx';

const ICONS = {
  resources: <><rect x="3" y="4" width="18" height="7" rx="1.5" /><rect x="3" y="13" width="18" height="7" rx="1.5" /><path d="M7 7.5h.01M7 16.5h.01" /></>,
  users: <><circle cx="9" cy="8" r="4" /><path d="M2 21c0-4 3-6 7-6s7 2 7 6M17 4a4 4 0 0 1 0 8M22 21c0-3-2-5-4-5.5" /></>,
  jit: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  routing: <><circle cx="12" cy="12" r="2.5" /><path d="M6.3 6.3a8 8 0 0 0 0 11.4M17.7 6.3a8 8 0 0 1 0 11.4M9.2 9.2a4 4 0 0 0 0 5.6M14.8 9.2a4 4 0 0 1 0 5.6" /></>,
  vault: <><circle cx="8" cy="15" r="4" /><path d="M11 12l9-9M17 6l3 3" /></>,
  security: <path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" />,
  itdr: <><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" /><path d="M12 8v5M12 16h.01" /></>,
  enterprise: <path d="M9 2v6M15 2v6M6 8h12v4a6 6 0 0 1-12 0zM12 18v4" />,
  k8s: <><path d="M12 2.5l8.5 4.9v9.2L12 21.5l-8.5-4.9V7.4z" /><circle cx="12" cy="12" r="3" /></>,
  appearance: <><rect x="3" y="4" width="18" height="16" rx="2" /><circle cx="9" cy="10" r="2" /><path d="M21 16l-5-5-9 9" /></>,
  license: <><rect x="4" y="3" width="16" height="18" rx="2" /><path d="M8 8h8M8 12h8M8 16h5" /></>
};

// Side menu of the Administration tab. Section content is rendered by the caller;
// it is outside the `.ef` scope so legacy panels keep their own look meanwhile.
export default function AdminLayout({ sections, current, onSelect, footer, children }) {
  const { t } = useI18n();
  // Narrow screens: the menu becomes a drawer opened from a burger on the right.
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (event) => { if (event.key === 'Escape') setOpen(false); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open]);
  const currentSection = sections.find((section) => section.id === current);

  return (
    <div className="ef-admin">
      <div className="ef ef-adminbar">
        <button
          type="button"
          className="ef-btn ef-adminbar__burger"
          aria-label={t('adminE.menu')}
          aria-expanded={open}
          aria-controls="ef-adminnav"
          onClick={() => setOpen((value) => !value)}
        >
          <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16" /></svg>
        </button>
        <span className="ef-adminbar__title">
          <span className="ef-muted">{t('shell.admin')}</span>
          <span aria-hidden="true" className="ef-muted">/</span>
          <strong>{currentSection?.label || ''}</strong>
        </span>
      </div>
      {open && <div className="ef-admin__scrim" onClick={() => setOpen(false)} aria-hidden="true" />}
      <nav id="ef-adminnav" className={open ? 'ef ef-adminnav is-open' : 'ef ef-adminnav'} aria-label={t('shell.admin')}>
        <div className="ef-adminnav__title">
          {t('shell.admin')}
          <button type="button" className="ef-btn ef-btn--sm ef-adminnav__close" aria-label={t('common.close')} onClick={() => setOpen(false)}>×</button>
        </div>
        {sections.map((section) => (
          <a
            key={section.id}
            href={`/admin/${section.id}`}
            className={current === section.id ? 'ef-adminnav__item is-active' : 'ef-adminnav__item'}
            aria-current={current === section.id ? 'page' : undefined}
            onClick={(event) => {
              if (event.metaKey || event.ctrlKey) return;
              event.preventDefault();
              setOpen(false);
              onSelect(section.id);
            }}
          >
            <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true">{ICONS[section.id]}</svg>
            <span className="ef-adminnav__label">{section.label}</span>
            {section.locked ? (
              <span className="ef-adminnav__count" title={t('adminE.locked')}><LockIcon /></span>
            ) : section.alert ? (
              <span className="ef-adminnav__count is-alert">{section.alert}</span>
            ) : section.count != null ? (
              <span className="ef-adminnav__count">{section.count}</span>
            ) : null}
          </a>
        ))}
        <span style={{ flex: 1 }} />
        {footer && <div className="ef-adminnav__foot">{footer}</div>}
      </nav>
      <main className="ef-admin__main">{children}</main>
    </div>
  );
}
