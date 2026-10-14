import React, { useEffect, useRef } from 'react';
import { useI18n } from '../i18n.jsx';

const TONE = { ok: 'var(--ef-ok)', busy: 'var(--ef-warn)', error: 'var(--ef-danger)', idle: 'var(--ef-line-2)' };

// Large window around a remote screen (VNC, isolated browser, graphical replay):
// header with status and actions, a dark viewport, an optional control bar.
// Escape is left to the remote screen: only the × button and the backdrop close it.
export default function ViewerFrame({ kicker, title, subtitle, status, message, onClose, bar, children }) {
  const { t } = useI18n();
  const panelRef = useRef(null);

  useEffect(() => {
    const previous = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = previous; };
  }, []);

  const toggleFullscreen = () => {
    if (document.fullscreenElement) document.exitFullscreen?.();
    else panelRef.current?.requestFullscreen?.();
  };

  return (
    <div className="ef ef-dlg ef-viewer" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <div ref={panelRef} className="ef-dlg__panel ef-viewer__panel" role="dialog" aria-modal="true" aria-label={title}>
        <div className="ef-dlg__head">
          <div className="ef-dlg__titles">
            {kicker && <span className="ef-dlg__kicker">{kicker}</span>}
            <h2>{title}</h2>
            {subtitle && <div className="ef-dlg__sub">{subtitle}</div>}
          </div>
          {status && (
            <span className="ef-status ef-viewer__status">
              <span className="ef-dot" style={{ background: TONE[status.tone] || TONE.idle }} />
              {status.label}
            </span>
          )}
          <button type="button" className="ef-btn ef-btn--sm" onClick={toggleFullscreen} title={t('viewer.fullscreen')} aria-label={t('viewer.fullscreen')}>
            <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5" /></svg>
          </button>
          <button type="button" className="ef-btn ef-btn--sm ef-dlg__close" onClick={onClose} aria-label={t('common.close')}>
            <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" /></svg>
          </button>
        </div>
        {message && <div className={`ef-viewer__msg${status?.tone === 'error' ? ' is-error' : ''}`}>{message}</div>}
        <div className="ef-viewer__screen">{children}</div>
        {bar && <div className="ef-viewer__bar">{bar}</div>}
      </div>
    </div>
  );
}
