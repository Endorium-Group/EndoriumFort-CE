import React, { useEffect, useId, useRef } from 'react';
import { useI18n } from '../i18n.jsx';

// Centered modal in the direction E style. `onClose` is optional: without it the
// dialog cannot be dismissed (Escape, backdrop and the × button are disabled).
// `onBackdropClose` overrides what a click on the backdrop does.
export default function Dialog({ kicker, title, subtitle, onClose, onBackdropClose, footer, width = 480, children, className = '' }) {
  const { t } = useI18n();
  const titleId = useId();
  const rootRef = useRef(null);

  useEffect(() => {
    if (!onClose) return undefined;
    const onKey = (event) => {
      if (event.key !== 'Escape') return;
      // With stacked dialogs (a confirmation over an editor), only the top one closes.
      const open = document.querySelectorAll('.ef-dlg');
      if (open[open.length - 1] === rootRef.current) onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div ref={rootRef} className="ef ef-dlg" onMouseDown={(event) => {
      const close = onBackdropClose || onClose;
      if (close && event.target === event.currentTarget) close();
    }}>
      <div
        className={`ef-dlg__panel ${className}`.trim()}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        style={{ width: `min(100%, ${width}px)` }}
      >
        <div className="ef-dlg__head">
          <div className="ef-dlg__titles">
            {kicker && <span className="ef-dlg__kicker">{kicker}</span>}
            <h2 id={titleId}>{title}</h2>
            {subtitle && <div className="ef-dlg__sub">{subtitle}</div>}
          </div>
          {onClose && (
            <button type="button" className="ef-btn ef-btn--sm ef-dlg__close" onClick={onClose} aria-label={t('common.close')}>
              <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" /></svg>
            </button>
          )}
        </div>
        <div className="ef-dlg__body">{children}</div>
        {footer && <div className="ef-dlg__foot">{footer}</div>}
      </div>
    </div>
  );
}
