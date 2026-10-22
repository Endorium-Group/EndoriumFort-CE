import React, { useEffect, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useI18n } from '../i18n.jsx';
import Dialog from './Dialog.jsx';

// Destructive or sensitive action behind a confirmation dialog: the button
// opens it, "Cancel" has the focus (so Enter or a double click never confirm
// by accident) and the action only runs from the dialog's confirm button.
//   title / message  what is about to happen (default: the button's label)
//   confirmLabel     the dialog's confirm button
//   requireText      text to type before confirming, for the heaviest actions
// onConfirm may return a promise: the dialog waits for it and stays open with
// the error if it throws, so the screen never claims a change the server
// refused. The dialog is portaled to <body>: it may be opened from inside a
// form or another dialog.
export default function ConfirmButton({
  children,
  confirmLabel,
  onConfirm,
  disabled,
  className = 'ef-btn ef-btn--danger',
  title,
  message,
  requireText = '',
  danger = true
}) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [typed, setTyped] = useState('');
  const cancelRef = useRef(null);
  const inputRef = useRef(null);
  const openedAt = useRef(0);
  const inputId = useId();

  useEffect(() => {
    if (!open) return;
    setError('');
    setTyped('');
    // Focus once the dialog is in the page.
    const timer = window.setTimeout(() => (requireText ? inputRef.current : cancelRef.current)?.focus(), 0);
    return () => window.clearTimeout(timer);
  }, [open, requireText]);

  const close = () => {
    if (!busy) setOpen(false);
  };
  // The second click of a double click lands on the backdrop that just
  // appeared: it must not close the dialog it opened.
  const closeFromBackdrop = () => {
    if (Date.now() - openedAt.current >= 400) close();
  };
  const textOk = !requireText || typed.trim() === requireText;

  const confirm = async () => {
    if (busy || !textOk) return;
    setBusy(true);
    setError('');
    try {
      await onConfirm();
      setOpen(false);
    } catch (err) {
      setError(err?.message || t('confirm.failed'));
    } finally {
      setBusy(false);
    }
  };

  const label = typeof children === 'string' ? children : confirmLabel;
  const dialog = open && createPortal(
    // Clicks inside a portal still bubble through React parents (a list row
    // that selects itself on click, for instance): stop them here.
    <div onClick={(event) => event.stopPropagation()}>
      <Dialog
        kicker={t('confirm.kicker')}
        title={title || label}
        onClose={busy ? undefined : close}
        onBackdropClose={busy ? undefined : closeFromBackdrop}
        width={460}
        className="ef-confirm"
        footer={
          <>
            <button ref={cancelRef} type="button" className="ef-btn" onClick={close} disabled={busy}>
              {t('common.cancel')}
            </button>
            <button
              type="button"
              className={danger ? 'ef-btn ef-btn--danger' : 'ef-btn ef-btn--primary'}
              onClick={confirm}
              disabled={busy || !textOk}
            >
              {busy ? t('confirm.busy') : confirmLabel || label}
            </button>
          </>
        }
      >
        {message && <p className="ef-confirm__msg">{message}</p>}
        {requireText && (
          <div className="ef-confirm__type">
            <label htmlFor={inputId}>{t('confirm.typeToConfirm', { text: requireText })}</label>
            <input
              id={inputId}
              ref={inputRef}
              className="ef-input ef-mono"
              value={typed}
              onChange={(event) => setTyped(event.target.value)}
              onKeyDown={(event) => { if (event.key === 'Enter') { event.preventDefault(); confirm(); } }}
              autoComplete="off"
              spellCheck={false}
              disabled={busy}
            />
          </div>
        )}
        {error && <div className="ef-alert ef-alert--danger" role="alert">{error}</div>}
      </Dialog>
    </div>,
    document.body
  );

  return (
    <>
      <button
        type="button"
        className={className}
        disabled={disabled}
        onClick={(event) => {
          event.stopPropagation();
          openedAt.current = Date.now();
          setOpen(true);
        }}
      >
        {children}
      </button>
      {dialog}
    </>
  );
}
