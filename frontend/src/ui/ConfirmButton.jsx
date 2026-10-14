import React, { useEffect, useState } from 'react';

// Two-step destructive button: the first click arms it, the second confirms.
// It disarms itself after a few seconds.
export default function ConfirmButton({ children, confirmLabel, onConfirm, disabled, className = 'ef-btn ef-btn--danger' }) {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return undefined;
    const timer = window.setTimeout(() => setArmed(false), 4000);
    return () => window.clearTimeout(timer);
  }, [armed]);
  return (
    <button
      type="button"
      className={armed ? `${className} is-armed` : className}
      disabled={disabled}
      onClick={(event) => {
        event.stopPropagation();
        if (armed) {
          setArmed(false);
          onConfirm();
        } else {
          setArmed(true);
        }
      }}
    >
      {armed ? confirmLabel : children}
    </button>
  );
}
