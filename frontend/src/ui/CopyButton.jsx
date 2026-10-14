import React, { useState } from 'react';
import { useI18n } from '../i18n.jsx';

// Copies `text` to the clipboard and says so for two seconds.
export default function CopyButton({ text, label }) {
  const { t } = useI18n();
  const [state, setState] = useState('');
  return (
    <button
      type="button"
      className="ef-btn ef-btn--sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text || '');
          setState('ok');
        } catch (_) {
          setState('fail');
        }
        window.setTimeout(() => setState(''), 2000);
      }}
    >
      {state === 'ok' ? t('relays.copied') : state === 'fail' ? t('relays.copyFailed') : label || t('relays.copy')}
    </button>
  );
}
