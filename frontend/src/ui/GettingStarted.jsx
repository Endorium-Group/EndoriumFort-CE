// First steps of a new bastion, shown to administrators at the top of the map
// until every required step is done (or hidden). Each step checks itself from
// live data: steps = [{ id, done, optional?, onGo }], computed by the caller.
// Optional steps are listed but neither counted nor needed to finish.
import React, { useState } from 'react';
import { useI18n } from '../i18n.jsx';

const storageKey = (user) => `endoriumfort_getting_started_hidden:${user || ''}`;

export default function GettingStarted({ user, steps }) {
  const { t } = useI18n();
  const [hidden, setHidden] = useState(() => {
    try { return localStorage.getItem(storageKey(user)) === '1'; } catch (_) { return false; }
  });
  const required = steps.filter((step) => !step.optional);
  const done = required.filter((step) => step.done).length;
  if (hidden || !required.length || done === required.length) return null;

  const hide = () => {
    setHidden(true);
    try { localStorage.setItem(storageKey(user), '1'); } catch (_) { /* per-browser convenience only */ }
  };
  const next = required.find((step) => !step.done);
  const textKey = (step) => (step.done ? 'done' : step.optional ? 'todoOptional' : 'todo');

  return (
    <section className="ef-card ef-start" aria-labelledby="ef-start-title">
      <div className="ef-start__head">
        <div>
          <h2 id="ef-start-title">{t('start.title')}</h2>
          <p>{t('start.subtitle')}</p>
        </div>
        <span className="ef-start__progress">
          <span className="ef-start__bar" aria-hidden="true"><span style={{ width: `${(done / required.length) * 100}%` }} /></span>
          {t('start.progress', { done, total: required.length })}
        </span>
        <button type="button" className="ef-btn ef-btn--link" onClick={hide}>{t('start.hide')}</button>
      </div>
      <ol className="ef-start__steps">
        {steps.map((step) => (
          <li
            key={step.id}
            className={[step.done ? 'is-done' : '', step === next ? 'is-next' : '', step.optional ? 'is-optional' : ''].join(' ').trim() || undefined}
          >
            <span className="ef-start__mark" aria-hidden="true">
              {step.done
                ? <svg className="ef-icon" viewBox="0 0 24 24"><path d="M5 12l5 5 9-10" /></svg>
                : null}
            </span>
            <span className="ef-start__text">
              <strong>
                {t(`start.steps.${step.id}.title`)}
                {step.optional && <span className="ef-start__optional">{t('start.optional')}</span>}
              </strong>
              <span>{t(`start.steps.${step.id}.${textKey(step)}`)}</span>
            </span>
            {!step.done && (
              <button type="button" className={step === next ? 'ef-btn ef-btn--primary ef-btn--sm' : 'ef-btn ef-btn--sm'} onClick={step.onGo}>
                {t(`start.steps.${step.id}.action`)}
              </button>
            )}
          </li>
        ))}
      </ol>
    </section>
  );
}
