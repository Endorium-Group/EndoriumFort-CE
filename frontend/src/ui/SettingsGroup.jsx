// EndoriumFort — settings form (integrations, SSH file transfer…).
//
// Renders one group of the settings catalog served by
// GET /api/settings/integrations. The form is generic on purpose: the backend
// descriptors carry the type, range, enum and help text, so a key added there
// shows up here with no frontend change.
//
// Two behaviours worth knowing:
//   * only edited fields are sent, so an untouched secret is never resubmitted
//     (and an empty secret box does not wipe a stored credential — the explicit
//     revert button does that);
//   * a key set in the store shadows the environment, which the field says out
//     loud, because a Helm value that silently stopped applying is the kind of
//     thing an operator debugs for an hour.
import React, { useMemo, useState } from 'react';
import { useI18n } from '../i18n.jsx';
import { saveIntegrationSettings } from '../api.js';

function Field({ item, draft, onChange, onRevert, t }) {
  const edited = Object.prototype.hasOwnProperty.call(draft, item.key);
  const value = edited ? draft[item.key] : item.value;
  const common = {
    className: 'ef-input',
    id: `set-${item.key}`,
    value: item.kind === 'bool' ? undefined : value ?? '',
    onChange: (e) => onChange(item.key, e.target.value)
  };
  let control;
  if (item.kind === 'bool') {
    control = (
      <select {...common} value={String(value ?? '0') === '1' ? '1' : '0'}>
        <option value="1">{t('settings.on')}</option>
        <option value="0">{t('settings.off')}</option>
      </select>
    );
  } else if (item.kind === 'enum') {
    control = (
      <select {...common}>
        <option value="">{t('settings.unset')}</option>
        {(item.enumValues || []).map((v) => <option key={v} value={v}>{v}</option>)}
      </select>
    );
  } else if (item.kind === 'secret') {
    control = (
      <input
        {...common}
        type="password"
        autoComplete="new-password"
        placeholder={item.configured ? t('settings.secretSet') : t('settings.secretUnset')}
        value={edited ? draft[item.key] : ''}
      />
    );
  } else if (item.kind === 'int') {
    control = <input {...common} type="number" min={item.min} max={item.max} inputMode="numeric" />;
  } else {
    control = <input {...common} type="text" spellCheck="false" />;
  }

  return (
    <div className="ef-setfield">
      <label htmlFor={`set-${item.key}`}>
        {item.label}
        {item.source === 'store' && <span className="ef-setbadge">{t('settings.fromStore')}</span>}
        {item.envShadowed && <span className="ef-setbadge is-warn">{t('settings.shadowsEnv')}</span>}
        {item.source === 'env' && <span className="ef-setbadge">{t('settings.fromEnv')}</span>}
      </label>
      {control}
      <span className="ef-setkey ef-mono">{item.key}</span>
      {item.hint && <span className="ef-sethint">{item.hint}</span>}
      {item.source === 'store' && (
        <button type="button" className="ef-btn ef-btn--link" onClick={() => onRevert(item.key)}>
          {t('settings.revert')}
        </button>
      )}
    </div>
  );
}

export default function SettingsGroup({ group, items, onSaved }) {
  const { t } = useI18n();
  const [draft, setDraft] = useState({});
  const [state, setState] = useState(null);
  const [saving, setSaving] = useState(false);

  const sections = useMemo(() => {
    const bySection = new Map();
    for (const item of items || []) {
      if (item.group !== group) continue;
      if (!bySection.has(item.subgroup)) bySection.set(item.subgroup, []);
      bySection.get(item.subgroup).push(item);
    }
    return [...bySection.entries()];
  }, [items, group]);

  if (!sections.length) return null;

  const change = (key, value) => {
    setState(null);
    setDraft((prev) => ({ ...prev, [key]: value }));
  };

  const submit = async (values) => {
    setSaving(true);
    setState(null);
    try {
      const response = await saveIntegrationSettings(values);
      const rejected = Array.isArray(response?.rejected) ? response.rejected : [];
      if (rejected.length) {
        setState({ ok: false, rejected });
      } else {
        setState({ ok: true, applied: response?.applied || 0 });
        setDraft({});
        if (onSaved) await onSaved();
      }
    } catch (err) {
      setState({ ok: false, message: err.message || t('settings.saveError') });
    } finally {
      setSaving(false);
    }
  };

  const save = () => {
    const values = {};
    for (const [key, value] of Object.entries(draft)) {
      // An untouched or emptied secret box must not clear a stored credential.
      const item = items.find((i) => i.key === key);
      if (item?.kind === 'secret' && !value) continue;
      values[key] = value === '' ? null : value;
    }
    if (!Object.keys(values).length) return;
    submit(values);
  };

  const revert = (key) => submit({ [key]: null });
  const pending = Object.keys(draft).length;
  const rejectedFor = (key) => state?.rejected?.find((r) => r.key === key)?.error;

  return (
    <div className="ef-setgroup">
      <p className="ef-hint" style={{ marginTop: 0 }}>{t('settings.intro')}</p>
      {sections.map(([section, fields]) => (
        <section key={section || 'main'}>
          {section && section !== 'general' && <h4 className="ef-setsection">{section}</h4>}
          <div className="ef-setgrid">
            {fields.map((item) => (
              <React.Fragment key={item.key}>
                <Field item={item} draft={draft} onChange={change} onRevert={revert} t={t} />
                {rejectedFor(item.key) && (
                  <p className="ef-seterror">{rejectedFor(item.key)}</p>
                )}
              </React.Fragment>
            ))}
          </div>
        </section>
      ))}
      <div className="ef-setactions">
        <button type="button" className="ef-btn ef-btn--primary" disabled={saving || !pending} onClick={save}>
          {pending ? t('settings.saveCount', { count: pending }) : t('settings.save')}
        </button>
        {pending > 0 && (
          <button type="button" className="ef-btn" disabled={saving} onClick={() => { setDraft({}); setState(null); }}>
            {t('settings.discard')}
          </button>
        )}
        {state?.ok && <span className="ef-setok">{t('settings.saved', { count: state.applied })}</span>}
        {state && !state.ok && (
          <span className="ef-seterror">{state.message || t('settings.rejected')}</span>
        )}
      </div>
    </div>
  );
}
