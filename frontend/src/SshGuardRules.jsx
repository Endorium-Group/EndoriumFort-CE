// EndoriumFort — SSH command guard blocklist. Core, present in the CE bundle:
// the guard itself has no license feature, so its configuration must not be
// reachable only from the Enterprise threat-detection page. That page renders
// this same component, against the same endpoints.
import React, { useCallback, useEffect, useState } from 'react';
import { useI18n } from './i18n.jsx';
import { deleteSshGuardRule, fetchSshGuardRules, saveSshGuardRule } from './api.js';
import ConfirmButton from './ui/ConfirmButton.jsx';

const NAME_RE = /^[A-Za-z0-9_-]{1,48}$/;

export default function SshGuardRules() {
  const { t } = useI18n();
  const [rules, setRules] = useState([]);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [name, setName] = useState('');
  const [command, setCommand] = useState('');

  const load = useCallback(async () => {
    try {
      const data = await fetchSshGuardRules();
      setRules(Array.isArray(data?.items) ? data.items : []);
      setError('');
    } catch (e) {
      setError(e?.message || t('sshGuard.loadError'));
    }
  }, [t]);

  useEffect(() => { load(); }, [load]);

  const save = async (rule, patch) => {
    setBusy(rule.name);
    try {
      await saveSshGuardRule(rule.name, { command: rule.command, enabled: rule.enabled, ...patch });
      await load();
    } catch (e) {
      setError(e?.message || t('sshGuard.saveError'));
    } finally {
      setBusy('');
    }
  };

  const remove = async (rule) => {
    setBusy(rule.name);
    try {
      await deleteSshGuardRule(rule.name);
      await load();
    } catch (e) {
      setError(e?.message || t('sshGuard.saveError'));
    } finally {
      setBusy('');
    }
  };

  const add = async (event) => {
    event.preventDefault();
    const cleanName = name.trim();
    const cleanCommand = command.trim();
    if (!NAME_RE.test(cleanName)) { setError(t('sshGuard.badName')); return; }
    if (!cleanCommand) { setError(t('sshGuard.badCommand')); return; }
    setBusy(cleanName);
    try {
      await saveSshGuardRule(cleanName, { command: cleanCommand, enabled: true });
      setName(''); setCommand('');
      await load();
    } catch (e) {
      setError(e?.message || t('sshGuard.saveError'));
    } finally {
      setBusy('');
    }
  };

  const builtinLabel = (id) => {
    const key = `sshGuard.builtin.${id}`;
    return t(key) === key ? id : t(key);
  };
  const activeCount = rules.filter((r) => r.enabled).length;

  return (
    <section className="ef-card" style={{ overflow: 'hidden', marginBottom: 16 }}>
      <div className="ef-enroll__head">
        <h2 className="ef-sectitle">{t('sshGuard.title')}</h2>
        <span className="ef-muted">{activeCount}/{rules.length}</span>
      </div>
      <p className="ef-hint">{t('sshGuard.intro')}</p>
      {error && <p className="ef-zwarn ef-small" role="alert">{error}</p>}

      <div style={{ overflowX: 'auto' }}>
        <table className="ef-table">
          <thead>
            <tr>
              <th>{t('sshGuard.rule')}</th>
              <th>{t('sshGuard.command')}</th>
              <th>{t('jit.active')}</th>
              <th aria-label={t('sshGuard.actions')} />
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => (
              <tr key={rule.name} style={{ cursor: 'default' }}>
                <td>
                  <span style={{ fontWeight: 500 }}>{rule.builtin ? builtinLabel(rule.name) : rule.name}</span>
                  {rule.builtin && <span className="ef-text-2 ef-small" style={{ display: 'block' }}>{t('sshGuard.builtinTag')}</span>}
                </td>
                <td>
                  {rule.builtin
                    ? <span className="ef-muted">{t('sshGuard.builtinPattern')}</span>
                    : <code className="ef-mono">{rule.command}</code>}
                </td>
                <td>
                  <label className="ef-check">
                    <input
                      type="checkbox"
                      checked={!!rule.enabled}
                      disabled={busy === rule.name}
                      aria-label={`${t('jit.active')} — ${rule.name}`}
                      onChange={(e) => save(rule, { enabled: e.target.checked })}
                    />
                  </label>
                </td>
                <td>
                  {!rule.builtin && (
                    <ConfirmButton
                      className="ef-btn ef-btn--danger ef-btn--sm"
                      title={t('confirm.removeRule', { name: rule.name })}
                      message={t('confirm.removeRuleMsg')}
                      confirmLabel={t('sshGuard.remove')}
                      disabled={busy === rule.name}
                      onConfirm={() => remove(rule)}
                    >
                      {t('sshGuard.remove')}
                    </ConfirmButton>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <form onSubmit={add} className="ef-row" style={{ gap: 8, marginTop: 12, flexWrap: 'wrap' }}>
        <input
          className="ef-input"
          value={name}
          maxLength={48}
          placeholder={t('sshGuard.namePlaceholder')}
          aria-label={t('sshGuard.rule')}
          onChange={(e) => setName(e.target.value)}
        />
        <input
          className="ef-input ef-mono"
          value={command}
          maxLength={200}
          style={{ flex: '1 1 220px' }}
          placeholder={t('sshGuard.commandPlaceholder')}
          aria-label={t('sshGuard.command')}
          onChange={(e) => setCommand(e.target.value)}
        />
        <button type="submit" className="ef-btn" disabled={!!busy}>{t('sshGuard.add')}</button>
      </form>
      <p className="ef-hint" style={{ marginTop: 8 }}>{t('sshGuard.hint')}</p>
    </section>
  );
}
