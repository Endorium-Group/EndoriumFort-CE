import React, { useState } from 'react';
import { useI18n } from '../../i18n.jsx';

import { LockIcon } from '../../ui/RelayLock.jsx';

// Modules and the tier that unlocks them (mirrors the server's license gates).
const MODULES = [
  ['recording', 'pro'],
  ['jit', 'pro'],
  ['relays', 'pro'],
  ['k8s', 'pro'],
  ['appearance', 'pro'],
  ['evidence', 'enterprise'],
  ['vault', 'enterprise'],
  ['integrations', 'enterprise'],
  ['itdr', 'enterprise'],
  ['securityCenter', 'enterprise'],
  ['cluster', 'enterprise']
];

export default function LicenseAdmin({ status, version, usersCount, isUnlocked, uploadText, setUploadText, onApply, onReload, busy, message }) {
  const { t, locale } = useI18n();
  const [dragging, setDragging] = useState(false);
  const dateOf = (value) => {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? '—' : d.toLocaleDateString(locale === 'fr' ? 'fr-FR' : 'en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
  };
  const state = String(status?.state || 'none').toLowerCase();
  const valid = state === 'valid';
  const days = Number(status?.daysRemaining);
  const hasDays = valid && Number.isFinite(days);
  const tier = valid ? status?.tier || 'free' : 'free';
  const edition = status?.edition || 'community';
  const maxSeats = Number(status?.maxSeats) || 0;
  const maxNodes = Number(status?.maxNodes) || 0;

  const readFile = (file) => {
    if (!file) return;
    const reader = new window.FileReader();
    reader.onload = (event) => setUploadText(String(event.target.result || '').trim());
    reader.readAsText(file);
  };

  const banner = !valid
    ? { tone: 'bad', text: state === 'expired' ? t('license.expired') : state === 'revoked' ? t('license.revoked') : t('license.none') }
    : hasDays && days <= 90
      ? { tone: days <= 7 ? 'bad' : days <= 30 ? 'warn' : 'info', text: t('license.expiresIn', { days, date: status?.expiresAt ? dateOf(status.expiresAt) : '—' }) }
      : null;

  return (
    <div className="ef ef-adminpage">
      <div className="ef-reqpage__head">
        <div>
          <h1>{t('license.title')}</h1>
          <p>{t('license.subtitle')}</p>
        </div>
      </div>

      {banner && <div className={`ef-licbanner is-${banner.tone}`}>{banner.text}</div>}

      <div className="ef-reqpage__grid">
        <div className="ef-card ef-licard">
          <div className="ef-licard__head">
            <img src="/assets/logo-mark.png" alt="" width="36" height="36" className="ef-logo" />
            <div style={{ flex: 1 }}>
              <div className="ef-licard__name">EndoriumFort {t(`license.tiers.${tier}`) === `license.tiers.${tier}` ? tier : t(`license.tiers.${tier}`)}</div>
              <div className="ef-muted ef-small">{t('license.editionBuild', { edition })}</div>
            </div>
            <span className="ef-status">
              <span className="ef-dot" style={{ background: valid ? 'var(--ef-ok)' : 'var(--ef-danger)' }} />
              {t(`license.states.${state}`) === `license.states.${state}` ? state : t(`license.states.${state}`)}
            </span>
          </div>
          <dl className="ef-kv ef-kv--wide" style={{ margin: 0, padding: '0 16px 16px' }}>
            <dt>{t('about.version')}</dt><dd className="ef-mono">{version || '—'}</dd>
            <dt>{t('license.customer')}</dt><dd>{status?.customer || '—'}</dd>
            <dt>{t('license.id')}</dt><dd className="ef-mono">{status?.licenseId || '—'}</dd>
            <dt>{t('license.kind')}</dt><dd>{status?.kind || '—'}</dd>
            <dt>{t('license.validUntil')}</dt><dd>{status?.expiresAt ? dateOf(status.expiresAt) : '—'}{hasDays ? ` · ${t('license.daysLeft', { days })}` : ''}</dd>
            <dt>{t('license.nodes')}</dt><dd>{maxNodes ? t('license.upTo', { count: maxNodes }) : t('license.unlimited')}</dd>
            <dt>{t('license.seats')}</dt>
            <dd>
              {maxSeats ? t('license.seatsUsed', { used: usersCount, max: maxSeats }) : t('license.seatsUnlimited', { used: usersCount })}
              {maxSeats > 0 && usersCount > maxSeats && <span className="ef-badge ef-badge--critical" style={{ marginLeft: 6 }}>{t('license.overSeats')}</span>}
            </dd>
          </dl>
        </div>

        <section className="ef-card ef-licmods">
          <div className="ef-enroll__head"><h2 className="ef-sectitle">{t('license.modules')}</h2></div>
          <ul>
            {MODULES.map(([id, need]) => {
              const on = isUnlocked(need);
              return (
                <li key={id} className={on ? 'is-on' : ''}>
                  {on
                    ? <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12l5 5 9-10" /></svg>
                    : <LockIcon size={14} />}
                  <span>{t(`license.mods.${id}`)}</span>
                  {!on && <span className="ef-muted ef-small">{t(`license.tiers.${need}`)}</span>}
                </li>
              );
            })}
          </ul>
          {Array.isArray(status?.features) && status.features.length > 0 && (
            <p className="ef-hint" style={{ padding: '0 16px 12px', margin: 0 }}>{t('license.extraFeatures', { list: status.features.join(', ') })}</p>
          )}
        </section>
      </div>

      <section className="ef-card" style={{ marginTop: 16, overflow: 'hidden' }}>
        <div className="ef-enroll__head"><h2 className="ef-sectitle">{t('license.import')}</h2></div>
        <div className="ef-licimport">
          <label
            className={dragging ? 'ef-drop is-drag' : 'ef-drop'}
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => { e.preventDefault(); setDragging(false); readFile(e.dataTransfer.files?.[0]); }}
          >
            <span>{t('license.dropHere')}</span>
            <span className="ef-btn ef-btn--sm">{t('license.chooseFile')}</span>
            <input type="file" accept=".jws,.lic,.txt,application/jose" hidden onChange={(e) => readFile(e.target.files?.[0])} />
          </label>
          <details open={!!uploadText}>
            <summary className="ef-text-2 ef-small">{t('license.pasteInstead')}</summary>
            <textarea className="ef-input ef-mono ef-rtextarea" rows={4} value={uploadText} spellCheck={false} onChange={(e) => setUploadText(e.target.value)} placeholder="eyJ…header.eyJ…payload.eyJ…signatures" />
          </details>
          {uploadText && <p className="ef-hint" style={{ margin: 0 }}>{t('license.ready', { size: uploadText.length })}</p>}
          <div className="ef-uform__actions">
            <button type="button" className="ef-btn ef-btn--primary" disabled={busy || !uploadText.trim()} onClick={onApply}>{t('license.apply')}</button>
            <button type="button" className="ef-btn" disabled={busy} onClick={onReload}>{t('license.reload')}</button>
          </div>
          {message && <div className={message.error ? 'ef-alert ef-alert--danger' : 'ef-alert'}>{message.message}</div>}
          <p className="ef-hint" style={{ margin: 0 }}>{t('license.importHint')}</p>
        </div>
      </section>
    </div>
  );
}
