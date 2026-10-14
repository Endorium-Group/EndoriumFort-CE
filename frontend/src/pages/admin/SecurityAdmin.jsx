import React, { useEffect, useMemo, useState } from 'react';
import { useI18n } from '../../i18n.jsx';
import { fetchRelays, fetchVaultRotation } from '../../api.js';
import { normalizeRiskLevel } from '../../accessPolicy.js';
import ConfirmButton from '../../ui/ConfirmButton.jsx';
import { LockIcon } from '../../ui/RelayLock.jsx';
import { formatDuration, formatWhen, useNow } from '../../ui/sessions.js';

const LONG_SESSION_MS = 8 * 3600 * 1000;
const OLD_REQUEST_MS = 3600 * 1000;

// Security checklist computed from data the UI already has. Each finding links
// to the page where it can be fixed; passing checks are listed as "in order".
export default function SecurityAdmin({
  users,
  resources,
  sessions,
  accessRequests,
  stats,
  licenseDaysRemaining,
  vaultLicensed,
  relaysLicensed,
  containment,
  onGo,
  children
}) {
  const { t, locale } = useI18n();
  const now = useNow(60000);
  const [rotations, setRotations] = useState(null);
  const [relays, setRelays] = useState(null);

  useEffect(() => {
    if (!vaultLicensed) return undefined;
    let active = true;
    fetchVaultRotation().then((d) => { if (active) setRotations(d.items || []); }).catch(() => {});
    return () => { active = false; };
  }, [vaultLicensed]);
  useEffect(() => {
    if (!relaysLicensed) return undefined;
    let active = true;
    fetchRelays().then((d) => { if (active) setRelays(d.items || []); }).catch(() => {});
    return () => { active = false; };
  }, [relaysLicensed]);

  const checks = useMemo(() => {
    const list = [];
    const names = (items, key = 'username') => items.slice(0, 3).map((x) => x[key]).join(', ') + (items.length > 3 ? ` +${items.length - 3}` : '');
    const add = (id, ok, severity, okText, problemText, detail, action) => list.push({ id, ok, severity, okText, problemText, detail, action });

    const adminsNoMfa = users.filter((u) => u.role === 'admin' && !u.totpEnabled && !u.webauthnEnabled);
    add('mfa', !adminsNoMfa.length, 'high', t('sec.okMfa'), t('sec.adminsNoMfa', { count: adminsNoMfa.length }), names(adminsNoMfa), { label: t('sec.openUsers'), path: '/admin/users' });

    const pendingPw = users.filter((u) => u.role === 'admin' && u.bootstrapPasswordChangeRequired);
    add('pw', !pendingPw.length, 'medium', t('sec.okPasswords'), t('sec.adminsPw', { count: pendingPw.length }), names(pendingPw), { label: t('sec.openUsers'), path: '/admin/users' });

    const critical = resources.filter((r) => normalizeRiskLevel(r.riskLevel) === 'critical' && !r.requireDualApproval);
    add('critical', !critical.length, 'high', t('sec.okCritical'), t('sec.criticalNoApproval', { count: critical.length }), names(critical, 'name'), { label: t('sec.openResources'), path: '/admin/resources' });

    const unguarded = resources.filter((r) => ['high', 'critical'].includes(normalizeRiskLevel(r.riskLevel)) && String(r.protocol).toLowerCase() === 'ssh' && !r.enableCommandGuard);
    add('guard', !unguarded.length, 'medium', t('sec.okGuard'), t('sec.noGuard', { count: unguarded.length }), names(unguarded, 'name'), { label: t('sec.openResources'), path: '/admin/resources' });

    const long = sessions.filter((s) => s.status === 'active' && now - Date.parse(s.createdAt) > LONG_SESSION_MS);
    add('long', !long.length, 'medium', t('sec.okLong'), t('sec.longSessions', { count: long.length }),
      long.slice(0, 3).map((s) => `#${s.id} · ${s.operator} (${formatDuration(now - Date.parse(s.createdAt), locale)})`).join(', '), { label: t('sec.openSessions'), path: '/sessions' });

    const oldRequests = accessRequests.filter((r) => r.status === 'pending' && now - Date.parse(r.createdAt) > OLD_REQUEST_MS);
    add('requests', !oldRequests.length, 'low', t('sec.okRequests'), t('sec.oldRequests', { count: oldRequests.length }), names(oldRequests, 'requester'), { label: t('sec.openRequests'), path: '/demandes' });

    if (rotations) {
      const failed = rotations.filter((p) => p.lastStatus && p.lastStatus !== 'ok');
      add('rotation', !failed.length, 'high', t('sec.okRotation'), t('sec.rotationFailed', { count: failed.length }),
        failed.slice(0, 3).map((p) => p.resourceName || resources.find((r) => r.id === p.resourceId)?.name || `#${p.resourceId}`).join(', '), { label: t('sec.openVault'), path: '/admin/vault' });
    }
    if (relays) {
      const down = relays.filter((r) => String(r.status).toLowerCase() !== 'online');
      add('relays', !down.length, 'medium', t('sec.okRelays'), t('sec.relaysDown', { count: down.length }), names(down, 'relayId'), { label: t('sec.openRelays'), path: '/admin/routing' });
    }
    const webauthn = stats?.auth?.webauthn;
    if (webauthn) {
      const ok = webauthn.rpIdValid !== false && webauthn.originValid !== false;
      add('webauthn', ok, 'medium', t('sec.okWebauthn'), t('sec.webauthnBad'), `${webauthn.rpId || '?'} · ${webauthn.origin || '?'}`, null);
    }
    if (Number.isFinite(licenseDaysRemaining)) {
      add('license', licenseDaysRemaining > 30, licenseDaysRemaining <= 7 ? 'high' : 'low', t('sec.okLicense'), t('sec.licenseSoon', { days: licenseDaysRemaining }), '', { label: t('sec.openLicense'), path: '/admin/license' });
    }
    return list;
  }, [users, resources, sessions, accessRequests, rotations, relays, stats, licenseDaysRemaining, now, t, locale]);

  const rank = { high: 0, medium: 1, low: 2 };
  const problems = checks.filter((c) => !c.ok).sort((a, b) => rank[a.severity] - rank[b.severity]);
  const fine = checks.filter((c) => c.ok);
  const sevColor = { high: 'var(--ef-danger)', medium: 'var(--ef-warn)', low: 'var(--ef-muted)' };

  return (
    <div className="ef ef-adminpage">
      <div className="ef-reqpage__head">
        <div>
          <h1>{t('sec.title')}</h1>
          <p>{t('sec.subtitle')}</p>
        </div>
      </div>

      <section className={containment.status.enabled ? 'ef-card ef-contain is-on' : 'ef-card ef-contain'}>
        <div>
          <h2 className="ef-sectitle">{containment.status.enabled ? t('sec.containOn') : t('sec.containTitle')}</h2>
          <p>{t('sec.containText')}</p>
          {containment.status.enabled && (
            <p className="ef-small">
              {t('sec.containSince', { who: containment.status.updatedBy || '?', when: containment.status.updatedAt ? formatWhen(containment.status.updatedAt, locale) : '—' })}
              {containment.status.reason && <> · {containment.status.reason}</>}
            </p>
          )}
        </div>
        <span style={{ flex: 1 }} />
        {!containment.licensed ? (
          <button type="button" className="ef-lock" onClick={containment.onUnlock}><LockIcon />{t('sec.containLocked')}</button>
        ) : containment.status.enabled ? (
          <button type="button" className="ef-btn" disabled={containment.busy} onClick={() => containment.onToggle(false)}>{t('sec.containStop')}</button>
        ) : (
          <ConfirmButton confirmLabel={t('sec.containConfirm')} disabled={containment.busy} onConfirm={() => containment.onToggle(true)}>{t('sec.containStart')}</ConfirmButton>
        )}
      </section>

      <section className="ef-card ef-checks">
        <div className="ef-enroll__head"><h2 className="ef-sectitle">{t('sec.toFix')}</h2><span className="ef-muted">{t('sec.points', { count: problems.length })}</span></div>
        {problems.length ? problems.map((c) => (
          <div key={c.id} className="ef-check-row">
            <span className="ef-dot" style={{ background: sevColor[c.severity] }} />
            <div className="ef-check-row__text">
              <div>{c.problemText}</div>
              {c.detail && <div className="ef-text-2 ef-small ef-mono">{c.detail}</div>}
            </div>
            {c.action && <button type="button" className="ef-btn ef-btn--sm" onClick={() => onGo(c.action.path)}>{c.action.label}</button>}
          </div>
        )) : <p className="ef-muted" style={{ margin: 0, padding: '14px 16px' }}>{t('sec.nothing')}</p>}
      </section>

      <section className="ef-card ef-checks">
        <div className="ef-enroll__head"><h2 className="ef-sectitle">{t('sec.inOrder')}</h2></div>
        {fine.map((c) => (
          <div key={c.id} className="ef-check-row is-ok">
            <span className="ef-dot" style={{ background: 'var(--ef-ok)' }} />
            <div className="ef-check-row__text">{c.okText}</div>
          </div>
        ))}
      </section>
      <p className="ef-hint" style={{ marginBottom: 16 }}>{t('sec.howComputed')}</p>
      {children}
    </div>
  );
}
