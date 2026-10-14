import React, { useEffect, useMemo, useState } from 'react';
import { useI18n } from '../i18n.jsx';
import {
  assignRelayToResource,
  clearRelayForResource,
  createAccessPolicy,
  fetchAccessPolicies,
  fetchRelays,
  updateAccessPolicy,
  updateResource
} from '../api.js';
import { normalizeRiskLevel } from '../accessPolicy.js';
import { useRelayRoutes, zoneOf } from './MapPage.jsx';
import RelayLock, { LockIcon } from '../ui/RelayLock.jsx';

const NO_ZONE = '';
const MIXED = '__mixed__';
const DURATIONS = [1800, 3600, 7200, 14400, 28800];
const ZONE_NAME = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const TIME_WINDOW = /^([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d$/;

const policyName = (zone) => `zone-${zone}`;
const zoneTag = (zone) => `zone:${zone}`;

const tagsWithZone = (tagsCsv, zone) => {
  const tags = String(tagsCsv || '').split(',').map((tag) => tag.trim()).filter(Boolean)
    .filter((tag) => !tag.toLowerCase().startsWith('zone:'));
  if (zone) tags.unshift(zoneTag(zone));
  return tags.join(',');
};

const resourcePayload = (resource, changes) => ({
  name: resource.name,
  target: resource.target,
  protocol: resource.protocol,
  port: resource.port,
  tunnelTicketRateLimitMaxAttempts: resource.tunnelTicketRateLimitMaxAttempts || 0,
  description: resource.description || '',
  imageUrl: resource.imageUrl || '',
  imageData: resource.imageData || '',
  tagsCsv: resource.tagsCsv || '',
  credentialSource: resource.credentialSource || 'vaulted',
  httpUsername: resource.httpUsername || '',
  sshUsername: resource.sshUsername || '',
  agentProtocol: resource.agentProtocol || '',
  requireAccessJustification: !!resource.requireAccessJustification,
  requireDualApproval: !!resource.requireDualApproval,
  enableCommandGuard: !!resource.enableCommandGuard,
  adaptiveAccessPolicy: !!resource.adaptiveAccessPolicy,
  riskLevel: resource.riskLevel || 'low',
  ...changes
});

// Rules a zone policy can add. Policies only ever tighten access, so there is no
// "approval: none" — the resource's own setting always still applies.
const rulesOf = (policy) => ({
  approval: String(policy?.approvalMode || 'inherit').toLowerCase() === 'required' ? 'required' : 'inherit',
  mfa: String(policy?.mfaRequirement || 'any').toLowerCase(),
  duration: Number(policy?.maxDurationSeconds) || 3600,
  ticket: !!policy?.ticketRequired,
  justification: !!policy?.requireJustification,
  route: String(policy?.routingConstraint || 'any').toLowerCase(),
  window: String(policy?.timeWindow || 'any').toLowerCase()
});

const common = (values) => {
  const set = new Set(values);
  if (!set.size) return '';
  return set.size === 1 ? values[0] : MIXED;
};

export default function ZonesPage({ resources, policiesLicensed, relaysLicensed, onResourcesChanged, onEditResource, onUnlock }) {
  const { t } = useI18n();
  const [policies, setPolicies] = useState([]);
  const [relays, setRelays] = useState([]);
  const [loadError, setLoadError] = useState('');
  const [refresh, setRefresh] = useState(0);
  const routes = useRelayRoutes(resources, relaysLicensed, refresh);
  const [newZones, setNewZones] = useState([]);
  const [selected, setSelected] = useState(null);
  const [moves, setMoves] = useState({});
  const [edits, setEdits] = useState({});
  const [dragId, setDragId] = useState(null);
  const [dropZone, setDropZone] = useState(null);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState('');
  const [saving, setSaving] = useState(false);
  const [report, setReport] = useState(null);

  useEffect(() => {
    if (!policiesLicensed) return undefined;
    let active = true;
    fetchAccessPolicies()
      .then((data) => { if (active) setPolicies(Array.isArray(data.items) ? data.items : []); })
      .catch((err) => { if (active) setLoadError(err.message || t('zones.loadError')); });
    return () => { active = false; };
  }, [policiesLicensed, refresh]);

  useEffect(() => {
    if (!relaysLicensed) return undefined;
    let active = true;
    fetchRelays()
      .then((data) => { if (active) setRelays(Array.isArray(data.items) ? data.items : []); })
      .catch(() => {});
    return () => { active = false; };
  }, [relaysLicensed]);

  const zoneOfResource = (resource) => (resource.id in moves ? moves[resource.id] : zoneOf(resource));

  const zones = useMemo(() => {
    const names = new Set(newZones);
    resources.forEach((r) => { const z = zoneOf(r); if (z) names.add(z); });
    Object.values(moves).forEach((z) => { if (z) names.add(z); });
    policies.forEach((p) => {
      if (String(p.name || '').startsWith('zone-')) names.add(String(p.name).slice(5));
    });
    return Array.from(names).sort();
  }, [resources, policies, newZones, moves]);

  const managedPolicy = (zone) => policies.find((p) => p.name === policyName(zone)) || null;
  const otherPolicies = (zone) => policies.filter((p) => p.name !== policyName(zone) &&
    String(p.resourceTagsCsv || '').split(',').map((s) => s.trim()).includes(zoneTag(zone)));

  const membersOf = (zone) => resources.filter((r) => zoneOfResource(r) === zone);

  // Current values of a zone, before pending edits.
  const baseOf = (zone) => {
    const members = resources.filter((r) => zoneOf(r) === zone);
    const relayValues = members.map((r) => (routes[r.id]?.route === 'relay' ? routes[r.id].relayId || routes[r.id].relay : ''));
    return {
      ...rulesOf(managedPolicy(zone)),
      risk: common(members.map((r) => normalizeRiskLevel(r.riskLevel))),
      guard: common(members.map((r) => (r.enableCommandGuard ? 'on' : 'off'))),
      relay: relaysLicensed ? common(relayValues) : ''
    };
  };
  const valuesOf = (zone) => ({ ...baseOf(zone), ...(edits[zone] || {}) });

  const setEdit = (zone, key, value) => {
    setEdits((prev) => {
      const next = { ...(prev[zone] || {}), [key]: value };
      if (baseOf(zone)[key] === value) delete next[key];
      const all = { ...prev, [zone]: next };
      if (!Object.keys(next).length) delete all[zone];
      return all;
    });
  };

  const moveResource = (resource, zone) => {
    setMoves((prev) => {
      const next = { ...prev };
      if (zoneOf(resource) === zone) delete next[resource.id];
      else next[resource.id] = zone;
      return next;
    });
  };

  // Human-readable list of what Save will do.
  const fmt = (key, value) => {
    if (value === MIXED) return t('zones.mixed');
    if (typeof value === 'boolean') return value ? t('zones.yes') : t('zones.no');
    if (key === 'duration') return t(`zones.dur.${value}`);
    if (key === 'approval') return t(`zones.approval.${value}`);
    if (key === 'mfa') return t(`zones.mfa.${value}`);
    if (key === 'route') return t(`zones.route.${value}`);
    if (key === 'window') return value === 'any' ? t('zones.anyTime') : `${value} UTC`;
    if (key === 'risk') return t(`map.risk.${value}`);
    if (key === 'guard') return value === 'on' ? t('zones.yes') : t('zones.no');
    if (key === 'relay') return value ? (relays.find((r) => r.relayId === value)?.label || value) : t('map.direct');
    return String(value);
  };
  const diffs = [];
  Object.entries(moves).forEach(([id, zone]) => {
    const resource = resources.find((r) => String(r.id) === String(id));
    if (resource) diffs.push({ key: `m${id}`, label: resource.name, from: zoneOf(resource) || t('map.noZone'), to: zone || t('map.noZone') });
  });
  Object.entries(edits).forEach(([zone, changes]) => {
    const base = baseOf(zone);
    Object.entries(changes).forEach(([key, value]) => {
      diffs.push({ key: `${zone}-${key}`, label: `${zone} · ${t(`zones.field.${key}`)}`, from: fmt(key, base[key]), to: fmt(key, value) });
    });
  });

  const save = async () => {
    setSaving(true);
    const done = [];
    const failed = [];
    const skipped = [];

    // 1. Resources: zone moves plus per-resource rules (risk, SSH guard).
    const resourceChanges = new Map();
    Object.entries(moves).forEach(([id, zone]) => {
      const resource = resources.find((r) => String(r.id) === String(id));
      if (resource) resourceChanges.set(resource.id, { tagsCsv: tagsWithZone(resource.tagsCsv, zone) });
    });
    Object.entries(edits).forEach(([zone, changes]) => {
      if (!('risk' in changes) && !('guard' in changes)) return;
      membersOf(zone).forEach((resource) => {
        const next = { ...(resourceChanges.get(resource.id) || {}) };
        if ('risk' in changes) next.riskLevel = changes.risk;
        if ('guard' in changes) next.enableCommandGuard = changes.guard === 'on';
        resourceChanges.set(resource.id, next);
      });
    });
    for (const [id, changes] of resourceChanges) {
      const resource = resources.find((r) => r.id === id);
      try {
        await updateResource(id, resourcePayload(resource, changes));
        done.push(resource.name);
      } catch (err) {
        failed.push(`${resource.name} : ${err.message}`);
      }
    }

    // 2. Zone policies (one managed policy per zone, targeting its tag).
    for (const [zone, changes] of Object.entries(edits)) {
      const ruleKeys = ['approval', 'mfa', 'duration', 'ticket', 'justification', 'route', 'window'];
      if (!ruleKeys.some((key) => key in changes)) continue;
      const values = valuesOf(zone);
      const existing = managedPolicy(zone);
      const payload = {
        ...(existing || {}),
        name: policyName(zone),
        description: existing?.description || t('zones.policyDescription', { zone }),
        identityPattern: existing?.identityPattern ?? '*',
        resourceTagsCsv: zoneTag(zone),
        riskLevel: existing?.riskLevel || 'any',
        approvalMode: values.approval,
        mfaRequirement: values.mfa,
        maxDurationSeconds: Number(values.duration),
        ticketRequired: !!values.ticket,
        requireJustification: !!values.justification,
        routingConstraint: values.route,
        timeWindow: values.window && TIME_WINDOW.test(values.window) ? values.window : 'any',
        enabled: existing ? existing.enabled !== false : true
      };
      try {
        if (existing) await updateAccessPolicy(existing.id, payload);
        else await createAccessPolicy(payload);
        done.push(policyName(zone));
      } catch (err) {
        failed.push(`${policyName(zone)} : ${err.message}`);
      }
    }

    // 3. Relay of every resource in the zone.
    for (const [zone, changes] of Object.entries(edits)) {
      if (!('relay' in changes) || changes.relay === MIXED) continue;
      for (const resource of membersOf(zone)) {
        try {
          if (changes.relay) await assignRelayToResource(resource.id, changes.relay);
          else await clearRelayForResource(resource.id);
          done.push(`${resource.name} → ${fmt('relay', changes.relay)}`);
        } catch (err) {
          failed.push(`${resource.name} : ${err.message}`);
        }
      }
    }

    await onResourcesChanged();
    setMoves({});
    setEdits({});
    setNewZones([]);
    setRefresh((n) => n + 1);
    setReport({ done: done.length, failed, skipped });
    setSaving(false);
  };

  const reset = () => {
    setMoves({});
    setEdits({});
    setReport(null);
  };

  const createZone = (event) => {
    event.preventDefault();
    const name = newName.trim().toLowerCase();
    if (!ZONE_NAME.test(name) || zones.includes(name)) return;
    setNewZones((prev) => [...prev, name]);
    setSelected({ kind: 'zone', id: name });
    setNewName('');
    setCreating(false);
  };

  const onDrop = (zone) => (event) => {
    event.preventDefault();
    const id = Number(event.dataTransfer.getData('text/plain') || dragId);
    const resource = resources.find((r) => r.id === id);
    if (resource) moveResource(resource, zone);
    setDragId(null);
    setDropZone(null);
  };

  const renderChip = (resource) => {
    const moved = resource.id in moves;
    const isSel = selected?.kind === 'res' && selected.id === resource.id;
    const route = routes[resource.id];
    return (
      <button
        key={resource.id}
        type="button"
        draggable
        onDragStart={(event) => { event.dataTransfer.setData('text/plain', String(resource.id)); setDragId(resource.id); }}
        onDragEnd={() => { setDragId(null); setDropZone(null); }}
        onClick={(event) => { event.stopPropagation(); setSelected({ kind: 'res', id: resource.id }); }}
        className={['ef-zchip', moved ? 'is-moved' : '', isSel ? 'is-selected' : '', dragId === resource.id ? 'is-dragging' : ''].join(' ').trim()}
        title={t('zones.dragHint')}
      >
        <span className="ef-dot" style={{ background: `var(--ef-risk-${normalizeRiskLevel(resource.riskLevel)}, var(--ef-line-2))` }} />
        <span className="ef-mono">{resource.name}</span>
        {route?.route === 'relay' && <span className="ef-muted ef-zchip__relay">{route.relay}</span>}
      </button>
    );
  };

  const renderZoneCard = (zone) => {
    const members = membersOf(zone);
    const values = valuesOf(zone);
    const isSel = selected?.kind === 'zone' && selected.id === zone;
    const badges = zone === NO_ZONE ? [] : [
      values.approval === 'required' && t('zones.badgeApproval'),
      values.mfa !== 'any' && t('zones.badgeMfa'),
      managedPolicy(zone) || edits[zone]?.duration ? t(`zones.dur.${values.duration}`) : null,
      values.ticket && t('zones.badgeTicket'),
      values.window && values.window !== 'any' && values.window,
      values.route === 'relay' && t('zones.badgeRelay')
    ].filter(Boolean);
    return (
      <section
        key={zone || 'none'}
        className={['ef-zcard', zone === NO_ZONE ? 'is-nozone' : '', isSel ? 'is-selected' : '', dropZone === zone ? 'is-drop' : ''].join(' ').trim()}
        onClick={() => zone !== NO_ZONE && setSelected({ kind: 'zone', id: zone })}
        onDragOver={(event) => { event.preventDefault(); setDropZone(zone); }}
        onDragLeave={() => setDropZone((value) => (value === zone ? null : value))}
        onDrop={onDrop(zone)}
        aria-label={zone ? t('zones.zoneLabel', { zone }) : t('map.noZone')}
      >
        <header className="ef-zcard__head">
          <strong>{zone || t('map.noZone')}</strong>
          {zone && <span className="ef-mono ef-muted">{zoneTag(zone)}</span>}
          <span style={{ flex: 1 }} />
          <span className="ef-muted">{t('map.resourceCount', { count: members.length })}</span>
        </header>
        {badges.length > 0 && <div className="ef-zcard__rules">{badges.map((b) => <span key={b} className="ef-badge">{b}</span>)}</div>}
        <div className="ef-zcard__chips">
          {members.map(renderChip)}
          {!members.length && <span className="ef-muted ef-zcard__empty">{t('zones.dropHere')}</span>}
        </div>
      </section>
    );
  };

  const renderZoneInspector = (zone) => {
    const values = valuesOf(zone);
    const others = otherPolicies(zone);
    const existing = managedPolicy(zone);
    const members = membersOf(zone);
    const field = (key, control) => (
      <>
        <label className="ef-zform__label" htmlFor={`z-${key}`}>{t(`zones.field.${key}`)}</label>
        {control}
      </>
    );
    return (
      <>
        <div className="ef-insp__head">
          <div className="ef-muted" style={{ fontSize: 12 }}>{t('zones.zone')}</div>
          <div className="ef-insp__title ef-mono">{zone}</div>
          <div className="ef-text-2" style={{ fontSize: 12.5, marginTop: 4 }}>
            {t('map.resourceCount', { count: members.length })} · {existing ? t('zones.policyIs', { name: existing.name }) : t('zones.noPolicy')}
          </div>
        </div>

        <div className="ef-insp__sec">
          <h3>{t('zones.access')}</h3>
          {!policiesLicensed ? (
            <div className="ef-lockline"><LockIcon /> {t('zones.rulesLocked')} <button type="button" className="ef-btn ef-btn--sm" onClick={() => onUnlock(t('zones.access'), 'pro')}>{t('req.unlock')}</button></div>
          ) : (
            <div className="ef-zform">
              {field('approval', (
                <select id="z-approval" className="ef-input" value={values.approval} onChange={(e) => setEdit(zone, 'approval', e.target.value)}>
                  <option value="inherit">{t('zones.approval.inherit')}</option>
                  <option value="required">{t('zones.approval.required')}</option>
                </select>
              ))}
              {field('mfa', (
                <select id="z-mfa" className="ef-input" value={values.mfa} onChange={(e) => setEdit(zone, 'mfa', e.target.value)}>
                  {['any', 'required', 'totp', 'webauthn'].map((v) => <option key={v} value={v}>{t(`zones.mfa.${v}`)}</option>)}
                </select>
              ))}
              {field('duration', (
                <select id="z-duration" className="ef-input" value={values.duration} onChange={(e) => setEdit(zone, 'duration', Number(e.target.value))}>
                  {(DURATIONS.includes(values.duration) ? DURATIONS : [...DURATIONS, values.duration]).map((v) => <option key={v} value={v}>{t(`zones.dur.${v}`) || `${v} s`}</option>)}
                </select>
              ))}
              {field('window', (
                <span className="ef-zwindow">
                  <select
                    id="z-window"
                    className="ef-input"
                    value={values.window === 'any' ? 'any' : 'hours'}
                    onChange={(e) => setEdit(zone, 'window', e.target.value === 'any' ? 'any' : '07:00-20:00')}
                  >
                    <option value="any">{t('zones.anyTime')}</option>
                    <option value="hours">{t('zones.onlyHours')}</option>
                  </select>
                  {values.window !== 'any' && (
                    <input
                      className={TIME_WINDOW.test(values.window) ? 'ef-input ef-mono' : 'ef-input ef-mono is-invalid'}
                      value={values.window}
                      onChange={(e) => setEdit(zone, 'window', e.target.value.trim())}
                      aria-label={t('zones.field.window')}
                      placeholder="07:00-20:00"
                    />
                  )}
                </span>
              ))}
              <span />
              <span className="ef-zform__checks">
                <label className="ef-check"><input type="checkbox" checked={!!values.ticket} onChange={(e) => setEdit(zone, 'ticket', e.target.checked)} />{t('zones.field.ticket')}</label>
                <label className="ef-check"><input type="checkbox" checked={!!values.justification} onChange={(e) => setEdit(zone, 'justification', e.target.checked)} />{t('zones.field.justification')}</label>
              </span>
            </div>
          )}
          {policiesLicensed && values.window !== 'any' && (
            <p className={TIME_WINDOW.test(values.window) ? 'ef-hint' : 'ef-zwarn'} style={{ margin: '10px 0 0' }}>
              {TIME_WINDOW.test(values.window) ? t('zones.timeWindowWarning', { window: values.window }) : t('zones.windowInvalid')}
            </p>
          )}
          {others.length > 0 && (
            <p className="ef-muted ef-small" style={{ margin: '10px 0 0' }}>{t('zones.otherPolicies', { names: others.map((p) => p.name).join(', ') })}</p>
          )}
        </div>

        <div className="ef-insp__sec">
          <h3>{t('zones.network')}</h3>
          {!relaysLicensed ? (
            <div className="ef-zform"><span className="ef-zform__label">{t('zones.field.relay')}</span><span><RelayLock onUnlock={() => onUnlock(t('relayLock.label'), 'pro')} /></span></div>
          ) : (
            <div className="ef-zform">
              {policiesLicensed && field('route', (
                <select id="z-route" className="ef-input" value={values.route} onChange={(e) => setEdit(zone, 'route', e.target.value)}>
                  {['any', 'direct', 'relay'].map((v) => <option key={v} value={v}>{t(`zones.route.${v}`)}</option>)}
                </select>
              ))}
              {field('relay', (
                <select id="z-relay" className="ef-input ef-mono" value={values.relay} onChange={(e) => setEdit(zone, 'relay', e.target.value)}>
                  {values.relay === MIXED && <option value={MIXED}>{t('zones.mixed')}</option>}
                  <option value="">{t('map.direct')}</option>
                  {relays.map((r) => <option key={r.relayId} value={r.relayId}>{r.label || r.relayId}{r.status && r.status !== 'online' ? ` (${r.status})` : ''}</option>)}
                </select>
              ))}
            </div>
          )}
          {values.route === 'relay' && values.relay === '' && relaysLicensed && <p className="ef-zwarn">{t('zones.relayNeeded')}</p>}
        </div>

        <div className="ef-insp__sec">
          <h3>{t('zones.perResource')}</h3>
          <div className="ef-zform">
            {field('risk', (
              <select id="z-risk" className="ef-input" value={values.risk} onChange={(e) => setEdit(zone, 'risk', e.target.value)}>
                {values.risk === MIXED && <option value={MIXED}>{t('zones.mixed')}</option>}
                {values.risk === '' && <option value="">—</option>}
                {['low', 'medium', 'high', 'critical'].map((v) => <option key={v} value={v}>{t(`map.risk.${v}`)}</option>)}
              </select>
            ))}
            {field('guard', (
              <select id="z-guard" className="ef-input" value={values.guard} onChange={(e) => setEdit(zone, 'guard', e.target.value)}>
                {values.guard === MIXED && <option value={MIXED}>{t('zones.mixed')}</option>}
                {values.guard === '' && <option value="">—</option>}
                <option value="on">{t('zones.yes')}</option>
                <option value="off">{t('zones.no')}</option>
              </select>
            ))}
          </div>
        </div>
      </>
    );
  };

  const renderResourceInspector = (resource) => {
    const current = zoneOfResource(resource);
    return (
      <>
        <div className="ef-insp__head">
          <div className="ef-muted" style={{ fontSize: 12 }}>{t('map.resource')}</div>
          <div className="ef-insp__title ef-mono">{resource.name}</div>
          <div className="ef-text-2" style={{ fontSize: 12.5, marginTop: 4 }}>{resource.target}:{resource.port} · {String(resource.protocol || '').toUpperCase()}</div>
        </div>
        <div className="ef-insp__sec">
          <div className="ef-zform">
            <label className="ef-zform__label" htmlFor="r-zone">{t('zones.zone')}</label>
            <select id="r-zone" className="ef-input" value={current} onChange={(e) => moveResource(resource, e.target.value)}>
              {zones.map((z) => <option key={z} value={z}>{z}</option>)}
              <option value="">{t('map.noZone')}</option>
            </select>
            <span className="ef-zform__label">{t('zones.tags')}</span>
            <span className="ef-mono ef-small">{tagsWithZone(resource.tagsCsv, current) || '—'}</span>
          </div>
          <p className="ef-text-2 ef-small" style={{ margin: '12px 0 10px' }}>{t('zones.resourceHint')}</p>
          <button type="button" className="ef-btn ef-btn--sm" onClick={() => onEditResource(resource)}>{t('zones.openResource')}</button>
        </div>
      </>
    );
  };

  const selectedResource = selected?.kind === 'res' ? resources.find((r) => r.id === selected.id) : null;
  const unzoned = membersOf(NO_ZONE);

  return (
    <div className="ef ef-page ef-mappage">
      <div className="ef-mappage__main">
        <div className="ef-reqpage__head" style={{ marginBottom: 0 }}>
          <div>
            <h1>{t('zones.title')}</h1>
            <p>{t('zones.subtitle')}</p>
          </div>
          <span style={{ flex: 1 }} />
          {creating ? (
            <form className="ef-zcreate" onSubmit={createZone}>
              <input
                className="ef-input ef-mono"
                autoFocus
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Escape') setCreating(false); }}
                placeholder="prod"
                aria-label={t('zones.newName')}
              />
              <button type="submit" className="ef-btn ef-btn--primary" disabled={!ZONE_NAME.test(newName.trim().toLowerCase()) || zones.includes(newName.trim().toLowerCase())}>{t('zones.create')}</button>
              <button type="button" className="ef-btn" onClick={() => setCreating(false)}>{t('common.cancel')}</button>
            </form>
          ) : (
            <button type="button" className="ef-btn" onClick={() => setCreating(true)}>
              <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14" /></svg>
              {t('zones.newZone')}
            </button>
          )}
        </div>
        {loadError && <div className="ef-alert ef-alert--danger">{loadError}</div>}
        <div className="ef-zgrid">
          {zones.map(renderZoneCard)}
          {(unzoned.length > 0 || dragId) && renderZoneCard(NO_ZONE)}
        </div>
        <p className="ef-muted ef-small" style={{ margin: 0 }}>{t('zones.footnote')}</p>
      </div>

      <aside className="ef-insp ef-zinsp" aria-label={t('zones.settings')}>
        <div className="ef-zinsp__body">
          {selected?.kind === 'zone' && zones.includes(selected.id) ? renderZoneInspector(selected.id)
            : selectedResource ? renderResourceInspector(selectedResource)
              : <div className="ef-insp__empty"><p>{t('zones.selectHint')}</p></div>}
        </div>
        <div className="ef-zpending">
          <div className="ef-zpending__head">
            <strong>{diffs.length ? t('zones.pending', { count: diffs.length }) : t('zones.noPendingTitle')}</strong>
            <span style={{ flex: 1 }} />
            {diffs.length > 0 && <button type="button" className="ef-btn ef-btn--sm" onClick={reset} disabled={saving}>{t('common.cancel')}</button>}
          </div>
          {diffs.length ? (
            <ul className="ef-zdiff">
              {diffs.map((d) => <li key={d.key}><span>{d.label}</span><span><s>{d.from}</s> → <b>{d.to}</b></span></li>)}
            </ul>
          ) : <p className="ef-muted ef-small" style={{ margin: 0 }}>{t('zones.noPending')}</p>}
          {report && (
            <div className={report.failed.length || report.skipped.length ? 'ef-alert ef-alert--warn ef-zreport' : 'ef-alert ef-zreport'}>
              <div>
                <div>{t('zones.saved', { count: report.done })}</div>
                {report.skipped.length > 0 && <div>{t('zones.skipped', { names: report.skipped.join(', ') })}</div>}
                {report.failed.map((f) => <div key={f}>{f}</div>)}
              </div>
            </div>
          )}
          <button type="button" className="ef-btn ef-btn--primary ef-btn--block" style={{ marginTop: 10 }} disabled={!diffs.length || saving} onClick={save}>
            {saving ? t('zones.saving') : t('common.save')}
          </button>
        </div>
      </aside>
    </div>
  );
}
