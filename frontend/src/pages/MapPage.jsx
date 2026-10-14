import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useI18n } from '../i18n.jsx';
import { fetchRelayResolution } from '../api.js';
import RelayLock, { LockIcon } from '../ui/RelayLock.jsx';
import { describeAccessOutcome, describeResourcePolicy, normalizeRiskLevel } from '../accessPolicy.js';

const VIEW_STORAGE_KEY = 'endoriumfort_map_view';
const NO_ZONE = '';

export const zoneOf = (resource) => {
  const tags = String(resource?.tagsCsv || '').split(',').map((tag) => tag.trim().toLowerCase());
  const zoneTag = tags.find((tag) => tag.startsWith('zone:') && tag.length > 5);
  return zoneTag ? zoneTag.slice(5) : NO_ZONE;
};

const protocolOf = (resource) => String(resource?.protocol || 'ssh').toLowerCase();

const RISK_COLOR = { critical: 'var(--ef-danger)', high: 'var(--ef-warn)', medium: 'var(--ef-muted)', low: 'var(--ef-ok)' };

function ResourceIcon({ protocol }) {
  if (protocol === 'rdp' || protocol === 'vnc') {
    return <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="13" rx="1.5" /><path d="M8 21h8M12 17v4" /></svg>;
  }
  if (protocol === 'http' || protocol === 'https') {
    return <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" /></svg>;
  }
  if (protocol === 'k8s' || protocol === 'kubernetes') {
    return <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2.5l8.5 4.9v9.2L12 21.5l-8.5-4.9V7.4z" /><circle cx="12" cy="12" r="3" /></svg>;
  }
  if (protocol === 'agent' || protocol === 'tcp') {
    return <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M9 2v6M15 2v6M6 8h12v4a6 6 0 0 1-12 0zM12 18v4" /></svg>;
  }
  return <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="7" rx="1.5" /><rect x="3" y="13" width="18" height="7" rx="1.5" /><path d="M7 7.5h.01M7 16.5h.01" /></svg>;
}

// Relay route of every resource (needs the relay license). Stops at the first failure.
export function useRelayRoutes(resources, enabled, refreshKey = 0) {
  const [routes, setRoutes] = useState({});
  const key = resources.map((r) => r.id).join(',');
  useEffect(() => {
    if (!enabled || !resources.length) return undefined;
    let active = true;
    (async () => {
      const next = {};
      for (const resource of resources) {
        try {
          const data = await fetchRelayResolution(resource.id);
          next[resource.id] = {
            route: String(data?.route || 'direct').toLowerCase() === 'relay' ? 'relay' : 'direct',
            relay: data?.relay?.label || data?.relay?.relayId || '',
            relayId: data?.relay?.relayId || '',
            relayStatus: String(data?.relay?.status || '').toLowerCase()
          };
        } catch (_) {
          break;
        }
        if (!active) return;
      }
      if (active) setRoutes(next);
    })();
    return () => { active = false; };
  }, [key, enabled, refreshKey]);
  return routes;
}

// Orthogonal connector between two points.
const elbow = (x1, y1, x2, y2) => {
  const mid = Math.round(x1 + (x2 - x1) / 2);
  return `M${x1} ${y1} H${mid} V${y2} H${x2}`;
};

function MapLinks({ containerRef, refs, links, deps }) {
  const [paths, setPaths] = useState([]);
  const [size, setSize] = useState({ w: 0, h: 0 });

  useLayoutEffect(() => {
    const container = containerRef.current;
    if (!container) return undefined;
    const compute = () => {
      const box = container.getBoundingClientRect();
      const rect = (id) => {
        const el = refs.current[id];
        if (!el) return null;
        const r = el.getBoundingClientRect();
        return { left: r.left - box.left, right: r.right - box.left, mid: r.top - box.top + r.height / 2, top: r.top - box.top };
      };
      setSize({ w: container.scrollWidth, h: container.scrollHeight });
      setPaths(
        links
          .map((link) => {
            const a = rect(link.from);
            const b = rect(link.to);
            if (!a || !b) return null;
            const y2 = link.toTop ? b.top + 16 : b.mid;
            return { ...link, d: elbow(Math.round(a.right), Math.round(a.mid), Math.round(b.left), Math.round(y2)) };
          })
          .filter(Boolean)
      );
    };
    compute();
    const observer = new ResizeObserver(compute);
    observer.observe(container);
    return () => observer.disconnect();
  }, deps);

  return (
    <svg className="ef-map__links" width={size.w} height={size.h} aria-hidden="true">
      {paths.map((p) => (
        <path key={p.key} d={p.d} className={`ef-link ef-link--${p.kind}`} style={{ opacity: p.dim ? 0.15 : 1 }} />
      ))}
    </svg>
  );
}

export default function MapPage({
  resources,
  sessions,
  auditItems,
  currentUser,
  canManage,
  canViewAudit,
  relaysEnabled,
  onUnlockRelays,
  loading,
  error,
  onConnect,
  onEdit,
  onOpenSession,
  onAddResource,
  previewAccess,
  intro
}) {
  const { t } = useI18n();
  const [view, setView] = useState(() => {
    try { return localStorage.getItem(VIEW_STORAGE_KEY) === 'liste' ? 'liste' : 'carte'; } catch (_) { return 'carte'; }
  });
  const [lens, setLens] = useState('acces');
  const [query, setQuery] = useState('');
  const [zoneFilter, setZoneFilter] = useState('all');
  const [mineOnly, setMineOnly] = useState(false);
  const [selectedId, setSelectedId] = useState(null);
  const [focusEvent, setFocusEvent] = useState(null);
  const searchRef = useRef(null);
  const mapRef = useRef(null);
  const nodeRefs = useRef({});
  const routes = useRelayRoutes(resources, relaysEnabled);
  // Rules that really apply to this person (zone/JIT policies included), when
  // the license has JIT governance; otherwise only the resource settings are known.
  const [preview, setPreview] = useState(null);
  useEffect(() => {
    setPreview(null);
    if (!selectedId || !previewAccess) return undefined;
    let active = true;
    previewAccess({ resourceId: selectedId, justification: '', ticketId: '', purpose: '' })
      .then((data) => { if (active) setPreview({ id: selectedId, data }); })
      .catch(() => {});
    return () => { active = false; };
  }, [selectedId, previewAccess]);

  const chooseView = (next) => {
    setView(next);
    try { localStorage.setItem(VIEW_STORAGE_KEY, next); } catch (_) {}
  };

  useEffect(() => {
    const onKey = (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const activeSessions = useMemo(() => sessions.filter((s) => s.status === 'active'), [sessions]);

  const sessionsByResource = useMemo(() => {
    const map = {};
    activeSessions.forEach((session) => {
      const resource =
        resources.find((r) => Number(r.id) === Number(session.resourceId)) ||
        resources.find((r) => r.target === session.target && Number(r.port) === Number(session.port));
      if (!resource) return;
      (map[resource.id] = map[resource.id] || []).push(session);
    });
    return map;
  }, [activeSessions, resources]);

  const sessionState = (resource) => {
    const list = sessionsByResource[resource.id] || [];
    if (list.some((s) => s.operator === currentUser)) return 'mine';
    return list.length ? 'other' : '';
  };

  const accessLabel = (resource) => {
    if (sessionState(resource) === 'mine') return t('map.accessOpen');
    if (resource.requireDualApproval) return t('policy.requestApproval');
    if (resource.requireAccessJustification) return t('policy.reasonRequired');
    return t('map.accessDirect');
  };

  const matches = (resource) => {
    if (mineOnly && sessionState(resource) !== 'mine') return false;
    if (zoneFilter !== 'all' && zoneOf(resource) !== zoneFilter) return false;
    const q = query.trim().toLowerCase();
    if (!q) return true;
    return [resource.name, resource.target, resource.tagsCsv, resource.description, resource.protocol]
      .some((value) => String(value || '').toLowerCase().includes(q));
  };

  const visible = resources.filter(matches);
  const zones = useMemo(() => {
    const names = Array.from(new Set(resources.map(zoneOf)));
    return names.sort((a, b) => (a === NO_ZONE ? 1 : b === NO_ZONE ? -1 : a.localeCompare(b)));
  }, [resources]);
  const grouped = zones
    .map((zone) => ({ zone, items: visible.filter((r) => zoneOf(r) === zone) }))
    .filter((group) => group.items.length);

  const selected = resources.find((r) => r.id === selectedId) || null;

  // Today's journal, newest first, with the resource / user each line points at.
  const todayLog = useMemo(() => {
    if (!canViewAudit) return [];
    const today = new Date().toDateString();
    return (auditItems || [])
      .filter((item) => new Date(item.createdAt).toDateString() === today)
      .slice(0, 8)
      .map((item) => {
        let payload = {};
        try { payload = item.payloadIsJson ? JSON.parse(item.payloadRaw) : {}; } catch (_) {}
        return { ...item, resourceId: Number(payload.resourceId) || null, target: payload.target || '' };
      });
  }, [auditItems, canViewAudit]);
  const focus = todayLog.find((item) => item.id === focusEvent) || null;
  const inFocus = (resource) => !focus || Number(focus.resourceId) === Number(resource.id);

  const users = useMemo(() => {
    const names = Array.from(new Set(activeSessions.map((s) => s.operator)));
    if (currentUser && !names.includes(currentUser)) names.unshift(currentUser);
    return names.sort((a, b) => (a === currentUser ? -1 : b === currentUser ? 1 : a.localeCompare(b)));
  }, [activeSessions, currentUser]);

  const dotColor = (resource) => {
    const state = sessionState(resource);
    if (lens === 'sessions') return state === 'mine' ? 'var(--ef-priv)' : state === 'other' ? 'var(--ef-accent)' : 'transparent';
    if (lens === 'risque') return RISK_COLOR[normalizeRiskLevel(resource.riskLevel)];
    if (lens === 'reseau') {
      const r = routes[resource.id];
      if (!r || r.route === 'direct') return 'transparent';
      return r.relayStatus === 'online' ? 'var(--ef-ok)' : 'var(--ef-warn)';
    }
    if (state === 'mine') return 'var(--ef-priv)';
    return resource.requireDualApproval || resource.requireAccessJustification ? 'var(--ef-muted)' : 'var(--ef-ok)';
  };

  const subLabel = (resource) => {
    const state = sessionState(resource);
    if (lens === 'sessions') {
      const list = sessionsByResource[resource.id] || [];
      return list.length ? list.map((s) => s.operator).join(', ') : t('map.noSession');
    }
    if (lens === 'risque') return t(`map.risk.${normalizeRiskLevel(resource.riskLevel)}`);
    if (lens === 'reseau') {
      if (!relaysEnabled) return `${resource.target}:${resource.port}`;
      const r = routes[resource.id];
      const route = r?.route === 'relay' ? `via ${r.relay}` : t('map.direct');
      return `${resource.target}:${resource.port} · ${route}`;
    }
    return state === 'other' ? t('map.inUse') : accessLabel(resource);
  };

  const links = [];
  users.forEach((user) => {
    const busy = activeSessions.some((s) => s.operator === user);
    links.push({ key: `u-${user}`, from: `user:${user}`, to: 'bastion', kind: !busy ? 'idle' : user === currentUser ? 'mine' : 'other', dim: !!focus });
  });
  grouped.forEach(({ zone, items }) => {
    const states = items.map(sessionState);
    const kind = states.includes('mine') ? 'mine' : states.includes('other') ? 'other' : 'idle';
    const dim = !!focus && !items.some(inFocus);
    links.push({ key: `z-${zone}`, from: 'bastion', to: `zone:${zone}`, kind, toTop: true, dim });
  });
  const linkDeps = [view, lens, query, zoneFilter, mineOnly, focusEvent, resources, sessions, users.join(','), Object.keys(routes).length];

  const primaryAction = (resource) => {
    const mine = (sessionsByResource[resource.id] || []).find((s) => s.operator === currentUser);
    if (mine) return { label: t('map.resume'), run: () => onOpenSession(mine) };
    if (resource.requireDualApproval && !canManage) return { label: t('map.requestAccess'), run: () => onConnect(resource) };
    return { label: t('map.connect'), run: () => onConnect(resource) };
  };

  const zoneLabel = (zone) => (zone === NO_ZONE ? t('map.noZone') : zone);

  const renderNode = (resource) => {
    const state = sessionState(resource);
    const isSel = resource.id === selectedId;
    return (
      <button
        key={resource.id}
        type="button"
        ref={(el) => { nodeRefs.current[`res:${resource.id}`] = el; }}
        className={`ef-node${state === 'mine' && (lens === 'acces' || lens === 'sessions') ? ' is-mine' : ''}${isSel ? ' is-selected' : ''}`}
        style={{ opacity: inFocus(resource) ? (lens === 'sessions' && !state ? 0.55 : 1) : 0.3 }}
        onClick={() => setSelectedId(resource.id)}
        onDoubleClick={() => primaryAction(resource).run()}
        title={resource.description || resource.name}
      >
        <span className="ef-node__icon"><ResourceIcon protocol={protocolOf(resource)} /></span>
        <span className="ef-node__text">
          <span className="ef-node__name">{resource.name}</span>
          <span className="ef-node__sub">{subLabel(resource)}</span>
        </span>
        <span className="ef-dot" style={{ background: dotColor(resource), boxShadow: dotColor(resource) === 'transparent' ? 'inset 0 0 0 1px var(--ef-line-2)' : 'none' }} />
      </button>
    );
  };

  const renderInspector = () => {
    if (!selected) {
      return (
        <div className="ef-insp__empty">
          <p>{t('map.selectHint')}</p>
          <p className="ef-muted">{t('map.doubleClickHint')}</p>
        </div>
      );
    }
    const state = sessionState(selected);
    const action = primaryAction(selected);
    const route = routes[selected.id];
    // The risk level already has its own line above; keep only the access conditions here.
    const riskItem = t('policy.risk', { level: normalizeRiskLevel(selected.riskLevel) });
    const rules = preview?.id === selected.id ? preview.data : null;
    const approval = !canManage && (selected.requireDualApproval || rules?.approvalRequired);
    const conditions = Array.from(new Set([
      ...describeAccessOutcome({ ...selected, requireDualApproval: approval }, t),
      ...describeResourcePolicy(selected, t),
      ...(rules ? [
        rules.justificationRequired && t('policy.reasonRequired'),
        rules.ticketRequired && t('policy.ticketRequired'),
        rules.purposeRequired && t('policy.purposeRequired'),
        rules.mfaRequirement && rules.mfaRequirement !== 'any' && t('policy.mfaLevel', { value: rules.mfaRequirement }),
        rules.routingConstraint === 'relay' && t('policy.viaRelay'),
        rules.timeWindow && rules.timeWindow !== 'any' && t('policy.hours', { window: rules.timeWindow }),
        rules.maxDurationSeconds > 0 && t('policy.maxDuration', { minutes: Math.round(rules.maxDurationSeconds / 60) })
      ] : [])
    ].filter(Boolean))).filter((item) => item !== riskItem);
    const onIt = sessionsByResource[selected.id] || [];
    return (
      <>
        <div className="ef-insp__head">
          <div className="ef-muted" style={{ fontSize: 12 }}>{t('map.resource')} · {protocolOf(selected).toUpperCase()}</div>
          <div className="ef-mono ef-insp__title">{selected.name}</div>
          <div className="ef-insp__state">
            <span className="ef-dot" style={{ background: state === 'mine' ? 'var(--ef-priv)' : state === 'other' ? 'var(--ef-accent)' : 'var(--ef-ok)' }} />
            {state === 'mine' ? t('map.yourSessionOpen') : state === 'other' ? t('map.inUseBy', { users: onIt.map((s) => s.operator).join(', ') }) : t('map.free')}
          </div>
          <div className="ef-insp__actions">
            <button type="button" className="ef-btn ef-btn--primary" onClick={action.run}>{action.label}</button>
            {canManage && <button type="button" className="ef-btn" onClick={() => onEdit(selected)}>{t('common.edit')}</button>}
          </div>
        </div>
        <div className="ef-insp__sec">
          <h3>{t('map.information')}</h3>
          <dl className="ef-kv">
            <dt>{t('map.address')}</dt><dd className="ef-mono">{selected.target}:{selected.port}</dd>
            <dt>{t('map.zone')}</dt><dd>{zoneLabel(zoneOf(selected))}</dd>
            <dt>{t('map.route')}</dt><dd className="ef-mono">{!relaysEnabled ? <RelayLock onUnlock={onUnlockRelays} /> : route?.route === 'relay' ? route.relay : t('map.direct')}</dd>
            <dt>{t('map.riskLabel')}</dt><dd>{t(`map.risk.${normalizeRiskLevel(selected.riskLevel)}`)}</dd>
            <dt>{t('map.credentials')}</dt><dd>{selected.hasCredentials ? t('map.vaulted') : t('map.typedAtLogin')}</dd>
          </dl>
          {selected.description && <p className="ef-text-2" style={{ margin: '10px 0 0' }}>{selected.description}</p>}
        </div>
        <div className="ef-insp__sec">
          <h3>{t('map.conditions')}</h3>
          <ul className="ef-conds">
            {conditions.map((item) => <li key={item}>{item}</li>)}
          </ul>
        </div>
      </>
    );
  };

  const renderMap = () => (
    <div className="ef-map" ref={mapRef}>
      <MapLinks containerRef={mapRef} refs={nodeRefs} links={links} deps={linkDeps} />
      <div className="ef-map__users">
        <div className="ef-map__label">{t('map.whoIsIn')}</div>
        {users.map((user) => {
          const busy = activeSessions.some((s) => s.operator === user);
          return (
            <div
              key={user}
              ref={(el) => { nodeRefs.current[`user:${user}`] = el; }}
              className={`ef-userpill${user === currentUser ? ' is-me' : ''}`}
              style={{ opacity: focus && focus.actor !== user ? 0.3 : 1 }}
            >
              <span className="ef-avatar">{user.slice(0, 2).toUpperCase()}</span>
              <span className="ef-mono">{user}</span>
              <span className="ef-dot" style={{ background: !busy ? 'transparent' : user === currentUser ? 'var(--ef-priv)' : 'var(--ef-accent)', boxShadow: busy ? 'none' : 'inset 0 0 0 1px var(--ef-line-2)' }} />
            </div>
          );
        })}
      </div>
      <div className="ef-map__core">
        <div className="ef-bastion" ref={(el) => { nodeRefs.current.bastion = el; }}>
          <img src="/assets/logo-mark.png" alt="" width="22" height="22" className="ef-logo" />
          <div>
            <div style={{ fontWeight: 600 }}>{t('map.bastion')}</div>
            <div className="ef-muted" style={{ fontSize: 11.5 }}>{t('map.activeSessions', { count: activeSessions.length })}</div>
          </div>
        </div>
      </div>
      <div className="ef-map__zones">
        {grouped.map(({ zone, items }) => {
          const relays = Array.from(new Set(items.map((r) => routes[r.id]).filter((r) => r?.route === 'relay').map((r) => r.relay)));
          return (
            <section
              key={zone || 'none'}
              className={zone === NO_ZONE ? 'ef-zone is-nozone' : 'ef-zone'}
              ref={(el) => { nodeRefs.current[`zone:${zone}`] = el; }}
            >
              <header className="ef-zone__head">
                <h2 className="ef-sectitle">{zoneLabel(zone)}</h2>
                {zone !== NO_ZONE && <span className="ef-mono ef-muted">zone:{zone}</span>}
                {relays.length > 0 && <span className="ef-muted">· via {relays.join(', ')}</span>}
                <span style={{ flex: 1 }} />
                <span className="ef-muted">{t('map.resourceCount', { count: items.length })}</span>
              </header>
              <div className="ef-zone__grid">{items.map(renderNode)}</div>
            </section>
          );
        })}
      </div>
    </div>
  );

  const renderList = () => (
    <div className="ef-card" style={{ overflow: 'hidden' }}>
      <div style={{ overflowX: 'auto' }}>
        <table className="ef-table">
          <thead>
            <tr>
              <th>{t('map.resource')}</th><th>{t('map.address')}</th><th>{t('map.type')}</th>
              <th>{t('map.riskLabel')}</th><th>{t('map.access')}</th><th>{t('map.sessionCol')}</th><th>{t('map.route')}</th>
            </tr>
          </thead>
          <tbody>
            {grouped.map(({ zone, items }) => (
              <React.Fragment key={zone || 'none'}>
                <tr className="ef-table__group">
                  <td colSpan={7}>
                    <strong>{zoneLabel(zone)}</strong>
                    {zone !== NO_ZONE && <span className="ef-mono ef-muted"> zone:{zone}</span>}
                    <span className="ef-muted"> · {t('map.resourceCount', { count: items.length })}</span>
                  </td>
                </tr>
                {items.map((resource) => {
                  const state = sessionState(resource);
                  const list = sessionsByResource[resource.id] || [];
                  const risk = normalizeRiskLevel(resource.riskLevel);
                  const route = routes[resource.id];
                  return (
                    <tr
                      key={resource.id}
                      className={`${state === 'mine' ? 'is-mine ' : ''}${resource.id === selectedId ? 'is-selected' : ''}`}
                      onClick={() => setSelectedId(resource.id)}
                      onDoubleClick={() => primaryAction(resource).run()}
                    >
                      <td>
                        <button type="button" className="ef-rowname" onClick={() => setSelectedId(resource.id)}>
                          <span className="ef-node__icon" style={{ width: 24, height: 24 }}><ResourceIcon protocol={protocolOf(resource)} /></span>
                          {resource.name}
                        </button>
                      </td>
                      <td className="ef-mono ef-text-2">{resource.target}:{resource.port}</td>
                      <td className="ef-text-2">{protocolOf(resource).toUpperCase()}</td>
                      <td><span className={`ef-badge ef-badge--${risk}`}>{t(`map.risk.${risk}`)}</span></td>
                      <td><span className="ef-status"><span className="ef-dot" style={{ background: dotColor({ ...resource }) }} />{accessLabel(resource)}</span></td>
                      <td className="ef-text-2">{list.length ? list.map((s) => `${s.operator} · #${s.id}`).join(', ') : '—'}</td>
                      <td className="ef-mono ef-muted">{!relaysEnabled ? <RelayLock onUnlock={onUnlockRelays} /> : route?.route === 'relay' ? route.relay : t('map.direct')}</td>
                    </tr>
                  );
                })}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  const lenses = [['acces', t('map.lens.access')], ['sessions', t('map.lens.sessions')], ['risque', t('map.lens.risk')], ['reseau', t('map.lens.network')]];

  return (
    <div className="ef ef-page ef-mappage">
      <div className="ef-mappage__main">
        {intro}
        <div className="ef-toolbar">
          <div className="ef-seg" role="group" aria-label={t('map.view')}>
            <button type="button" className={view === 'carte' ? 'is-on' : ''} aria-pressed={view === 'carte'} onClick={() => chooseView('carte')}>{t('map.viewMap')}</button>
            <button type="button" className={view === 'liste' ? 'is-on' : ''} aria-pressed={view === 'liste'} onClick={() => chooseView('liste')}>{t('map.viewList')}</button>
          </div>
          <label className="ef-search">
            <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="M20 20l-4-4" /></svg>
            <input ref={searchRef} value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t('map.searchPlaceholder')} aria-label={t('map.search')} />
            <kbd>Ctrl K</kbd>
          </label>
          {view === 'carte' ? (
            <div className="ef-seg" role="group" aria-label={t('map.lensLabel')}>
              {lenses.map(([id, label]) => (
                <button key={id} type="button" className={lens === id ? 'is-on' : ''} aria-pressed={lens === id} onClick={() => setLens(id)} title={id === 'reseau' && !relaysEnabled ? t('relayLock.hint') : undefined}>{label}{id === 'reseau' && !relaysEnabled && <LockIcon />}</button>
              ))}
            </div>
          ) : (
            <select className="ef-input" style={{ width: 'auto' }} value={zoneFilter} onChange={(e) => setZoneFilter(e.target.value)} aria-label={t('map.zone')}>
              <option value="all">{t('map.allZones')}</option>
              {zones.map((zone) => <option key={zone || 'none'} value={zone}>{zoneLabel(zone)}</option>)}
            </select>
          )}
          <label className="ef-check"><input type="checkbox" checked={mineOnly} onChange={(e) => setMineOnly(e.target.checked)} />{t('map.mineOnly')}</label>
          <span style={{ flex: 1 }} />
          <span className="ef-muted" style={{ fontSize: 12 }}>{t('map.resourceCount', { count: visible.length })}</span>
        </div>

        {error && <div className="ef-alert ef-alert--danger">{error}</div>}
        {!loading && !resources.length ? (
          <section className="ef-card ef-soon" style={{ margin: '24px 0' }}>
            <h1>{t('map.emptyTitle')}</h1>
            <p>{canManage ? t('map.emptyAdmin') : t('map.emptyUser')}</p>
            {canManage && <button type="button" className="ef-btn ef-btn--primary" onClick={onAddResource}>{t('map.addResource')}</button>}
          </section>
        ) : view === 'carte' ? renderMap() : renderList()}

        {view === 'carte' && grouped.some(({ zone }) => zone === NO_ZONE) && canManage && (
          <p className="ef-muted" style={{ fontSize: 12, margin: 0 }}>{t('map.zoneHint')}</p>
        )}

        {todayLog.length > 0 && (
          <section className="ef-card ef-log">
            <header className="ef-log__head">
              <h2 className="ef-sectitle">{t('map.today')}</h2>
              <span className="ef-muted">{t('map.todayHint')}</span>
              <span style={{ flex: 1 }} />
              {focus && <button type="button" className="ef-btn ef-btn--sm" onClick={() => setFocusEvent(null)}>{t('map.showAll')}</button>}
            </header>
            <table className="ef-table ef-table--compact">
              <tbody>
                {todayLog.map((item) => (
                  <tr key={item.id} className={focusEvent === item.id ? 'is-selected' : ''} onClick={() => setFocusEvent(focusEvent === item.id ? null : item.id)}>
                    <td className="ef-mono ef-muted" style={{ width: 70 }}>{new Date(item.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</td>
                    <td className="ef-mono" style={{ width: 220 }}>{item.type}</td>
                    <td style={{ width: 120 }}>{item.actor}</td>
                    <td className="ef-mono ef-text-2">{item.target || (item.resourceId ? `#${item.resourceId}` : '')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        )}
      </div>

      <aside className="ef-insp" aria-label={t('map.details')}>{renderInspector()}</aside>
    </div>
  );
}
