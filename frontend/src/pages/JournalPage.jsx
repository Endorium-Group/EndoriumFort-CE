import React, { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import { useI18n } from '../i18n.jsx';
import { normalizeRiskLevel } from '../accessPolicy.js';
import AuditIntegrity from '../ui/AuditIntegrity.jsx';
import { fetchAuditPage } from '../api.js';

const PAGE_SIZE = 100;

const parsePayload = (item) => {
  if (!item?.payloadIsJson) return null;
  try {
    const value = JSON.parse(item.payloadRaw || '{}');
    return value && typeof value === 'object' ? value : null;
  } catch (_) {
    return null;
  }
};

// Same rules as the server's category filter (backend/src/audit_query.cc).
const FAILURE = /fail|denied|deny|block|reject|rate_limited|error|unjustified|anomaly|incident|detection|containment/;
const ADMIN = /^(resource|user|access_policy|access_profile|relay|license|integration|cluster|itdr\.rule|automation)\.|^access_request\.(approve|deny)$|^credential\.rotat/;

const toneOf = (type) => {
  if (FAILURE.test(type)) return 'var(--ef-danger)';
  if (type === 'session.create') return 'var(--ef-priv)';
  if (/grant\.issued|approve|success/.test(type)) return 'var(--ef-ok)';
  if (ADMIN.test(type)) return 'var(--ef-warn)';
  return 'var(--ef-line-2)';
};

// Excel/Sheets treat cells starting with = + - @ as formulas, even quoted.
const csvCell = (value) => {
  const raw = String(value ?? '');
  const guarded = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
  return `"${guarded.replace(/"/g, '""')}"`;
};

// The page searches the whole audit log on the server (archives included):
// every filter except "critical resources" is applied there, and further
// pages are fetched with the cursor the server returns.
export default function JournalPage({
  resources,
  sessionFilter,
  actorFocus,
  onActorFocusUsed,
  canViewRecordings,
  onRefresh,
  onClearSessionFilter,
  onFilterSession,
  onOpenRecordings
}) {
  const { t, locale } = useI18n();
  const searchRef = useRef(null);
  const [query, setQuery] = useState('');
  const [family, setFamily] = useState('');
  const [actor, setActor] = useState('');
  const [quick, setQuick] = useState('all');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [openId, setOpenId] = useState(null);
  const [search, setSearch] = useState({ items: [], next: '', loading: true, more: false, error: '' });
  const [facets, setFacets] = useState({ actors: [], families: [] });
  const [reloadTick, setReloadTick] = useState(0);
  // Typing in the search box waits a moment before asking the server.
  const [text, setText] = useState('');
  useEffect(() => {
    const timer = setTimeout(() => setText(query.trim().replace(/^#/, '')), 300);
    return () => clearTimeout(timer);
  }, [query]);
  const filters = useMemo(() => ({
    actor,
    family,
    category: quick === 'fail' ? 'failure' : quick === 'admin' ? 'admin' : '',
    from,
    to,
    q: text,
    session: sessionFilter || ''
  }), [actor, family, quick, from, to, text, sessionFilter]);
  const requestRef = useRef(0);

  useEffect(() => {
    const request = ++requestRef.current;
    setSearch((current) => ({ ...current, loading: true, error: '' }));
    fetchAuditPage({ ...filters, limit: PAGE_SIZE, facets: true })
      .then((page) => {
        if (request !== requestRef.current) return;
        setSearch({ items: page.items || [], next: page.next || '', loading: false, more: false, error: '' });
        if (page.facets) setFacets({ actors: page.facets.actors || [], families: page.facets.families || [] });
      })
      .catch((err) => {
        if (request !== requestRef.current) return;
        setSearch({ items: [], next: '', loading: false, more: false, error: err.message || t('journal.loadError') });
      });
  }, [filters, reloadTick]);

  const loadMore = () => {
    const request = requestRef.current;
    setSearch((current) => ({ ...current, more: true }));
    fetchAuditPage({ ...filters, limit: PAGE_SIZE, cursor: search.next })
      .then((page) => {
        if (request !== requestRef.current) return;
        setSearch((current) => ({ ...current, items: current.items.concat(page.items || []), next: page.next || '', more: false }));
      })
      .catch((err) => {
        if (request !== requestRef.current) return;
        // The archive holding the next page was purged meanwhile: start over.
        if (err.expired) setReloadTick((n) => n + 1);
        else setSearch((current) => ({ ...current, more: false, error: err.message || t('journal.loadError') }));
      });
  };
  const items = search.items;
  const loading = search.loading;
  const error = search.error;
  // "Refresh" also re-checks the audit chain.
  const [verifyTick, setVerifyTick] = useState(0);

  // Arriving from Administration > Users: show that person's events.
  useEffect(() => {
    if (!actorFocus) return;
    setActor(actorFocus);
    onActorFocusUsed?.();
  }, [actorFocus]);

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

  const resourceById = useMemo(() => new Map(resources.map((r) => [Number(r.id), r])), [resources]);

  const rows = useMemo(() => items.map((item) => {
    const payload = parsePayload(item) || {};
    const type = String(item.type || '');
    const resource = resourceById.get(Number(payload.resourceId)) || null;
    const target = resource?.name || payload.resourceName || payload.target || payload.subject || payload.requester || payload.username || '';
    const bits = [];
    if (payload.sessionId) bits.push(t('journal.sessionNo', { id: payload.sessionId }));
    if (type.startsWith('access_request') && payload.id) bits.push(t('journal.requestNo', { id: payload.id }));
    if (payload.ticketId) bits.push(payload.ticketId);
    ['command', 'rule', 'reason', 'message', 'method', 'justification', 'purpose'].forEach((key) => {
      if (payload[key] && typeof payload[key] === 'string') bits.push(payload[key]);
    });
    if (!item.payloadIsJson && item.payloadRaw) bits.push(item.payloadRaw);
    return {
      item,
      payload,
      type,
      resource,
      target,
      detail: bits.join(' · '),
      origin: payload.sourceIp || payload.ip || payload.clientIp || '',
      sessionId: Number(payload.sessionId) || 0
    };
  }).sort((a, b) => (Date.parse(b.item.createdAt) || 0) - (Date.parse(a.item.createdAt) || 0)), [items, resourceById, t]);

  const families = facets.families;
  const actors = !actor || facets.actors.includes(actor) ? facets.actors : [...facets.actors, actor];
  const hasOrigin = rows.some((r) => r.origin);

  // Only "critical resources" is applied here: the server does not know the
  // resources' risk level. It filters the events loaded so far.
  const filtered = useMemo(
    () => (quick === 'critical' ? rows.filter((row) => normalizeRiskLevel(row.resource?.riskLevel) === 'critical') : rows),
    [rows, quick]
  );

  const formatTime = (value) => {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '—';
    const tag = locale === 'fr' ? 'fr-FR' : 'en-GB';
    const time = date.toLocaleTimeString(tag, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    if (date.toDateString() === new Date().toDateString()) return time;
    return `${date.toLocaleDateString(tag, { day: 'numeric', month: 'short' })} ${time}`;
  };

  const exportCsv = () => {
    const header = ['id', 'createdAt', 'type', 'actor', 'role', 'target', 'detail', 'origin', 'payload'];
    const lines = filtered.map((row) => [
      row.item.id, row.item.createdAt, row.type, row.item.actor, row.item.role, row.target, row.detail, row.origin, row.item.payloadRaw
    ]);
    const csv = `﻿${[header, ...lines].map((line) => line.map(csvCell).join(',')).join('\n')}`;
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8;' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `endoriumfort-journal-${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const resetFilters = () => {
    setQuery('');
    setFamily('');
    setActor('');
    setQuick('all');
    setFrom('');
    setTo('');
    if (sessionFilter) onClearSessionFilter();
  };
  const filtersActive = query || family || actor || quick !== 'all' || sessionFilter || from || to;
  const quickFilters = [['all', t('journal.quickAll')], ['fail', t('journal.quickFail')], ['admin', t('journal.quickAdmin')], ['critical', t('journal.quickCritical')]];
  const columns = hasOrigin ? 7 : 6;

  return (
    <div className="ef ef-page ef-reqpage">
      <div className="ef-reqpage__head">
        <div>
          <h1>{t('journal.title')}</h1>
          <p>{t('journal.subtitle')}</p>
        </div>
        <span style={{ flex: 1 }} />
        <button type="button" className="ef-btn" onClick={() => { onRefresh?.(); setReloadTick((n) => n + 1); setVerifyTick((n) => n + 1); }} disabled={loading}>{t('common.refresh')}</button>
        <button type="button" className="ef-btn ef-btn--primary" onClick={exportCsv} disabled={!filtered.length}>
          <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v12M7 10l5 5 5-5M5 21h14" /></svg>
          {t('journal.export')}
        </button>
      </div>
      <AuditIntegrity refreshKey={verifyTick} />
      {error && <div className="ef-alert ef-alert--danger ef-reqpage__alert">{error}</div>}

      <div className="ef-card" style={{ overflow: 'hidden' }}>
        <div className="ef-toolbar ef-journal__bar">
          <label className="ef-search">
            <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="M20 20l-4-4" /></svg>
            <input ref={searchRef} value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t('journal.searchPlaceholder')} aria-label={t('map.search')} />
            <kbd>Ctrl K</kbd>
          </label>
          <select className="ef-input ef-journal__select" value={family} onChange={(event) => setFamily(event.target.value)} aria-label={t('journal.type')}>
            <option value="">{t('journal.allTypes')}</option>
            {families.map((value) => <option key={value} value={value}>{value}.*</option>)}
          </select>
          <select className="ef-input ef-journal__select" value={actor} onChange={(event) => setActor(event.target.value)} aria-label={t('journal.actor')}>
            <option value="">{t('journal.allActors')}</option>
            {actors.map((value) => <option key={value} value={value}>{value}</option>)}
          </select>
          <label className="ef-journal__date">
            <span>{t('journal.from')}</span>
            <input type="date" className="ef-input" value={from} max={to || undefined} onChange={(event) => setFrom(event.target.value)} />
          </label>
          <label className="ef-journal__date">
            <span>{t('journal.to')}</span>
            <input type="date" className="ef-input" value={to} min={from || undefined} onChange={(event) => setTo(event.target.value)} />
          </label>
          {sessionFilter && (
            <span className="ef-chip">
              {t('journal.sessionNo', { id: sessionFilter })}
              <button type="button" onClick={onClearSessionFilter} aria-label={t('journal.clearSession')}>×</button>
            </span>
          )}
          <span style={{ flex: 1 }} />
          <div className="ef-seg" role="group" aria-label={t('journal.quick')}>
            {quickFilters.map(([id, label]) => (
              <button key={id} type="button" className={quick === id ? 'is-on' : ''} aria-pressed={quick === id} onClick={() => setQuick(id)}>{label}</button>
            ))}
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="ef-table ef-journal">
            <thead>
              <tr>
                <th style={{ width: 22 }}><span className="ef-sr-only">{t('journal.details')}</span></th>
                <th>{t('journal.time')}</th>
                <th>{t('journal.event')}</th>
                <th>{t('journal.actor')}</th>
                <th>{t('journal.target')}</th>
                <th>{t('journal.detail')}</th>
                {hasOrigin && <th>{t('journal.origin')}</th>}
              </tr>
            </thead>
            <tbody>
              {filtered.map((row) => {
                const rowKey = row.item.key || row.item.id;
                const open = openId === rowKey;
                return (
                  <Fragment key={rowKey}>
                    <tr className={open ? 'is-open' : undefined} onClick={() => setOpenId(open ? null : rowKey)}>
                      <td>
                        <button type="button" className="ef-expander" aria-expanded={open} aria-label={t('journal.details')}>
                          <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true" style={{ width: 14, height: 14, transform: open ? 'rotate(90deg)' : undefined }}><path d="M9 6l6 6-6 6" /></svg>
                        </button>
                      </td>
                      <td className="ef-mono ef-text-2">{formatTime(row.item.createdAt)}</td>
                      <td><span className="ef-status ef-mono"><span className="ef-dot" style={{ background: toneOf(row.type) }} />{row.type}</span></td>
                      <td>{row.item.actor || '—'}</td>
                      <td className="ef-mono">{row.target || '—'}</td>
                      <td className="ef-text-2 ef-journal__detail" title={row.detail}>{row.detail || '—'}</td>
                      {hasOrigin && <td className="ef-mono ef-muted">{row.origin || '—'}</td>}
                    </tr>
                    {open && (
                      <tr className="ef-journal__open">
                        <td />
                        <td colSpan={columns}>
                          <div className="ef-journal__more">
                            <pre className="ef-json">{row.item.payloadIsJson ? JSON.stringify(row.payload, null, 2) : row.item.payloadRaw || '—'}</pre>
                            <div className="ef-journal__links">
                              <span className="ef-muted">{t('journal.goFurther')}</span>
                              <dl className="ef-kv">
                                <dt>{t('journal.eventId')}</dt><dd className="ef-mono">#{row.item.id}</dd>
                                <dt>{t('journal.role')}</dt><dd>{row.item.role || '—'}</dd>
                              </dl>
                              {row.item.actor && row.item.actor !== actor && (
                                <button type="button" className="ef-btn ef-btn--link" onClick={() => setActor(row.item.actor)}>
                                  {t('journal.allOfActor', { actor: row.item.actor })}
                                </button>
                              )}
                              {row.sessionId > 0 && Number(sessionFilter) !== row.sessionId && (
                                <button type="button" className="ef-btn ef-btn--link" onClick={() => onFilterSession(row.sessionId)}>
                                  {t('journal.allOfSession', { id: row.sessionId })}
                                </button>
                              )}
                              {row.sessionId > 0 && canViewRecordings && (
                                <button type="button" className="ef-btn ef-btn--link" onClick={() => onOpenRecordings(row.sessionId)}>
                                  {t('journal.recordingsOf', { id: row.sessionId })}
                                </button>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
          {!filtered.length && (
            <div className="ef-sessempty">
              <p>{loading ? t('common.loading') : filtersActive ? t('journal.noMatch') : t('journal.empty')}</p>
              {filtersActive && !loading && <button type="button" className="ef-btn" onClick={resetFilters}>{t('journal.reset')}</button>}
            </div>
          )}
        </div>
        <div className="ef-workfoot">
          <span>{t(search.next ? 'journal.countMore' : 'journal.countAll', { count: filtered.length })}</span>
          {search.next && (
            <button type="button" className="ef-btn ef-btn--sm" onClick={loadMore} disabled={search.more || loading}>
              {search.more ? t('common.loading') : t('journal.loadMore', { count: PAGE_SIZE })}
            </button>
          )}
          <span style={{ flex: 1 }} />
          <span>{t('journal.limitNote')}</span>
        </div>
      </div>
    </div>
  );
}
