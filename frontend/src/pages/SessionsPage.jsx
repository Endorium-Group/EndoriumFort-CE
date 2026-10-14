import React, { useEffect, useMemo, useRef, useState } from 'react';
import ConfirmButton from '../ui/ConfirmButton.jsx';
import { useI18n } from '../i18n.jsx';
import { fetchSessionDna } from '../api.js';
import TerminalSlot from '../ui/TerminalSlot.jsx';
import RelayLock from '../ui/RelayLock.jsx';
import {
  formatClock,
  formatDuration,
  formatRemaining,
  formatWhen,
  initialsOf,
  privilegeWindow,
  useNow
} from '../ui/sessions.js';

const protocolOf = (session) => String(session?.protocol || '').toLowerCase();
const isWeb = (session) => ['http', 'https'].includes(protocolOf(session));

const Chevron = () => (
  <svg className="ef-icon ef-muted" viewBox="0 0 24 24" aria-hidden="true" style={{ width: 14, height: 14 }}>
    <path d="M9 6l6 6-6 6" />
  </svg>
);

function SnippetMenu({ snippets, disabled, onSend, label, command, onLabelChange, onCommandChange, onAdd, onRemove }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const onDown = (event) => {
      if (ref.current && !ref.current.contains(event.target)) setOpen(false);
    };
    const onKey = (event) => { if (event.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <div className="ef-snip" ref={ref}>
      <button type="button" className="ef-btn" aria-expanded={open} onClick={() => setOpen((value) => !value)}>
        {t('sess.snippets')}
      </button>
      {open && (
        <div className="ef-snip__panel">
          {disabled && <p className="ef-snip__hint">{t('sess.snippetsNeedLive')}</p>}
          <ul className="ef-snip__list">
            {snippets.map((snippet) => (
              <li key={snippet.id}>
                <div className="ef-snip__text">
                  <strong>{snippet.label}</strong>
                  <code>{snippet.command}</code>
                </div>
                <div className="ef-snip__acts">
                  <button type="button" className="ef-btn ef-btn--sm" disabled={disabled} onClick={() => onSend(snippet, false)} title={t('sess.insertHint')}>
                    {t('sess.insert')}
                  </button>
                  <button type="button" className="ef-btn ef-btn--sm" disabled={disabled} onClick={() => { onSend(snippet, true); setOpen(false); }}>
                    {t('sess.run')}
                  </button>
                  {snippet.custom && (
                    <button type="button" className="ef-btn ef-btn--sm ef-btn--link" onClick={() => onRemove(snippet.id)} aria-label={t('common.delete')}>
                      ×
                    </button>
                  )}
                </div>
              </li>
            ))}
          </ul>
          <form
            className="ef-snip__add"
            onSubmit={(event) => {
              event.preventDefault();
              onAdd();
            }}
          >
            <input className="ef-input" value={label} onChange={(event) => onLabelChange(event.target.value)} placeholder={t('sess.snippetName')} aria-label={t('sess.snippetName')} />
            <input className="ef-input ef-mono" value={command} onChange={(event) => onCommandChange(event.target.value)} placeholder="tail -n 80 /var/log/syslog" aria-label={t('sess.snippetCommand')} />
            <button type="submit" className="ef-btn ef-btn--sm" disabled={!label.trim() || !command.trim()}>{t('sess.addSnippet')}</button>
          </form>
        </div>
      )}
    </div>
  );
}

function useSessionEvents(session, { enabled, dnaEnabled, auditItems }) {
  const [dna, setDna] = useState(null);
  const id = session?.id;

  useEffect(() => {
    setDna(null);
    if (!enabled || !dnaEnabled || !id) return undefined;
    let active = true;
    fetchSessionDna(id)
      .then((data) => { if (active) setDna(data); })
      .catch(() => { if (active) setDna({ failed: true }); });
    return () => { active = false; };
  }, [id, enabled, dnaEnabled]);

  const fromAudit = useMemo(() => {
    if (!enabled || !id) return [];
    return (auditItems || [])
      .filter((item) => {
        if (!item.payloadIsJson) return false;
        try {
          return Number(JSON.parse(item.payloadRaw || '{}').sessionId) === Number(id);
        } catch (_) {
          return false;
        }
      })
      .map((item) => ({ key: `a-${item.id}`, type: item.type, at: item.createdAt, actor: item.actor }))
      .sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
  }, [auditItems, id, enabled]);

  if (dna && !dna.failed && Array.isArray(dna.entries) && dna.entries.length) {
    return {
      verified: !!dna.verified,
      fromChain: true,
      items: dna.entries.map((entry) => ({ key: `d-${entry.id}`, type: entry.eventType, at: entry.createdAt }))
    };
  }
  return { verified: null, fromChain: false, items: fromAudit };
}

const eventTone = (type) => {
  const value = String(type || '');
  if (value.includes('block') || value.includes('deny') || value.includes('fail') || value.includes('terminate')) return 'var(--ef-danger)';
  if (value.includes('elevation') || value.includes('sudo')) return 'var(--ef-warn)';
  if (value === 'session.create') return 'var(--ef-priv)';
  return 'var(--ef-line-2)';
};

function SessionDetails({ session, resource, route, relaysEnabled, onUnlockRelays, now, canViewAudit, dnaEnabled, auditItems, canEnd, onTerminate, onOpenAudit, onOpenRecordings }) {
  const { t, locale } = useI18n();
  const events = useSessionEvents(session, { enabled: canViewAudit, dnaEnabled, auditItems });

  if (!session) {
    return (
      <aside className="ef-insp" aria-label={t('sess.details')}>
        <div className="ef-insp__empty">
          <p>{t('sess.selectHint')}</p>
        </div>
      </aside>
    );
  }

  const active = session.status === 'active';
  const span = privilegeWindow(session, now);
  const grant = session.grant;
  const opened = new Date(session.createdAt);

  return (
    <aside className="ef-insp" aria-label={t('sess.details')}>
      <div className="ef-insp__head ef-sesshead">
        <span className={active ? 'ef-avatar ef-avatar--priv' : 'ef-avatar'}>{initialsOf(session.operator)}</span>
        <div style={{ minWidth: 0 }}>
          <div className="ef-insp__title">{t('sess.sessionNo', { id: session.id })}</div>
          <div className="ef-muted" style={{ fontSize: 12 }}>
            {session.operator} · {t('sess.openedAt', { time: formatWhen(opened, locale) })}
          </div>
        </div>
      </div>
      <div className="ef-insp__sec">
        <dl className="ef-kv">
          <dt>{t('map.resource')}</dt>
          <dd className="ef-mono">{resource?.name || session.target}</dd>
          <dt>{t('map.address')}</dt>
          <dd className="ef-mono">{session.target}:{session.port}</dd>
          <dt>{t('sess.account')}</dt>
          <dd className="ef-mono">{session.user || '—'}</dd>
          <dt>{t('sess.protocol')}</dt>
          <dd className="ef-mono">{protocolOf(session).toUpperCase() || '—'}</dd>
          <dt>{t('map.route')}</dt>
          <dd>{!relaysEnabled ? <RelayLock onUnlock={onUnlockRelays} /> : route?.route === 'relay' ? t('sess.viaRelay', { relay: route.relayLabel || '?' }) : t('map.direct')}</dd>
          {(grant?.justification || grant?.purpose) && (
            <>
              <dt>{t('sess.reason')}</dt>
              <dd>{grant.justification || grant.purpose}</dd>
            </>
          )}
          {grant?.ticketId && (
            <>
              <dt>{t('sess.ticket')}</dt>
              <dd className="ef-mono">{grant.ticketId}</dd>
            </>
          )}
          {Number(grant?.approvalRef) > 0 && (
            <>
              <dt>{t('sess.approval')}</dt>
              <dd>{t('sess.requestNo', { id: grant.approvalRef })}</dd>
            </>
          )}
          {active && span && (
            <>
              <dt>{t('sess.accessEnds')}</dt>
              <dd>
                {formatClock(span.expiresAt, locale)}{' '}
                <span className="ef-muted">({t('sess.inTime', { time: formatRemaining(span.remaining) })})</span>
              </dd>
            </>
          )}
          {!active && session.terminatedAt && (
            <>
              <dt>{t('sess.closedAt')}</dt>
              <dd>{formatWhen(session.terminatedAt, locale)}</dd>
            </>
          )}
        </dl>
        <div className="ef-insp__actions">
          {canViewAudit && (
            <button type="button" className="ef-btn ef-btn--sm" onClick={() => onOpenAudit(session.id)}>{t('sess.openJournal')}</button>
          )}
          {canViewAudit && !isWeb(session) && (
            <button type="button" className="ef-btn ef-btn--sm" onClick={() => onOpenRecordings(session.id)}>{t('sess.recordings')}</button>
          )}
          {active && canEnd && (
            <ConfirmButton className="ef-btn ef-btn--sm ef-btn--danger" confirmLabel={t('sess.confirmEnd')} onConfirm={() => onTerminate(session.id)}>
              {t('sess.end')}
            </ConfirmButton>
          )}
        </div>
      </div>
      {canViewAudit && (
        <div className="ef-insp__sec">
          <h3 className="ef-evhead">
            {t('sess.events')}
            {events.fromChain && (
              <span className={events.verified ? 'ef-evchain is-ok' : 'ef-evchain is-bad'}>
                {events.verified ? t('sess.chainOk') : t('sess.chainBroken')}
              </span>
            )}
          </h3>
          {events.items.length ? (
            <ol className="ef-ev">
              {events.items.map((event) => (
                <li key={event.key}>
                  <span className="ef-mono ef-muted ef-ev__t">{formatClock(new Date(event.at), locale)}</span>
                  <span className="ef-ev__rail"><span className="ef-dot" style={{ background: eventTone(event.type) }} /></span>
                  <span className="ef-mono ef-ev__type">{event.type}</span>
                </li>
              ))}
            </ol>
          ) : (
            <p className="ef-muted" style={{ margin: 0, fontSize: 12.5 }}>{t('sess.noEvents')}</p>
          )}
        </div>
      )}
    </aside>
  );
}

export default function SessionsPage({
  sessions,
  resources,
  currentUser,
  canOperate,
  canViewAudit,
  dnaEnabled,
  relayHints,
  relaysEnabled,
  onUnlockRelays,
  auditItems,
  loading,
  error,
  terminalHost,
  activeTerminalSession,
  terminalStatus,
  terminalError,
  terminalInfo,
  sshPassword,
  onSshPasswordChange,
  onConnectTerminal,
  onOpenTerminal,
  onRefitTerminal,
  snippets,
  snippetLabel,
  snippetCommand,
  onSnippetLabelChange,
  onSnippetCommandChange,
  onSendSnippet,
  onAddSnippet,
  onRemoveSnippet,
  shadowSession,
  shadowStatus,
  shadowTermRef,
  onObserve,
  onCloseShadow,
  onOpenVnc,
  onTerminate,
  onOpenAudit,
  onOpenRecordings,
  onNewSession
}) {
  const { t, locale } = useI18n();
  const now = useNow(30000);
  const workRef = useRef(null);
  const searchRef = useRef(null);

  // Workspace tabs: my active sessions (plus whatever the terminal currently shows).
  const mine = useMemo(() => {
    const list = sessions.filter((s) => s.status === 'active' && s.operator === currentUser);
    if (activeTerminalSession && !list.some((s) => s.id === activeTerminalSession.id)) {
      const current = sessions.find((s) => s.id === activeTerminalSession.id) || activeTerminalSession;
      if (current.status === 'active') list.push(current);
    }
    return list.sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt));
  }, [sessions, currentUser, activeTerminalSession]);

  const [view, setView] = useState(() => (activeTerminalSession ? `s:${activeTerminalSession.id}` : 'all'));
  const [listMode, setListMode] = useState('active');
  const [query, setQuery] = useState('');
  // '' = everyone; otherwise one operator (the checkbox "mine only" sets currentUser).
  const [operator, setOperator] = useState('');
  const [picked, setPicked] = useState(null);

  // Follow the terminal: a session opened from the map shows up as the current tab.
  useEffect(() => {
    if (activeTerminalSession) setView(`s:${activeTerminalSession.id}`);
  }, [activeTerminalSession?.id]);

  useEffect(() => {
    if (shadowSession) setView('shadow');
    else setView((value) => (value === 'shadow' ? 'all' : value));
  }, [shadowSession?.id]);

  const current = view.startsWith('s:') ? sessions.find((s) => `s:${s.id}` === view) || null : null;
  const currentIsTerminal = !!current && protocolOf(current) === 'ssh' && activeTerminalSession?.id === current.id;

  // A tab whose session ended or disappeared falls back to the list.
  useEffect(() => {
    if (!view.startsWith('s:')) return;
    if (current && current.status === 'active') return;
    if (current) setPicked(current.id);
    setView('all');
  }, [view, current]);

  // xterm cannot measure itself while hidden; refit whenever it becomes visible again.
  useEffect(() => {
    if (!currentIsTerminal) return undefined;
    const frame = window.requestAnimationFrame(() => onRefitTerminal());
    return () => window.cancelAnimationFrame(frame);
  }, [currentIsTerminal, view]);

  // The observer terminal is bound to this page's DOM: stop observing when leaving.
  useEffect(() => () => onCloseShadow(), []);

  useEffect(() => {
    const onFull = () => window.requestAnimationFrame(() => onRefitTerminal());
    document.addEventListener('fullscreenchange', onFull);
    return () => document.removeEventListener('fullscreenchange', onFull);
  }, [onRefitTerminal]);

  useEffect(() => {
    const onKey = (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k' && view === 'all') {
        event.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [view]);

  const resourceById = useMemo(() => new Map(resources.map((r) => [Number(r.id), r])), [resources]);
  const resourceOf = (session) =>
    resourceById.get(Number(session?.resourceId)) ||
    resources.find((r) => r.target === session?.target && Number(r.port) === Number(session?.port)) ||
    null;
  const nameOf = (session) => resourceOf(session)?.name || session.target;

  const activeCount = sessions.filter((s) => s.status === 'active').length;
  // Operators present in the current tab, with their session count. Only
  // admins and auditors receive other people's sessions, so for an operator
  // this holds just themselves and the plain checkbox is shown instead.
  const operators = useMemo(() => {
    const counts = new Map();
    sessions
      .filter((s) => (listMode === 'active' ? s.status === 'active' : s.status !== 'active'))
      .forEach((s) => { if (s.operator) counts.set(s.operator, (counts.get(s.operator) || 0) + 1); });
    sessions.forEach((s) => { if (s.operator && !counts.has(s.operator)) counts.set(s.operator, 0); });
    return [...counts.entries()].sort((a, b) => (a[0] === currentUser ? -1 : b[0] === currentUser ? 1 : a[0].localeCompare(b[0])));
  }, [sessions, listMode, currentUser]);
  const manyOperators = operators.length > 1;
  const listed = useMemo(() => {
    const q = query.trim().toLowerCase();
    return sessions
      .filter((s) => (listMode === 'active' ? s.status === 'active' : s.status !== 'active'))
      .filter((s) => !operator || s.operator === operator)
      .filter((s) => {
        if (!q) return true;
        const resource = resourceById.get(Number(s.resourceId));
        return [String(s.id), s.operator, s.user, s.target, s.protocol, resource?.name]
          .some((value) => String(value || '').toLowerCase().includes(q));
      })
      .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
  }, [sessions, listMode, operator, query, resourceById]);

  const openTab = (session) => {
    if (protocolOf(session) === 'ssh' && activeTerminalSession?.id !== session.id) onOpenTerminal(session);
    setView(`s:${session.id}`);
  };

  const canEnd = (session) => canOperate || session.operator === currentUser;
  const detailSession = view === 'all' ? sessions.find((s) => s.id === picked) || null : view === 'shadow' ? shadowSession : current;

  const statusLabel = {
    live: t('sess.statusLive'),
    connecting: t('sess.statusConnecting'),
    closed: t('sess.statusClosed'),
    error: t('sess.statusError'),
    idle: t('sess.statusIdle')
  };

  const toggleFullscreen = () => {
    if (document.fullscreenElement) document.exitFullscreen?.();
    else workRef.current?.requestFullscreen?.();
  };

  const renderRowActions = (session) => {
    const active = session.status === 'active';
    const mineRow = session.operator === currentUser;
    return (
      <span className="ef-rowacts">
        {active && mineRow && (
          <button type="button" className="ef-btn ef-btn--sm" onClick={(event) => { event.stopPropagation(); openTab(session); }}>
            {t('map.resume')}
          </button>
        )}
        {active && !mineRow && canViewAudit && protocolOf(session) === 'ssh' && (
          <button type="button" className="ef-btn ef-btn--sm" onClick={(event) => { event.stopPropagation(); onObserve(session); }}>
            {t('sess.observe')}
          </button>
        )}
        {active && canEnd(session) && (
          <ConfirmButton className="ef-btn ef-btn--sm ef-btn--danger" confirmLabel={t('sess.confirmEnd')} onConfirm={() => onTerminate(session.id)}>
            {t('sess.end')}
          </ConfirmButton>
        )}
      </span>
    );
  };

  const renderList = () => (
    <div className="ef-sesslist">
      <div className="ef-toolbar ef-sesslist__bar">
        <div className="ef-seg" role="group" aria-label={t('sess.filter')}>
          <button type="button" className={listMode === 'active' ? 'is-on' : ''} aria-pressed={listMode === 'active'} onClick={() => setListMode('active')}>
            {t('sess.active')} <span className="ef-muted">{activeCount}</span>
          </button>
          <button type="button" className={listMode === 'history' ? 'is-on' : ''} aria-pressed={listMode === 'history'} onClick={() => setListMode('history')}>
            {t('sess.history')}
          </button>
        </div>
        <label className="ef-search">
          <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="M20 20l-4-4" /></svg>
          <input ref={searchRef} value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t('sess.searchPlaceholder')} aria-label={t('map.search')} />
          <kbd>Ctrl K</kbd>
        </label>
        {manyOperators ? (
          <select className="ef-input ef-sesslist__operator" value={operator} onChange={(event) => setOperator(event.target.value)} aria-label={t('sess.operator')}>
            <option value="">{t('sess.allOperators')}</option>
            {operators.map(([name, count]) => (
              <option key={name} value={name}>
                {name === currentUser ? t('sess.operatorMe', { name }) : name} · {count}
              </option>
            ))}
          </select>
        ) : (
          <label className="ef-check">
            <input type="checkbox" checked={operator === currentUser} onChange={(event) => setOperator(event.target.checked ? currentUser : '')} />
            {t('sess.mineOnly')}
          </label>
        )}
      </div>
      {error && <div className="ef-alert ef-alert--danger" style={{ margin: '0 14px 12px' }}>{error}</div>}
      <div style={{ overflowX: 'auto' }}>
        <table className="ef-table">
          <thead>
            <tr>
              <th>#</th>
              <th>{t('sess.operator')}</th>
              <th>{t('map.resource')}</th>
              <th>{t('sess.account')}</th>
              <th>{t('sess.protocol')}</th>
              <th>{t('map.route')}</th>
              <th>{t('sess.opened')}</th>
              <th>{listMode === 'active' ? t('sess.remaining') : t('sess.duration')}</th>
              <th><span className="ef-sr-only">{t('sess.actions')}</span></th>
            </tr>
          </thead>
          <tbody>
            {listed.map((session) => {
              const route = relayHints[session.id];
              const span = privilegeWindow(session, now);
              const opened = Date.parse(session.createdAt);
              const ended = Date.parse(session.terminatedAt || '');
              const mineRow = session.operator === currentUser;
              return (
                <tr
                  key={session.id}
                  className={[picked === session.id ? 'is-selected' : '', mineRow && session.status === 'active' ? 'is-mine' : ''].join(' ').trim() || undefined}
                  onClick={() => setPicked(session.id)}
                  onDoubleClick={() => { if (session.status === 'active' && mineRow) openTab(session); }}
                >
                  <td className="ef-mono ef-muted">{session.id}</td>
                  <td>
                    <span className="ef-status">
                      <span className="ef-dot" style={{ background: session.status !== 'active' ? 'var(--ef-line-2)' : mineRow ? 'var(--ef-priv)' : 'var(--ef-accent)' }} />
                      {manyOperators && operator !== session.operator ? (
                        <button
                          type="button"
                          className="ef-linkish"
                          title={t('sess.onlyOperator', { name: session.operator })}
                          onClick={(event) => { event.stopPropagation(); setOperator(session.operator); }}
                        >
                          {session.operator}
                        </button>
                      ) : session.operator}
                    </span>
                  </td>
                  <td className="ef-mono">{nameOf(session)}</td>
                  <td className="ef-mono ef-text-2">{session.user || '—'}</td>
                  <td className="ef-mono ef-text-2">{protocolOf(session).toUpperCase()}</td>
                  <td className="ef-text-2">{!relaysEnabled ? <RelayLock onUnlock={onUnlockRelays} /> : route?.route === 'relay' ? route.relayLabel || t('sess.relay') : t('map.direct')}</td>
                  <td className="ef-text-2">{formatWhen(session.createdAt, locale)}</td>
                  <td className="ef-text-2">
                    {listMode === 'active'
                      ? span ? formatRemaining(span.remaining) : <span className="ef-muted">{t('sess.noLimit')}</span>
                      : Number.isNaN(ended) ? '—' : formatDuration(ended - opened, locale)}
                  </td>
                  <td style={{ textAlign: 'right' }}>{renderRowActions(session)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!listed.length && (
          <div className="ef-sessempty">
            <p>
              {loading ? t('common.loading')
                : operator && operator !== currentUser ? t(listMode === 'active' ? 'sess.noActiveFor' : 'sess.noHistoryFor', { name: operator })
                : listMode === 'active' ? t('sess.noActive') : t('sess.noHistory')}
            </p>
            {operator && manyOperators && !loading && (
              <button type="button" className="ef-btn" onClick={() => setOperator('')}>{t('sess.allOperators')}</button>
            )}
            {listMode === 'active' && !loading && !operator && (
              <button type="button" className="ef-btn" onClick={onNewSession}>{t('sess.openFromMap')}</button>
            )}
          </div>
        )}
      </div>
    </div>
  );

  const renderPath = (session) => {
    const route = relayHints[session.id];
    return (
      <span className="ef-path">
        <span className="ef-mono">{session.operator}</span><Chevron />
        <span className="ef-mono">{t('map.bastion')}</span><Chevron />
        {!relaysEnabled ? <RelayLock onUnlock={onUnlockRelays} /> : <span className="ef-mono">{route?.route === 'relay' ? route.relayLabel || t('sess.relay') : t('map.direct')}</span>}<Chevron />
        <span className="ef-mono" style={{ fontWeight: 600 }}>{session.target}:{session.port}</span>
        {session.user && <span className="ef-muted">{t('sess.asAccount')} <span className="ef-mono">{session.user}</span></span>}
      </span>
    );
  };

  const renderWorkspaceBody = (session) => {
    const protocol = protocolOf(session);
    if (protocol === 'ssh') return null; // the terminal host below is always mounted
    if (protocol === 'vnc') {
      return (
        <div className="ef-stage__msg">
          <p className="ef-stage__title">{t('sess.vncTitle')}</p>
          <p>{t('sess.vncText')}</p>
          <button type="button" className="ef-btn ef-btn--primary" onClick={() => onOpenVnc(session)}>{t('sess.openDisplay')}</button>
        </div>
      );
    }
    if (isWeb(session)) {
      return (
        <div className="ef-stage__msg">
          <p className="ef-stage__title">{t('sess.webTitle')}</p>
          <p>{t('sess.webText')}</p>
          <button type="button" className="ef-btn ef-btn--primary" onClick={() => window.open(`/?rbi=${session.id}`, '_blank')}>
            {t('sess.openBrowser')}
          </button>
        </div>
      );
    }
    return (
      <div className="ef-stage__msg">
        <p className="ef-stage__title">{t('sess.tunnelTitle')}</p>
        <p>{t('sess.tunnelText')}</p>
      </div>
    );
  };

  const showConnectBar = currentIsTerminal && terminalStatus !== 'live';
  const span = current ? privilegeWindow(current, now) : null;

  return (
    <div className="ef ef-page ef-mappage">
      <div className="ef-mappage__main">
        <div className="ef-card ef-work" ref={workRef}>
          <div className="ef-stabs" role="tablist" aria-label={t('sess.openSessions')}>
            <button type="button" role="tab" aria-selected={view === 'all'} className={view === 'all' ? 'ef-stab is-on' : 'ef-stab'} onClick={() => setView('all')}>
              <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01" /></svg>
              <span className="ef-stab__label">{t('sess.allSessions')}</span>
            </button>
            {mine.map((session) => (
              <button
                key={session.id}
                type="button"
                role="tab"
                aria-selected={view === `s:${session.id}`}
                className={view === `s:${session.id}` ? 'ef-stab ef-mono is-on' : 'ef-stab ef-mono'}
                onClick={() => openTab(session)}
              >
                <span className="ef-dot" style={{ background: 'var(--ef-priv)' }} />
                {nameOf(session)}
                <span className="ef-muted ef-stab__id">#{session.id}</span>
              </button>
            ))}
            {shadowSession && (
              <button type="button" role="tab" aria-selected={view === 'shadow'} className={view === 'shadow' ? 'ef-stab ef-mono is-on' : 'ef-stab ef-mono'} onClick={() => setView('shadow')}>
                <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true" style={{ width: 14, height: 14 }}><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></svg>
                {nameOf(shadowSession)}
                <span className="ef-muted ef-stab__id">#{shadowSession.id}</span>
              </button>
            )}
            <button type="button" className="ef-stab ef-stab--add" onClick={onNewSession} aria-label={t('sess.newSession')} title={t('sess.newSession')}>
              <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14" /></svg>
            </button>
          </div>

          {view === 'all' && renderList()}

          {current && (
            <div className="ef-workbar">
              {renderPath(current)}
              <span style={{ flex: 1 }} />
              {protocolOf(current) === 'ssh' && (
                <SnippetMenu
                  snippets={snippets}
                  disabled={terminalStatus !== 'live'}
                  onSend={onSendSnippet}
                  label={snippetLabel}
                  command={snippetCommand}
                  onLabelChange={onSnippetLabelChange}
                  onCommandChange={onSnippetCommandChange}
                  onAdd={onAddSnippet}
                  onRemove={onRemoveSnippet}
                />
              )}
              {protocolOf(current) === 'ssh' && (
                <button type="button" className="ef-btn" onClick={toggleFullscreen} aria-label={t('sess.fullscreen')} title={t('sess.fullscreen')}>
                  <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5" /></svg>
                </button>
              )}
              {canEnd(current) && (
                <ConfirmButton confirmLabel={t('sess.confirmEnd')} onConfirm={() => onTerminate(current.id)}>
                  {t('sess.end')}
                </ConfirmButton>
              )}
            </div>
          )}

          {view === 'shadow' && shadowSession && (
            <div className="ef-workbar ef-workbar--watch">
              <span>
                {t('sess.observing')} <span className="ef-mono">{shadowSession.operator}</span> → <span className="ef-mono">{shadowSession.target}</span>
              </span>
              <span className="ef-muted">{statusLabel[shadowStatus] || shadowStatus}</span>
              <span style={{ flex: 1 }} />
              <button type="button" className="ef-btn" onClick={onCloseShadow}>{t('sess.stopObserving')}</button>
            </div>
          )}

          {showConnectBar && (
            <form
              className="ef-connectbar"
              onSubmit={(event) => {
                event.preventDefault();
                onConnectTerminal();
              }}
            >
              <span className={terminalError ? 'ef-connectbar__msg is-error' : 'ef-connectbar__msg'}>
                {terminalError || terminalInfo || t('sess.connectHint')}
              </span>
              <input
                className="ef-input"
                type="password"
                autoComplete="off"
                value={sshPassword}
                onChange={(event) => onSshPasswordChange(event.target.value)}
                placeholder={t('sess.sshPassword')}
                aria-label={t('sess.sshPassword')}
              />
              <button type="submit" className="ef-btn ef-btn--primary" disabled={terminalStatus === 'connecting'}>
                {terminalStatus === 'closed' || terminalStatus === 'error' ? t('sess.reconnect') : t('sess.connect')}
              </button>
            </form>
          )}
          {currentIsTerminal && terminalStatus === 'live' && (terminalError || terminalInfo) && (
            <div className={terminalError ? 'ef-connectbar__note is-error' : 'ef-connectbar__note'}>{terminalError || terminalInfo}</div>
          )}

          <div className="ef-stage" style={{ display: current || view === 'shadow' ? undefined : 'none' }}>
            {current && renderWorkspaceBody(current)}
            {/* Both terminal hosts stay mounted: xterm is attached to them once. */}
            <TerminalSlot className="ef-term" host={terminalHost} onAttach={onRefitTerminal} style={{ display: currentIsTerminal ? undefined : 'none' }} />
            <div className="ef-term" ref={shadowTermRef} style={{ display: view === 'shadow' ? undefined : 'none' }} />
          </div>

          {current && (
            <div className="ef-workfoot">
              {protocolOf(current) === 'ssh' && (
                <span className="ef-status">
                  <span className="ef-dot" style={{ background: terminalStatus === 'live' ? 'var(--ef-ok)' : terminalStatus === 'error' ? 'var(--ef-danger)' : 'var(--ef-line-2)' }} />
                  {statusLabel[terminalStatus] || terminalStatus}
                </span>
              )}
              <span>{t('sess.openedAt', { time: formatWhen(current.createdAt, locale) })}</span>
              {span && <span>{t('sess.endsAt', { time: formatClock(span.expiresAt, locale), left: formatRemaining(span.remaining) })}</span>}
            </div>
          )}
        </div>
      </div>
      <SessionDetails
        session={detailSession}
        resource={detailSession ? resourceOf(detailSession) : null}
        route={detailSession ? relayHints[detailSession.id] : null}
        relaysEnabled={relaysEnabled}
        onUnlockRelays={onUnlockRelays}
        now={now}
        canViewAudit={canViewAudit}
        dnaEnabled={dnaEnabled}
        auditItems={auditItems}
        canEnd={detailSession ? canEnd(detailSession) : false}
        onTerminate={onTerminate}
        onOpenAudit={onOpenAudit}
        onOpenRecordings={onOpenRecordings}
      />
    </div>
  );
}
