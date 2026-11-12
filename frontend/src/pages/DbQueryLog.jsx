// EndoriumFort — the SQL of a database-proxy session: every journaled query
// (db.query / db.query.blocked) in order, with filters and a replay that shows
// them again at their own pace. Read from /api/audit, so it needs audit.read.
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useI18n } from '../i18n.jsx';
import { fetchAuditPage } from '../api.js';
import { filterQueries, outcomeOf, replayDelays, summarize, toQueries } from '../dbQueries.js';

const PAGE = 500;
const MAX_PAGES = 20;  // 10 000 queries; beyond that, the journal is the tool
const SPEEDS = [1, 4, 16, 60];
const FILTERS = ['all', 'ok', 'error', 'blocked'];
// To the second: queries of one minute must stay apart in a replay.
const clock = (ms, locale) =>
  new Date(ms).toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit', second: '2-digit' });

const BADGE = { ok: 'ef-badge ef-badge--low', error: 'ef-badge ef-badge--high', blocked: 'ef-badge ef-badge--critical' };

async function loadAll(sessionId) {
  let items = [];
  let cursor = '';
  for (let i = 0; i < MAX_PAGES; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const page = await fetchAuditPage({ sessionId, family: 'db', limit: PAGE, cursor });
    items = items.concat(page.items || []);
    cursor = page.next || '';
    if (!cursor) return { items, complete: true };
  }
  return { items, complete: false };
}

export default function DbQueryLog({ sessionId, live = false }) {
  const { t, locale } = useI18n();
  const [state, setState] = useState({ items: [], complete: true, loading: true, error: '' });
  const [filter, setFilter] = useState('all');
  const [text, setText] = useState('');
  const [open, setOpen] = useState('');
  const [replay, setReplay] = useState({ on: false, playing: false, index: 0, speed: 4 });
  const timer = useRef(null);
  const selectedRef = useRef(null);

  const refresh = useCallback(() => {
    loadAll(sessionId)
      .then(({ items, complete }) => setState({ items, complete, loading: false, error: '' }))
      .catch((e) => setState((s) => ({ ...s, loading: false, error: e?.message || t('dbLog.loadError') })));
  }, [sessionId, t]);

  useEffect(() => {
    setState({ items: [], complete: true, loading: true, error: '' });
    refresh();
    if (!live) return undefined;
    const id = window.setInterval(refresh, 4000);
    return () => window.clearInterval(id);
  }, [refresh, live]);

  const queries = useMemo(() => toQueries(state.items), [state.items]);
  const shown = useMemo(() => filterQueries(queries, { filter, text }), [queries, filter, text]);
  const stats = useMemo(() => summarize(queries), [queries]);
  const delays = useMemo(() => replayDelays(shown, { speed: replay.speed }), [shown, replay.speed]);

  // Replay: reveal the filtered queries one by one, at their recorded pace.
  useEffect(() => {
    window.clearTimeout(timer.current);
    if (!replay.on || !replay.playing) return undefined;
    if (replay.index >= shown.length - 1) {
      setReplay((r) => ({ ...r, playing: false }));
      return undefined;
    }
    timer.current = window.setTimeout(
      () => setReplay((r) => ({ ...r, index: Math.min(r.index + 1, shown.length - 1) })),
      delays[replay.index + 1] || 0
    );
    return () => window.clearTimeout(timer.current);
  }, [replay, shown.length, delays]);

  useEffect(() => {
    if (replay.on) selectedRef.current?.scrollIntoView?.({ block: 'nearest' });
  }, [replay.on, replay.index]);

  const visible = replay.on ? shown.slice(0, replay.index + 1) : shown;
  const startReplay = () => setReplay((r) => ({ ...r, on: true, playing: true, index: 0 }));
  const stopReplay = () => setReplay((r) => ({ ...r, on: false, playing: false, index: 0 }));

  if (state.loading) return <p className="ef-muted">{t('dbLog.loading')}</p>;
  if (state.error) return <p className="ef-zwarn ef-small" role="alert">{state.error}</p>;

  return (
    <div className="ef-dblog">
      <div className="ef-dblog__stats ef-muted">
        {t('dbLog.summary', { total: stats.total, rows: stats.rows, ms: stats.durationMs })}
        {stats.error > 0 && <span className={BADGE.error}>{t('dbLog.errors', { n: stats.error })}</span>}
        {stats.blocked > 0 && <span className={BADGE.blocked}>{t('dbLog.blockedN', { n: stats.blocked })}</span>}
        {!state.complete && <span className="ef-hint">{t('dbLog.truncated')}</span>}
      </div>

      <div className="ef-row ef-dblog__bar">
        <div className="ef-seg" role="group" aria-label={t('dbLog.filter')}>
          {FILTERS.map((f) => (
            <button key={f} type="button" className={filter === f ? 'is-on' : ''} onClick={() => { setFilter(f); stopReplay(); }}>
              {t(`dbLog.filters.${f}`)}
            </button>
          ))}
        </div>
        <input
          className="ef-input ef-mono"
          value={text}
          placeholder={t('dbLog.search')}
          aria-label={t('dbLog.search')}
          onChange={(e) => { setText(e.target.value); stopReplay(); }}
          style={{ flex: '1 1 160px' }}
        />
        {!replay.on ? (
          <button type="button" className="ef-btn ef-btn--sm" disabled={!shown.length} onClick={startReplay}>{t('dbLog.replay')}</button>
        ) : (
          <>
            <button type="button" className="ef-btn ef-btn--sm" onClick={() => setReplay((r) => ({ ...r, playing: !r.playing }))}>
              {replay.playing ? t('dbLog.pause') : t('dbLog.resume')}
            </button>
            <button type="button" className="ef-btn ef-btn--sm" onClick={stopReplay}>{t('dbLog.stop')}</button>
            <span className="ef-mono ef-muted">{replay.index + 1}/{shown.length}</span>
          </>
        )}
        <select
          className="ef-input"
          value={replay.speed}
          aria-label={t('dbLog.speed')}
          onChange={(e) => setReplay((r) => ({ ...r, speed: Number(e.target.value) }))}
        >
          {SPEEDS.map((s) => <option key={s} value={s}>{`${s}×`}</option>)}
        </select>
      </div>

      {visible.length === 0 ? (
        <p className="ef-muted">{queries.length ? t('dbLog.noMatch') : t('dbLog.empty')}</p>
      ) : (
        <ol className="ef-dblog__list">
          {visible.map((q, i) => {
            const outcome = outcomeOf(q);
            const current = replay.on && i === replay.index;
            return (
              <li
                key={q.key}
                ref={current ? selectedRef : null}
                className={`ef-dblog__q${current ? ' is-on' : ''}${open === q.key ? ' is-open' : ''}`}
              >
                <button type="button" className="ef-dblog__head" onClick={() => setOpen(open === q.key ? '' : q.key)}>
                  <span className="ef-mono ef-muted">{clock(q.at, locale)}</span>
                  <span className={BADGE[outcome]}>{outcome === 'ok' ? (q.command || 'OK') : t(`dbLog.outcome.${outcome}`)}</span>
                  {outcome !== 'blocked' && (
                    <span className="ef-mono ef-muted">{t('dbLog.meta', { ms: q.durationMs, rows: q.rows })}</span>
                  )}
                  {q.mode !== 'simple' && <span className="ef-muted">{t(`dbLog.modes.${q.mode}`)}{q.parameters ? ` · ${t('dbLog.params', { n: q.parameters })}` : ''}</span>}
                </button>
                <pre className="ef-mono ef-dblog__sql">{q.sql}{q.truncated ? ' …' : ''}</pre>
                {q.blocked && <p className="ef-dblog__note">{t('dbLog.blockedBy', { rule: q.rule })}</p>}
                {q.error && <p className="ef-dblog__note">{q.sqlstate ? `${q.sqlstate} · ` : ''}{q.error}</p>}
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}
