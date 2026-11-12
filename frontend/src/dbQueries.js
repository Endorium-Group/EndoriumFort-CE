// EndoriumFort — the queries of a database-proxy session, read from the audit
// log (db.query / db.query.blocked, see docs/database-proxy.md). Pure, so the
// replay timing and the filters are unit-tested (test/db-queries.test.mjs).

const parse = (item) => {
  if (!item?.payloadIsJson) return null;
  try {
    const value = JSON.parse(item.payloadRaw || '{}');
    return value && typeof value === 'object' ? value : null;
  } catch (_) {
    return null;
  }
};

// Audit rows (any order, any family) → the session's queries, oldest first.
export function toQueries(items) {
  const out = [];
  for (const item of items || []) {
    if (item?.type !== 'db.query' && item?.type !== 'db.query.blocked') continue;
    const p = parse(item);
    if (!p) continue;
    const at = Date.parse(item.createdAt);
    out.push({
      key: item.key || `${item.createdAt}-${out.length}`,
      at: Number.isFinite(at) ? at : 0,
      blocked: item.type === 'db.query.blocked',
      sql: String(p.sql || ''),
      truncated: !!p.sqlTruncated,
      mode: p.mode || 'simple',
      durationMs: Number(p.durationMs) || 0,
      rows: Number(p.rows) || 0,
      command: p.command || '',
      error: p.error || '',
      sqlstate: p.sqlstate || '',
      rule: p.rule || '',
      parameters: Number(p.parameters) || 0,
      database: p.database || '',
      dbUser: p.dbUser || '',
      actor: item.actor || ''
    });
  }
  // The log is read newest first; equal timestamps keep their log order.
  return out
    .map((q, index) => ({ q, index }))
    .sort((a, b) => a.q.at - b.q.at || b.index - a.index)
    .map(({ q }) => q);
}

export const outcomeOf = (q) => (q.blocked ? 'blocked' : q.error ? 'error' : 'ok');

// filter: 'all' | 'ok' | 'error' | 'blocked'; text: case-insensitive, in the SQL.
export function filterQueries(queries, { filter = 'all', text = '' } = {}) {
  const needle = String(text || '').trim().toLowerCase();
  return queries.filter((q) =>
    (filter === 'all' || outcomeOf(q) === filter) && (!needle || q.sql.toLowerCase().includes(needle)));
}

export function summarize(queries) {
  const s = { total: queries.length, ok: 0, error: 0, blocked: 0, rows: 0, durationMs: 0 };
  for (const q of queries) {
    s[outcomeOf(q)] += 1;
    s.rows += q.rows;
    s.durationMs += q.durationMs;
  }
  return s;
}

// Milliseconds to wait before showing each query during a replay, at `speed`
// times real time. Long pauses are shortened to `maxGapMs` so an idle hour
// does not stall the replay; the first query shows at once.
export function replayDelays(queries, { speed = 1, maxGapMs = 3000 } = {}) {
  const factor = speed > 0 ? speed : 1;
  return queries.map((q, i) => {
    if (i === 0) return 0;
    const gap = Math.max(0, q.at - queries[i - 1].at) / factor;
    return Math.min(gap, maxGapMs);
  });
}
