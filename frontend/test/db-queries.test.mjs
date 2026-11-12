import test from 'node:test';
import assert from 'node:assert/strict';

import { filterQueries, outcomeOf, replayDelays, summarize, toQueries } from '../src/dbQueries.js';

const row = (type, createdAt, payload, key) => ({
  key: key || createdAt + type,
  type,
  actor: 'alice',
  createdAt,
  payloadIsJson: true,
  payloadRaw: JSON.stringify(payload)
});

// As /api/audit returns them: newest first, other families mixed in.
const items = [
  row('db.query', '2026-11-05T10:00:09Z', { sql: 'SELECT * FROM missing', error: 'relation does not exist', sqlstate: '42P01' }),
  row('db.query.blocked', '2026-11-05T10:00:05Z', { sql: 'DROP TABLE items', rule: 'drop' }),
  row('db.connect', '2026-11-05T10:00:00Z', { database: 'app' }),
  row('db.query', '2026-11-05T10:00:01Z', { sql: 'SELECT 1', rows: 1, durationMs: 2, command: 'SELECT', mode: 'simple' }, 'b'),
  row('db.query', '2026-11-05T10:00:01Z', { sql: 'SELECT count(*) FROM items', rows: 1, durationMs: 5 }, 'a'),
  { key: 'x', type: 'db.query', createdAt: '2026-11-05T10:00:02Z', payloadIsJson: false, payloadRaw: 'garbled' }
];

test('toQueries keeps only queries, oldest first, log order kept on ties', () => {
  const queries = toQueries(items);
  assert.deepEqual(queries.map((q) => q.sql), [
    'SELECT count(*) FROM items', // logged after "SELECT 1" in the newest-first list, so it ran first
    'SELECT 1',
    'DROP TABLE items',
    'SELECT * FROM missing'
  ]);
  assert.equal(queries[2].blocked, true);
  assert.equal(queries[2].rule, 'drop');
  assert.equal(queries[3].sqlstate, '42P01');
});

test('outcome, filters and summary', () => {
  const queries = toQueries(items);
  assert.deepEqual(queries.map(outcomeOf), ['ok', 'ok', 'blocked', 'error']);
  assert.equal(filterQueries(queries, { filter: 'blocked' }).length, 1);
  assert.equal(filterQueries(queries, { text: 'items' }).length, 2);
  assert.equal(filterQueries(queries, { filter: 'ok', text: 'select 1' }).length, 1);
  assert.deepEqual(summarize(queries), { total: 4, ok: 2, error: 1, blocked: 1, rows: 2, durationMs: 7 });
});

test('replayDelays follows real time, sped up and with long gaps capped', () => {
  const queries = toQueries(items);
  assert.deepEqual(replayDelays(queries), [0, 0, 3000, 3000]);
  assert.deepEqual(replayDelays(queries, { speed: 4 }), [0, 0, 1000, 1000]);
  assert.deepEqual(replayDelays(queries, { speed: 4, maxGapMs: 500 }), [0, 0, 500, 500]);
  assert.deepEqual(replayDelays([]), []);
});
