# Database proxy (PostgreSQL)

**Enterprise** — license feature `database.proxy`.

A resource with protocol `postgres` is not a raw TCP tunnel: the bastion
**speaks the PostgreSQL protocol**. The operator's client never learns the
database password, every query is journaled, and a SQL guard can refuse
dangerous statements before they reach the server.

```
psql / DBeaver ──► agent (127.0.0.1:port) ══ WSS /ws/tunnel ══► bastion ──► PostgreSQL
                   any user, no password                       vaulted account, TLS
```

## Setting up a resource

In **Administration → Resources**, create a resource:

| Field | Value |
|---|---|
| Protocol | **PostgreSQL (database proxy)** |
| Address / port | the database server, e.g. `db.internal` / `5432` |
| TLS to the database | `prefer` (default), `require`, `verify-full` or `disable` — see below |
| Database account | the role the proxy logs in with (stored in the vault) |
| Secret | its password |
| SQL guard | refuses the statements listed under [SQL guard](#sql-guard) |

Access goes through the normal session flow: access policies, justification,
dual approval, MFA and maximum duration all apply. **Terminating the session
from the console cuts the connection** within a second, and a query still
running at that moment is journaled as interrupted.

Through the API, the fields are `protocol: "postgres"`, `sshUsername`,
`sshPassword` and `dbTlsMode`.

### TLS towards the database

| `dbTlsMode` | Behaviour |
|---|---|
| `prefer` | TLS when the server offers it, plain otherwise (libpq's default) |
| `require` | TLS mandatory; the certificate is **not** checked |
| `verify-full` | TLS mandatory; the certificate must chain to the system CAs, or to `ENDORIUMFORT_DB_CA_FILE`, and match the resource address |
| `disable` | never TLS |

The leg between the operator's client and the agent stays on the
operator's own machine (`127.0.0.1`); the agent ↔ bastion leg is the agent's
WSS connection. The proxy therefore answers the client's `SSLRequest` with
"no".

### Authentication towards the database

SCRAM-SHA-256 (the server's signature is verified, so an impostor server is
detected), MD5 and cleartext. SCRAM with channel binding only
(`SCRAM-SHA-256-PLUS` without plain SCRAM), GSSAPI and SSPI are not supported.

## Dynamic per-session roles

Tick **Throw-away role per session** on the resource (or
`PUT /api/db-proxy/dynamic/:resourceId` with `{enabled, grantRoles, ttlSeconds}`)
and nobody works as the resource's account any more. On a session's first
connection the proxy uses that account to create a role of its own:

```sql
CREATE ROLE "ef_3f9a1c2b" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS INHERIT
  PASSWORD 'SCRAM-SHA-256$4096:…' VALID UNTIL '2026-11-05T11:00:00Z';
GRANT "app_rw" TO "ef_3f9a1c2b";
```

- The role gets **only** the roles listed in *Roles granted* (`grantRoles`),
  and every connection of the session uses it; the journal's `dbUser` shows it.
- `VALID UNTIL` is the smaller of *Maximum validity* (`ttlSeconds`, 5 minutes
  to 7 days, default 1 hour) and the session's own limit: even if the bastion
  vanished, the role could not log in afterwards.
- Only the SCRAM verifier, computed by the bastion, is sent: a server that logs
  statements (`log_statement = all`) records no usable password.
- **When the session ends** (terminated, expired, or the reaper finding it gone
  after a restart), the proxy locks the role (`NOLOGIN`), ends its backends,
  runs `REASSIGN OWNED BY … TO CURRENT_USER` and `DROP OWNED BY …` in every
  database it used — objects it created are kept, owned by the management
  account — then `DROP ROLE`. A failure leaves the role `NOLOGIN` and is
  journaled with `result: "error"`.
- A scheduler job (`db-dynamic-role-reaper`, every 5 minutes) removes roles
  past their validity or whose session is no longer active.

The resource's account then only manages roles. It needs `CREATEROLE` and
`ADMIN OPTION` on each granted role; on PostgreSQL 16+ the creator also needs
`createrole_self_grant = 'set, inherit'` (or superuser) for `REASSIGN OWNED`:

```sql
CREATE ROLE ef_manager LOGIN CREATEROLE PASSWORD '…';
GRANT app_rw TO ef_manager WITH ADMIN OPTION;
ALTER ROLE ef_manager SET createrole_self_grant = 'set, inherit';
```

Journal: `db.role.created` (`role`, `grants`, `validUntil`, `database`),
`db.role.dropped` (`role`, `result`, `detail`), `db.dynamic.configured`.

## Connecting

Connect from the resource's **Connect** button: the agent opens a local port
and the dialog shows the `psql` line to run. Any user name works and no password
is asked: the bastion has already authenticated you and logs in with the
resource's account.

```bash
psql "host=127.0.0.1 port=<local port> dbname=app"
```

The client's `database`, `application_name` (prefixed with `endoriumfort / `),
`client_encoding`, `DateStyle`, `TimeZone`, `IntervalStyle` and
`extra_float_digits` are passed on. `options` and `search_path` set at start-up
are dropped (they would configure the session before the guard sees anything),
and replication connections are refused.

## Journal

Every event carries `sessionId`, `resourceId`, `resource`, `database` and
`dbUser` (the vaulted account); the actor is the bastion user.

| Event | Extra fields |
|---|---|
| `db.connect` | `tls`, `tlsMode`, `sourceIp` |
| `db.connect.failed` | `error` (e.g. the database refused the login) |
| `db.query` | `mode` (`simple`, `extended`, `fastpath`), `sql` (first 4 KiB, `sqlTruncated` beyond), `durationMs`, `rows`, `command`, and `error` + `sqlstate` when it failed. Extended-protocol queries also carry `parameters`, the **number** of bound values — the values themselves are never recorded. A query cut by the end of the connection has `error: "interrupted: …"` |
| `db.query.blocked` | `mode`, `sql`, `rule` |
| `db.disconnect` | `queries`, `blocked`, `reason` |

They reach the hash-chained audit trail, the SIEM export and the session's
event list like every other event. In **Sessions**, the details of a PostgreSQL
session have a **SQL queries** button (needs `audit.read`): every query of the
session in the order it ran, to the second, with its outcome, duration, rows
and error, filters (succeeded, failed, refused) and a search in the SQL, and a
**Replay** that shows them again one by one at their recorded pace (1× to 60×,
long pauses shortened to 3 s). It reads `GET /api/audit?sessionId=…&family=db`
and follows a live session as it goes. Bulk work (a `pg_dump`, an ETL job) produces
one event per statement: give such jobs their own resource if that volume is a
concern.

## SQL guard

On a resource with **SQL guard** ticked, each query (simple Query and
extended-protocol Parse) is checked before it is forwarded. A refused statement
never reaches the server; the client gets a normal PostgreSQL error
(`SQLSTATE 42501`, *statement refused by SQL guard rule "…"*) at the place the
server would have put one, and the session carries on. Fast-path function
calls are refused outright on a guarded resource.

Rules are managed in **Threat detection → Rules** or through the API.

**Built-in rules** (on by default; can be switched off, not removed):

| Rule | Refuses |
|---|---|
| `drop` | any `DROP` |
| `truncate` | `TRUNCATE` |
| `delete_without_where` | `DELETE FROM` with no `WHERE`, also inside a CTE or `EXPLAIN ANALYZE` |
| `update_without_where` | `UPDATE … SET` with no `WHERE` |
| `role_change` | `CREATE/ALTER/DROP ROLE|USER|GROUP`, `GRANT`, `REVOKE`, `SET ROLE`, `SET SESSION AUTHORIZATION` |
| `alter_system` | `ALTER SYSTEM` |
| `copy_program` | `COPY … PROGRAM` (runs a shell command on the database server) |
| `do_block` | anonymous `DO` blocks, whose body the other rules cannot see |

**Custom rules**: a *statement* rule (`ALTER SYSTEM`, `VACUUM FULL`) matches
statements starting with those words; a *schema* rule (`payroll`) matches any
name qualified by that schema (`payroll.salaries`, `"payroll".x`) and
`SET search_path` to it.

The SQL is tokenised, not pattern-matched: comments, string literals,
`E''` strings and dollar-quoted bodies are removed first, so `'DROP'` in a
string does not fire and `/**/DROP` does not slip through. **Limits**: code run
indirectly — a function body, `EXECUTE` of a built string, a trigger — is not
visible, and an unqualified table reached through the role's own
`search_path` escapes a schema rule. The guard raises the bar and records
intent; keep the database account's privileges as narrow as the job allows.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/db-guard/rules` | All rules, built-ins first |
| `PUT` | `/api/db-guard/rules/:name` | `{kind: "statement"\|"schema", value, enabled}`; built-ins take `enabled` only |
| `DELETE` | `/api/db-guard/rules/:name` | Custom rules only |
| `GET` | `/api/db-proxy/dynamic/:resourceId` | Dynamic role settings (`resources.read`) |
| `PUT` | `/api/db-proxy/dynamic/:resourceId` | `{enabled, grantRoles, ttlSeconds}` (`resources.manage`) |

Changes are journaled as `db_guard.rule.configured` / `db_guard.rule.removed`.
All three need `resources.manage`; API tokens may reach them.

## Metrics

With [`/api/metrics`](./configuration.md#prometheus-metrics):
`endoriumfort_db_queries_total{result="ok|error|blocked"}`,
`endoriumfort_db_query_duration_seconds` (histogram) and
`endoriumfort_db_connections_active`.

## Not yet

MySQL/MariaDB and a web SQL console are tracked as follow-up issues.
