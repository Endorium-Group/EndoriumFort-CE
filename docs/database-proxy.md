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
event list like every other event. Bulk work (a `pg_dump`, an ETL job) produces
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

Changes are journaled as `db_guard.rule.configured` / `db_guard.rule.removed`.
All three need `resources.manage`; API tokens may reach them.

## Metrics

With [`/api/metrics`](./configuration.md#prometheus-metrics):
`endoriumfort_db_queries_total{result="ok|error|blocked"}`,
`endoriumfort_db_query_duration_seconds` (histogram) and
`endoriumfort_db_connections_active`.

## Not yet

Dynamic per-session roles (`CREATE ROLE … VALID UNTIL`), MySQL/MariaDB and a
web SQL console are tracked as follow-up issues.
