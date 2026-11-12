---
layout: default
title: API reference
---

# API reference

All endpoints are served under the bastion host. Authenticate with
`POST /api/auth/login` and pass the returned token as `Authorization: Bearer
<token>`, or rely on the auth cookie set for browser sessions.

Endpoints belonging to Enterprise Edition features are absent from Community
Edition builds and return `404`.

### Endpoints documented elsewhere

This page covers the endpoints shared by both editions plus the session and
governance surface. The remaining Enterprise families are documented with their
features, or listed in the overlay inventory in
[OPEN-CORE.md](./OPEN-CORE.md#pro-overlay-contents):

| Family | Prefix | Reference |
|---|---|---|
| Relay control plane | `/api/relays/*` | [relay-deployment.md](./relay-deployment.md) |
| SSO, LDAP, SCIM, ITSM | `/api/auth/directory/*`, `/api/scim/v2/*` | [integration-settings.md](./integration-settings.md) |
| SIEM export | configured in the admin UI | [siem-logging.md](./siem-logging.md) |
| File share tickets | `/api/sessions/<id>/fileshare-ticket` | [fileshare.md](./fileshare.md) |
| Security center | `/api/security/*` | — |
| ITDR | `/api/itdr/*` | — |
| Kubernetes | `/api/k8s/*`, `/api/ws/k8s` | — |
| Dynamic secrets and rotation | `/api/vault/dynamic`, `/api/vault/rotation` | — |
| Automation scheduler | `/api/automation/jobs` | — |
| White-label branding | `/api/branding/*` | — |
| Isolated browser | `/api/rbi/capabilities`, `/api/ws/rbi` | — |
| License | `/api/license/status`, `/api/license/reload` | [OPEN-CORE.md](./OPEN-CORE.md) |

---

## Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login` | Authenticate (returns Bearer token) |
| `POST` | `/api/auth/logout` | Invalidate token server-side |
| `POST` | `/api/auth/change-password` | Change current user's password |
| `POST` | `/api/auth/setup-2fa` | Generate TOTP secret + QR URI |
| `POST` | `/api/auth/verify-2fa` | Verify and enable 2FA |
| `POST` | `/api/auth/disable-2fa` | Disable 2FA |
| `GET`  | `/api/auth/2fa-status` | Check 2FA status |

## API tokens

Personal tokens for scripts, CI and Terraform. A token acts **for its owner and
never beyond**: a request is allowed only when the owner's current role holds the
permission *and* the token's scope lists it. Send it as
`Authorization: Bearer efapi_…` (never as a cookie).

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/tokens/scopes` | Scopes the caller may grant, and `maxLifetimeDays` |
| `GET`  | `/api/tokens` | The caller's tokens; `?all=1` lists everyone's (`users.manage`) |
| `POST` | `/api/tokens` | Create: `name`, `scopes[]`, `expiresInDays` (default 30), optional `allowedCidrs[]`. The clear `token` is in this response only |
| `DELETE` | `/api/tokens/:id` | Revoke (own tokens, or anyone's with `users.manage`) |

**Service accounts.** For automation that should not hang off a person, create a
user with `"serviceAccount": true` on `POST /api/users` (no `password`: it gets an
unguessable one). A service account can never sign in — not with a password,
LDAP or SSO (a directory identity with the same name is refused) — and has no
MFA or password-rotation setup. An administrator holding `users.manage` mints
its tokens with `POST /api/tokens` and `"serviceAccountId": <id>`; each scope
must then be held by both the administrator and the account's role. `PUT
/api/users/:id` only changes its role; deleting it revokes its tokens. Service
accounts do not count towards the "last administrator" guard.

**Limits.** Only the SHA-256 of a token is stored. Lifetime 1 day up to
`ENDORIUMFORT_API_TOKEN_MAX_DAYS` (default 365); 25 active tokens per person;
`allowedCidrs` takes IPv4 addresses or CIDRs and literal IPv6 addresses (max 16).
A token dies with its owner's account, follows a role change at once, and is
refused while the owner still has first-login setup pending.

**Grantable scopes:** `users.read`, `users.manage`, `resources.read`,
`resources.manage`, `resources.assign`, `sessions.read`, `sessions.terminate`,
`audit.read`, `recordings.read`, `stats.read`, `access_requests.read`,
`cluster.read`, `cluster.manage`, `settings.manage`, `metrics.read`. Interactive permissions
(`sessions.create`, `*.connect`, `ssh.shadow.watch`, `access_requests.review`,
`credentials.ephemeral.*`, `totp.manage`) can never be put on a token.

**Reachable endpoints.** Tokens reach the management API only, and every other
path answers `403 Not available to API tokens` before any handler runs:
resources (except one-time credentials and the file-share directory), users,
access policies/profiles/grants, access requests (read only — approving stays a
human decision), audit, reports, stats, recordings, SSH guard, vault,
automation, ITDR, security center, Kubernetes resources, SIEM integration,
evidence packs, cluster status, `/api/health`, `/api/license/status`,
`GET /api/metrics`, and
sessions (list, read, `terminate`, `dna` only). Authentication, MFA, devices,
tokens themselves, WebSockets and `/proxy/*` are out of reach.

**Journal.** `apitoken.create` and `apitoken.revoke` on each change;
`apitoken.use` (with the token id, prefix and source IP) on the first use, then
at most once an hour per token. Events produced by a token's requests carry the
owner as actor.

## Sessions

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/sessions` | List sessions (filterable) |
| `POST` | `/api/sessions` | Create new session (`resourceId`, `justification`, `ticketId`, optional `accessRequestId`) |
| `GET`  | `/api/sessions/:id` | Get session details |
| `POST` | `/api/sessions/:id/terminate` | Terminate session |
| `GET`  | `/api/sessions/stream` | SSE event stream |

## Resources

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`    | `/api/resources` | List resources (RBAC filtered) |
| `POST`   | `/api/resources` | Create resource (admin) |
| `PUT`    | `/api/resources/:id` | Update resource (admin) |
| `DELETE` | `/api/resources/:id` | Delete resource (admin) |
| `GET`    | `/api/resources/:id/credentials` | Get stored credentials (admin/auditor) |

## Access Requests

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/access-requests` | List access requests (admin/auditor: all, operator: own) |
| `POST` | `/api/access-requests` | Create access request (operator/admin) |
| `POST` | `/api/access-requests/:id/approve` | Approve request (admin) |
| `POST` | `/api/access-requests/:id/deny` | Deny request (admin) |

## Access Governance (JIT)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` / `POST` | `/api/access-policies` | List or create centralized JIT access policies |
| `PUT` / `DELETE` | `/api/access-policies/:id` | Update or delete an access policy |
| `GET` / `POST` | `/api/access-profiles` | List or create reusable access profiles |
| `PUT` / `DELETE` | `/api/access-profiles/:id` | Update or delete an access profile |
| `GET` | `/api/access-grants` | List ephemeral access grants (auto-expiration enforced) |
| `GET` | `/api/sessions/:id/dna` | Get session DNA integrity chain |
| `GET` | `/api/evidence-packs/sessions/:id` | Export signed evidence pack for a session |
| `POST` | `/api/sessions/:id/elevation/start` | Record a JIT elevation start (`access.elevation.started`) |
| `POST` | `/api/sessions/:id/elevation/end` | Record a JIT elevation end (`access.elevation.ended`) |
| `POST` | `/api/sessions/:id/goal-review` | Record mission outcome review (`session.goal.match\|mismatch`) |

## Users & Permissions

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`    | `/api/users` | List users (admin) |
| `POST`   | `/api/users` | Create user (admin) |
| `PUT`    | `/api/users/:id` | Update user (admin) |
| `DELETE` | `/api/users/:id` | Delete user (admin) |
| `POST`   | `/api/users/:userId/resources/:resourceId` | Grant access |
| `DELETE` | `/api/users/:userId/resources/:resourceId` | Revoke access |

## WebSocket Endpoints

| Endpoint | Description |
|----------|-------------|
| `/api/ws/ssh` | Live SSH terminal |
| `/api/ws/shadow` | Session shadowing (read-only) |
| `/api/ws/rdp` | RDP session (requires FreeRDP) |
| `/api/ws/vnc` | Browser VNC session bridge (noVNC client) |
| `/ws/tunnel` | Agent TCP tunnel |

## Other

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/health` | Health check |
| `GET`  | `/api/metrics` | Prometheus exposition (`metrics.read`); see [configuration.md](configuration.md#prometheus-metrics) |
| `GET`  | `/api/stats` | Dashboard KPI metrics |
| `GET`  | `/api/audit` | Audit events |
| `GET`  | `/api/reports` | Statistics over one calendar period (`period=day\|month\|quarter\|year`, `date`, `top`) |
| `GET`  | `/api/reports/export` | The same report as a CSV download |
| `GET`  | `/api/recordings` | List session recordings |
| `GET`  | `/api/recordings/:id/cast` | Download .cast file |
| `GET`  | `/api/recordings/search` | Full-text search in terminal recordings (Enterprise, `recordings.search`; needs `recordings.read`). `q` (searched as a phrase, case and accents ignored), optional `from`/`to` (dates on the recording start), `user` (session operator), `resourceId`. Answers recordings, newest first, each with `hits[]` = `{offset, snippet}` (seconds from the recording start; the match between `\u0002` and `\u0003`). Journaled as `recording.search` |
| `GET`  | `/api/vnc/capabilities` | VNC browser capability and runtime metadata |
| `GET`  | `/api/cluster/status` | Cluster/HA status snapshot (local node + peers + health summary) |
| `GET`  | `/api/cluster/config` | Cluster/HA runtime configuration metadata |
| `POST` | `/api/cluster/heartbeat` | Peer heartbeat update (shared secret auth) |
| `DELETE` | `/api/cluster/peers/:nodeId` | Remove a cluster peer from runtime registry |
| `ANY`  | `/proxy/:resourceId/*` | HTTP reverse proxy |

The database proxy and its SQL guard (`/api/db-guard/rules`) are documented in
[docs/database-proxy.md](database-proxy.md).

Relay, SSO/LDAP/SCIM, ITSM and SIEM endpoints are documented in
[docs/relay-deployment.md](docs/relay-deployment.md) and
[docs/integration-settings.md](docs/integration-settings.md).

---
