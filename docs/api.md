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
| `GET`  | `/api/stats` | Dashboard KPI metrics |
| `GET`  | `/api/audit` | Audit events |
| `GET`  | `/api/reports` | Statistics over one calendar period (`period=day\|month\|quarter\|year`, `date`, `top`) |
| `GET`  | `/api/reports/export` | The same report as a CSV download |
| `GET`  | `/api/recordings` | List session recordings |
| `GET`  | `/api/recordings/:id/cast` | Download .cast file |
| `GET`  | `/api/vnc/capabilities` | VNC browser capability and runtime metadata |
| `GET`  | `/api/cluster/status` | Cluster/HA status snapshot (local node + peers + health summary) |
| `GET`  | `/api/cluster/config` | Cluster/HA runtime configuration metadata |
| `POST` | `/api/cluster/heartbeat` | Peer heartbeat update (shared secret auth) |
| `DELETE` | `/api/cluster/peers/:nodeId` | Remove a cluster peer from runtime registry |
| `ANY`  | `/proxy/:resourceId/*` | HTTP reverse proxy |

Relay, SSO/LDAP/SCIM, ITSM and SIEM endpoints are documented in
[docs/relay-deployment.md](docs/relay-deployment.md) and
[docs/integration-settings.md](docs/integration-settings.md).

---
