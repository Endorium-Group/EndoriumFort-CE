---
layout: default
title: Admin Console Guide
---

# Admin Console Guide

This document holds the explanatory material that should not live inside the admin UI.

## Access Model

EndoriumFort now follows a three-layer access model:

1. `Role`
   Global capabilities such as user management, audit visibility, or session operations.
2. `Access Scope`
   The resources assigned to a given user.
3. `Resource Policy`
   Guardrails defined on the resource itself, such as:
   - justification required
   - dual approval
   - command guard
   - adaptive risk controls

The admin UI focuses on actions and state. This page is the place for the conceptual explanation.

## Admin MFA Rules

- Seeded `admin` accounts must rotate their initial password.
- MFA is mandatory for every admin account.
- Admins must keep at least one MFA factor active.
- MFA can be satisfied with:
  - TOTP
  - WebAuthn passkeys / security keys

## Relay Operations

`Relay Fabric` in the admin UI is intentionally action-focused.

Operational notes:

- Relay enrollment stays disabled unless `ENDORIUMFORT_RELAY_ENROLL_SECRET` is configured.
- Certificates and short-lived enrollment tokens can be generated from the admin console.
- Resource routing can stay direct or be bound to a relay.
- Online-only relay assignment is available to avoid routing toward stale relays.

## Resource Administration

Resource editing is split into these operational sections:

- `Identity`
- `Connectivity`
- `Access Policy`
- `Routing`

The form intentionally avoids long explanatory text. Use this page when onboarding operators or admins.

## Runtime Configuration

Backend runtime variables are documented in:

- [README](../README.md)
- [.env.example](../.env.example)
- [.env.prod.example](../.env.prod.example)

These cover:

- backend port
- session TTL
- WebAuthn RP ID / origin
- relay enrollment and token TTLs

---

## Console walkthrough (access workspace)


1. Login at `http://localhost:5173`
2. **User console is access-first**:
  - open a resource tile and access it directly on the **same page**
  - web resources are rendered inline through the embedded bastion proxy view
  - SSH sessions and live terminal stay in the same workspace (no page switching)
3. **Access traceability**:
  - admins can enable a per-resource popup requiring **Access Reason** (and optional **Ticket ID**)
  - metadata is attached to bastion audit events for compliance and investigations
4. **Dual control and adaptive policy**:
  - admins can enforce **dual approval** per resource
  - operators submit access requests from the same connect modal (reason + optional ticket)
  - admins approve/deny from the built-in Access Requests queue
  - for high-risk adaptive resources, `ticketId` is enforced server-side
  - use **Access Playbook** actions in the access modal to save/apply recurring justification and purpose templates per resource
5. **Sessions** - Monitor, shadow (read-only), or terminate active sessions
  - monitor **Session SLO Insights** (completion rate, average duration, stale active sessions)
  - pin critical sessions in **Watchlist** to track state transitions (active/closed/errors) faster
  - each session card now shows effective routing path (`direct route` or `via relay`) with relay label/status when applicable
  - VNC sessions can now be opened directly in-browser with the integrated noVNC viewer
  - use **SSH Snippets Studio** to inject or execute recurring troubleshooting commands
  - save custom snippets per operator browser profile for faster interventions
  - open **Session DNA** to inspect integrity chain entries and verification status
6. **Audit** — Search and filter all security events
  - export the current filtered audit view as CSV for reporting and case evidence
7. **Reports** — Statistics over a day, a month, a quarter or a year (`audit.read`)
  - built on the server from the audit log, archives included, so the figures cover the whole retention window
  - sessions opened/closed/refused, sign-ins and their failures, access requests and decisions, blocked commands, incidents, administration changes
  - every figure compared with the period before, with a per-hour, per-day or per-month chart
  - busiest users, most frequent targets (the resource or account an event names) and most frequent event types
  - `GET /api/reports?period=day|month|quarter|year&date=<YYYY-MM-DD>&top=<1-50>`
  - `GET /api/reports/export?…` downloads the same report as CSV, and journals the export (`report.export`)
8. **Recordings** — Replay past SSH sessions with the animated Asciinema player (admin/auditor)
9. **Admin dashboard** — Manage users/resources/access scope and view platform stats
  - includes **Relay Fabric** operations panel for distributed bastion control-plane:
    - live relay fleet inventory with online/offline status
    - per-resource relay assignment from the admin console
    - online-only assignment toggle to prevent accidental routing toward stale relays
    - agent-first relay bootstrap guidance in UI (manual API bootstrap kept as advanced fallback)
    - direct relay bootstrap from UI with relay certificate + short-lived one-time enrollment token generation (advanced mode)
    - runtime relay policy visibility (certificate policy, enrollment enabled, token TTL, stale threshold)
  - includes **Enterprise IAM** operations workspace:
    - LDAP/Active Directory provider inventory with runtime capability visibility
    - LDAP bind-test workspace (admin-triggered bind validation with audit trace)
    - SSO provider diagnostics and default-provider visibility for OIDC start/callback paths
    - SCIM directory explorer for `Users` and `Groups` with `startIndex`, `count`, `filter`
    - SCIM PATCH operator workspace for partial updates (`userName`, `role`, `active`)
    - ITSM verification drills with explicit fail-open/fail-closed behavior simulation
    - SIEM export of every audit event over syslog (RFC 5424, UDP/TCP/TLS), a JSON webhook or Splunk HEC, with retries, batching and a liveness heartbeat
    - SIEM forwarding drills to validate channel availability and delivery-mode behavior
    - Cluster/HA control-plane board (local node role, peer heartbeat inventory, stale/offline state visibility, and peer eviction)
10. **Role + resource policy access model**:
  - role defines the global permission baseline
  - assigned resources define the user scope
  - each resource carries its own access policy (justification, dual approval, adaptive risk, command guard)
  - admin UI is centered on **Access Scope** and **Access Policy**, not per-action user overrides
11. **Risk-aware access prompt**:
  - before access, operators get a live **Risk Preview** (`score`, `effectiveRiskLevel`, factors)
  - high/critical resources enforce **Session Purpose** at creation time
  - optional `purposeEvidence` can be attached for compliance context
12. **Live security notifications**:
  - the console raises real-time toast alerts when new critical audit signals are observed
  - currently includes auth anomalies, unjustified session creation, and behavior anomaly events
  - alerts auto-expire and can be dismissed manually
  - powered by dedicated API polling: `GET /api/security/alerts?sinceId=<id>`
  - incident escalation is audit-tracked via: `POST /api/security/incidents/escalate` (event type `security.incident.escalated`)
  - active incident case lifecycle APIs:
    - `GET /api/security/incidents/active`
    - `POST /api/security/incidents/open`
    - `POST /api/security/incidents/close`
  - escalation banner can open incident cases for SOC coordination and show active case metadata
  - escalation banner now correlates suspect sessions and provides one-click `Audit session` shortcuts
  - correlated sessions are ranked by a risk score (signal count, criticality, recency, active status)
  - operators with session permissions can terminate all active correlated suspects from a confirmation dialog
  - platform admins can enable/disable containment from the incident banner to enforce justifications globally
  - containment state API: `GET /api/security/containment` and `POST /api/security/containment`
  - while containment is active, backend blocks session creation without `justification` and emits `session.create.blocked.containment`
13. **Relay control-plane (distributed bastion foundations)**:
  - enroll relay nodes with a shared enrollment secret:
    - `POST /api/relays/enroll`
    - header: `X-EndoriumFort-Relay-Secret`
  - enroll relay nodes with an admin-issued short-lived one-time token:
    - `POST /api/relays/enroll`
    - header: `X-EndoriumFort-Relay-Enrollment-Token`
  - relay must present an admin-issued certificate for enrollment and heartbeat:
    - header: `X-EndoriumFort-Relay-Certificate`
  - mint relay certificates from admin API:
    - `POST /api/relays/certificate`
  - mint relay enrollment tokens from admin API:
    - `POST /api/relays/enrollment-token`
  - keep relay health fresh with heartbeat:
    - `POST /api/relays/heartbeat`
    - header: `X-EndoriumFort-Relay-Token`
  - list relay fleet health and metadata (admin):
    - `GET /api/relays`
  - inspect relay runtime control-plane settings (admin, secret never returned):
    - `GET /api/relays/config`
  - bind/unbind one resource to one relay (admin):
    - `POST /api/relays/assign`
  - resolve runtime path for a resource (direct or relay):
    - `GET /api/relays/resolve/:resourceId`
  - relay route automatically falls back to `direct` when assigned relay is stale/offline
  - relay enrollment/heartbeat routes require secure transport (`HTTPS`) except local loopback lab usage

14. **Cluster / HA control-plane foundations**:
  - inspect local node posture and full peer health inventory (admin/read scopes):
    - `GET /api/cluster/status`
  - inspect local Cluster/HA runtime configuration:
    - `GET /api/cluster/config`
  - register peer heartbeat metadata (inter-node auth secret required):
    - `POST /api/cluster/heartbeat`
    - header: `X-EndoriumFort-Cluster-Secret`
  - evict a retired/stale peer node from the runtime registry (admin):
    - `DELETE /api/cluster/peers/:nodeId`
  - stale peer detection is controlled by `cluster_heartbeat_stale_seconds` and reported as `online`/`offline`

