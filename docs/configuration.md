---
layout: default
title: Runtime configuration
---

# Runtime configuration

Every runtime knob EndoriumFort reads from the environment.

Variables whose enforcement lives in the Enterprise overlay are called out where
they appear: setting them in a Community build has **no effect**, rather than
failing loudly. Read those notes before relying on a value for a security
control.

- [Relay control plane](#relay-runtime-configuration)
- [Cluster / HA](#cluster--ha-runtime-configuration)
- [Auth / WebAuthn](#auth--webauthn-runtime-configuration)
- [Vault encryption](#vault-encryption-aes-256-gcm)
- [Rate limiting](#rate-limiting--brute-force-protection)
- [CSP and hardening headers](#csp-headers--security-hardening)
- [Anomaly detection](#anomaly-detection--alerting)
- [Remote browser isolation](#remote-browser-isolation)
- [File share drives](#file-share-drives)
- [Container environment variables](#environment-variables)

---

## Relay Runtime Configuration

Set relay control-plane hardening values in backend runtime:

- `ENDORIUMFORT_RELAY_ENROLL_SECRET`: shared secret required by `POST /api/relays/enroll`
- `ENDORIUMFORT_RELAY_CERT_REQUIRED`: require relay certificate presentation on enroll/heartbeat (default `true`)
- `ENDORIUMFORT_RELAY_CERT_TTL_SECONDS`: admin-issued relay certificate TTL (default `2592000`)
- `ENDORIUMFORT_RELAY_ENROLL_TOKEN_TTL_SECONDS`: admin-issued one-time enrollment token TTL (default `600`)
- `ENDORIUMFORT_RELAY_TOKEN_TTL_SECONDS`: relay auth token TTL (default `86400`)
- `ENDORIUMFORT_RELAY_HEARTBEAT_STALE_SECONDS`: relay stale threshold for online/offline decision (default `90`)

If `ENDORIUMFORT_RELAY_ENROLL_SECRET` is not set, enrollment stays fail-closed (disabled).

## Cluster / HA Runtime Configuration

Set Cluster/HA control-plane values in backend runtime:

- `ENDORIUMFORT_CLUSTER_ENABLED`: enable cluster mode (`true`/`false`, default `false`)
- `ENDORIUMFORT_CLUSTER_NODE_ID`: stable local node identifier exposed by `/api/cluster/status`
- `ENDORIUMFORT_CLUSTER_NODE_LABEL`: human-readable local node label
- `ENDORIUMFORT_CLUSTER_ADVERTISE_ADDR`: advertised local node endpoint shown to peers/admin UI
- `ENDORIUMFORT_CLUSTER_ROLE`: local role (`leader`, `follower`, `standalone`)
- `ENDORIUMFORT_CLUSTER_SHARED_SECRET`: shared secret required by `POST /api/cluster/heartbeat`
- `ENDORIUMFORT_CLUSTER_HEARTBEAT_STALE_SECONDS`: stale threshold for peer online/offline state (default `45`)

If `ENDORIUMFORT_CLUSTER_ENABLED=true` but `ENDORIUMFORT_CLUSTER_SHARED_SECRET` is not configured, peer heartbeat authentication is fail-open (warning emitted at startup).

## Auth / WebAuthn Runtime Configuration

Use these backend runtime variables to control login sessions, passkeys, and local/dev compatibility:

- `ENDORIUMFORT_PORT`: backend listen port (default `8080`)
- `ENDORIUMFORT_TOKEN_TTL_SECONDS`: auth session TTL in seconds (default `3600`)
- `ENDORIUMFORT_DB_DSN`: storage backend. Empty/omitted or a path = embedded SQLite file (default); a `postgresql://...` URI uses PostgreSQL. Selected at runtime, no image change needed.
- `ENDORIUMFORT_TUNNEL_CREDENTIAL_TTL_SECONDS`: TTL of the resource-scoped tunnel credential an agent exchanges its bootstrap token for (default `43200`, i.e. 12h)
- `ENDORIUMFORT_WEBAUTHN_CHALLENGE_TTL_SECONDS`: passkey challenge TTL in seconds (default `180`)
- `ENDORIUMFORT_WEBAUTHN_RP_ID`: explicit WebAuthn RP ID override
- `ENDORIUMFORT_WEBAUTHN_ORIGIN`: explicit WebAuthn origin override

Recommended values:

- local Vite dev:
  - `ENDORIUMFORT_WEBAUTHN_RP_ID=localhost`
  - `ENDORIUMFORT_WEBAUTHN_ORIGIN=http://localhost:5173`
- production:
  - `ENDORIUMFORT_WEBAUTHN_RP_ID=bastion.example.com`
  - `ENDORIUMFORT_WEBAUTHN_ORIGIN=https://bastion.example.com`

Notes:

- `localhost` and `127.0.0.1` are accepted for local development.
- For non-localhost deployments, WebAuthn should use a real domain and `https`.
- The backend now logs effective runtime config at startup without printing secrets.

## Vault Encryption (AES-256-GCM)

Resource credentials (SSH/HTTP passwords) are optionally encrypted at rest using **AES-256-GCM**. Encryption is transparent and backward-compatible:

**Enabling vault encryption:**

Generate a 256-bit (32-byte) encryption key:

```bash
openssl rand -hex 32
# Example output: 3f8d2e1a9c7b4f6e5a3d2c1b9e8f7a6d5c4b3a2f1e9d8c7b6a5f4e3d2c1b9a
```

Set the environment variable **before starting the backend:**

```bash
export ENDORIUMFORT_VAULT_KEY=<your-hex-32-byte-key>
./endoriumfort_backend
```

**Behavior:**

- **With key set**: New credentials are encrypted with AES-256-GCM and stored in format `aes256:v1:iv:tag:ciphertext` (all hex).
- **Without key**: Credentials are stored in plaintext (for backward compatibility). Existing encrypted data can still be decrypted if the key is later provided.
- **Key rotation**: Currently not supported. Generate a new database if key change is required.

**Notes:**

- The IV (initialization vector) is unique per credential and embedded in the ciphertext.
- If `ENDORIUMFORT_VAULT_KEY` is set but invalid (wrong size or bad hex), encryption falls back to plaintext.
- All existing plaintext credentials remain readable. Only newly created/updated credentials are encrypted.

## Rate Limiting & Brute-Force Protection

EndoriumFort implements multi-layered rate limiting to protect against brute-force attacks:

**Dual-Track Rate Limiting:**

1. **Username-based tracking**: Limits failed attempts per username across a 5-minute sliding window
2. **IP-based tracking**: Limits failed attempts per source IP across a 5-minute sliding window

This dual approach protects against both single-source targeted attacks and distributed brute-force campaigns.

**Exponential Backoff:**

After reaching rate limits, progressive delays are applied:

| Failed Attempts | Lockout Duration | Use Case |
|-----------------|------------------|----------|
| 10 attempts | 30 seconds | Normal typos/user errors |
| 20 attempts | 5 minutes | Coordinated single-source attack |
| 30+ attempts | 30 minutes | Distributed or persistent brute-force |

**Configuration:**

```bash
# Default: 10 attempts per 5-minute window (300 seconds)
# You can inspect the source code to adjust these values:
# backend/src/app_context.h: rate_limit_max_attempts, rate_limit_window

# No explicit environment variables yet; configuration is code-level
```

**Behavior:**

- Failed login attempts (wrong password or unknown user) increment both username and IP counters
- Successful login clears both counters, allowing immediate re-use
- Rate-limited responses return HTTP 429 with a descriptive error message
- All rate limit events are logged to the audit trail with type `auth.login.rate_limited`
- X-Forwarded-For header is respected for reverse proxy deployments
- If an IP/username is blocked, even a correct password will be rejected during the lockout period

**Notes:**

- Rate limits are in-memory; they reset on service restart
- The sliding window uses a queue of recent attempt timestamps
- Protected endpoints: `/api/auth/login`
- Audit events include IP address, username, and rate limit reason for security monitoring

## CSP Headers & Security Hardening

EndoriumFort now applies a centralized security-header policy on every backend response through `SecurityHeadersMiddleware`.

**Always-on headers:**

- `Content-Security-Policy` with restrictive defaults:
  - `default-src 'self'`
  - `object-src 'none'`
  - `frame-ancestors 'self'`
  - `base-uri 'self'`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy` with sensitive APIs disabled (`camera`, `microphone`, `geolocation`, `payment`, `usb`)
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`
- `X-Permitted-Cross-Domain-Policies: none`
- `Cache-Control: no-store, no-cache, must-revalidate, private`

**HSTS behavior:**

- `Strict-Transport-Security` is enabled when requests are identified as HTTPS (via reverse-proxy headers like `X-Forwarded-Proto: https`).
- HSTS is intentionally skipped for localhost development hosts to avoid sticky local-browser TLS behavior.

**Validation:**

- SCIM integration tests now enforce hardening headers on API responses.
- Tests also verify HSTS activation behind HTTPS proxy headers and non-activation on localhost.

## Anomaly Detection & Alerting

EndoriumFort now emits correlated anomaly alerts in addition to raw audit events, so suspicious patterns are surfaced directly in the live Security Center feed.

**New correlated anomaly signals:**

- `behavior.anomaly.auth_failure_burst`: emitted when repeated authentication failures/rate-limited attempts exceed a threshold in a short rolling window (per username and per source IP).
- `behavior.anomaly.stale_session`: emitted when a session remains active beyond a configurable stale threshold.
- Existing `behavior.anomaly.command_spike` session-telemetry signal remains active and is now complemented by the new auth/session correlation rules.

**How it works:**

- Correlation is integrated into existing runtime flows:
  - `/api/auth/login` tracks auth-failure signals and emits burst anomalies with anti-spam cooldown.
  - `/api/security/alerts` performs stale-session checks before building the live alert payload.
- Alerts stay backward-compatible with the current `GET /api/security/alerts` contract (`id`, `eventType`, `createdAt`, `actor`, `severity`, `title`, `hint`, optional `sessionId`).
- Alert classifications now include dedicated titles/severity for auth bursts (`critical`) and stale sessions (`warning`).

**Environment variables:**

```bash
# Authentication anomaly correlation
ENDORIUMFORT_ALERT_AUTH_WINDOW_SECONDS=180
ENDORIUMFORT_ALERT_AUTH_FAILURE_THRESHOLD=5
ENDORIUMFORT_ALERT_AUTH_IP_THRESHOLD=8
ENDORIUMFORT_ALERT_AUTH_COOLDOWN_SECONDS=90

# Stale session detection
ENDORIUMFORT_ALERT_STALE_SESSION_SECONDS=7200
ENDORIUMFORT_ALERT_STALE_SESSION_COOLDOWN_SECONDS=900
```

**Validation:**

- Added backend integration tests in `backend/tests/security_alerts_test.cc` covering:
  - emission of `behavior.anomaly.auth_failure_burst` through repeated failed/rate-limited logins
  - emission of `behavior.anomaly.stale_session` for long-running active sessions
- Added CTest target: `backend_security_alerts_test`.


---

## Remote Browser Isolation

An `rbi` resource launches a throwaway headless Chromium server-side and streams
the rendered frames to the operator. These values shape the stream and are
enforced in **every edition**:

- `ENDORIUMFORT_RBI_ENGINE`: rendering engine; selected automatically from the image when unset
- `ENDORIUMFORT_RBI_MAX_SESSIONS`: concurrent isolated sessions
- `ENDORIUMFORT_RBI_MAX_FPS`, `ENDORIUMFORT_RBI_JPEG_QUALITY`: frame rate and frame quality
- `ENDORIUMFORT_RBI_MAX_WIDTH`, `ENDORIUMFORT_RBI_MAX_HEIGHT`: remote viewport ceiling
- `ENDORIUMFORT_RBI_MAX_UPLOAD_MB`: size ceiling for a single upload
- `ENDORIUMFORT_RBI_CHROMIUM`, `ENDORIUMFORT_RBI_HELPER`, `ENDORIUMFORT_RBI_FLAGS`: browser binary, helper and extra flags

> **Edition boundary.** File transfer and clipboard paste inside the isolated
> browser are relayed by the core, so they work in Community Edition. *Governing*
> them is an Enterprise feature: the variables below are read by
> `pro/rbi_transfer.cc` and have **no effect in a Community build**, where the
> policy seam stays unset and every transfer is therefore allowed.
>
> - `ENDORIUMFORT_RBI_ALLOW_PASTE`, `ENDORIUMFORT_RBI_ALLOW_UPLOAD`, `ENDORIUMFORT_RBI_ALLOW_DOWNLOAD`
> - `ENDORIUMFORT_RBI_BLOCKED_EXTENSIONS`
> - `ENDORIUMFORT_RBI_MAX_TRANSFER_MB`

---

## File Share Drives

A `fileshare` resource opens a web drive served by a **separate container**
(`endoriumfort-files`). The bastion only signs short single-use tickets; it never
stores or serves the bytes.

| Variable | Side | Default | Role |
|---|---|---|---|
| `ENDORIUMFORT_FILESHARE_SECRET` (or `_FILE`) | both | — | Ticket signing key, 32 characters minimum. Must match on both sides; unset means `/files/` answers `503` |
| `ENDORIUMFORT_FILESHARE_UPSTREAM` | bastion (nginx) | — | Service URL, e.g. `http://endoriumfort-files:8090`. Unset means `/files/` answers `503` |
| `ENDORIUMFORT_FILESHARE_MAX_BODY` | bastion (nginx) | `2g` | Maximum request size towards `/files/` |
| `EF_FS_QUOTA_MB` | service | `10240` | Quota per user drive (0 = unlimited) |
| `EF_FS_MAX_UPLOAD_MB` | service | `2048` | Maximum size of a single file |
| `EF_FS_SESSION_TTL_SECONDS` | service | `900` | Drive cookie lifetime between renewals |
| `EF_FS_MAX_ZIP_ENTRIES` | service | `20000` | Entry ceiling when downloading a folder as `.zip` |
| `EF_FS_LISTEN`, `EF_FS_DATA_DIR` | service | `:8090`, `/data` | Listen address and storage path |
| `EF_FS_COOKIE_SECURE` | service | `auto` | `auto` follows `X-Forwarded-Proto` |

The service volume is **separate from the bastion's** — back it up too. Full
guide, including Helm and Debian packaging: [fileshare.md](./fileshare.md).

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DOCKER_IMAGE` | `nergyr/endoriumfort` | Docker Hub image name |
| `DOCKER_TAG` | `latest` | Image tag |
| `EF_HTTP_PORT` | `80` | Host HTTP port mapping |
| `EF_HTTPS_PORT` | `443` | Host HTTPS port mapping |
| `TZ` | `Europe/Paris` | Container timezone |
| `ACME_ENABLED` | `0` | Enable Let's Encrypt provisioning (`1` to enable) |
| `ACME_DOMAIN` | _(empty)_ | Public DNS name for certificate issuance |
| `ACME_EMAIL` | _(empty)_ | Contact email used by Let's Encrypt |
| `ENDORIUMFORT_PORT` | `8080` | Internal backend listen port used by the container |
| `ENDORIUMFORT_TOKEN_TTL_SECONDS` | `3600` | Auth session TTL in seconds |
| `ENDORIUMFORT_DB_DSN` | _(empty)_ | `postgresql://...` for PostgreSQL; otherwise a SQLite file path |
| `ENDORIUMFORT_TUNNEL_CREDENTIAL_TTL_SECONDS` | `43200` | Tunnel credential TTL in seconds (agent tunnels outlive the deep-link token) |
| `ENDORIUMFORT_WEBAUTHN_CHALLENGE_TTL_SECONDS` | `180` | WebAuthn challenge TTL in seconds |
| `ENDORIUMFORT_WEBAUTHN_RP_ID` | _(empty)_ | Explicit WebAuthn RP ID override |
| `ENDORIUMFORT_WEBAUTHN_ORIGIN` | _(empty)_ | Explicit WebAuthn origin override |
| `ENDORIUMFORT_RELAY_ENROLL_SECRET` | _(empty)_ | Shared secret for relay enrollment |
| `ENDORIUMFORT_RELAY_CERT_REQUIRED` | `true` | Require relay certificate on enroll/heartbeat |
| `ENDORIUMFORT_RELAY_CERT_TTL_SECONDS` | `2592000` | Relay certificate TTL in seconds |
| `ENDORIUMFORT_RELAY_ENROLL_TOKEN_TTL_SECONDS` | `600` | Relay enrollment token TTL in seconds |
| `ENDORIUMFORT_RELAY_TOKEN_TTL_SECONDS` | `86400` | Relay auth token TTL in seconds |
| `ENDORIUMFORT_RELAY_HEARTBEAT_STALE_SECONDS` | `90` | Relay stale threshold in seconds |
| `ENDORIUMFORT_CLUSTER_ENABLED` | `false` | Enable Cluster/HA mode |
| `ENDORIUMFORT_CLUSTER_NODE_ID` | _(empty)_ | Stable local node identifier |
| `ENDORIUMFORT_CLUSTER_NODE_LABEL` | _(empty)_ | Local node display label |
| `ENDORIUMFORT_CLUSTER_ADVERTISE_ADDR` | _(empty)_ | Advertised local node endpoint |
| `ENDORIUMFORT_CLUSTER_ROLE` | `standalone` | Local cluster role (`leader`, `follower`, `standalone`) |
| `ENDORIUMFORT_CLUSTER_SHARED_SECRET` | _(empty)_ | Shared secret required for peer heartbeat updates |
| `ENDORIUMFORT_CLUSTER_HEARTBEAT_STALE_SECONDS` | `45` | Cluster peer stale threshold in seconds |
| `ENDORIUMFORT_SIEM_HOSTNAME` | _(system hostname)_ | Value stamped on every exported event as `host` |
| `ENDORIUMFORT_SIEM_QUEUE_LIMIT` | `20000` | Export queue depth; past it the oldest events are dropped |
| `ENDORIUMFORT_SIEM_BATCH_MAX` | `50` | Events grouped per delivery |
| `ENDORIUMFORT_SIEM_RETRY_ATTEMPTS` | `4` | Delivery attempts per batch (exponential backoff) |
| `ENDORIUMFORT_SIEM_RETRY_BASE_MS` / `_MAX_MS` | `1000` / `30000` | First backoff delay and its cap |
| `ENDORIUMFORT_SIEM_HEARTBEAT_SECONDS` | `300` | `integration.siem.heartbeat` interval; `0` disables it |
| `ENDORIUMFORT_SIEM_DRAIN_SECONDS` | `5` | Time spent flushing the queue on shutdown |
| `ENDORIUMFORT_SIEM_SYSLOG_ENABLED` | `0` | Enable the syslog channel |
| `ENDORIUMFORT_SIEM_SYSLOG_HOST` / `_PORT` | _(empty)_ / `514` | Syslog collector address |
| `ENDORIUMFORT_SIEM_SYSLOG_PROTOCOL` | `udp` | `udp`, `tcp` or `tls` |
| `ENDORIUMFORT_SIEM_SYSLOG_FORMAT` | `rfc5424` | `rfc5424` or `rfc3164` |
| `ENDORIUMFORT_SIEM_SYSLOG_MESSAGE` | `cee` | `cee` (JSON behind an `@cee:` cookie), `json` or `text` |
| `ENDORIUMFORT_SIEM_SYSLOG_FRAMING` | `octet` | TCP/TLS framing: `octet` (RFC 6587) or `lf` |
| `ENDORIUMFORT_SIEM_SYSLOG_FACILITY` | `13` | RFC 5424 facility (`13` = log audit) |
| `ENDORIUMFORT_SIEM_SYSLOG_APP_NAME` | `endoriumfort` | Syslog APP-NAME |
| `ENDORIUMFORT_SIEM_SYSLOG_TLS_VERIFY` | `1` | Verify the collector's certificate chain **and** hostname |
| `ENDORIUMFORT_SIEM_SYSLOG_CA_FILE` | _(system CAs)_ | CA bundle for the collector certificate |
| `ENDORIUMFORT_SIEM_SYSLOG_SERVER_NAME` | _(host)_ | Expected certificate name / SNI |
| `ENDORIUMFORT_SIEM_SYSLOG_MAX_BYTES` | `8192` / `65000` | Line truncation (UDP / stream) |
| `ENDORIUMFORT_SIEM_SYSLOG_CONNECT_TIMEOUT_MS` | `5000` | Bounded connect, so an unreachable collector cannot stall the worker |
| `ENDORIUMFORT_SIEM_SYSLOG_WRITE_TIMEOUT_MS` | `10000` | Socket write timeout |
| `ENDORIUMFORT_SIEM_WEBHOOK_ENABLED` | `0` | Enable the JSON webhook channel |
| `ENDORIUMFORT_SIEM_WEBHOOK_URL` | _(empty)_ | Full URL, query string included |
| `ENDORIUMFORT_SIEM_WEBHOOK_TOKEN` | _(empty)_ | Sent as `Authorization: Bearer` |
| `ENDORIUMFORT_SIEM_WEBHOOK_NDJSON` | `0` | One request per batch, one JSON object per line |
| `ENDORIUMFORT_SIEM_SPLUNK_ENABLED` | `0` | Enable the Splunk HEC channel |
| `ENDORIUMFORT_SIEM_SPLUNK_URL` / `_TOKEN` | _(empty)_ | HEC collector endpoint and token |
| `ENDORIUMFORT_SIEM_SPLUNK_INDEX` | _(empty)_ | Target index, optional |

> Audit-event export is an Enterprise feature. The field model, the VictoriaLogs
> recipes and the LogsQL queries are in [docs/siem-logging.md](docs/siem-logging.md).

> Every `SIEM`, `LDAP`, `SSO`, `ITSM` and `RBI` variable above is also settable from
> **Administration → Integrations**, with no redeploy. A value set there takes
> precedence over the environment and says so; secrets are encrypted with the
> vault key and never read back. Executable paths, process flags, the license,
> the vault key and the database DSN are deliberately not settable from the UI.
> See [docs/integration-settings.md](docs/integration-settings.md).

## Persistent Volumes

| Volume | Mount Point | Description |
|--------|-------------|-------------|
| `ef-data` | `/app/data` | SQLite database, configuration |
| `ef-recordings` | `/app/recordings` | Session recordings (.cast) |

