<p align="center">
  <img src="assets/logo-full-blue.png" alt="EndoriumFort" height="76">
</p>

<h1 align="center">EndoriumFort</h1>

<p align="center">
  Sovereign privileged access management.<br>
  One gateway for SSH, HTTP, RDP, VNC, Kubernetes and raw TCP — with an audit trail you can prove.
</p>

<p align="center">
  <a href="https://github.com/Endorium-Group/EndoriumFort-CE/releases"><img src="https://img.shields.io/github/v/release/Endorium-Group/EndoriumFort-CE?style=flat-square" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Source--Available-orange?style=flat-square" alt="License"></a>
  <a href="https://github.com/Endorium-Group/EndoriumFort-CE/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Endorium-Group/EndoriumFort-CE/ci.yml?branch=master&label=CI&style=flat-square" alt="CI"></a>
  <a href="https://github.com/Endorium-Group/EndoriumFort-CE/actions/workflows/release-gate.yml"><img src="https://img.shields.io/github/actions/workflow/status/Endorium-Group/EndoriumFort-CE/release-gate.yml?branch=master&label=release%20gate&style=flat-square" alt="Release gate"></a>
  <a href="https://github.com/Endorium-Group/EndoriumFort-CE/actions/workflows/codeql.yml"><img src="https://img.shields.io/github/actions/workflow/status/Endorium-Group/EndoriumFort-CE/codeql.yml?branch=master&label=CodeQL&style=flat-square" alt="CodeQL"></a>
  <br>
  <img src="https://img.shields.io/badge/C%2B%2B17-00599C?style=flat-square&logo=cplusplus&logoColor=white" alt="C++17">
  <img src="https://img.shields.io/badge/React%2018-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React 18">
  <img src="https://img.shields.io/badge/Go%201.25-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go 1.25">
  <img src="https://img.shields.io/badge/Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square" alt="Platforms">
</p>

---

## Overview

EndoriumFort is a **privileged access management (PAM) bastion** you run
yourself. Operators reach infrastructure through a single audited gateway
instead of holding standing credentials, and every action leaves a
tamper-evident trace.

It is built for sovereign deployments rather than as a generic workforce IAM
suite:

- **Zero standing privilege first** — access is granted by short-lived policy
  decisions and ephemeral grants, not by permanent accounts on targets.
- **Self-hosted and single-tenant** — no control plane you do not own,
  air-gap compatible, offline license verification.
- **Evidence-grade traceability** — hash-chained audit, per-session integrity
  chains, and signed evidence bundles built for auditors and investigations.
- **Agentless by default** — the browser is the client; a local agent is
  optional, for native RDP clients and raw TCP.

EndoriumFort follows an [open-core model](docs/OPEN-CORE.md). This repository is
the **Community Edition**. See [Editions](#editions) for the boundary.

---

## Capabilities

### Access and protocols

| Capability | What it does | Edition |
|---|---|:--:|
| **Web SSH terminal** | Full xterm.js terminal over WebSocket, credentials injected from the vault | CE |
| **HTTP/HTTPS proxy** | Transparent reverse proxy, rendered inline in the console, cookie-based auth | CE |
| **Remote browser isolation** | Throwaway headless Chromium runs server-side; only rendered pixels reach the operator (CDP screencast) | CE |
| **File share drives** | A web drive per user — folders, upload/download, shares with expiry — served by a separate hardened service | CE |
| **SSH file transfer** | Browse, download and upload on SSH targets (SFTP, SCP fallback); off by default, per-resource, size-capped, each file audited with its SHA-256 | CE |
| **SSH snippets studio** | Reusable command snippets, injected or executed in one click | CE |
| **RDP and VNC** | Browser RDP via FreeRDP and an integrated noVNC viewer | EE |
| **Kubernetes shells** | A cluster is a resource; list pods and open a recorded `kubectl exec` shell in the web terminal | EE |
| **Agent tunnel** | Local Go agent for zero-rewrite TCP tunneling, multi-tunnel, live TUI, `endoriumfort://` deep links | EE |

### Policy and governance

| Capability | What it does | Edition |
|---|---|:--:|
| **Granular permissions** | Action-level rights with role defaults and per-user overrides | CE |
| **Access scope** | Per-user resource assignment, independent of role | CE |
| **Justification trail** | Per-resource reason and ticket ID, required at session creation and attached to the audit event | CE |
| **SSH command guard** | Server-side blocking of dangerous commands, with its own audit events | CE |
| **Access requests** | Four-eyes control: operators submit, admins approve or deny from a queue — with optional mobile push | EE |
| **Access policies and profiles** | Centralized, reusable JIT policy objects instead of per-resource settings | EE |
| **Ephemeral grants** | Time-boxed access that expires on its own, with privilege elevation tracking | EE |
| **Adaptive risk** | Live risk scoring before access; high-risk sessions require an explicit purpose | EE |
| **Isolation transfer policy** | DLP over isolated-browser transfers — deny a direction, cap sizes, block extensions, with its own audit trail. Transfers themselves work in CE, but **ungoverned** | EE |

### Audit and evidence

| Capability | What it does | Edition |
|---|---|:--:|
| **Audit trail** | Every action in hash-chained JSONL — login, connect, shadow, proxy, file transfer | CE |
| **Session shadowing** | Real-time read-only observation of an active session | CE |
| **Audit export** | Filtered timeline to CSV for reporting and case files | CE |
| **Reporting** | Daily, monthly, quarterly and annual statistics over the audit log — sessions, sign-ins, failures, busiest users and targets, each period compared with the one before, exportable to CSV | CE |
| **Session recording** | SSH captured in Asciinema v2 with an animated in-browser player; RBI sessions recorded too | EE |
| **Session DNA** | Per-session integrity chain with a verification endpoint, so a recording can be proven unaltered | EE |
| **Evidence packs** | Signed, exportable bundles for a single session | EE |
| **SIEM export** | Every audit event over syslog (RFC 5424, UDP/TCP/TLS), JSON webhook or Splunk HEC, with retries and heartbeat | EE |
| **ITDR** | Detection rules over the audit stream, with acknowledgement and response playbooks | EE |
| **Security center** | Anomaly signals, live notifications, incident cases, containment mode | EE |

### Identity, secrets and platform

| Capability | What it does | Edition |
|---|---|:--:|
| **MFA** | TOTP (RFC 6238) and WebAuthn passkeys; enrollment forced for admins | CE |
| **Credential vault** | Target credentials encrypted at rest (AES-256-GCM), never returned by the standard API | CE |
| **Integration settings** | SSO, LDAP, SCIM, ITSM and SIEM configured from the admin UI, secrets encrypted in the database | CE |
| **SSO and directory** | OIDC and SAML 2.0 single sign-on, LDAP/Active Directory authentication, SCIM provisioning | EE |
| **Dynamic secrets** | Ephemeral OS accounts created on connect and destroyed on disconnect — no shared credential at all | EE |
| **Credential rotation** | Scheduled rotation of stored target credentials | EE |
| **Automation scheduler** | Background job engine behind rotation, ITDR responses, session reaping and scheduled reports | EE |
| **Relay fabric** | Relay enrollment, certificates, heartbeat health, per-resource routing with direct fallback | EE |
| **Cluster / HA** | Node identity, peer heartbeat registry, stale-peer detection, peer eviction | EE |
| **White-label branding** | Replace logo, favicon and background for customer-facing deployments | EE |

---

## Editions

The premium code lives in a `backend/src/pro/` overlay mounted through a single
hook. In a Community build that overlay is **not compiled** — premium code is
physically absent from the binary and its routes return `404`.

|  | Community Edition | Enterprise Edition |
|---|---|---|
| Repository | public [`EndoriumFort-CE`](https://github.com/Endorium-Group/EndoriumFort-CE) | private, commercial |
| Premium code | absent from the binary | present, license-gated |
| Premium routes | `404` | registered, `403` without a valid license |
| Distribution | public image on Docker Hub and GHCR, signed `.deb` via APT | signed offline tarball, no registry access needed |
| Use | free for personal, educational, research, evaluation and internal non-production use | commercial and production use |

Enterprise licenses are **hybrid Ed25519 + ML-DSA-65 (post-quantum) tokens
verified entirely offline** — no phone-home, no license server, which is what
makes air-gapped deployments workable.

Full architecture of the split: [docs/OPEN-CORE.md](docs/OPEN-CORE.md).

---

## Quick start

### Docker

```bash
docker run -d --name endoriumfort -p 80:80 \
  -v ef-data:/app/data \
  -v ef-recordings:/app/recordings \
  ghcr.io/endorium-group/endoriumfort:latest
```

Open `http://localhost` and sign in with `admin` / `Admin123`. First sign-in
forces a password change and MFA enrollment.

This runs the bastion alone. **File share drives need a second container**
(`endoriumfort-files`), which the compose files below already declare — see
[docs/fileshare.md](docs/fileshare.md). A Docker Hub mirror
(`nergyr/endoriumfort`) is published too, but GHCR is the reference registry.

### Docker Compose

```bash
git clone https://github.com/Endorium-Group/EndoriumFort-CE.git
cd EndoriumFort-CE
docker compose up -d

# or pick your own ports and timezone
EF_HTTP_PORT=8080 EF_HTTPS_PORT=8443 TZ=America/New_York docker compose up -d
```

| Volume | Mount | Holds |
|---|---|---|
| `ef-data` | `/app/data` | SQLite database, configuration, license |
| `ef-recordings` | `/app/recordings` | Session recordings |

### From source

```bash
# Debian / Ubuntu
sudo apt install build-essential cmake libsqlite3-dev libssh2-1-dev nodejs npm golang

git clone https://github.com/Endorium-Group/EndoriumFort-CE.git
cd EndoriumFort-CE
./build-all.sh      # backend (CMake) + frontend (Vite) + agent (Go)
./run-dev.sh        # backend on :8080, frontend on :5173
```

Requires CMake 3.16+, a C++17 compiler, SQLite3 and libssh2 headers, Node.js 18+
and Go 1.25+. Build tuning, WSL defaults and the test suites are covered in
[docs/development.md](docs/development.md).

Production deployment — hardened compose stack, Helm chart, Debian packages,
upgrade and rollback — is in [docs/deployment.md](docs/deployment.md).

---

## Architecture

```
┌──────────┐     HTTPS/WSS      ┌───────────────┐    SSH/RDP/VNC/HTTP/TCP   ┌──────────┐
│ Browser  │◄──────────────────►│ EndoriumFort  │◄─────────────────────────►│ Targets  │
│ (React)  │                    │ backend (C++) │                           │          │
└──────────┘                    └───────────────┘                           └──────────┘
                                        ▲
                                        │ WebSocket tunnel
                                 ┌──────────────┐
                                 │ Agent (Go)   │   optional, for native
                                 │              │   clients and raw TCP
                                 └──────────────┘
```

The browser is the client: SSH terminals, isolated browsing, proxied web apps
and file drives all run through the backend over HTTPS and WebSocket. The Go
agent is only needed when a native client has to speak to the target directly —
a local RDP client, or arbitrary TCP.

File share drives run in a **separate service** (`endoriumfort-files`). The
bastion decides who may open a drive and signs a short single-use ticket; nginx
routes `/files/` straight to the service, which owns its volume and never sees
the bastion database.

```
Browser ──/api/───►  backend (C++)  ── signed ticket ──┐
   └─────/files/──►  endoriumfort-files (Go, own volume, internal network)
```

Relay nodes extend the data plane to networks the bastion cannot reach
directly, with per-resource assignment and automatic fallback to a direct route
when a relay goes stale — see [docs/relay-deployment.md](docs/relay-deployment.md).

---

## Security

| Area | Posture |
|---|---|
| Password storage | `scrypt`, with transparent migration of legacy hashes |
| Session tokens | Bearer tokens expire after one hour, invalidated server-side |
| Cookies | `HttpOnly` + `SameSite=Strict`; `Secure` set automatically over HTTPS |
| WebSocket auth | Credentials read from cookie or header — never appended to the URL, so they stay out of logs and history |
| Secrets at rest | Target credentials and integration secrets encrypted with AES-256-GCM |
| Brute force | Rate-limited authentication with a configurable window |
| Transport | CSP, HSTS and strict transport defaults; relay enrollment requires HTTPS |
| Supply chain | CodeQL, Dependabot, Trivy gate in CI; releases ship checksums, Cosign bundles and an SBOM |
| Containers | Non-root backend, read-only filesystem and no network egress for the file share service |

Release artifacts can be verified with `sha256sum -c` and `cosign verify-blob`
— see [docs/deployment.md](docs/deployment.md).

**Reporting a vulnerability** — do not open a public issue. Follow
[SECURITY.md](SECURITY.md) and file a private advisory.

---

## Configuration

Runtime behaviour is driven by environment variables, grouped as follows:

| Group | Controls |
|---|---|
| Auth and WebAuthn | Relying-party ID, origin, MFA enforcement |
| Vault encryption | AES-256-GCM master key provisioning and rotation |
| Rate limiting | Attempt ceiling and window |
| Hardening headers | CSP and transport-security policy |
| Anomaly detection | Authentication correlation, stale-session and behaviour signals |
| Browser isolation | Engine, stream quality and size ceilings; transfer policy is Enterprise |
| File share | Service secret, quotas, drive cookie lifetime |
| Relay control plane | Enrollment secret and tokens, certificate policy, stale thresholds |
| Cluster / HA | Node identity, inter-node secret, heartbeat and stale detection |
| Container runtime | Ports, timezone, image and tag selection, volumes |

Every variable and its default: **[docs/configuration.md](docs/configuration.md)**.

Integrations (SSO, LDAP, SCIM, ITSM, SIEM) are configured from the admin UI
rather than the environment, with secrets encrypted in the database — see
[docs/integration-settings.md](docs/integration-settings.md).

---

## Documentation

| Guide | Covers |
|---|---|
| [docs/index.md](docs/index.md) | Documentation hub |
| [docs/OPEN-CORE.md](docs/OPEN-CORE.md) | CE/EE boundary, build switches, licensing model |
| [docs/admin-console.md](docs/admin-console.md) | Admin console and operator walkthrough |
| [docs/api.md](docs/api.md) | REST and WebSocket API reference |
| [docs/configuration.md](docs/configuration.md) | Every runtime environment variable |
| [docs/deployment.md](docs/deployment.md) | Production deployment, upgrades, artifact verification |
| [docs/development.md](docs/development.md) | Repository layout, build system, test suites |
| [docs/relay-deployment.md](docs/relay-deployment.md) | Relay fabric and the Linux relay daemon |
| [docs/agent.md](docs/agent.md) | Agent tunnel and `endoriumfort://` deep links |
| [docs/fileshare.md](docs/fileshare.md) | File share drives |
| [docs/integration-settings.md](docs/integration-settings.md) | SSO, LDAP, SCIM, ITSM configuration |
| [docs/siem-logging.md](docs/siem-logging.md) | Audit export to a SIEM |
| [docs/mobile-app.md](docs/mobile-app.md) | Mobile companion app |

---

## Tech stack

| Layer | Built with |
|---|---|
| Backend | C++17, [Crow](https://crowcpp.org/) 1.2, SQLite3, libssh2, Asio |
| Frontend | React 18, Vite 7, [xterm.js](https://xtermjs.org/) |
| Agent and file share | Go 1.25 |
| Isolation | Headless Chromium over the DevTools Protocol |
| Packaging | Docker, Helm, Debian packages with a signed APT repository |

---

## Roadmap

Planning happens in the open:

- [Roadmap board](https://github.com/Endorium-Group/EndoriumFort-CE/projects) — what is planned, in progress and shipped
- [Feature requests](https://github.com/Endorium-Group/EndoriumFort-CE/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement) — add yours, or upvote an existing one
- [Known issues](https://github.com/Endorium-Group/EndoriumFort-CE/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

Release history is in [CHANGELOG.md](CHANGELOG.md).

---

## License

The Community Edition is released under the **EndoriumFort Community Edition
Source-Available License v1.1** ([LICENSE](LICENSE)):

- **Free** for personal, educational, research, evaluation and internal
  non-production use.
- **Commercial or production use requires an Enterprise license.**
- Verbatim redistribution is allowed with attribution. Modified versions may
  only be contributed back as pull requests.
- Any use must cite
  [github.com/Endorium-Group/EndoriumFort-CE](https://github.com/Endorium-Group/EndoriumFort-CE).

This is a source-available license, **not** OSI open source. Review it with
counsel before relying on it commercially.

Enterprise Edition features are not covered by this license and are distributed
under a separate commercial agreement.

---

## Contributing

Pull requests are welcome. Modified versions may only be distributed as pull
requests back to this repository (LICENSE §5).

1. **Open an issue first** — pick a form in
   [New issue](https://github.com/Endorium-Group/EndoriumFort-CE/issues/new/choose):
   bug, feature, idea, or tech debt.
2. Branch from `master` (`git checkout -b feature/short-description`).
3. Keep the build green: `./build-all.sh` and the backend tests
   (see [docs/development.md](docs/development.md)).
4. Open a pull request and fill in the migration and validation sections of the
   template.

---

## Support

| Need | Where |
|---|---|
| Deployment and configuration questions | [Discussions](https://github.com/Endorium-Group/EndoriumFort-CE/discussions) |
| Bugs and feature requests | [Issues](https://github.com/Endorium-Group/EndoriumFort-CE/issues/new/choose) |
| Vulnerability reports | [SECURITY.md](SECURITY.md) — private advisory |
| Enterprise licensing | see the repository profile for contact details |

Maintained by [NergYR](https://github.com/NergYR).
