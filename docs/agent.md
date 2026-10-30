---
layout: default
title: Agent tunnel
---

# Agent tunnel and deep-link protocol

> **Enterprise Edition.** The agent tunnel routes are absent from Community
> Edition builds and return `404`.

---

## Agent Tunnel

For transparent TCP access through the bastion (HTTP, SSH, RDP, VNC, and other TCP protocols):

```bash
# Authenticate
./agent/endoriumfort-agent login \
  --server http://bastion:8080 \
  --user admin --password Admin123

# List available resources
./agent/endoriumfort-agent list \
  --server http://bastion:8080 --token <your-token>

# Open tunnel to resource #3 on local port 8888
./agent/endoriumfort-agent connect \
  --server http://bastion:8080 --token <your-token> \
  --resource 3 --local-port 8888

# Open multiple tunnels with one single agent instance
./agent/endoriumfort-agent connect \
  --server http://bastion:8080 --token <your-token> \
  --tunnel 3:8888 --tunnel 7:8890 --tunnel 10:8892

# Open multi-tunnel agent in live management mode
./agent/endoriumfort-agent connect \
  --server http://bastion:8080 --token <your-token> \
  --tunnel 3:8888 --manage
# then use: add 7:8890 | remove 8888 | list | stats | quit

# Live TUI monitoring (health + TX/RX)
./agent/endoriumfort-agent connect \
  --server http://bastion:8080 --token <your-token> \
  --tunnel 3:8888 --tunnel 7:8890 --tui

# Structured JSON logs
./agent/endoriumfort-agent connect \
  --server http://bastion:8080 --token <your-token> \
  --tunnel 3:8888 --log-json

# Browse http://127.0.0.1:8888 — traffic tunneled through bastion
```

Quick protocol tests with the same tunnel primitive:

```bash
# SSH over agent tunnel (local 2222 -> remote 22)
./agent/endoriumfort-agent connect \
  --server http://bastion:8080 --token <your-token> \
  --resource <ssh-resource-id> --local-port 2222
ssh user@127.0.0.1 -p 2222

# RDP over agent tunnel (local 3390 -> remote 3389)
./agent/endoriumfort-agent connect \
  --server http://bastion:8080 --token <your-token> \
  --resource <rdp-resource-id> --local-port 3390
# Then open your native RDP client to 127.0.0.1:3390
```

Security note (agent tunnel hardening):
- The agent no longer sends long-lived auth tokens in WebSocket URL query parameters.
- Before opening each tunnel WebSocket, the agent requests a short-lived one-time ticket from `POST /api/tunnel/ticket`.
- The backend consumes this ticket on first use for replay resistance and tighter tunnel traceability.
- Tunnel tickets are IP-bound server-side (issued source IP must match WebSocket source IP).
- Tunnel auth now uses split credentials: one-time `ticket` plus one-time `proof` sent in WebSocket headers.
- Tunnel tickets are also bound to agent `User-Agent` to reduce cross-client replay opportunities.
- Tunnel handshake now requires a cryptographic HMAC-SHA256 proof-of-possession signature with `timestamp` + `nonce` headers.
- Ticket issuance now includes a server challenge that must be echoed in `X-EndoriumFort-Tunnel-Challenge` and included in the handshake signature payload.
- Ticket issuance now includes a rotating cryptographic key identifier (`signingKeyId`) that must be echoed in `X-EndoriumFort-Tunnel-Key-Id` and signed.
- Ticket issuance also includes a server HMAC attestation (`serverAttestation`) that must be echoed in `X-EndoriumFort-Tunnel-Attestation`.
- Backend rotates real in-memory signing secrets and verifies the attestation against current/previous secret windows.
- Backend enforces signature freshness window (`max skew`) to block delayed/replayed handshake frames.
- Backend now caches handshake nonces per ticket for a short TTL to reject duplicate nonce reuse attempts.
- Backend accepts only active key IDs (current plus short grace window) to support safe key rotation without breaking active clients.
- Tunnel ticket issuance is rate-limited per user to reduce abuse/bruteforce pressure.
- Agent transport policy is strict by default: HTTPS/WSS required. CLI and interactive commands retain explicit lab overrides; browser deep-links always require HTTPS with certificate validation.
- A single running agent process can now host multiple concurrent local tunnels via repeated `--tunnel resource_id:local_port` options.
- With `--manage`, tunnels can be added/removed at runtime from the same process (`add`, `remove`, `list`, `quit`) without restarting the agent. `quit`, `exit`, end-of-input, and termination signals use the same idempotent shutdown path.
- Removing or stopping a tunnel cancels pending ticket requests, WebSocket handshakes and retry waits, closes active connections, and waits for connection workers to finish before releasing the tunnel entry. An occupied local port is reported immediately when starting a tunnel.
- Agent API requests (health, login, resources and tunnel tickets) have a 30-second total timeout, including response body reads, and 10-second connection/TLS/header deadlines. Responses are capped at 64 KiB (8 MiB for resource lists, 4 KiB for error bodies); oversized or malformed JSON responses are rejected. These request deadlines do not limit the lifetime of established tunnels.
- Agent tracks per-tunnel health and traffic counters (`TX` / `RX` bytes), visible in `list`/`stats` manage commands and in `--tui` mode.
- Agent retries WebSocket establishment with exponential backoff + jitter for better resilience during transient network/backend failures.
- Agent can refresh a token on auth failures only when its saved server binding, or `EF_TOKEN_SERVER` for `EF_TOKEN`, matches the tunnel server.
- Token storage uses current-user Windows DPAPI encryption on Windows, and strict file permissions (mode `600`) on Linux and macOS.
- Optional `--log-json` enables structured logs for easier SIEM/observability pipelines.

Or simply **click a resource tile** with the agent protocol:

- the frontend generates an `endoriumfort://connect?...` deep-link (random local port)
- your browser proposes opening EndoriumFort Agent
- the agent starts the tunnel and redirects to the local URL automatically
- the modal still provides a fallback CLI command if protocol handler is not installed

## Agent Deep-Link Protocol (`endoriumfort://`)

The agent now supports browser deep-links to provide a one-click flow:

1. User clicks an `endoriumfort://connect?...` link in browser
2. OS opens `EndoriumFortAgent`
3. Agent starts the local tunnel
4. Agent opens/redirects browser to the target URL (typically local tunnel URL)

Deep-link format:

```text
endoriumfort://connect?server=https%3A%2F%2Fendorium.space&resource=2&local-port=35739&token=eft_xxx&redirect-url=http%3A%2F%2F127.0.0.1%3A%7B%7BLOCAL_PORT%7D%7D%2F
```

Supported query parameters:

- `server` (required)
- `resource` (required)
- `local-port` (optional, auto-allocated if omitted)
- `token` (optional when a token is saved for the same server, or when `EF_TOKEN` and a matching `EF_TOKEN_SERVER` are configured)
- `redirect-url` (optional, defaults to `http://127.0.0.1:<local-port>`)
- `no-browser=1` (optional, skip automatic browser opening; useful for RDP/SSH/VNC client flows)
- `insecure=1` / `allow-http=1` and their aliases are rejected in links; lab usage requires direct CLI commands

Credential protection:

- On Windows, existing unencrypted token files are rejected: run `login --server` again to create the protected file. Do not copy it between user accounts.
- `login --server` now saves the token together with its server in `~/.endoriumfort_token` (JSON on Linux/macOS; the entire record is encrypted with current-user DPAPI on Windows). The scheme, host, port and base path must match when the token is reused; default ports and trailing slashes are normalized.
- **After upgrading, log in again.** Legacy plaintext token files have no trusted server binding and are rejected instead of being automatically assigned to a server chosen by a link.
- For links and automatic token refresh, an environment token requires `EF_TOKEN_SERVER=https://your-bastion` alongside `EF_TOKEN`. An unbound `EF_TOKEN` remains supported for direct `list`/`connect` CLI commands where the operator chooses `--server` explicitly. A configured binding is always checked.
- Links cannot enable HTTP or disable certificate validation, including through `EF_ALLOW_INSECURE_HTTP` or `EF_INSECURE_TLS`. CLI lab flags remain available.
- API requests do not follow HTTP redirects, so login passwords and bearer tokens cannot be forwarded to another endpoint. Configure the canonical backend URL directly.

Template placeholders in `redirect-url`:

- `{{LOCAL_PORT}}`
- `{{RESOURCE_ID}}`
- `{{SERVER_URL}}`

Example fallback CLI invocation:

```bash
./agent/endoriumfort-agent open-link "endoriumfort://connect?server=https%3A%2F%2Fendorium.space&resource=2&local-port=35739"
```

#### Register protocol handler per OS

Linux:

```bash
chmod +x agent/installers/linux/install-protocol.sh
./agent/installers/linux/install-protocol.sh ./agent/endoriumfort-agent
```

macOS:

```bash
chmod +x agent/installers/macos/install-protocol.sh
./agent/installers/macos/install-protocol.sh ./agent/endoriumfort-agent-darwin-arm64
```

Windows (PowerShell):

```powershell
./agent/installers/windows/install-protocol.ps1 -AgentPath .\agent\endoriumfort-agent.exe
```

Uninstall scripts are available in the same folders (`uninstall-protocol.*`).

#### Build native installer packages

Each OS folder has a self-contained **build entry point** that compiles the agent
from source and produces the native installer(s):

- Linux (`.deb` / `.rpm`): `agent/packaging/linux/build.sh`
- macOS (`.pkg`): `agent/packaging/macos/build.sh`
- Windows (`.msi`): `agent/packaging/windows/build.ps1`

Each entry point delegates to a lower-level **package-only** script that packages a
prebuilt binary (used by CI): `build-packages.sh`, `build-pkg.sh`, `build-msi.ps1`.

Every agent instance runs in the system terminal: interactive mode when launched with
no arguments, and `open-link` (tunnel with visible logs) on a deep link. macOS opens
Terminal.app, Windows opens a console window, and Linux uses the desktop environment's
terminal (`Terminal=true`).

Linux local build (compiles amd64 + arm64, then packages; requires `go`, `fpm`, `rpm`):

```bash
VERSION=1.1.0 bash agent/packaging/linux/build.sh
```

Package-only (requires prebuilt Linux binaries in `release/`):

```bash
VERSION=1.1.0 bash agent/packaging/linux/build-packages.sh
```

Linux APT packages for relay + web bastion:

```bash
VERSION=1.1.0 bash agent/packaging/linux/build-apt-packages.sh
```

macOS local build (compiles from source, then packages; requires `go` and `pkgbuild`):

```bash
# Both architectures:
VERSION=1.1.0 bash agent/packaging/macos/build.sh
# Single architecture:
VERSION=1.1.0 ARCH=arm64 bash agent/packaging/macos/build.sh
```

Package-only (requires a prebuilt Darwin binary):

```bash
VERSION=1.1.0 \
BINARY="$PWD/release/endoriumfort-agent-darwin-arm64" \
ARCH=arm64 \
bash agent/packaging/macos/build-pkg.sh
```

The `.pkg` also installs `/usr/local/bin/endoriumfort-agent`, linked to the agent
inside `/Applications/EndoriumFortAgent.app`, and registers `/usr/local/bin` in
`/etc/paths.d/endoriumfort-agent`. Open a new terminal after installation and run
`command -v endoriumfort-agent` or `endoriumfort-agent --version`. This applies to
the system-wide `.pkg` installer; the user-local protocol installer is separate.

For Intel, use `ARCH=amd64` with `endoriumfort-agent-darwin-amd64`.
Both packages contain a native Go agent and a Swift launcher compiled for the selected
architecture, targeting macOS 12 or later. The packaging script checks the executable
architectures and rejects mismatched payloads. If `ARCH` is omitted, it detects the
architecture from the agent binary. CI also checks both executables inside each `.pkg`.

`agent/packaging/build-installers.sh` is a convenience dispatcher: it detects the
host OS and runs the matching per-folder entry point (`linux/build.sh` on Linux,
`macos/build.sh` on macOS). Windows is not covered by this dispatcher — run
`windows/build.ps1` directly in PowerShell.

```bash
bash agent/packaging/build-installers.sh
# macOS, single architecture:
ARCH=arm64 bash agent/packaging/build-installers.sh
```

For the macOS/Linux entry points: `ARCH` selects a single architecture (macOS only;
Linux always builds both), `BINARY=/path/to/agent` packages an existing executable
without compiling (macOS), and packages are written under `release/` (or `RELEASE_DIR`).
`OUT_DIR` is passed through to the underlying packaging script.

Windows local build (compiles from source, then packages; requires `go` and WiX CLI):

```powershell
dotnet tool install --global wix
.\agent\packaging\windows\build.ps1              # amd64 by default
.\agent\packaging\windows\build.ps1 -Arch arm64  # Windows on ARM
.\agent\packaging\windows\build.ps1 -SkipMsi     # compile the .exe only
```

Package-only (requires a prebuilt Windows binary):

```powershell
.\agent\packaging\windows\build-msi.ps1 -Version 1.1.0 -BinaryPath .\release\endoriumfort-agent-windows-amd64.exe
# Windows on ARM:
.\agent\packaging\windows\build-msi.ps1 -Version 1.1.0 -Arch arm64 -BinaryPath .\release\endoriumfort-agent-windows-arm64.exe
```

Automated release packaging is handled by GitHub Actions workflow:

- `.github/workflows/release-agent.yml` (triggered on tag `v*`)
- uploads `.deb`, `.rpm`, `.pkg`, and `.msi` to the GitHub release
- uploads APT-ready `.deb` packages for:
  - `endoriumfort-relay`
  - `endoriumfort-web-bastion`
- publishes APT metadata for both `amd64` and `all` package architectures
- publishes an APT repository to GitHub Pages under `/apt`
- supports optional signing when secrets are configured:
  - macOS notarization: `APPLE_NOTARY_APPLE_ID`, `APPLE_NOTARY_TEAM_ID`, `APPLE_NOTARY_PASSWORD`
  - Windows Authenticode: `WINDOWS_SIGN_PFX_BASE64`, `WINDOWS_SIGN_PFX_PASSWORD`
  - APT repository signing: `APT_GPG_PRIVATE_KEY_BASE64`, `APT_GPG_PASSPHRASE` (optional), `APT_GPG_KEY_ID` (optional)

Generate APT signing secrets (one command):

```bash
chmod +x scripts/generate-apt-gpg-secrets.sh
GITHUB_REPO="Endorium-Group/EndoriumFort-CE" \
KEY_NAME="EndoriumFort APT Signing" \
KEY_EMAIL="security@endoriumfort.local" \
APT_GPG_PASSPHRASE="change-me" \
./scripts/generate-apt-gpg-secrets.sh
```

If `gh` CLI is configured and `GITHUB_REPO` is provided, the script can push secrets automatically.

Install from APT repository:

```bash
REPO_OWNER="endorium-group"
REPO_NAME="EndoriumFort-CE"

sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL "https://${REPO_OWNER}.github.io/${REPO_NAME}/apt/public.key" | \
  sudo tee /etc/apt/keyrings/endoriumfort-archive-keyring.asc >/dev/null

echo "deb [signed-by=/etc/apt/keyrings/endoriumfort-archive-keyring.asc] https://${REPO_OWNER}.github.io/${REPO_NAME}/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/endoriumfort.list

sudo apt update
sudo apt install endoriumfort-relay endoriumfort-web-bastion
```

If your environment gets `curl: (52) Empty reply from server` when fetching `public.key` (typically due custom-domain redirection issues on GitHub Pages), use this temporary fallback:

```bash
echo "deb [trusted=yes] https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/gh-pages/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/endoriumfort.list

sudo apt update
sudo apt install endoriumfort-agent endoriumfort-relay endoriumfort-web-bastion
```

This bypasses GPG verification and should be treated as a temporary workaround only.

Unsigned fallback (only if APT GPG signing is not configured in CI):

```bash
echo "deb [trusted=yes] https://${REPO_OWNER}.github.io/${REPO_NAME}/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/endoriumfort.list
```

After installing `endoriumfort-web-bastion`:

```bash
sudo cp -n /etc/endoriumfort/.env.prod.example /etc/endoriumfort/.env.prod
sudo nano /etc/endoriumfort/.env.prod

# Start stack via wrapper
sudo endoriumfort-web-bastion up -d
```

Continuous installer builds (for visibility on every change) are handled by:

- `.github/workflows/agent-installers-ci.yml` (push/PR on `dev` and `master`)
- publishes installer artifacts in the workflow run (`agent-installers-linux`, `agent-installers-macos`, `agent-installers-windows`)

---

