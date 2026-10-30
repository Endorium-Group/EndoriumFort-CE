---
layout: default
title: Development
---

# Development

Repository layout, the build system, and build tuning. See the
[README](../README.md) for the standard build path.

---

## Repository layout

```
EndoriumFort/
├── backend/            # C++17 API server (Crow framework)
│   ├── src/            #   main.cc, routes, SSH, tunnel, proxy, RDP
│   ├── CMakeLists.txt  #   CMake build with FetchContent (Asio, Crow)
│   └── VERSION         #   Backend version
├── frontend/           # React 18 + Vite 7 SPA
│   ├── src/            #   App.jsx, styles.css, api.js, WebProxyViewer
│   ├── package.json    #   Dependencies (xterm.js, React)
│   └── VERSION         #   Frontend version
├── fileshare/          # File share drive service (Go, separate container)
├── agent/              # Go CLI tunnel agent
│   ├── main.go         #   Login, list, connect commands
│   ├── go.mod          #   gorilla/websocket
│   └── VERSION         #   Agent version
├── compliance/         # Compliance mappings and evidence templates
├── deploy/             # Helm chart and deployment manifests
├── docker/             # Container entrypoints and nginx configuration
├── docs/               # Documentation set (see docs/index.md)
├── packaging/          # Debian packaging and APT repository tooling
├── build-all.sh        # Linux/macOS build script (smart versioning)
├── build-all.ps1       # Windows build script (PowerShell)
├── run-dev.sh          # Dev launcher (backend + frontend + file share service)
├── VERSION             # Global version
├── CHANGELOG.md        # Version history
└── LICENSE             # Source-Available License
```

---


---

## Build system

EndoriumFort uses a **smart versioning system** based on SHA-256 hashing of source files:

- Each component (backend, frontend, agent) has its own `VERSION` file
- Versions only increment when source code actually changes
- A global `VERSION` at the root tracks the overall project version
- On each build, if any component changed, a git commit + tag is created automatically

```bash
# Full build with auto-versioning
./build-all.sh          # Linux / macOS
./build-all.ps1         # Windows (PowerShell)

# Development mode (backend + frontend with hot reload)
./run-dev.sh
```

### Cross-compilation

The build scripts cross-compile the agent automatically:

| Host | Agent binaries produced |
|------|------------------------|
| Linux amd64 | `endoriumfort-agent` (Linux) + `.exe` (Windows) + macOS amd64 / arm64 |
| macOS Intel / Apple Silicon | `endoriumfort-agent` (native macOS) + `.exe` (Windows) + Linux amd64 + macOS amd64 / arm64 |

With cross-compilation enabled, both named macOS binaries land in `agent/`:
`endoriumfort-agent-darwin-amd64` and `endoriumfort-agent-darwin-arm64`. Under
WSL, set `ENDORIUMFORT_AGENT_CROSS_COMPILE=1` to enable it.

---

---

## Build tuning on WSL

`build-all.sh` and `run-dev.sh` now use safer defaults on WSL to reduce crash/OOM risk:
- backend build uses `BUILD_TESTING=OFF` by default
- parallel compilation is capped to `2` jobs by default
- agent cross-compilation is disabled by default on WSL (`native` + `relay` only)

You can override these defaults when needed:

```bash
# Force lower peak usage
ENDORIUMFORT_BUILD_JOBS=1 ./build-all.sh

# Re-enable backend tests during normal build
ENDORIUMFORT_BUILD_TESTING=ON ./build-all.sh

# Re-enable agent cross-compilation targets on WSL
ENDORIUMFORT_AGENT_CROSS_COMPILE=1 ./build-all.sh
```

## Backend tests

```bash
cmake -S backend -B backend/build -DBUILD_TESTING=ON
cmake --build backend/build
ctest --test-dir backend/build --output-on-failure
```

SCIM validation now includes both parser-level and route-level coverage:
- `backend_scim_query_test` validates query/filter parser rules (`startIndex`, `count`, operator support).
- `backend_scim_routes_test` validates in-memory SCIM API contract behavior for `/api/scim/v2/Users`, `/api/scim/v2/Groups`, and `/api/scim/v2/ServiceProviderConfig` (pagination metadata, count clamp, invalid filter handling, SCIM `schemas` list/resource shape checks, strict hardening headers via middleware, JSON response headers, and SCIM Error envelope fields including `scimType`) and SCIM user lifecycle mutations (`POST` / `PUT` / `PATCH` / `DELETE`) including malformed JSON/missing field negative paths, PUT compatibility behavior for incoherent payloads (non-boolean `active` ignored, blank/non-string `userName` treated as absent, non-string/malformed `role(s)` values coerced to fallback `operator`, mixed `roles` arrays normalized from the first supported item with fallback on blank/unsupported leading entries, and explicit first-valid-item precedence for mixed valid/invalid role lists) with explicit `schemas`/`meta.resourceType` success-contract assertions, SCIM User metadata/validator contract checks (`meta.location`, `meta.version`, `ETag` parity on single-resource responses), expanded PATCH parser-shape failures (missing/empty `Operations`, missing `op`, unsupported `remove userName`, empty `userName`, invalid `active` type, missing role payload value, and invalid role values), PATCH precedence/atomicity behavior (last-write-wins for repeated `role`/`userName` mutations, `active=false` then `active=true` cancels deprovision, `active=true` then `active=false` triggers deprovision, `active=true` then `active=false` then `active=true` keeps user/session, `active=false` then `active=true` then `active=false` deprovisions on last op, `active=true` then `active=false` then `active=true` then `active=false` deprovisions on last op, `active=false` then `active=true` then `active=false` then `active=true` keeps user/session, `active=false` then `active=true` then `active=false` then `active=true` then `active=false` deprovisions on last op, and later invalid `op`/`path`/`value` operations fail atomically including after repeated `userName` operations), pathless PATCH compatibility fallback for invalid role payload values (normalized to `operator`), deprovision session invalidation, and emitted SCIM audit events with strict actor/role/payload checks including temporary-user deprovision payload details, consolidated anti-leak assertions for temporary deprovisioned accounts/sessions, first-valid precedence mixed-role cases, and multi-operation PATCH success paths.
- `backend_scim_routes_test` also validates enterprise LDAP routes (`/api/auth/directory/providers`, `/api/auth/directory/ldap/config`, `/api/auth/directory/ldap/test-bind`) including disabled-path contract behavior.
