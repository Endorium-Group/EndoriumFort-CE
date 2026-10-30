# EndoriumFort — Open-Core Architecture & Repo Split

This document describes how EndoriumFort is split into a **public Community
Edition (CE)** and a **private Enterprise Edition (EE)**, how the two editions
are built and distributed, and how licenses are issued.

## 1. Two editions, one codebase

| | Community (CE) | Enterprise (EE) |
|---|---|---|
| Repo | **public** `Endorium-Group/EndoriumFort-CE` | **private** `NergYR/EndoriumFort` (this repo) |
| Premium code | **absent** (physically) | present in `backend/src/pro/` |
| Build switch | `-DENDORIUMFORT_PRO=OFF` (default) | `-DENDORIUMFORT_PRO=ON` |
| Docker build arg | `--build-arg EDITION=community` | `--build-arg EDITION=enterprise` |
| Premium routes | return **404** (not registered) | registered, **license-gated** (403 without a valid license) |
| Distribution | public image (Docker Hub + GHCR) | **signed offline tarball** (`ee-release.yml`) |

The premium features live in the `backend/src/pro/` overlay and are mounted
through a single hook, `register_pro_features()`:
- EE build compiles `backend/src/pro/pro_features.cc` (registers every premium
  route group).
- CE build compiles `backend/src/pro_stub.cc` (a no-op) instead — so the premium
  code is **physically absent** from the Community binary.

Shared logic needed by both editions lives in `backend/src/route_common.{h,cc}`
(permissions, env helpers, JSON response helpers, access-policy readers) and
`backend/src/iam_common.{h,cc}` (LDAP auth — core login depends on it).

### `pro/` overlay contents

`pro_features.cc` is the registration point; `register_pro_features()` mounts
every group below. Keep this list in step with it — it is what the README and
the public docs derive the CE/EE boundary from.

| Module | Premium capability | Routes |
|---|---|---|
| `cluster` | Cluster / HA: node identity, peer heartbeat, eviction | `/api/cluster/*` |
| `relay` | Relay control plane: enrollment, certificates, heartbeat, assignment | `/api/relays/*` |
| `rdp` | Browser RDP via FreeRDP | `/api/ws/rdp` |
| `vnc` | Browser VNC via noVNC | `/api/ws/vnc`, `/api/vnc/*` |
| `k8s` | Kubernetes resources: pod listing and recorded `kubectl exec` shells | `/api/k8s/*`, `/api/ws/k8s` |
| `tunnel` | Agent TCP tunnel | `/ws/tunnel` |
| `recording` | SSH session recording and replay | `/api/recordings/*` |
| `rbi_recording` | Recording of isolated-browser sessions | `/api/recordings/<id>/rbi` |
| `rbi_transfer` | DLP policy over isolated-browser transfers and clipboard | fills the `rbi_transfer_check` seam |
| `access_governance` | JIT access requests: four-eyes submit / approve / deny | `/api/access-requests/*` |
| `governance` | Centralized access policies and reusable profiles | `/api/access-policies/*`, `/api/access-profiles/*` |
| `session_premium` | Ephemeral grants, Session DNA, evidence packs, privilege elevation, goal review | `/api/access-grants`, `/api/sessions/<id>/dna`, `/api/evidence-packs/*` |
| `security_center` | Incidents, containment, live alerts | `/api/security/*` |
| `itdr` | Detection rules over the audit stream + response playbooks | `/api/itdr/*` |
| `enterprise` | SSO (OIDC/SAML), LDAP/AD directory, SCIM 2.0, SIEM, ITSM | `/api/auth/directory/*`, `/api/scim/v2/*`, SSO start/callback |
| `vault` / `vault_dynamic` | Dynamic secrets: ephemeral OS accounts per session | `/api/vault/dynamic` |
| `vault_rotation` | Scheduled rotation of stored target credentials | `/api/vault/rotation` |
| `scheduler` | Background job engine behind rotation, ITDR responses, session reaping, scheduled reports | `/api/automation/jobs` |
| `branding` | White-label logo, favicon and background | `/api/branding/*` |
| `push` | Mobile push dispatch on access requests (no routes of its own) | — |

**Boundary traps.** Two capabilities are split across the boundary rather than
being wholly premium, which is easy to document wrong:

- **Remote browser isolation** — the isolated browser itself is CE
  (`backend/src/rbi.cc`): the bytes of a file transfer or a clipboard paste are
  relayed regardless of edition. Only the *policy* over them is EE. In a CE
  build the seam is unset, so **every transfer is allowed** and the
  `ENDORIUMFORT_RBI_ALLOW_*`, `_BLOCKED_EXTENSIONS` and `_MAX_TRANSFER_MB`
  variables have no effect.
- **Access policy fields** — per-resource justification, ticket requirement and
  SSH command guard are CE. The *approval queue* (`access_governance`) and the
  *centralized policy objects* (`governance`) are EE.

## 2. Building each edition

```bash
# Enterprise (this repo) — premium present, license-gated
cmake -S backend -B backend/build -DENDORIUMFORT_PRO=ON
cmake --build backend/build

# Community — premium physically absent
cmake -S backend -B backend/build -DENDORIUMFORT_PRO=OFF
cmake --build backend/build
```

Docker:
```bash
docker build --build-arg EDITION=community  -t endoriumfort-ce .
docker build --build-arg EDITION=enterprise --build-arg PROD_KEY=ON -t endoriumfort-ee .
```

## 3. Producing the public core repo

The private monorepo is the source of truth. Generate the CE-only tree and push
it to the public repo:

```bash
scripts/publish-core.sh ../endoriumfort-core     # strips pro/, private CI, keys
cd ../endoriumfort-core
cmake -S backend -B backend/build && cmake --build backend/build   # verify CE builds
git init && git add -A && git commit -m "EndoriumFort Community Edition"
git remote add origin git@github.com:Endorium-Group/EndoriumFort-CE.git
git push -u origin master
```

> **Submodule variant** — if you prefer the private repo to consume the public
> core as a `git submodule` (rather than keeping the full monorepo), add it with
> `git submodule add <core-url> core` and provide an EE CMake wrapper that
> compiles `core/backend/src/*` **plus** `pro/backend/src/*`. The overlay
> references core headers, so the wrapper must put both source roots on the
> include path. The `publish-core.sh` export flow above is simpler and is the
> recommended default.

## 4. Distribution

- **CE (public)** — `.github/workflows/docker-publish.yml` builds
  `EDITION=community` and pushes to Docker Hub + GHCR (Cosign keyless signature +
  SLSA provenance). This workflow lives in the public core repo.
- **EE (private)** — `.github/workflows/ee-release.yml` builds `EDITION=enterprise`,
  exports the image with `docker save | gzip`, signs it with `cosign sign-blob`,
  and attaches the `.tar.gz` + `.sha256` + `.sig` + `.pem` to a private release.
  Customers install offline:
  ```bash
  cosign verify-blob --signature endoriumfort-ee-<v>.tar.gz.sig \
    --certificate endoriumfort-ee-<v>.tar.gz.pem \
    --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*' \
    endoriumfort-ee-<v>.tar.gz
  docker load < endoriumfort-ee-<v>.tar.gz
  ```
  Ideal for air-gapped / sovereign deployments — no registry access required.

## 5. Licensing (offline, no 24/7 server)

Licenses are hybrid **Ed25519 + ML-DSA-65** (post-quantum) signed tokens verified
100% offline. See `backend/src/license.h`.

- **Issue** (offline): `scripts/sign-license.sh` (labs=7d / standard=30d /
  annual=365d), or the `sign-license.yml` workflow (`workflow_dispatch`) using
  the issuer private keys stored as GitHub secrets
  (`ENDORIUMFORT_LICENSE_ED25519_KEY`, `ENDORIUMFORT_LICENSE_MLDSA_KEY`).
- **Install**: drop the token at `/app/data/license.jws` (or set
  `ENDORIUMFORT_LICENSE`), then `POST /api/license/reload` (admin). Check status
  at `GET /api/license/status`.
- **Keys**: private keys live only offline / as CI secrets (gitignored `keys/`,
  `*_priv.pem`). The public issuer keys are compiled into `license.h`
  (`issuer_keys()`), guarded by `ENDORIUMFORT_LICENSE_PROD_KEY` /
  `ENDORIUMFORT_LICENSE_DEV_KEY`. **Before shipping EE, generate the prod
  keypair, paste its public SPKI-DER (base64url) into `issuer_keys()`, and build
  with `-DENDORIUMFORT_LICENSE_PROD_KEY=ON`.**

## 6. Going public — status

- [x] **Prod issuer keypair** — embedded in `license.h` as `efort-issuer-2026`
      (Ed25519 + ML-DSA-65 public keys, under `ENDORIUMFORT_LICENSE_PROD_KEY`).
      Build EE with `-DENDORIUMFORT_LICENSE_PROD_KEY=ON`.
- [x] **Licensing split** — `LICENSE` is the CE source-available license v1.1,
      `LICENSE-PRO` the commercial terms for the `pro/` overlay. The README
      states the boundary explicitly; the earlier contradiction is gone.
      Note the choice landed on source-available rather than Apache-2.0 or BSL,
      so the CE is **not** OSI open source — say "source-available" in public
      copy, never "open source".
- [x] **Public core repo** — `Endorium-Group/EndoriumFort-CE` is published, with
      `ci`, `codeql`, `security-scan`, `release-gate`, `ce-packages`,
      `docker-publish` and `helm-publish` wired.
- [x] **Docker Hub credentials** — `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` set
      in both repos, so the Docker Hub mirror is pushed alongside GHCR.
- [ ] **License signing secrets are missing.** `sign-license.yml` needs
      `ENDORIUMFORT_LICENSE_ED25519_KEY` and `ENDORIUMFORT_LICENSE_MLDSA_KEY` in
      the private monorepo; neither is currently configured, so the
      `workflow_dispatch` issuance path cannot run. Until they are set, EE
      licenses can only be minted offline with `scripts/sign-license.sh`.
- [ ] **APT signing lives only in the CE repo.** `APT_GPG_PRIVATE_KEY_BASE64`
      and `APT_GPG_PASSPHRASE` are set there and not in the monorepo — expected,
      since `ce-packages.yml` runs in the public repo, but worth knowing before
      moving the workflow.
