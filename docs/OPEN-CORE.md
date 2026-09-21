# EndoriumFort — Open-Core Architecture & Repo Split

This document describes how EndoriumFort is split into a **public Community
Edition (CE)** and a **private Enterprise Edition (EE)**, how the two editions
are built and distributed, and how licenses are issued.

## 1. Two editions, one codebase

| | Community (CE) | Enterprise (EE) |
|---|---|---|
| Repo | **public** `endoriumfort-core` | **private** `endoriumfort` (this repo) |
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
`cluster`, `relay`, `rdp`, `vnc`, `tunnel`, `recording`, `access_governance`
(JIT access requests), `enterprise` (SSO/OIDC, SCIM, LDAP directory, SIEM, ITSM),
`security_center` (incidents/containment/alerts), `governance` (access
policies/profiles), `session_premium` (grants, Session DNA, evidence packs,
privilege elevation, goal review), plus `pro_features.cc`.

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
git remote add origin git@github.com:NergYR/endoriumfort-core.git
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

## 6. Before going public — checklist

- [ ] Generate the **prod** issuer keypair (offline); embed public keys in
      `license.h`; keep private keys in CI secrets.
- [ ] Split licensing: core repo `LICENSE` (Apache-2.0 or BSL), `pro/` under a
      commercial `LICENSE-PRO`; fix the README licence contradiction.
- [ ] Configure `secrets.ENDORIUMFORT_LICENSE_*` and (optionally) Docker Hub
      credentials in the respective repos.
- [ ] `scripts/publish-core.sh` → push the public core repo; wire its CI.
