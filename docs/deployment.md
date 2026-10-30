---
layout: default
title: Deployment and support
---

# Deployment and support

Production deployment, support policy and release verification. See the README
for the single-host Docker quick start.

---

## Stability & Support (v1)

EndoriumFort is maintained with a v1-oriented support policy:

- Stable scope: SSH web terminal, HTTP/HTTPS proxy, agent tunnel, audit trail, session recording, RBAC/permission model, and 2FA/TOTP.
- Security support: only the latest tagged release is supported for security fixes (see `SECURITY.md`).
- Compatibility target: Linux-first deployments with official release assets for Linux/macOS/Windows agent binaries.
- Experimental or roadmap items remain explicitly marked in `## Roadmap` and are not covered by strict backward compatibility guarantees.

## Upgrade and Rollback

Minimal production-safe flow:

1. Backup persistent data (`ef-data` volume or SQLite DB + recordings).
2. Upgrade to the latest tag image/binaries.
3. Run health checks (`GET /api/health`) and a login/session smoke test.
4. If required, roll back to the previous tag and restore the backup.

---


---

## Docker Compose (Production)

```bash
# 1) Prepare production environment file
cp .env.prod.example .env.prod

# 2) Adjust .env.prod (domain, WebAuthn origin, immutable tag, ports)

# 3) Start production stack
docker compose --env-file .env.prod -f docker-compose.prod.yml up -d

# Follow logs
docker compose --env-file .env.prod -f docker-compose.prod.yml logs -f
```

Alternative with helper script:

```bash
# first run auto-creates .env.prod from .env.prod.example if missing
./run-prod.sh start

# common operations
./run-prod.sh status
./run-prod.sh logs
./run-prod.sh update
./run-prod.sh stop
```

Production notes:
- Use immutable `DOCKER_TAG` values (avoid `latest`).
- Enable ACME only when DNS and ports 80/443 are correctly exposed.
- Keep volumes (`ef-data`, `ef-recordings`, `ef-letsencrypt`) persistent and backed up.


---

## Published images

`docker-publish.yml` builds and pushes on every tag push (`v*`). Two images are
published, and they are **upgraded together** — they share the file-share ticket
format:

| Image | Registry | Contents |
|---|---|---|
| `ghcr.io/endorium-group/endoriumfort` | GHCR | The bastion: backend, frontend, nginx |
| `ghcr.io/endorium-group/endoriumfort-files` | GHCR | The file share service |
| `nergyr/endoriumfort` | Docker Hub | Mirror of the bastion image |
| `nergyr/endoriumfort-files` | Docker Hub | Mirror of the file share service |

**GHCR is the reference registry**: it is pushed on every release using the
workflow's own `GITHUB_TOKEN`, and its namespace must match the organization
that runs the workflow (`endorium-group`) — pushing under a personal namespace
fails with `permission_denied`.

The Docker Hub mirror is **conditional**: it is only pushed when
`DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` are configured as repository secrets.
Prefer GHCR in documentation and deployment manifests, since it is always
present.

Images carry a Cosign keyless signature and SLSA provenance.

## Release Artifact Verification

For tag releases, verify checksums and signed bundles from release assets:

```bash
# 1) Verify checksums file integrity
sha256sum -c checksums-sha256.txt

# 2) Verify keyless signature bundle for checksums
cosign verify-blob \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer-regexp ".*" \
  --bundle checksums-sha256.txt.bundle.json \
  checksums-sha256.txt

# 3) Verify keyless signature bundle for repository SBOM
cosign verify-blob \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer-regexp ".*" \
  --bundle repository-sbom.cdx.json.bundle.json \
  repository-sbom.cdx.json
```

---

