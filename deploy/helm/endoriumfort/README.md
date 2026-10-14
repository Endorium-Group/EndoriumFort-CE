# EndoriumFort Helm chart

Deploy the [EndoriumFort](https://github.com/Endorium-Group/EndoriumFort-CE) PAM
bastion on Kubernetes.

## Install

```bash
helm install ef oci://ghcr.io/endorium-group/charts/endoriumfort \
  --version <X.Y.Z> \
  --namespace endoriumfort --create-namespace \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=pam.example.com \
  --set config.webauthn.rpId=pam.example.com \
  --set config.webauthn.origin=https://pam.example.com \
  --set secrets.vaultKey=$(openssl rand -hex 32)
```

> **First-time 401 `unauthorized`?** A GHCR package is **private by default** on its
> first publish, independently of the repository being public — so an anonymous
> `helm install` gets `401`. One-time fix (org owner): GitHub → org **Packages** →
> `charts/endoriumfort` → **Package settings** → **Change visibility → Public**.
> To keep it private instead, `helm registry login ghcr.io -u <user> --password-stdin`
> with a PAT (`read:packages`) before installing.

## Architecture notes

- One pod runs the backend (`:8080`) and nginx (`:80` redirect, `:443` TLS with a
  built-in self-signed cert). The Service exposes `:443`; terminate the
  browser-facing TLS at the Ingress and re-encrypt to the pod over HTTPS
  (`nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"`, already set).
- **Single replica only.** The embedded SQLite store is a single writer on a
  `ReadWriteOnce` volume; the Deployment uses the `Recreate` strategy. Active/active
  HA is an Enterprise feature and out of scope for this chart.
- Persistent volumes: `/app/data` (databases, audit log, uploaded license) and
  `/app/recordings` (session recordings).

## Storage: SQLite or PostgreSQL

The chart defaults to the embedded SQLite file on the `data` PVC — single node,
nothing else to run. Point it at PostgreSQL to lift the single-writer limit:

```yaml
database:
  type: postgresql
  postgresql:
    dsn: "postgresql://endoriumfort:PASSWORD@pg:5432/endoriumfort?sslmode=require"
```

The DSN carries a password, so it is delivered through the chart's Secret. Keep
it in your own Secret instead with `database.postgresql.existingSecret` (and
`existingSecretKey`), which is what you want with SOPS, Sealed Secrets or an
external-secrets operator. Selecting `postgresql` without a DSN fails the
render rather than silently falling back to SQLite.

The chart does not bundle a PostgreSQL server: tying a stateful dependency's
lifecycle to the app chart means `helm uninstall` can take the data with it.
Use a managed instance, an operator such as CloudNativePG, or the reference
single-instance manifest in `deploy/k8s/postgresql.yaml`. The `data` PVC stays
in use for the uploaded license file and session recording metadata, so keep
it.

⚠️ PostgreSQL is **necessary but not sufficient** for several replicas. The
backend still caches its working state in memory per pod, and the ids of some
tables come from in-process counters, so two pods would diverge and hand out
colliding ids. Keep `replicaCount: 1` and `updateStrategy: Recreate` until that
work lands — see the next section.

**Migrating an existing SQLite install**: stop the bastion, start it once
against the new DSN so it creates its schema, stop it again, then
`scripts/migrate-sqlite-to-postgres.py --replace` (in the repo) generates a
single SQL transaction to load the data. `--replace` is needed because that
first start seeded a default admin, so the target is no longer empty; without
it the script refuses to run against a database that already holds rows. Apply
with `psql "<dsn>" -v ON_ERROR_STOP=1 -f load.sql`.

## Upgrades and downtime

`helm upgrade` replaces the pod with the `Recreate` strategy: the old pod is
stopped **before** the new one starts, so there is a short gap. This is
deliberate, and `updateStrategy` must not be switched to `RollingUpdate` on the
default storage:

- The backend keeps its working state in memory and persists to single-writer
  SQLite databases. Two overlapping pods give you two divergent states writing
  the same files, and they break the tamper-evident audit hash chain, which is
  strictly sequential. That is data loss, not a blip.
- `persistence.*.accessMode` is `ReadWriteOnce`, so the volume attaches to one
  node at a time. With `maxUnavailable: 0`, a new pod scheduled onto a different
  node hangs in `Multi-Attach error` and the upgrade deadlocks.

Zero-downtime upgrades need an external shared database and active/active
clustering first; the chart exposes `updateStrategy` so it is a one-line change
once that is true.

**Keeping the gap short.** Probes target `:443` (the port the Service routes to)
so a pod is Ready only when nginx *and* the backend serve traffic, and
`readinessProbe.periodSeconds: 2` flips it within ~2s of the app being up. A
`startupProbe` absorbs a slow boot so readiness can poll that aggressively.
`terminationGracePeriodSeconds: 15` stops the old pod lingering.

The largest remaining cost is usually the image pull, which happens inside the
gap. Pre-pull the new tag on the node before upgrading:

```bash
# k3s / containerd
sudo k3s ctr images pull docker.io/nergyr/endoriumfort:1.0.35
```

With the image already present and `image.pullPolicy: IfNotPresent`, the gap is
roughly backend start + ~2s.

## Must-set values

| Value | Why |
| --- | --- |
| `config.webauthn.rpId` / `config.webauthn.origin` | Passkey/WebAuthn login fails unless these match the public hostname. |
| `secrets.vaultKey` | 64 hex chars (`openssl rand -hex 32`); enables AES-256-GCM vault encryption at rest. |
| `ingress.*` + cert-manager | Provides the real HTTPS certificate (browsers require a secure context). |

## k3s

k3s differs from the chart defaults in two ways:

- **Ingress = Traefik** (not nginx-ingress). Use `examples/values-k3s.yaml`: it sets
  `ingress.className: traefik` and `traefik.serversTransport.enabled: true`, which
  renders a Traefik `ServersTransport` and auto-adds the annotations to re-encrypt
  to the pod's self-signed `:443`.
  ```bash
  helm install ef oci://ghcr.io/endorium-group/charts/endoriumfort \
    -n endoriumfort --create-namespace \
    -f examples/values-k3s.yaml \
    --set-string secrets.vaultKey=$(openssl rand -hex 32)
  ```
- **Storage = local-path** (default StorageClass). Leave `persistence.*.storageClass`
  empty — it just works. Note `local-path` is node-local (fine on single-node k3s).

No ingress at all? `examples/values-k3s-simple.yaml` exposes the pod's TLS `:443`
directly via a `LoadBalancer` (k3s ServiceLB) — browse `https://<node-ip>` and accept
the self-signed cert once (HTTPS is still a secure context, so WebAuthn works).

If you prefer nginx-ingress on k3s, disable Traefik (`--disable traefik`), install
ingress-nginx, and use the default values.

## SIEM / log export

`config.siem` ships every audit event to a SIEM or log platform (Enterprise
licence required). Credentials belong in `secrets.siemWebhookToken` /
`secrets.siemSplunkToken`, never in `config`.

Shipping to VictoriaLogs' syslog listener:

```yaml
config:
  siem:
    hostname: bastion-prod-1   # else the pod name, which changes on restart
    syslog:
      enabled: true
      host: victorialogs.monitoring.svc.cluster.local
      port: 5514
      protocol: tcp            # prefer tcp/tls: UDP confirms nothing
```

Or to its HTTP ingestion API, with no listener to open:

```yaml
config:
  siem:
    webhook:
      enabled: true
      ndjson: true
      url: "http://victorialogs.monitoring.svc.cluster.local:9428/insert/jsonline?_time_field=_time&_msg_field=_msg&_stream_fields=host,event_category"
```

Enabling a channel without its address fails the render with a named value, so a
misconfigured export is caught at `helm install` rather than at the first event.

These values are the bootstrap defaults: an operator can override any of them
from **Administration → Integrations** without a redeploy, and the UI marks a key
it has overridden so the drift from these values stays visible. Keep the repo
authoritative by not editing those fields, or see
[docs/integration-settings.md](../../../docs/integration-settings.md).
The field model, the LogsQL queries and the operational counters are documented
in [docs/siem-logging.md](../../../docs/siem-logging.md).

## License (freemium)

The default image is **freemium**: premium is compiled in but license-gated, so it
runs as the free tier out of the box. To unlock premium, provide the offline license
token inline via `secrets.license` (or a `secrets.existingSecret` with key
`ENDORIUMFORT_LICENSE`), or upload it in the admin UI — **no image swap needed**.
A premium-free Community image is published under the `:<ver>-ce` tag for those who
want it.

See `values.yaml` for the full list of options.
