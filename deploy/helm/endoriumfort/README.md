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

## License (Enterprise)

Provide the offline license token inline via `secrets.license` (or a referenced
`secrets.existingSecret` with key `ENDORIUMFORT_LICENSE`), or upload it later in the
admin UI. Enterprise users override `image.repository`/`image.tag` to point at the
registry into which they loaded the EE image.

See `values.yaml` for the full list of options.
