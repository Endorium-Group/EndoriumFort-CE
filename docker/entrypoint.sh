#!/bin/sh
set -e

# ─── EndoriumFort Docker Entrypoint ─────────────────────────────────────
# Starts both the backend (C++) and Nginx (frontend + reverse proxy)

echo "╔══════════════════════════════════════════════╗"
echo "║  EndoriumFort — Privileged Access Management ║"
echo "╚══════════════════════════════════════════════╝"

# Ensure data directory is writable
cd /app/data

ACME_ENABLED="${ACME_ENABLED:-0}"
ACME_DOMAIN="${ACME_DOMAIN:-}"
ACME_EMAIL="${ACME_EMAIL:-}"

refresh_tls_from_letsencrypt() {
  domain="$1"
  src_dir="/etc/letsencrypt/live/$domain"
  if [ ! -f "$src_dir/fullchain.pem" ] || [ ! -f "$src_dir/privkey.pem" ]; then
    return 1
  fi
  cp "$src_dir/fullchain.pem" /etc/nginx/tls/tls.crt
  cp "$src_dir/privkey.pem" /etc/nginx/tls/tls.key
  chmod 644 /etc/nginx/tls/tls.crt
  chmod 600 /etc/nginx/tls/tls.key
  return 0
}

configure_acme() {
  if [ "$ACME_ENABLED" != "1" ]; then
    return
  fi

  if [ -z "$ACME_DOMAIN" ] || [ -z "$ACME_EMAIL" ]; then
    echo "[entrypoint] ACME_ENABLED=1 requires ACME_DOMAIN and ACME_EMAIL"
    exit 1
  fi

  echo "[entrypoint] ACME enabled for domain: $ACME_DOMAIN"
  mkdir -p /var/www/certbot /etc/letsencrypt

  if certbot certonly --webroot -w /var/www/certbot \
      -d "$ACME_DOMAIN" \
      --email "$ACME_EMAIL" \
      --agree-tos --non-interactive --keep-until-expiring; then
    if refresh_tls_from_letsencrypt "$ACME_DOMAIN"; then
      echo "[entrypoint] ACME certificate installed for $ACME_DOMAIN"
      nginx -s reload >/dev/null 2>&1 || true
    else
      echo "[entrypoint] ACME cert obtained but copy failed for domain $ACME_DOMAIN"
      exit 1
    fi
  else
    echo "[entrypoint] ACME issuance failed, keeping current certificate"
  fi

  (
    while true; do
      sleep 12h
      certbot renew --webroot -w /var/www/certbot --quiet \
        --deploy-hook "/bin/sh -c 'cp /etc/letsencrypt/live/$ACME_DOMAIN/fullchain.pem /etc/nginx/tls/tls.crt && cp /etc/letsencrypt/live/$ACME_DOMAIN/privkey.pem /etc/nginx/tls/tls.key && chmod 644 /etc/nginx/tls/tls.crt && chmod 600 /etc/nginx/tls/tls.key && nginx -s reload'" || true
    done
  ) &
  ACME_RENEW_PID=$!
}

# Handle shutdown gracefully
shutdown() {
  echo "[entrypoint] Shutting down..."
  kill "$BACKEND_PID" "$NGINX_PID" "$ACME_RENEW_PID" 2>/dev/null || true
  wait
  exit 0
}
trap shutdown TERM INT

# RBI engine: if the CEF "tiles" helper is bundled (RBI_ENGINE=cef image) and the
# operator hasn't chosen an engine, default to tiles — the cdp fallback can't
# render native <select> popups or carry file transfers. Explicit override wins.
if [ -z "$ENDORIUMFORT_RBI_ENGINE" ] && [ -x /app/bin/rbi/endoriumfort-rbi-cef ]; then
  export ENDORIUMFORT_RBI_ENGINE=tiles
  echo "[entrypoint] CEF helper present → defaulting ENDORIUMFORT_RBI_ENGINE=tiles"
fi
echo "[entrypoint] RBI engine: ${ENDORIUMFORT_RBI_ENGINE:-cdp}"

# Start backend in background
echo "[entrypoint] Starting backend on :8080..."
/app/bin/endoriumfort_backend &
BACKEND_PID=$!

# Wait for backend to be ready
echo "[entrypoint] Waiting for backend health..."
i=0
while [ "$i" -lt 30 ]; do
  if curl -sf http://127.0.0.1:8080/api/health >/dev/null 2>&1; then
    echo "[entrypoint] Backend is healthy"
    break
  fi
  i=$((i + 1))
  if [ "$i" = "30" ]; then
    echo "[entrypoint] WARNING: Backend did not become healthy in 30s"
  fi
  sleep 1
done

# Trusted reverse proxies (ingress, load balancer) in front of this container.
# Their X-Forwarded-For is believed, so nginx (and the backend after it, through
# X-Real-IP) sees the real client address instead of the proxy's. Empty = trust
# nobody: a client cannot pick the address used for rate limits and audit.
REAL_IP_CONF=/etc/nginx/endoriumfort-real-ip.conf
: > "$REAL_IP_CONF"
if [ -n "${ENDORIUMFORT_TRUSTED_PROXIES:-}" ]; then
  for proxy in $(printf '%s' "$ENDORIUMFORT_TRUSTED_PROXIES" | tr ',' ' '); do
    # Addresses / CIDRs only: anything else would be injected into nginx.conf.
    case "$proxy" in
      *[!0-9A-Fa-f.:/]* | "")
        echo "[entrypoint] ERROR: invalid ENDORIUMFORT_TRUSTED_PROXIES entry: $proxy" >&2
        exit 1
        ;;
    esac
    echo "set_real_ip_from $proxy;" >> "$REAL_IP_CONF"
  done
  {
    echo "real_ip_header X-Forwarded-For;"
    echo "real_ip_recursive on;"
  } >> "$REAL_IP_CONF"
  echo "[entrypoint] Trusting X-Forwarded-For from: $ENDORIUMFORT_TRUSTED_PROXIES"
fi

# File share drives (fileshare resources) are served by a separate service,
# reached under /files/. Resolved per request (resolver + variable) so nginx
# starts even while that container is down or not deployed at all.
FILESHARE_CONF=/etc/nginx/endoriumfort-fileshare.conf
FILESHARE_UPSTREAM="${ENDORIUMFORT_FILESHARE_UPSTREAM:-}"
# No trailing slash: nginx would replace the request path with it.
FILESHARE_UPSTREAM="${FILESHARE_UPSTREAM%/}"
FILESHARE_MAX_BODY="${ENDORIUMFORT_FILESHARE_MAX_BODY:-2g}"
case "$FILESHARE_MAX_BODY" in
  "" | *[!0-9kKmMgG]*)
    echo "[entrypoint] ERROR: invalid ENDORIUMFORT_FILESHARE_MAX_BODY: $FILESHARE_MAX_BODY" >&2
    exit 1
    ;;
esac
if [ -n "$FILESHARE_UPSTREAM" ]; then
  case "$FILESHARE_UPSTREAM" in
    http://*) ;;
    *) echo "[entrypoint] ERROR: ENDORIUMFORT_FILESHARE_UPSTREAM must start with http://" >&2; exit 1 ;;
  esac
  case "$FILESHARE_UPSTREAM" in
    *[!A-Za-z0-9.:/_-]*)
      echo "[entrypoint] ERROR: invalid ENDORIUMFORT_FILESHARE_UPSTREAM: $FILESHARE_UPSTREAM" >&2
      exit 1
      ;;
  esac
  RESOLVER="$(awk '/^nameserver/ { print $2; exit }' /etc/resolv.conf 2>/dev/null)"
  case "$RESOLVER" in *:*) RESOLVER="[$RESOLVER]" ;; esac
  {
    echo "location /files/ {"
    if [ -n "$RESOLVER" ]; then echo "    resolver $RESOLVER valid=30s;"; fi
    echo "    set \$ef_files_upstream $FILESHARE_UPSTREAM;"
    echo "    proxy_pass \$ef_files_upstream;"
    echo "    proxy_http_version 1.1;"
    echo "    proxy_set_header Host \$host;"
    echo "    proxy_set_header X-Real-IP \$remote_addr;"
    echo "    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;"
    echo "    proxy_set_header X-Forwarded-Proto \$scheme;"
    echo "    client_max_body_size $FILESHARE_MAX_BODY;"
    # The server-level security headers apply; drop the service's duplicates.
    echo "    proxy_hide_header X-Frame-Options;"
    echo "    proxy_hide_header X-Content-Type-Options;"
    echo "    proxy_hide_header Referrer-Policy;"
    echo "    proxy_request_buffering off;"
    echo "    proxy_buffering off;"
    echo "    proxy_read_timeout 3600s;"
    echo "    proxy_send_timeout 3600s;"
    echo "}"
  } > "$FILESHARE_CONF"
  echo "[entrypoint] File share service: $FILESHARE_UPSTREAM"
else
  printf '%s\n' 'location /files/ { default_type application/json; return 503 '"'"'{"error":"File share service is not configured"}'"'"'; }' > "$FILESHARE_CONF"
fi

# Start Nginx in background
echo "[entrypoint] Starting Nginx on :443 (TLS) and :80 (redirect)..."
nginx -g "daemon off;" &
NGINX_PID=$!

configure_acme

# Wait for either process to exit
wait "$BACKEND_PID" "$NGINX_PID" 2>/dev/null || true
echo "[entrypoint] Process exited, shutting down..."
kill "$BACKEND_PID" "$NGINX_PID" 2>/dev/null || true
wait
