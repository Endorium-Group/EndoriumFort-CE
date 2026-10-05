# ─── EndoriumFort — Multi-stage Dockerfile ───────────────────────────────
# Produces a minimal image with:
#   - C++ backend (Crow) on port 8080
#   - React frontend served by Nginx on port 80 (reverse-proxies to backend)
#
# Build: docker build -t endoriumfort .
# Run:   docker compose up -d

# RBI streaming engine baked into the image:
#   cdp  (default) → in-image chromium + CDP/MJPEG (no CEF fetch)
#   cef            → build + bundle the CEF-OSR "tiles" helper (homemade dirty-rect
#                    transport). Requires CEF_VERSION. The runtime engine is still
#                    chosen via ENDORIUMFORT_RBI_ENGINE at deploy time.
ARG RBI_ENGINE=cdp
# Validated CEF build (chromium 154); override to pin another. Only used when
# RBI_ENGINE=cef. main.cc compiles clean against these headers (needs C++20).
ARG CEF_VERSION=154.0.32+g682c378+chromium-154.0.8037.58

# ═══════════════════════════════════════════════════════════════════════════
#  Stage 1 — Build backend (C++17)
# ═══════════════════════════════════════════════════════════════════════════
# trixie ships OpenSSL 3.5 (native ML-DSA / post-quantum) — required by the
# hybrid Ed25519+ML-DSA-65 license verifier in backend/src/license.h.
FROM debian:trixie-slim AS backend-build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git ca-certificates \
    libsqlite3-dev libssh2-1-dev pkg-config \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy backend sources
COPY backend/CMakeLists.txt backend/VERSION backend/
COPY backend/src/ backend/src/
COPY backend/scripts/ backend/scripts/

# Generate version.h if missing
RUN if [ ! -f backend/src/version.h ]; then \
      VER=$(cat backend/VERSION 2>/dev/null || echo "0.0.0"); \
      printf '#pragma once\n#define APP_VERSION "%s"\n' "$VER" > backend/src/version.h; \
    fi

# Edition: "enterprise" (EE, includes pro/ premium modules, license-gated) or
# "community" (CE, premium physically absent). The public core repo builds CE;
# the private repo builds EE. EE builds embed the prod license issuer public key
# (set PROD_ISSUER=ON once the compiled-in public key in license.h is populated).
# PROD_ISSUER is a plain ON/OFF toggle, not a secret — the embedded issuer key is
# a *public* key (renamed from PROD_KEY to avoid the BuildKit secret-in-ARG lint).
ARG EDITION=enterprise
ARG PROD_ISSUER=OFF

# Build
RUN if [ "$EDITION" = "community" ]; then PRO_FLAG=OFF; else PRO_FLAG=ON; fi \
  && cmake -S backend -B backend/build \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_TESTING=OFF \
      -DENDORIUMFORT_PRO=$PRO_FLAG \
      -DENDORIUMFORT_LICENSE_PROD_KEY=$PROD_ISSUER \
      -DCMAKE_CXX_FLAGS="-O2" \
  && cmake --build backend/build -j"$(nproc)"

# ═══════════════════════════════════════════════════════════════════════════
#  Stage 2 — Build frontend (React + Vite)
# ═══════════════════════════════════════════════════════════════════════════
FROM node:22-slim AS frontend-build

# Same edition switch as the backend: community forces the @pro stub (premium UI
# absent), enterprise bundles the real src/pro/ overlay via the @pro alias.
ARG EDITION=enterprise

WORKDIR /build/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts

COPY frontend/ ./
RUN if [ "$EDITION" = "community" ]; then export EF_EDITION=community; fi \
  && npm run build

# ═══════════════════════════════════════════════════════════════════════════
#  Stage 2b — RBI CEF-OSR "tiles" helper (only when RBI_ENGINE=cef)
# ═══════════════════════════════════════════════════════════════════════════
# Empty default so `RBI_ENGINE=cdp` builds pull nothing (no CEF download).
FROM debian:trixie-slim AS rbi-cdp
RUN mkdir -p /rbi-out

# Real CEF helper build. Downloads a pinned CEF minimal distribution, builds the
# helper + copies the CEF runtime files next to it.
FROM debian:trixie-slim AS rbi-cef-build
ARG CEF_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build git ca-certificates curl python3 bzip2 \
      libjpeg62-turbo-dev libx11-dev \
      libasound2 libatk1.0-0 libatk-bridge2.0-0 libatspi2.0-0 libcairo2 libcups2 \
      libdbus-1-3 libexpat1 libgbm1 libglib2.0-0 libnss3 libnspr4 libpango-1.0-0 \
      libudev1 libx11-6 libxcb1 libxcomposite1 libxdamage1 libxext6 libxfixes3 \
      libxkbcommon0 libxrandr2 \
  && rm -rf /var/lib/apt/lists/*
RUN test -n "$CEF_VERSION" || (echo "CEF_VERSION build-arg is required for RBI_ENGINE=cef" >&2; exit 1)
WORKDIR /opt
# CEF version strings contain '+' → URL-encode as %2B for the download. The CDN
# can drop large transfers, so resume (-C -) with retries until the archive is
# valid (bzip2 -t), then extract.
RUN CEF_ENC="$(printf '%s' "$CEF_VERSION" | sed 's/+/%2B/g')" \
  && URL="https://cef-builds.spotifycdn.com/cef_binary_${CEF_ENC}_linux64_minimal.tar.bz2" \
  && n=0 \
  && until bzip2 -t cef.tar.bz2 2>/dev/null; do \
       n=$((n+1)); [ "$n" -gt 60 ] && { echo "CEF download failed after $n tries" >&2; exit 1; }; \
       curl -sS --connect-timeout 20 --max-time 180 -C - "$URL" -o cef.tar.bz2 || true; \
     done \
  && mkdir -p /opt/cef \
  && tar -xjf cef.tar.bz2 -C /opt/cef --strip-components=1 \
  && rm cef.tar.bz2
COPY backend/tools/rbi-cef /src/rbi-cef
RUN cmake -S /src/rbi-cef -B /build -G Ninja -DCEF_ROOT=/opt/cef -DCMAKE_BUILD_TYPE=Release \
  && cmake --build /build -j"$(nproc)"
# Normalise output: the helper + all CEF runtime files land flat in /rbi-out.
RUN mkdir -p /rbi-out \
  && cp -a /build/endoriumfort-rbi-cef /rbi-out/ \
  && find /build -maxdepth 1 -type f \( -name '*.so' -o -name '*.bin' -o -name '*.dat' -o -name '*.pak' -o -name 'chrome-sandbox' \) -exec cp -a {} /rbi-out/ \; \
  && if [ -d /build/locales ]; then cp -a /build/locales /rbi-out/; fi

FROM rbi-cef-build AS rbi-cef
RUN echo "cef helper staged"

# Select which RBI stage feeds the production image (rbi-cdp = empty, rbi-cef = helper).
FROM rbi-${RBI_ENGINE} AS rbi-selected

# ═══════════════════════════════════════════════════════════════════════════
#  Stage 3 — Production image
# ═══════════════════════════════════════════════════════════════════════════
FROM debian:trixie-slim AS production

# Edition switch (mirrors the build stages). The Kubernetes resource type needs
# kubectl, which is only installed for the Enterprise image.
ARG EDITION=enterprise
ARG TARGETARCH=amd64
ARG RBI_ENGINE=cdp

# chromium powers the default RBI engine (CDP/MJPEG) — a CORE feature, installed
# for both editions. fonts-liberation gives pages sane default fonts.
RUN apt-get update && apt-get install -y --no-install-recommends \
  nginx libsqlite3-0 libssh2-1 ca-certificates curl openssl certbot \
  chromium fonts-liberation \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --shell /usr/sbin/nologin --home-dir /app endoriumfort

# When the CEF "tiles" helper is bundled it needs libjpeg + the usual Chromium
# runtime shared libraries present in the image.
RUN if [ "$RBI_ENGINE" = "cef" ]; then \
      apt-get update && apt-get install -y --no-install-recommends \
        libjpeg62-turbo libx11-6 libxcb1 libxext6 libexpat1 libudev1 libdbus-1-3 \
        libglib2.0-0 libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
        libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
        libxrandr2 libgbm1 libasound2 libpango-1.0-0 libcairo2 libatspi2.0-0 libxshmfence1 \
      && rm -rf /var/lib/apt/lists/*; \
    fi

# kubectl for the Kubernetes exec feature (Enterprise only; skipped for CE).
RUN if [ "$EDITION" != "community" ]; then \
      KVER="$(curl -fsSL https://dl.k8s.io/release/stable.txt)" \
      && curl -fsSL "https://dl.k8s.io/release/${KVER}/bin/linux/${TARGETARCH}/kubectl" \
           -o /usr/local/bin/kubectl \
      && chmod 755 /usr/local/bin/kubectl; \
    fi

WORKDIR /app

# Backend binary
COPY --from=backend-build /build/backend/build/endoriumfort_backend /app/bin/endoriumfort_backend
RUN chmod 755 /app/bin/endoriumfort_backend

# RBI "tiles" helper + CEF runtime (empty when RBI_ENGINE=cdp). To activate at
# runtime set ENDORIUMFORT_RBI_ENGINE=tiles (the helper path below is preset).
COPY --from=rbi-selected /rbi-out/ /app/bin/rbi/
ENV ENDORIUMFORT_RBI_HELPER=/app/bin/rbi/endoriumfort-rbi-cef

# Frontend static files
COPY --from=frontend-build /build/frontend/dist /app/frontend

# Nginx config
COPY docker/nginx.conf /etc/nginx/sites-available/default

# Default TLS certificate (self-signed) generated at build time
RUN mkdir -p /etc/nginx/tls \
  && openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout /etc/nginx/tls/tls.key \
    -out /etc/nginx/tls/tls.crt \
    -days 3650 \
    -subj "/C=FR/ST=IDF/L=Paris/O=EndoriumFort/OU=Docker/CN=localhost" \
  && chmod 600 /etc/nginx/tls/tls.key \
  && chmod 644 /etc/nginx/tls/tls.crt

# Entrypoint
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod 755 /app/entrypoint.sh

# Create data directories
RUN mkdir -p /app/data /app/recordings /app/logs \
  /var/www/certbot \
  && chown -R endoriumfort:endoriumfort /app/data /app/recordings /app/logs

# Volumes for persistent data
VOLUME ["/app/data", "/app/recordings"]

# Backend on 8080 (internal), Nginx on 80
EXPOSE 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -sf http://127.0.0.1:8080/api/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
