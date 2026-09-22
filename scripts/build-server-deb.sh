#!/usr/bin/env bash
# ─── EndoriumFort — build the Community server .deb ───────────────────────────
# Native Debian package (endoriumfort-server): C++ backend binary + built
# frontend + nginx site + systemd unit. Community Edition (premium code absent).
# Uses dpkg-deb (present on every Debian/Ubuntu; no fpm/ruby needed).
#
# Usage: scripts/build-server-deb.sh [version]   (default: from VERSION file)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-$(tr -d '[:space:]' < "$ROOT_DIR/VERSION" 2>/dev/null || echo 0.0.0)}"
ARCH="${ARCH:-amd64}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/release/packages/linux}"
BUILD_DIR="$ROOT_DIR/backend/build"

command -v dpkg-deb >/dev/null || { echo "dpkg-deb required (dpkg package)" >&2; exit 1; }

# 1. Build backend (Community: pro/ absent auto-detected, or forced OFF)
if [ ! -x "$BUILD_DIR/endoriumfort_backend" ]; then
  echo "== Building backend (Community) =="
  cmake -S "$ROOT_DIR/backend" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTING=OFF -DENDORIUMFORT_PRO=OFF
  cmake --build "$BUILD_DIR" --target endoriumfort_backend -j"$(nproc)"
fi

# 2. Build frontend
if [ ! -d "$ROOT_DIR/frontend/dist" ]; then
  echo "== Building frontend =="
  ( cd "$ROOT_DIR/frontend" && npm ci --ignore-scripts && npm run build )
fi

# 3. Assemble package tree
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
install -d "$WORK/DEBIAN" \
           "$WORK/opt/endoriumfort/bin" "$WORK/opt/endoriumfort/frontend" \
           "$WORK/etc/nginx/sites-available" "$WORK/lib/systemd/system"
install -m 0755 "$BUILD_DIR/endoriumfort_backend" "$WORK/opt/endoriumfort/bin/endoriumfort_backend"
cp -r "$ROOT_DIR/frontend/dist/." "$WORK/opt/endoriumfort/frontend/"
install -m 0644 "$ROOT_DIR/packaging/deb/nginx-endoriumfort.conf" "$WORK/etc/nginx/sites-available/endoriumfort.conf"
install -m 0644 "$ROOT_DIR/packaging/deb/endoriumfort.service" "$WORK/lib/systemd/system/endoriumfort.service"
install -m 0755 "$ROOT_DIR/packaging/deb/postinst" "$WORK/DEBIAN/postinst"
install -m 0755 "$ROOT_DIR/packaging/deb/prerm"    "$WORK/DEBIAN/prerm"
install -m 0755 "$ROOT_DIR/packaging/deb/postrm"   "$WORK/DEBIAN/postrm"

INSTALLED_KB=$(du -sk "$WORK/opt" "$WORK/etc" "$WORK/lib" | awk '{s+=$1} END{print s}')
cat > "$WORK/DEBIAN/control" <<EOF
Package: endoriumfort-server
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: NergYR <https://github.com/NergYR/EndoriumFort>
Section: admin
Priority: optional
Homepage: https://github.com/NergYR/EndoriumFort
Installed-Size: ${INSTALLED_KB}
Depends: libsqlite3-0, libssh2-1, libssl3, nginx, ca-certificates, openssl
Description: EndoriumFort PAM Bastion - Community Edition server
 Self-hosted Privileged Access Management bastion (backend + frontend),
 served by nginx and managed by systemd. Premium/Enterprise features are not
 included in this package.
EOF

# conffiles (preserve admin edits on upgrade)
cat > "$WORK/DEBIAN/conffiles" <<'EOF'
/etc/nginx/sites-available/endoriumfort.conf
EOF

mkdir -p "$OUT_DIR"
PKG="$OUT_DIR/endoriumfort-server_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$WORK" "$PKG"
echo "Built: $PKG"
dpkg-deb --info "$PKG" | sed -n '1,20p'
