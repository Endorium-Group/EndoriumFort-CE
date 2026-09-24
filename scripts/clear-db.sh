#!/usr/bin/env bash
# ─── EndoriumFort — reset local dev state to a clean base ─────────────────────
# Removes the SQLite database(s) so the next backend start reseeds the default
# admin account (admin / Admin123, first-login forces password + MFA setup).
#
# All targets are dev artifacts and gitignored — nothing tracked is touched.
#
# Usage:
#   scripts/clear-db.sh            # remove DB files only (default)
#   scripts/clear-db.sh --all      # also wipe recordings + local audit log
#   scripts/clear-db.sh -y         # skip the confirmation prompt
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WIPE_ALL=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --all) WIPE_ALL=1 ;;
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "Unknown flag: $arg" >&2; exit 2 ;;
  esac
done

# Warn if a backend is currently holding the DB open.
if pgrep -f endoriumfort_backend >/dev/null 2>&1; then
  echo "⚠  A running endoriumfort_backend was detected — stop it (Ctrl+C) before"
  echo "   clearing, or the fresh DB will only take effect after you restart it."
fi

# DB files the backend may create depending on the launch directory.
mapfile -t DB_FILES < <(
  find "$ROOT_DIR" \
    \( -path '*/node_modules/*' -o -path '*/.git/*' \) -prune -o \
    -type f \( -name 'endoriumfort.db' -o -name 'endoriumfort.db-wal' \
               -o -name 'endoriumfort.db-shm' -o -name 'sessions.db' \) -print
)

echo "== Reset EndoriumFort dev state =="
if [ "${#DB_FILES[@]}" -eq 0 ]; then
  echo "No database files found (already clean)."
else
  printf '  DB: %s\n' "${DB_FILES[@]}"
fi

EXTRA=()
if [ "$WIPE_ALL" -eq 1 ]; then
  [ -d "$ROOT_DIR/recordings" ] && EXTRA+=("$ROOT_DIR/recordings")
  [ -d "$ROOT_DIR/backend/recordings" ] && EXTRA+=("$ROOT_DIR/backend/recordings")
  [ -d "$ROOT_DIR/backend/build/recordings" ] && EXTRA+=("$ROOT_DIR/backend/build/recordings")
  [ -f "$ROOT_DIR/audit-log.jsonl" ] && EXTRA+=("$ROOT_DIR/audit-log.jsonl")
  for e in "${EXTRA[@]}"; do echo "  EXTRA: $e"; done
fi

if [ "${#DB_FILES[@]}" -eq 0 ] && [ "${#EXTRA[@]}" -eq 0 ]; then
  exit 0
fi

if [ "$ASSUME_YES" -ne 1 ]; then
  printf "Delete the above? [y/N] "
  read -r reply
  case "$reply" in y|Y|yes|YES) ;; *) echo "Aborted."; exit 0 ;; esac
fi

for f in "${DB_FILES[@]}"; do rm -f "$f"; done
for e in "${EXTRA[@]}"; do rm -rf "$e"; done

echo "✓ Clean. Next start reseeds: admin / Admin123 (first login forces password + MFA)."
