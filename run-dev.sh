#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_BUILD_DIR="$ROOT_DIR/backend/build"
BACKEND_BIN="$BACKEND_BUILD_DIR/endoriumfort_backend"
FRONTEND_DIR="$ROOT_DIR/frontend"

is_wsl() {
  grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null
}

cpu_cores() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
  elif command -v getconf >/dev/null 2>&1; then
    getconf _NPROCESSORS_ONLN
  else
    echo 2
  fi
}

CORES="$(cpu_cores)"
if [[ ! "$CORES" =~ ^[0-9]+$ ]] || [[ "$CORES" -lt 1 ]]; then
  CORES=2
fi

DEFAULT_BUILD_JOBS="$CORES"
if is_wsl; then
  DEFAULT_BUILD_JOBS=2
fi

BUILD_JOBS="${ENDORIUMFORT_BUILD_JOBS:-$DEFAULT_BUILD_JOBS}"
if [[ ! "$BUILD_JOBS" =~ ^[0-9]+$ ]] || [[ "$BUILD_JOBS" -lt 1 ]]; then
  echo "Invalid ENDORIUMFORT_BUILD_JOBS='$BUILD_JOBS' (must be integer >= 1)" >&2
  exit 1
fi

BUILD_TESTING="${ENDORIUMFORT_BUILD_TESTING:-OFF}"
case "$BUILD_TESTING" in
  ON|OFF) ;;
  *)
    echo "Invalid ENDORIUMFORT_BUILD_TESTING='$BUILD_TESTING' (use ON or OFF)" >&2
    exit 1
    ;;
esac

BACKEND_PORT="${ENDORIUMFORT_PORT:-8080}"
FRONTEND_PORT="${ENDORIUMFORT_FRONTEND_PORT:-5173}"

FILES_PORT="${EF_FS_PORT:-8090}"
# File share service (fileshare/): dev data and ticket key, kept across runs.
FILES_DEV_DIR="$ROOT_DIR/.fileshare-dev"

BACKEND_PID=""
FRONTEND_PID=""
FILES_PID=""

info() {
  printf "\n\033[1;36m==> %s\033[0m\n" "$1"
}

cleanup() {
  local code=$?
  if [[ -n "$FRONTEND_PID" ]] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
    kill "$FRONTEND_PID" 2>/dev/null || true
  fi
  if [[ -n "$BACKEND_PID" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
  if [[ -n "$FILES_PID" ]] && kill -0 "$FILES_PID" 2>/dev/null; then
    kill "$FILES_PID" 2>/dev/null || true
  fi
  wait >/dev/null 2>&1 || true
  exit "$code"
}
trap cleanup INT TERM EXIT

ensure_backend() {
  if [[ -x "$BACKEND_BIN" ]]; then
    return
  fi

  info "Backend binary missing - building backend"
  cmake -S "$ROOT_DIR/backend" -B "$BACKEND_BUILD_DIR" -DBUILD_TESTING="$BUILD_TESTING"
  cmake --build "$BACKEND_BUILD_DIR" --parallel "$BUILD_JOBS"
}

ensure_frontend_deps() {
  if ! command -v npm >/dev/null 2>&1; then
    echo "npm is required to run the frontend dev server." >&2
    exit 1
  fi

  if [[ ! -x "$FRONTEND_DIR/node_modules/.bin/vite" ]]; then
    info "Installing frontend dependencies"
    (cd "$FRONTEND_DIR" && npm install)
  fi
}

# The file share service needs Go; without it, file share drives answer 503.
start_files() {
  if ! command -v go >/dev/null 2>&1; then
    info "Go not found - file share service not started (fileshare resources unavailable)"
    return
  fi
  mkdir -p "$FILES_DEV_DIR/data"
  if [[ ! -s "$FILES_DEV_DIR/secret" ]]; then
    (umask 077 && od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > "$FILES_DEV_DIR/secret")
  fi
  export ENDORIUMFORT_FILESHARE_SECRET_FILE="$FILES_DEV_DIR/secret"
  # Lets the backend purge a deleted resource's drive.
  export ENDORIUMFORT_FILESHARE_UPSTREAM="http://127.0.0.1:${FILES_PORT}"
  info "Building and starting file share service on http://localhost:${FILES_PORT}"
  (cd "$ROOT_DIR/fileshare" && go build -o "$FILES_DEV_DIR/endoriumfort-files" .)
  EF_FS_LISTEN="127.0.0.1:${FILES_PORT}" \
    EF_FS_DATA_DIR="$FILES_DEV_DIR/data" \
    "$FILES_DEV_DIR/endoriumfort-files" &
  FILES_PID=$!
}

start_backend() {
  info "Starting backend on http://localhost:${BACKEND_PORT}"
  (
    cd "$BACKEND_BUILD_DIR"
    # WebAuthn origin/RP must match the BROWSER origin (Vite on FRONTEND_PORT),
    # not the proxied backend Host — otherwise passkey verification fails.
    ENDORIUMFORT_PORT="$BACKEND_PORT" \
    ENDORIUMFORT_WEBAUTHN_RP_ID="${ENDORIUMFORT_WEBAUTHN_RP_ID:-localhost}" \
    ENDORIUMFORT_WEBAUTHN_ORIGIN="${ENDORIUMFORT_WEBAUTHN_ORIGIN:-http://localhost:${FRONTEND_PORT}}" \
    ./endoriumfort_backend
  ) &
  BACKEND_PID=$!
}

start_frontend() {
  info "Starting frontend on http://localhost:${FRONTEND_PORT}"
  (
    cd "$FRONTEND_DIR"
    EF_API_TARGET="${EF_API_TARGET:-http://localhost:${BACKEND_PORT}}" \
    EF_FILES_TARGET="${EF_FILES_TARGET:-http://localhost:${FILES_PORT}}" \
    npm run dev -- --host 0.0.0.0 --port "$FRONTEND_PORT"
  ) &
  FRONTEND_PID=$!
}

main() {
  ensure_backend
  ensure_frontend_deps

  start_files
  start_backend
  start_frontend

  info "Dev stack ready"
  echo "Backend : http://localhost:${BACKEND_PORT}"
  echo "Frontend: http://localhost:${FRONTEND_PORT}"
  [[ -n "$FILES_PID" ]] && echo "Files   : http://localhost:${FILES_PORT}"
  echo "Press Ctrl+C to stop all processes."

  wait -n "$BACKEND_PID" "$FRONTEND_PID"
}

main "$@"
