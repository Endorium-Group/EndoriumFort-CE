#!/usr/bin/env bash
# Starts a brand-new bastion for the end-to-end tests: empty data directory,
# factory admin, nothing else. Runs in the foreground; stop it with Ctrl-C.
#
#   E2E_BACKEND_BIN   backend binary (default: ../backend/build/endoriumfort_backend)
#   E2E_PORT          port (default 8095)
#   E2E_LICENSE_FILE  optional license, for the Pro tests (JIT policy, Appearance)
#
# On Windows the backend runs in WSL:
#   wsl -d Debian -- env E2E_BACKEND_BIN=~/ef-build-git/endoriumfort_backend bash e2e/start-backend.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${E2E_BACKEND_BIN:-$HERE/../../backend/build/endoriumfort_backend}"
PORT="${E2E_PORT:-8095}"
[ -x "$BIN" ] || { echo "Backend binary not found: $BIN (set E2E_BACKEND_BIN)" >&2; exit 1; }

DATA="$(mktemp -d "${TMPDIR:-/tmp}/endoriumfort-e2e.XXXXXX")"
trap 'rm -rf "$DATA"' EXIT
cd "$DATA"
export ENDORIUMFORT_PORT="$PORT"
export ENDORIUMFORT_WEBAUTHN_RP_ID=localhost
export ENDORIUMFORT_WEBAUTHN_ORIGIN="http://localhost:${E2E_UI_PORT:-5175}"
if [ -n "${E2E_LICENSE_FILE:-}" ]; then export ENDORIUMFORT_LICENSE_FILE="$E2E_LICENSE_FILE"; fi
# Resource passwords are refused without a vault key: use a throwaway one.
export ENDORIUMFORT_VAULT_KEY="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
echo "Fresh bastion on :$PORT (data in $DATA, removed on exit)"
"$BIN"
