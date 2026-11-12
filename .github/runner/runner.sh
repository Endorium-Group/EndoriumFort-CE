#!/usr/bin/env bash
# Self-hosted runner for the Linux jobs, in a container (see README.md here).
#
#   runner.sh register   one-time: build the image, register the runner
#   runner.sh start      start it (restarts with Docker / WSL from then on)
#   runner.sh stop       stop it; jobs then wait — clear LINUX_RUNNER first
#   runner.sh logs       follow its output
#   runner.sh remove     unregister it and delete the container
set -euo pipefail

REPO="${RUNNER_REPO:-NergYR/EndoriumFort}"
DIR="${RUNNER_DIR:-$HOME/actions-runner}"   # runner binaries, config, _work
NAME="${RUNNER_NAME:-wsl-$(hostname)}"
LABELS="${RUNNER_LABELS:-wsl}"
IMAGE=endoriumfort-gh-runner
CONTAINER=gh-runner
HERE="$(cd "$(dirname "$0")" && pwd)"

[ -x "$DIR/run.sh" ] || { echo "No runner in $DIR — see README.md (download and extract it there)." >&2; exit 1; }

in_container() {
  docker run --rm -v "$DIR:$DIR" -w "$DIR" "$IMAGE" "$@"
}

case "${1:-}" in
  register)
    docker build -t "$IMAGE" \
      --build-arg RUNNER_UID="$(id -u)" \
      --build-arg DOCKER_GID="$(getent group docker | cut -d: -f3)" \
      "$HERE"
    token="$(gh api -X POST "repos/$REPO/actions/runners/registration-token" -q .token)"
    in_container ./config.sh --unattended --replace \
      --url "https://github.com/$REPO" --token "$token" \
      --name "$NAME" --labels "$LABELS" --work "$DIR/_work"
    # Jobs that run as root in their own container leave root-owned files in
    # the workspace; give them back before the next checkout cleans it.
    cat > "$DIR/job-hook.sh" <<'EOF'
#!/bin/sh
[ -n "${GITHUB_WORKSPACE:-}" ] && sudo chown -R "$(id -u):$(id -g)" "$(dirname "$GITHUB_WORKSPACE")" 2>/dev/null
exit 0
EOF
    chmod +x "$DIR/job-hook.sh"
    printf 'ACTIONS_RUNNER_HOOK_JOB_STARTED=%s\nACTIONS_RUNNER_HOOK_JOB_COMPLETED=%s\n' \
      "$DIR/job-hook.sh" "$DIR/job-hook.sh" > "$DIR/.env"
    echo "Registered as $NAME. Now: $0 start"
    ;;
  start)
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    # HOME three levels above the workspace ($DIR/_work/<repo>/<repo>), as on
    # hosted runners: actions/cache stores paths relative to the workspace,
    # so caches saved on GitHub (setup-trivy…) restore where they are looked for.
    docker run -d --name "$CONTAINER" --restart unless-stopped \
      -e HOME="$DIR" \
      -v "$DIR:$DIR" -w "$DIR" \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v gh-runner-toolcache:/opt/hostedtoolcache \
      "$IMAGE" ./run.sh
    echo "Started. Jobs go to it once the repository variable LINUX_RUNNER is set (README.md)."
    ;;
  stop) docker stop "$CONTAINER" ;;
  logs) docker logs -f "$CONTAINER" ;;
  remove)
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    token="$(gh api -X POST "repos/$REPO/actions/runners/remove-token" -q .token)"
    in_container ./config.sh remove --token "$token"
    ;;
  *) sed -n '2,9p' "$0"; exit 1 ;;
esac
