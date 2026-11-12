#!/usr/bin/env bash
# Prints, as GitHub step outputs (key=true|false), which parts of the tree a
# change touches, so CI jobs run only where something moved. Arguments: base
# and head commits. Without them (push, schedule, manual run) every area is
# reported as changed: nothing is skipped by accident.
set -euo pipefail
base="${1:-}"
head="${2:-}"
if [[ -z "$base" || -z "$head" ]] || ! files="$(git diff --name-only "$base" "$head" 2>/dev/null)"; then
  for area in backend frontend agent fileshare docker helm; do echo "$area=true"; done
  exit 0
fi
has() { grep -Eq "$1" <<<"$files" && echo true || echo false; }
# The workflows and this script count as every area: a CI change is tested.
ci='^\.github/(workflows|scripts)/'
echo "backend=$(has "^backend/|$ci")"
echo "frontend=$(has "^frontend/|$ci")"
echo "agent=$(has "^agent/|$ci")"
echo "fileshare=$(has "^fileshare/|$ci")"
echo "docker=$(has "^(Dockerfile|docker-compose[^/]*\.ya?ml|docker/|backend/|frontend/)|$ci")"
echo "helm=$(has "^deploy/helm/|$ci")"
