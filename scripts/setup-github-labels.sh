#!/usr/bin/env bash
# ─── EndoriumFort — provision the shared label vocabulary ────────────────────
# Creates (or updates) the labels the issue forms in .github/ISSUE_TEMPLATE
# reference, plus the area / edition / priority sets used by the Project board.
#
# Idempotent: existing labels are updated in place, never duplicated.
#
# Usage:
#   scripts/setup-github-labels.sh                 # this checkout's repo
#   scripts/setup-github-labels.sh owner/repo ...  # explicit repos
#   DRY_RUN=1 scripts/setup-github-labels.sh       # print without applying
set -euo pipefail

REPOS=("$@")
if [ ${#REPOS[@]} -eq 0 ]; then
  # Default to the repository this checkout points at, so the script carries no
  # hardcoded repository name into the public community tree.
  REPOS=("$(gh repo view --json nameWithOwner -q .nameWithOwner)")
  echo "No repository given — defaulting to ${REPOS[0]}"
  echo "Pass repositories explicitly to cover several: $(basename "$0") owner/repo ..."
  echo
fi

# name|color|description
LABELS=(
  # ─ type ─ (bug/enhancement/documentation already ship with GitHub)
  "idea|c5def5|Exploratory direction, not yet a specification"
  "tech-debt|fef2c0|Refactoring, dependency or CI maintenance"
  "needs-triage|ededed|Awaiting triage — set area, edition and priority"
  "regression|b60205|Worked in a previous release"

  # ─ area ─
  "area:backend|1d76db|C++ backend"
  "area:frontend|1d76db|React frontend"
  "area:agent|1d76db|Go agent and tunnels"
  "area:relay|1d76db|Relay daemon and routing"
  "area:fileshare|1d76db|File share drives"
  "area:rbi|1d76db|Remote browser isolation"
  "area:licensing|1d76db|License issuance, validation and gating"
  "area:infra|1d76db|CI, packaging, Docker, Helm"
  "area:docs|1d76db|Documentation"
  "area:mobile|1d76db|Mobile companion app"
  "area:security|b60205|Hardening, crypto, compliance"

  # ─ edition ─ (the open-core boundary)
  "edition:ce|0e8a16|Ships in Community Edition"
  "edition:core|0e8a16|Ships in CORE"
  "edition:ee|5319e7|Enterprise Edition only"

  # ─ priority ─
  "P0|b60205|Blocking — drop everything"
  "P1|d93f0b|Next release"
  "P2|fbca04|Planned"
  "P3|c2e0c6|Nice to have"
)

for repo in "${REPOS[@]}"; do
  echo "── $repo ──"
  for entry in "${LABELS[@]}"; do
    IFS='|' read -r name color desc <<< "$entry"
    if [ -n "${DRY_RUN:-}" ]; then
      printf '  would set %-22s #%s  %s\n' "$name" "$color" "$desc"
      continue
    fi
    # --force updates an existing label instead of failing on conflict
    gh label create "$name" \
      --repo "$repo" \
      --color "$color" \
      --description "$desc" \
      --force >/dev/null
    printf '  %-22s ok\n' "$name"
  done
done

echo
echo "Done. Labels the issue forms depend on: idea, tech-debt, needs-triage."
