#!/usr/bin/env bash
# FaultLine one-shot maintenance:
#   ./update.sh            # sync everything, commit, push
#   ./update.sh --no-push  # sync + commit, leave the push to you
#   ./update.sh --dry-run  # sync only, no git operations
# Any other arguments are passed through to `python3 -m faultline sync`
# (e.g. --skip-enrich, --max-enrich 5, --days 7, --refresh-limit 100).
#
# Optional environment:
#   NVD_API_KEY           10x faster NVD refresh (https://nvd.nist.gov/developers/request-an-api-key)
#   GITHUB_TOKEN          higher GHSA rate limit; also used for pushing in CI
#   FAULTLINE_ENRICH=0    skip Claude enrichment even if `claude` is installed
#   FAULTLINE_ENRICH_MODEL  model passed to `claude --model`
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

PUSH=1
DRY=0
PASS=()
for arg in "$@"; do
  case "$arg" in
    --no-push) PUSH=0 ;;
    --dry-run) DRY=1; PUSH=0 ;;
    *) PASS+=("$arg") ;;
  esac
done

log() { printf '[update.sh] %s\n' "$*" >&2; }

if ! command -v python3 >/dev/null; then log "python3 not found"; exit 1; fi
if [ "$DRY" = 0 ] && [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  log "working tree has uncommitted changes; commit or stash them first"; exit 1
fi

log "running pipeline"
if ! python3 -m faultline sync "${PASS[@]+"${PASS[@]}"}"; then
  log "pipeline failed; nothing committed"; exit 2
fi
python3 -m unittest discover -s tests -q >/dev/null || { log "unit tests failed; nothing committed"; exit 2; }

[ "$DRY" = 1 ] && { log "dry run complete"; exit 0; }

PATHS=()
for p in CVE-json index.json stats.json README.md; do [ -e "$p" ] && PATHS+=("$p"); done
git add -A "${PATHS[@]}"
if git diff --cached --quiet; then
  log "no changes to commit"; exit 0
fi

TOTAL=$(python3 -c "import json;print(json.load(open('stats.json'))['total'])")
ADDED=$(git diff --cached --name-status --diff-filter=A -- CVE-json | wc -l | tr -d ' ')
UPDATED=$(git diff --cached --name-status --diff-filter=M -- CVE-json | wc -l | tr -d ' ')
PENDING=$(python3 -c "import json,os;p='data/queue/pending.json';print(len(json.load(open(p))) if os.path.exists(p) else 0)")
MSG="data: sync $(date -u +%Y-%m-%d) — ${TOTAL} records (+${ADDED} new, ${UPDATED} refreshed, ${PENDING} queued)"
git -c user.name="${GIT_AUTHOR_NAME:-$(git config user.name || echo FaultLine Bot)}" \
    -c user.email="${GIT_AUTHOR_EMAIL:-$(git config user.email || echo faultline-bot@users.noreply.github.com)}" \
    commit -q -m "$MSG" -m "Automated by update.sh (python3 -m faultline sync)."
log "committed: $MSG"

if [ "$PUSH" = 1 ]; then
  BRANCH=$(git rev-parse --abbrev-ref HEAD)
  if git push origin "$BRANCH"; then log "pushed to origin/$BRANCH"; else log "push failed (commit kept locally)"; exit 3; fi
else
  log "push skipped (--no-push); run: git push origin $(git rev-parse --abbrev-ref HEAD)"
fi
