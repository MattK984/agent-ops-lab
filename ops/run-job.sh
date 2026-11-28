#!/usr/bin/env bash
# Run one scheduled agent-ops job. Called by agent-ops-job@<job>.service (systemd),
# or by hand for a test: ops/run-job.sh cve-triage-daily [--force]
#
# Guardrails:
#   - kill switch: AGENT_OPS_SCHEDULE in .env must be "on", otherwise the job is
#     skipped (exit 0, one log line). --force runs it anyway (manual test only).
#   - allow-list: only the jobs in the case block below can run; no free-form commands.
#   - one job at a time: a host-wide lock, so a manual run and a timer never overlap
#     on the shared VPS (memory limits assume a single agent container).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${AGENT_OPS_ENV_FILE:-$REPO_DIR/.env}"
LOCK_FILE="${AGENT_OPS_LOCK_FILE:-/tmp/agent-ops-jobs.lock}"
DOCKER="${DOCKER:-docker}"

log() { printf '%s agent-ops %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

job="${1:-}"
force="${2:-}"
if [[ -z "$job" ]]; then
  echo "usage: $0 <job> [--force]" >&2
  exit 2
fi

# Allow-list: job name -> compose arguments (after `docker compose run --rm -T`)
case "$job" in
  cve-triage-daily) cmd=(cve-triage) ;;
  # added in later steps of Q-2.1-05:
  #   cve-digest-weekly, cve-triage-deferred
  *)
    log "job=$job result=refused reason=unknown-job"
    exit 2
    ;;
esac

# Kill switch: read only this one key, never source the whole .env
flag="off"
if [[ -r "$ENV_FILE" ]]; then
  line="$(grep -E '^[[:space:]]*AGENT_OPS_SCHEDULE=' "$ENV_FILE" | tail -n 1 || true)"
  value="${line#*=}"
  value="${value//[[:space:]\"\']/}"
  [[ -n "$value" ]] && flag="${value,,}"
fi

if [[ "$flag" != "on" && "$force" != "--force" ]]; then
  log "job=$job result=skipped reason=AGENT_OPS_SCHEDULE=$flag"
  exit 0
fi

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  log "job=$job result=skipped reason=another-job-running"
  exit 0
fi

cd "$REPO_DIR"
log "job=$job result=started flag=$flag${force:+ $force}"
start=$(date +%s)
set +e
"$DOCKER" compose run --rm -T "${cmd[@]}"
rc=$?
set -e
log "job=$job result=$([[ $rc -eq 0 ]] && echo ok || echo failed) exit=$rc seconds=$(( $(date +%s) - start ))"
exit "$rc"
