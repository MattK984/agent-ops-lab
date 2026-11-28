#!/usr/bin/env bash
# Switch the agent-ops schedule on or off, or show its state.
#   ops/schedule.sh status | on | off
# Only flips AGENT_OPS_SCHEDULE in .env; the timers stay installed either way
# (while "off", every timer run logs "skipped" and exits).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${AGENT_OPS_ENV_FILE:-$REPO_DIR/.env}"

current() {
  local line
  line="$(grep -E '^[[:space:]]*AGENT_OPS_SCHEDULE=' "$ENV_FILE" 2>/dev/null | tail -n 1 || true)"
  line="${line#*=}"; line="${line//[[:space:]\"\']/}"
  echo "${line:-off (not set)}"
}

set_flag() {
  [[ -f "$ENV_FILE" ]] || { echo "no $ENV_FILE" >&2; exit 1; }
  if grep -qE '^[[:space:]]*AGENT_OPS_SCHEDULE=' "$ENV_FILE"; then
    sed -i -E "s/^[[:space:]]*AGENT_OPS_SCHEDULE=.*/AGENT_OPS_SCHEDULE=$1/" "$ENV_FILE"
  else
    printf '\n# Scheduled jobs (ops/schedule.sh on|off)\nAGENT_OPS_SCHEDULE=%s\n' "$1" >> "$ENV_FILE"
  fi
  echo "AGENT_OPS_SCHEDULE=$(current)"
}

case "${1:-status}" in
  on)  set_flag on ;;
  off) set_flag off ;;
  status)
    echo "AGENT_OPS_SCHEDULE=$(current)"
    if command -v systemctl >/dev/null; then
      systemctl list-timers --all 'agent-ops-*' --no-pager || true
      journalctl -t agent-ops-job -n 10 --no-pager 2>/dev/null || true
    fi
    ;;
  *) echo "usage: $0 status|on|off" >&2; exit 2 ;;
esac
