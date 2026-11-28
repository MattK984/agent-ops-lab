#!/usr/bin/env bash
# Install (or remove) the agent-ops systemd timers on the VPS. Needs sudo.
#   sudo ops/install-timers.sh            # install + enable timers (schedule flag untouched)
#   sudo ops/install-timers.sh uninstall  # disable + remove
# The timers fire, but jobs only run while AGENT_OPS_SCHEDULE=on (ops/schedule.sh).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_USER="${RUN_USER:-${SUDO_USER:-admin}}"
UNIT_DIR=/etc/systemd/system
TIMERS=(agent-ops-cve-triage-daily.timer)

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

if [[ "${1:-install}" == "uninstall" ]]; then
  for t in "${TIMERS[@]}"; do systemctl disable --now "$t" 2>/dev/null || true; rm -f "$UNIT_DIR/$t"; done
  rm -f "$UNIT_DIR/agent-ops-job@.service"
  systemctl daemon-reload
  echo "removed"; exit 0
fi

id -nG "$RUN_USER" | grep -qw docker || { echo "$RUN_USER is not in the docker group" >&2; exit 1; }

sed -e "s#@REPO_DIR@#$REPO_DIR#g" -e "s#@RUN_USER@#$RUN_USER#g" \
  "$REPO_DIR/ops/systemd/agent-ops-job@.service" > "$UNIT_DIR/agent-ops-job@.service"
for t in "${TIMERS[@]}"; do install -m 644 "$REPO_DIR/ops/systemd/$t" "$UNIT_DIR/$t"; done
chmod 755 "$REPO_DIR/ops/run-job.sh" "$REPO_DIR/ops/schedule.sh"

# Make sure the kill switch exists and defaults to off
if [[ -f "$REPO_DIR/.env" ]] && ! grep -qE '^[[:space:]]*AGENT_OPS_SCHEDULE=' "$REPO_DIR/.env"; then
  sudo -u "$RUN_USER" "$REPO_DIR/ops/schedule.sh" off >/dev/null
fi

systemd-analyze verify "$UNIT_DIR/agent-ops-job@.service" "${TIMERS[@]/#/$UNIT_DIR/}" || true
systemctl daemon-reload
for t in "${TIMERS[@]}"; do systemctl enable --now "$t"; done
"$REPO_DIR/ops/schedule.sh" status
