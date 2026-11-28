#!/usr/bin/env bash
# Offline tests for ops/run-job.sh and ops/schedule.sh (fake docker, temp .env).
#   bash ops/tests/test_run_job.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPS="$HERE/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
export AGENT_OPS_ENV_FILE="$T/.env" AGENT_OPS_LOCK_FILE="$T/lock" DOCKER="$T/docker"
cat > "$DOCKER" <<'FAKE'
#!/usr/bin/env bash
echo "$*" >> "$(dirname "$0")/calls"; exit "${FAKE_RC:-0}"
FAKE
chmod +x "$DOCKER"
pass=0; fail=0
check() { if eval "$2"; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $1"; fi; }
calls() { cat "$T/calls" 2>/dev/null; }

: > "$T/.env"
out="$("$OPS/run-job.sh" cve-triage-daily)"; rc=$?
check "flag missing -> skipped, exit 0" '[[ $rc -eq 0 && "$out" == *"result=skipped reason=AGENT_OPS_SCHEDULE=off"* && -z "$(calls)" ]]'

echo 'AGENT_OPS_SCHEDULE=off' > "$T/.env"
out="$("$OPS/run-job.sh" cve-triage-daily)"; rc=$?
check "flag off -> skipped, docker not called" '[[ $rc -eq 0 && "$out" == *skipped* && -z "$(calls)" ]]'

out="$("$OPS/run-job.sh" cve-triage-daily --force)"; rc=$?
check "--force runs while off" '[[ $rc -eq 0 && "$(calls)" == "compose run --rm -T cve-triage" ]]'
rm -f "$T/calls"

"$OPS/schedule.sh" on >/dev/null
check "schedule.sh on flips the flag" 'grep -qx "AGENT_OPS_SCHEDULE=on" "$T/.env" && [[ $(grep -c AGENT_OPS_SCHEDULE "$T/.env") -eq 1 ]]'
out="$("$OPS/run-job.sh" cve-triage-daily)"; rc=$?
check "flag on -> runs, result=ok" '[[ $rc -eq 0 && "$out" == *"result=ok exit=0"* && "$(calls)" == "compose run --rm -T cve-triage" ]]'
rm -f "$T/calls"

echo 'AGENT_OPS_SCHEDULE="ON" ' > "$T/.env"
"$OPS/run-job.sh" cve-triage-daily >/dev/null
check "quoted/uppercase ON accepted" '[[ -n "$(calls)" ]]'
rm -f "$T/calls"

out="$(FAKE_RC=3 "$OPS/run-job.sh" cve-triage-daily)"; rc=$?
check "docker failure propagates" '[[ $rc -eq 3 && "$out" == *"result=failed exit=3"* ]]'

out="$("$OPS/run-job.sh" 'rm -rf /' 2>&1)"; rc=$?
check "unknown job refused, exit 2" '[[ $rc -eq 2 && "$out" == *refused* ]]'
rm -f "$T/calls"

exec 8>"$T/lock"; flock -n 8
out="$("$OPS/run-job.sh" cve-triage-daily)"; rc=$?
check "lock held -> skipped, docker not called" '[[ $rc -eq 0 && "$out" == *another-job-running* && -z "$(calls)" ]]'
exec 8>&-

"$OPS/schedule.sh" off >/dev/null
check "schedule.sh off" 'grep -qx "AGENT_OPS_SCHEDULE=off" "$T/.env"'
printf 'FOO=1\n' > "$T/.env"; "$OPS/schedule.sh" off >/dev/null
check "schedule.sh appends when missing, keeps other keys" 'grep -qx "FOO=1" "$T/.env" && grep -qx "AGENT_OPS_SCHEDULE=off" "$T/.env"'

echo "passed $pass, failed $fail"
[[ $fail -eq 0 ]]
