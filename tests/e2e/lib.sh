# shellcheck shell=bash disable=SC2034
# Shared helpers for the Kafka harness scenarios (kafka_out.sh, kafka_in.sh). Source it; it sets FAILED=0.

FAILED=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILED=1; }
check() { local what=$1; shift; if "$@"; then pass "$what"; else fail "$what"; fi; }

# The inside.sh syslog set (48 lines, timestamp now in UTC) on stdout.
syslog_lines() {
  python3 - <<'PY'
import time
ts = time.strftime("%b %d %Y %H:%M:%S", time.gmtime())
lines = [
    f"sip=10.50.0.{i} dip=10.60.0.{i % 7} dport={443 if i % 2 else 22} prot=6 date_time={ts}" for i in range(1, 40)
] + [f"sip=10.50.1.{i} dip=10.60.1.1 dport=53 prot=udp date_time={ts}" for i in range(1, 10)]
print("\n".join(lines))
PY
}

# FILE PATTERN SECS: wait until FILE contains PATTERN (fixed string).
wait_for() {
  for _ in $(seq "$3"); do grep -qF "$2" "$1" 2>/dev/null && return 0; sleep 1; done
  return 1
}

# PID: wait up to 60 s for it to exit, then kill it (status 137); its exit status goes to $REAPED (not a
# subshell: wait needs the parent).
reap() {
  for _ in $(seq 60); do kill -0 "$1" 2>/dev/null || break; sleep 1; done
  if kill -0 "$1" 2>/dev/null; then
    kill -KILL "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
    REAPED=137
    return
  fi
  REAPED=0; wait "$1" || REAPED=$?
}
