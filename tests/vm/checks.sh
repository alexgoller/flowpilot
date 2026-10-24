#!/usr/bin/env bash
# The installer checks, run inside the VM as root by tests/vm/run.sh, which copies flowpilot, ca.pem and
# netflow-v5.bin to /tmp/fpvm and serves the mock PCEs on the Mac (host.lima.internal).
# Usage: checks.sh PCE_PORT PCE_401_PORT        CHECKS=basic: install, status and uninstall only
# Prints `PASS <name>` or `FAIL <name>: <why>` per check and ends with `RESULT: PASS|FAIL`.
set -uo pipefail
D=/tmp/fpvm
PORT=$1 PORT401=$2
MODE=${CHECKS:-full}
PCE=host.lima.internal:$PORT
BIN=/usr/local/bin/flowpilot
UNIT=/etc/systemd/system/flowpilot.service
ANCHOR=/etc/pki/ca-trust/source/anchors/flowpilot-vm-test-ca.pem
FAILED=0
# Never in an argv: generated here, handed to the installer on stdin by the `printf` builtin.
SECRET=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1: $2"; FAILED=1; }
# check NAME WHY COMMAND...: PASS when COMMAND succeeds, else FAIL with WHY. The output of the last command run goes
# to $D/transcript under the check's name.
check() {
  local name=$1 why=$2
  shift 2
  if "$@"; then pass "$name"; else fail "$name" "$why"; fi
  if [ "$D/out" -nt "$D/transcript" ]; then { echo "=== $name"; cat "$D/out"; } >>"$D/transcript"; fi
}

# fp_install BINARY [FLAG...]: an unattended install with the secret on stdin; the output goes to $D/out, the exit code
# to $RC. `ps -eo args` is sampled while it runs ($D/ps.log). PCE_ADDR overrides the PCE.
fp_install() {
  local bin=$1
  shift
  printf '%s\n' "$SECRET" | "$bin" install --yes --pce "${PCE_ADDR:-$PCE}" --org 1 --api-user api_1 \
    --api-secret-file - --netflow 2055 "$@" >"$D/out" 2>&1 &
  sample $!
}

# sample PID: records `ps -eo args` until PID exits; its exit code goes to $RC.
sample() {
  while kill -0 "$1" 2>/dev/null; do
    ps -eo args >>"$D/ps.log"
    sleep 0.1
  done
  wait "$1"
  RC=$?
}

out_has() { grep -qF -- "$1" "$D/out"; }
active() { [ "$(systemctl is-active flowpilot)" = active ]; }
listen() { sed -n 's/^ *http_listen: *//p' /etc/flowpilot/config.yaml; }
# What a failed install must leave as it was: the files, their modes, owners and labels, and the running process.
snapshot() {
  ls -lZ "$BIN" "$BIN.prev" /etc/flowpilot "$UNIT" 2>&1 | grep -v '^total'
  sha256sum "$BIN" "$BIN.prev" /etc/flowpilot/* "$UNIT" 2>&1
  systemctl show -p MainPID flowpilot
}
modes_are() {
  local want="750 root:flowpilot /etc/flowpilot
640 root:flowpilot /etc/flowpilot/config.yaml
640 root:flowpilot /etc/flowpilot/api_key
750 flowpilot:flowpilot /var/lib/flowpilot
644 root:root $UNIT
755 root:root $BIN"
  local got
  got=$(stat -c '%a %U:%G %n' /etc/flowpilot /etc/flowpilot/config.yaml /etc/flowpilot/api_key /var/lib/flowpilot "$UNIT" "$BIN")
  [ "$got" = "$want" ] || { echo "$got" | diff <(echo "$want") - | sed 's/^/  /'; return 1; }
  getent passwd flowpilot | grep -q ':/sbin/nologin$\|:/usr/sbin/nologin$'
}
labelled_bin_t() { ls -Z "$BIN" | grep -q ':bin_t:'; }
# wait_for SECONDS COMMAND...: retries COMMAND every half second.
wait_for() {
  local end=$((SECONDS + $1))
  shift
  until "$@"; do
    [ $SECONDS -lt $end ] || return 1
    sleep 0.5
  done
}
exporter_in_stats() { curl -sf "http://$(listen)/stats" | grep -qE '"address": ?"127\.0\.0\.1"'; }
healthy() { curl -sf "http://$(listen)/healthz" >/dev/null; }

# Start from a clean host: no install left by an earlier run, the mock CA not trusted.
if [ -e "$BIN" ] || [ -e /etc/flowpilot ] || id flowpilot >/dev/null 2>&1; then
  "$D/flowpilot" uninstall --purge --yes >/dev/null 2>&1
fi
rm -f "$ANCHOR" "$D/ps.log" "$D/out" "$D/transcript" && update-ca-trust extract

check selinux_enforcing "getenforce says $(getenforce)" test "$(getenforce)" = Enforcing

fp_install "$D/flowpilot"
check pce_cert_untrusted "exit $RC: $(head -c 300 "$D/out")" \
  eval '[ $RC = 1 ] && out_has "certificate is not trusted" && [ ! -e /etc/flowpilot ] && [ ! -e $BIN ]'
cp "$D/ca.pem" "$ANCHOR" && update-ca-trust extract

fp_install "$D/flowpilot"
check install "exit $RC: $(tail -c 600 "$D/out")" eval '[ $RC = 0 ] && active'
check bin_t "$(ls -Z $BIN)" labelled_bin_t
check modes "modes, owners or the user's shell differ" modes_are
"$BIN" status >"$D/status" 2>&1
check status "exit $?: $(cat "$D/status")" grep -q '^Service:  active' "$D/status"

if [ "$MODE" != basic ]; then
  fp_install "$D/flowpilot"
  check rerun_unchanged "exit $RC: $(cat "$D/out")" eval '[ $RC = 0 ] && out_has unchanged'

  cat "$D/netflow-v5.bin" >/dev/udp/127.0.0.1/2055
  wait_for 15 exporter_in_stats
  check netflow_in_stats "/stats lists no exporter 127.0.0.1" exporter_in_stats
  "$BIN" status >"$D/status" 2>&1
  check netflow_in_status "$(cat "$D/status")" grep -qE '^  127\.0\.0\.1  netflow_v5' "$D/status"

  # A newer build: other bytes, same version (the installer compares content).
  cp "$D/flowpilot" "$D/flowpilot.next" && printf 'flowpilot-vm-upgrade' >>"$D/flowpilot.next"
  "$D/flowpilot.next" install --yes >"$D/out" 2>&1
  RC=$?
  check upgrade "exit $RC: $(tail -c 600 "$D/out")" \
    eval '[ $RC = 0 ] && cmp -s $BIN $D/flowpilot.next && cmp -s $BIN.prev $D/flowpilot && active && labelled_bin_t'

  # A broken upgrade: a script that exits 1 must be what the installer installs. A script cannot run the installer,
  # and the installer installs the file at the path it was started from (std::env::current_exe), so the good
  # installer is started from $D/inst and, while it waits for the secret on stdin, the script is bind-mounted over
  # that path. The new service then fails its health check, and the installer must switch back by itself.
  # (Should the installer ever copy its running image instead, the script is no longer installed and
  # rollback_installed_broken fails: the check never passes without the broken binary.)
  cp "$D/flowpilot" "$D/inst"
  printf '#!/bin/sh\nexit 1\n' >"$D/broken" && chmod 755 "$D/broken"
  rm -f "$D/secret.fifo" && mkfifo -m 600 "$D/secret.fifo"
  "$D/inst" install --yes --pce "$PCE" --org 1 --api-user api_1 --api-secret-file - --netflow 2055 \
    <"$D/secret.fifo" >"$D/out" 2>&1 &
  pid=$!
  exec 3>"$D/secret.fifo"
  wait_for 10 eval '[ "$(readlink /proc/$pid/exe)" = "$D/inst" ]'
  mount --bind "$D/broken" "$D/inst"
  printf '%s\n' "$SECRET" >&3
  exec 3>&-
  wait_for 30 cmp -s "$BIN" "$D/broken"
  check rollback_installed_broken "$BIN never held the broken script" test $? = 0
  sample $pid
  umount "$D/inst"
  check rollback "exit $RC: $(tail -c 800 "$D/out")" \
    eval '[ $RC = 1 ] && out_has "switching back" && out_has "upgrade rolled back" && cmp -s $BIN $D/flowpilot.next \
      && active && healthy && labelled_bin_t'

  before=$(snapshot)
  PCE_ADDR=host.lima.internal:$PORT401 fp_install "$D/flowpilot.next"
  check auth_401_changes_nothing "exit $RC: $(cat "$D/out")" \
    eval '[ $RC = 1 ] && out_has "HTTP 401" && [ "$before" = "$(snapshot)" ]'

  fp_install "$D/flowpilot.next" --text 514 --text-src-ip sip --text-dst-ip dip --text-dst-port dport \
    --text-protocol prot
  wait_for 10 eval 'ss -ulpn | grep -E ":514 .*flowpilot" >/dev/null'
  check text_binds_514 "exit $RC: $(tail -c 600 "$D/out") / $(ss -ulpn | grep ':514 ')" \
    eval '[ $RC = 0 ] && active && ss -ulpn | grep -qE ":514 .*flowpilot" && grep -q CAP_NET_BIND_SERVICE $UNIT'
fi

check secret_not_in_ps "the secret is in $D/ps.log" eval '[ -s $D/ps.log ] && ! grep -qF "$SECRET" $D/ps.log'
check secret_not_in_journal "the secret is in the journal" \
  eval '! journalctl -u flowpilot --no-pager | grep -qF "$SECRET" && ! journalctl --no-pager | grep -qF "$SECRET"'

"$D/flowpilot" uninstall >"$D/out" 2>&1
RC=$?
check uninstall_keeps_config "exit $RC: $(cat "$D/out")" \
  eval '[ $RC = 0 ] && [ -e /etc/flowpilot/config.yaml ] && [ ! -e $BIN ] && [ ! -e $UNIT ] && ! active'
"$D/flowpilot" uninstall --purge --yes >"$D/out" 2>&1
RC=$?
check purge "exit $RC: $(cat "$D/out")" \
  eval '[ $RC = 0 ] && [ ! -e /etc/flowpilot ] && [ ! -e /var/lib/flowpilot ] && [ ! -e $BIN.prev ] && ! id flowpilot >/dev/null 2>&1'

rm -f "$ANCHOR" && update-ca-trust extract
[ $FAILED = 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
