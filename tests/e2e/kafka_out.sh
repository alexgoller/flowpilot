#!/usr/bin/env bash
# PCE Kafka mode scenarios inside a linux/amd64 container on the Docker network flowpilot-e2e, with the
# test broker (tests/kafka/broker.sh up network) reachable as kafka:9093 and the topics already created.
# Usage:
#   kafka_out.sh out   CERTS TOOL OUT_DIR RUST_BIN ORIG_BIN FLOWGEN_BIN [SCENARIO_SECS]
#       Differential: FlowLink (topic flows-orig, built-in gateway name mapped to 127.0.0.1 by the caller and
#       passed in $FLOWLINK_GW) and FlowPilot (topic flows-pilot, pce_kafka.gateway) on identical input.
#   kafka_out.sh pilot CERTS TOOL OUT_DIR RUST_BIN
#       FlowPilot only (CI): the gateway answers 404, the settings come from the kafka_info file.
# CERTS is the broker's certificate directory (connection_string); TOOL is the kafka_tool example.
# The connection string never appears in an argv or on stdout. $FLOWLINK_GW is never printed: FlowLink's
# log is redacted as soon as FlowLink has exited, and again from the EXIT trap on every other way out.
set -euo pipefail
MODE=$1 CERTS=$2 TOOL=$3 OUT=$4 RUST=$5
HERE=$(cd "$(dirname "$0")" && pwd)
CS=$CERTS/connection_string
rm -rf "$OUT" && mkdir -p "$OUT"
cd "$OUT"
umask 077
printf 'api_test secret_test\n' > api_info

FAILED=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILED=1; }
check() { local what=$1; shift; if "$@"; then pass "$what"; else fail "$what"; fi; }

# The Integrations JSON for TOPIC, with the broker's connection string (read from a file, never from argv).
gateway_body() {
  python3 - "$CS" "$1" "$2" <<'PY'
import json, sys
cs, topic, out = open(sys.argv[1]).read(), sys.argv[2], sys.argv[3]
json.dump({"bootstrapServers": "kafka:9093", "topic": topic, "connectionString": cs,
           "maxObjectsPerMessage": 10000}, open(out, "w"))
PY
}

# NAME PORT [mock_gateway options]: start a mock gateway, wait until it listens.
start_gateway() {
  local name=$1 port=$2; shift 2
  python3 "$HERE/mock_gateway.py" --port "$port" --requests "$name.requests" "$@" \
    >"$name.out" 2>"$name.log" &
  for _ in $(seq 50); do grep -q listening "$name.out" 2>/dev/null && return 0; sleep 0.2; done
  echo "mock gateway $name did not start"; exit 1
}

# Every config request of gateway NAME asked for pce.e2e.test, org 1, with Basic auth.
gateway_asked() {
  python3 - "$1.requests" <<'PY'
import json, sys
reqs = [json.loads(l) for l in open(sys.argv[1])]
ok = reqs and all(r["path"] == "/integrations/api/v1/config/flowlink-kafka" and
                  r["query"] == "pceHost=pce.e2e.test&orgId=1" and r["basic_auth"] for r in reqs)
sys.exit(0 if ok else 1)
PY
}

# NAME NETFLOW IPFIX TEXT EXTRA_YAML: config.yaml for one collector, consumers as in inside.sh.
setup() {
  local name=$1 nf=$2 ipfix=$3 text=$4 extra=$5
  mkdir -p "$name/data"
  {
    cat <<YAML
pce_addr: pce.e2e.test:8443
org_id: 1
api_key: $OUT/api_info
verify_pce_cert: false
data_directory: $OUT/$name/data
YAML
    printf '%s\n' "$extra"
    echo "consumers:"
    [ "$nf" ] && cat <<YAML
  - name: netflow
    parser: {type: netflow}
    connectors: [{type: udp, properties: {ports: "$nf"}}]
  - name: ipfix
    parser: {type: ipfix}
    connectors: [{type: udp, properties: {ports: "$ipfix"}}]
YAML
    cat <<YAML
  - name: syslog
    parser:
      type: text
      properties: {src_ip: sip, dst_ip: dip, dst_port: dport, protocol: prot, timestamp: "date_time, 1", timestamp_format: "mmm dd yyyy HH:MM:SS"}
    connectors: [{type: udp, properties: {ports: "$text"}}]
YAML
  } > "$name/config.yaml"
}

# The inside.sh syslog set (48 lines) to 127.0.0.1:PORT.
send_syslog() {
  python3 - "$1" <<'PY'
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ts = time.strftime("%b %d %Y %H:%M:%S", time.gmtime())
lines = [
    f"sip=10.50.0.{i} dip=10.60.0.{i % 7} dport={443 if i % 2 else 22} prot=6 date_time={ts}" for i in range(1, 40)
] + [f"sip=10.50.1.{i} dip=10.60.1.1 dport=53 prot=udp date_time={ts}" for i in range(1, 10)]
for l in lines:
    s.sendto(l.encode(), ("127.0.0.1", int(sys.argv[1])))
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

# Neither the log nor anything else FlowPilot wrote there holds the connection string.
no_secret() { ! grep -rqF -f "$CS" "$1"; }

# The last 20 lines of a FlowPilot log, only once it is known not to hold the connection string.
show_tail() {
  if no_secret "$1"; then tail -20 "$1"; else echo "($1 withheld: it contains the connection string)"; fi
}

# FlowLink's log may name its built-in gateway (e.g. in a request error): stop FlowLink if it still runs,
# then replace the name. Idempotent; runs on the normal path and from the EXIT trap.
ORIG_PID=
redact_flowlink() {
  [ -n "${FLOWLINK_GW:-}" ] && [ -f "$OUT/orig/flowlink.log" ] || return 0
  if [ -n "$ORIG_PID" ] && kill -0 "$ORIG_PID" 2>/dev/null; then
    kill -KILL "$ORIG_PID" 2>/dev/null || true
    wait "$ORIG_PID" 2>/dev/null || true
  fi
  python3 - "$OUT/orig/flowlink.log" <<'PY'
import os, sys
p, gw = sys.argv[1], os.environ["FLOWLINK_GW"].encode()
data = open(p, "rb").read()
open(p, "wb").write(data.replace(gw, b"<flowlink-gateway>"))
PY
}
trap redact_flowlink EXIT

dump() { "$TOOL" dump --brokers kafka:9093 --topic "$1" --out "$2" --sasl-password-file "$CS" --insecure; }

keys_ok() {
  python3 - "$1/keys.txt" <<'PY'
import re, sys
keys = open(sys.argv[1]).read().splitlines()
sys.exit(0 if keys and all(re.fullmatch(r"1\+\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", k) for k in keys) else 1)
PY
}

scenario_out() {
  local ORIG=$6 FLOWGEN=$7 SECS=${8:-10}
  [ -n "${FLOWLINK_GW:-}" ] || { echo "FLOWLINK_GW is not set"; exit 1; }
  gateway_body flows-orig gw-orig.json
  gateway_body flows-pilot gw-pilot.json
  start_gateway gw-orig 443 --body-file gw-orig.json
  start_gateway gw-pilot 8444 --body-file gw-pilot.json
  setup orig 12055 14739 16514 $'pce_kafka:\n  installation_id: inst-e2e'
  setup rust 22055 24739 26514 $'pce_kafka:\n  installation_id: inst-e2e\n  gateway: localhost:8444'
  python3 "$HERE/udp_fanout.py" 2055:12055,22055 4739:14739,24739 6514:16514,26514 &
  sleep 1

  (cd orig && CONFIG_FILE=$OUT/orig/config.yaml TZ=UTC exec "$ORIG" "" >flowlink.log 2>&1) & ORIG_PID=$!
  (cd rust && CONFIG_FILE=$OUT/rust/config.yaml TZ=UTC exec "$RUST" "" >flowlink.log 2>&1) & local RUST_PID=$!
  wait_for rust/flowlink.log "KafkaProducer setup" 60 || { show_tail rust/flowlink.log; fail "FlowPilot producer setup"; }
  wait_for orig/flowlink.log "KafkaProducer setup" 120 || fail "FlowLink producer setup"
  sleep 2

  for proto in v5 v9 ipfix; do
    "$FLOWGEN" run --preset three-tier --collector "127.0.0.1:$([ $proto = ipfix ] && echo 4739 || echo 2055)" \
      --protocol "$proto" --rate 50 --duration "${SECS}s" --seed 7 --quiet
  done
  send_syslog 6514
  sleep 3

  kill -QUIT $ORIG_PID $RUST_PID
  local orig_st rust_st
  reap $ORIG_PID; orig_st=$REAPED
  reap $RUST_PID; rust_st=$REAPED
  redact_flowlink
  echo "exit status: original=$orig_st flowpilot=$rust_st"
  check "FlowPilot exits 0 after the signal" [ "$rust_st" = 0 ]

  dump flows-orig orig/kafka
  dump flows-pilot rust/kafka
  python3 "$HERE/decode_posts.py" --kafka orig/kafka > orig.json
  python3 "$HERE/decode_posts.py" --kafka rust/kafka > rust.json
  check "message keys match 1+<time>Z (FlowLink)" keys_ok orig/kafka
  check "message keys match 1+<time>Z (FlowPilot)" keys_ok rust/kafka
  check "FlowLink's gateway asked for pce.e2e.test org 1 with Basic auth" gateway_asked gw-orig
  check "FlowPilot's gateway asked for pce.e2e.test org 1 with Basic auth" gateway_asked gw-pilot
  check "FlowPilot logs Sending file: ... kafkaSync: true" grep -qE '^.* Sending file: .* kafkaSync: true$' rust/flowlink.log
  check "FlowPilot logs Sent kafka message to partition:" grep -qF "Sent kafka message to partition:" rust/flowlink.log
  check "FlowPilot's log has no connection string" no_secret rust

  # A second short run with -debug: still no connection string.
  setup debug 32055 34739 36514 $'pce_kafka:\n  installation_id: inst-e2e\n  gateway: localhost:8444'
  (cd debug && CONFIG_FILE=$OUT/debug/config.yaml TZ=UTC exec "$RUST" -debug >flowlink.log 2>&1) & local DBG_PID=$!
  wait_for debug/flowlink.log "KafkaProducer setup" 60 || fail "FlowPilot -debug producer setup"
  send_syslog 36514
  sleep 1
  kill -QUIT $DBG_PID
  reap $DBG_PID
  check "FlowPilot's -debug log has no connection string" no_secret debug
  check "FlowPilot's -debug log is a debug log" grep -qF "brokers:" debug/flowlink.log

  python3 - "$OUT" <<'PY' || FAILED=1
import json, sys
o, r = (json.load(open(f"{sys.argv[1]}/{n}.json")) for n in ("orig", "rust"))
print(f"messages: orig={o['posts']} rust={r['posts']}  records: orig={len(o['records'])} rust={len(r['records'])}")
print(f"aggregation_seconds: orig={o['aggregation_seconds']} rust={r['aggregation_seconds']}")
ok = True
want = {"org_ids": [1], "installation_ids": ["inst-e2e"], "pce_hosts": ["pce.e2e.test:8443"]}
for k, v in want.items():
    good = o[k] == r[k] == v
    ok &= good
    print(f"{'PASS' if good else 'FAIL'}: header {k}: orig={o[k]} rust={r[k]}")
devs = {x.get("device_addr") for x in o["records"] + r["records"]}
good = devs == {"7f000001"}
ok &= good
print(f"{'PASS' if good else 'FAIL'}: every record has device_addr 127.0.0.1 (seen {sorted(map(str, devs))})")
good = not any("dst_dbi" in x or "dst_dbo" in x for x in o["records"] + r["records"])
ok &= good
print(f"{'PASS' if good else 'FAIL'}: no record has dst_dbi/dst_dbo")
same = o["records"] == r["records"]
print("RECORDS IDENTICAL" if same else "RECORDS DIFFER")
if not same:
    so = {json.dumps(x, sort_keys=True) for x in o["records"]}
    sr = {json.dumps(x, sort_keys=True) for x in r["records"]}
    for x in sorted(so - sr)[:20]: print("  only orig:", x)
    for x in sorted(sr - so)[:20]: print("  only rust:", x)
sys.exit(0 if ok and same and o["records"] else 1)
PY
}

scenario_pilot() {
  gateway_body flows-pilot kafka_info.json
  chmod 600 kafka_info.json
  start_gateway gw-pilot 8444 --status 404
  setup rust "" "" 6514 "$(cat <<YAML
aggregation_minutes: 5
pce_kafka:
  installation_id: inst-e2e
  gateway: localhost:8444
  kafka_info: $OUT/kafka_info.json
stats:
  interval_seconds: 5
  http_listen: 127.0.0.1:9180
YAML
)"
  (cd rust && CONFIG_FILE=$OUT/rust/config.yaml TZ=UTC exec "$RUST" "" >flowpilot.log 2>&1) & local PID=$!
  wait_for rust/flowpilot.log "KafkaProducer setup" 60 || { show_tail rust/flowpilot.log; fail "producer setup"; exit 1; }
  sleep 1
  send_syslog 6514
  # The first window closes 5 minutes after the start; then one stats line that has counted the upload.
  wait_for rust/flowpilot.log "Sent kafka message to partition:" 420 || { show_tail rust/flowpilot.log; fail "no Kafka message sent"; }
  local n
  n=$(grep -c FLOWPILOT_STATS rust/flowpilot.log || true)
  for _ in $(seq 30); do [ "$(grep -c FLOWPILOT_STATS rust/flowpilot.log || true)" -gt "$n" ] && break; sleep 1; done
  python3 -c 'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:9180/metrics").read().decode())' > metrics.txt
  kill -QUIT $PID
  reap $PID
  local st=$REAPED
  check "FlowPilot exits 0 after the signal (status $st)" [ "$st" = 0 ]

  dump flows-pilot rust/kafka
  python3 "$HERE/decode_posts.py" --kafka rust/kafka > rust.json
  python3 - rust.json rust/flowpilot.log <<'PY' || FAILED=1
import json, sys
d = json.load(open(sys.argv[1]))
stats = [l.split("FLOWPILOT_STATS ", 1)[1] for l in open(sys.argv[2]) if "FLOWPILOT_STATS " in l]
uploaded = json.loads(stats[-1])["uploads"]["records_uploaded"] if stats else -1
good = uploaded >= 1 and len(d["records"]) == uploaded
print(f"{'PASS' if good else 'FAIL'}: records in the topic ({len(d['records'])} in {d['posts']} messages) == records_uploaded ({uploaded})")
want = {"org_ids": [1], "installation_ids": ["inst-e2e"], "pce_hosts": ["pce.e2e.test:8443"]}
hdr = all(d[k] == v for k, v in want.items())
print(f"{'PASS' if hdr else 'FAIL'}: header fields {[d[k] for k in want]}")
sys.exit(0 if good and hdr else 1)
PY
  check "message keys match 1+<time>Z" keys_ok rust/kafka
  check "the gateway was asked for pce.e2e.test org 1 with Basic auth" gateway_asked gw-pilot
  check "log has Response Code 404" grep -qF "Response Code 404" rust/flowpilot.log
  check "log has KafkaProducer setup" grep -qF "KafkaProducer setup" rust/flowpilot.log
  check "log has Sending file: ... kafkaSync: true" grep -qE ' Sending file: .* kafkaSync: true$' rust/flowpilot.log
  check "log has no connection string" no_secret rust
  check "/metrics has the kafka upload transport" grep -qxF 'flowpilot_upload_transport_info{transport="kafka"} 1' metrics.txt
  check "/metrics has no connection string" no_secret metrics.txt
}

case $MODE in
  out) scenario_out "$@" ;;
  pilot) scenario_pilot ;;
  *) echo "usage: kafka_out.sh out|pilot ..."; exit 2 ;;
esac
[ "$FAILED" = 0 ] && echo "ALL CHECKS PASSED" || { echo "SOME CHECKS FAILED"; exit 1; }
