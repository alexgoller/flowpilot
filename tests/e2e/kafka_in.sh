#!/usr/bin/env bash
# Kafka input differential inside a linux/amd64 container on the Docker network flowpilot-e2e, with the test
# broker (tests/kafka/broker.sh up network) reachable as kafka and the topics flows-plain and flows-tls
# already created. FlowLink and FlowPilot run in REST mode against their own mock PCE, each with two text
# consumers: flows-plain over PLAINTEXT (kafka:9092) and flows-tls over SSL with a client certificate
# (kafka:9094). The test CA goes into the container's trust store, so both verify the broker.
# Usage: kafka_in.sh CERTS TOOL OUT_DIR RUST_BIN ORIG_BIN
# CERTS is the broker's certificate directory; TOOL is the kafka_tool example. The client key is passed to
# the collectors as a file path; no log tail is shown before the log is known not to hold it.
set -euo pipefail
CERTS=$1 TOOL=$2 OUT=$3 RUST=$4 ORIG=$5
HERE=$(cd "$(dirname "$0")" && pwd)
KEY=$CERTS/client.key
rm -rf "$OUT" && mkdir -p "$OUT"
cd "$OUT"
umask 077
printf 'api_test secret_test\n' > api_info
# shellcheck source=tests/e2e/lib.sh
. "$HERE/lib.sh"

cp "$CERTS/ca.pem" /usr/local/share/ca-certificates/flowpilot-test-ca.crt
update-ca-certificates >/dev/null 2>&1

# Nothing under PATH holds a line of the client key's body.
no_key() { ! grep -rqF -f <(grep -v -- ----- "$KEY") "$1"; }

# The last 20 lines of a log, only once it is known not to hold the client key.
show_tail() {
  if no_key "$1"; then tail -20 "$1"; else echo "($1 withheld: it contains the client key)"; fi
}

# Stdin lines to TOPIC, one record each, over PLAINTEXT.
produce() { "$TOOL" produce --brokers kafka:9092 --topic "$1"; }

# Ten lines that are not in the inside.sh set.
later_lines() {
  python3 - <<'PY'
import time
ts = time.strftime("%b %d %Y %H:%M:%S", time.gmtime())
print("\n".join(f"sip=10.50.2.{i} dip=10.60.2.1 dport=8080 prot=6 date_time={ts}" for i in range(1, 11)))
PY
}

# NAME PCE_PORT GROUP: config.yaml with the two Kafka consumers (text properties as in inside.sh), and
# the mock PCE.
setup() {
  local name=$1 pce=$2 group=$3
  local text='{src_ip: sip, dst_ip: dip, dst_port: dport, protocol: prot, timestamp: "date_time, 1", timestamp_format: "mmm dd yyyy HH:MM:SS"}'
  mkdir -p "$name/data"
  cat > "$name/config.yaml" <<YAML
pce_addr: localhost:$pce
api_key: $OUT/api_info
verify_pce_cert: false
data_directory: $OUT/$name/data
consumers:
  - name: kafka-plain
    parser:
      type: text
      properties: $text
    connectors:
      - type: kafka
        properties: {brokers: "kafka:9092", version: "2.8.1", topics: flows-plain, group: $group}
  - name: kafka-tls
    parser:
      type: text
      properties: $text
    connectors:
      - type: kafka
        properties: {brokers: "kafka:9094", version: "2.8.1", topics: flows-tls, group: $group-tls, broker_certs: $CERTS/client.pem, broker_keys: $KEY}
YAML
  python3 "$HERE/mock_pce.py" "$pce" "$OUT/$name/posts" cert.pem key.pem 2>"$name/pce.log" &
}

# LOG: both consumers of a collector have joined their groups.
both_connected() {
  wait_for "$1" "Client: Illumio-flowlink connected to kafka brokers: kafka:9092" 120 &&
    wait_for "$1" "Client: Illumio-flowlink connected to kafka brokers: kafka:9094" 120
}

openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 -subj /CN=localhost 2>/dev/null
setup orig 8443 orig
setup rust 9443 rust

# Before the collectors start: a new group reads from the oldest offset.
LINES=$(syslog_lines)
for topic in flows-plain flows-tls; do printf '%s\n' "$LINES" | produce "$topic"; done
sleep 1

(cd orig && CONFIG_FILE=$OUT/orig/config.yaml TZ=UTC exec "$ORIG" "" >flowlink.log 2>&1) & ORIG_PID=$!
(cd rust && CONFIG_FILE=$OUT/rust/config.yaml TZ=UTC exec "$RUST" "" >flowlink.log 2>&1) & RUST_PID=$!
check "FlowPilot's consumers connected" both_connected rust/flowlink.log
check "FlowLink's consumers connected" both_connected orig/flowlink.log

LATER=$(later_lines)
for topic in flows-plain flows-tls; do printf '%s\n' "$LATER" | produce "$topic"; done
sleep 5

kill -QUIT $ORIG_PID $RUST_PID
reap $ORIG_PID; ORIG_ST=$REAPED
reap $RUST_PID; RUST_ST=$REAPED
echo "exit status: original=$ORIG_ST flowpilot=$RUST_ST"
check "FlowPilot exits 0 after the signal" [ "$RUST_ST" = 0 ]
check "FlowPilot's log has no client key" no_key rust
check "FlowLink's log has no client key" no_key orig
for impl in rust orig; do echo "--- $impl/flowlink.log (tail)"; show_tail "$impl/flowlink.log"; done
check "FlowPilot logs Client: Illumio-flowlink connected to kafka brokers: kafka:9092" \
  grep -qE '^.* Client: Illumio-flowlink connected to kafka brokers: kafka:9092$' rust/flowlink.log

python3 "$HERE/decode_posts.py" orig/posts > orig.json
python3 "$HERE/decode_posts.py" rust/posts > rust.json
python3 - "$OUT" <<'PY' || FAILED=1
import json, sys
o, r = (json.load(open(f"{sys.argv[1]}/{n}.json")) for n in ("orig", "rust"))
print(f"posts: orig={o['posts']} rust={r['posts']}  records: orig={len(o['records'])} rust={len(r['records'])}")
print(f"aggregation_seconds: orig={o['aggregation_seconds']} rust={r['aggregation_seconds']}")
# 58 distinct lines on each of the two topics: every line counted once per topic (the text parser sets no
# device_addr, so a line's flow from both topics is one record with count 2).
counts = [sum(x.get("count", 0) for x in d["records"]) for d in (o, r)]
good = counts == [116, 116]
print(f"{'PASS' if good else 'FAIL'}: flow count sum orig={counts[0]} rust={counts[1]} (want 116 each)")
same = o["records"] == r["records"]
print("RECORDS IDENTICAL" if same else "RECORDS DIFFER")
if not same:
    so = {json.dumps(x, sort_keys=True) for x in o["records"]}
    sr = {json.dumps(x, sort_keys=True) for x in r["records"]}
    for x in sorted(so - sr)[:20]: print("  only orig:", x)
    for x in sorted(sr - so)[:20]: print("  only rust:", x)
sys.exit(0 if good and same else 1)
PY
[ "$FAILED" = 0 ] && echo "ALL CHECKS PASSED" || { echo "SOME CHECKS FAILED"; exit 1; }
