#!/usr/bin/env bash
# Differential run inside a linux/amd64 container: original vs Rust FlowPilot on identical input.
# Usage: inside.sh ORIG_BIN RUST_BIN FLOWGEN_BIN OUT_DIR [SCENARIO_SECS]
set -euo pipefail
ORIG=$1 RUST=$2 FLOWGEN=$3 OUT=$4 SECS=${5:-10}
HERE=$(cd "$(dirname "$0")" && pwd)
rm -rf "$OUT" && mkdir -p "$OUT"
cd "$OUT"

openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 -subj /CN=localhost 2>/dev/null
printf 'api_test secret_test\n' > api_info

# impl  pce-port  netflow ipfix syslog
setup() {
  local name=$1 pce=$2 nf=$3 ipfix=$4 text=$5
  mkdir -p "$name/data"
  cat > "$name/config.yaml" <<YAML
pce_addr: localhost:$pce
api_key: $OUT/api_info
verify_pce_cert: false
data_directory: $OUT/$name/data
consumers:
  - name: netflow
    parser: {type: netflow}
    connectors: [{type: udp, properties: {ports: "$nf"}}]
  - name: ipfix
    parser: {type: ipfix}
    connectors: [{type: udp, properties: {ports: "$ipfix"}}]
  - name: syslog
    parser:
      type: text
      properties: {src_ip: sip, dst_ip: dip, dst_port: dport, protocol: prot, timestamp: "date_time, 1", timestamp_format: "mmm dd yyyy HH:MM:SS"}
    connectors: [{type: udp, properties: {ports: "$text"}}]
YAML
  python3 "$HERE/mock_pce.py" "$pce" "$OUT/$name/posts" cert.pem key.pem 2>"$name/pce.log" &
}
setup orig 8443 12055 14739 16514
setup rust 9443 22055 24739 26514
python3 "$HERE/udp_fanout.py" 2055:12055,22055 4739:14739,24739 6514:16514,26514 &
sleep 1

# Same process environment for both; stdout+stderr like illumio-flowlink-ctl.
(cd orig && CONFIG_FILE=$OUT/orig/config.yaml TZ=UTC exec "$ORIG" "" >flowlink.log 2>&1) & ORIG_PID=$!
(cd rust && CONFIG_FILE=$OUT/rust/config.yaml TZ=UTC exec "$RUST" "" >flowlink.log 2>&1) & RUST_PID=$!
sleep 3

for proto in v5 v9 ipfix; do
  "$FLOWGEN" run --preset three-tier --collector "127.0.0.1:$([ $proto = ipfix ] && echo 4739 || echo 2055)" \
    --protocol "$proto" --rate 50 --duration "${SECS}s" --seed 7 --quiet
done
python3 - <<'PY'
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ts = time.strftime("%b %d %Y %H:%M:%S", time.gmtime())
lines = [
    f"sip=10.50.0.{i} dip=10.60.0.{i % 7} dport={443 if i % 2 else 22} prot=6 date_time={ts}" for i in range(1, 40)
] + [f"sip=10.50.1.{i} dip=10.60.1.1 dport=53 prot=udp date_time={ts}" for i in range(1, 10)]
for l in lines:
    s.sendto(l.encode(), ("127.0.0.1", 6514))
PY
sleep 3

kill -QUIT $ORIG_PID $RUST_PID
for pid in $ORIG_PID $RUST_PID; do
  for _ in $(seq 60); do kill -0 $pid 2>/dev/null || break; sleep 1; done
done
# FlowLink exits 1 after a signal, FlowPilot exits 0. Collect the status without tripping set -e.
st=0; wait $ORIG_PID || st=$?; echo "orig exit: $st" > orig/exit
st=0; wait $RUST_PID || st=$?; echo "rust exit: $st" > rust/exit
echo "exit status: original=$(cat orig/exit) flowpilot=$(cat rust/exit)"
[ "$(cat rust/exit)" = "rust exit: 0" ] || { echo "FAIL: FlowPilot did not exit 0 after the signal"; exit 1; }

python3 "$HERE/decode_posts.py" orig/posts > orig.json
python3 "$HERE/decode_posts.py" rust/posts > rust.json
python3 - "$OUT" <<'PY'
import json, sys
o, r = (json.load(open(f"{sys.argv[1]}/{n}.json")) for n in ("orig", "rust"))
print(f"posts: orig={o['posts']} rust={r['posts']}  records: orig={len(o['records'])} rust={len(r['records'])}")
print(f"aggregation_seconds: orig={o['aggregation_seconds']} rust={r['aggregation_seconds']}")
same = o["records"] == r["records"]
print("RECORDS IDENTICAL" if same else "RECORDS DIFFER")
if not same:
    so = {json.dumps(x, sort_keys=True) for x in o["records"]}
    sr = {json.dumps(x, sort_keys=True) for x in r["records"]}
    for x in sorted(so - sr)[:20]: print("  only orig:", x)
    for x in sorted(sr - so)[:20]: print("  only rust:", x)
sys.exit(0 if same and o["records"] else 1)
PY
