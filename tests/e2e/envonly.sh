#!/usr/bin/env bash
# Variables-only scenario inside a linux/amd64 container (also runs on a Linux host with python3 and openssl):
# FlowPilot starts with no CONFIG_FILE, configured only by FLOWPILOT_* variables, against mock_pce.py. Checks the
# data directory is created, the stats HTTP endpoint and log line, remote_addrs rejection, an upload, and that the
# API secret never reaches the log, /stats or /metrics.
# Usage: envonly.sh RUST_BIN FLOWGEN_BIN OUT_DIR
# ENV_WAIT_SECS (default 420) bounds the wait for the first aggregation window (5 minutes after the start).
set -euo pipefail
RUST=$1 FLOWGEN=$2 OUT=$3
WAIT=${ENV_WAIT_SECS:-420}
HERE=$(cd "$(dirname "$0")" && pwd)
SECRET=envonly-Secret-7f3a9c
STATS=http://127.0.0.1:9180
rm -rf "$OUT" && mkdir -p "$OUT"
cd "$OUT"

openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 -subj /CN=localhost 2>/dev/null
python3 "$HERE/mock_pce.py" 8443 "$OUT/posts" cert.pem key.pem --dump "$OUT/state.json" 2>pce.log &
sleep 1

[ -e "$OUT/new" ] && { echo "FAIL: $OUT/new exists before the start"; exit 1; }
# FLOWPILOT_VERIFY_PCE_CERT: the mock's certificate is self-signed.
env -u CONFIG_FILE TZ=UTC \
  FLOWPILOT_PCE_ADDR=localhost:8443 \
  FLOWPILOT_API_USER=api_envonly FLOWPILOT_API_SECRET=$SECRET \
  FLOWPILOT_VERIFY_PCE_CERT=false \
  FLOWPILOT_DATA_DIRECTORY="$OUT/new/dir" \
  FLOWPILOT_NETFLOW_PORTS=2055 FLOWPILOT_IPFIX_PORTS=4739 \
  FLOWPILOT_NETFLOW_REMOTE_ADDRS=127.0.0.1 \
  FLOWPILOT_AGGREGATION_MINUTES=5 \
  FLOWPILOT_STATS_INTERVAL_SECONDS=10 \
  FLOWPILOT_STATS_HTTP_LISTEN=127.0.0.1:9180 \
  "$RUST" "" >flowpilot.log 2>&1 & PID=$!
sleep 3

"$FLOWGEN" run --preset three-tier --collector 127.0.0.1:2055 --protocol v9 --rate 50 --duration 30s --seed 7 --quiet &
GEN1=$!
"$FLOWGEN" run --preset three-tier --collector 127.0.0.1:4739 --protocol ipfix --rate 50 --duration 30s --seed 7 --quiet &
GEN2=$!
# One NetFlow v5 datagram (one record) from a sender outside FLOWPILOT_NETFLOW_REMOTE_ADDRS.
python3 - <<'PY'
import socket, struct, time
now = int(time.time())
hdr = struct.pack(">HHIIIIBBH", 5, 1, 100_000, now, 0, 1, 0, 0, 0)
rec = socket.inet_aton("10.9.0.1") + socket.inet_aton("10.9.0.2") + bytes(4) + struct.pack(
    ">HHIIIIHHBBBBHHBBH", 0, 0, 1, 500, 90_000, 99_000, 40000, 443, 0, 0, 6, 0, 0, 0, 24, 24, 0)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.2", 0))
s.sendto(hdr + rec, ("127.0.0.1", 2055))
PY
wait $GEN1 $GEN2
sleep 3

# While the flows are fresh: /healthz, /stats and /metrics (kept as artifacts).
python3 - "$STATS" <<'PY'
import sys, urllib.request
base = sys.argv[1]
for path, name in (("/healthz", "healthz"), ("/stats", "stats_after_traffic.json"), ("/metrics", "metrics.txt")):
    try:
        r = urllib.request.urlopen(base + path, timeout=5)
        code, body = r.status, r.read()
    except urllib.error.HTTPError as e:
        code, body = e.code, e.read()
    open(name + ".code", "w").write(str(code))
    open(name, "wb").write(body)
PY

# Poll /stats until the first window has been uploaded, then let one more FLOWPILOT_STATS line go out.
uploaded() { python3 -c '
import json, sys, urllib.request
s = json.load(urllib.request.urlopen(sys.argv[1] + "/stats", timeout=5))
sys.exit(0 if s["uploads"]["succeeded"] >= 1 else 1)' "$STATS" 2>/dev/null; }
waited=0
until uploaded || [ $waited -ge "$WAIT" ]; do sleep 5; waited=$((waited + 5)); done
echo "waited ${waited}s for the first upload"
sleep 12

# SIGQUIT is the shutdown path, which exits 0.
kill -QUIT $PID
for _ in $(seq 60); do kill -0 $PID 2>/dev/null || break; sleep 1; done
if kill -0 $PID 2>/dev/null; then
  kill -9 $PID; wait $PID 2>/dev/null || true; echo hung > exit
else
  st=0; wait $PID || st=$?; echo "$st" > exit
fi

python3 - "$OUT" "$SECRET" <<'PY'
import json, os, sys

out, secret = sys.argv[1], sys.argv[2]
failed = []


def check(ok, what):
    print(("PASS " if ok else "FAIL ") + what)
    if not ok:
        failed.append(what)


log = open(f"{out}/flowpilot.log", errors="replace").read()
check(os.path.isdir(f"{out}/new/dir"), "data directory new/dir was created")
check(open(f"{out}/healthz.code").read() == "200", "/healthz answered 200")
try:
    s = json.load(open(f"{out}/stats_after_traffic.json"))
except ValueError:
    s = {}
check(open(f"{out}/stats_after_traffic.json.code").read() == "200" and bool(s), "/stats answered 200 with JSON")
check(s.get("status") == "ok", f"/stats status is ok (got {s.get('status')})")
cols = {c["name"]: c for c in s.get("collectors", [])}
for name in ("netflow", "ipfix"):
    c = cols.get(name, {})
    check(c.get("flows_decoded", 0) > 0, f"collector {name}: flows_decoded > 0 (got {c.get('flows_decoded')})")
    check(any(e["address"] == "127.0.0.1" for e in c.get("exporters", [])), f"collector {name}: exporter 127.0.0.1")
nf = cols.get("netflow", {})
check(nf.get("rejected_datagrams", 0) >= 1, f"netflow: rejected_datagrams >= 1 (got {nf.get('rejected_datagrams')})")
check(not any(e["address"] == "127.0.0.2" for e in nf.get("exporters", [])), "netflow: no exporter row for 127.0.0.2")

lines = []
for l in log.splitlines():
    if " FLOWPILOT_STATS " in l:
        try:
            lines.append(json.loads(l.split(" FLOWPILOT_STATS ", 1)[1]))
        except ValueError:
            pass
check(len(lines) >= 1, f"FLOWPILOT_STATS lines parse as JSON ({len(lines)} parsed)")
state = json.load(open(f"{out}/state.json"))
check(204 in state["uploads"], f"mock PCE received an upload (statuses {state['uploads']})")
last = lines[-1] if lines else {}
got = last.get("uploads", {}).get("succeeded", 0)
check(got >= 1, f"last FLOWPILOT_STATS line: uploads.succeeded >= 1 (got {got})")
bad = [i + 1 for i, l in enumerate(log.splitlines()) if secret in l]
check(not bad, f"no log line contains the API secret (lines {bad})")
metrics = open(f"{out}/metrics.txt", errors="replace").read()
check(open(f"{out}/metrics.txt.code").read() == "200" and "flowpilot_" in metrics, "/metrics answered 200")
for name in ("stats_after_traffic.json", "metrics.txt"):
    check(secret not in open(f"{out}/{name}", errors="replace").read(), f"{name} does not contain the API secret")
check(open(f"{out}/exit").read().strip() == "0", "exit status 0 after SIGQUIT")

print("RESULT: " + ("FAIL" if failed else "PASS"))
sys.exit(1 if failed else 0)
PY
