#!/usr/bin/env bash
# Unmanaged-workload scenario inside a linux/amd64 container (also runs on a host with python3 and openssl).
# Two flowpilot instances see the same flowgen traffic:
#   A: normal mock PCE (seeded with one existing workload and one label), max_creates_per_window 3
#   B: mock PCE that answers every REST call with 403; flow uploads must keep working
#   C: like A but max_creates_per_window 100 (every eligible IP is selected), and one eligible IP has a workload
#      that the startup export does not list, only the per-IP pre-create check finds it
# Usage: unmanaged.sh RUST_BIN FLOWGEN_BIN OUT_DIR
# UW_WAIT_SECS (default 420) bounds the wait for the first aggregation window.
set -euo pipefail
RUST=$1 FLOWGEN=$2 OUT=$3
WAIT=${UW_WAIT_SECS:-420}
HERE=$(cd "$(dirname "$0")" && pwd)
rm -rf "$OUT" && mkdir -p "$OUT"
cd "$OUT"

openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 -subj /CN=localhost 2>/dev/null
printf 'api_test secret_test\n' > api_info

# The IPs flowgen emits for the three-tier preset (`flowgen ips`), labelled by CIDR.
RULES='[
  {cidr: 10.1.0.0/16, labels: {app: portal, env: prod, loc: dc1}},
  {cidr: 192.168.10.0/27, labels: {app: portal, env: prod, loc: office, role: client}},
  {cidr: 10.1.0.10/31, labels: {role: dns, app: infra}},
  {cidr: 10.1.1.8/29, labels: {role: web}},
  {cidr: 10.1.2.8/29, labels: {role: app}},
  {cidr: 10.1.3.8/30, labels: {role: db}}
]'

# name pce-port netflow-port creates-per-window [mock options]
setup() {
  local name=$1 pce=$2 nf=$3 cap=$4; shift 4
  mkdir -p "$name/data"
  cat > "$name/config.yaml" <<YAML
pce_addr: localhost:$pce
api_key: $OUT/api_info
verify_pce_cert: false
aggregation_minutes: 5
data_directory: $OUT/$name/data
consumers:
  - name: netflow
    parser: {type: netflow}
    connectors: [{type: udp, properties: {ports: "$nf"}}]
unmanaged_workloads:
  enabled: true
  min_flows: 1
  max_creates_per_window: $cap
  dns: {enabled: false}
  label_rules: $RULES
YAML
  python3 "$HERE/mock_pce.py" "$pce" "$OUT/$name/posts" cert.pem key.pem --dump "$OUT/$name/state.json" "$@" 2>"$name/pce.log" &
}

cat > seed.json <<'JSON'
{"labels": [{"key": "loc", "value": "dc1"}],
 "workloads": [{"name": "existing", "hostname": "existing.example.invalid", "interfaces": [{"name": "umwl", "address": "10.1.0.10"}]}]}
JSON
# Eligible for sure (busy web server); only the pre-create check can see this workload.
HIDDEN=10.1.1.9
cat > hidden.json <<JSON
{"workloads": [{"name": "late", "interfaces": [{"name": "umwl", "address": "$HIDDEN"}]}]}
JSON
setup a 8443 12055 3 --seed "$OUT/seed.json"
setup b 9443 22055 3 --api-status 403
setup c 7443 32055 100 --seed "$OUT/seed.json" --hidden-seed "$OUT/hidden.json"
python3 "$HERE/udp_fanout.py" 2055:12055,22055,32055 &
sleep 1

(cd a && CONFIG_FILE=$OUT/a/config.yaml TZ=UTC exec "$RUST" "" >flowpilot.log 2>&1) & A_PID=$!
(cd b && CONFIG_FILE=$OUT/b/config.yaml TZ=UTC exec "$RUST" "" >flowpilot.log 2>&1) & B_PID=$!
(cd c && CONFIG_FILE=$OUT/c/config.yaml TZ=UTC exec "$RUST" "" >flowpilot.log 2>&1) & C_PID=$!
sleep 3
"$FLOWGEN" run --preset three-tier --collector 127.0.0.1:2055 --protocol v5 --rate 50 --duration 20s --seed 7 --quiet

# Poll instead of sleeping: each instance logs once its first window has been handled.
a_done() { grep -q 'Unmanaged workloads: [0-9]* candidates' a/flowpilot.log 2>/dev/null; }
c_done() { grep -q 'Unmanaged workloads: [0-9]* candidates' c/flowpilot.log 2>/dev/null; }
b_done() { grep -q 'needs permission' b/flowpilot.log 2>/dev/null && python3 -c '
import json,sys; sys.exit(0 if json.load(open("b/state.json"))["uploads"] else 1)' 2>/dev/null; }
waited=0
until { a_done && b_done && c_done; } || [ $waited -ge "$WAIT" ]; do sleep 5; waited=$((waited + 5)); done
sleep 3
echo "waited ${waited}s for the first window"

# SIGQUIT is the shutdown path, which exits 0. A process that ignores it is killed and counts as a failure.
kill -QUIT $A_PID $B_PID $C_PID
for n in a b c; do
  pid=$(eval echo \$"$(echo $n | tr a-z A-Z)_PID")
  for _ in $(seq 60); do kill -0 $pid 2>/dev/null || break; sleep 1; done
  if kill -0 $pid 2>/dev/null; then
    kill -9 $pid; wait $pid 2>/dev/null || true; echo "hung" > $n/exit
  else
    st=0; wait $pid || st=$?; echo "$st" > $n/exit
  fi
done

python3 - "$OUT" <<'PY'
import glob, ipaddress, json, re, sys

out = sys.argv[1]
RULES = [  # same rules as the config above, written independently of it
    ("10.1.0.0/16", {"app": "portal", "env": "prod", "loc": "dc1"}),
    ("192.168.10.0/27", {"app": "portal", "env": "prod", "loc": "office", "role": "client"}),
    ("10.1.0.10/31", {"role": "dns", "app": "infra"}),
    ("10.1.1.8/29", {"role": "web"}),
    ("10.1.2.8/29", {"role": "app"}),
    ("10.1.3.8/30", {"role": "db"}),
]
SEEDED = "10.1.0.10"
HIDDEN = "10.1.1.9"
failed = []


def check(ok, what):
    print(("PASS " if ok else "FAIL ") + what)
    if not ok:
        failed.append(what)


def expected_labels(ip):
    """Longest prefix wins per label type; broader rules fill the gaps."""
    ip = ipaddress.ip_address(ip)
    hit = sorted((ipaddress.ip_network(c) for c, _ in RULES if ip in ipaddress.ip_network(c)),
                 key=lambda n: -n.prefixlen)
    by_net = {ipaddress.ip_network(c): l for c, l in RULES}
    labels = {}
    for n in hit:
        for k, v in by_net[n].items():
            labels.setdefault(k, v)
    return labels


def load(n):
    return json.load(open(f"{out}/{n}/state.json")), open(f"{out}/{n}/flowpilot.log").read()


# --- A: normal PCE
state, log = load("a")
created = [w for w in state["workloads"] if w.get("external_data_set")]
ips = [w["interfaces"][0]["address"] for w in created]
check(len(created) == 3, f"A: exactly 3 workloads created (got {ips})")
check(all(w["external_data_set"] == "flowpilot" and w["external_data_reference"] == w["name"] for w in created),
      "A: external_data_set is flowpilot and external_data_reference equals name")
check(all(w["name"] == w["interfaces"][0]["address"] and w["interfaces"][0]["name"] == "umw0" for w in created),
      "A: name is the IP, interface umw0")
check(all(not w.get("hostname") for w in created), "A: no hostnames (dns disabled)")
by_href = {l["href"]: (l["key"], l["value"]) for l in state["labels"]}
got_ok = all(
    dict(by_href[l["href"]] for l in w["labels"]) == expected_labels(w["interfaces"][0]["address"]) and w["labels"]
    for w in created
)
check(got_ok, "A: labels match the rules")
# B keeps no known set, so its candidate counts show which IPs the flows really contained.
seen = set()
for sl in json.load(open(glob.glob(f"{out}/b/data/*uw_candidates.json")[0]))["slices"]:
    seen |= set(sl["counts"])
check(SEEDED in seen, f"A: seeded IP {SEEDED} appeared in the flows")
check(SEEDED not in ips, f"A: seeded IP {SEEDED} skipped as already known")
check(sum(1 for w in state["workloads"] if w["interfaces"][0]["address"] == SEEDED) == 1,
      "A: still exactly one workload at the seeded IP")
check(len(set(by_href.values())) == len(by_href), "A: no duplicate labels")
check(set(ips) <= set(state["ip_queries"]),
      "A: pre-create check (GET /workloads?ip_address=) ran for every created IP")
m = re.search(r"Unmanaged workloads: (\d+) candidates, (\d+) eligible, (\d+) created, (\d+) deferred, "
              r"(\d+)/(\d+) resolved, (\d+) labels? created, (\d+) errors", log)
check(bool(m), "A: summary line present")
if m:
    c, e, cr, d, r, l, lc, x = map(int, m.groups())
    check(cr == 3 and d > 0 and x == 0, f"A: summary shows 3 created, deferred > 0, 0 errors ({m.group(0)})")
    check(lc > 0, "A: missing label values were created")
check(not state["rejected"], "A: mock saw no malformed requests")

# --- C: a workload the startup export does not list, found only by the pre-create check
state, log = load("c")
created = [w for w in state["workloads"] if w.get("external_data_set")]
ips = {w["interfaces"][0]["address"] for w in created}
check(HIDDEN in state["ip_queries"], f"C: pre-create check queried {HIDDEN}")
check(HIDDEN not in ips, f"C: no workload created for {HIDDEN}")
check(sum(1 for w in state["workloads"] if w["interfaces"][0]["address"] == HIDDEN) == 1,
      f"C: exactly one workload at {HIDDEN}")
check(len(created) > 3 and SEEDED not in ips and len(ips) == len(created),
      f"C: the other eligible IPs were created ({len(created)} workloads)")
check(HIDDEN in seen and "0 errors" in log, "C: the hidden IP was in the flows and the run had 0 errors")
check(not state["rejected"], "C: mock saw no malformed requests")

# --- B: every REST call answered 403
state, log = load("b")
check(len(state["uploads"]) > 0 and set(state["uploads"]) == {204},
      f"B: flow uploads got 204 ({len(state['uploads'])} posts)")
check("needs permission" in log, "B: log says the API key needs permission")
check(not state["workloads"], "B: no workloads")
check(not state["rejected"], "B: mock saw no malformed requests")
for n in "abc":
    check(open(f"{out}/{n}/exit").read().strip() == "0", f"{n.upper()}: exit status 0 after SIGQUIT")

print("RESULT: " + ("FAIL" if failed else "PASS"))
sys.exit(1 if failed else 0)
PY
