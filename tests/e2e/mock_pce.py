"""Fake PCE for the e2e runs. Accepts FlowPilot flow uploads over HTTPS and stores each body (gzip, as sent), and
speaks the PCE REST API used for unmanaged workloads (docs/unmanaged-workloads.md) from an in-memory store.

Usage: mock_pce.py PORT OUT_DIR CERT KEY [STATUS ...] [--seed seed.json] [--hidden-seed hidden.json] [--dump state.json] [--api-status CODE]

STATUS: flow-upload reply codes in order (default 204 forever, last one repeats).
--seed: JSON {"label_dimensions": ["role", ...], "labels": [{"key","value"}], "workloads": [{"name","hostname",
        "interfaces": [{"name","address"}]}]}. Default dimensions are role, app, env, loc.
--hidden-seed: same shape as --seed (workloads only). Those workloads are not in the async export but
        `GET /workloads?ip_address=` returns them: a workload created after the startup export.
--dump: the store is written here after every request, as {label_dimensions, labels, workloads, ip_queries,
        uploads, requests, rejected}. ip_queries lists every `GET /workloads?ip_address=` value, uploads the status
        of every flow upload, rejected the malformed requests the mock refused with 400.
--api-status: answer every REST call (not flow uploads) with this status, e.g. 403.
"""
import http.server
import json
import os
import re
import ssl
import sys
import threading
import urllib.parse
import uuid

args = sys.argv[1:]
port, out, cert, key = int(args[0]), args[1], args[2], args[3]
statuses, opts, rest = [], {}, args[4:]
while rest:
    if rest[0] in ("--seed", "--hidden-seed", "--dump", "--api-status"):
        opts[rest[0]] = rest[1]
        rest = rest[2:]
    else:
        statuses.append(int(rest[0]))
        rest = rest[1:]
statuses = statuses or [204]
api_status = int(opts["--api-status"]) if "--api-status" in opts else None
os.makedirs(out, exist_ok=True)
lock = threading.Lock()
count = 0

ORG = 1
seed = json.load(open(opts["--seed"])) if "--seed" in opts else {}
store = {
    "label_dimensions": seed.get("label_dimensions", ["role", "app", "env", "loc"]),
    "labels": [],
    "workloads": [],
    "ip_queries": [],
    "uploads": [],
    "requests": [],
    "rejected": [],
}
jobs = {}      # job id -> datafile id
datafiles = {}  # datafile id -> list of objects
next_label = [24000000000000000]


def new_label(k, v):
    next_label[0] += 1
    lab = {"href": f"/orgs/{ORG}/labels/{next_label[0]}", "key": k, "value": v, "caps": ["read", "write"]}
    store["labels"].append(lab)
    return lab


def new_workload(item):
    return {
        "href": f"/orgs/{ORG}/workloads/{uuid.uuid4()}",
        "deleted": False,
        "managed": False,
        "name": item.get("name"),
        "hostname": item.get("hostname"),
        "interfaces": [
            {"name": i.get("name"), "cidr_block": None, "address": i["address"]} for i in item.get("interfaces", [])
        ],
        "labels": item.get("labels", []),
        "external_data_set": item.get("external_data_set"),
        "external_data_reference": item.get("external_data_reference"),
        "caps": ["write"],
    }


for l in seed.get("labels", []):
    new_label(l["key"], l["value"])
for w in seed.get("workloads", []):
    store["workloads"].append(new_workload(w))
hidden = set()  # hrefs of workloads the async export leaves out
if "--hidden-seed" in opts:
    for w in json.load(open(opts["--hidden-seed"])).get("workloads", []):
        store["workloads"].append(new_workload(w))
        hidden.add(store["workloads"][-1]["href"])


def dump():
    if "--dump" in opts:
        tmp = opts["--dump"] + ".tmp"
        with open(tmp, "w") as f:
            json.dump(store, f, indent=1)
        os.replace(tmp, opts["--dump"])


dump()
REST = re.compile(rf"^/api/v2/orgs/{ORG}/(label_dimensions|labels|workloads(?:/bulk_create)?|jobs/[^/]+|datafiles/[^/]+)$")


def match_ip(query, address):
    """A full address is an exact match; a partial one matches by whole leading octets (PCE 26.30.4)."""
    q, a = query.split("."), address.split(".")
    return len(q) <= 4 and a[: len(q)] == q


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def send(self, status, body=None, headers=None):
        raw = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if raw:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def bad(self, what):
        store["rejected"].append(f"{self.command} {self.path}: {what}")
        self.send(400, [{"token": "invalid_request", "message": what}])

    def rest(self, body):
        url = urllib.parse.urlsplit(self.path)
        m = REST.match(url.path)
        if not m:
            return self.send(404, [{"token": "not_found", "message": url.path}])
        q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        what = m.group(1)
        with lock:
            store["requests"].append(f"{self.command} {url.path}" + (f"?{url.query}" if url.query else ""))
            if api_status is not None:
                self.send(api_status, [{"token": "unauthorized", "message": "mock: API access refused"}])
            elif self.command == "GET":
                self.get(what, q)
            elif self.command == "POST" and what == "labels":
                self.post_label(body)
            elif self.command == "PUT" and what == "workloads/bulk_create":
                self.bulk_create(body)
            else:
                self.send(405, [{"token": "method_not_allowed", "message": self.command}])
            dump()

    def get(self, what, q):
        if what.startswith("jobs/"):
            jid = what.split("/")[1]
            if jid not in jobs:
                return self.send(404, [{"token": "not_found", "message": "job"}])
            return self.send(200, {
                "href": f"/orgs/{ORG}/jobs/{jid}", "job_type": ":illumio/async_requests", "status": "done",
                "result": {"href": f"/orgs/{ORG}/datafiles/{jobs[jid]}"},
            })
        if what.startswith("datafiles/"):
            fid = what.split("/")[1]
            if fid not in datafiles:
                return self.send(404, [{"token": "not_found", "message": "datafile"}])
            return self.send(200, datafiles[fid])
        if what == "label_dimensions":
            items = [{"href": f"/orgs/{ORG}/label_dimensions/{i}", "key": k, "deleted": False}
                     for i, k in enumerate(store["label_dimensions"])]
            return self.send(200, items, {"X-Total-Count": str(len(items)), "X-Matched-Count": str(len(items))})
        if what == "labels":
            items = [l for l in store["labels"]
                     if ("key" not in q or l["key"] == q["key"])
                     and ("value" not in q or q["value"].lower() in l["value"].lower())]
            total = len(store["labels"])
        elif what == "workloads":
            if "ip_address" in q:
                store["ip_queries"].append(q["ip_address"])
            items = [w for w in store["workloads"]
                     if ("ip_address" not in q or any(match_ip(q["ip_address"], i["address"]) for i in w["interfaces"]))
                     and ("external_data_set" not in q or w["external_data_set"] == q["external_data_set"])]
            total = len(store["workloads"])
        else:
            return self.send(405, [{"token": "method_not_allowed", "message": "GET"}])
        if self.headers.get("Prefer") == "respond-async":
            jid, fid = str(uuid.uuid4()), str(uuid.uuid4())
            jobs[jid], datafiles[fid] = fid, [i for i in items if i["href"] not in hidden]
            return self.send(202, None, {"Location": f"/orgs/{ORG}/jobs/{jid}", "Retry-After": "1"})
        self.send(200, items, {"X-Total-Count": str(total), "X-Matched-Count": str(len(items))})

    def post_label(self, body):
        try:
            k, v = body["key"], body["value"]
        except (TypeError, KeyError):
            return self.bad("label needs key and value")
        # The token below is an assumption: pce_api.md does not record the PCE's answer for an unknown label type.
        if k not in store["label_dimensions"]:
            return self.send(406, [{"token": "label_dimension_not_found", "message": f"unknown label type {k}"}])
        if any(l["key"] == k and l["value"] == v for l in store["labels"]):
            return self.send(406, [{"token": "label_key_and_value_must_be_unique",
                                    "message": "Label key and value must be unique"}])
        self.send(201, new_label(k, v))

    def bulk_create(self, body):
        if not isinstance(body, list) or not 0 < len(body) <= 1000:
            return self.bad("bulk_create takes a JSON array of 1 to 1000 workloads")
        by_href = {l["href"]: l for l in store["labels"]}
        results = []
        for item in body:
            ok = (isinstance(item, dict) and item.get("name") and item.get("interfaces")
                  and all(i.get("address") for i in item["interfaces"])
                  and all(set(l) == {"href"} and l["href"] in by_href for l in item.get("labels", [])))
            if not ok:
                return self.bad(f"malformed workload {json.dumps(item)[:200]}")
            res = {"external_data_set": item.get("external_data_set"),
                   "external_data_reference": item.get("external_data_reference")}
            dup = item.get("external_data_set") and any(
                w["external_data_set"] == item["external_data_set"]
                and w["external_data_reference"] == item.get("external_data_reference") for w in store["workloads"])
            if dup:
                results.append({**res, "status": "validation_failure", "message": "external_reference_not_unique"})
                continue
            w = new_workload(item)
            w["labels"] = [{"href": l["href"], "key": by_href[l["href"]]["key"], "value": by_href[l["href"]]["value"]}
                           for l in item.get("labels", [])]
            store["workloads"].append(w)
            results.append({**res, "status": "created", "href": w["href"]})
        self.send(200, results)

    def do_GET(self):
        self.rest(None)

    def do_PUT(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(n) or b"null")
        except ValueError:
            body = None
        self.rest(body)

    def do_POST(self):
        global count
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        if REST.match(urllib.parse.urlsplit(self.path).path):
            try:
                parsed = json.loads(body or b"null")
            except ValueError:
                parsed = None
            return self.rest(parsed)
        with lock:
            idx = count
            count += 1
        status = statuses[min(idx, len(statuses) - 1)]
        with open(os.path.join(out, f"{idx:04d}.req"), "w") as f:
            f.write(f"{self.command} {self.path}\n{self.headers}")
        with open(os.path.join(out, f"{idx:04d}.pb.gz"), "wb") as f:
            f.write(body)
        with lock:
            store["uploads"].append(status)
            dump()
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        sys.stderr.write("mock_pce:%d %s\n" % (port, fmt % args))


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
