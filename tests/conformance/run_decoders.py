#!/usr/bin/env python3
"""Runs both decoders over every case in <work>/cases.json.

FlowPilot: one `pcap_decode` process per case (a panic or crash only affects that case), records in
<work>/fp/<case>.jsonl and decoder log lines in <work>/fp/<case>.log.
tshark: one container for all cases, PDML in <work>/tshark/<case>.pdml. UDP ports that carry flow
export (as seen by pcap_decode) get `-d udp.port==N,cflow|sflow`, so non-standard ports decode too.

usage: run_decoders.py [--fp-only] WORK_DIR PCAP_DECODE_BIN TSHARK_IMAGE

--fp-only reruns FlowPilot and keeps the existing tshark output (e.g. after a parser change).
"""
import json
import os
import subprocess
import sys

def safe(case):
    return case.replace("/", "__")

def main():
    args = sys.argv[1:]
    fp_only = "--fp-only" in args
    args = [a for a in args if a != "--fp-only"]
    work, binary, image = args[0], args[1], args[2]
    docker = os.environ.get("DOCKER", "docker")
    cases = json.load(open(os.path.join(work, "cases.json")))
    os.makedirs(os.path.join(work, "fp"), exist_ok=True)
    os.makedirs(os.path.join(work, "tshark"), exist_ok=True)
    script = ["set -u"]
    for c in cases:
        name = safe(c["case"])
        out = os.path.join(work, "fp", name + ".jsonl")
        with open(os.path.join(work, "fp", name + ".log"), "w") as log:
            p = subprocess.run([binary, "--out", out, "--device-prefix", c["case"], c["pcap"]],
                               stdout=log, stderr=subprocess.STDOUT)
        c["fp_exit"] = p.returncode
        summary = {}
        if os.path.exists(out):
            for line in open(out):
                rec = json.loads(line)
                if rec.get("type") == "summary":
                    summary = rec
        c["fp_summary"] = summary
        rules = []
        for port, parser in sorted(summary.get("ports", {}).items(), key=lambda kv: int(kv[0])):
            rules += ["-d", f"udp.port=={port},{'sflow' if parser == 'sflow' else 'cflow'}"]
        rel = os.path.relpath(os.path.realpath(c["pcap"]), os.path.realpath(work))
        args = " ".join(["tshark", "-n", "-r", f"'/data/{rel}'", "-T", "pdml"] + rules)
        script.append(f"{args} > '/data/tshark/{name}.pdml' 2> '/data/tshark/{name}.err' || echo 'tshark failed: {name}'")
        print(f"fp {c['case']}: exit {p.returncode}, {summary.get('records', '?')} records", flush=True)
    with open(os.path.join(work, "cases.json"), "w") as f:
        json.dump(cases, f, indent=1)
    if fp_only:
        return
    with open(os.path.join(work, "tshark", "run.sh"), "w") as f:
        f.write("\n".join(script) + "\n")
    version = subprocess.run([docker, "run", "--rm", image, "-v"], capture_output=True, text=True).stdout
    c0 = version.splitlines()[0] if version else "unknown"
    subprocess.run([docker, "run", "--rm", "-v", f"{os.path.realpath(work)}:/data", "--entrypoint", "sh", image,
                    "/data/tshark/run.sh"], check=True)
    with open(os.path.join(work, "tshark", "version.txt"), "w") as f:
        f.write(c0 + "\n")
    print(f"tshark: {c0}")

if __name__ == "__main__":
    main()
