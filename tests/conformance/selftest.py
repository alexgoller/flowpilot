#!/usr/bin/env python3
"""Sensitivity self-test for the comparison: does it notice a decoding error?

For every case with FlowPilot records, each mutation below is applied to one FlowPilot record
(the first one that matched the reference exactly), the case is compared again, and the mutation
counts as detected when that record now shows up as a NEW MISMATCH. A mutation absorbed by a
known-quirk rule or by the pairing would mean the harness can hide real decoder bugs.

usage: selftest.py WORK_DIR   (after run.sh; reads <work>/fp and <work>/tshark, writes nothing there)
"""
import collections
import functools
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import compare  # noqa: E402
import reference  # noqa: E402


def bump_ip(s):
    if ":" in s:
        return s[:-1] + ("1" if s[-1] != "1" else "2")
    a = s.split(".")
    a[-1] = str((int(a[-1]) + 1) % 256)
    return ".".join(a)


MUTATIONS = {
    "dst_ip +1": lambda r: r.update(dst_ip=bump_ip(r["dst_ip"])),
    "src_port +1": lambda r: r.update(src_port=(r["src_port"] + 1) % 65536),
    "protocol changed": lambda r: r.update(protocol=(r["protocol"] + 1) % 256 or 2),
    "octets -1": lambda r: r.update(octets=r["octets"] - 1),
    "flow_time +1s": lambda r: r.update(flow_time=r["flow_time"] + 1),
    "masks swapped": lambda r: r.update(src_mask=r["dst_mask"], dst_mask=r["src_mask"] + 1),
    "src_mac changed": lambda r: r.update(src_mac="02:00:00:00:00:01"),
    "record dropped": None,
}


def main():
    work = sys.argv[1]
    cases = json.load(open(os.path.join(work, "cases.json")))
    reference.parse_pdml = functools.lru_cache(maxsize=None)(reference.parse_pdml)
    tmp = tempfile.mkdtemp(prefix="conformance-selftest-")
    os.symlink(os.path.realpath(os.path.join(work, "tshark")), os.path.join(tmp, "tshark"))
    os.mkdir(os.path.join(tmp, "fp"))
    tally = collections.defaultdict(collections.Counter)
    misses = []
    try:
        for c in cases:
            name = compare.safe(c["case"])
            lines = [json.loads(x) for x in open(os.path.join(work, "fp", name + ".jsonl"))]
            base = compare.run_case(c, work)
            if base["matched"] == 0:
                continue
            is_sflow = "sflow" in base["per_parser"]
            # The first record that matched exactly in the baseline.
            unmatched = {json.dumps(i["fp"], sort_keys=True) for i in base["items"] if "fp" in i}
            target = next((i for i, x in enumerate(lines) if x.get("type") == "record" and
                           json.dumps(compare.norm(x), sort_keys=True) not in unmatched), None)
            if target is None:
                continue
            base_new = sum(1 for i in base["items"] if i["class"] == compare.NEW)
            for mname, fn in MUTATIONS.items():
                if is_sflow and mname == "flow_time +1s":
                    continue  # not compared for sFlow (collector clock)
                if not is_sflow and mname == "src_mac changed" and not lines[target]["src_mac"]:
                    continue
                mut = [dict(x) for x in lines]
                if fn is None:
                    del mut[target]
                else:
                    fn(mut[target])
                    if mut[target] == lines[target]:
                        continue
                with open(os.path.join(tmp, "fp", name + ".jsonl"), "w") as f:
                    f.write("".join(json.dumps(x) + "\n" for x in mut))
                res = compare.run_case(c, tmp)
                new = sum(1 for i in res["items"] if i["class"] == compare.NEW)
                ok = new > base_new
                tally[mname]["detected" if ok else "missed"] += 1
                if not ok:
                    classes = collections.Counter((i["class"], i["ref"]) for i in res["items"])
                    misses.append((c["case"], mname, dict(classes)))
    finally:
        shutil.rmtree(tmp)
    print("mutation | detected | missed")
    for m, t in tally.items():
        print(f"{m} | {t['detected']} | {t['missed']}")
    for case, m, classes in misses:
        print(f"MISSED {case}: {m}: {classes}")
    sys.exit(1 if misses else 0)


if __name__ == "__main__":
    main()
