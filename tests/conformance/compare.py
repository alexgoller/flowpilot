#!/usr/bin/env python3
"""Compares FlowPilot's records with the tshark reference and writes the conformance report.

usage: compare.py WORK_DIR [REPORT_PATH]

Inputs per case (see run_decoders.py): <work>/fp/<case>.jsonl and <work>/tshark/<case>.pdml.
Outputs: <work>/report.md (or REPORT_PATH) and <work>/results.json.

Matching. Records are compared per datagram (pcap frame). The reference records go through the
same flow filter and direction normalisation as FlowPilot's (src/flow.rs
check_flow), so both sides describe the records FlowPilot would hand to the aggregator. Within a
frame, records are paired first on all compared fields, then on the 5-tuple, then in order; what
remains is FlowPilot-only or reference-only.

Classification. Every difference is run through the rules in `classify_*`: a rule names the
documented FlowLink behaviour (docs/differences-from-flowlink.md, docs/compatibility.md) that
explains it. A
difference no rule explains is a NEW MISMATCH.
"""
import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import reference  # noqa: E402

FIELDS = ["src_ip", "dst_ip", "src_port", "dst_port", "ip_version", "protocol", "icmp_type", "icmp_code",
          "src_mac", "dst_mac", "src_mask", "dst_mask", "flow_time", "flows", "octets", "direction_ind", "seq_id"]
# sFlow: flow_time is the collector's clock and seq_id the harness datagram number in FlowPilot.
SFLOW_SKIP = {"flow_time", "seq_id"}
KEY = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]

STALE_TEMPLATE_WHY = ("templates are keyed on the exporter IP without the UDP port, so a data set from a new transport "
           "session (e.g. exporter restart) is decoded with the old session's template; tshark scopes templates "
           "to the session (RFC 7011 section 8) and does not decode it")
MATCH, KNOWN, NEW, BYDESIGN, INVALID = "MATCH", "KNOWN QUIRK", "NEW MISMATCH", "UNSUPPORTED-BY-DESIGN", "REFERENCE INCOMPLETE"


def safe(case):
    return case.replace("/", "__")


def norm(rec):
    r = dict(rec)
    r["src_ip"] = reference.norm_ip(r["src_ip"])
    r["dst_ip"] = reference.norm_ip(r["dst_ip"])
    r["seq_id"] = str(r.get("seq_id", ""))
    return r


def diff(a, b, skip):
    return [f for f in FIELDS if f not in skip and a.get(f) != b.get(f)]


# ---------------------------------------------------------------------------------------------
# Classification rules. Each returns (class, reference, explanation) or None.

def classify_cflow(ctx, fields_):
    """For a paired record with differing fields, or a reference-only record (fields_ is None)."""
    tf = ctx.get("tflags") or {}
    s, ts = ctx.get("set") or {}, ctx.get("template_set") or {}
    v = ctx.get("version")
    if ctx.get("malformed"):
        return INVALID, "tshark exception", "tshark stopped dissecting this datagram (malformed input or a tshark limitation); the reference is partial"
    if ctx.get("stale_template"):
        return KNOWN, "template keyed without exporter port", STALE_TEMPLATE_WHY
    if fields_ is None:
        if s.get("beyond_count") or ts.get("beyond_count"):
            return KNOWN, "v9 header record count", "v9 FlowSet beyond the header record count is never read" + \
                (" (its template set was skipped)" if ts.get("beyond_count") and not s.get("beyond_count") else "")
        if ts.get("template_padding"):
            return KNOWN, "template set padding", "template set padding is read as another template"
        if tf.get("ie1_bad_len") or tf.get("ie3_bad_len"):
            return KNOWN, "reduced-size IE 1 or IE 3", \
                "IE 1 or IE 3 with a reduced-size length: FlowPilot abandons the data set (the original crashed)"
        if tf.get("fixed_width_mismatch"):
            return KNOWN, "fixed-width field read", "fixed-width read of " + str(tf["fixed_width_mismatch"]) + " desynchronises the record"
        if ctx.get("prior_set_hazard"):
            return KNOWN, ctx["prior_set_hazard"][0], "an earlier set in the same message desynchronised the reader: " + ctx["prior_set_hazard"][1]
        return None
    f = set(fields_)
    if tf.get("fixed_width_mismatch"):
        return KNOWN, "fixed-width field read", "fixed-width read of " + str(tf["fixed_width_mismatch"]) + " desynchronises the record"
    rest = set(f)
    expl = []
    if "octets" in rest and not ctx.get("ie1") and ctx.get("octets_from") not in (None, 85, 231):
        rest.discard("octets")
        expl.append(f"bytes only in IE {ctx['octets_from']} ({reference.ALT_OCTETS[ctx['octets_from']]}); FlowPilot reads IE 1, 231 and 85 only")
    if "flows" in rest and tf.get("ie3_len8"):
        rest.discard("flows")
        expl.append("IE 3 with length 8: FlowLink takes the high 32 bits")
    if "flow_time" in rest and 158 in ctx.get("start_ies", []):
        rest.discard("flow_time")
        expl.append("IE 158 subtracts microseconds/1000 from seconds")
    if not rest:
        ref = []
        if any("IE 1, 231 and 85 only" in e for e in expl):
            ref.append("byte counter fields")
        if any("IE 3" in e for e in expl):
            ref.append("IE 3 with length 8")
        if any("IE 158" in e for e in expl):
            ref.append("IE 158 flow time")
        return KNOWN, "; ".join(ref), "; ".join(expl)
    if ctx.get("prior_set_hazard"):
        return KNOWN, ctx["prior_set_hazard"][0], "an earlier set in the same message desynchronised the reader: " + ctx["prior_set_hazard"][1]
    return None


def classify_sflow(ctx, fields_):
    notes = ctx.get("notes", [])
    if ctx.get("malformed"):
        return INVALID, "tshark exception", "tshark stopped dissecting this datagram (malformed input or a tshark limitation); the reference is partial"
    if fields_ is None:
        for n in notes:
            if n.startswith("bare IPv6") or n.startswith("IPv6 data") or n.startswith("QinQ") or n.startswith("802.3"):
                return KNOWN, "sFlow: header type without flows", n + " produces no flow"
        if ctx.get("after_ip") == 0 or (ctx.get("l4") is None and ctx.get("protocol") == 59):
            return KNOWN, "sFlow: nothing after the IP header", "nothing after the IP header: no flow"
        if any(n.startswith("IPv6 extension") for n in notes):
            return KNOWN, "sFlow: IPv6 extension header length", "IPv6 extension header length bug"
        if ctx.get("abort_before"):
            return KNOWN, "sFlow: failed record aborts the datagram", "an earlier record aborted the datagram: " + ctx["abort_before"]
        return None
    f = set(fields_)
    if any(n.startswith("IPv6 extension") for n in notes):
        return KNOWN, "sFlow: IPv6 extension header length", "IPv6 extension header length bug: wrong protocol/ports"
    if any(n.startswith("non-first IPv4 fragment") for n in notes) and f <= {"src_port", "dst_port", "icmp_type", "icmp_code", "protocol"}:
        return KNOWN, "sFlow: IPv4 fragment offset ignored", "IPv4 fragment offset ignored: ports read from fragment payload"
    if f <= {"src_port"} and ctx.get("state_src_port"):
        return KNOWN, "sFlow: fields carried over within a sample", "src_port inherited from an earlier format-3 record of the same sample"
    if f <= {"src_mac", "dst_mac"} and ctx.get("state_macs"):
        return KNOWN, "sFlow: fields carried over within a sample", "MACs inherited from an earlier record of the same sample"
    return None


def sflow_abort_reason(ctx):
    """Would FlowPilot's sFlow header decoders give up on this record (a failed record aborts the datagram)?"""
    if ctx.get("format") != 1 or ctx.get("kind") != "data":
        return None
    l4, after = ctx.get("l4"), ctx.get("after_ip")
    proto = ctx.get("protocol")
    if after is None or after <= 0:
        return None
    if l4 == "tcp" and after < 18:
        return "TCP header with fewer than 18 bytes"
    if l4 in ("icmp", "icmpv6") and after < 8:
        return "ICMP header with fewer than 8 bytes"
    if proto in (0, 43, 44) and ctx.get("ip_version") == 4:
        return "IPv4 with protocol 0/43/44"
    return None


# ---------------------------------------------------------------------------------------------

def load_fp(path):
    recs, panics, summary = collections.defaultdict(list), [], {}
    if not os.path.exists(path):
        return recs, panics, summary
    for line in open(path):
        r = json.loads(line)
        if r.get("type") == "record":
            recs[r["frame"]].append(norm(r))
        elif r.get("type") == "panic":
            panics.append(r)
        elif r.get("type") == "summary":
            summary = r
    return recs, panics, summary


def pair(fp, ref, skip):
    """Returns (pairs [(fp, (ref, ctx), diff)], fp_only, ref_only)."""
    fp, ref = list(fp), list(ref)
    pairs = []
    for key in (lambda r: tuple(r.get(f) for f in FIELDS if f not in skip), lambda r: tuple(r.get(f) for f in KEY)):
        rest = []
        for rr in ref:
            k = key(rr[0])
            j = next((i for i, x in enumerate(fp) if key(x) == k), None)
            if j is None:
                rest.append(rr)
            else:
                x = fp.pop(j)
                pairs.append((x, rr, diff(x, rr[0], skip)))
        ref = rest
    n = min(len(fp), len(ref))
    for i in range(n):
        pairs.append((fp[i], ref[i], diff(fp[i], ref[i][0], skip)))
    return pairs, fp[n:], ref[n:]


def run_case(case, work):
    name = safe(case["case"])
    fp, panics, summary = load_fp(os.path.join(work, "fp", name + ".jsonl"))
    frames, facts = reference.parse_pdml(os.path.join(work, "tshark", name + ".pdml"))
    res = {"case": case["case"], "vendor": case["vendor"], "source": case["source"], "inputs": case["inputs"],
           "pcap": case["pcap"], "fp_exit": case.get("fp_exit"), "panics": panics, "facts": facts,
           "datagrams": summary.get("datagrams", 0), "fp_records": summary.get("records", 0),
           "per_parser": summary.get("per_parser", {}), "ref_records": 0, "ref_dropped": collections.Counter(),
           "fp_meter": summary.get("meter", 0), "ref_prefilter": facts["data_records"],
           "matched": 0, "items": []}
    is_sflow = "sflow" in summary.get("per_parser", {})
    predicted_missing = collections.Counter()
    for frame in sorted(set(frames) | set(fp)):
        refs = []
        hazard = None
        abort = None
        for rec, ctx in frames.get(frame, []):
            if rec is None:
                continue
            if "set" in ctx:
                tf = ctx.get("tflags") or {}
                ctx["prior_set_hazard"] = hazard
                si = ctx["set"]["set_index"]
                if tf.get("fixed_width_mismatch"):
                    hazard = hazard or ("fixed-width field read", f"fixed-width mismatch in set {si}")
                elif ctx["template_set"].get("template_padding"):
                    hazard = hazard or ("template set padding", "padded template set")
            if ctx.get("format") is not None:
                ctx["abort_before"] = abort
                ctx["protocol"] = rec.get("protocol")
                ctx["ip_version"] = rec.get("ip_version")
                abort = abort or sflow_abort_reason(ctx)
            ok, why = reference.check_flow(dict(rec))
            if ok is None:
                res["ref_dropped"][why] += 1
                # Records both sides drop are not compared field by field; FlowPilot's meter still
                # counts them, so predict whether FlowPilot decodes them at all.
                c = (classify_sflow if ctx.get("format") is not None else classify_cflow)(ctx, None)
                if c and c[0] == KNOWN:
                    predicted_missing[c[1]] += 1
                continue
            refs.append((norm(ok), ctx))
        res["ref_records"] += len(refs)
        skip = SFLOW_SKIP if is_sflow else set()
        pairs, fp_only, ref_only = pair(fp.get(frame, []), refs, skip)
        classify = classify_sflow if is_sflow else classify_cflow
        for x, (r, ctx), d in pairs:
            if ctx.get("stale_template"):
                # Decoded with a template from another transport session of the same exporter IP.
                res["items"].append({"kind": "decoded with another session's template", "frame": frame,
                                     "class": KNOWN, "ref": "template keyed without exporter port", "why": STALE_TEMPLATE_WHY + (
                                         "" if not d else f"; differs in {', '.join(d)}"),
                                     "fp": x, "reference": r, "ctx": summarize_ctx(ctx)})
                continue
            if not d:
                res["matched"] += 1
                continue
            c = classify(ctx, d) or (NEW, "", "")
            res["items"].append({"kind": "mismatch", "frame": frame, "class": c[0], "ref": c[1], "why": c[2],
                                 "fields": {f: [x.get(f), r.get(f)] for f in d}, "fp": x, "reference": r,
                                 "ctx": summarize_ctx(ctx)})
        for r, ctx in ref_only:
            c = classify(ctx, None) or (NEW, "", "")
            res["items"].append({"kind": "missing in FlowPilot", "frame": frame, "class": c[0], "ref": c[1],
                                 "why": c[2], "reference": r, "ctx": summarize_ctx(ctx)})
        for x in fp_only:
            c = classify_extra(frames.get(frame, []), frame in facts["malformed_list"])
            res["items"].append({"kind": "extra in FlowPilot", "frame": frame, "class": c[0], "ref": c[1],
                                 "why": c[2], "fp": x})
    res["ref_dropped"] = dict(res["ref_dropped"])
    if not is_sflow:
        # FlowPilot's meter = records it decoded (before the filter). Expected: every reference record
        # minus those a known quirk keeps FlowPilot from decoding, plus FlowPilot-only records.
        missing = sum(1 for i in res["items"] if i["kind"] == "missing in FlowPilot") \
            + sum(predicted_missing.values())
        extra = sum(1 for i in res["items"] if i["kind"] == "extra in FlowPilot")
        expected = res["ref_prefilter"] - missing + extra
        res["prefilter_explained"] = dict(predicted_missing)
        if expected != res["fp_meter"]:
            res["items"].append({"kind": "decoded-record count (incl. records both sides drop)", "frame": 0,
                                 "class": NEW, "ref": "", "why": "",
                                 "fields": {"records decoded": [res["fp_meter"], expected]}})
    return res


def classify_extra(frame_refs, malformed):
    """A FlowPilot record with no reference counterpart in its frame."""
    if malformed:
        return INVALID, "tshark exception", "tshark stopped dissecting this datagram (malformed input or a tshark limitation); the reference is partial"
    for _rec, ctx in frame_refs:
        if ctx.get("stale_template"):
            return KNOWN, "template keyed without exporter port", STALE_TEMPLATE_WHY
    for _rec, ctx in frame_refs:
        tf = ctx.get("tflags") or {}
        if tf.get("fixed_width_mismatch"):
            return KNOWN, "fixed-width field read", "fixed-width read desynchronises the record"
        if (ctx.get("template_set") or {}).get("template_padding"):
            return KNOWN, "template set padding", "padded template set"
        if any(n.startswith("IPv6 extension") for n in ctx.get("notes", [])):
            return KNOWN, "sFlow: IPv6 extension header length", "IPv6 extension header length bug"
    return NEW, "", ""


def summarize_ctx(ctx):
    out = {}
    for k in ("version", "tid", "template_frame", "record_index", "start_ies", "end_ies", "octets_from",
              "notes", "format", "header_protocol", "after_ip", "l4", "sample_index", "sampling_rate"):
        if ctx.get(k) not in (None, [], {}):
            out[k] = ctx[k]
    tf = ctx.get("tflags")
    if tf:
        out["template"] = {k: (sorted(v) if isinstance(v, set) else v) for k, v in tf.items() if v and k != "ies"}
    for k in ("set", "template_set"):
        if ctx.get(k):
            out[k] = {a: b for a, b in ctx[k].items() if b}
    return out


# ---------------------------------------------------------------------------------------------
# Report

def case_class(res):
    classes = {i["class"] for i in res["items"]}
    if res["panics"]:
        return "PANIC"
    for c in (NEW, INVALID, KNOWN):
        if c in classes:
            return c
    if res["fp_records"] == 0 and res["ref_records"] == 0:
        return "NO FLOWS"
    return MATCH


def fmt_rec(r):
    return (f"{r.get('src_ip')}:{r.get('src_port')} -> {r.get('dst_ip')}:{r.get('dst_port')} proto {r.get('protocol')} "
            f"v{r.get('ip_version')} octets {r.get('octets')} flows {r.get('flows')} t {r.get('flow_time')} dir {r.get('direction_ind')}")


def write_report(results, work, path):
    version = open(os.path.join(work, "tshark", "version.txt")).read().strip() if os.path.exists(
        os.path.join(work, "tshark", "version.txt")) else "tshark"
    L = []
    tot = collections.Counter()
    by_class = collections.Counter()
    quirks = collections.Counter()
    for r in results:
        tot["cases"] += 1
        tot["datagrams"] += r["datagrams"]
        tot["fp"] += r["fp_records"]
        tot["ref"] += r["ref_records"]
        tot["matched"] += r["matched"]
        by_class[case_class(r)] += 1
        for i in r["items"]:
            tot[i["class"]] += 1
            if i["class"] == KNOWN:
                quirks[i["ref"]] += 1
    L.append("# FlowPilot decoder conformance report\n")
    L.append(f"Reference decoder: {version}. Generated by tests/conformance/run.sh; see tests/conformance/README.md.\n")
    L.append("## Summary\n")
    L.append(f"- Cases: {tot['cases']} ({', '.join(f'{k}: {v}' for k, v in sorted(by_class.items()))})")
    L.append(f"- Datagrams: {tot['datagrams']}; FlowPilot records: {tot['fp']}; reference records (after the "
             f"flow filter): {tot['ref']}; matched exactly: {tot['matched']}")
    L.append(f"- Differences: {tot[NEW]} new, {tot[KNOWN]} known quirk, {tot[INVALID]} in datagrams tshark could not fully dissect")
    panics = [(r["case"], p) for r in results for p in r["panics"]]
    L.append(f"- Panics: {len(panics)}" + "".join(f"\n  - {c}: datagram {p['datagram']} ({p['parser']}): {p['message']}" for c, p in panics))
    L.append("")
    L.append("### Known quirks hit\n")
    L.append("| Quirk | Records |\n|---|---|")
    for q, n in quirks.most_common():
        L.append(f"| {q} | {n} |")
    L.append("")
    L.append("## Cases\n")
    L.append("Records are counted after the flow filter. \"Pre-filter\" is FlowPilot's meter "
             "(records decoded, NetFlow/IPFIX only) against the reference's decoded data records; it covers the "
             "records both sides then drop. \"Ref incomplete\" counts differences in datagrams tshark could not "
             "fully dissect.\n")
    L.append("| Case | Vendor | Protocol | Datagrams | FlowPilot | Reference | Matched | New | Known | Ref incomplete | Pre-filter FP/ref | Result |")
    L.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in results:
        c = collections.Counter(i["class"] for i in r["items"])
        proto = ",".join(sorted(r["facts"]["versions"])) or "-"
        pre = "-" if "sflow" in r["per_parser"] else f"{r['fp_meter']}/{r['ref_prefilter']}"
        if pre != "-" and r["fp_meter"] != r["ref_prefilter"]:
            pre = f"**{pre}**"
        L.append(f"| {r['case']} | {r['vendor']} | {proto} | {r['datagrams']} | {r['fp_records']} | {r['ref_records']} | "
                 f"{r['matched']} | {c[NEW]} | {c[KNOWN]} | {c[INVALID]} | {pre} | {case_class(r)} |")
    L.append("")
    L.append("## Coverage by vendor\n")
    vend = collections.defaultdict(lambda: collections.Counter())
    for r in results:
        v = vend[r["vendor"]]
        v["cases"] += 1
        v["ref"] += r["ref_records"]
        v["matched"] += r["matched"]
        for k in r["facts"]["versions"]:
            v[k] += 1
    L.append("| Vendor | Cases | Protocols | Reference records | Matched |\n|---|---|---|---|---|")
    for name, v in sorted(vend.items()):
        protos = ",".join(sorted(k for k in v if k.startswith(("v", "sflow")) and k not in ("cases",)))
        L.append(f"| {name} | {v['cases']} | {protos} | {v['ref']} | {v['matched']} |")
    L.append("")
    L.append("## Sampling and options data\n")
    L.append("FlowLink applies no sampling rate (sFlow is not scaled; NetFlow/IPFIX options templates are "
             "not learned). Cases that carry sampling information:\n")
    for r in results:
        if r["facts"]["sampling"]:
            L.append(f"- {r['case']}: {', '.join(r['facts']['sampling'][:6])}")
    L.append("")
    L.append("## Reference records dropped by the flow filter\n")
    L.append("Applied identically to both sides; listed because some are real traffic lost by design.\n")
    drops = collections.Counter()
    for r in results:
        for k, n in r["ref_dropped"].items():
            drops[k] += n
    for k, n in drops.most_common():
        L.append(f"- {k}: {n}")
    L.append("")
    L.append("## New mismatches\n")
    new_items = [(r, i) for r in results for i in r["items"] if i["class"] == NEW]
    if not new_items:
        L.append("None.\n")
    groups = collections.defaultdict(list)
    for r, i in new_items:
        groups[(r["case"], i["kind"], tuple(sorted(i.get("fields", {}))))].append(i)
    for (case, kind, fl), items in sorted(groups.items()):
        L.append(f"### {case}: {kind}" + (f" ({', '.join(fl)})" if fl else "") + f" x{len(items)}\n")
        for i in items[:3]:
            L.append(f"- frame {i['frame']}")
            if "fields" in i:
                L.append("  - " + "; ".join(f"{f}: FlowPilot {a!r} vs reference {b!r}" for f, (a, b) in i["fields"].items()))
            if "reference" in i:
                L.append(f"  - reference: {fmt_rec(i['reference'])}")
            if "fp" in i:
                L.append(f"  - FlowPilot: {fmt_rec(i['fp'])}")
            if i.get("ctx"):
                L.append(f"  - context: `{json.dumps(i['ctx'], sort_keys=True)}`")
        L.append("")
    L.append("## Known quirks and invalid input, by case\n")
    for r in results:
        items = [i for i in r["items"] if i["class"] in (KNOWN, INVALID)]
        if not items:
            continue
        c = collections.Counter((i["class"], i["ref"], i["kind"], i["why"]) for i in items)
        L.append(f"- **{r['case']}**")
        for (cl, ref, kind, why), n in c.most_common():
            L.append(f"  - {n} x {kind}: {cl} ({ref}): {why}")
    L.append("")
    with open(path, "w") as f:
        f.write("\n".join(L) + "\n")


def main():
    work = sys.argv[1]
    path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(work, "report.md")
    cases = json.load(open(os.path.join(work, "cases.json")))
    results = [run_case(c, work) for c in cases]
    with open(os.path.join(work, "results.json"), "w") as f:
        json.dump(results, f, indent=1, default=str)
    write_report(results, work, path)
    new = sum(1 for r in results for i in r["items"] if i["class"] == NEW)
    print(f"{len(results)} cases, {new} new mismatches -> {path}")


if __name__ == "__main__":
    main()
