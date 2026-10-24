"""Reference side of the conformance harness: tshark PDML -> FlowLink-shaped flow records.

tshark does the structural work (header, set and template walking, template state across packets,
record boundaries, IP reassembly, dissection of sFlow sampled headers). This module maps what
tshark found onto the record FlowPilot is meant to produce:

* NetFlow v9 / IPFIX: each data record's raw bytes (the "Flow N" item tshark emits) are split with
  the template tshark used (`cflow.template_frame`), and each information element is interpreted
  per RFC 7011/7012 (any length, reduced-size encoding, variable length). The FlowLink semantics
  on top (which IE feeds which field, `flows` default 1, direction default 2, NAT duplicate,
  flow-time rules) follow docs/collectors.md.
* NetFlow v5/v7: the 48-byte record layout, FlowLink time rule.
* sFlow v5: one record per sampled packet (format 1), IPv4/IPv6 data (formats 3/4), with fields
  from tshark's dissection of the sampled header (eth/vlan/ip/ipv6/tcp/udp/icmp).

Every record carries a `ctx` dict describing the input features the classifier needs
(template IEs and lengths, set position, sFlow header facts).
"""
import ipaddress
import xml.etree.ElementTree as ET

NTP_UNIX_OFFSET = 2_208_988_800

# FlowPilot reads these IEs with a fixed width regardless of the template length,
# as FlowLink does. A template that gives another length desynchronises the record.
FIXED_WIDTH = {8: 4, 12: 4, 225: 4, 226: 4, 27: 16, 28: 16, 281: 16, 282: 16, 9: 1, 13: 1, 29: 1,
               30: 1, 61: 1, 176: 1, 177: 1, 178: 1, 179: 1, 22: 4, 158: 4, 154: 8, 156: 8, 56: 6,
               57: 6, 227: 2, 228: 2}
MIN_WIDTH = {4: 1, 60: 1, 7: 2, 11: 2, 32: 2, 139: 2, 180: 2, 181: 2, 182: 2, 183: 2}
# Octet counters other than IE 1. FlowPilot reads 231 and 85 when IE 1 is absent (in that order);
# FlowLink read none of them.
ALT_OCTETS = {85: "octetTotalCount", 23: "postOctetDeltaCount", 231: "initiatorOctets (NSEL)",
              232: "responderOctets (NSEL)", 352: "layer2OctetDeltaCount"}
START_TIME_IES = {22, 150, 152, 154, 156, 158}
END_TIME_IES = {21, 151, 153, 155, 157, 159}
SAMPLING_IES = {34, 305, 306, 50, 48}


def go_ip(b):
    """Go net.IP.String() of 4 or 16 raw bytes (IPv4-mapped IPv6 prints dotted)."""
    if len(b) == 4:
        return str(ipaddress.IPv4Address(b))
    a = ipaddress.IPv6Address(b)
    return str(a.ipv4_mapped) if a.ipv4_mapped else a.compressed


def norm_ip(s):
    """Canonical text for comparisons (accepts any textual form)."""
    if not s:
        return ""
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return s
    if a.version == 6 and a.ipv4_mapped:
        return str(a.ipv4_mapped)
    return a.compressed


def mac(b):
    return ":".join(f"{x:02X}" for x in b)


def new_record(**kw):
    r = {"src_ip": "", "dst_ip": "", "src_port": 0, "dst_port": 0, "ip_version": 0, "protocol": 0,
         "icmp_type": 0, "icmp_code": 0, "src_mac": "", "dst_mac": "", "src_mask": 0, "dst_mask": 0,
         "flow_time": 0, "flows": 1, "octets": 0, "direction_ind": 2, "seq_id": ""}
    r.update(kw)
    return r


# ---------------------------------------------------------------------------------------------
# The flow filter (src/flow.rs check_flow), applied to reference records as well

def is_multicast_or_broadcast(ip, mac_s):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        a = None
    v4 = None
    if a is not None:
        v4 = a if a.version == 4 else a.ipv4_mapped
    in_v4_d = v4 is not None and (v4.packed[0] & 0xE0) == 0xE0
    in_v6_d = v4 is None and a is not None and a.version == 6 and a.packed[0] == 0xFF

    def has(c):
        i = ip.find(c)
        return i > 0
    return (has(".") and (in_v4_d or mac_s.startswith("01:00:5E:") or mac_s == "FF:FF:FF:FF:FF:FF")) or \
        (has(":") and (in_v6_d or mac_s.startswith("33:33")))


def icmp_from_port(r):
    """FlowPilot fix (ICMP type/code in the destination port): an ICMP record without IE 32/139/176-179 (and every v5 record)
    carries type and code in the destination port: type*256 + code, or the bare type below 256
    (type 0 has no codes). src/flow.rs icmp_from_dst_port."""
    p = r["dst_port"]
    if r["protocol"] in (1, 58) and p:
        r["icmp_type"], r["icmp_code"] = (p, 0) if p < 256 else (p >> 8, p & 0xFF)
        r["dst_port"] = 0
    return r


def check_flow(r):
    """Returns (record or None, drop reason)."""
    if not r["src_ip"] or not r["dst_ip"] or r["ip_version"] == 0:
        return None, "empty address or ip_version 0"
    if r["ip_version"] == 6 and r["protocol"] in (0, 43, 44):
        return None, "IPv6 protocol 0/43/44"
    if is_multicast_or_broadcast(r["src_ip"], r["src_mac"]) or is_multicast_or_broadcast(r["dst_ip"], r["dst_mac"]):
        return None, "multicast/broadcast/240/4 address or MAC"
    if r["dst_port"] > 0 and r["protocol"] in (1, 58):
        return None, "ICMP with dst_port > 0 and a type/code field (Cisco ASA)"
    if r["direction_ind"] == 2 and r["src_port"] != 0 and r["dst_port"] != 0:
        if r["src_port"] < r["dst_port"] and r["dst_port"] > 32768 and r["src_port"] < 32768:
            r["src_ip"], r["dst_ip"] = r["dst_ip"], r["src_ip"]
            r["src_port"], r["dst_port"] = r["dst_port"], r["src_port"]
        r["direction_ind"] = 0
    return r, None


# ---------------------------------------------------------------------------------------------
# PDML helpers

def fields(el, name=None):
    return [c for c in el if c.tag == "field" and (name is None or c.get("name") == name)]


def first(el, name):
    for c in el.iter("field"):
        if c.get("name") == name:
            return c
    return None


def show_int(el, name, default=0):
    f = first(el, name)
    if f is None:
        return default
    try:
        return int(f.get("show"), 0)
    except (TypeError, ValueError):
        return default


def raw(el):
    v = el.get("value") or ""
    try:
        return bytes.fromhex(v)
    except ValueError:
        return b""


def raw_int(el, name, default=0):
    f = first(el, name)
    if f is None or not f.get("value"):
        return default
    return int.from_bytes(raw(f), "big")


def containers(el, prefix):
    return [c for c in fields(el, "") if (c.get("show") or "").startswith(prefix)]


def has_child(el, name):
    return any(c.get("name") == name for c in fields(el))


# ---------------------------------------------------------------------------------------------
# NetFlow v9 / IPFIX

class Template:
    def __init__(self, frame, tid, fields_, options, set_ctx):
        self.frame, self.tid, self.fields, self.options = frame, tid, fields_, options
        self.set_ctx = set_ctx  # flags of the template set (beyond the record count, padding)


def parse_template_fields(cont, v10):
    out = []
    for f in containers(cont, "Field ("):
        b = raw(f)
        if len(b) < 4:
            continue
        t, ln = int.from_bytes(b[0:2], "big"), int.from_bytes(b[2:4], "big")
        pen = 0
        if v10 and t & 0x8000:
            pen = int.from_bytes(b[4:8], "big") if len(b) >= 8 else -1
            t &= 0x7FFF
        out.append((t, pen, ln))
    return out


def template_flags(fields_):
    """Template-level facts that change how FlowPilot decodes its records."""
    fl = {"varlen": False, "fixed_width_mismatch": [], "ie1_bad_len": False, "ie3_bad_len": False,
          "ie3_len8": False, "enterprise": False, "ies": set()}
    for ie, pen, ln in fields_:
        if ln == 0xFFFF:
            fl["varlen"] = True  # also for enterprise IEs (records are walked per RFC 7011 section 7)
        if pen:
            fl["enterprise"] = True
            continue
        fl["ies"].add(ie)
        if ln == 0xFFFF:
            continue
        if ie in FIXED_WIDTH and ln != FIXED_WIDTH[ie]:
            fl["fixed_width_mismatch"].append((ie, ln))
        if ie in MIN_WIDTH and ln < MIN_WIDTH[ie]:
            fl["fixed_width_mismatch"].append((ie, ln))
        if ie in (150, 152) and ln not in (4, 8):
            fl["fixed_width_mismatch"].append((ie, ln))
        if ie == 1 and not (ln == 4 or ln >= 8):
            fl["ie1_bad_len"] = True
        if ie == 3 and ln < 4:
            fl["ie3_bad_len"] = True
        if ie == 3 and ln == 8:
            fl["ie3_len8"] = True
    return fl


def decode_cflow_record(b, tmpl, version, hdr):
    """Interprets one data record. Returns (record, ctx) or (None, ctx) for options data."""
    ctx = {"kind": "options" if tmpl.options else "data", "tid": tmpl.tid, "template_frame": tmpl.frame,
           "alt_octets": {}, "start_ies": [], "end_ies": [], "ie1": False, "sampling": {}}
    rec = new_record(seq_id=str(hdr["seq"]), flow_time=hdr["export"])
    nat = {"src": "", "dst": "", "ver": 0, "sport": 0, "dport": 0}
    off = 0
    vals = []
    for ie, pen, ln in tmpl.fields:
        if ln == 0xFFFF:
            if off >= len(b):
                break
            n = b[off]
            off += 1
            if n == 255:
                n = int.from_bytes(b[off:off + 2], "big")
                off += 2
        else:
            n = ln
        vals.append((ie, pen, b[off:off + n]))
        off += n
    ctx["record_len"] = off
    if tmpl.options:
        for ie, pen, v in vals:
            if pen == 0 and ie in SAMPLING_IES:
                ctx["sampling"][ie] = int.from_bytes(v, "big")
        return None, ctx
    for ie, pen, v in vals:
        if pen:
            continue
        u = int.from_bytes(v, "big") if v else 0
        if ie == 1:
            rec["octets"] = u
            ctx["ie1"] = True
        elif ie in ALT_OCTETS:
            ctx["alt_octets"][ie] = u
        elif ie == 3:
            rec["flows"] = u
        elif ie == 4:
            rec["protocol"] = u & 0xFF
        elif ie in (7, 180, 182):
            rec["src_port"] = u & 0xFFFF
        elif ie in (11, 181, 183):
            rec["dst_port"] = u & 0xFFFF
        elif ie in (8, 12) and len(v) == 4:
            if u:
                rec["ip_version"] = 4
                rec["src_ip" if ie == 8 else "dst_ip"] = go_ip(v)
        elif ie in (27, 28) and len(v) == 16:
            a = ipaddress.IPv6Address(v)
            if not (a.is_unspecified or a.ipv4_mapped == ipaddress.IPv4Address(0)):
                rec["ip_version"] = 6
                rec["src_ip" if ie == 27 else "dst_ip"] = go_ip(v)
        elif ie in (9, 29):
            rec["src_mask"] = u & 0xFF
        elif ie in (13, 30):
            rec["dst_mask"] = u & 0xFF
        elif ie == 56 and len(v) == 6:
            rec["src_mac"] = mac(v)
        elif ie == 57 and len(v) == 6:
            rec["dst_mac"] = mac(v)
        elif ie == 60:
            rec["ip_version"] = u & 0xFF
        elif ie == 61:
            rec["direction_ind"] = u & 0xFF
        elif ie in (32, 139):
            rec["icmp_type"], rec["icmp_code"] = (u >> 8) & 0xFF, u & 0xFF
            ctx["icmp_ie"] = True
        elif ie in (176, 178):
            rec["icmp_type"] = u & 0xFF
            ctx["icmp_ie"] = True
        elif ie in (177, 179):
            rec["icmp_code"] = u & 0xFF
            ctx["icmp_ie"] = True
        elif ie in START_TIME_IES:
            ctx["start_ies"].append(ie)
            if ie == 150:
                rec["flow_time"] = u
            elif ie == 152:
                rec["flow_time"] = u // 1000
            elif ie in (154, 156):
                rec["flow_time"] = (u >> 32) - NTP_UNIX_OFFSET
            elif ie == 158:
                # Flow started v microseconds before the export time (RFC 7011 / IANA).
                if rec["flow_time"] == hdr["export"]:
                    rec["flow_time"] = hdr["export"] - u // 1_000_000
            elif ie == 22 and version == 9 and hdr["uptime"]:
                rec["flow_time"] -= ((hdr["uptime"] - u) & 0xFFFFFFFF) // 1000
        elif ie in END_TIME_IES:
            ctx["end_ies"].append(ie)
        elif ie in (225, 226) and len(v) == 4:
            if u:
                nat["src" if ie == 225 else "dst"] = go_ip(v)
                nat["ver"] = 4
        elif ie in (281, 282) and len(v) == 16:
            a = ipaddress.IPv6Address(v)
            if not (a.is_unspecified or a.ipv4_mapped == ipaddress.IPv4Address(0)):
                nat["src" if ie == 281 else "dst"] = go_ip(v)
                nat["ver"] = 6
        elif ie == 227:
            nat["sport"] = u & 0xFFFF
        elif ie == 228:
            nat["dport"] = u & 0xFFFF
    if not ctx["ie1"]:
        # Without IE 1, take the counter the exporter did send: 231 and 85 are what FlowPilot reads,
        # 23 and 352 only make the diff show the unread bytes.
        for ie in (231, 85, 23, 352):
            if ie in ctx["alt_octets"]:
                rec["octets"] = ctx["alt_octets"][ie]
                ctx["octets_from"] = ie
                break
    ctx["nat"] = nat if nat["src"] and nat["dst"] else None
    return rec, ctx


def walk_records(d, tmpl):
    """Splits a data set's bytes into records (RFC 7011 section 7 variable-length encoding).

    Only used where tshark gave no record boundaries: a data set it had no template for (templates
    keyed without the exporter port), or a datagram where it stopped with an exception (see fallback_sets). The rest is padding.
    """
    minimum = sum(1 if ln == 0xFFFF else ln for _ie, _pen, ln in tmpl.fields)
    out, off = [], 0
    if minimum == 0:
        return out
    while len(d) - off >= minimum:
        start = off
        for _ie, _pen, ln in tmpl.fields:
            if ln == 0xFFFF:
                n = d[off]
                off += 1
                if n == 255:
                    n = int.from_bytes(d[off:off + 2], "big")
                    off += 2
                off += n
            else:
                off += ln
        if off > len(d):
            break
        out.append(d[start:off])
    return out


def is_malformed(pkt):
    return any(p.get("name") == "_ws.malformed" for p in pkt.iter("proto"))


def udp_payload(pkt):
    for p in pkt:
        if p.tag == "proto" and p.get("name") == "udp":
            f = first(p, "udp.payload")
            if f is not None and f.get("show"):
                try:
                    return bytes.fromhex(f.get("show").replace(":", ""))
                except ValueError:
                    return None
    return None


def tshark_sets(proto, version):
    """The sets as tshark dissected them."""
    msg_start = int(proto.get("pos", 0))
    out = []
    for s in fields(proto, ""):
        if not has_child(s, "cflow.flowset_id"):
            continue
        sid = show_int(s, "cflow.flowset_id")
        d = {"sid": sid, "slen": show_int(s, "cflow.flowset_length"), "pos": int(s.get("pos", 0)) - msg_start}
        if sid in (0, 1, 2, 3):
            conts = containers(s, "Options Template (") if sid in (1, 3) else containers(s, "Template (")
            # Byte count from the field items (tshark's own item size omits enterprise numbers).
            d["used"] = 4 + sum(4 + sum(len(raw(f)) for f in containers(c, "Field (")) for c in conts)
            d["templates"] = [(show_int(c, "cflow.template_id"), parse_template_fields(c, version == 10)) for c in conts]
        else:
            tf = first(s, "cflow.template_frame")
            d["template_frame"] = int(tf.get("show")) if tf is not None else None
            d["records"] = [raw(rc) for rc in containers(s, "Flow ")]
            d["data"] = next((raw(c) for c in containers(s, "Data (")), b"")
            d["raw"] = raw(s)[4:]
        out.append(d)
    return out


def fallback_sets(p, version):
    """Harness set walker (RFC 3954 / RFC 7011), used only for datagrams where tshark raised an
    exception part-way and so left the rest undissected. Records from it are marked `fallback`."""
    out = []
    off = 20 if version == 9 else 16
    while off + 4 <= len(p):
        sid, slen = int.from_bytes(p[off:off + 2], "big"), int.from_bytes(p[off + 2:off + 4], "big")
        if slen < 4:
            break
        body = p[off + 4:off + slen]
        d = {"sid": sid, "slen": slen, "pos": off, "used": 4, "templates": []}
        if sid in (0, 2):
            o = 0
            while o + 4 <= len(body):
                tid, count = int.from_bytes(body[o:o + 2], "big"), int.from_bytes(body[o + 2:o + 4], "big")
                o += 4
                fl = []
                for _ in range(count):
                    t, ln = int.from_bytes(body[o:o + 2], "big"), int.from_bytes(body[o + 2:o + 4], "big")
                    o += 4
                    pen = 0
                    if sid == 2 and t & 0x8000:
                        pen, t = int.from_bytes(body[o:o + 4], "big"), t & 0x7FFF
                        o += 4
                    fl.append((t, pen, ln))
                if tid < 256:
                    break
                d["templates"].append((tid, fl))
                d["used"] = 4 + o
        elif sid in (1, 3):
            d["used"] = slen
        else:
            d["data"] = body
        out.append(d)
        off += slen
    return out


def cflow_records(pkt, frame, src, sport, proto, templates):
    """Yields (record, ctx) for one cflow PDU and updates `templates`."""
    version = show_int(proto, "cflow.version")
    out = []
    malformed = is_malformed(pkt)
    if version in (5, 7):
        hdr = {"uptime": raw_int(proto, "cflow.sysuptime"), "secs": raw_int(proto, "cflow.unix_secs"),
               "nsecs": raw_int(proto, "cflow.unix_nsecs"), "seq": show_int(proto, "cflow.sequence")}
        sampling = show_int(proto, "cflow.samplerate")
        for i, pdu in enumerate(containers(proto, "pdu ")):
            b = raw(pdu)
            if len(b) < 48:
                continue
            first_ = int.from_bytes(b[24:28], "big")
            t = hdr["secs"] + hdr["nsecs"] // 1_000_000_000 - ((hdr["uptime"] - first_) & 0xFFFFFFFF) // 1000
            rec = new_record(src_ip=go_ip(b[0:4]), dst_ip=go_ip(b[4:8]), src_port=int.from_bytes(b[32:34], "big"),
                             dst_port=int.from_bytes(b[34:36], "big"), ip_version=4, protocol=b[38],
                             src_mask=b[44], dst_mask=b[45], flow_time=t, octets=int.from_bytes(b[20:24], "big"),
                             direction_ind=0, seq_id=str(hdr["seq"]))
            out.append((icmp_from_port(rec), {"kind": "data", "version": version, "record_index": i, "malformed": malformed,
                              "v5_sampling": sampling}))
        return out
    if version not in (9, 10):
        return out
    if version == 9:
        hdr = {"uptime": raw_int(proto, "cflow.sysuptime"), "export": raw_int(proto, "cflow.unix_secs"),
               "seq": show_int(proto, "cflow.sequence"), "domain": show_int(proto, "cflow.source_id"),
               "count": show_int(proto, "cflow.count")}
    else:
        hdr = {"uptime": 0, "export": raw_int(proto, "cflow.exporttime"), "seq": show_int(proto, "cflow.sequence"),
               "domain": show_int(proto, "cflow.od_id"), "count": None}
    payload = udp_payload(pkt)
    fallback = malformed and payload is not None
    sets = fallback_sets(payload, version) if fallback else tshark_sets(proto, version)
    for si, s in enumerate(sets, 1):
        sid, slen = s["sid"], s["slen"]
        set_ctx = {
            "set_index": si,
            # As in FlowLink, v9 FlowSets beyond the header count are never read.
            "beyond_count": version == 9 and si > (hdr["count"] or 0),
        }
        if sid in (0, 2, 1, 3):
            options = sid in (1, 3)
            set_ctx["template_padding"] = s["used"] < slen and not options
            for tid, f in s["templates"]:
                t = Template(frame, tid, f, options, set_ctx)
                templates[(frame, src, hdr["domain"], tid)] = t
                templates[("latest", src, hdr["domain"], tid)] = t
                templates[("session", src, sport, hdr["domain"], tid)] = t
            continue
        if sid < 256:
            continue
        # What FlowPilot uses: the last template with this id from the exporter IP, whatever the
        # UDP port, as FlowLink does. tshark scopes templates to the transport session (RFC 7011 8).
        by_ip = templates.get(("latest", src, hdr["domain"], sid))
        by_session = templates.get(("session", src, sport, hdr["domain"], sid))
        stale = by_ip is not None and (by_session is None or
                                        (by_ip.fields, by_ip.options) != (by_session.fields, by_session.options))
        if fallback or s["template_frame"] is None:
            t = by_ip
            recs = walk_records(s["data"], t) if t is not None else []
        else:
            t = templates.get((s["template_frame"], src, hdr["domain"], sid))
            # tshark sizes a record item without its variable-length fields; walk those sets ourselves.
            recs = walk_records(s["raw"], t) if t is not None and template_flags(t.fields)["varlen"] else s["records"]
        if t is None:
            continue
        flags = template_flags(t.fields)
        for ri, rb in enumerate(recs):
            rec, ctx = decode_cflow_record(rb, t, version, hdr)
            if rec is not None and not ctx.get("icmp_ie"):
                icmp_from_port(rec)
            ctx.update({"version": version, "set": set_ctx, "template_set": t.set_ctx, "tflags": flags,
                        "record_index": ri, "malformed": malformed and not fallback, "fallback": fallback,
                        "frame": frame, "stale_template": stale,
                        "walk_disagrees": not fallback and s.get("template_frame") is not None and len(recs) != len(s["records"])})
            out.append((rec, ctx))
            if rec is not None and ctx.get("nat"):
                n = ctx["nat"]
                dup = dict(rec)
                dup.update(src_ip=n["src"], dst_ip=n["dst"], ip_version=n["ver"])
                if n["dport"]:
                    dup["dst_port"] = n["dport"]
                if n["sport"]:
                    dup["src_port"] = n["sport"]
                if not ctx.get("icmp_ie"):
                    icmp_from_port(dup)
                out.append((dup, dict(ctx, nat_duplicate=True)))
    return out


# ---------------------------------------------------------------------------------------------
# sFlow v5

def sflow_header_record(state, cont):
    """One format-1 record: fields from tshark's dissection of the sampled header."""
    hp = show_int(cont, "sflow_245.header_protocol")
    hdr_f = first(cont, "sflow_245.header")
    hdr_bytes = raw(hdr_f) if hdr_f is not None else b""
    hdr_pos = int(hdr_f.get("pos", 0)) if hdr_f is not None else 0
    protos = [p for p in cont.iter("proto")]
    names = [p.get("name") for p in protos]
    ctx = {"format": 1, "header_protocol": hp, "notes": []}
    rec = dict(state)
    if hp == 1:
        eth = next((p for p in protos if p.get("name") == "eth"), None)
        if eth is None:
            return None, ctx
        rec["src_mac"] = (first(eth, "eth.src").get("show") or "").upper()
        rec["dst_mac"] = (first(eth, "eth.dst").get("show") or "").upper()
        vlans = [p for p in protos if p.get("name") == "vlan"]
        if len(hdr_bytes) >= 14 and int.from_bytes(hdr_bytes[12:14], "big") <= 0x05DC:
            ctx["notes"].append("802.3 LLC frame")
            return None, ctx
        if len(vlans) > 1 or (len(hdr_bytes) >= 14 and int.from_bytes(hdr_bytes[12:14], "big") == 0x88A8):
            ctx["notes"].append("QinQ / stacked VLAN")
    elif hp not in (11, 12):
        ctx["notes"].append(f"header protocol {hp}")
        return None, ctx
    if hp == 12:
        ctx["notes"].append("bare IPv6 header (protocol 12)")
    ip = next((p for p in protos if p.get("name") in ("ip", "ipv6")), None)
    if ip is None:
        ctx["notes"].append("no IP header (" + ",".join(n for n in names if n) + ")")
        return None, ctx
    rec["dst_port"] = 0  # FlowLink resets dst_port only; src_port is reset here for the intended value
    rec["src_port"] = 0
    rec["icmp_type"] = rec["icmp_code"] = 0
    ip_pos = int(ip.get("pos", 0))
    if ip.get("name") == "ip":
        rec["ip_version"] = 4
        rec["src_ip"] = norm_ip(first(ip, "ip.src").get("show"))
        rec["dst_ip"] = norm_ip(first(ip, "ip.dst").get("show"))
        rec["protocol"] = show_int(ip, "ip.proto")
        ihl = show_int(ip, "ip.hdr_len", 20)
        l4_start = ip_pos + ihl
        if show_int(ip, "ip.frag_offset") > 0:
            ctx["notes"].append("non-first IPv4 fragment")
    else:
        rec["ip_version"] = 6
        rec["src_ip"] = norm_ip(first(ip, "ipv6.src").get("show"))
        rec["dst_ip"] = norm_ip(first(ip, "ipv6.dst").get("show"))
        nxt = [f for f in ip.iter("field") if (f.get("name") or "").endswith(".nxt")]
        rec["protocol"] = int(nxt[-1].get("show"), 0) if nxt else 0
        first_nxt = show_int(ip, "ipv6.nxt")
        if first_nxt != rec["protocol"] or len(nxt) > 1:
            ctx["notes"].append(f"IPv6 extension headers (first next header {first_nxt})")
        l4_start = ip_pos + 40
    ctx["after_ip"] = hdr_pos + len(hdr_bytes) - l4_start
    l4 = next((p for p in protos[protos.index(ip) + 1:] if p.get("name") in ("tcp", "udp", "icmp", "icmpv6")), None)
    if l4 is not None:
        n = l4.get("name")
        if n in ("tcp", "udp"):
            rec["src_port"] = show_int(l4, n + ".srcport")
            rec["dst_port"] = show_int(l4, n + ".dstport")
        else:
            rec["icmp_type"] = show_int(l4, n + ".type")
            rec["icmp_code"] = show_int(l4, n + ".code")
    ctx["l4"] = l4.get("name") if l4 is not None else None
    return rec, ctx


def sflow_records(pkt, frame, proto):
    out = []
    malformed = is_malformed(pkt)
    samples = [c for c in fields(proto, "") if has_child(c, "sflow_245.sampletype")]
    for si, s in enumerate(samples):
        b = raw(s)
        stype = int.from_bytes(b[0:4], "big") if len(b) >= 4 else -1
        if stype not in (1, 3):
            continue
        rate = show_int(s, "sflow.flow_sample.sampling_rate")
        state = new_record(flows=1, octets=0, direction_ind=2)
        recs = [c for c in fields(s, "") if has_child(c, "sflow_245.flow_record_format")]
        prev_formats = []
        for ri, c in enumerate(recs):
            cb = raw(c)
            fmt = int.from_bytes(cb[0:4], "big") if len(cb) >= 4 else -1
            base = {"sample_index": si, "record_index": ri, "sampling_rate": rate, "malformed": malformed,
                    "frame": frame, "prev_formats": list(prev_formats), "state_src_port": state["src_port"],
                    "state_macs": bool(state["src_mac"] or state["dst_mac"])}
            prev_formats.append(fmt)
            if fmt == 1:
                rec, ctx = sflow_header_record(state, c)
                ctx.update(base)
                ctx["kind"] = "data" if rec is not None else "none"
                out.append((rec, ctx))
            elif fmt == 2 and len(cb) >= 34:
                state["src_mac"], state["dst_mac"] = mac(cb[16:22]), mac(cb[24:30])
            elif fmt == 3 and len(cb) >= 44:
                state.update(ip_version=4, protocol=int.from_bytes(cb[12:16], "big") & 0xFF,
                             src_ip=go_ip(cb[16:20]), dst_ip=go_ip(cb[20:24]),
                             src_port=int.from_bytes(cb[24:28], "big") & 0xFFFF,
                             dst_port=int.from_bytes(cb[28:32], "big") & 0xFFFF)
                out.append((dict(state), dict(base, format=3, kind="data", notes=[])))
            elif fmt == 4 and len(cb) >= 64:
                rec = dict(state)
                rec.update(ip_version=6, protocol=int.from_bytes(cb[12:16], "big") & 0xFF,
                           src_ip=go_ip(cb[16:32]), dst_ip=go_ip(cb[32:48]),
                           src_port=int.from_bytes(cb[48:52], "big") & 0xFFFF,
                           dst_port=int.from_bytes(cb[52:56], "big") & 0xFFFF)
                out.append((rec, dict(base, format=4, kind="data", notes=["IPv6 data record (format 4)"])))
    return out


# ---------------------------------------------------------------------------------------------

def parse_pdml(path):
    """Returns {frame: [(record or None, ctx), ...]} plus per-file facts."""
    frames = {}
    facts = {"packets": 0, "cflow_pdus": 0, "sflow_pdus": 0, "versions": {}, "sampling": set(),
             "malformed_frames": 0, "malformed_list": [], "options_records": 0, "data_records": 0}
    templates = {}
    for _ev, el in ET.iterparse(path, events=("end",)):
        if el.tag != "packet":
            continue
        facts["packets"] += 1
        top = [c for c in el if c.tag == "proto"]
        geninfo = next((p for p in top if p.get("name") == "geninfo"), None)
        frame = show_int(geninfo, "num") if geninfo is not None else facts["packets"]
        src = ""
        for p in top:
            if p.get("name") in ("ip", "ipv6"):
                f = first(p, p.get("name") + ".src")
                src = norm_ip(f.get("show")) if f is not None else ""
                break
        udp = next((p for p in top if p.get("name") == "udp"), None)
        sport = show_int(udp, "udp.srcport") if udp is not None else 0
        if is_malformed(el):
            facts["malformed_frames"] += 1
            facts["malformed_list"].append(frame)
        res = []
        for p in top:
            if p.get("name") == "cflow":
                facts["cflow_pdus"] += 1
                v = show_int(p, "cflow.version")
                facts["versions"][f"v{v}"] = facts["versions"].get(f"v{v}", 0) + 1
                res += cflow_records(el, frame, src, sport, p, templates)
            elif p.get("name") == "sflow":
                facts["sflow_pdus"] += 1
                facts["versions"]["sflow5"] = facts["versions"].get("sflow5", 0) + 1
                res += sflow_records(el, frame, p)
        for rec, ctx in res:
            if ctx.get("kind") == "options":
                facts["options_records"] += 1
                for ie, val in ctx.get("sampling", {}).items():
                    facts["sampling"].add(f"IE{ie}={val}")
            elif rec is not None:
                facts["data_records"] += 1
                if ctx.get("v5_sampling"):
                    facts["sampling"].add(f"v5 header sample rate={ctx['v5_sampling']}")
                if ctx.get("sampling_rate", 0) > 1:
                    facts["sampling"].add(f"sFlow rate={ctx['sampling_rate']}")
        if res:
            frames[frame] = res
        el.clear()
    facts["sampling"] = sorted(facts["sampling"])
    return frames, facts
