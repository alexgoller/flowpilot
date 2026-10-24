"""Decode stored FlowLink uploads (gzip + UploadBatch proto2) into canonical JSON.

Usage: decode_posts.py DIR  -> prints {"posts": n, "aggregation_seconds": [...], "records": [...]}
Records are sorted; instance_id is reported separately. Field numbers: src/proto.rs.
"""
import glob
import gzip
import ipaddress
import json
import os
import sys

REC = {1: "timestamp", 2: "src_ip", 3: "dst_ip", 4: "dst_port", 5: "proto", 6: "count", 7: "icmp_type",
       8: "icmp_code", 9: "src_mac", 10: "dst_mac", 11: "device_addr", 12: "src_mask_bits",
       13: "dst_mask_bits", 14: "octets", 15: "dst_dbi", 16: "dst_dbo"}
TD = {1: "aggregation_seconds", 2: "org_id", 3: "installation_id", 4: "pce_host", 5: "instance_id", 10: "flows"}


def varint(b, i):
    v = shift = 0
    while True:
        x = b[i]
        i += 1
        v |= (x & 0x7F) << shift
        shift += 7
        if x < 0x80:
            return v, i


def fields(b):
    i = 0
    while i < len(b):
        tag, i = varint(b, i)
        num, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i = varint(b, i)
        elif wt == 2:
            n, i = varint(b, i)
            v, i = b[i:i + n], i + n
        else:
            raise ValueError(f"unexpected wire type {wt}")
        yield num, v


def signed(v):
    return v - (1 << 64) if v >= 1 << 63 else v


def record(b):
    r = {}
    for num, v in fields(b):
        name = REC[num]
        if name in ("src_ip", "dst_ip"):
            v = str(ipaddress.ip_address(bytes(v))) + ("/16" if len(v) == 16 else "/4")
        elif isinstance(v, bytes):
            v = v.hex()
        elif name != "octets":
            v = signed(v)
        r[name] = v
    return r


posts, aggs, ids, recs = 0, [], set(), []
for path in sorted(glob.glob(os.path.join(sys.argv[1], "*.pb.gz"))):
    posts += 1
    for num, v in fields(gzip.decompress(open(path, "rb").read())):
        if TD[num] == "flows":
            recs.append(record(v))
        elif TD[num] == "aggregation_seconds":
            aggs.append(signed(v))
        elif TD[num] == "instance_id":
            ids.add(v.decode())
        else:
            recs.append({"unexpected_traffic_data_field": TD[num]})
recs.sort(key=lambda r: json.dumps(r, sort_keys=True))
print(json.dumps({"posts": posts, "aggregation_seconds": aggs, "instance_ids": sorted(ids), "records": recs},
                 indent=1, sort_keys=True))
