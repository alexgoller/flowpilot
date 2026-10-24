#!/usr/bin/env python3
"""Builds the list of conformance cases from the fetched corpus.

Every capture in corpus.lock is one case. Every line of dat_sequences.txt becomes one case whose
raw payloads are wrapped into a synthetic pcap (Ethernet/IPv4/UDP from 192.0.2.1:50000 to
192.0.2.2, port 2055 for NetFlow v5/v9 and 4739 for IPFIX), so FlowPilot and tshark read the same
file. Writes <work>/cases.json.

usage: prepare.py CORPUS_DIR WORK_DIR
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# (substring of the case name, vendor label); first match wins.
VENDORS = [
    ("asa", "Cisco ASA (NSEL)"), ("asr9k", "Cisco ASR 9000"), ("asr1001", "Cisco ASR 1000"),
    ("nbar", "Cisco NBAR"), ("wlc", "Cisco WLC"), ("1941", "Cisco ISR 1941"), ("aci", "Cisco ACI"),
    ("iosxe", "Cisco IOS XE"), ("iosxr", "Cisco IOS XR"), ("cisco", "Cisco"),
    ("juniper", "Juniper"), ("paloalto", "Palo Alto"), ("fortigate", "Fortinet FortiGate"),
    ("mikrotik", "MikroTik"), ("ubnt", "Ubiquiti EdgeRouter"), ("ubiquiti", "Ubiquiti EdgeRouter"),
    ("vmware", "VMware vDS"), ("netscaler", "Citrix NetScaler"), ("barracuda", "Barracuda"),
    ("nprobe", "ntop nProbe"), ("softflowd", "softflowd"), ("iptnetflow", "ipt_NETFLOW (Linux)"),
    ("h3c", "H3C"), ("huawei", "Huawei"), ("nokia", "Nokia BRAS"), ("procera", "Procera"),
    ("viptela", "Cisco Viptela"), ("yaf", "CERT YAF"), ("openbsd", "OpenBSD pflow"),
    ("ixia", "Ixia"), ("streamcore", "Streamcore"), ("ipfixprobe", "CESNET ipfixprobe"),
    ("e10s", "Elastic test exporter"), ("sflow", "sFlow agent"), ("data-", "sFlow agent"),
]

def vendor_of(name):
    low = name.lower()
    for sub, v in VENDORS:
        if sub in low:
            return v
    return "unspecified"

def ip_checksum(h):
    s = sum(struct.unpack("!10H", h))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def frame(payload):
    version = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 0
    port = 4739 if version == 10 else 2055
    udp = struct.pack("!HHHH", 50000, port, 8 + len(payload), 0) + payload
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                               bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])))
    ip[10:12] = struct.pack("!H", ip_checksum(bytes(ip)))
    eth = bytes.fromhex("020000000002" "020000000001" "0800")
    return eth + bytes(ip) + udp

def write_pcap(path, payloads):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(payloads):
            fr = frame(p)
            f.write(struct.pack("<IIII", 1_600_000_000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def main():
    corpus, work = sys.argv[1], sys.argv[2]
    os.makedirs(os.path.join(work, "synthetic"), exist_ok=True)
    cases = []
    dat_dir = None
    for line in open(os.path.join(HERE, "corpus.lock")):
        if not line.strip() or line.startswith("#"):
            continue
        source, repo, commit, path, _sha = line.split()
        full = os.path.join(corpus, source, path)
        if path.endswith(".dat"):
            dat_dir = os.path.dirname(full)
            continue
        name = path.split("/testdata/")[-1] if "/testdata/" in path else path.replace("tests/", "")
        name = name.replace("/", "_").rsplit(".", 1)[0]
        cases.append({"case": f"{source}/{name}", "source": source, "vendor": vendor_of(name),
                      "pcap": full, "inputs": [path], "repo": repo, "commit": commit})
    for line in open(os.path.join(HERE, "dat_sequences.txt")):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, files = line.split(":", 1)
        files = files.split()
        payloads = [open(os.path.join(dat_dir, f), "rb").read() for f in files]
        out = os.path.join(work, "synthetic", name + ".pcap")
        write_pcap(out, payloads)
        cases.append({"case": f"logstash/{name}", "source": "logstash", "vendor": vendor_of(name),
                      "pcap": out, "inputs": files, "repo": "logstash-plugins/logstash-codec-netflow"})
    cases.sort(key=lambda c: c["case"])
    with open(os.path.join(work, "cases.json"), "w") as f:
        json.dump(cases, f, indent=1)
    print(f"{len(cases)} cases -> {work}/cases.json")

if __name__ == "__main__":
    main()
