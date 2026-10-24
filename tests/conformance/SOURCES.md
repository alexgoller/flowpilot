# Conformance corpus sources

The corpus is third-party data. `fetch_corpus.sh` downloads it into `target/conformance/corpus/`
(not committed) from the commits pinned in `corpus.lock`, and checks every file's SHA-256. Nothing
from it is redistributed: it is used locally as test input only. Do not copy these files into the
repository.

| Source id | Repository | Commit | Files | Licence | What is in it |
|---|---|---|---|---|---|
| `logstash` | [logstash-plugins/logstash-codec-netflow](https://github.com/logstash-plugins/logstash-codec-netflow) | `c3834617fc5d5f3332eb28ff776507c8acc53747` | `spec/codecs/*.dat` (92) | Apache-2.0 | One raw UDP payload per file, captured from real exporters: Cisco ASA (NSEL), ASR 1000/9000, NBAR, WLC, ISR, ACI, Viptela; Juniper MX/SRX; Palo Alto; FortiGate; MikroTik; Ubiquiti; VMware vDS; Citrix NetScaler; Barracuda; nProbe; softflowd; ipt_NETFLOW; H3C; Huawei; Nokia; Procera/Sandvine; YAF; OpenBSD pflow; Ixia; Streamcore. `dat_sequences.txt` groups them into replay sequences (template file before data file). |
| `beats` | [elastic/beats](https://github.com/elastic/beats) | `60a0754b21c4a96926bba0a8e2ac63c9ed24e6bb` | `x-pack/filebeat/input/netflow/testdata/pcap/*.pcap`, `.../integration/test.pcap` (5) | Elastic License 2.0 (x-pack folder) | Cisco IPFIX (also in reversed order), Ubiquiti NetFlow v9, IPFIX with 4/7-byte set padding. Elastic License: local testing only, no redistribution. |
| `pmacct` | [pmacct/pmacct](https://github.com/pmacct/pmacct) | `b3efe37f9ed6867501515568078060e15ad715d6` | `tests/1xx-*/traffic-*.pcap`, `tests/401-*`, `tests/500-*`, `tests/501-*` (16) | GPL-2.0-or-later (parts ISC) | Cisco and Huawei IPFIX and NetFlow v9, sampling options, options template id reassignment, IPv6, MPLS, SRv6, multiple exporters. |
| `akvorado` | [akvorado/akvorado](https://github.com/akvorado/akvorado) | `f17c4e4dbbd537f27f4cd356c9751f93e3b60aa1` | `outlet/flow/decoder/{netflow,sflow}/testdata/*.pcap` (28) | AGPL-3.0 | NetFlow v5/v9 and IPFIX (Cisco IOS XE/XR timestamps, NAT, MPLS, SRv6, sampling, ICMP, Juniper, ipfixprobe, data-link sections) and sFlow (Arista/Juniper style raw headers, expanded samples, IPv4 data records, QinQ, VXLAN, ICMPv4/v6). |
| `tcpdump` | [the-tcpdump-group/tcpdump](https://github.com/the-tcpdump-group/tcpdump) | `f34cf40526e1f6326138fedba2a606d1c2f089f3` | `tests/sflow*.pcap` (4) | BSD-3-Clause | sFlow v5 with IPv6 agents, expanded samples, many counter samples, and a malformed datagram. |

## Looked at, not used

- **Wireshark SampleCaptures** (wiki.wireshark.org, now the GitLab wiki of wireshark/wireshark): the
  wiki has no NetFlow, IPFIX or sFlow captures (checked 2026-10-22 via the GitLab wiki API), and
  `test/captures` in the Wireshark repository has none either.
- **netsampler/goflow2, phaag/nfdump, Edgio/vflow (formerly VerizonDigital/vflow), cloudflare/goflow,
  sflow/sflowtool, CESNET/ipfixcol2, pavel-odintsov/fastnetmon**: no pcap or raw datagram test data in
  their trees at the time of writing.
- The `elastic/beats` `testdata/dat` directory is a copy of the logstash files; the Apache-2.0 originals
  are used instead.

## Updating

Change or add lines in `corpus.lock` (`<source> <owner/repo> <commit> <path> <sha256>`), add the
source here with its licence, and run `fetch_corpus.sh`. For raw `.dat` payloads, add a replay
sequence to `dat_sequences.txt`.
