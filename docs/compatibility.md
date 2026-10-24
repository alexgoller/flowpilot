# Flow decoder compatibility

How we check that FlowPilot's NetFlow, IPFIX and sFlow decoders follow the specs and work with real exporters,
what has been checked so far, and what has not. For how to run each test, see [testing.md](testing.md).

Two questions are kept apart throughout:

- **Spec and vendor compatibility:** does FlowPilot decode what real exporters send, the way the RFCs say?
- **Compatibility with the original FlowLink:** does FlowPilot upload the same records as FlowLink 2.0.1-2?

Mostly the answers agree. Where they don't, the original's behaviour was kept on purpose, unless it loses data on
real hardware. In that case it was changed. Both kinds are listed in
[differences-from-flowlink.md](differences-from-flowlink.md).

## The checks

| Check | Question it answers | Where | Status |
|---|---|---|---|
| Unit tests | Does each decoder behave as specified, field by field, on hand-built datagrams? | `src/parsers/*.rs` | Passing |
| Differential test | Same traffic in, same records uploaded as the original? | `tests/e2e/run.sh` | Passing |
| Vendor capture conformance | Does FlowPilot decode real exporters' traffic the same way as an independent decoder? | `tests/conformance/run.sh` | Passing, see results below |
| Fuzzing | Can any datagram crash, hang or exhaust memory? | `fuzz/` | In progress |
| Round-trip property test | Random template + record, encoded and decoded: are the values right? | `tests/decode_roundtrip.rs` | In progress |

The planned release build aborts on any panic, so one bad datagram would stop the whole collector. That is why
crashes get their own check (fuzzing), separate from correctness.

### Differential test against the original

Runs the original binary and FlowPilot side by side in Docker. A UDP fan-out copies every datagram to both, and a mock
PCE stores what each uploads. A synthetic generator sends NetFlow v5, v9 and IPFIX, plus text lines. A pass means the
uploaded records are identical. It covers only the generator's templates, so it says little about other vendors.

### Vendor capture conformance

Replays public captures from real exporters through FlowPilot's decoders (`examples/pcap_decode.rs`, which calls
`parsers::decode_datagram`), and through TShark in a pinned Docker image. Both sides go through the same flow filter
FlowPilot applies before aggregation, then every record is compared field by field.

- **Corpus:** 145 files, 104 cases, about 30 vendors and exporters, from logstash-codec-netflow, elastic/beats,
  pmacct, akvorado and tcpdump. Each file is pinned by commit and SHA-256 in `tests/conformance/corpus.lock`.
  The files are downloaded into `target/` and never committed, because their licences differ;
  `tests/conformance/SOURCES.md` lists them.
- **Classification:** every difference is MATCH, KNOWN QUIRK (with the FlowLink behaviour that explains it), or NEW
  MISMATCH.
  A run fails on any new mismatch.
- **Self-test:** after each run, errors are injected into FlowPilot's output, and the run fails unless the comparison
  reports every one of them. This guards against a comparison that matches everything.

What TShark is and is not used for: it decides the structure (sets, templates, record boundaries). The values
of each record are then read per the RFC, but with FlowPilot's choice of which element feeds which field. A mistake
in that choice, shared by both sides, would not show up.

## Results (2026-10-23)

Vendor captures, after the fixes below:

- 1,744 datagrams. 2,454 of 2,464 reference records are identical on every field. 0 new mismatches, 0 panics.
- The other 10 are known quirks: template keyed without the exporter's port (9), QinQ in sFlow (1).
- Before the ICMP fix: 2,422 of 2,432 identical. The 32 records added on both sides are ICMP flows that carry type
  and code in the destination port; the filter used to drop them on both sides, so they were not compared.
- Before the variable-length fix: 2,402 of 2,431 identical, 29 known quirks (19 of them variable-length fields).
  The reference count changed by one because a Barracuda record now decodes in full and passes the flow filter;
  the original's partial record did not.

| Vendor or exporter | Protocols | Result |
|---|---|---|
| Cisco IOS XE, IOS XR, ASR 1000/9000, ISR, ACI, NBAR, Viptela, WLC | v9, IPFIX | Identical |
| Cisco ASA (NSEL) | v9 | Identical (since the byte-count fix) |
| Cisco, pmacct test captures (MPLS, SRv6, IPv6, options reassignment) | v9, IPFIX | Identical except 9 records after an exporter restart (templates keyed without the exporter's port); 26 ICMPv6 records since the ICMP fix |
| Juniper MX, SRX | v5, v9, IPFIX | Identical |
| MikroTik, Palo Alto, Fortinet FortiGate, Ubiquiti EdgeRouter | v5, v9, IPFIX | Identical |
| VMware vDS, OpenBSD pflow, ipt_NETFLOW, nProbe, softflowd, Streamcore, ipfixprobe | v9, IPFIX | Identical |
| H3C, Huawei | v9, IPFIX | Identical (since the variable-length fix) |
| Citrix NetScaler, CERT YAF, Procera/Sandvine, Barracuda, Ixia, Nokia BRAS | IPFIX | Identical (since the variable-length fix; Procera was 1 of 8 records, and 3 more since the ICMP fix) |
| sFlow v5 agents (Arista, Juniper and others) | sFlow | Identical except QinQ |

## Findings and decisions

Changed from the original (2026-10-22 and 2026-10-23):

| Finding | Effect before | Now |
|---|---|---|
| Byte counts only read from field 1 | Cisco ASA (fields 231/232) and exporters sending only field 85 uploaded 0 bytes; 37 records in the corpus | Field 231, then 85, is used when field 1 is absent |
| Padding after the last template in a template set | Read as another template, which also misreads the sets after it | Skipped. No capture in the corpus pads template sets, so this is covered by unit tests only |
| ICMP type/code in the destination port, 2026-10-23 | Dropped by the filter as ICMP with a port: 39 records in the corpus | For an ICMP record without an ICMP field (32, 139, 176-179), type and code are read from the port (`type*256 + code`, or the bare type below 256) and the port is set to 0; NetFlow v5 too. 32 of the 39 now reach the aggregator and match the reference: Cisco IPFIX in the pmacct captures (26, bare type: ICMPv6 neighbour solicitation/advertisement), an akvorado v9 capture (3, `type*256 + code`: echo request/reply), Procera (3, bare type). The other 7 are Cisco ASA records that carry fields 176/177 (0/0) and another value in the port (0x448d, 0x458d, 0x468d: an ICMP identifier or sequence, not a type); they are kept as sent and still dropped. Not in the corpus: NetFlow v5 ICMP |
| Sets in the last 32 bytes of an IPFIX message, 2026-10-23 | Not parsed; a template there is never learned, so all its data is lost | Every set header that fits is read; fewer than 4 bytes or an all-zero set header end the message without a decode error. 13 more records are decoded in 4 akvorado cases (L2, EoMPLS and SRv6 templates in a small trailing set), as in TShark; all 13 have no IP address and are then dropped by the filter on both sides, so the uploaded records do not change. Small options sets at the end are now seen as well (logged and ignored, as elsewhere) |
| Variable-length fields, 2026-10-23 | The record was sent with only the fields before the variable-length one, and the rest of the message was lost: 19 records in the corpus (NetScaler, YAF, Procera 1 of 8, Barracuda, Ixia, Huawei, H3C, Nokia BRAS) | Decoded per RFC 7011 section 7: the value is skipped and the whole record and the rest of the message are decoded. All 19 now match TShark. A length running past the data set drops the rest of that set as one decode error |

Still as in the original, open for decision:

| Finding | Effect | Severity |
|---|---|---|
| Cisco ASA ICMP with fields 176/177 and a value in the destination port | Dropped by the filter: 7 records in the corpus. The port looks like an ICMP identifier, and the fields say type 0 code 0 | Low |
| Templates keyed by exporter address without its port | After an exporter restart, data can be decoded with the old template | Low to medium |
| sFlow with stacked VLAN tags (QinQ) | No flow | Low |
| Sampling rates (options templates, sFlow) | Not applied; 23 cases carry one | By design for now |
| Biflow reverse counters, NSEL responderOctets (232) | Not read: only one direction's bytes | Planned (bidirectional byte counts) |

### Fuzzing findings

From the fuzz campaigns (`fuzz/`, report 2026-10-22). Reproducers are in `fuzz/regressions/` and
`tests/fuzz_findings.rs`.

| Finding | Effect before | Now |
|---|---|---|
| F1: data set with a length below 4 or past the end of the datagram, with a known template | The last partial record repeats until the wrapped length is used up: about 65 500 records and log lines from one small spoofed datagram, and a parser thread kept busy. Inherited from the original | The datagram ends at that set, one decode error; sets before it are decoded |
| F4: FIRST_SWITCHED (field 22) after a flow start (150/152, 8 bytes) with the sign bit set | Integer overflow: a panic in a debug build, which aborts the process; a wrapped time in release, as in the original | Saturates at the smallest time; values that do not overflow are unchanged |
| Template map growth | No limit: spoofed datagrams of empty templates grow the heap by 22 times their size (200 datagrams: 3.27 million templates, 279 MiB). Inherited from the original | About 32 MiB of templates per store; the template defined longest ago is dropped first and counted in `template_store_evicted`. A flood levels off at 25 MiB of heap (`tests/template_store_growth.rs`); 1000 exporters with 20 templates of 100 fields each fit without eviction |
| F2: every template definition scanned the whole list of data waiting for a template (up to 10 000 entries) | With the list kept full, a datagram of templates cost 60 times more CPU (1.2 s instead of 21 ms). The original is worse: no cap, and the scan holds the lock | Only a template that has data waiting scans the list: 17 ms either way |
| F3: reduced-size field 1 (width 1, 2, 3, 5, 6 or 7) | The data set is dropped (the original crashes) | Unchanged, open for decision |

## Not covered yet

- Not in the corpus: IE 158, IPFIX template withdrawal, NetFlow v7, reduced-size field 1 or 3 in v9, sFlow format-4
  IPv6 data records, IPv6 extension headers inside sampled sFlow headers, padded template sets.
- Data that arrives before its template: TShark doesn't decode it, and old captures never replay because the 120-second
  window is measured against the exporter's clock.
- Live exporters. The next steps are software exporters in Docker (softflowd, pmacct, YAF, Open vSwitch,
  ipt_NETFLOW, hsflowd), then free virtual appliances (MikroTik CHR, VyOS, OPNsense), then licensed ones
  (Cisco Cat8000v, Juniper vSRX, Arista cEOS, Palo Alto VM-Series, FortiGate VM).
- Field data: logging each new template (exporter, template id, field list) would turn a customer's report into a
  test fixture.
