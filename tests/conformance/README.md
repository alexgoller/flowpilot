# Decoder conformance harness

Replays public captures from real NetFlow v5/v9, IPFIX and sFlow exporters through FlowPilot's
decoders and compares every record with an independent decoder, tshark. The goal is to find
decoding errors that hand-built unit-test datagrams miss.

## Run

```
tests/conformance/run.sh            # needs Docker, Python 3, network on the first run
tests/conformance/run.sh --fp-only  # after a parser change: reuse tshark's output
```

Set `DOCKER=/path/to/docker` if `docker` is not on `PATH`. The script:

1. `fetch_corpus.sh` downloads the corpus listed in `corpus.lock` (pinned commits, SHA-256 checked)
   into `target/conformance/corpus/`. Sources and licences: [SOURCES.md](SOURCES.md). The files are
   never committed.
2. Builds the tshark image (`tshark.Dockerfile`, Debian trixie) and `examples/pcap_decode.rs`.
3. `prepare.py` lists the cases: each capture, plus each line of `dat_sequences.txt` (raw `.dat`
   payloads wrapped into a synthetic pcap so both decoders read the same bytes).
4. `run_decoders.py` runs `pcap_decode` once per case (a crash only affects that case) and tshark
   (`-T pdml`) in one container. The parser is chosen as a deployment would: by default port (2055,
   4739, 6343), otherwise by version; tshark gets matching `-d udp.port==N,cflow|sflow` rules.
5. `compare.py` writes `target/conformance/report.md` and `results.json`.
6. `selftest.py` injects errors into FlowPilot's output (wrong IP, port, protocol, bytes, time,
   masks, MAC, a dropped record) and checks that every one is reported as a new mismatch. The run
   fails if the comparison misses one.

`pcap_decode` also works on its own:
`cargo run --release --example pcap_decode -- --out recs.jsonl capture.pcap` (or a sequence of
`.dat` payloads). It prints decoder log lines on stdout and writes one JSON line per record (all
`FlowData` fields, plus datagram and frame number) and a summary line to `--out`.

## How the reference is built

tshark does the structural work: headers, set and template walking, template state across packets
(scoped to the transport session), record boundaries, IP reassembly, and the dissection of sFlow
sampled headers. `reference.py` maps that onto the record FlowPilot should produce:

- NetFlow v9 / IPFIX: each data record's bytes are split with the template tshark used, and each
  information element is read per RFC 7011/7012 (any length, reduced-size encoding, variable
  length). FlowLink's choices on top are applied: which IE feeds which field (IE 1 for bytes, else 231, else 85),
  `flows` default 1, direction default 2, the NAT duplicate record, the flow-time rules
  (docs/collectors.md), and ICMP type/code taken from the destination port when the record has no
  ICMP field (a FlowPilot fix, docs/differences-from-flowlink.md; `type*256 + code`, or the bare type
  below 256).
- NetFlow v5/v7: the fixed record layout, FlowLink's time rule and the same ICMP rule.
- sFlow: one record per sampled packet header (format 1) and per IPv4/IPv6 data record (formats
  3/4), with fields from tshark's dissection of the sampled header.
- Both sides then go through the same flow filter and direction normalisation
  (`src/flow.rs` `check_flow`), so the comparison covers what reaches the aggregator.

Two places where the harness reads bytes itself: data sets with a variable-length field (tshark
sizes those record items without the variable part) and datagrams where tshark raised an exception
part-way (the rest is walked by `fallback_sets`; such records are marked `fallback`).

## Reading the report

Records are paired per datagram: on all fields, then on the 5-tuple, then in order. Each case gets
one result:

| Result | Meaning |
|---|---|
| MATCH | Every record is identical on both sides. |
| KNOWN QUIRK | Every difference is explained by documented FlowLink behaviour (docs/differences-from-flowlink.md, docs/compatibility.md); the rule is listed per case. |
| NEW MISMATCH | A difference no rule explains: a finding to triage. Examples with field-level diffs and the decoding context are listed. |
| REFERENCE INCOMPLETE | tshark could not fully dissect the datagram; not a FlowPilot finding. |
| NO FLOWS | Both sides drop every record (no IPs, multicast, ICMP with a port, ...); the pre-filter column still compares how many records each side decoded. |

The "Pre-filter FP/ref" column compares FlowPilot's meter (records decoded before the filter) with
the reference count, adjusted for records a known quirk keeps FlowPilot from decoding; a difference
there is reported as a new mismatch. sFlow `flow_time` (collector clock) and `seq_id` are not
compared.

Not covered: data that arrives before its template. tshark (single pass) does not decode it, and
FlowPilot only replays it within 120 seconds of the exporter's clock, so old captures never replay.
