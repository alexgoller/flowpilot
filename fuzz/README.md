# Fuzzing the flow decoders

cargo-fuzz (libFuzzer) targets for the NetFlow v5/v7/v9, IPFIX and sFlow decoders. They call
`flowpilot::parsers::decode_datagram`, the same code the collector's parser threads run. This crate
has its own `[workspace]`, so it never affects the main build or `Cargo.lock`.

cargo-fuzz needs nightly Rust. The commands below run everything in Docker, so the host only needs
stable Rust.

## Targets

| Target | Input | Notes |
|---|---|---|
| `netflow_datagram` | one datagram, NetFlow parser | v5/v7/v9, v10 misdirected; also checks that the NetFlow and IPFIX parsers agree on v9/v10 |
| `ipfix_datagram` | one datagram, IPFIX parser | v10, v9 misdirected; same parser-agreement check |
| `sflow_datagram` | one sFlow datagram | |
| `netflow_sequence` | `[len u16 BE][bytes]...`, up to 16 datagrams from one exporter | templates and stored data carry over between them |
| `ipfix_sequence` | same, IPFIX parser | |
| `ipfix_structured` | `arbitrary` bytes → generated IPFIX conversation | valid headers, template sets with random IEs and lengths (incl. 0xFFFF varlen and enterprise bit), then data sets that follow the templates; occasional corrupted lengths |
| `netflow_v9_structured` | same for NetFlow v9 | |
| `sflow_structured` | `arbitrary` bytes → generated sFlow datagram | Ethernet/802.1Q/IPv4/IPv6 + extension headers, TCP/UDP/ICMP, all record and sample kinds |

The template stores are process-wide statics that cannot be reset, so each input uses a new device
address (`fz<N>`) and does not see templates from earlier inputs. Besides crashes, hangs and memory
limits, the harness (`src/lib.rs`) checks these oracles:

- every emitted flow passed `check_flow`;
- at most `2 * bytes + 2` flows per input (catches runaway record loops);
- at most `4 * bytes + 64` log lines per input (catches loops that spin without reading input, finding F1).
  `FLOWPILOT_FUZZ_LOG_ORACLE=reject` keeps such inputs out of the corpus without crashing (use it to look past F1);
  `=off` disables the check;
- v9/v10 datagrams decode the same on both parsers.

The parsers log to stdout with no quiet switch. The harness points fd 1 at a temporary file, reads it
back after each input, and defines an empty template for every key the input stashed, so that
PendingSet does not stay at its 10 000-entry cap (before the fix for finding F2, every template
definition scanned the whole list). Set `FLOWPILOT_FUZZ_VERBOSE=1` to see the log instead.

## Running (Docker)

From the repository root:

```sh
docker build -t flowpilot-fuzz fuzz/                       # nightly + cargo-fuzz, once
FUZZ="docker run --rm -v $PWD:/work -w /work \
  -v flowpilot-fuzz-registry:/usr/local/cargo/registry -v flowpilot-fuzz-target:/target flowpilot-fuzz"

$FUZZ cargo fuzz list
$FUZZ fuzz/run.sh ipfix_structured 600 2                   # target, seconds, fork jobs
```

`fuzz/run.sh` runs in fork mode with `-ignore_crashes/-ignore_timeouts/-ignore_ooms`, so one finding
does not stop the run. Limits: `-rss_limit_mb=1024 -malloc_limit_mb=512 -timeout=10 -max_len=8192`. It
writes the corpus to `fuzz/corpus/<target>/` (seeded from `fuzz/seeds/<target>/`), crashes to
`fuzz/artifacts/<target>/` and the libFuzzer log to `fuzz/logs/<target>.log`. Build output goes to the
`flowpilot-fuzz-target` volume, not to `target/`.

The default build is optimized with debug assertions, overflow checks and AddressSanitizer, so an
integer overflow counts as a crash even though release builds wrap. Add `-O` as the fourth argument of
`run.sh` to fuzz with release arithmetic, or `-s none` to drop ASan (about twice as fast; the decoders
have no `unsafe` code).

To run every target at once, use one container per target with `docker run -d --name fz-<target> ...`.

## Reproducing and minimizing

```sh
$FUZZ cargo fuzz run --target-dir /target ipfix_datagram fuzz/regressions/ipfix_datagram/<file>
$FUZZ cargo fuzz tmin --target-dir /target ipfix_datagram fuzz/artifacts/ipfix_datagram/<crash-file>
$FUZZ sh -c 'FLOWPILOT_FUZZ_VERBOSE=1 cargo fuzz run --target-dir /target ipfix_datagram <file>'
```

`fuzz/regressions/<target>/` holds the minimized reproducers of the findings (our own bytes). Each one
is also a hand-written test in `tests/fuzz_findings.rs`; an open finding's test is marked
`#[ignore = "finding F<n>: ..."]`. F1, F2 and F4 and the template-map growth are fixed (see
[docs/compatibility.md](../docs/compatibility.md#fuzzing-findings)); F3 (reduced-size field 1) is open
for decision.

## Seeds

`fuzz/seeds/` is generated from the packet shapes of the parser unit tests (`src/seeds.rs`), with no
third-party captures. Regenerate it with:

```sh
$FUZZ sh -c 'cd fuzz && CARGO_TARGET_DIR=/target/test cargo test --lib -- --ignored write_seeds'
```

`cargo test --lib` in this crate also checks that every seed decodes to at least one flow, and the
variable-length seeds (`*varlen*`, IPFIX and v9) to both of their records.

## Related tests in the main crate

- `tests/decode_roundtrip.rs`: stable-Rust property test. Random IPFIX/v9 templates and records with
  known values go through `decode_datagram`, and the result is compared with a model of the documented
  behaviour, including the flow filter and the FlowLink behaviour it keeps.
- `tests/template_store_growth.rs`: asserts the template-map memory cap and that templates without
  waiting data skip the PendingSet scan (F2); its ignored tests measure memory and CPU for
  template-store and PendingSet growth.
  `cargo test --release --test template_store_growth -- --ignored --nocapture --test-threads=1`
