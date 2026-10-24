//! Hand-written reproducers for the fuzzing findings (fuzz/README.md; minimized fuzz inputs are
//! in fuzz/regressions/). Each test asserts the behaviour we want; a finding that is still open
//! is `#[ignore]`d with its number (run those with `cargo test --test fuzz_findings -- --ignored`).

use std::panic::{catch_unwind, AssertUnwindSafe};

use crossbeam_channel::{unbounded, Receiver};
use flowpilot::flow::{FlowData, FlowSink};
use flowpilot::metrics::Meter;
use flowpilot::parsers::{decode_datagram, ParserContext, ReceivedDatagram};

fn decode(kind: &str, dev: &str, buf: Vec<u8>) -> (Vec<FlowData>, i64) {
    let (tx, rx): (_, Receiver<FlowData>) = unbounded();
    let ctx = ParserContext::new(Meter::new(), FlowSink::new(tx), Default::default());
    let pd = ReceivedDatagram { device_addr: dev.into(), seq_id: String::new(), transport: "udp".into(), buf };
    decode_datagram(kind, &pd, &ctx);
    (rx.try_iter().collect(), ctx.meter.count())
}

fn be(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn u16b(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

fn u32b(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// F1 (hang-like CPU and log amplification): a data set whose Length is below 4 wraps
/// `data_len` to ~65 532, and when the reader holds fewer bytes than the next
/// template field, decode_data_set's "Not enough data" branch advances `offset` by the bytes left
/// without reading them. The empty-record guard only stops a record that moved neither `offset` nor the
/// reader, so with 1 byte left the loop ran ~65 500 times, logging a line and "sending" an empty
/// record each time: a 65-byte datagram cost ~60 ms of CPU, ~5 MB of stdout log and a meter mark
/// of ~65 500. Fixed: such a set ends the datagram (`malformed_data_set`).
#[test]
fn short_tail_in_wrapped_data_set_does_not_spin() {
    let tmpl = be(&[&u16b(256), &u16b(1), &u16b(27), &u16b(16)]); // one sourceIPv6Address field
    let msg_body = be(&[
        &u16b(2),
        &u16b(4 + tmpl.len() as u16),
        &tmpl,
        &u16b(256),
        &u16b(0), // data set Length 0 -> data_len 65532
        &[0x20; 33], // two 16-byte records and 1 byte left over
    ]);
    let msg = be(&[&u16b(10), &u16b(16 + msg_body.len() as u16), &u32b(1_700_000_000), &u32b(1), &u32b(0), &msg_body]);
    let n = msg.len() as i64;
    let (_, marked) = decode("ipfix", "f1.ipfix", msg);
    assert!(marked <= n, "{marked} records metered from a {n}-byte datagram");

    // NetFlow v9 takes the same path (no 32-byte cut-off there).
    let tmpl = be(&[&u16b(256), &u16b(1), &u16b(8), &u16b(4)]);
    let v9 = be(&[
        &u16b(9),
        &u16b(2),
        &u32b(10_000),
        &u32b(1_700_000_000),
        &u32b(1),
        &u32b(0),
        &u16b(0),
        &u16b(4 + tmpl.len() as u16),
        &tmpl,
        &u16b(256),
        &u16b(0),
        &[10, 0, 0, 1, 10],
    ]);
    let n = v9.len() as i64;
    let (_, marked) = decode("netflow", "f1.v9", v9);
    assert!(marked <= n, "{marked} records metered from a {n}-byte datagram");

    // Flow-amplification variant: when the template carries both addresses, every spin emits a
    // flow that passes check_flow, so the record loop both hangs on CPU and floods the sink
    // (fuzz/regressions/ipfix_structured/f1-hang-flow-amplification is this, caught as a
    // libFuzzer timeout). A legitimate datagram yields at most ~2 flows per record.
    let tmpl = be(&[&u16b(256), &u16b(2), &u16b(8), &u16b(4), &u16b(12), &u16b(4)]);
    let msg_body = be(&[&u16b(2), &u16b(4 + tmpl.len() as u16), &tmpl, &u16b(256), &u16b(0), &[10, 0, 0, 1, 10, 0, 0, 2, 9]]);
    let msg = be(&[&u16b(10), &u16b(16 + msg_body.len() as u16), &u32b(1_700_000_000), &u32b(1), &u32b(0), &msg_body]);
    let n = msg.len();
    let (flows, _) = decode("ipfix", "f1.flood", msg);
    assert!(flows.len() <= 2 * n + 2, "{} flows from a {n}-byte datagram", flows.len());
}

/// F4 (debug-build overflow panic; wraps in release): flowStartSeconds/-Milliseconds with
/// length 8 is read as a signed i64, so a value with the top bit set makes
/// flow time hugely negative; a later FIRST_SWITCHED (IE 22) then subtracts from it with
/// `-=`: "attempt to subtract with overflow" in debug builds. In release the flow time wrapped to
/// ~i64::MAX (garbage, but no crash). Fixed: the subtraction saturates at i64::MIN.
#[test]
fn negative_flow_start_then_first_switched_does_not_panic() {
    let fields: &[(u16, u16)] = &[(8, 4), (12, 4), (150, 8), (22, 4)];
    let tmpl: Vec<u8> = [256u16, fields.len() as u16].iter().chain(fields.iter().flat_map(|(a, b)| [a, b])).flat_map(|x| x.to_be_bytes()).collect();
    let uptime = 100_000u32;
    let rec = be(&[&[10, 0, 0, 1], &[10, 0, 0, 2], &(1u64 << 63).to_be_bytes(), &u32b(uptime - 5_000)]);
    let v9 = be(&[
        &u16b(9),
        &u16b(2),
        &u32b(uptime),
        &u32b(1_700_000_000),
        &u32b(1),
        &u32b(0),
        &u16b(0),
        &u16b(4 + tmpl.len() as u16),
        &tmpl,
        &u16b(256),
        &u16b(4 + rec.len() as u16),
        &rec,
    ]);
    let r = catch_unwind(AssertUnwindSafe(|| decode("netflow", "f4.v9", v9)));
    assert!(r.is_ok(), "decoder panicked");
}
