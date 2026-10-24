//! Stats overhead check (design goal: counting on the
//! per-flow path is atomics only, per-exporter updates once per datagram).
//!
//! ```text
//! cargo run --release --example decode_bench [-- ITERATIONS]
//! ```
//!
//! Decodes a fixed set of datagrams, one NetFlow v9 and one IPFIX data message of 10 records each (templates are
//! learned once up front; the record layouts are the unit tests' `T9` and `T1`), ITERATIONS times (default
//! 1 000 000) through `decode_datagram`, once with registered `CollectorStats` and once with
//! `CollectorStats::default()`, and prints flows per second for both. Counting is always on, so both runs count;
//! the baseline without stats is the same loop built on the commit before the counters were added.
//!
//! Not shipped: this is an example, built only for the measurement.

use std::sync::Arc;
use std::time::Instant;

use flowpilot::flow::FlowSink;
use flowpilot::metrics::Meter;
use flowpilot::parsers::{decode_datagram, ParserContext, ReceivedDatagram};
use flowpilot::stats::{register_collector, CollectorStats};

/// Records per data message.
const RECORDS: usize = 10;

#[derive(Default)]
struct B(Vec<u8>);

impl B {
    fn u8(mut self, v: u8) -> Self {
        self.0.push(v);
        self
    }
    fn u16(mut self, v: u16) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u64(mut self, v: u64) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn bytes(mut self, v: &[u8]) -> Self {
        self.0.extend_from_slice(v);
        self
    }
}

/// A set (or v9 FlowSet): header with Length = body + 4.
fn set(id: u16, body: &[u8]) -> Vec<u8> {
    B::default().u16(id).u16(body.len() as u16 + 4).bytes(body).0
}

/// One template record: template id and field count, then (id, len) pairs.
fn tmpl(tid: u16, fields: &[(u16, u16)]) -> Vec<u8> {
    fields.iter().fold(B::default().u16(tid).u16(fields.len() as u16), |b, &(i, l)| b.u16(i).u16(l)).0
}

/// NetFlow v9: 8 fields, 27-byte records (the unit tests' `T9`).
const T9: &[(u16, u16)] = &[(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (22, 4), (2, 4)];
/// IPFIX: 10 fields, 38-byte records (the unit tests' `T1`).
const T1: &[(u16, u16)] = &[(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 8), (56, 6), (57, 6), (61, 1), (150, 4)];

fn v9_message(sets: &[Vec<u8>], count: u16) -> Vec<u8> {
    let b = B::default().u16(9).u16(count).u32(10_000).u32(1_700_000_000).u32(11).u32(3);
    sets.iter().fold(b, |b, s| b.bytes(s)).0
}

fn ipfix_message(sets: &[Vec<u8>]) -> Vec<u8> {
    let body = sets.concat();
    B::default().u16(10).u16(16 + body.len() as u16).u32(1_700_000_000).u32(7).u32(1).bytes(&body).0
}

fn v9_records() -> Vec<u8> {
    (0..RECORDS as u8)
        .flat_map(|i| {
            B::default().bytes(&[10, 4, 0, i + 1]).bytes(&[10, 4, 1, i + 1]).u16(50000).u16(443).u8(17).u32(900).u32(4_000).u32(3).0
        })
        .collect()
}

fn ipfix_records() -> Vec<u8> {
    (0..RECORDS as u8)
        .flat_map(|i| {
            B::default()
                .bytes(&[10, 1, 0, i + 1])
                .bytes(&[10, 1, 1, i + 1])
                .u16(50000)
                .u16(443)
                .u8(6)
                .u64(1000)
                .bytes(&[0x00, 0x1b, 0x21, 0xaa, 0xbb, 0xcc])
                .bytes(&[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
                .u8(1)
                .u32(1_700_000_000)
                .0
        })
        .collect()
}

fn pd(dev: &str, buf: Vec<u8>) -> ReceivedDatagram {
    ReceivedDatagram { device_addr: dev.into(), seq_id: String::new(), transport: "udp".into(), buf }
}

/// Flows per second over `iterations` passes of the datagram set.
fn run(label: &str, netflow: Arc<CollectorStats>, ipfix: Arc<CollectorStats>, iterations: u64) -> f64 {
    let (tx, rx) = crossbeam_channel::unbounded();
    let nf = ParserContext::new(Meter::new(), FlowSink::new(tx.clone()), netflow);
    let ix = ParserContext::new(Meter::new(), FlowSink::new(tx), ipfix);
    // Each run has its own exporters, so it learns its templates once here, outside the timing.
    let (nf_dev, ix_dev) = (format!("192.0.2.1|{label}"), format!("192.0.2.2|{label}"));
    decode_datagram("netflow", &pd(&nf_dev, v9_message(&[set(0, &tmpl(256, T9))], 1)), &nf);
    decode_datagram("ipfix", &pd(&ix_dev, ipfix_message(&[set(2, &tmpl(256, T1))])), &ix);
    let set_v9 = pd(&nf_dev, v9_message(&[set(256, &v9_records())], RECORDS as u16));
    let set_ipfix = pd(&ix_dev, ipfix_message(&[set(256, &ipfix_records())]));

    let start = Instant::now();
    let mut flows = 0u64;
    for _ in 0..iterations {
        decode_datagram("netflow", &set_v9, &nf);
        decode_datagram("ipfix", &set_ipfix, &ix);
        flows += rx.try_iter().count() as u64;
    }
    let secs = start.elapsed().as_secs_f64();
    assert_eq!(flows, iterations * 2 * RECORDS as u64, "{label}: every record must be forwarded");
    let rate = flows as f64 / secs;
    println!("{label:<12} {flows} flows in {secs:.3} s = {rate:.0} flows/s");
    rate
}

fn main() {
    let iterations = std::env::args().nth(1).map_or(1_000_000, |a| a.parse().expect("ITERATIONS must be a number"));
    let registered = run(
        "registered",
        register_collector("netflow", "netflow"),
        register_collector("ipfix", "ipfix"),
        iterations,
    );
    let default = run("default", Arc::default(), Arc::default(), iterations);
    println!("difference   {:+.2}% (registered vs default)", (registered / default - 1.0) * 100.0);
}
