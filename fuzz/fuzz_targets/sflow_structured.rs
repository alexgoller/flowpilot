//! Structure-aware: a generated sFlow v5 datagram (flow samples with raw Ethernet/IPv4/IPv6
//! headers, extension headers, TCP/UDP/ICMP; counter and unknown samples).
#![no_main]
use arbitrary::Unstructured;
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|data: &[u8]| -> Corpus {
    let mut u = Unstructured::new(data);
    if let Ok(d) = flowpilot_fuzz::gen::sflow(&mut u) {
        flowpilot_fuzz::decode_sequence("sflow", &[&d]);
    }
    flowpilot_fuzz::verdict()
});
