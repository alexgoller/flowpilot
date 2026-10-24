//! Structure-aware: a generated NetFlow v9 conversation (templates, then data that follows
//! them), decoded by the NetFlow or (misdirected) by the IPFIX parser.
#![no_main]
use arbitrary::Unstructured;
use flowpilot_fuzz::gen::{template_sequence, Flavor};
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|data: &[u8]| -> Corpus {
    let mut u = Unstructured::new(data);
    let kind = if u.ratio(1, 4u8).unwrap_or(false) { "ipfix" } else { "netflow" };
    let Ok(msgs) = template_sequence(&mut u, Flavor::V9) else { return Corpus::Keep };
    let refs: Vec<&[u8]> = msgs.iter().map(Vec::as_slice).collect();
    flowpilot_fuzz::decode_sequence(kind, &refs);
    if let Some(m) = msgs.first() {
        flowpilot_fuzz::cross_parser(m);
    }
    flowpilot_fuzz::verdict()
});
