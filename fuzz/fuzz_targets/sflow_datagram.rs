//! One input = one sFlow datagram.
#![no_main]
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|data: &[u8]| -> Corpus {
    flowpilot_fuzz::decode_sequence("sflow", &[data]);
    flowpilot_fuzz::verdict()
});
