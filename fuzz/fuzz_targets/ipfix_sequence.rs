//! One input = several datagrams (`[len u16 BE][bytes]`...) from one exporter on the IPFIX
//! parser, so templates and stored data carry over between them.
#![no_main]
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|data: &[u8]| -> Corpus {
    flowpilot_fuzz::decode_sequence("ipfix", &flowpilot_fuzz::split_sequence(data));
    flowpilot_fuzz::verdict()
});
