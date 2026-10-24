//! One input = one datagram on the IPFIX parser (v10, v9 misdirected).
#![no_main]
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|data: &[u8]| -> Corpus {
    flowpilot_fuzz::decode_sequence("ipfix", &[data]);
    flowpilot_fuzz::cross_parser(data);
    flowpilot_fuzz::verdict()
});
