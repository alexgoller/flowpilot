//! One input = one datagram on the NetFlow parser (v5/v7/v9, v10 misdirected).
#![no_main]
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|data: &[u8]| -> Corpus {
    flowpilot_fuzz::decode_sequence("netflow", &[data]);
    flowpilot_fuzz::cross_parser(data);
    flowpilot_fuzz::verdict()
});
