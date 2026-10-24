//! Seed corpus built from the unit-test packet shapes (our own bytes, no third-party captures).
//! Regenerate fuzz/seeds/ with `cargo test --manifest-path fuzz/Cargo.toml -- --ignored write_seeds`.

use crate::gen::*;
use crate::join_sequence;

/// The IPFIX unit tests' 10-field template (38-byte records).
const T1: &[(u16, u16)] = &[(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 8), (56, 6), (57, 6), (61, 1), (150, 4)];
/// The NetFlow unit tests' 8-field v9 template (27-byte records).
const T9: &[(u16, u16)] = &[(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (22, 4), (2, 4)];
/// IPv6, ICMP, NAT and timestamp IEs.
const T6: &[(u16, u16)] =
    &[(27, 16), (28, 16), (4, 1), (176, 1), (177, 1), (225, 4), (226, 4), (227, 2), (228, 2), (152, 8), (158, 4)];

fn t1_record(a: u8) -> Vec<u8> {
    B::default()
        .bytes(&[10, 1, 0, a])
        .bytes(&[10, 1, 0, 2])
        .u16(50000)
        .u16(443)
        .u8(6)
        .u64(1000)
        .bytes(&[0x00, 0x1b, 0x21, 0xaa, 0xbb, 0xcc])
        .bytes(&[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
        .u8(1)
        .u32(1_700_000_000)
        .0
}

fn t9_record(a: u8) -> Vec<u8> {
    B::default().bytes(&[10, 4, 0, a]).bytes(&[10, 4, 0, 2]).u16(50000).u16(443).u8(17).u32(900).u32(4000).u32(3).0
}

fn t6_record() -> Vec<u8> {
    let mut src = [0u8; 16];
    src[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    src[15] = 1;
    let mut dst = src;
    dst[15] = 2;
    B::default()
        .bytes(&src)
        .bytes(&dst)
        .u8(58)
        .u8(128)
        .u8(0)
        .bytes(&[192, 0, 2, 10])
        .bytes(&[198, 51, 100, 7])
        .u16(1)
        .u16(8080)
        .u64(1_700_000_000_123)
        .u32(5_000_000)
        .0
}

fn ipfix_tmpl_and_data() -> Vec<u8> {
    ipfix_msg(1_600_000_000, 7, 1, &[set(2, &tmpl(256, T1)), set(256, &t1_record(1))])
}

fn ipfix_enterprise() -> Vec<u8> {
    let t = B::default().u16(256).u16(3).u16(8).u16(4).u16(0x8001).u16(4).u32(9).u16(12).u16(4).0;
    let rec = B::default().bytes(&[10, 1, 0, 7]).u32(0xdead_beef).bytes(&[10, 1, 0, 8]).0;
    ipfix_msg(1_600_000_000, 5, 0, &[set(3, &[0xee; 20]), set(2, &t), set(256, &[rec.clone(), rec.clone(), rec].concat())])
}

fn ipfix_varlen() -> Vec<u8> {
    let t = tmpl(300, &[(8, 4), (12, 4), (100, 0xffff), (7, 2)]);
    let rec = B::default().bytes(&[10, 1, 0, 1]).bytes(&[10, 1, 0, 2]).u8(3).bytes(b"abc").u16(80).0;
    ipfix_msg(1_600_000_000, 1, 0, &[set(2, &t), set(300, &[rec.clone(), rec].concat()), set(4, &[0; 32])])
}

/// Long (255 + u16) and empty variable-length values, an enterprise one, and set padding.
fn ipfix_varlen_long() -> Vec<u8> {
    // 8, enterprise 100 (PEN 9, variable), 12, 82 (variable)
    let t = B::default().u16(301).u16(4).u16(8).u16(4).u16(0x8064).u16(0xffff).u32(9).u16(12).u16(4).u16(82).u16(0xffff);
    let rec = |a: u8, n: u16| {
        B::default().bytes(&[10, 1, 1, a]).u8(255).u16(n).bytes(&vec![0x41; n.into()]).bytes(&[10, 1, 1, 9]).u8(0).0
    };
    ipfix_msg(1_600_000_000, 2, 0, &[set(2, &t.0), set(301, &[rec(1, 300), rec(2, 3), vec![0; 3]].concat()), set(4, &[0; 32])])
}

/// H3C NetStream style: a v9 template with a variable-length interface name.
fn v9_varlen() -> Vec<u8> {
    let t = tmpl(260, &[(8, 4), (12, 4), (82, 0xffff), (7, 2), (4, 1)]);
    let rec = |a: u8, name: &[u8]| {
        B::default().bytes(&[10, 4, 1, a]).bytes(&[10, 4, 1, 2]).u8(name.len() as u8).bytes(name).u16(53).u8(17).0
    };
    v9_msg(2, 10_000, 1_700_000_000, 3, 0, &[set(0, &t), set(260, &[rec(1, b"GigabitEthernet1/0/1"), rec(2, b"")].concat())])
}

fn ipfix_v6_nat() -> Vec<u8> {
    ipfix_msg(1_600_000_000, 9, 2, &[set(2, &tmpl(257, T6)), set(257, &t6_record()), set(4, &[0; 32])])
}

fn v9_tmpl_and_data() -> Vec<u8> {
    v9_msg(2, 10_000, 1_700_000_000, 11, 3, &[set(0, &tmpl(256, T9)), set(256, &[t9_record(1), vec![0, 0]].concat())])
}

fn v9_options() -> Vec<u8> {
    v9_msg(
        4,
        10_000,
        1_700_000_000,
        1,
        0,
        &[set(1, &[0xab; 12]), set(77, &[0xcd; 4]), set(0, &tmpl(256, T9)), set(256, &t9_record(3))],
    )
}

fn v5() -> Vec<u8> {
    v5_header(5, 2, 100_000, 1_700_000_000, 2_500_000_000, 42)
        .bytes(&v5_record([10, 2, 0, 1], [10, 2, 0, 2], 40_000).0)
        .bytes(&v5_record([10, 2, 0, 3], [10, 2, 0, 4], 200_000).0)
        .0
}

fn v7() -> Vec<u8> {
    let rec = |a| v5_record([10, 2, 2, a], [10, 2, 2, 9], 100_000).u32(0xdead_beef).0;
    v5_header(7, 2, 100_000, 1_700_000_000, 0, 42).bytes(&rec(1)).bytes(&rec(2)).0
}

fn sflow_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let v4a = [10, 0, 0, 1];
    let v4b = [10, 0, 0, 2];
    let mut s6 = [0u8; 16];
    s6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    let mut d6 = s6;
    (s6[15], d6[15]) = (1, 2);
    let agent4 = [192, 0, 2, 1];
    let tcp_pkt = [eth(0x0800), ipv4(6, v4a, v4b), tcp(50000, 443), vec![1, 2, 3]].concat();
    let vlan_udp = [eth(0x8100), vec![0x00, 0x0a, 0x08, 0x00], ipv4(17, v4a, v4b), udp(40000, 53)].concat();
    let v6_frag = [eth(0x86dd), ipv6(44, s6, d6), vec![17, 0, 0, 0, 0, 0, 0, 1], udp(40000, 53)].concat();
    let v6_rh = [eth(0x86dd), ipv6(43, s6, d6), vec![17, 1, 0x9c, 0x40, 0, 0x35, 0, 0], tcp(1, 2)].concat();
    let icmp = [ipv4(1, v4b, v4a), vec![8, 0, 0, 0, 0, 0, 0, 0]].concat();
    vec![
        ("eth_ipv4_tcp", sflow_datagram(1, &agent4, &[flow_sample(1, &[raw(1, &tcp_pkt)])])),
        ("v6agent_expanded_vlan_udp", sflow_datagram(2, &s6, &[flow_sample(3, &[raw(1, &vlan_udp)])])),
        ("ipv6_ext_headers", sflow_datagram(1, &agent4, &[flow_sample(1, &[raw(1, &v6_frag), raw(1, &v6_rh)])])),
        (
            "records_and_counters",
            sflow_datagram(
                1,
                &agent4,
                &[
                    counter_sample(),
                    flow_sample(
                        1,
                        &[
                            eth_record([0, 0x1b, 0x21, 0xaa, 0xbb, 0xcc], [2, 0, 0, 0, 0, 1]),
                            ipv4_record(17, v4a, v4b, 50000, 53),
                            raw(11, &icmp),
                            u32s(&[1001, 16, 10, 0, 20, 0]),
                            u32s(&[1002, 16, 1, 0x0a00_0001, 24, 24]),
                        ],
                    ),
                ],
            ),
        ),
    ]
}

/// `(target, name, bytes)` for every seed.
pub fn all() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    let mut out = Vec::new();
    let nf = [
        ("v5", v5()),
        ("v7", v7()),
        ("v9_template_data", v9_tmpl_and_data()),
        ("v9_options", v9_options()),
        ("v9_varlen", v9_varlen()),
    ];
    let ipfix = [
        ("ipfix_template_data", ipfix_tmpl_and_data()),
        ("ipfix_enterprise_options", ipfix_enterprise()),
        ("ipfix_varlen", ipfix_varlen()),
        ("ipfix_varlen_long", ipfix_varlen_long()),
        ("ipfix_v6_nat", ipfix_v6_nat()),
    ];
    for (n, b) in nf.iter().chain(&ipfix) {
        out.push(("netflow_datagram", *n, b.clone()));
        out.push(("ipfix_datagram", *n, b.clone()));
    }
    // Data before template (PendingSet replay), then template-then-data across datagrams.
    let now = now_secs();
    let v9_data = v9_msg(1, 20_000, now, 5, 0, &[set(256, &t9_record(1))]);
    let v9_tmpl = v9_msg(1, 99_000, now, 6, 0, &[set(0, &tmpl(256, T9))]);
    let ipfix_data = ipfix_msg(now, 3, 9, &[set(300, &t1_record(3))]);
    let ipfix_tmpl = ipfix_msg(now, 4, 9, &[set(2, &tmpl(300, T1)), set(4, &[0; 32])]);
    let ipfix_more = ipfix_msg(now, 5, 9, &[set(300, &[t1_record(5), t1_record(6)].concat())]);
    for t in ["netflow_sequence", "ipfix_sequence"] {
        out.push((t, "v9_data_then_template", join_sequence(&[v9_data.clone(), v9_tmpl.clone()])));
        out.push((t, "ipfix_data_template_data", join_sequence(&[ipfix_data.clone(), ipfix_tmpl.clone(), ipfix_more.clone()])));
        out.push((t, "v5_then_v9", join_sequence(&[v5(), v9_tmpl_and_data()])));
    }
    for (n, b) in sflow_seeds() {
        out.push(("sflow_datagram", n, b));
    }
    for t in ["ipfix_structured", "netflow_v9_structured", "sflow_structured"] {
        out.push((t, "zeros", vec![0; 256]));
        out.push((t, "ones", vec![0xff; 256]));
        out.push((t, "ramp", (0..=255u8).cycle().take(1024).collect()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "writes fuzz/seeds/; run explicitly"]
    fn write_seeds() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds");
        for (target, name, bytes) in all() {
            let dir = root.join(target);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(name), bytes).unwrap();
        }
    }

    #[test]
    fn seeds_decode_and_emit_flows() {
        for (target, name, bytes) in all() {
            let kind = target.split('_').next().unwrap();
            let flows = match target {
                t if t.ends_with("_sequence") => {
                    crate::decode_sequence(kind, &crate::split_sequence(&bytes))
                }
                t if t.ends_with("_structured") => continue,
                _ => crate::decode_sequence(kind, &[&bytes]),
            };
            let v5_on_ipfix = target == "ipfix_datagram" && matches!(name, "v5" | "v7");
            assert!(flows > 0 || v5_on_ipfix, "{target}/{name} emitted no flows");
            if name.contains("varlen") {
                assert_eq!(flows, 2, "{target}/{name}: both records with variable-length fields");
            }
        }
    }
}
