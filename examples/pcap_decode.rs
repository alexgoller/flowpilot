//! Conformance harness helper (tests/conformance): replays captured flow export datagrams through
//! FlowPilot's decoders and writes every emitted `FlowData` as one JSON line.
//!
//! ```text
//! cargo run --example pcap_decode -- --out records.jsonl [--device-prefix NAME] FILE...
//! ```
//!
//! Each FILE is a pcap or pcapng capture (Ethernet, Linux SLL/SLL2, raw IP or BSD loopback link
//! types; IPv4 fragments are reassembled) or, when the name ends in `.dat`, one raw UDP payload.
//! All files are fed in order into the same process, so a `.dat` template file followed by its
//! data file behaves like a capture. The parser is picked per datagram from the payload version
//! (NetFlow v5/v7/v9 → `netflow`, IPFIX v10 → `ipfix`, sFlow v5 → `sflow`).
//!
//! The device address (the template-store key) is `<prefix>|<exporter IP>`, so captures never
//! share templates. Records are tagged with the 1-based datagram number in replay order. Decoder
//! log lines go to stdout; records and a final summary go to `--out`. A panic inside a decoder is
//! caught, written as a `{"type":"panic"}` line, and the run continues; the exit status is then 3.
//!
//! Not shipped: this is an example, built only for the harness.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;

use flowpilot::flow::{FlowData, FlowSink};
use flowpilot::metrics::Meter;
use flowpilot::parsers::{decode_datagram, ParserContext, ReceivedDatagram};
use serde_json::{json, Value};

/// One UDP datagram recovered from the input.
struct Datagram {
    src: IpAddr,
    dst_port: u16,
    payload: Vec<u8>,
}

#[derive(Default)]
struct Stats {
    frames: u64,
    datagrams: u64,
    skipped_non_udp: u64,
    skipped_fragments: u64,
    malformed: u64,
}

// ---------------------------------------------------------------------------------------------
// Capture readers

fn u16_at(b: &[u8], o: usize, le: bool) -> Option<u16> {
    let s: [u8; 2] = b.get(o..o + 2)?.try_into().ok()?;
    Some(if le { u16::from_le_bytes(s) } else { u16::from_be_bytes(s) })
}

fn u32_at(b: &[u8], o: usize, le: bool) -> Option<u32> {
    let s: [u8; 4] = b.get(o..o + 4)?.try_into().ok()?;
    Some(if le { u32::from_le_bytes(s) } else { u32::from_be_bytes(s) })
}

/// Link-layer frames of a pcap or pcapng file as (link type, bytes).
fn read_frames(data: &[u8]) -> Result<Vec<(u32, Vec<u8>)>, String> {
    let magic = u32_at(data, 0, false).ok_or("file too short")?;
    match magic {
        0xa1b2c3d4 | 0xa1b23c4d => read_pcap(data, false),
        0xd4c3b2a1 | 0x4d3cb2a1 => read_pcap(data, true),
        0x0a0d0d0a => read_pcapng(data),
        m => Err(format!("unknown capture magic {m:#010x}")),
    }
}

fn read_pcap(data: &[u8], le: bool) -> Result<Vec<(u32, Vec<u8>)>, String> {
    let link = u32_at(data, 20, le).ok_or("short pcap header")?;
    let mut out = Vec::new();
    let mut o = 24;
    while o + 16 <= data.len() {
        let incl = u32_at(data, o + 8, le).unwrap_or(0) as usize;
        let body = data.get(o + 16..o + 16 + incl).ok_or("truncated pcap record")?;
        out.push((link, body.to_vec()));
        o += 16 + incl;
    }
    Ok(out)
}

fn read_pcapng(data: &[u8]) -> Result<Vec<(u32, Vec<u8>)>, String> {
    let mut out = Vec::new();
    let mut links: Vec<u32> = Vec::new();
    let mut le = true;
    let mut o = 0;
    while o + 12 <= data.len() {
        let btype_raw = u32_at(data, o, false).unwrap_or(0);
        if btype_raw == 0x0a0d0d0a {
            // Section header: byte-order magic decides the endianness of this section.
            le = u32_at(data, o + 8, true) == Some(0x1a2b3c4d);
            links.clear();
        }
        let btype = u32_at(data, o, le).unwrap_or(0);
        let blen = u32_at(data, o + 4, le).unwrap_or(0) as usize;
        if blen < 12 || o + blen > data.len() {
            return Err("truncated pcapng block".into());
        }
        let b = &data[o..o + blen];
        match btype {
            1 => links.push(u32::from(u16_at(b, 8, le).unwrap_or(0))),
            6 => {
                let iface = u32_at(b, 8, le).unwrap_or(0) as usize;
                let cap = u32_at(b, 20, le).unwrap_or(0) as usize;
                let pkt = b.get(28..28 + cap).ok_or("truncated EPB")?;
                out.push((links.get(iface).copied().unwrap_or(1), pkt.to_vec()));
            }
            3 => {
                let pkt = &b[12..blen - 4];
                out.push((links.first().copied().unwrap_or(1), pkt.to_vec()));
            }
            _ => {}
        }
        o += blen;
    }
    Ok(out)
}

/// IPv4 fragment reassembly buffer, keyed on (src, dst, id, protocol).
type FragKey = (Ipv4Addr, Ipv4Addr, u16, u8);

/// Fragments seen so far (offset, bytes) and, once the last fragment arrived, the total length.
#[derive(Default)]
struct Pending {
    frags: Vec<(usize, Vec<u8>)>,
    total: Option<usize>,
}

#[derive(Default)]
struct Reassembly {
    parts: HashMap<FragKey, Pending>,
}

impl Reassembly {
    /// Adds one fragment; returns the full IP payload once every byte is present.
    fn add(&mut self, key: FragKey, off: usize, more: bool, data: &[u8]) -> Option<Vec<u8>> {
        let e = self.parts.entry(key).or_default();
        e.frags.push((off, data.to_vec()));
        if !more {
            e.total = Some(off + data.len());
        }
        let total = e.total?;
        let mut buf = vec![0u8; total];
        let mut have = vec![false; total];
        for (o, d) in &e.frags {
            for (i, &x) in d.iter().enumerate() {
                if let Some(slot) = buf.get_mut(o + i) {
                    *slot = x;
                    have[o + i] = true;
                }
            }
        }
        if have.iter().all(|&h| h) {
            self.parts.remove(&key);
            Some(buf)
        } else {
            None
        }
    }
}

/// Network-layer start of a frame for the given link type, after Ethernet/VLAN/SLL headers.
fn l3(link: u32, f: &[u8]) -> Option<(u16, &[u8])> {
    match link {
        1 => {
            let mut et = u16_at(f, 12, false)?;
            let mut o = 14;
            while matches!(et, 0x8100 | 0x88a8 | 0x9100) {
                et = u16_at(f, o + 2, false)?;
                o += 4;
            }
            Some((et, f.get(o..)?))
        }
        113 => Some((u16_at(f, 14, false)?, f.get(16..)?)),
        276 => Some((u16_at(f, 0, false)?, f.get(20..)?)),
        0 | 108 => {
            let fam = u32_at(f, 0, true)?;
            let et = if fam == 2 { 0x0800 } else { 0x86dd };
            Some((et, f.get(4..)?))
        }
        12 | 101 | 228 | 229 => {
            let v = f.first()? >> 4;
            Some((if v == 4 { 0x0800 } else { 0x86dd }, f))
        }
        _ => None,
    }
}

fn udp(src: IpAddr, seg: &[u8]) -> Option<Datagram> {
    let dst_port = u16_at(seg, 2, false)?;
    let len = usize::from(u16_at(seg, 4, false)?);
    let end = if len >= 8 && len <= seg.len() { len } else { seg.len() };
    Some(Datagram { src, dst_port, payload: seg.get(8..end)?.to_vec() })
}

fn frame_to_datagram(link: u32, f: &[u8], ra: &mut Reassembly, st: &mut Stats) -> Option<Datagram> {
    let Some((et, ip)) = l3(link, f) else {
        st.skipped_non_udp += 1;
        return None;
    };
    match et {
        0x0800 => {
            let ihl = usize::from(ip.first()? & 0x0f) * 4;
            let total = usize::from(u16_at(ip, 2, false)?).clamp(ihl, ip.len());
            let (frag, proto) = (u16_at(ip, 6, false)?, ip[9]);
            let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
            let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
            if proto != 17 {
                st.skipped_non_udp += 1;
                return None;
            }
            let body = ip.get(ihl..total)?;
            let (more, off) = (frag & 0x2000 != 0, usize::from(frag & 0x1fff) * 8);
            if more || off != 0 {
                let id = u16_at(ip, 4, false)?;
                return match ra.add((src, dst, id, proto), off, more, body) {
                    Some(whole) => udp(IpAddr::V4(src), &whole),
                    None => {
                        st.skipped_fragments += 1;
                        None
                    }
                };
            }
            udp(IpAddr::V4(src), body)
        }
        0x86dd => {
            let src: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
            let plen = usize::from(u16_at(ip, 4, false)?);
            let body = ip.get(40..(40 + plen).min(ip.len()))?;
            if ip[6] != 17 {
                st.skipped_non_udp += 1; // extension headers are not followed (none in the corpus)
                return None;
            }
            udp(IpAddr::V6(Ipv6Addr::from(src)), body)
        }
        _ => {
            st.skipped_non_udp += 1;
            None
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Decoding

/// The FlowPilot parser for a datagram: the parser listening on a default port (2055 netflow,
/// 4739 ipfix, 6343 sflow), as in a deployment; on any other port, the version field decides.
fn parser_for(port: u16, p: &[u8]) -> Option<&'static str> {
    match port {
        2055 => return Some("netflow"),
        4739 => return Some("ipfix"),
        6343 => return Some("sflow"),
        _ => {}
    }
    let v16 = u16_at(p, 0, false)?;
    match v16 {
        5 | 7 | 9 => Some("netflow"),
        10 => Some("ipfix"),
        0 if u32_at(p, 0, false) == Some(5) => Some("sflow"),
        _ => None,
    }
}

fn record_json(n: u64, frame: u64, parser: &str, fd: &FlowData) -> Value {
    let k = &fd.key;
    json!({
        "type": "record", "datagram": n, "frame": frame, "parser": parser,
        "transport": fd.transport, "seq_id": fd.seq_id, "device_addr": k.device_addr,
        "src_ip": k.src_ip, "dst_ip": k.dst_ip, "src_port": fd.src_port, "dst_port": k.dst_port,
        "ip_version": k.ip_version, "protocol": k.protocol, "icmp_type": k.icmp_type, "icmp_code": k.icmp_code,
        "src_mac": k.src_mac, "dst_mac": k.dst_mac, "src_mask": k.src_mask, "dst_mask": k.dst_mask,
        "flow_time": fd.flow_time, "flows": fd.flows, "octets": fd.octets, "direction_ind": fd.direction_ind,
    })
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut out_path, mut prefix, mut files) = (None, None, Vec::new());
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" | "-o" => out_path = args.next(),
            "--device-prefix" => prefix = args.next(),
            _ => files.push(a),
        }
    }
    let (Some(out_path), false) = (out_path, files.is_empty()) else {
        eprintln!("usage: pcap_decode --out FILE [--device-prefix NAME] CAPTURE|PAYLOAD.dat...");
        std::process::exit(2);
    };
    let prefix = prefix.unwrap_or_else(|| files[0].clone());
    let mut out = BufWriter::new(File::create(&out_path).unwrap_or_else(|e| {
        eprintln!("cannot create {out_path}: {e}");
        std::process::exit(2);
    }));

    // Keep the default hook's message on stderr, but continue after a panic.
    let (tx, rx) = crossbeam_channel::unbounded();
    let ctx = ParserContext::new(Meter::new(), FlowSink::new(tx), Arc::default());
    let mut st = Stats::default();
    let (mut n, mut records, mut panics) = (0u64, 0u64, 0u64);
    let mut per_parser: HashMap<&str, u64> = HashMap::new();
    let mut ports: BTreeMap<u16, &str> = BTreeMap::new();
    let mut ra = Reassembly::default();
    let mut errors = Vec::new();

    for path in &files {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                errors.push(format!("{path}: {e}"));
                continue;
            }
        };
        // (frame number in replay order, datagram); a reassembled datagram takes its last fragment's.
        let base = st.frames;
        let dgrams: Vec<(u64, Datagram)> = if path.ends_with(".dat") {
            st.frames += 1;
            vec![(base + 1, Datagram { src: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), dst_port: 0, payload: data })]
        } else {
            match read_frames(&data) {
                Ok(frames) => {
                    st.frames += frames.len() as u64;
                    let mut v = Vec::new();
                    for (i, (l, f)) in frames.iter().enumerate() {
                        if let Some(d) = frame_to_datagram(*l, f, &mut ra, &mut st) {
                            v.push((base + i as u64 + 1, d));
                        }
                    }
                    v
                }
                Err(e) => {
                    errors.push(format!("{path}: {e}"));
                    continue;
                }
            }
        };
        for (frame, d) in dgrams {
            n += 1;
            st.datagrams += 1;
            let Some(parser) = parser_for(d.dst_port, &d.payload) else {
                st.malformed += 1;
                let _ = writeln!(out, "{}", json!({"type": "skipped", "datagram": n, "frame": frame, "dst_port": d.dst_port, "reason": "unknown version"}));
                continue;
            };
            *per_parser.entry(parser).or_default() += 1;
            if d.dst_port != 0 {
                ports.insert(d.dst_port, parser);
            }
            let pd = ReceivedDatagram {
                device_addr: format!("{prefix}|{}", d.src),
                seq_id: n.to_string(),
                transport: "udp".into(),
                buf: d.payload,
            };
            let res = panic::catch_unwind(AssertUnwindSafe(|| decode_datagram(parser, &pd, &ctx)));
            for fd in rx.try_iter() {
                records += 1;
                let _ = writeln!(out, "{}", record_json(n, frame, parser, &fd));
            }
            if let Err(e) = res {
                panics += 1;
                let msg = e
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                let _ = writeln!(out, "{}", json!({"type": "panic", "datagram": n, "frame": frame, "parser": parser, "message": msg}));
            }
        }
    }
    let summary = json!({
        "type": "summary", "files": files, "frames": st.frames, "datagrams": st.datagrams,
        "skipped_non_udp": st.skipped_non_udp, "pending_fragments": st.skipped_fragments,
        "unknown_version": st.malformed, "per_parser": per_parser, "ports": ports, "records": records,
        "meter": ctx.meter.count(), "panics": panics, "errors": errors,
    });
    let _ = writeln!(out, "{summary}");
    let _ = out.flush();
    if panics > 0 {
        std::process::exit(3);
    }
}
