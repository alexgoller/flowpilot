//! Byte builders (the same shapes as the unit-test builders in src/parsers/*.rs, which are
//! `cfg(test)` there) and the structure-aware generators behind the `*_structured` targets.
//!
//! Raw bytes rarely get past the template lookup, so the generators emit a mostly valid
//! exporter conversation — headers, template sets with random IEs/lengths (incl. 0xFFFF varlen
//! and the enterprise bit), data sets whose records follow the templates defined so far — and
//! corrupt a length or a header field with low probability.

use std::time::{SystemTime, UNIX_EPOCH};

use arbitrary::{Result, Unstructured};

/// Fluent big-endian byte builder.
#[derive(Clone, Default)]
pub struct B(pub Vec<u8>);

impl B {
    pub fn u8(mut self, v: u8) -> Self {
        self.0.push(v);
        self
    }
    pub fn u16(mut self, v: u16) -> Self {
        self.0.extend(v.to_be_bytes());
        self
    }
    pub fn u32(mut self, v: u32) -> Self {
        self.0.extend(v.to_be_bytes());
        self
    }
    pub fn u64(mut self, v: u64) -> Self {
        self.0.extend(v.to_be_bytes());
        self
    }
    pub fn bytes(mut self, v: &[u8]) -> Self {
        self.0.extend_from_slice(v);
        self
    }
}

pub fn now_secs() -> u32 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as u32)
}

// ---------------------------------------------------------------------------------------------
// NetFlow v5/v7/v9 and IPFIX

/// A set (or v9 FlowSet) with Length = body + 4.
pub fn set(id: u16, body: &[u8]) -> Vec<u8> {
    B::default().u16(id).u16(body.len() as u16 + 4).bytes(body).0
}

/// One template record: template id and field count, then (id, len) pairs.
pub fn tmpl(tid: u16, fields: &[(u16, u16)]) -> Vec<u8> {
    fields.iter().fold(B::default().u16(tid).u16(fields.len() as u16), |b, &(i, l)| b.u16(i).u16(l)).0
}

pub fn ipfix_msg(export: u32, seq: u32, domain: u32, sets: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = sets.concat();
    B::default().u16(10).u16(16 + body.len() as u16).u32(export).u32(seq).u32(domain).bytes(&body).0
}

pub fn v9_msg(count: u16, uptime: u32, secs: u32, seq: u32, source_id: u32, sets: &[Vec<u8>]) -> Vec<u8> {
    B::default().u16(9).u16(count).u32(uptime).u32(secs).u32(seq).u32(source_id).bytes(&sets.concat()).0
}

/// v5/v7 header: common (12 B) + specific (12 B).
pub fn v5_header(version: u16, count: u16, uptime: u32, secs: u32, nsec: u32, seq: u32) -> B {
    B::default().u16(version).u16(count).u32(uptime).u32(secs).u32(nsec).u32(seq).u32(0)
}

pub fn v5_record(src: [u8; 4], dst: [u8; 4], first: u32) -> B {
    B::default()
        .bytes(&src)
        .bytes(&dst)
        .bytes(&[0; 4])
        .u16(1)
        .u16(2)
        .u32(10)
        .u32(5000)
        .u32(first)
        .u32(first + 500)
        .u16(50000)
        .u16(443)
        .u8(0)
        .u8(0x18)
        .u8(6)
        .u8(0)
        .u16(0)
        .u16(0)
        .u8(24)
        .u8(16)
        .u16(0)
}

/// Known information elements with their natural lengths (incl. some the decoder ignores).
pub const IES: &[(u16, u16)] = &[
    (1, 8),
    (1, 4),
    (2, 8),
    (3, 4),
    (4, 1),
    (7, 2),
    (8, 4),
    (9, 1),
    (10, 4),
    (11, 2),
    (12, 4),
    (13, 1),
    (14, 4),
    (21, 4),
    (22, 4),
    (27, 16),
    (28, 16),
    (29, 1),
    (30, 1),
    (32, 2),
    (56, 6),
    (57, 6),
    (60, 1),
    (61, 1),
    (80, 6),
    (136, 1),
    (139, 2),
    (150, 4),
    (150, 8),
    (151, 4),
    (152, 8),
    (152, 4),
    (153, 8),
    (154, 8),
    (156, 8),
    (158, 4),
    (176, 1),
    (177, 1),
    (178, 1),
    (179, 1),
    (180, 2),
    (181, 2),
    (182, 2),
    (183, 2),
    (225, 4),
    (226, 4),
    (227, 2),
    (228, 2),
    (239, 1),
    (281, 16),
    (282, 16),
];

#[derive(Clone, Debug)]
pub struct TField {
    pub id: u16,
    pub len: u16,
    /// Enterprise number (IPFIX only, when bit 15 of `id` is set).
    pub pen: Option<u32>,
}

fn field(u: &mut Unstructured, ipfix: bool) -> Result<TField> {
    let (mut id, natural) = IES[u.choose_index(IES.len())?];
    let len = match u.int_in_range(0..=19u8)? {
        0 => 0xFFFF,
        1 => u.int_in_range(0..=17)?,
        2 => u.arbitrary()?,
        _ => natural,
    };
    if u.ratio(1, 32u8)? {
        id = u.arbitrary()?;
    }
    let pen = if ipfix && (id & 0x8000 != 0 || u.ratio(1, 10u8)?) {
        id |= 0x8000;
        Some(u.arbitrary()?)
    } else {
        None
    };
    Ok(TField { id, len, pen })
}

/// `n` bytes from the input, zero-padded once it runs out.
fn fill(u: &mut Unstructured, n: usize, out: &mut Vec<u8>) -> Result<()> {
    let take = n.min(u.len());
    out.extend_from_slice(u.bytes(take)?);
    out.resize(out.len() + (n - take), 0);
    Ok(())
}

/// 0..=`max` bytes from the input (count chosen by the input).
fn fill_upto(u: &mut Unstructured, max: u8, out: &mut Vec<u8>) -> Result<()> {
    let n = u.int_in_range(0..=max)?;
    fill(u, n.into(), out)
}

/// One field value in a data record (RFC 7011 §7 varlen prefix for 0xFFFF).
fn value(u: &mut Unstructured, f: &TField, out: &mut Vec<u8>) -> Result<()> {
    if f.len == 0xFFFF {
        let n: u16 = u.int_in_range(0..=300)?;
        if n < 255 && u.ratio(3, 4u8)? {
            out.push(n as u8);
        } else {
            out.push(255);
            out.extend(n.to_be_bytes());
        }
        return fill(u, n.into(), out);
    }
    // Interesting values for the fields the decoder interprets.
    let l = usize::from(f.len);
    match (f.id, l) {
        (150 | 152, 8) if u.ratio(1, 4u8)? => out.extend(u.choose(&[i64::MIN, -1, i64::MAX, 0])?.to_be_bytes()),
        (22 | 158, 4) if u.ratio(1, 4u8)? => out.extend(u.choose(&[0u32, u32::MAX, 1000])?.to_be_bytes()),
        _ => fill(u, l.min(4096), out)?,
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flavor {
    Ipfix,
    V9,
}

/// A conversation of 1-4 IPFIX or NetFlow v9 messages from one exporter. Templates defined in
/// one message are used by data sets in the same and later messages; data sets may also come
/// before their template (PendingSet path) or reference no template at all.
pub fn template_sequence(u: &mut Unstructured, flavor: Flavor) -> Result<Vec<Vec<u8>>> {
    let ipfix = flavor == Flavor::Ipfix;
    let now = now_secs();
    let domain: u32 = if u.ratio(1, 4u8)? { u.arbitrary()? } else { 0 };
    let mut defined: Vec<(u16, Vec<TField>)> = Vec::new();
    let mut msgs = Vec::new();
    for _ in 0..u.int_in_range(1..=4u8)? {
        let mut sets: Vec<Vec<u8>> = Vec::new();
        for _ in 0..u.int_in_range(1..=5u8)? {
            let (id, body) = match u.int_in_range(0..=9u8)? {
                0..=2 => {
                    let mut body = Vec::new();
                    for _ in 0..u.int_in_range(1..=3u8)? {
                        let tid = 256 + u16::from(u.int_in_range(0..=3u8)?);
                        let nf = if u.ratio(1, 32u8)? { 0 } else { u.int_in_range(1..=12u8)? };
                        let fields = (0..nf).map(|_| field(u, ipfix)).collect::<Result<Vec<_>>>()?;
                        body.extend(tid.to_be_bytes());
                        body.extend((fields.len() as u16).to_be_bytes());
                        for f in &fields {
                            body.extend(f.id.to_be_bytes());
                            body.extend(f.len.to_be_bytes());
                            if let Some(pen) = f.pen {
                                body.extend(pen.to_be_bytes());
                            }
                        }
                        defined.retain(|(t, _)| *t != tid);
                        defined.push((tid, fields));
                    }
                    (if ipfix { 2 } else { 0 }, body)
                }
                3..=7 => {
                    let mut body = Vec::new();
                    let tid = if defined.is_empty() || u.ratio(1, 8u8)? {
                        let tid = 256 + u16::from(u.int_in_range(0..=3u8)?);
                        fill_upto(u, 64, &mut body)?;
                        tid
                    } else {
                        let (tid, fields) = defined[u.choose_index(defined.len())?].clone();
                        for _ in 0..u.int_in_range(0..=5u8)? {
                            for f in &fields {
                                value(u, f, &mut body)?;
                            }
                        }
                        tid
                    };
                    body.resize(body.len() + usize::from(u.int_in_range(0..=3u8)?), 0); // padding
                    (tid, body)
                }
                8 => {
                    let mut body = Vec::new();
                    fill_upto(u, 40, &mut body)?;
                    (if ipfix { 3 } else { 1 }, body)
                }
                _ => {
                    let mut body = Vec::new();
                    let id = u.arbitrary()?;
                    fill_upto(u, 40, &mut body)?;
                    (id, body)
                }
            };
            let len = if u.ratio(1, 16u8)? { u.arbitrary()? } else { (body.len() + 4) as u16 };
            sets.push(B::default().u16(id).u16(len).bytes(&body).0);
        }
        if ipfix && u.ratio(1, 2u8)? {
            sets.push(set(4, &[0; 32])); // an ignored trailing set (was needed for FlowLink's 32-byte cut-off)
        }
        let time = match u.int_in_range(0..=3u8)? {
            0 => 0,
            1 => now,
            2 => now.wrapping_sub(300),
            _ => u.arbitrary()?,
        };
        let seq: u32 = u.arbitrary()?;
        let body = sets.concat();
        let msg = if ipfix {
            let len = if u.ratio(1, 16u8)? { u.arbitrary()? } else { (16 + body.len()) as u16 };
            B::default().u16(10).u16(len).u32(time).u32(seq).u32(domain).bytes(&body).0
        } else {
            let count = if u.ratio(1, 8u8)? { u.arbitrary()? } else { sets.len() as u16 };
            let uptime: u32 = if u.ratio(1, 2u8)? { u.arbitrary()? } else { 100_000 };
            v9_msg(count, uptime, time, seq, domain, &[body])
        };
        msgs.push(msg);
    }
    Ok(msgs)
}

// ---------------------------------------------------------------------------------------------
// sFlow v5

pub fn u32s(v: &[u32]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_be_bytes()).collect()
}

/// sFlow v5 datagram header with `agent` = 4 (IPv4) or 16 (IPv6) bytes.
pub fn sflow_datagram(addr_type: u32, agent: &[u8], samples: &[Vec<u8>]) -> Vec<u8> {
    let mut d = u32s(&[5, addr_type]);
    d.extend_from_slice(agent);
    d.extend(u32s(&[0, 1, 1000, samples.len() as u32]));
    samples.iter().for_each(|s| d.extend_from_slice(s));
    d
}

/// Flow sample (type 1) or expanded flow sample (type 3).
pub fn flow_sample(ty: u32, records: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = records.concat();
    let n = records.len() as u32;
    let fixed = if ty == 1 { u32s(&[512, 1000, 0, 1, 2, n]) } else { u32s(&[512, 1000, 0, 0, 1, 0, 2, n]) };
    let mut hdr = if ty == 1 { u32s(&[1, 0, 7, 3]) } else { u32s(&[3, 0, 7, 0, 3]) };
    let len = (hdr.len() - 8 + fixed.len() + body.len()) as u32;
    hdr[4..8].copy_from_slice(&len.to_be_bytes());
    [hdr, fixed, body].concat()
}

fn pad4(mut v: Vec<u8>) -> Vec<u8> {
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}

/// Format 1 raw packet header record.
pub fn raw(proto: u32, hdr: &[u8]) -> Vec<u8> {
    let h = pad4(hdr.to_vec());
    [u32s(&[1, 16 + h.len() as u32, proto, 1500, 4, hdr.len() as u32]), h].concat()
}

pub fn eth(ty: u16) -> Vec<u8> {
    [&[2, 0, 0, 0, 0, 1][..], &[0x00, 0x1b, 0x21, 0xaa, 0xbb, 0xcc][..], &ty.to_be_bytes()[..]].concat()
}

pub fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut h = vec![0x45, 0, 0, 60, 0, 1, 0, 0, 64, proto, 0, 0];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    h
}

pub fn ipv6(next: u8, src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
    let mut h = vec![0x60, 0, 0, 0, 0, 20, next, 64];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    h
}

pub fn tcp(sp: u16, dp: u16) -> Vec<u8> {
    [&sp.to_be_bytes()[..], &dp.to_be_bytes()[..], &[0; 8], &[0x50, 0x10, 0xff, 0xff, 0, 0, 0, 0]].concat()
}

pub fn udp(sp: u16, dp: u16) -> Vec<u8> {
    [&sp.to_be_bytes()[..], &dp.to_be_bytes()[..], &[0, 8, 0, 0][..]].concat()
}

/// Format 2 Ethernet frame record.
pub fn eth_record(src: [u8; 6], dst: [u8; 6]) -> Vec<u8> {
    [u32s(&[2, 28, 1500]), src.to_vec(), vec![0, 0], dst.to_vec(), vec![0, 0], u32s(&[0x0800])].concat()
}

/// Format 3 IPv4 data record.
pub fn ipv4_record(proto: u32, src: [u8; 4], dst: [u8; 4], sp: u32, dp: u32) -> Vec<u8> {
    [u32s(&[3, 32, 100, proto]), src.to_vec(), dst.to_vec(), u32s(&[sp, dp, 0, 0])].concat()
}

pub fn counter_sample() -> Vec<u8> {
    let recs = [u32s(&[1, 8]), vec![0xaa; 8], u32s(&[2, 4]), vec![0xbb; 4]].concat();
    [u32s(&[2, 4 + 4 + 4 + recs.len() as u32, 9, 3, 2]), recs].concat()
}

fn l4(u: &mut Unstructured, proto: u8, out: &mut Vec<u8>) -> Result<()> {
    match proto {
        6 => {
            let mut h = tcp(u.arbitrary()?, u.arbitrary()?);
            if u.ratio(1, 4u8)? {
                h[12] = u.arbitrary()?; // data offset
                h[13] = u.arbitrary()?; // flags incl. URG
            }
            out.extend(h);
        }
        17 => out.extend(udp(u.arbitrary()?, u.arbitrary()?)),
        1 | 58 => out.extend([u.arbitrary()?, u.arbitrary()?, 0, 0, 0, 0, 0, 0]),
        _ => {}
    }
    let extra = usize::from(u.int_in_range(0..=24u8)?);
    fill(u, extra, out)?;
    if u.ratio(1, 6u8)? {
        let keep = u.int_in_range(0..=out.len())?;
        out.truncate(keep);
    }
    Ok(())
}

const PROTOS: &[u8] = &[6, 17, 1, 58, 0, 43, 44, 59, 47, 50];

fn l3(u: &mut Unstructured, v6: bool, out: &mut Vec<u8>) -> Result<()> {
    let mut proto = *u.choose(PROTOS)?;
    if u.ratio(1, 16u8)? {
        proto = u.arbitrary()?;
    }
    if v6 {
        let (s, d): ([u8; 16], [u8; 16]) = (u.arbitrary()?, u.arbitrary()?);
        out.extend(ipv6(proto, s, d));
        // IPv6 extension headers: next(1) len(1) and len-1 bytes; fragment: next + 7 bytes.
        let mut p = proto;
        let mut hops = 0;
        while matches!(p, 0 | 43 | 44) && hops < 4 {
            let next = *u.choose(PROTOS)?;
            out.push(next);
            if p == 44 {
                out.extend([0; 7]);
            } else {
                let len: u8 = u.int_in_range(0..=8)?;
                out.push(len);
                fill(u, usize::from(len.saturating_sub(1)), out)?;
            }
            p = next;
            hops += 1;
        }
        l4(u, p, out)
    } else {
        let (s, d): ([u8; 4], [u8; 4]) = (u.arbitrary()?, u.arbitrary()?);
        let mut h = ipv4(proto, s, d);
        if u.ratio(1, 8u8)? {
            let ihl: u8 = u.int_in_range(0..=15)?;
            h[0] = 0x40 | ihl;
            out.extend(h);
            fill(u, usize::from(ihl.saturating_sub(5)) * 4, out)?;
        } else {
            out.extend(h);
        }
        l4(u, proto, out)
    }
}

fn raw_header(u: &mut Unstructured) -> Result<Vec<u8>> {
    let mut pkt = Vec::new();
    let proto: u32 = match u.int_in_range(0..=9u8)? {
        0..=5 => {
            let ty = match u.int_in_range(0..=9u8)? {
                0..=3 => 0x0800,
                4..=5 => 0x86dd,
                6 => 0x8100,
                7 => *u.choose(&[0x0806, 0x8035, 0x886f, 0x05dc, 0x0040])?,
                _ => u.arbitrary()?,
            };
            pkt.extend(eth(ty));
            let inner = if ty == 0x8100 {
                let t = *u.choose(&[0x0800u16, 0x86dd, 0x8100])?;
                pkt.extend([0, 10]);
                pkt.extend(t.to_be_bytes());
                t
            } else {
                ty
            };
            match inner {
                0x0800 => l3(u, false, &mut pkt)?,
                0x86dd => l3(u, true, &mut pkt)?,
                _ => fill_upto(u, 30, &mut pkt)?,
            }
            1
        }
        6..=7 => {
            l3(u, false, &mut pkt)?;
            11
        }
        8 => {
            l3(u, true, &mut pkt)?;
            12
        }
        _ => {
            fill_upto(u, 40, &mut pkt)?;
            u.arbitrary()?
        }
    };
    let mut rec = raw(proto, &pkt);
    if u.ratio(1, 16u8)? {
        let dl: u32 = u.arbitrary()?;
        rec[4..8].copy_from_slice(&dl.to_be_bytes()); // sampled header length, including < 16
    }
    Ok(rec)
}

fn flow_record(u: &mut Unstructured) -> Result<Vec<u8>> {
    Ok(match u.int_in_range(0..=9u8)? {
        0..=4 => raw_header(u)?,
        5 => eth_record(u.arbitrary()?, u.arbitrary()?),
        6 => ipv4_record(*u.choose(&[6u32, 17, 1])?, u.arbitrary()?, u.arbitrary()?, u.arbitrary()?, u.arbitrary()?),
        7 => [u32s(&[1001, 16]), vec![0; 16]].concat(),
        8 => {
            let at: u32 = *u.choose(&[1u32, 2, 0, 7])?;
            let body = match at {
                1 => 12,
                2 => 24,
                _ => usize::from(u.int_in_range(0..=20u8)?),
            };
            let mut r = u32s(&[1002, (body + 4) as u32, at]);
            fill(u, body, &mut r)?;
            r
        }
        _ => {
            let n = usize::from(u.int_in_range(0..=24u8)?);
            let mut r = u32s(&[u.arbitrary()?, n as u32]);
            fill(u, n, &mut r)?;
            r
        }
    })
}

/// A mostly valid sFlow v5 datagram with flow, counter and unknown samples.
pub fn sflow(u: &mut Unstructured) -> Result<Vec<u8>> {
    let addr_type: u32 = match u.int_in_range(0..=7u8)? {
        0..=4 => 1,
        5..=6 => 2,
        _ => u.arbitrary()?,
    };
    let agent: Vec<u8> = if addr_type == 1 { vec![192, 0, 2, 1] } else { vec![0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] };
    let mut samples = Vec::new();
    for _ in 0..u.int_in_range(0..=4u8)? {
        let mut s = match u.int_in_range(0..=7u8)? {
            0..=4 => {
                let ty = *u.choose(&[1u32, 3])?;
                let recs = (0..u.int_in_range(0..=4u8)?).map(|_| flow_record(u)).collect::<Result<Vec<_>>>()?;
                flow_sample(ty, &recs)
            }
            5 => counter_sample(),
            _ => {
                let n = usize::from(u.int_in_range(0..=24u8)?);
                let ty: u32 = u.arbitrary()?;
                let hdr = if ty <= 2 { u32s(&[ty, n as u32]) } else { u32s(&[ty, n as u32 + 4, 0]) };
                let mut s = hdr;
                fill(u, n, &mut s)?;
                s
            }
        };
        if u.ratio(1, 16u8)? && s.len() >= 8 {
            let l: u32 = u.arbitrary()?;
            s[4..8].copy_from_slice(&l.to_be_bytes());
        }
        samples.push(s);
    }
    let mut d = sflow_datagram(addr_type, &agent, &samples);
    if u.ratio(1, 16u8)? {
        let n: u32 = u.arbitrary()?;
        let at = 8 + agent.len() + 12;
        d[at..at + 4].copy_from_slice(&n.to_be_bytes()); // sample count
    }
    Ok(d)
}
