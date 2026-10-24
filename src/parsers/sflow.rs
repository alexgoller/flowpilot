//! sFlow v5 parser (docs/collectors.md).
//!
//! Every read goes through [`Rd`], a borrowing big-endian cursor with Go `io.ReadFull` error
//! strings. It never allocates, so wrapped/huge length fields simply fail (or are clamped) instead
//! of allocating gigabytes (FlowLink tries to). FlowLink's struct debug dumps are not reproduced.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crossbeam_channel::Sender;

use crate::config::{Info, Properties};
use crate::flow::FlowData;
use crate::log::{join_bytes, check_error, go_slice, debug_hex, note_decode_error, take_decode_errors};
use crate::parsers::{Parser, ParserContext, ReceivedDatagram};
use crate::stats::{CollectorStats, Proto, ThreadGuard};
use crate::{debug_log, log_line};

/// Largest datagram read; longer sFlow datagrams are clamped to this size.
const MAX_DATAGRAM: usize = 65536;

/// Sets up the sFlow parser and its connectors. Every connector is attempted (no
/// short-circuit, unlike `connect_all`); success means at least one attached.
pub fn setup(properties: &Properties, connectors: &[Info], ctx: ParserContext) -> bool {
    for key in properties.keys() {
        log_line!("Unsupported sflow parser property:", key);
    }
    let parser: Arc<dyn Parser> = Arc::new(SflowParser { ctx });
    let n = connectors
        .iter()
        .filter(|c| crate::connectors::start_connector(parser.clone(), &c.kind, &c.properties))
        .count();
    n != 0
}

/// The sFlow parser: no state besides the meter (and, here, the flow sink).
pub struct SflowParser {
    ctx: ParserContext,
}

impl Parser for SflowParser {
    fn type_name(&self) -> &'static str {
        "sflow"
    }

    fn default_port(&self) -> u16 {
        6343
    }

    fn supports_connector(&self, conn_type: &str) -> bool {
        conn_type == "udp"
    }

    fn stats(&self) -> Arc<CollectorStats> {
        self.ctx.stats.clone()
    }

    /// `n` workers on one channel of capacity `10*n`.
    fn start_workers(self: Arc<Self>, n: usize) -> Sender<ReceivedDatagram> {
        let (tx, rx) = crossbeam_channel::bounded::<ReceivedDatagram>(n * 10);
        for _ in 0..n {
            let (p, rx) = (self.clone(), rx.clone());
            std::thread::spawn(move || {
                let _guard = ThreadGuard::core("sflow parser");
                // Divergence: FlowLink busy-loops logging on a closed channel; we log once and stop.
                rx.iter().for_each(|pd| process(&pd, &p.ctx));
                log_line!("Unable to get data from sflow parser channel");
            });
        }
        tx
    }
}

/// Go `io.ReadFull` errors as returned by `binary.Read` on a `*bytes.Reader`.
type ReadErr = &'static str;

/// Big-endian cursor over a borrowed slice (`*bytes.Reader` + `binary.Read`).
struct Rd<'a>(&'a [u8]);

impl<'a> Rd<'a> {
    fn len(&self) -> usize {
        self.0.len()
    }

    /// `io.ReadFull(r, make([]byte, n))`: "EOF" on an empty reader, "unexpected EOF" on a
    /// partial read (which drains the reader, like Go). Zero-length reads always succeed.
    fn take(&mut self, n: usize) -> Result<&'a [u8], ReadErr> {
        if n > self.0.len() {
            let e = if self.0.is_empty() { "EOF" } else { "unexpected EOF" };
            self.0 = &[];
            return Err(e);
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Ok(h)
    }

    fn u8(&mut self) -> Result<u8, ReadErr> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Result<u16, ReadErr> {
        self.take(2).map(|b| be16(b, 0))
    }

    fn u32(&mut self) -> Result<u32, ReadErr> {
        self.take(4).map(|b| be32(b, 0))
    }
}

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// `log::check_error`: logs and yields `None` on error.
fn ck<T>(res: Result<T, ReadErr>) -> Option<T> {
    res.map_err(|e| check_error(Some(e))).ok()
}

/// Go `net.IP(b).String()` for 4- or 16-byte addresses (IPv4-mapped IPv6 prints dotted).
/// Ported from the Go standard library (`net`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
fn go_ip(b: &[u8]) -> String {
    match b.len() {
        4 => Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            let v6 = Ipv6Addr::from(a);
            v6.to_ipv4_mapped().map_or_else(|| v6.to_string(), |v4| v4.to_string())
        }
        _ => String::new(),
    }
}

/// One iteration of the worker loop for a received datagram, counted in the collector stats.
pub(crate) fn process(pd: &ReceivedDatagram, ctx: &ParserContext) {
    take_decode_errors(); // errors before this datagram are not its own
    let (mut proto, mut flows) = (None, 0u64);
    decode(pd, ctx, &mut proto, &mut flows);
    ctx.stats.datagram(&pd.device_addr, proto, pd.buf.len(), flows, take_decode_errors());
}

/// Decode one datagram. Sets `proto` once the version is known; `flows` counts the records handed to the flow
/// filter (the meter counts declared records instead, as in FlowLink).
fn decode(pd: &ReceivedDatagram, ctx: &ParserContext, proto: &mut Option<Proto>, flows: &mut u64) {
    // Divergence: FlowLink panics when Length > 65536; clamp to FlowLink's buffer size.
    let mut r = Rd(&pd.buf[..pd.buf.len().min(MAX_DATAGRAM)]);
    let mut fd = FlowData {
        transport: pd.transport.clone(),
        seq_id: pd.seq_id.clone(),
        ..Default::default()
    };
    fd.key.device_addr = pd.device_addr.clone();

    let hdr = match r.take(8) {
        Ok(b) => b,
        Err(e) => {
            check_error(Some(e));
            log_line!("Unable to read sFlow header. Error:", e);
            return;
        }
    };
    if be32(hdr, 0) != 5 {
        log_line!("Ignoring non-version 5 data");
        note_decode_error();
        return;
    }
    *proto = Some(Proto::Sflow);
    // As in FlowLink, any address type other than 1 is read as 16 bytes of IPv6.
    let agent = if be32(hdr, 4) == 1 { ck(r.take(4)) } else { ck(r.take(16)) };
    if agent.is_none() {
        return;
    }
    let Some(hdr2) = ck(r.take(16)) else { return };
    let num_samples = be32(hdr2, 12);
    fd.flow_time = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    fd.flows = 1; // as in FlowLink, never scaled by the sampling rate; Octets stays 0

    // A sample is read only while more than 16 bytes remain (as in FlowLink).
    let mut i = 0u32;
    while i < num_samples && r.len() > 16 {
        let Some(sh) = ck(r.take(16)) else { return };
        let (ty, length) = (be32(sh, 0), be32(sh, 4));
        // As in FlowLink, every type above 2 consumes a 4-byte source-id index.
        let hdr_len = if ty <= 2 {
            8
        } else {
            let Some(_idx) = ck(r.u32()) else { return };
            12
        };
        let ok = match ty {
            1 | 3 => {
                fd.direction_ind = 2;
                read_flow_sample(&mut r, ty, fd.clone(), ctx, flows)
            }
            2 | 4 => skip_counter_sample(&mut r),
            _ => {
                log_line!("Unhandled Sample Type:", ty);
                let mut n = length.wrapping_sub(hdr_len) as usize;
                if n > r.len() {
                    n = r.len();
                    log_line!("Adjusted read to number of bytes left:", n);
                }
                ck(r.take(n)).map(|b| debug_hex("Sample data:", b)).is_some()
            }
        };
        if !ok {
            return; // as in FlowLink, a failed sample abandons the datagram
        }
        i += 1;
    }
}

/// Counter samples: read and discard. As in FlowLink, lengths are not clamped.
fn skip_counter_sample(r: &mut Rd) -> bool {
    let Some(count) = ck(r.u32()) else { return false };
    debug_log!("Counters:", count, "Sample(s)");
    let mut i = 0u32;
    while i < count && r.len() > 0 {
        let Some(format) = ck(r.u32()) else { return false };
        let Some(length) = ck(r.u32()) else { return false };
        debug_log!("Counter format:", format, "length:", length);
        if ck(r.take(length as usize)).is_none() {
            return false;
        }
        i += 1;
    }
    true
}

/// Flow samples. `fd` is a per-sample copy whose mutations
/// carry over between its records, as in FlowLink. Counts the records sent into `flows`.
fn read_flow_sample(r: &mut Rd, sample_type: u32, mut fd: FlowData, ctx: &ParserContext, flows: &mut u64) -> bool {
    debug_log!("Flow Sample(s)");
    let fixed = if sample_type == 1 { ck(r.take(24)) } else { ck(r.take(32)) };
    let Some(fixed) = fixed else { return false };
    let nrec = be32(fixed, fixed.len() - 4);
    ctx.meter.mark(nrec as i64); // declared records, before parsing, as in FlowLink

    let mut i = 0u32;
    while i < nrec && r.len() > 0 {
        let Some(format) = ck(r.u32()) else { return false };
        let ok = match format {
            1 => {
                let Some(rp) = ck(r.take(20)) else { return false };
                // Divergence: a sampled header length below 16 wraps to ~4 GiB in FlowLink; the borrowed read fails
                // with the same EOF/unexpected EOF error and no allocation.
                let Some(hdr) = ck(r.take(be32(rp, 0).wrapping_sub(16) as usize)) else { return false };
                debug_hex("Raw packet data:", hdr);
                match be32(rp, 4) {
                    1 => decode_ethernet(&mut Rd(hdr), fd.clone(), ctx, flows),
                    11 => decode_ipv4(&mut Rd(hdr), fd.clone(), ctx, flows),
                    _ => true, // as in FlowLink, bare IPv6 (12) and others emit nothing
                }
            }
            2 => {
                let Some(e) = ck(r.take(28)) else { return false };
                fd.key.src_mac = join_bytes(&e[8..14], ":", true);
                fd.key.dst_mac = join_bytes(&e[16..22], ":", true);
                true
            }
            3 => {
                let Some(s) = ck(r.take(36)) else { return false };
                fd.key.ip_version = 4;
                fd.key.src_ip = go_ip(&s[12..16]);
                fd.src_port = be32(s, 20) as u16;
                fd.key.dst_ip = go_ip(&s[16..20]);
                fd.key.dst_port = be32(s, 24) as u16;
                fd.key.protocol = be32(s, 8) as u8;
                send(ctx, fd.clone(), flows);
                true
            }
            1001 => ck(r.take(20)).is_some(),
            1002 => {
                let Some(b) = ck(r.take(8)) else { return false };
                match be32(b, 4) {
                    1 => ck(r.take(12)).is_some(),
                    2 => ck(r.take(24)).is_some(),
                    _ => {
                        // Other record types: 4 bytes of the record are left unread (as in FlowLink); a
                        // short read is ignored.
                        let mut n = be32(b, 0).wrapping_sub(8) as usize;
                        if r.len() < n {
                            n = r.len();
                            log_line!("Adjusted read to number of bytes left:", n);
                        }
                        let _ = r.take(n);
                        true
                    }
                }
            }
            _ => {
                let Some(mut length) = ck(r.u32()) else { return false };
                debug_log!("Flow format:", format, "length:", length);
                if length as usize > r.len() {
                    length = r.len() as u32;
                    log_line!("Adjusted read to number of bytes left:", length);
                }
                ck(r.take(length as usize)).map(|b| debug_hex("Sample data:", b)).is_some()
            }
        };
        if !ok {
            return false;
        }
        i += 1;
    }
    true
}

/// Ethernet header. As in FlowLink, a single 802.1Q tag only.
fn decode_ethernet(r: &mut Rd, mut fd: FlowData, ctx: &ParserContext, flows: &mut u64) -> bool {
    let Some(e) = ck(r.take(14)) else { return false };
    fd.key.src_mac = join_bytes(&e[6..12], ":", true);
    fd.key.dst_mac = join_bytes(&e[0..6], ":", true);
    let mut t = be16(e, 12);
    if t <= 0x05dc {
        let Some(dsap) = ck(r.u8()) else { return false };
        let Some(ssap) = ck(r.u8()) else { return false };
        debug_log!(format!("IEEE 802.3 LLC Packet Length: {t} DSAP: 0x{dsap:02x} SSAP: 0x{ssap:02x}"));
        return true;
    }
    if t == 0x8100 {
        debug_log!(format!("Ethernet 2 Type: 0x{:04x}", 0x8100));
        let Some(vlan) = ck(r.take(4)) else { return false };
        t = be16(vlan, 2);
    }
    debug_log!(format!("Ethernet 2 Type: 0x{t:04x}"));
    match t {
        0x0800 => return decode_ipv4(r, fd, ctx, flows),
        0x0806 => debug_log!("ARP frame"),
        0x8035 => debug_log!("RARP frame"),
        0x86dd => return decode_ipv6(r, fd, ctx, flows),
        0x886f => debug_log!("MS NLB Heartbeat"),
        _ => {}
    }
    true
}

/// IPv6 header. The source port is not reset, as in FlowLink.
fn decode_ipv6(r: &mut Rd, mut fd: FlowData, ctx: &ParserContext, flows: &mut u64) -> bool {
    let Some(h) = ck(r.take(40)) else { return false };
    fd.key.ip_version = 6;
    fd.key.src_ip = go_ip(&h[8..24]);
    fd.key.dst_ip = go_ip(&h[24..40]);
    fd.key.dst_port = 0;
    fd.key.protocol = h[6];
    decode_transport(r, fd, ctx, flows)
}

/// IPv4 header. Version, length and fragment fields are ignored.
fn decode_ipv4(r: &mut Rd, mut fd: FlowData, ctx: &ParserContext, flows: &mut u64) -> bool {
    let Some(h) = ck(r.take(20)) else { return false };
    fd.key.ip_version = 4;
    fd.key.src_ip = go_ip(&h[12..16]);
    fd.key.dst_ip = go_ip(&h[16..20]);
    fd.key.dst_port = 0;
    fd.key.protocol = h[9];
    let ihl = h[0] & 0x0f;
    if ihl > 5 {
        let Some(opts) = ck(r.take(((ihl - 5) * 4) as usize)) else { return false };
        debug_hex("Options:", opts);
    }
    decode_transport(r, fd, ctx, flows)
}

/// Transport header after the IP header. Extension headers are walked in a loop
/// so that a datagram of thousands of 2-byte headers cannot overflow the stack.
fn decode_transport(r: &mut Rd, mut fd: FlowData, ctx: &ParserContext, flows: &mut u64) -> bool {
    loop {
        if r.len() == 0 {
            return true; // as in FlowLink, nothing after the IP header, no flow
        }
        let p = fd.key.protocol;
        let label = match p {
            0 | 43 | 44 => {
                if fd.key.ip_version != 6 {
                    log_line!("Invalid protocol for IPv4:", p);
                    return false;
                }
                debug_log!("IPv6 Extension header:", p);
                if r.len() > 1 {
                    let Some(next) = ck(r.u8()) else { return false };
                    fd.key.protocol = next;
                    debug_log!("Next protocol:", next);
                    // An extension header is taken to be (Hdr Ext Len - 1) bytes long, not the RFC 8200
                    // (Hdr Ext Len * 8 + 6); a fragment header 7. This matches FlowLink's output.
                    let hdr_bytes = if p == 44 { Ok(7u8) } else { r.u8().map(|b| b.wrapping_sub(1)) };
                    let n = hdr_bytes.unwrap_or(0);
                    debug_log!("header bytes:", n);
                    if hdr_bytes.is_err() || n as usize > r.len() {
                        debug_log!("Unable to read extension header len");
                        return true;
                    }
                    let Ok(data) = r.take(n as usize) else {
                        debug_log!("Unable to read extension header data");
                        return true;
                    };
                    // The debug line drops the brackets around the byte list, as in FlowLink.
                    debug_log!("data:", go_slice(data).trim_end_matches(['[', ']']));
                    continue;
                }
                "" // <= 1 byte left: emitted with the extension protocol
            }
            1 | 58 => {
                let v = fd.key.ip_version;
                if (v == 4 && p == 58) || (v == 6 && p == 1) {
                    log_line!(format!("Invalid protocol for IPv{v}: {p}"));
                    return false;
                }
                let Some(h) = ck(r.take(8)) else { return false };
                fd.key.icmp_type = h[0];
                fd.key.icmp_code = h[1];
                ""
            }
            6 => {
                if r.len() < 18 {
                    return false;
                }
                let Some(h) = ck(r.take(18)) else { return false };
                fd.src_port = be16(h, 0);
                fd.key.dst_port = be16(h, 2);
                let flags = be16(h, 12);
                let (off, urg) = (flags >> 12, (flags & 0x20) >> 5);
                if (urg == 1 || off > 5) && r.len() >= 2 && ck(r.take(2)).is_none() {
                    return false;
                }
                if off > 5 {
                    let n = (((off - 5) * 4) as usize).min(r.len());
                    let Some(opts) = ck(r.take(n)) else { return false };
                    debug_hex("Options:", opts);
                }
                "TCP Packet Bytes:"
            }
            17 => {
                let (mut sp, mut dp) = (0, 0);
                if r.len() >= 8 {
                    let Some(h) = ck(r.take(8)) else { return false };
                    (sp, dp) = (be16(h, 0), be16(h, 2));
                } else {
                    // Piecewise: these reads cannot fail given the length checks.
                    if r.len() >= 2 {
                        sp = r.u16().unwrap_or(0);
                    }
                    if r.len() >= 2 {
                        dp = r.u16().unwrap_or(0);
                    }
                    let _ = r.take(r.len());
                }
                fd.src_port = sp;
                fd.key.dst_port = dp;
                "UDP Packet Bytes:"
            }
            59 => return true,
            _ => {
                debug_log!("Protocol:", p);
                "Packet Bytes:"
            }
        };
        // Trailer.
        let n = r.len();
        if n > 0 {
            let Some(rest) = ck(r.take(n)) else { return false };
            debug_hex(label, rest);
        }
        send(ctx, fd, flows);
        return true;
    }
}

/// Hand one record to the flow filter, counting it for the stats.
fn send(ctx: &ParserContext, fd: FlowData, flows: &mut u64) {
    ctx.sink.send(fd);
    *flows += 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{FlowData, FlowSink};
    use crate::metrics::Meter;
    use crate::parsers::decode_datagram;
    use crate::stats::{register_collector, CollectorStats, Proto};
    use crossbeam_channel::Receiver;

    const MAC_A: [u8; 6] = [0x00, 0x1b, 0x21, 0xaa, 0xbb, 0xcc];
    const MAC_B: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const V4_A: [u8; 4] = [10, 0, 0, 1];
    const V4_B: [u8; 4] = [10, 0, 0, 2];

    fn ctx() -> (ParserContext, Receiver<FlowData>) {
        let (tx, rx) = crossbeam_channel::unbounded();
        (ParserContext::new(Meter::new(), FlowSink::new(tx), Arc::new(CollectorStats::default())), rx)
    }

    fn run(buf: Vec<u8>) -> (Vec<FlowData>, i64) {
        let (c, rx) = ctx();
        let pd = ReceivedDatagram { device_addr: "192.0.2.9".into(), seq_id: "s1".into(), transport: "udp".into(), buf };
        process(&pd, &c);
        (rx.try_iter().collect(), c.meter.count())
    }

    fn u32s(v: &[u32]) -> Vec<u8> {
        v.iter().flat_map(|x| x.to_be_bytes()).collect()
    }

    /// sFlow v5 datagram header with `agent` = 4 (IPv4) or 16 (IPv6) bytes.
    fn datagram(addr_type: u32, agent: &[u8], samples: &[Vec<u8>]) -> Vec<u8> {
        let mut d = u32s(&[5, addr_type]);
        d.extend_from_slice(agent);
        d.extend(u32s(&[0, 1, 1000, samples.len() as u32]));
        samples.iter().for_each(|s| d.extend_from_slice(s));
        d
    }

    fn v4dg(samples: &[Vec<u8>]) -> Vec<u8> {
        datagram(1, &[192, 0, 2, 1], samples)
    }

    /// Flow sample (type 1) or expanded flow sample (type 3).
    fn flow_sample(ty: u32, records: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = records.concat();
        let n = records.len() as u32;
        let fixed = if ty == 1 { u32s(&[512, 1000, 0, 1, 2, n]) } else { u32s(&[512, 1000, 0, 0, 1, 0, 2, n]) };
        let mut hdr = if ty == 1 { u32s(&[1, 0, 7, 3]) } else { u32s(&[3, 0, 7, 0, 3]) };
        let len = (hdr.len() - 8 + fixed.len() + body.len()) as u32;
        hdr[4..8].copy_from_slice(&len.to_be_bytes());
        [hdr, fixed, body].concat()
    }

    fn pad4(mut v: Vec<u8>) -> Vec<u8> {
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        v
    }

    /// Format 1 raw packet header record.
    fn raw(proto: u32, hdr: &[u8]) -> Vec<u8> {
        let h = pad4(hdr.to_vec());
        [u32s(&[1, 16 + h.len() as u32, proto, 1500, 4, hdr.len() as u32]), h].concat()
    }

    fn eth(ty: u16) -> Vec<u8> {
        [&MAC_B[..], &MAC_A[..], &ty.to_be_bytes()[..]].concat()
    }

    fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut h = vec![0x45, 0, 0, 60, 0, 1, 0, 0, 64, proto, 0, 0];
        h.extend_from_slice(&src);
        h.extend_from_slice(&dst);
        h
    }

    fn ipv6(next: u8, src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
        let mut h = vec![0x60, 0, 0, 0, 0, 20, next, 64];
        h.extend_from_slice(&src);
        h.extend_from_slice(&dst);
        h
    }

    fn v6(last: u8) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[0] = 0x20;
        a[1] = 0x01;
        a[2] = 0x0d;
        a[3] = 0xb8;
        a[15] = last;
        a
    }

    fn tcp(sp: u16, dp: u16) -> Vec<u8> {
        [&sp.to_be_bytes()[..], &dp.to_be_bytes()[..], &[0; 8], &[0x50, 0x10, 0xff, 0xff, 0, 0, 0, 0]].concat()
    }

    fn udp(sp: u16, dp: u16) -> Vec<u8> {
        [&sp.to_be_bytes()[..], &dp.to_be_bytes()[..], &[0, 8, 0, 0][..]].concat()
    }

    fn icmp(t: u8, c: u8) -> Vec<u8> {
        vec![t, c, 0, 0, 0, 0, 0, 0]
    }

    /// Format 2 Ethernet frame record.
    fn eth_record(src: [u8; 6], dst: [u8; 6]) -> Vec<u8> {
        [u32s(&[2, 28, 1500]), src.to_vec(), vec![0, 0], dst.to_vec(), vec![0, 0], u32s(&[0x0800])].concat()
    }

    /// Format 3 IPv4 data record.
    fn ipv4_record(proto: u32, src: [u8; 4], dst: [u8; 4], sp: u32, dp: u32) -> Vec<u8> {
        [u32s(&[3, 32, 100, proto]), src.to_vec(), dst.to_vec(), u32s(&[sp, dp, 0, 0])].concat()
    }

    fn counter_sample() -> Vec<u8> {
        let recs = [u32s(&[1, 8]), vec![0xaa; 8], u32s(&[2, 4]), vec![0xbb; 4]].concat();
        [u32s(&[2, 4 + 4 + 4 + recs.len() as u32, 9, 3, 2]), recs].concat()
    }

    #[test]
    fn ipv4_agent_flow_sample_ethernet_ipv4_tcp() {
        let pkt = [eth(0x0800), ipv4(6, V4_A, V4_B), tcp(50000, 443), vec![1, 2, 3]].concat();
        let (flows, marks) = run(v4dg(&[flow_sample(1, &[raw(1, &pkt)])]));
        assert_eq!(marks, 1);
        assert_eq!(flows.len(), 1);
        let f = &flows[0];
        assert_eq!((f.transport.as_str(), f.seq_id.as_str(), f.key.device_addr.as_str()), ("udp", "s1", "192.0.2.9"));
        assert_eq!((f.key.src_ip.as_str(), f.key.dst_ip.as_str()), ("10.0.0.1", "10.0.0.2"));
        assert_eq!((f.src_port, f.key.dst_port, f.key.protocol, f.key.ip_version), (50000, 443, 6, 4));
        assert_eq!((f.key.src_mac.as_str(), f.key.dst_mac.as_str()), ("00:1B:21:AA:BB:CC", "02:00:00:00:00:01"));
        assert_eq!((f.flows, f.octets), (1, 0)); // as in FlowLink, no sampling-rate scaling, Octets 0
        assert_eq!(f.direction_ind, 0); // 2 normalised by the flow filter
        assert!(f.flow_time > 0);
    }

    #[test]
    fn ipv6_agent_expanded_sample_vlan_udp() {
        let pkt = [eth(0x8100), vec![0x00, 0x0a, 0x08, 0x00], ipv4(17, V4_A, V4_B), udp(40000, 53)].concat();
        let (flows, marks) = run(datagram(2, &v6(1), &[flow_sample(3, &[raw(1, &pkt)])]));
        assert_eq!(marks, 1);
        assert_eq!(flows.len(), 1);
        assert_eq!((flows[0].src_port, flows[0].key.dst_port, flows[0].key.protocol), (40000, 53, 17));
    }

    #[test]
    fn agent_addr_type_other_than_one_reads_16_bytes() {
        // as in FlowLink, agent address type 0 reads 16 bytes; a 4-byte agent address misaligns and nothing decodes.
        let pkt = [eth(0x0800), ipv4(17, V4_A, V4_B), udp(40000, 53)].concat();
        let (flows, _) = run(datagram(0, &[192, 0, 2, 1], &[flow_sample(1, &[raw(1, &pkt)])]));
        assert!(flows.is_empty());
    }

    #[test]
    fn qinq_is_not_unwrapped() {
        let pkt = [eth(0x8100), vec![0, 10, 0x81, 0x00], vec![0, 20, 0x08, 0x00], ipv4(17, V4_A, V4_B), udp(1, 2)].concat();
        assert!(run(v4dg(&[flow_sample(1, &[raw(1, &pkt)])])).0.is_empty());
    }

    #[test]
    fn ethernet_ipv6_tcp() {
        let pkt = [eth(0x86dd), ipv6(6, v6(1), v6(2)), tcp(50001, 22)].concat();
        let (flows, _) = run(v4dg(&[flow_sample(1, &[raw(1, &pkt)])]));
        assert_eq!(flows.len(), 1);
        let f = &flows[0];
        assert_eq!((f.key.src_ip.as_str(), f.key.dst_ip.as_str(), f.key.ip_version), ("2001:db8::1", "2001:db8::2", 6));
        assert_eq!((f.src_port, f.key.dst_port, f.key.protocol), (50001, 22, 6));
    }

    #[test]
    fn ipv6_fragment_header_is_parsed_correctly() {
        let frag = vec![17, 0, 0, 0, 0, 0, 0, 1];
        let pkt = [eth(0x86dd), ipv6(44, v6(1), v6(2)), frag, udp(40000, 53)].concat();
        let (flows, _) = run(v4dg(&[flow_sample(1, &[raw(1, &pkt)])]));
        assert_eq!((flows[0].src_port, flows[0].key.dst_port, flows[0].key.protocol), (40000, 53, 17));
    }

    #[test]
    fn ipv6_ext_header_len_bug_is_preserved() {
        // as in FlowLink, routing header (43) with HdrExtLen=1 is 16 bytes, but only 2 are skipped
        // (header bytes = 1-1 = 0), so the UDP ports come from routing-header bytes 2..6.
        let rh = vec![17, 1, 0x9c, 0x40, 0x00, 0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let pkt = [eth(0x86dd), ipv6(43, v6(1), v6(2)), rh, udp(1111, 2222)].concat();
        let (flows, _) = run(v4dg(&[flow_sample(1, &[raw(1, &pkt)])]));
        assert_eq!((flows[0].src_port, flows[0].key.dst_port, flows[0].key.protocol), (40000, 53, 17));

        // HdrExtLen=0 -> 255 header bytes > remaining: no flow, but the datagram continues.
        let hbh = vec![17, 0, 0, 0, 0, 0, 0, 0];
        let pkt = [eth(0x86dd), ipv6(0, v6(1), v6(2)), hbh, udp(1111, 2222)].concat();
        let ok = [eth(0x0800), ipv4(17, V4_A, V4_B), udp(40000, 53)].concat();
        let (flows, _) = run(v4dg(&[flow_sample(1, &[raw(1, &pkt), raw(1, &ok)])]));
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].key.ip_version, 4);
    }

    #[test]
    fn bare_ipv4_icmp_and_ipv4_options() {
        let mut ip = ipv4(1, V4_A, V4_B);
        ip[0] = 0x46; // IHL 6: 4 option bytes
        let pkt = [ip, vec![1, 1, 1, 1], icmp(8, 0)].concat();
        let (flows, _) = run(v4dg(&[flow_sample(1, &[raw(11, &pkt)])]));
        let f = &flows[0];
        assert_eq!((f.key.protocol, f.key.icmp_type, f.key.icmp_code, f.key.dst_port), (1, 8, 0, 0));
        assert_eq!(f.key.src_mac, "");
    }

    #[test]
    fn bare_ipv6_raw_header_emits_nothing() {
        let pkt = [ipv6(6, v6(1), v6(2)), tcp(1, 2)].concat();
        assert!(run(v4dg(&[flow_sample(1, &[raw(12, &pkt)])])).0.is_empty());
    }

    #[test]
    fn record_mutations_carry_over_within_sample_only() {
        // as in FlowLink, format-2 MACs and format-3 source port leak into later records of the same sample.
        let icmp_pkt = [ipv4(1, V4_B, V4_A), icmp(0, 0)].concat();
        let s1 = flow_sample(
            1,
            &[eth_record(MAC_A, MAC_B), ipv4_record(17, V4_A, V4_B, 50000, 53), raw(11, &icmp_pkt)],
        );
        let s2 = flow_sample(1, &[raw(11, &icmp_pkt)]);
        let (flows, marks) = run(v4dg(&[s1, s2]));
        assert_eq!(marks, 4);
        assert_eq!(flows.len(), 3);
        let (f3, f_icmp, f_next) = (&flows[0], &flows[1], &flows[2]);
        assert_eq!((f3.key.protocol, f3.src_port, f3.key.dst_port), (17, 50000, 53));
        assert_eq!(f3.key.src_mac, "00:1B:21:AA:BB:CC");
        assert_eq!((f3.key.icmp_type, f3.key.icmp_code), (0, 0));
        assert_eq!((f_icmp.key.protocol, f_icmp.src_port, f_icmp.key.dst_port), (1, 50000, 0));
        assert_eq!(f_icmp.key.dst_mac, "02:00:00:00:00:01");
        assert_eq!((f_next.src_port, f_next.key.src_mac.as_str()), (0, ""));
    }

    #[test]
    fn counter_and_unknown_samples_are_skipped() {
        let pkt = [ipv4(17, V4_A, V4_B), udp(40000, 53)].concat();
        let unknown = [u32s(&[5, 20, 1, 0, 0]), vec![0xee; 8]].concat();
        let (flows, marks) = run(v4dg(&[counter_sample(), unknown, flow_sample(1, &[raw(11, &pkt)])]));
        assert_eq!(marks, 1);
        assert_eq!(flows.len(), 1);
    }

    #[test]
    fn extended_and_unknown_flow_records_are_skipped() {
        let pkt = [ipv4(17, V4_A, V4_B), udp(40000, 53)].concat();
        let sw = u32s(&[1001, 16, 10, 0, 20, 0]);
        let rt4 = u32s(&[1002, 16, 1, 0x0a000001, 24, 24]);
        let unk = [u32s(&[4, 8]), vec![0; 8]].concat();
        let ent = [u32s(&[(9 << 12) | 1, 4]), vec![0; 4]].concat();
        let (flows, marks) = run(v4dg(&[flow_sample(1, &[sw, rt4, unk, ent, raw(11, &pkt)])]));
        assert_eq!(marks, 5);
        assert_eq!(flows.len(), 1);
    }

    #[test]
    fn version_not_5_is_ignored() {
        let pkt = [ipv4(17, V4_A, V4_B), udp(40000, 53)].concat();
        let mut d = v4dg(&[flow_sample(1, &[raw(11, &pkt)])]);
        d[3] = 4;
        assert_eq!(run(d), (vec![], 0));
    }

    #[test]
    fn arp_llc_nlb_emit_nothing_but_continue() {
        let ok = raw(11, &[ipv4(17, V4_A, V4_B), udp(40000, 53)].concat());
        let arp = raw(1, &[eth(0x0806), vec![0; 28]].concat());
        let llc = raw(1, &[eth(0x0040), vec![0x42, 0x42, 3]].concat());
        let nlb = raw(1, &[eth(0x886f), vec![0; 20]].concat());
        let rarp = raw(1, &[eth(0x8035), vec![0; 28]].concat());
        let (flows, _) = run(v4dg(&[flow_sample(1, &[arp, llc, nlb, rarp, ok])]));
        assert_eq!(flows.len(), 1);
    }

    #[test]
    fn false_returns_abort_the_datagram() {
        let next = flow_sample(1, &[raw(11, &[ipv4(17, V4_A, V4_B), udp(40000, 53)].concat())]);
        // Protocol 0 over IPv4: "Invalid protocol for IPv4:".
        let bad = flow_sample(1, &[raw(11, &[ipv4(0, V4_A, V4_B), vec![0; 8]].concat())]);
        assert!(run(v4dg(&[bad, next.clone()])).0.is_empty());
        // ICMPv6 over IPv4.
        let bad = flow_sample(1, &[raw(11, &[ipv4(58, V4_A, V4_B), icmp(1, 0)].concat())]);
        assert!(run(v4dg(&[bad, next.clone()])).0.is_empty());
        // TCP with fewer than 18 bytes.
        let bad = flow_sample(1, &[raw(11, &[ipv4(6, V4_A, V4_B), vec![0; 12]].concat())]);
        assert!(run(v4dg(&[bad, next.clone()])).0.is_empty());
        // Truncated counter record (length not clamped, as in FlowLink).
        let bad_ctr = [u32s(&[2, 12, 1, 3, 1, 1, 100]), vec![0; 4]].concat();
        assert!(run(v4dg(&[bad_ctr, next.clone()])).0.is_empty());
        // Sanity: `next` alone emits.
        assert_eq!(run(v4dg(&[next])).0.len(), 1);
    }

    #[test]
    fn no_bytes_after_ip_header_or_proto_59_emit_nothing() {
        assert!(run(v4dg(&[flow_sample(1, &[raw(11, &ipv4(17, V4_A, V4_B))])])).0.is_empty());
        let pkt = [eth(0x86dd), ipv6(59, v6(1), v6(2)), vec![0; 4]].concat();
        assert!(run(v4dg(&[flow_sample(1, &[raw(1, &pkt)])])).0.is_empty());
    }

    #[test]
    fn short_udp_is_read_piecewise() {
        let pkt = [ipv4(17, V4_A, V4_B), vec![0x9c, 0x40, 0x00, 0x35, 0x00]].concat();
        let (flows, _) = run(v4dg(&[flow_sample(1, &[raw(11, &pkt)])]));
        assert_eq!((flows[0].src_port, flows[0].key.dst_port), (40000, 53));
    }

    #[test]
    fn other_protocol_emits_with_zero_ports() {
        let pkt = [ipv4(47, V4_A, V4_B), vec![0; 4]].concat();
        let (flows, _) = run(v4dg(&[flow_sample(1, &[raw(11, &pkt)])]));
        assert_eq!((flows[0].key.protocol, flows[0].key.dst_port), (47, 0));
    }

    #[test]
    fn malformed_input_never_panics() {
        let pkt = [eth(0x86dd), ipv6(43, v6(1), v6(2)), vec![17, 1, 0, 0], tcp(1, 2)].concat();
        let good = v4dg(&[counter_sample(), flow_sample(3, &[eth_record(MAC_A, MAC_B), raw(1, &pkt)])]);
        for n in 0..good.len() {
            run(good[..n].to_vec());
        }
        // Raw record with a header length below 16, and huge lengths everywhere.
        let small = [u32s(&[1, 3, 1, 0, 0, 0])].concat();
        run(v4dg(&[flow_sample(1, &[small])]));
        let huge = [u32s(&[1, u32::MAX, 1, 0, 0, 0])].concat();
        run(v4dg(&[flow_sample(1, &[huge])]));
        run(v4dg(&[[u32s(&[2, 12, 1, 3, 1, 1, u32::MAX])].concat()]));
        run(v4dg(&[[u32s(&[77, 0, 1, 0, 0])].concat(), vec![0; 20]]));
        run(v4dg(&[flow_sample(1, &[u32s(&[1002, 0, 9])])]));
        // Many 2-byte extension headers: must not recurse deeply.
        let mut chain = [eth(0x86dd), ipv6(0, v6(1), v6(2))].concat();
        chain.extend(std::iter::repeat_n([0u8, 1], 30000).flatten());
        run(v4dg(&[flow_sample(1, &[raw(1, &chain)])]));
        // Oversized datagram and pseudo-random garbage.
        let mut big = good.clone();
        big.resize(70000, 0);
        run(big);
        let mut x: u32 = 0x1234_5678;
        for _ in 0..2000 {
            let mut d = v4dg(&[]);
            d.truncate(28);
            d[27] = 4;
            for _ in 0..(x % 200) {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                d.push((x >> 16) as u8 % 8);
            }
            run(d);
        }
    }

    #[test]
    fn go_ip_text() {
        assert_eq!(go_ip(&[10, 1, 2, 3]), "10.1.2.3");
        assert_eq!(go_ip(&v6(1)), "2001:db8::1");
        let mut m = [0u8; 16];
        m[10] = 0xff;
        m[11] = 0xff;
        m[12..].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(go_ip(&m), "1.2.3.4");
    }

    #[test]
    fn parser_interface_and_workers() {
        let (c, rx) = ctx();
        let p = Arc::new(SflowParser { ctx: c.clone() });
        assert_eq!((p.type_name(), p.default_port()), ("sflow", 6343));
        assert!(p.supports_connector("udp"));
        assert!(!p.supports_connector("tcp") && !p.supports_connector("kafka"));
        let tx = p.start_workers(2);
        assert_eq!(tx.capacity(), Some(20));
        let pkt = [ipv4(17, V4_A, V4_B), udp(40000, 53)].concat();
        let pd = ReceivedDatagram { device_addr: "d".into(), buf: v4dg(&[flow_sample(1, &[raw(11, &pkt)])]), ..Default::default() };
        tx.send(pd).unwrap();
        let f = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(f.key.device_addr, "d");
    }

    #[test]
    fn stats_per_datagram() {
        let stats = register_collector("sflow-stats", "sflow");
        let (tx, _rx) = crossbeam_channel::unbounded();
        let c = ParserContext::new(Meter::new(), FlowSink::new(tx), stats.clone());
        let pd = |buf| ReceivedDatagram { device_addr: "192.0.2.10".into(), seq_id: String::new(), transport: "udp".into(), buf };
        let rec = ipv4_record(6, V4_A, V4_B, 50000, 443);
        // Two flow samples of 2 and 1 declared records, plus a counter sample.
        let d = v4dg(&[flow_sample(1, &[rec.clone(), rec.clone()]), counter_sample(), flow_sample(3, &[rec])]);
        decode_datagram("sflow", &pd(d.clone()), &c);
        decode_datagram("sflow", &pd(u32s(&[4, 1])), &c); // not version 5
        decode_datagram("sflow", &pd(d[..d.len() - 4].to_vec()), &c); // last record cut short
        let row = stats.exporters(SystemTime::now()).remove(0);
        assert_eq!(row.protocols, [Proto::Sflow]);
        // flows = records handed to the filter (3 + 2); the meter counts declared records, as in FlowLink.
        assert_eq!((row.datagrams, row.flows, row.decode_errors), (3, 5, 2));
        assert_eq!(c.meter.count(), 6);
        assert_eq!(stats.counters().flows, 5);
        assert_eq!(stats.counters().forwarded, 5);
    }

    #[test]
    fn setup_without_connectors_fails() {
        let (c, _rx) = ctx();
        let props: Properties = [("x".to_string(), "1".to_string())].into();
        assert!(!setup(&props, &[], c));
    }
}
