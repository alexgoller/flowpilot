//! NetFlow v5/v7/v9 parser (docs/collectors.md). v9 records
//! are decoded by the shared `decode_data_set` in ipfix.rs; v10 on this port takes the IPFIX path.

use std::net::Ipv4Addr;
use std::sync::{Arc, LazyLock};
use std::thread;

use crossbeam_channel::{bounded, Receiver, Sender};

use crate::config::{Info, Properties};
use crate::flow::{icmp_from_dst_port, FlowData, FlowKey, FlowSink};
use crate::log::{check_error, debug_hex, note_decode_error, take_decode_errors};
use crate::log_line;
use crate::parsers::ipfix::{
    be16, be32, malformed_data_set, decode_ipfix_message, decode_data_set, ReadError, Reader, Stamp, TemplateKey, FieldSpec,
    TemplateStore, V10Header,
};
use crate::parsers::{connect_all, Parser, ParserContext, ReceivedDatagram};
use crate::stats::{CollectorStats, Proto, ThreadGuard};

/// The NetFlow v9 template store (process-wide, separate from the IPFIX store).
pub(crate) static NETFLOW_STORE: LazyLock<TemplateStore> = LazyLock::new(TemplateStore::default);

/// Sets up the NetFlow parser and its connectors.
pub fn setup(properties: &Properties, connectors: &[Info], ctx: ParserContext) -> bool {
    for k in properties.keys() {
        log_line!("Unsupported netflow parser property:", k);
    }
    connect_all(Arc::new(NetflowParser { ctx }), connectors)
}

/// The NetFlow parser.
pub struct NetflowParser {
    ctx: ParserContext,
}

/// Per-worker "log once" flags, never reset, as in FlowLink.
struct OnceFlags {
    ipfix: bool,
    bad_version: bool,
}

impl Default for OnceFlags {
    fn default() -> Self {
        Self { ipfix: true, bad_version: true }
    }
}

impl NetflowParser {
    /// Decodes one datagram synchronously (for `parsers::decode_datagram`).
    pub(crate) fn decode_one(ctx: &ParserContext, pd: &ReceivedDatagram) {
        Self { ctx: ctx.clone() }.handle(pd, &mut OnceFlags::default());
    }

    /// Worker loop. Divergence: the loop ends when the channel is closed instead of spinning.
    fn parse(&self, rx: Receiver<ReceivedDatagram>) {
        let mut once = OnceFlags::default();
        for pd in rx.iter() {
            self.handle(&pd, &mut once);
        }
    }

    /// One iteration of the worker loop, counted in the collector stats.
    fn handle(&self, pd: &ReceivedDatagram, once: &mut OnceFlags) {
        take_decode_errors(); // errors before this datagram are not its own
        let (proto, n) = self.decode(pd, once);
        self.ctx.stats.datagram(&pd.device_addr, proto, pd.buf.len(), n.into(), take_decode_errors());
    }

    /// Decode one datagram: the protocol seen (if any) and the records sent (what is metered).
    fn decode(&self, pd: &ReceivedDatagram, once: &mut OnceFlags) -> (Option<Proto>, u16) {
        let mut r = Reader::new(&pd.buf);
        let h: [u8; 12] = match r.array() {
            Ok(h) => h,
            Err(e) => {
                check_error(Some(e));
                return (None, 0);
            }
        };
        let (version, count, sys_uptime, unix_secs) = (be16(&h, 0), be16(&h, 2), be32(&h, 4), be32(&h, 8));
        let (dev, transport, sink) = (pd.device_addr.as_str(), pd.transport.as_str(), &self.ctx.sink);
        let (proto, n) = match version {
            5 | 7 => {
                let proto = if version == 5 { Proto::NetflowV5 } else { Proto::NetflowV7 };
                (proto, decode_v5_v7_packet(dev, transport, version, count, sys_uptime, unix_secs, &mut r, sink))
            }
            9 => {
                let s: [u8; 8] = match r.array() {
                    Ok(s) => s,
                    Err(e) => {
                        check_error(Some(e));
                        return (Some(Proto::NetflowV9), 0);
                    }
                };
                let h9 = V9Header { count, sys_uptime, unix_secs, seq: be32(&s, 0), source_id: be32(&s, 4) };
                (Proto::NetflowV9, decode_v9_packet(dev, transport, &h9, &mut r, sink))
            }
            10 => {
                if once.ipfix {
                    log_line!("Netflow parser handling misdirected Ipfix data from", dev);
                }
                once.ipfix = false; // reset even when the read below fails, so the message is logged once
                let domain = match r.u32() {
                    Ok(d) => d,
                    Err(e) => {
                        check_error(Some(e));
                        return (Some(Proto::Ipfix), 0);
                    }
                };
                // Same wire bytes reinterpreted as the IPFIX header, as in FlowLink.
                let hdr = V10Header { export_time: sys_uptime, seq: unix_secs, domain };
                (Proto::Ipfix, decode_ipfix_message(dev, transport, hdr, &mut r, sink))
            }
            _ => {
                if once.bad_version {
                    log_line!("Ignoring Netflow version", version, "from", dev);
                    once.bad_version = false;
                }
                note_decode_error();
                return (None, 0);
            }
        };
        self.ctx.meter.mark(n.into());
        (Some(proto), n)
    }
}

impl Parser for NetflowParser {
    fn type_name(&self) -> &'static str {
        "netflow"
    }

    fn default_port(&self) -> u16 {
        2055
    }

    fn supports_connector(&self, conn_type: &str) -> bool {
        conn_type == "udp"
    }

    fn stats(&self) -> Arc<CollectorStats> {
        self.ctx.stats.clone()
    }

    fn start_workers(self: Arc<Self>, n: usize) -> Sender<ReceivedDatagram> {
        let (tx, rx) = bounded(n.saturating_mul(10));
        for _ in 0..n {
            let (p, rx) = (self.clone(), rx.clone());
            thread::spawn(move || {
                let _guard = ThreadGuard::core("netflow parser");
                p.parse(rx)
            });
        }
        tx
    }
}

/// NetFlow v5/v7: fixed 48-byte records (v7: plus 4 skipped bytes). Returns the number
/// of loop iterations completed, as in FlowLink.
#[allow(clippy::too_many_arguments)]
fn decode_v5_v7_packet(
    dev: &str,
    transport: &str,
    version: u16,
    count: u16,
    sys_uptime: u32,
    unix_secs: u32,
    r: &mut Reader,
    sink: &FlowSink,
) -> u16 {
    let h: [u8; 12] = r.array().unwrap_or([0; 12]); // error ignored, as in FlowLink
    let seq_id = be32(&h, 4).to_string();
    // Go time.Unix(secs, nsec).Unix(): nsec >= 1e9 is folded into the seconds, as in FlowLink.
    let unix_t = i64::from(unix_secs) + i64::from(be32(&h, 0) / 1_000_000_000);
    let mut i = 0u16;
    while i < count && r.remaining() >= 48 {
        let rec: [u8; 48] = match r.array() {
            Ok(b) => b,
            Err(e) => {
                check_error(Some(e));
                return i;
            }
        };
        debug_hex("record:", &rec);
        let ip = |o: usize| Ipv4Addr::new(rec[o], rec[o + 1], rec[o + 2], rec[o + 3]).to_string();
        let mut fd = FlowData {
            transport: transport.into(),
            seq_id: seq_id.clone(),
            key: FlowKey {
                device_addr: dev.into(),
                src_ip: ip(0),
                dst_ip: ip(4),
                dst_port: be16(&rec, 34),
                ip_version: 4,
                protocol: rec[38],
                src_mask: rec[44],
                dst_mask: rec[45],
                ..Default::default()
            },
            src_port: be16(&rec, 32),
            flow_time: unix_t - i64::from(sys_uptime.wrapping_sub(be32(&rec, 24)) / 1000),
            flows: 1,
            octets: be32(&rec, 20).into(),
            direction_ind: 0,
        };
        // Divergence ("ICMP type/code in the destination port"): v5 has no ICMP field; type/code are in the port.
        icmp_from_dst_port(&mut fd.key);
        sink.send(fd);
        if version == 7 {
            if let Err(e) = r.read(4) {
                check_error(Some(e));
                return i; // as in FlowLink: the record above was already sent
            }
        }
        i += 1;
    }
    i
}

/// The v9 header fields the parser uses (common header + v9-specific part).
pub(crate) struct V9Header {
    pub count: u16,
    pub sys_uptime: u32,
    pub unix_secs: u32,
    pub seq: u32,
    pub source_id: u32,
}

/// Parse the FlowSets of one v9 packet. Returns records sent (u16, wraps, as in FlowLink).
pub(crate) fn decode_v9_packet(dev: &str, transport: &str, h: &V9Header, r: &mut Reader, sink: &FlowSink) -> u16 {
    let mut total = 0u16;
    if let Err(e) = read_v9_flowsets(dev, transport, h, r, sink, &mut total) {
        check_error(Some(e));
    }
    total
}

fn read_v9_flowsets(dev: &str, transport: &str, h: &V9Header, r: &mut Reader, sink: &FlowSink, total: &mut u16) -> Result<(), ReadError> {
    // Whole seconds of the exporter clock, or local now when unix_secs is 0.
    let t = if h.unix_secs != 0 { Stamp::from_unix(h.unix_secs) } else { Stamp::now() };
    let key = |template_id| TemplateKey { device_addr: dev.into(), domain: h.source_id, template_id };
    // As in FlowLink, FlowSets are counted against the header's record count.
    let mut i = 0u16;
    while i < h.count && r.remaining() >= 4 {
        i += 1;
        let (set_id, len) = r.pair()?;
        match set_id {
            0 => {
                // Divergence: the FlowSet length bounds the templates, and padding after the last
                // one is skipped instead of being read as more templates.
                let end = r.pos() + usize::from(len.saturating_sub(4));
                while end.saturating_sub(r.pos()) >= 4 {
                    let (tid, field_count) = r.pair()?;
                    if tid < 256 {
                        break; // padding
                    }
                    let fields = (0..field_count)
                        .map(|_| r.pair().map(|(id, len)| FieldSpec { id, len }))
                        .collect::<Result<Vec<_>, _>>()
                        ?;
                    if r.pos() > end {
                        break; // the field list overruns the FlowSet: not a template
                    }
                    *total = total.wrapping_add(NETFLOW_STORE.learn(key(tid), fields, sink));
                }
                r.seek_to(end);
            }
            1 => {
                log_line!("Ignoring Netflow SetID", set_id);
                r.seek(len.wrapping_sub(4).into());
            }
            2..=255 => {
                log_line!("Ignoring invalid Netflow SetID", set_id);
                r.seek(len.wrapping_sub(4).into());
            }
            _ => {
                let data_len = len.wrapping_sub(4);
                match NETFLOW_STORE.get(&key(set_id)) {
                    Some(_) if malformed_data_set(set_id, len, r) => return Ok(()),
                    Some(f) => {
                        let n = decode_data_set(dev, transport, h.seq, t.unix(), h.sys_uptime, &f, r, data_len, sink);
                        *total = total.wrapping_add(n);
                    }
                    None => NETFLOW_STORE.stash(key(set_id), transport, h.seq, t, h.sys_uptime, r, data_len)?,
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::decode_datagram;
    use crate::parsers::ipfix::tests::{ctx, ctx_with, now_secs, pd, set, tmpl, B};
    use crate::parsers::ipfix::{IpfixParser, OnceFlags as IpfixOnce};
    use crate::stats::{register_collector, CollectorStats, ExporterSnapshot, Proto};
    use std::time::SystemTime;
    use crossbeam_channel::Receiver;

    fn parser() -> (NetflowParser, Receiver<FlowData>) {
        let (ctx, rx) = ctx();
        (NetflowParser { ctx }, rx)
    }

    fn run(p: &NetflowParser, dev: &str, buf: Vec<u8>) {
        p.handle(&pd(dev, buf), &mut OnceFlags::default());
    }

    fn flows(rx: &Receiver<FlowData>) -> Vec<FlowData> {
        rx.try_iter().collect()
    }

    /// v5/v7 header: common (12 B) + specific (12 B).
    fn v5_header(version: u16, count: u16, uptime: u32, secs: u32, nsec: u32, seq: u32) -> B {
        B::default().u16(version).u16(count).u32(uptime).u32(secs).u32(nsec).u32(seq).u32(0)
    }

    fn v5_record(src: [u8; 4], dst: [u8; 4], first: u32) -> B {
        B::default()
            .bytes(&src)
            .bytes(&dst)
            .bytes(&[0; 4]) // next hop
            .u16(1)
            .u16(2) // ifindexes
            .u32(10) // packets
            .u32(5000) // octets
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

    fn v5_expected(dev: &str, src: &str, dst: &str, flow_time: i64) -> FlowData {
        FlowData {
            transport: "udp".into(),
            seq_id: "42".into(),
            key: FlowKey {
                device_addr: dev.into(),
                src_ip: src.into(),
                dst_ip: dst.into(),
                dst_port: 443,
                ip_version: 4,
                protocol: 6,
                src_mask: 24,
                dst_mask: 16,
                ..Default::default()
            },
            src_port: 50000,
            flow_time,
            flows: 1,
            octets: 5000,
            direction_ind: 0,
        }
    }

    fn v9_header(count: u16, uptime: u32, secs: u32, seq: u32, source_id: u32) -> B {
        B::default().u16(9).u16(count).u32(uptime).u32(secs).u32(seq).u32(source_id)
    }

    /// 8 fields, 27-byte records, incl. IN_PKTS (2, ignored) and FIRST_SWITCHED.
    const T9: &[(u16, u16)] = &[(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (22, 4), (2, 4)];

    fn t9_record(src: [u8; 4], dst: [u8; 4], first: u32) -> B {
        B::default().bytes(&src).bytes(&dst).u16(50000).u16(443).u8(17).u32(900).u32(first).u32(3)
    }

    fn t9_expected(dev: &str, seq: &str, src: &str, dst: &str, flow_time: i64) -> FlowData {
        FlowData {
            transport: "udp".into(),
            seq_id: seq.into(),
            key: FlowKey {
                device_addr: dev.into(),
                src_ip: src.into(),
                dst_ip: dst.into(),
                dst_port: 443,
                ip_version: 4,
                protocol: 17,
                ..Default::default()
            },
            src_port: 50000,
            flow_time,
            flows: 1,
            octets: 900,
            direction_ind: 0, // 2 from the decoder, normalised by the flow filter
        }
    }

    #[test]
    fn parser_contract() {
        let (p, _rx) = parser();
        assert_eq!((p.type_name(), p.default_port()), ("netflow", 2055));
        assert!(p.supports_connector("udp") && !p.supports_connector("kafka"));
        let (ctx, _rx) = ctx();
        let props = Properties::from([("x".to_string(), "y".to_string())]);
        assert!(!setup(&props, &[Info { kind: "tcp".into(), properties: Properties::new() }], ctx));
        assert!(!setup(&Properties::new(), &[], parser().0.ctx.clone()));
    }

    #[test]
    fn v5_icmp_type_code_from_the_destination_port() {
        let (p, rx) = parser();
        let dev = "203.0.113.160";
        let icmp = |dport: u16| {
            let mut r = v5_record([10, 2, 0, 1], [10, 2, 0, 2], 40_000).0;
            r[32..36].copy_from_slice(&[0, 0, (dport >> 8) as u8, dport as u8]);
            r[38] = 1;
            r
        };
        let m = v5_header(5, 3, 100_000, 1_700_000_000, 0, 42).bytes(&icmp(0x0303)).bytes(&icmp(0)).bytes(&icmp(8)).0;
        run(&p, dev, m);
        let k: Vec<_> = flows(&rx).iter().map(|f| (f.key.icmp_type, f.key.icmp_code, f.key.dst_port)).collect();
        assert_eq!(k, [(3, 3, 0), (0, 0, 0), (8, 0, 0)]);
    }

    #[test]
    fn v9_icmp_type_code_from_the_destination_port() {
        let (p, rx) = parser();
        let f = [(8, 4), (12, 4), (4, 1), (11, 2)];
        let rec = B::default().bytes(&[10, 2, 0, 1]).bytes(&[10, 2, 0, 2]).u8(58).u16(0x8100).0;
        let m = v9_header(2, 100_000, 1_700_000_000, 1, 0).bytes(&set(0, &tmpl(256, &f))).bytes(&set(256, &rec)).0;
        run(&p, "203.0.113.161", m);
        let k: Vec<_> = flows(&rx).iter().map(|f| (f.key.icmp_type, f.key.icmp_code, f.key.dst_port)).collect();
        assert_eq!(k, [(129, 0, 0)]);
    }

    #[test]
    fn v5_records() {
        let (p, rx) = parser();
        let dev = "203.0.113.1";
        // nsec 2.5e9 folds two seconds into unix_secs (Go time.Unix normalisation).
        let m = v5_header(5, 2, 100_000, 1_700_000_000, 2_500_000_000, 42)
            .bytes(&v5_record([10, 2, 0, 1], [10, 2, 0, 2], 40_000).0)
            .bytes(&v5_record([10, 2, 0, 3], [224, 0, 0, 5], 200_000).0); // multicast: dropped by the sink
        run(&p, dev, m.0);
        let got = flows(&rx);
        assert_eq!(got.len(), 1, "both records are counted; the sink drops the multicast one");
        assert_eq!(got[0], v5_expected(dev, "10.2.0.1", "10.2.0.2", 1_700_000_002 - 60));
        assert_eq!(p.ctx.meter.count(), 2);
    }

    #[test]
    fn v5_uptime_wraps_in_32_bits() {
        let (p, rx) = parser();
        let m = v5_header(5, 1, 1_000, 1_700_000_000, 0, 42).bytes(&v5_record([10, 2, 1, 1], [10, 2, 1, 2], 2_000).0);
        run(&p, "203.0.113.2", m.0);
        assert_eq!(flows(&rx)[0].flow_time, 1_700_000_000 - i64::from(1_000u32.wrapping_sub(2_000) / 1000));
    }

    #[test]
    fn v7_records_and_truncated_trailer() {
        let (p, rx) = parser();
        let dev = "203.0.113.3";
        let rec = |a| v5_record([10, 2, 2, a], [10, 2, 2, 9], 100_000).u32(0xdead_beef).0;
        let m = v5_header(7, 2, 100_000, 1_700_000_000, 0, 42).bytes(&rec(1)).bytes(&rec(2));
        run(&p, dev, m.0);
        let got = flows(&rx);
        assert_eq!(got.iter().map(|f| f.key.src_ip.as_str()).collect::<Vec<_>>(), ["10.2.2.1", "10.2.2.2"]);
        assert_eq!(p.ctx.meter.count(), 2);
        // The record is sent, but the failed 4-byte trailer read returns i (= 0).
        let m = v5_header(7, 1, 100_000, 1_700_000_000, 0, 42).bytes(&v5_record([10, 2, 2, 3], [10, 2, 2, 9], 0).0);
        run(&p, dev, m.0);
        assert_eq!(flows(&rx).len(), 1);
        assert_eq!(p.ctx.meter.count(), 2);
    }

    #[test]
    fn v5_count_beyond_data_stops() {
        let (p, rx) = parser();
        let m = v5_header(5, 30, 0, 1, 0, 42).bytes(&v5_record([10, 2, 3, 1], [10, 2, 3, 2], 0).0).u16(7);
        run(&p, "203.0.113.4", m.0);
        assert_eq!(flows(&rx).len(), 1);
        assert_eq!(p.ctx.meter.count(), 1);
    }

    #[test]
    fn v9_template_and_data() {
        let (p, rx) = parser();
        let dev = "203.0.113.5";
        let data = [t9_record([10, 4, 0, 1], [10, 4, 0, 2], 4_000).0, vec![0, 0]].concat(); // 2 pad bytes
        let m = v9_header(2, 10_000, 1_700_000_000, 11, 3).bytes(&set(0, &tmpl(256, T9))).bytes(&set(256, &data));
        run(&p, dev, m.0);
        assert_eq!(flows(&rx), vec![t9_expected(dev, "11", "10.4.0.1", "10.4.0.2", 1_700_000_000 - 6)]);
        assert_eq!(p.ctx.meter.count(), 1);
    }

    #[test]
    fn v9_data_flowset_running_past_the_datagram_ends_it_f1() {
        let (p, rx) = parser();
        for (i, len) in [0u16, 3, 200].into_iter().enumerate() {
            let dev = format!("203.0.113.6{i}");
            let m = v9_header(3, 10_000, 1_700_000_000, 11, 3)
                .bytes(&set(0, &tmpl(256, T9)))
                .bytes(&set(256, &t9_record([10, 4, 0, 1], [10, 4, 0, 2], 4_000).0))
                .u16(256)
                .u16(len) // < 4 wraps data_len; 200 is past the end
                .bytes(&[10; 30]);
            crate::log::take_decode_errors();
            let (_, n) = p.decode(&pd(&dev, m.0), &mut OnceFlags::default());
            assert_eq!((n, flows(&rx).len(), crate::log::take_decode_errors()), (1, 1, 1), "Length {len}");
        }
    }

    #[test]
    fn v9_data_before_template_then_replay() {
        let (p, rx) = parser();
        let dev = "203.0.113.6";
        let now = now_secs();
        let data = v9_header(1, 20_000, now, 5, 0).bytes(&set(256, &t9_record([10, 4, 1, 1], [10, 4, 1, 2], 18_000).0));
        run(&p, dev, data.0);
        assert!(flows(&rx).is_empty());
        assert_eq!(NETFLOW_STORE.stored_for(dev), 1);
        // The replay uses the stored sequence number, time and sysUptime, not the template packet's.
        let t = v9_header(1, 99_000, now, 6, 0).bytes(&set(0, &tmpl(256, T9)));
        run(&p, dev, t.0);
        assert_eq!(flows(&rx), vec![t9_expected(dev, "5", "10.4.1.1", "10.4.1.2", i64::from(now) - 2)]);
        assert_eq!(p.ctx.meter.count(), 1);
        assert_eq!(NETFLOW_STORE.stored_for(dev), 0);
    }

    #[test]
    fn v9_options_template_is_skipped() {
        let (p, rx) = parser();
        let dev = "203.0.113.7";
        let m = v9_header(4, 10_000, 1_700_000_000, 1, 0)
            .bytes(&set(1, &[0xab; 12]))
            .bytes(&set(77, &[0xcd; 4])) // invalid SetID 2..255
            .bytes(&set(0, &tmpl(256, T9)))
            .bytes(&set(256, &t9_record([10, 4, 2, 1], [10, 4, 2, 2], 10_000).0));
        run(&p, dev, m.0);
        assert_eq!(flows(&rx).len(), 1);
    }

    #[test]
    fn v9_template_flowset_padding_is_skipped() {
        let (p, rx) = parser();
        let dev = "203.0.113.20";
        let m = v9_header(2, 10_000, 1_700_000_000, 1, 0)
            .bytes(&set(0, &[tmpl(256, T9), vec![0; 2]].concat()))
            .bytes(&set(256, &t9_record([10, 4, 3, 1], [10, 4, 3, 2], 10_000).0));
        run(&p, dev, m.0);
        assert_eq!(flows(&rx).len(), 1);
    }

    #[test]
    fn v9_variable_length_field() {
        // H3C NetStream sends interface names as variable-length strings.
        let (p, rx) = parser();
        let dev = "203.0.113.10";
        let t = tmpl(260, &[(8, 4), (12, 4), (82, 0xffff), (7, 2)]);
        let rec = |a, name: &[u8]| {
            B::default().bytes(&[10, 4, 1, a]).bytes(&[10, 4, 1, 2]).u8(name.len() as u8).bytes(name).u16(53).0
        };
        let data = [rec(1, b"GigabitEthernet1/0/1"), rec(2, b""), vec![0, 0]].concat();
        let m = v9_header(2, 10_000, 1_700_000_000, 4, 0).bytes(&set(0, &t)).bytes(&set(260, &data));
        run(&p, dev, m.0);
        let got: Vec<(String, u16)> = flows(&rx).into_iter().map(|f| (f.key.src_ip, f.src_port)).collect();
        assert_eq!(got, [("10.4.1.1".to_string(), 53), ("10.4.1.2".to_string(), 53)]);
    }

    #[test]
    fn v9_flowset_count_bound() {
        let (p, rx) = parser();
        let dev = "203.0.113.8";
        let m = v9_header(1, 10_000, 1_700_000_000, 1, 0)
            .bytes(&set(0, &tmpl(256, T9)))
            .bytes(&set(256, &t9_record([10, 4, 3, 1], [10, 4, 3, 2], 10_000).0));
        run(&p, dev, m.0);
        assert!(flows(&rx).is_empty());
        assert_eq!(NETFLOW_STORE.stored_for(dev), 0, "the second FlowSet is never looked at");
    }

    #[test]
    fn v10_on_netflow_port_uses_ipfix_path() {
        let (p, rx) = parser();
        let dev = "203.0.113.9";
        let fields: &[(u16, u16)] = &[(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (150, 4)];
        let rec = B::default().bytes(&[10, 5, 0, 1]).bytes(&[10, 5, 0, 2]).u16(50000).u16(22).u8(6).u32(64).u32(1_650_000_000).0;
        let body = [set(2, &tmpl(400, fields)), set(400, &[rec.clone(), rec].concat())].concat();
        let m = B::default().u16(10).u16(16 + body.len() as u16).u32(1_600_000_000).u32(8).u32(0).bytes(&body);
        run(&p, dev, m.0);
        let got = flows(&rx);
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].seq_id.as_str(), got[0].flow_time, got[0].octets), ("8", 1_650_000_000, 64));
        assert_eq!(p.ctx.meter.count(), 2);
        assert_eq!(NETFLOW_STORE.stored_for(dev), 0);
    }

    #[test]
    fn v10_on_netflow_port_decodes_small_sets_at_the_end() {
        let (p, rx) = parser();
        let fields: &[(u16, u16)] = &[(8, 4), (12, 4)];
        let body = [set(2, &tmpl(401, fields)), set(401, &B::default().bytes(&[10, 5, 0, 1]).bytes(&[10, 5, 0, 2]).0)].concat();
        let m = B::default().u16(10).u16(16 + body.len() as u16).u32(1_600_000_000).u32(9).u32(0).bytes(&body).bytes(&[0; 3]);
        run(&p, "203.0.113.162", m.0);
        assert_eq!(flows(&rx).len(), 1, "28 bytes of sets and 3 bytes of padding");
    }

    #[test]
    fn v9_on_ipfix_port_uses_netflow_store() {
        let (ctx, rx) = ctx();
        let p = IpfixParser::for_test(ctx.clone());
        let dev = "203.0.113.10";
        let data = v9_header(1, 10_000, now_secs(), 2, 0).bytes(&set(256, &t9_record([10, 4, 4, 1], [10, 4, 4, 2], 10_000).0));
        p.handle(&pd(dev, data.0), &mut IpfixOnce::default());
        assert_eq!(NETFLOW_STORE.stored_for(dev), 1);
        let t = v9_header(1, 10_000, now_secs(), 3, 0).bytes(&set(0, &tmpl(256, T9)));
        p.handle(&pd(dev, t.0), &mut IpfixOnce::default());
        assert_eq!(flows(&rx).len(), 1);
        assert_eq!(ctx.meter.count(), 1);
    }

    #[test]
    fn unknown_versions_are_not_metered() {
        let (p, rx) = parser();
        run(&p, "203.0.113.11", v5_header(1, 1, 0, 0, 0, 0).0);
        run(&p, "203.0.113.11", vec![0, 5]);
        assert!(flows(&rx).is_empty());
        assert_eq!(p.ctx.meter.count(), 0);
    }

    /// One registered collector, fed through `decode_datagram` like the fuzz/conformance entry.
    fn stats_run(name: &str, dev: &str, bufs: &[Vec<u8>]) -> (Arc<CollectorStats>, ExporterSnapshot) {
        let stats = register_collector(name, "netflow");
        let (ctx, _rx) = ctx_with(stats.clone());
        for b in bufs {
            decode_datagram("netflow", &pd(dev, b.clone()), &ctx);
        }
        let row = stats.exporters(SystemTime::now()).into_iter().find(|e| e.address == dev).expect("exporter row");
        (stats, row)
    }

    #[test]
    fn stats_v9_template_and_data() {
        let m = v9_header(2, 10_000, 1_700_000_000, 11, 3)
            .bytes(&set(0, &tmpl(256, T9)))
            .bytes(&set(256, &t9_record([10, 4, 9, 1], [10, 4, 9, 2], 4_000).0))
            .0;
        let (stats, row) = stats_run("stats-v9", "203.0.113.30", std::slice::from_ref(&m));
        assert_eq!(row.protocols, [Proto::NetflowV9]);
        assert_eq!((row.datagrams, row.flows, row.decode_errors), (1, 1, 0));
        let c = stats.counters();
        assert_eq!((c.datagrams, c.bytes, c.flows, c.forwarded, c.decode_errors), (1, m.len() as u64, 1, 1, 0));
    }

    #[test]
    fn stats_truncated_v9_is_one_decode_error() {
        // Header, FlowSet header and template header, then the field list is cut short.
        let m = v9_header(1, 10_000, 1_700_000_000, 1, 0).bytes(&set(0, &tmpl(256, T9))).0;
        let (stats, row) = stats_run("stats-v9-short", "203.0.113.31", &[m[..30].to_vec()]);
        assert_eq!((row.protocols.as_slice(), row.decode_errors), ([Proto::NetflowV9].as_slice(), 1));
        assert_eq!(stats.counters().decode_errors, 1);
    }

    #[test]
    fn stats_v5_and_filter_drops() {
        let m = v5_header(5, 2, 100_000, 1_700_000_000, 0, 42)
            .bytes(&v5_record([10, 2, 9, 1], [10, 2, 9, 2], 40_000).0)
            .bytes(&v5_record([10, 2, 9, 3], [224, 0, 0, 5], 40_000).0)
            .0;
        let (stats, row) = stats_run("stats-v5", "203.0.113.32", &[m]);
        assert_eq!((row.protocols.as_slice(), row.flows), ([Proto::NetflowV5].as_slice(), 2));
        let c = stats.counters();
        assert_eq!((c.flows, c.forwarded, c.dropped_special_address), (2, 1, 1));
    }

    #[test]
    fn stats_ipfix_on_netflow_port() {
        let fields: &[(u16, u16)] = &[(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (150, 4)];
        let rec = B::default().bytes(&[10, 5, 9, 1]).bytes(&[10, 5, 9, 2]).u16(50000).u16(22).u8(6).u32(64).u32(1_650_000_000).0;
        let body = [set(2, &tmpl(401, fields)), set(401, &[rec.clone(), rec].concat())].concat();
        let m = B::default().u16(10).u16(16 + body.len() as u16).u32(1_600_000_000).u32(8).u32(0).bytes(&body).0;
        let (_, row) = stats_run("stats-v10", "203.0.113.33", &[m]);
        assert_eq!((row.protocols.as_slice(), row.flows), ([Proto::Ipfix].as_slice(), 2));
    }

    #[test]
    fn stats_unknown_version_and_short_header() {
        let (stats, row) = stats_run("stats-v1", "203.0.113.34", &[v5_header(1, 1, 0, 0, 0, 0).0, vec![0, 5]]);
        assert!(row.protocols.is_empty());
        assert_eq!((row.datagrams, row.flows, row.decode_errors), (2, 0, 2));
        assert_eq!(stats.counters().decode_errors, 2);
    }

    #[test]
    fn malformed_and_truncated_input_never_panics() {
        let (p, _rx) = parser();
        let dev = "198.18.1.1";
        let v9 = v9_header(3, 10_000, 1_700_000_000, 1, 0)
            .bytes(&set(0, &tmpl(256, &[(8, 4), (12, 4), (1, 3), (3, 2)])))
            .bytes(&set(0, &tmpl(257, &[(8, 4), (12, 4), (3, 1)])))
            .bytes(&set(256, &[0x0a; 30]))
            .0;
        let v9b = v9_header(2, 1, 1, 1, 0).bytes(&set(257, &[0x0a; 30])).bytes(&set(2, &[])).0;
        let v5 = v5_header(7, 2, 1, 1, 1, 1).bytes(&v5_record([10, 0, 0, 1], [10, 0, 0, 2], 0).0).0;
        for m in [v9, v9b, v5] {
            for n in 0..=m.len() {
                run(&p, dev, m[..n].to_vec());
            }
        }
        // Template set with wrapping length and zero-field template + data.
        let m = v9_header(3, 1, 1, 1, 0).bytes(&B::default().u16(0).u16(2).u16(258).u16(0).0).0;
        run(&p, dev, m);
        let m = v9_header(2, 1, 1, 1, 0).bytes(&set(0, &tmpl(259, &[]))).bytes(&set(259, &[1; 40])).0;
        run(&p, dev, m);
        let mut x: u32 = 12345;
        for i in 0..3000u32 {
            let mut b = Vec::new();
            for _ in 0..(i % 160) {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                b.push((x >> 16) as u8);
            }
            if b.len() >= 24 {
                b[0..2].copy_from_slice(&[0, [5u8, 7, 9, 10][i as usize % 4]]);
                b[20..22].copy_from_slice(&[0, (i % 3) as u8]);
            }
            run(&p, dev, b);
        }
    }
}
