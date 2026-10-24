//! Flow records shared by all parsers and the aggregator, plus the flow filter and direction
//! normalisation applied before aggregation.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use crossbeam_channel::Sender;

use crate::stats::{CollectorStats, DropReason};
use crate::{debug_log, log_line};

/// Aggregation key. Equality covers every field, as in FlowLink.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub device_addr: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub ip_version: u8,
    pub protocol: u8,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub src_mac: String,
    pub dst_mac: String,
    pub src_mask: u8,
    pub dst_mask: u8,
}

/// One decoded flow. `flow_time` is unix seconds.
/// `direction_ind`: 0 = forward/in, 1 = reverse/out, 2 = unknown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlowData {
    pub transport: String,
    pub seq_id: String,
    pub key: FlowKey,
    pub src_port: u16,
    pub flow_time: i64,
    pub flows: u32,
    pub octets: i64,
    pub direction_ind: u8,
}

/// Per-key aggregate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlowInfo {
    pub first_flow_time: i64,
    pub flow_count: u32,
    pub flow_in_octets: i64,
    pub flow_out_octets: i64,
}

// Go `%v` struct formatting: fields separated by single spaces inside braces.
impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{{} {} {} {} {} {} {} {} {} {} {} {}}}",
            self.device_addr,
            self.src_ip,
            self.dst_ip,
            self.dst_port,
            self.ip_version,
            self.protocol,
            self.icmp_type,
            self.icmp_code,
            self.src_mac,
            self.dst_mac,
            self.src_mask,
            self.dst_mask
        )
    }
}

impl fmt::Display for FlowData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{{} {} {} {} {} {} {} {}}}",
            self.transport,
            self.seq_id,
            self.key,
            self.src_port,
            self.flow_time,
            self.flows,
            self.octets,
            self.direction_ind
        )
    }
}

impl fmt::Display for FlowInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{{} {} {} {}}}",
            self.first_flow_time, self.flow_count, self.flow_in_octets, self.flow_out_octets
        )
    }
}

/// Go `net.ParseIP`: dotted IPv4 or IPv6 text without zone. IPv4 is returned as-is
/// (Go's 16-byte form is irrelevant here because callers only test membership).
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    s.parse().ok()
}

/// Multicast/broadcast test: IPv4 224.0.0.0/3 or multicast/broadcast
/// MAC; IPv6 ff00::/8 or `33:33` MAC. MAC tests are uppercase and case-sensitive, as in FlowLink.
pub fn is_multicast_or_broadcast(ip: &str, mac: &str) -> bool {
    let p = parse_ip(ip);
    // Go net.IPNet.Contains: IPv4 net matches IPv4 and IPv4-mapped IPv6; the IPv6 net matches neither.
    let v4 = p.and_then(|a| match a {
        IpAddr::V4(v) => Some(v),
        IpAddr::V6(v) => v.to_ipv4_mapped(),
    });
    let in_v4_class_d = v4.is_some_and(|v| v.octets()[0] & 0xe0 == 0xe0);
    let in_v6_class_d = v4.is_none() && matches!(p, Some(IpAddr::V6(v)) if v.octets()[0] == 0xff);
    // strings.Index(ip, x) > 0: found and not at position 0.
    let has = |c: char| ip.find(c).is_some_and(|i| i > 0);
    (has('.') && (in_v4_class_d || mac.starts_with("01:00:5E:") || mac == "FF:FF:FF:FF:FF:FF"))
        || (has(':') && (in_v6_class_d || mac.starts_with("33:33")))
}

/// Handle given to every parser: the flow filter in front of the aggregator channel, counting into the
/// collector's stats (atomics only).
#[derive(Clone)]
pub struct FlowSink {
    tx: Sender<FlowData>,
    stats: Arc<CollectorStats>,
}

impl FlowSink {
    /// A sink counting into unregistered stats; see `with_stats`.
    pub fn new(tx: Sender<FlowData>) -> Self {
        Self { tx, stats: Arc::default() }
    }

    /// The same sink, counting into `stats`.
    pub fn with_stats(self, stats: Arc<CollectorStats>) -> Self {
        Self { stats, ..self }
    }

    /// Filters `fd` and sends it to the aggregator. Blocks when the aggregator is busy.
    pub fn send(&self, fd: FlowData) {
        match check_flow(fd) {
            Ok(fd) => {
                debug_log!(">>>>>>>> Sending FlowData", fd);
                if self.tx.send(fd).is_ok() {
                    self.stats.forwarded();
                }
            }
            Err(r) => self.stats.dropped(r),
        }
    }
}

/// Differs from FlowLink (docs/differences-from-flowlink.md, "ICMP type/code in the destination port"): an ICMP or ICMPv6 record that carried no
/// type/code field (IPFIX/v9 IE 32, 139, 176-179; NetFlow v5 has none) but a destination port
/// has type and code in that port, and `check_flow` would drop it as ICMP with a port. Most
/// exporters send `type*256 + code` (nProbe, softflowd, the v5 convention); some send the bare
/// type (Cisco IPFIX and Procera in the conformance corpus). A value below 256 read as `type*256 + code` would
/// be type 0 with a code, which no ICMP message has, so it is taken as the type with code 0.
/// The source port is left as sent.
pub(crate) fn icmp_from_dst_port(key: &mut FlowKey) {
    if !matches!(key.protocol, 1 | 58) || key.dst_port == 0 {
        return;
    }
    let p = key.dst_port;
    (key.icmp_type, key.icmp_code) = if p < 256 { (p as u8, 0) } else { ((p >> 8) as u8, p as u8) };
    key.dst_port = 0;
}

/// The flow filter and direction normalisation.
pub fn check_flow(mut fd: FlowData) -> Result<FlowData, DropReason> {
    let k = &fd.key;
    if k.src_ip.is_empty() || k.dst_ip.is_empty() || k.ip_version == 0 {
        debug_log!("Discarding flow, due to empty/zero data:", fd);
        return Err(DropReason::EmptyAddress);
    }
    if k.ip_version == 6 && matches!(k.protocol, 0 | 43 | 44) {
        debug_log!("Discarding IPv6 Extension flows (Protocol 0,43,44)");
        return Err(DropReason::Ipv6Extension);
    }
    if is_multicast_or_broadcast(&k.src_ip, &k.src_mac) || is_multicast_or_broadcast(&k.dst_ip, &k.dst_mac) {
        debug_log!("Discarding flow to/from special address:", fd);
        return Err(DropReason::SpecialAddress);
    }
    if k.dst_port > 0 && matches!(k.protocol, 1 | 58) {
        log_line!("Discarding flow, due to bad data:", fd);
        return Err(DropReason::IcmpWithPort);
    }
    // Unknown direction: guess the server side from ephemeral port ranges (MACs/masks not swapped).
    if fd.direction_ind == 2 && fd.src_port != 0 && fd.key.dst_port != 0 {
        if fd.src_port < fd.key.dst_port && fd.key.dst_port > 32768 && fd.src_port < 32768 {
            std::mem::swap(&mut fd.key.src_ip, &mut fd.key.dst_ip);
            std::mem::swap(&mut fd.key.dst_port, &mut fd.src_port);
        }
        fd.direction_ind = 0;
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(src: &str, dst: &str, ver: u8, proto: u8) -> FlowData {
        FlowData {
            transport: "udp".into(),
            key: FlowKey { src_ip: src.into(), dst_ip: dst.into(), ip_version: ver, protocol: proto, ..Default::default() },
            direction_ind: 2,
            flows: 1,
            ..Default::default()
        }
    }

    #[test]
    fn special_addresses() {
        assert!(is_multicast_or_broadcast("224.0.0.1", ""));
        assert!(is_multicast_or_broadcast("255.255.255.255", ""));
        assert!(is_multicast_or_broadcast("240.1.2.3", ""));
        assert!(!is_multicast_or_broadcast("223.255.255.255", ""));
        assert!(!is_multicast_or_broadcast("127.0.0.1", ""));
        assert!(!is_multicast_or_broadcast("169.254.1.1", ""));
        assert!(is_multicast_or_broadcast("10.0.0.1", "01:00:5E:00:00:01"));
        assert!(!is_multicast_or_broadcast("10.0.0.1", "01:00:5e:00:00:01")); // case-sensitive
        assert!(is_multicast_or_broadcast("10.0.0.1", "FF:FF:FF:FF:FF:FF"));
        assert!(is_multicast_or_broadcast("ff02::1", ""));
        assert!(!is_multicast_or_broadcast("fe80::1", ""));
        assert!(is_multicast_or_broadcast("fe80::1", "33:33:00:00:00:01"));
        assert!(is_multicast_or_broadcast("::ffff:224.0.0.1", "")); // mapped v4 hits the v4 branch
        assert!(!is_multicast_or_broadcast("::1", "01:00:5E:00:00:01")); // v4 MAC test needs a '.'
    }

    #[test]
    fn filters() {
        assert_eq!(check_flow(flow("", "10.0.0.2", 4, 6)), Err(DropReason::EmptyAddress));
        assert_eq!(check_flow(flow("10.0.0.1", "10.0.0.2", 0, 6)), Err(DropReason::EmptyAddress));
        assert_eq!(check_flow(flow("::1", "::2", 6, 43)), Err(DropReason::Ipv6Extension));
        assert_eq!(check_flow(flow("10.0.0.1", "224.0.0.5", 4, 17)), Err(DropReason::SpecialAddress));
        let mut icmp = flow("10.0.0.1", "10.0.0.2", 4, 1);
        icmp.key.dst_port = 3;
        assert_eq!(check_flow(icmp), Err(DropReason::IcmpWithPort));
    }

    #[test]
    fn sink_counts_forwarded_and_dropped() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let stats = Arc::new(CollectorStats::new("sink", "netflow"));
        let sink = FlowSink::new(tx).with_stats(stats.clone());
        sink.send(flow("10.0.0.1", "10.0.0.2", 4, 6));
        sink.send(flow("10.0.0.1", "224.0.0.5", 4, 17));
        sink.send(flow("", "10.0.0.2", 4, 6));
        assert_eq!(rx.try_iter().count(), 1);
        let c = stats.counters();
        assert_eq!((c.forwarded, c.dropped_special_address, c.dropped_empty_address), (1, 1, 1));
    }

    #[test]
    fn direction_heuristic_swaps_client_to_server() {
        let mut f = flow("10.0.0.1", "10.0.0.2", 4, 6);
        f.src_port = 443;
        f.key.dst_port = 50000;
        let out = check_flow(f).unwrap();
        assert_eq!((out.key.src_ip.as_str(), out.key.dst_ip.as_str()), ("10.0.0.2", "10.0.0.1"));
        assert_eq!((out.src_port, out.key.dst_port), (50000, 443));
        assert_eq!(out.direction_ind, 0);

        let mut g = flow("10.0.0.1", "10.0.0.2", 4, 6);
        g.src_port = 50000;
        g.key.dst_port = 443;
        let out = check_flow(g).unwrap();
        assert_eq!(out.key.src_ip, "10.0.0.1");
        assert_eq!(out.direction_ind, 0);

        let mut h = flow("10.0.0.1", "10.0.0.2", 4, 6); // a zero port keeps direction 2
        h.key.dst_port = 443;
        assert_eq!(check_flow(h).unwrap().direction_ind, 2);
    }

    #[test]
    fn go_struct_formatting() {
        let f = flow("10.0.0.1", "10.0.0.2", 4, 6);
        assert_eq!(f.to_string(), "{udp  { 10.0.0.1 10.0.0.2 0 4 6 0 0   0 0} 0 0 1 0 2}");
    }
}
