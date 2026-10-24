//! Collector and exporter counters (docs/stats.md, `collectors[]` and
//! `collectors[].exporters[]`). One `CollectorStats` per consumer; parsers report once per datagram,
//! `FlowSink::send` once per flow (atomics only), `read_udp` per rejected datagram.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use super::rfc3339;

/// Exporters tracked per collector; inserting into a full table evicts the least recently seen.
pub const MAX_EXPORTERS: usize = 10_000;
/// An exporter idle for longer than this is dropped.
const EXPORTER_IDLE: Duration = Duration::from_secs(24 * 3600);

/// Protocol (and version) of a datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    NetflowV5,
    NetflowV7,
    NetflowV9,
    Ipfix,
    Sflow,
    Text,
}

/// Why the flow filter (`flow::check_flow`) discarded a flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    EmptyAddress,
    SpecialAddress,
    Ipv6Extension,
    IcmpWithPort,
}

/// Collector totals since start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CollectorCounters {
    pub datagrams: u64,
    pub bytes: u64,
    /// Flows decoded: records handed to the flow filter (NetFlow/IPFIX records sent, sFlow records sent, text flow
    /// lines).
    pub flows: u64,
    /// Flows that passed the filter and went on to aggregation.
    pub forwarded: u64,
    pub dropped_empty_address: u64,
    pub dropped_special_address: u64,
    pub dropped_ipv6_extension: u64,
    pub dropped_icmp_with_port: u64,
    /// Failure points, not datagrams: every `check_error` while decoding counts (a text datagram with N bad lines
    /// counts N), plus datagrams of an unknown version.
    pub decode_errors: u64,
    /// Datagrams from senders not in `remote_addrs`.
    pub rejected_datagrams: u64,
}

/// One exporter row as of `CollectorStats::exporters(now)`.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ExporterSnapshot {
    pub address: String,
    /// In the order first seen.
    pub protocols: Vec<Proto>,
    pub datagrams: u64,
    pub flows: u64,
    pub decode_errors: u64,
    #[serde(serialize_with = "rfc3339::time")]
    pub first_seen: SystemTime,
    #[serde(serialize_with = "rfc3339::time")]
    pub last_seen: SystemTime,
    /// Flows in the last complete minute (UTC minute buckets) / 60.
    pub flows_per_second: f64,
}

/// Counters of one collector (consumer).
#[derive(Default)]
pub struct CollectorStats {
    /// Consumer name ("" when unregistered).
    pub name: String,
    /// Parser type.
    pub parser: String,
    datagrams: AtomicU64,
    bytes: AtomicU64,
    flows: AtomicU64,
    forwarded: AtomicU64,
    /// Indexed by `DropReason as usize`.
    dropped: [AtomicU64; 4],
    decode_errors: AtomicU64,
    rejected: AtomicU64,
    /// Unix seconds of the last datagram that carried flows; 0 = none yet.
    last_flow: AtomicU64,
    exporters: Mutex<ExporterTable>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl CollectorStats {
    pub fn new(name: &str, parser: &str) -> Self {
        Self { name: name.into(), parser: parser.into(), ..Self::default() }
    }

    /// One received datagram, after decoding: once per datagram (takes the exporter table lock).
    pub fn datagram(&self, exporter: &str, proto: Option<Proto>, bytes: usize, flows: u64, decode_errors: u64) {
        self.datagram_at(exporter, proto, bytes, flows, decode_errors, SystemTime::now());
    }

    pub(crate) fn datagram_at(
        &self,
        exporter: &str,
        proto: Option<Proto>,
        bytes: usize,
        flows: u64,
        decode_errors: u64,
        now: SystemTime,
    ) {
        self.datagrams.fetch_add(1, Relaxed);
        self.bytes.fetch_add(bytes as u64, Relaxed);
        self.flows.fetch_add(flows, Relaxed);
        self.decode_errors.fetch_add(decode_errors, Relaxed);
        if flows > 0 {
            let secs = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
            self.last_flow.fetch_max(secs, Relaxed);
        }
        lock(&self.exporters).record(exporter, proto, flows, decode_errors, now);
    }

    /// When a datagram last carried flows (whole seconds).
    pub fn last_flow_at(&self) -> Option<SystemTime> {
        match self.last_flow.load(Relaxed) {
            0 => None,
            s => Some(UNIX_EPOCH + Duration::from_secs(s)),
        }
    }

    /// A datagram from a sender not in `remote_addrs`. Counted per collector only: rejected senders get no
    /// exporter row, so they cannot push real exporters out of the table.
    pub fn rejected(&self, _exporter: &str) {
        self.rejected.fetch_add(1, Relaxed);
    }

    /// A flow sent on to aggregation.
    pub fn forwarded(&self) {
        self.forwarded.fetch_add(1, Relaxed);
    }

    /// A flow discarded by the filter.
    pub fn dropped(&self, r: DropReason) {
        self.dropped[r as usize].fetch_add(1, Relaxed);
    }

    pub fn counters(&self) -> CollectorCounters {
        let d = |r: DropReason| self.dropped[r as usize].load(Relaxed);
        CollectorCounters {
            datagrams: self.datagrams.load(Relaxed),
            bytes: self.bytes.load(Relaxed),
            flows: self.flows.load(Relaxed),
            forwarded: self.forwarded.load(Relaxed),
            dropped_empty_address: d(DropReason::EmptyAddress),
            dropped_special_address: d(DropReason::SpecialAddress),
            dropped_ipv6_extension: d(DropReason::Ipv6Extension),
            dropped_icmp_with_port: d(DropReason::IcmpWithPort),
            decode_errors: self.decode_errors.load(Relaxed),
            rejected_datagrams: self.rejected.load(Relaxed),
        }
    }

    /// The exporter rows, sorted by address, after dropping those idle for more than 24 hours.
    pub fn exporters(&self, now: SystemTime) -> Vec<ExporterSnapshot> {
        // Parser threads take this lock once per datagram: hold it only to expire and copy, list outside it.
        let rows = lock(&self.exporters).expire_and_copy(now);
        list_exporters(rows, now)
    }
}

static COLLECTORS: Mutex<Vec<Arc<CollectorStats>>> = Mutex::new(Vec::new());

/// Create and register the counters of one collector.
pub fn register_collector(name: &str, parser: &str) -> Arc<CollectorStats> {
    let s = Arc::new(CollectorStats::new(name, parser));
    lock(&COLLECTORS).push(s.clone());
    s
}

/// Every registered collector, in registration order.
pub fn collectors() -> Vec<Arc<CollectorStats>> {
    lock(&COLLECTORS).clone()
}

/// UTC minute index of `t` (0 before the epoch).
fn minute(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() / 60)
}

#[derive(Clone)]
struct ExporterRow {
    protocols: Vec<Proto>,
    datagrams: u64,
    flows: u64,
    decode_errors: u64,
    first_seen: SystemTime,
    last_seen: SystemTime,
    /// Recency order for eviction (a counter, so equal timestamps still have an order).
    touched: u64,
    /// Flows in minute `minute`, and in the minute before it.
    minute: u64,
    minute_flows: u64,
    prev_minute_flows: u64,
}

/// Exporter rows of one collector, keyed by source address, at most `MAX_EXPORTERS`.
#[derive(Default)]
pub struct ExporterTable {
    rows: HashMap<String, ExporterRow>,
    tick: u64,
}

impl ExporterTable {
    pub fn record(&mut self, exporter: &str, proto: Option<Proto>, flows: u64, decode_errors: u64, now: SystemTime) {
        self.tick += 1;
        let m = minute(now);
        // Known exporters (the common case) are looked up without allocating a key.
        if !self.rows.contains_key(exporter) {
            if self.rows.len() >= MAX_EXPORTERS {
                if let Some(oldest) = self.rows.iter().min_by_key(|(_, r)| r.touched).map(|(k, _)| k.clone()) {
                    self.rows.remove(&oldest);
                }
            }
            let row = ExporterRow {
                protocols: Vec::new(),
                datagrams: 0,
                flows: 0,
                decode_errors: 0,
                first_seen: now,
                last_seen: now,
                touched: 0,
                minute: m,
                minute_flows: 0,
                prev_minute_flows: 0,
            };
            self.rows.insert(exporter.to_string(), row);
        }
        let Some(row) = self.rows.get_mut(exporter) else { return };
        if let Some(p) = proto {
            if !row.protocols.contains(&p) {
                row.protocols.push(p);
            }
        }
        row.datagrams += 1;
        row.flows += flows;
        row.decode_errors += decode_errors;
        row.last_seen = now;
        row.touched = self.tick;
        if m != row.minute {
            row.prev_minute_flows = if m == row.minute + 1 { row.minute_flows } else { 0 };
            row.minute = m;
            row.minute_flows = 0;
        }
        row.minute_flows += flows;
    }

    /// Drop rows idle for more than 24 hours and copy the rest. Done under the table lock, so kept to the minimum: the
    /// snapshot rows are built and sorted by `list_exporters` after the lock is released.
    fn expire_and_copy(&mut self, now: SystemTime) -> Vec<(String, ExporterRow)> {
        self.rows.retain(|_, r| now.duration_since(r.last_seen).map_or(true, |idle| idle <= EXPORTER_IDLE));
        self.rows.iter().map(|(a, r)| (a.clone(), r.clone())).collect()
    }
}

/// The snapshot of copied exporter rows, sorted by address.
fn list_exporters(rows: Vec<(String, ExporterRow)>, now: SystemTime) -> Vec<ExporterSnapshot> {
    let m = minute(now);
    let mut out: Vec<ExporterSnapshot> = rows
        .into_iter()
        .map(|(address, r)| {
            let last_complete = if m == r.minute {
                r.prev_minute_flows
            } else if m == r.minute + 1 {
                r.minute_flows
            } else {
                0
            };
            ExporterSnapshot {
                address,
                protocols: r.protocols,
                datagrams: r.datagrams,
                flows: r.flows,
                decode_errors: r.decode_errors,
                first_seen: r.first_seen,
                last_seen: r.last_seen,
                flows_per_second: last_complete as f64 / 60.0,
            }
        })
        .collect();
    out.sort_by(|a, b| a.address.cmp(&b.address));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const HOUR: Duration = Duration::from_secs(3600);

    #[test]
    fn exporter_table_bounded() {
        let s = CollectorStats::new("bounded", "netflow");
        let t0 = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        for i in 0..=MAX_EXPORTERS {
            s.datagram_at(&format!("e{i}"), Some(Proto::NetflowV9), 100, 1, 0, t0 + Duration::from_millis(i as u64));
        }
        let ex = s.exporters(t0 + Duration::from_secs(60));
        assert_eq!(ex.len(), MAX_EXPORTERS);
        assert!(!ex.iter().any(|e| e.address == "e0"), "the oldest is gone");
        assert!(ex.iter().any(|e| e.address == format!("e{MAX_EXPORTERS}")));
        // Least recently seen, not first inserted: e1 is seen again, so e2 goes next.
        s.datagram_at("e1", Some(Proto::NetflowV9), 100, 1, 0, t0 + Duration::from_secs(30));
        s.datagram_at("new", Some(Proto::Ipfix), 100, 1, 0, t0 + Duration::from_secs(31));
        let ex = s.exporters(t0 + Duration::from_secs(60));
        assert_eq!(ex.len(), MAX_EXPORTERS);
        assert!(ex.iter().any(|e| e.address == "e1"));
        assert!(!ex.iter().any(|e| e.address == "e2"));
        assert_eq!(s.counters().datagrams, MAX_EXPORTERS as u64 + 3, "collector totals keep every datagram");
    }

    #[test]
    fn idle_exporter_expires() {
        let s = CollectorStats::new("idle", "ipfix");
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        s.datagram_at("10.0.0.9", Some(Proto::Ipfix), 10, 1, 0, now - 25 * HOUR);
        s.datagram_at("10.0.0.1", Some(Proto::Ipfix), 10, 1, 0, now - 23 * HOUR);
        let ex = s.exporters(now);
        assert_eq!(ex.iter().map(|e| e.address.as_str()).collect::<Vec<_>>(), ["10.0.0.1"]);
    }

    #[test]
    fn datagram_accumulates() {
        let s = CollectorStats::new("acc", "netflow");
        let t0 = UNIX_EPOCH + Duration::from_secs(60 * 28_000_000); // a minute boundary
        s.datagram_at("10.0.0.1", Some(Proto::NetflowV9), 100, 30, 0, t0);
        s.datagram_at("10.0.0.1", Some(Proto::Ipfix), 200, 90, 1, t0 + Duration::from_secs(10));
        s.datagram_at("10.0.0.1", Some(Proto::NetflowV9), 50, 0, 0, t0 + Duration::from_secs(20));
        s.datagram_at("10.0.0.2", None, 3, 0, 1, t0 + Duration::from_secs(20));
        let ex = s.exporters(t0 + Duration::from_secs(65));
        assert_eq!(ex.len(), 2);
        let e = &ex[0];
        assert_eq!(e.address, "10.0.0.1");
        assert_eq!(e.protocols, [Proto::NetflowV9, Proto::Ipfix]);
        assert_eq!((e.datagrams, e.flows, e.decode_errors), (3, 120, 1));
        assert_eq!((e.first_seen, e.last_seen), (t0, t0 + Duration::from_secs(20)));
        assert_eq!(e.flows_per_second, 2.0, "120 flows in the last complete minute");
        assert_eq!(s.last_flow_at(), Some(t0 + Duration::from_secs(10)), "the last datagram with flows");
        assert_eq!(CollectorStats::default().last_flow_at(), None);
        assert!(ex[1].protocols.is_empty());
        // Still inside the first minute: no complete bucket yet. Two minutes later: idle.
        assert_eq!(s.exporters(t0 + Duration::from_secs(59))[0].flows_per_second, 0.0);
        assert_eq!(s.exporters(t0 + Duration::from_secs(125))[0].flows_per_second, 0.0);
        s.forwarded();
        s.dropped(DropReason::SpecialAddress);
        s.dropped(DropReason::IcmpWithPort);
        s.rejected("192.0.2.1");
        assert_eq!(
            s.counters(),
            CollectorCounters {
                datagrams: 4,
                bytes: 353,
                flows: 120,
                forwarded: 1,
                dropped_empty_address: 0,
                dropped_special_address: 1,
                dropped_ipv6_extension: 0,
                dropped_icmp_with_port: 1,
                decode_errors: 2,
                rejected_datagrams: 1,
            }
        );
        assert!(!s.exporters(t0).iter().any(|e| e.address == "192.0.2.1"), "rejected senders get no row");
    }

    #[test]
    fn rate_carries_over_minute_boundaries() {
        let s = CollectorStats::new("rate", "sflow");
        let t0 = UNIX_EPOCH + Duration::from_secs(60 * 28_000_000);
        s.datagram_at("a", Some(Proto::Sflow), 1, 60, 0, t0 + Duration::from_secs(5));
        s.datagram_at("a", Some(Proto::Sflow), 1, 30, 0, t0 + Duration::from_secs(65));
        // In minute 1: minute 0 is the last complete one; in minute 2: minute 1.
        assert_eq!(s.exporters(t0 + Duration::from_secs(70))[0].flows_per_second, 1.0);
        assert_eq!(s.exporters(t0 + Duration::from_secs(130))[0].flows_per_second, 0.5);
        // A gap of more than a minute leaves nothing complete from before it.
        s.datagram_at("a", Some(Proto::Sflow), 1, 6, 0, t0 + Duration::from_secs(300));
        assert_eq!(s.exporters(t0 + Duration::from_secs(301))[0].flows_per_second, 0.0);
    }

    #[test]
    fn registry_keeps_registration_order() {
        let a = register_collector("reg-a", "netflow");
        let b = register_collector("reg-b", "text");
        assert_eq!((b.name.as_str(), b.parser.as_str()), ("reg-b", "text"));
        let names: Vec<String> = collectors().iter().map(|c| c.name.clone()).filter(|n| n.starts_with("reg-")).collect();
        assert_eq!(names, ["reg-a", "reg-b"]);
        assert!(Arc::ptr_eq(&a, collectors().iter().find(|c| c.name == "reg-a").unwrap()));
        assert_eq!(CollectorStats::default().name, "");
    }
}
