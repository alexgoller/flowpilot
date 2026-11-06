//! Flow aggregation and window flush.
//!
//! PCE (HTTP) mode clears the device address from the key, and records carry dst_dbi/dst_dbo.
//! Kafka mode (a [`KafkaHeader`] is set) keeps the device address in the key, so each exporter
//! aggregates on its own. Its batches carry org_id/installation_id/pce_host, and its records
//! carry device_addr, the MACs, the mask bits and the summed octets instead of dst_dbi/dst_dbo.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

use crossbeam_channel::Receiver;
use flate2::write::GzEncoder;
use flate2::Compression;
use prost::Message;
use serde::Serialize;

use crate::flow::{FlowData, FlowInfo, FlowKey};
use crate::log::{go_slice, shutdown};
use crate::proto::{UploadBatch, UploadRecord};
use crate::reported_ips::ReportedIpsStore;
use crate::spool::Spool;
use crate::stats::{self, rfc3339, ThreadGuard};
use crate::{debug_log, log_line};

/// Capacity of the flow channel.
pub const FLOW_CHANNEL_CAPACITY: usize = 300;
const AGGREGATOR_THREADS: usize = 10;

#[derive(Debug)]
struct Window {
    flows: HashMap<FlowKey, FlowInfo>,
    min_time: i64,
    max_time: i64,
    reported_ips: HashSet<String>,
    new_ips: Vec<String>,
    /// device → transport → highest sequence id (compared as text, as in FlowLink).
    restart: BTreeMap<String, BTreeMap<String, String>>,
    /// Set by the final shutdown flush; later flows are ignored, as in FlowLink.
    closed: bool,
    /// `add_flow` calls since the last flush (stats).
    flows_seen: u64,
    /// The last flush, for the stats.
    last_flush: LastFlush,
}

#[derive(Clone, Copy, Debug, Default)]
struct LastFlush {
    at: Option<SystemTime>,
    records: usize,
    new_ips: usize,
}

/// Aggregation counters (docs/stats.md, `aggregation`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct AggregationStats {
    /// Flow records merged into the current window (`add_flow` calls since the last flush).
    pub window_flows: u64,
    /// Distinct keys in the current window.
    pub window_keys: usize,
    #[serde(serialize_with = "rfc3339::opt")]
    pub last_flush_at: Option<SystemTime>,
    /// Aggregated records (distinct keys) in the last window.
    pub last_window_records: usize,
    pub last_window_new_ips: usize,
}

impl Default for Window {
    fn default() -> Self {
        Self {
            flows: HashMap::new(),
            min_time: i64::MAX,
            max_time: 0,
            reported_ips: HashSet::new(),
            new_ips: Vec::new(),
            restart: BTreeMap::new(),
            closed: false,
            flows_seen: 0,
            last_flush: LastFlush::default(),
        }
    }
}

/// What one window flush hands to consumers such as unmanaged-workload creation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowReport {
    /// IPs never reported before, in first-seen order (FlowLink only logs these).
    pub new_ips: Vec<String>,
    /// Flows per IP in this window: each aggregated record counts for its source and destination.
    pub ip_flow_counts: HashMap<String, u64>,
}

/// The batch header fields of Kafka mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KafkaHeader {
    pub org_id: i32,
    pub installation_id: String,
    /// `pce_addr` verbatim, including `:port`.
    pub pce_host: String,
}

pub struct Aggregator {
    window: Mutex<Window>,
    spool: Arc<Spool>,
    reported_store: ReportedIpsStore,
    instance_id: String,
    max_flows_per_post: i64,
    /// `Some` in Kafka mode.
    kafka: Option<KafkaHeader>,
}

impl Aggregator {
    /// Create the aggregator and load persisted reported IPs. `kafka` selects Kafka mode.
    pub fn new(
        spool: Arc<Spool>,
        pce_addr: &str,
        org_id: i32,
        instance_id: String,
        max_flows_per_post: i64,
        kafka: Option<KafkaHeader>,
    ) -> Self {
        let reported_store = ReportedIpsStore::new(spool.dir(), pce_addr, org_id);
        let window = Window { reported_ips: reported_store.load(), ..Window::default() };
        Self { window: Mutex::new(window), spool, reported_store, instance_id, max_flows_per_post, kafka }
    }

    /// Starts ten aggregator consumers of the flow channel.
    pub fn start(self: &Arc<Self>, rx: Receiver<FlowData>) {
        for i in 0..AGGREGATOR_THREADS {
            let (agg, rx) = (self.clone(), rx.clone());
            thread::spawn(move || {
                let _guard = ThreadGuard::core("aggregator");
                for fd in rx.iter() {
                    debug_log!(i, "<<<<<<<<< Data Aggregator Received FlowData", fd);
                    agg.add_flow(fd);
                }
            });
        }
    }

    /// Merge `fd` into the window, folding reverse-direction flows into
    /// an existing entry and recording IPs never reported before.
    pub fn add_flow(&self, mut fd: FlowData) {
        let mut w = self.lock();
        if w.closed {
            return;
        }
        w.flows_seen += 1;
        debug_log!("Handling flow:", fd);
        if self.kafka.is_none() {
            fd.key.device_addr.clear();
        }
        let mut info = match w.flows.get(&fd.key) {
            Some(i) => *i,
            None => {
                let rk = FlowKey {
                    src_ip: fd.key.dst_ip.clone(),
                    dst_ip: fd.key.src_ip.clone(),
                    src_mac: fd.key.dst_mac.clone(),
                    dst_mac: fd.key.src_mac.clone(),
                    src_mask: fd.key.dst_mask,
                    dst_mask: fd.key.src_mask,
                    dst_port: fd.src_port,
                    ..fd.key.clone()
                };
                match w.flows.get(&rk) {
                    Some(r) => {
                        let r = *r;
                        fd.src_port = fd.key.dst_port;
                        fd.key = rk;
                        fd.direction_ind = 1;
                        r
                    }
                    None => {
                        for ip in [fd.key.src_ip.clone(), fd.key.dst_ip.clone()] {
                            if w.reported_ips.insert(ip.clone()) {
                                w.new_ips.push(ip);
                            }
                        }
                        FlowInfo::default()
                    }
                }
            }
        };
        info.flow_count = info.flow_count.wrapping_add(fd.flows);
        if fd.direction_ind == 0 {
            info.flow_in_octets += fd.octets;
        } else {
            info.flow_out_octets += fd.octets;
        }
        if info.first_flow_time == 0 || fd.flow_time < info.first_flow_time {
            info.first_flow_time = fd.flow_time;
        }
        w.flows.insert(fd.key.clone(), info);
        w.min_time = w.min_time.min(fd.flow_time);
        w.max_time = w.max_time.max(fd.flow_time);
        if !fd.seq_id.is_empty() {
            let cur = w.restart.entry(fd.key.device_addr.clone()).or_default().entry(fd.transport.clone()).or_default();
            if fd.seq_id > *cur {
                *cur = fd.seq_id;
            }
        }
    }

    /// Flush the window into gzipped protobuf spool files. Returns the
    /// window's new IPs and per-IP flow counts (the hook for workload auto-creation).
    pub fn write_flows(&self) -> WindowReport {
        let (flows, min_t, max_t, ips, reported, restart) = {
            let mut w = self.lock();
            let flows = std::mem::take(&mut w.flows);
            let (min_t, max_t) = (w.min_time, w.max_time);
            w.min_time = i64::MAX;
            w.max_time = 0;
            let ips = std::mem::take(&mut w.new_ips);
            w.flows_seen = 0;
            w.last_flush = LastFlush { at: Some(SystemTime::now()), records: flows.len(), new_ips: ips.len() };
            let reported = (!ips.is_empty()).then(|| w.reported_ips.clone());
            if shutdown() {
                w.closed = true;
            }
            (flows, min_t, max_t, ips, reported, w.restart.clone())
        };
        if flows.is_empty() {
            log_line!("No flows to report");
            return WindowReport { new_ips: ips, ..Default::default() };
        }
        let mut ip_flow_counts: HashMap<String, u64> = HashMap::new();
        for (k, v) in &flows {
            for ip in [&k.src_ip, &k.dst_ip] {
                *ip_flow_counts.entry(ip.clone()).or_default() += v.flow_count as u64;
            }
        }
        log_line!("Flow count:", flows.len());
        debug_log!("restart info:", format!("{restart:?}"), "\nFlows:");

        let mut max_per_post = self.max_flows_per_post;
        let mut final_flush = false;
        // As in FlowLink: with max_per_post 0 (Kafka maxObjectsPerMessage absent) this is false, so the
        // shutdown window is spooled but not sent.
        if shutdown() && self.spool.queue_len() == 0 && max_per_post >= flows.len() as i64 {
            max_per_post = flows.len() as i64;
            final_flush = true;
        }
        let aggregation_seconds = (max_t.saturating_sub(min_t) as f64).round() as i32;
        let mut entries = flows.into_iter();
        loop {
            let batch = build_batch(&mut entries, max_per_post, aggregation_seconds, &self.instance_id, self.kafka.as_ref());
            let Some(td) = batch else { break };
            let records = td.flows.len() as u64;
            let mut gz = GzEncoder::new(Vec::new(), Compression::best());
            let data = gz.write_all(&td.encode_to_vec()).and_then(|_| gz.finish());
            match data {
                Ok(bytes) => self.spool.add(&bytes, records, final_flush),
                Err(e) => {
                    crate::log::check_error(Some(e));
                }
            }
        }

        if let Some(reported) = reported {
            if let Err(e) = self.reported_store.save(&reported) {
                log_line!("Error writing reported_ip data file:", e);
            }
        }
        if !restart.is_empty() {
            write_restart_info(self.spool.dir(), &restart);
        }
        if !ips.is_empty() {
            log_line!("***** Following new IP addresses found in flows:", go_slice(&ips));
        }
        if shutdown() && (final_flush || self.spool.sending() > 0) {
            log_line!("Waiting for file senders to drain");
            thread::sleep(Duration::from_secs(2));
            for _ in 0..30 {
                if self.spool.sending() <= 0 {
                    break;
                }
                thread::sleep(Duration::from_secs(1));
            }
        }
        WindowReport { new_ips: ips, ip_flow_counts }
    }

    /// The current window and the last flush.
    pub fn stats(&self) -> AggregationStats {
        let w = self.lock();
        AggregationStats {
            window_flows: w.flows_seen,
            window_keys: w.flows.len(),
            last_flush_at: w.last_flush.at,
            last_window_records: w.last_flush.records,
            last_window_new_ips: w.last_flush.new_ips,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Window> {
        self.window.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Build one `UploadBatch` of up to `max_per_post` records (`<= 0` means unlimited). Returns
/// `None` when no entries are left. Records with an IP version other than 4/6 vanish, as in FlowLink.
/// Divergence: an unparsable IP drops only that record, not the whole batch.
fn build_batch(
    entries: &mut impl Iterator<Item = (FlowKey, FlowInfo)>,
    max_per_post: i64,
    aggregation_seconds: i32,
    instance_id: &str,
    kafka: Option<&KafkaHeader>,
) -> Option<UploadBatch> {
    let mut td = UploadBatch {
        aggregation_seconds,
        instance_id: Some(instance_id.as_bytes().to_vec()),
        ..Default::default()
    };
    if let Some(k) = kafka {
        // Always present in Kafka mode, even when 0 or empty.
        td.org_id = Some(k.org_id);
        td.installation_id = Some(k.installation_id.as_bytes().to_vec());
        td.pce_host = Some(k.pce_host.as_bytes().to_vec());
    }
    let mut any = false;
    for (key, value) in entries.by_ref() {
        any = true;
        debug_log!("key:", key, "value:", value);
        let (src, dst) = match key.ip_version {
            4 => (ip4_bytes(&key.src_ip), ip4_bytes(&key.dst_ip)),
            6 => (ip16_bytes(&key.src_ip), ip16_bytes(&key.dst_ip)),
            _ => continue,
        };
        let (Some(src_ip), Some(dst_ip)) = (src, dst) else {
            log_line!("Discarding flow with invalid IP address:", key);
            continue;
        };
        let icmp = matches!(key.protocol, 1 | 58);
        let mut rec = UploadRecord {
            timestamp: value.first_flow_time,
            src_ip,
            dst_ip,
            dst_port: key.dst_port as i32,
            proto: key.protocol as i32,
            count: value.flow_count as i32,
            icmp_type: icmp.then_some(key.icmp_type as i32),
            icmp_code: icmp.then_some(key.icmp_code as i32),
            ..Default::default()
        };
        if kafka.is_some() {
            let opt = |s: &str, f: fn(&str) -> Option<Vec<u8>>| if s.is_empty() { None } else { f(s) };
            rec.src_mac = opt(&key.src_mac, go_parse_mac);
            rec.dst_mac = opt(&key.dst_mac, go_parse_mac);
            rec.device_addr = opt(&key.device_addr, device_addr_bytes);
            rec.src_mask_bits = (key.src_mask != 0).then_some(key.src_mask as i32);
            rec.dst_mask_bits = (key.dst_mask != 0).then_some(key.dst_mask as i32);
            // Direction is collapsed: in + out.
            rec.octets = (value.flow_in_octets != 0 || value.flow_out_octets != 0)
                .then(|| value.flow_in_octets.wrapping_add(value.flow_out_octets) as u64);
        } else {
            rec.dst_dbi = (value.flow_in_octets != 0).then_some(value.flow_in_octets);
            rec.dst_dbo = (value.flow_out_octets != 0).then_some(value.flow_out_octets);
        }
        debug_log!("flow:", format!("{rec:?}"));
        td.flows.push(rec);
        if td.flows.len() as i64 == max_per_post {
            break;
        }
    }
    any.then_some(td)
}

/// Go `net.ParseIP(s).To4()`.
fn ip4_bytes(s: &str) -> Option<Vec<u8>> {
    match s.parse::<IpAddr>().ok()? {
        IpAddr::V4(v) => Some(v.octets().to_vec()),
        IpAddr::V6(v) => v.to_ipv4_mapped().map(|v| v.octets().to_vec()),
    }
}

/// Go `net.ParseIP(s).To16()`: IPv4 becomes `::ffff:a.b.c.d`.
fn ip16_bytes(s: &str) -> Option<Vec<u8>> {
    match s.parse::<IpAddr>().ok()? {
        IpAddr::V4(v) => Some(v.to_ipv6_mapped().octets().to_vec()),
        IpAddr::V6(v) => Some(v.octets().to_vec()),
    }
}

/// The Kafka record's device address: Go `net.ParseIP(s).To4()` if `s` contains a `.`, else `.To16()`.
fn device_addr_bytes(s: &str) -> Option<Vec<u8>> {
    if s.contains('.') {
        ip4_bytes(s)
    } else {
        ip16_bytes(s)
    }
}

/// Go `net.ParseMAC`: `aa:bb:..`, `aa-bb-..` or `aabb.ccdd.eeff` forms of 6, 8 or 20 bytes.
pub(crate) fn go_parse_mac(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() < 14 {
        return None;
    }
    let hex = |i: usize| -> Option<u8> {
        let d = |c: u8| (c as char).to_digit(16);
        Some((d(*b.get(i)?)? * 16 + d(*b.get(i + 1)?)?) as u8)
    };
    let (n, out) = if b[2] == b':' || b[2] == b'-' {
        if !(b.len() + 1).is_multiple_of(3) {
            return None;
        }
        let n = (b.len() + 1) / 3;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let x = 3 * i;
            if x + 2 < b.len() && b[x + 2] != b[2] {
                return None;
            }
            out.push(hex(x)?);
        }
        (n, out)
    } else if b[4] == b'.' {
        if !(b.len() + 1).is_multiple_of(5) {
            return None;
        }
        let n = 2 * (b.len() + 1) / 5;
        let mut out = Vec::with_capacity(n);
        for i in 0..n / 2 {
            let x = 5 * i;
            if x + 4 < b.len() && b[x + 4] != b'.' {
                return None;
            }
            out.push(hex(x)?);
            out.push(hex(x + 2)?);
        }
        (n, out)
    } else {
        return None;
    };
    if !matches!(n, 6 | 8 | 20) {
        return None;
    }
    Some(out)
}

/// `restart_info.yml`. Divergence: truncated on write.
fn write_restart_info(dir: &Path, restart: &BTreeMap<String, BTreeMap<String, String>>) {
    let path = dir.join("restart_info.yml");
    let yaml = match serde_yaml::to_string(restart) {
        Ok(y) => y,
        Err(e) => {
            log_line!("Error creating restart info:", e);
            return;
        }
    };
    match crate::reported_ips::open_0640(&path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(yaml.as_bytes()) {
                log_line!("Error writing restart info:", e);
            }
        }
        Err(e) => log_line!("Error opening restart info file:", e),
    }
}

/// Start the uploader, then flush every `aggregation_minutes`.
/// Each window is a sleep, so a period is `aggregation_minutes` plus the flush time. Each iteration is a
/// `stats::heartbeat` for the health check.
pub fn report_flows(agg: &Aggregator, aggregation_minutes: i16, on_window: impl Fn(WindowReport)) {
    log_line!("Reporting flows every", aggregation_minutes, "minutes");
    while !shutdown() {
        stats::heartbeat();
        thread::sleep(Duration::from_secs(60 * aggregation_minutes.max(0) as u64));
        if shutdown() {
            break;
        }
        log_line!("Reporting Flows");
        on_window(agg.write_flows());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;

    fn fd(src: &str, dst: &str, dport: u16, sport: u16, t: i64, octets: i64, dir: u8) -> FlowData {
        FlowData {
            transport: "udp".into(),
            key: FlowKey { device_addr: "192.0.2.1".into(), src_ip: src.into(), dst_ip: dst.into(), dst_port: dport, ip_version: 4, protocol: 6, ..Default::default() },
            src_port: sport,
            flow_time: t,
            flows: 1,
            octets,
            direction_ind: dir,
            ..Default::default()
        }
    }

    fn agg(dir: &Path, max: i64) -> Aggregator {
        Aggregator::new(Arc::new(Spool::new(dir.to_path_buf(), 24, 500)), "pce.test:8443", 1, "uuid-1".into(), max, None)
    }

    fn read_batches(dir: &Path) -> Vec<UploadBatch> {
        let mut names: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).filter(|p| p.to_string_lossy().contains("traffic_flows_")).collect();
        names.sort();
        names
            .iter()
            .map(|p| {
                let mut raw = Vec::new();
                GzDecoder::new(std::fs::File::open(p).unwrap()).read_to_end(&mut raw).unwrap();
                UploadBatch::decode(raw.as_slice()).unwrap()
            })
            .collect()
    }

    #[test]
    fn merges_forward_and_reverse_and_tracks_new_ips() {
        let dir = tempfile::tempdir().unwrap();
        let a = agg(dir.path(), 10000);
        a.add_flow(fd("10.0.0.1", "10.0.0.2", 443, 50000, 100, 10, 0));
        a.add_flow(fd("10.0.0.1", "10.0.0.2", 443, 50001, 90, 5, 0)); // same key: in octets
        a.add_flow(fd("10.0.0.2", "10.0.0.1", 50000, 443, 120, 7, 0)); // reverse of the first
        let report = a.write_flows();
        assert_eq!(report.new_ips, ["10.0.0.1", "10.0.0.2"]);
        assert_eq!(report.ip_flow_counts["10.0.0.1"], 3);
        assert_eq!(report.ip_flow_counts["10.0.0.2"], 3);
        let td = read_batches(dir.path()).remove(0);
        assert_eq!(td.aggregation_seconds, 30);
        assert_eq!(td.instance_id.as_deref(), Some(&b"uuid-1"[..]));
        assert_eq!(td.org_id, None);
        assert_eq!(td.flows.len(), 1);
        let r = &td.flows[0];
        assert_eq!((r.timestamp, r.count, r.dst_port, r.proto), (90, 3, 443, 6));
        assert_eq!((r.dst_dbi, r.dst_dbo), (Some(15), Some(7)));
        assert_eq!((r.src_ip.as_slice(), r.dst_ip.as_slice()), (&[10, 0, 0, 1][..], &[10, 0, 0, 2][..]));
        assert_eq!((r.device_addr.as_ref(), r.icmp_type), (None, None));
    }

    #[test]
    fn reported_ips_persist_and_are_not_new_again() {
        let dir = tempfile::tempdir().unwrap();
        let a = agg(dir.path(), 10000);
        a.add_flow(fd("10.0.0.1", "10.0.0.2", 443, 0, 100, 0, 2));
        assert_eq!(a.write_flows().new_ips.len(), 2);
        let b = agg(dir.path(), 10000); // restart: loads the persisted set
        b.add_flow(fd("10.0.0.1", "10.0.0.3", 443, 0, 100, 0, 2));
        assert_eq!(b.write_flows().new_ips, ["10.0.0.3"]);
    }

    #[test]
    fn batches_split_and_skip_bad_records() {
        let dir = tempfile::tempdir().unwrap();
        let a = agg(dir.path(), 2);
        for i in 1..=5 {
            a.add_flow(fd(&format!("10.0.1.{i}"), "10.0.2.1", 443, 0, 100, 0, 2));
        }
        let mut bad = fd("not-an-ip", "10.0.2.1", 80, 0, 100, 0, 2);
        bad.key.ip_version = 4;
        a.add_flow(bad);
        let mut v7 = fd("10.0.3.1", "10.0.2.1", 80, 0, 100, 0, 2);
        v7.key.ip_version = 7;
        a.add_flow(v7);
        a.write_flows();
        let total: usize = read_batches(dir.path()).iter().map(|b| b.flows.len()).sum();
        assert_eq!(total, 5);
        assert!(read_batches(dir.path()).iter().all(|b| b.flows.len() <= 2));
    }

    #[test]
    fn ipv6_and_icmp_encoding() {
        let mut v6 = fd("2001:db8::1", "2001:db8::2", 0, 0, 1, 0, 2);
        v6.key.ip_version = 6;
        v6.key.protocol = 58;
        v6.key.icmp_type = 128;
        let mut mapped = fd("10.0.0.1", "10.0.0.2", 22, 0, 1, 0, 2);
        mapped.key.ip_version = 6;
        let dir = tempfile::tempdir().unwrap();
        let a = agg(dir.path(), 10000);
        a.add_flow(v6);
        a.add_flow(mapped);
        a.write_flows();
        let td = read_batches(dir.path()).remove(0);
        let icmp = td.flows.iter().find(|r| r.proto == 58).unwrap();
        assert_eq!((icmp.icmp_type, icmp.icmp_code, icmp.src_ip.len()), (Some(128), Some(0), 16));
        let m = td.flows.iter().find(|r| r.proto == 6).unwrap();
        assert_eq!(m.src_ip, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1]);
    }

    #[test]
    fn stats_track_window_and_last_flush() {
        let dir = tempfile::tempdir().unwrap();
        let a = agg(dir.path(), 10000);
        assert_eq!(a.stats(), AggregationStats::default());
        // Folded: the second flow is the reverse of the first.
        a.add_flow(fd("10.0.0.1", "10.0.0.2", 443, 50000, 100, 10, 0));
        a.add_flow(fd("10.0.0.2", "10.0.0.1", 50000, 443, 120, 7, 0));
        let s = a.stats();
        assert_eq!((s.window_flows, s.window_keys, s.last_flush_at), (2, 1, None));
        a.write_flows();
        let s = a.stats();
        assert_eq!((s.window_flows, s.window_keys, s.last_window_records, s.last_window_new_ips), (0, 0, 1, 2));
        assert!(s.last_flush_at.is_some());
        // Distinct keys.
        a.add_flow(fd("10.0.0.1", "10.0.0.3", 443, 0, 100, 0, 2));
        a.add_flow(fd("10.0.0.1", "10.0.0.4", 443, 0, 100, 0, 2));
        a.write_flows();
        let s = a.stats();
        assert_eq!((s.window_flows, s.last_window_records, s.last_window_new_ips), (0, 2, 2));
    }

    #[test]
    fn spool_files_carry_their_record_count() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Arc::new(Spool::new(dir.path().to_path_buf(), 24, 500));
        let a = Aggregator::new(spool.clone(), "pce.test:8443", 1, "uuid-1".into(), 2, None);
        for i in 1..=3 {
            a.add_flow(fd(&format!("10.0.1.{i}"), "10.0.2.1", 443, 0, 100, 0, 2));
        }
        a.write_flows();
        let mut records = vec![spool.get().records, spool.get().records];
        records.sort();
        assert_eq!(records, [1, 2]);
    }

    #[test]
    fn empty_window_reports_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(agg(dir.path(), 10000).write_flows(), WindowReport::default());
        assert!(read_batches(dir.path()).is_empty());
    }

    fn kagg(dir: &Path, max: i64) -> Aggregator {
        let header = KafkaHeader { org_id: 1, installation_id: "inst-1".into(), pce_host: "pce.test:8443".into() };
        Aggregator::new(Arc::new(Spool::new(dir.to_path_buf(), 24, 500)), "pce.test:8443", 1, "uuid-1".into(), max, Some(header))
    }

    #[test]
    fn kafka_records_carry_device_macs_masks_and_octets() {
        let dir = tempfile::tempdir().unwrap();
        let a = kagg(dir.path(), 10000);
        let mut f = fd("10.0.0.1", "10.0.0.2", 443, 50000, 100, 15, 0);
        f.key.src_mac = "00:11:22:33:44:55".into();
        f.key.dst_mac = "bogus".into();
        f.key.src_mask = 24;
        a.add_flow(f);
        // The reverse flow, same exporter: MACs and masks swap with the direction, so it folds.
        let mut r = fd("10.0.0.2", "10.0.0.1", 50000, 443, 110, 7, 0);
        r.key.src_mac = "bogus".into();
        r.key.dst_mac = "00:11:22:33:44:55".into();
        r.key.dst_mask = 24;
        a.add_flow(r);
        a.write_flows();
        let td = read_batches(dir.path()).remove(0);
        assert_eq!(
            (td.org_id, td.installation_id.as_deref(), td.pce_host.as_deref()),
            (Some(1), Some(&b"inst-1"[..]), Some(&b"pce.test:8443"[..]))
        );
        assert_eq!(td.instance_id.as_deref(), Some(&b"uuid-1"[..]));
        assert_eq!(td.flows.len(), 1);
        let r = &td.flows[0];
        assert_eq!((r.count, r.octets, r.dst_dbi, r.dst_dbo), (2, Some(22), None, None));
        assert_eq!(r.device_addr.as_deref(), Some(&[192, 0, 2, 1][..]));
        assert_eq!((r.src_mac.as_deref(), r.dst_mac.as_ref()), (Some(&[0, 0x11, 0x22, 0x33, 0x44, 0x55][..]), None));
        assert_eq!((r.src_mask_bits, r.dst_mask_bits), (Some(24), None));
    }

    #[test]
    fn kafka_header_present_even_when_empty_and_zero_octets_absent() {
        let dir = tempfile::tempdir().unwrap();
        let header = KafkaHeader { org_id: 0, installation_id: String::new(), pce_host: String::new() };
        let a = Aggregator::new(Arc::new(Spool::new(dir.path().to_path_buf(), 24, 500)), "", 0, "uuid-1".into(), 10000, Some(header));
        a.add_flow(fd("10.0.0.1", "10.0.0.2", 443, 0, 100, 0, 2));
        a.write_flows();
        let td = read_batches(dir.path()).remove(0);
        assert_eq!((td.org_id, td.installation_id.as_deref(), td.pce_host.as_deref()), (Some(0), Some(&b""[..]), Some(&b""[..])));
        let r = &td.flows[0];
        assert_eq!((r.octets, r.src_mac.as_ref(), r.src_mask_bits), (None, None, None));
    }

    #[test]
    fn kafka_mode_keeps_exporters_apart() {
        let dir = tempfile::tempdir().unwrap();
        let a = kagg(dir.path(), 10000);
        let devices = ["192.0.2.1", "192.0.2.2", "2001:db8::9", "kafka1:9092"];
        for dev in devices {
            let mut f = fd("10.0.0.1", "10.0.0.2", 443, 50000, 100, 10, 0);
            f.key.device_addr = dev.into();
            f.seq_id = "5".into();
            a.add_flow(f);
        }
        a.write_flows();
        let td = read_batches(dir.path()).remove(0);
        assert_eq!(td.flows.len(), 4);
        let mut addrs: Vec<_> = td.flows.iter().map(|r| r.device_addr.clone()).collect();
        addrs.sort();
        assert_eq!(addrs, [None, Some(vec![32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]), Some(vec![192, 0, 2, 1]), Some(vec![192, 0, 2, 2])]);
        assert!(td.flows.iter().all(|r| r.octets == Some(10)));
        // Restart info is keyed by the real device address.
        let restart = std::fs::read_to_string(dir.path().join("restart_info.yml")).unwrap();
        for dev in devices {
            assert!(restart.contains(dev), "{dev} missing from {restart}");
        }
    }

    #[test]
    fn rest_mode_clears_device_and_folds_exporters() {
        let dir = tempfile::tempdir().unwrap();
        let a = agg(dir.path(), 10000);
        for dev in ["192.0.2.1", "192.0.2.2"] {
            let mut f = fd("10.0.0.1", "10.0.0.2", 443, 50000, 100, 10, 0);
            f.key.device_addr = dev.into();
            a.add_flow(f);
        }
        a.write_flows();
        let td = read_batches(dir.path()).remove(0);
        assert_eq!(td.flows.len(), 1);
        assert_eq!((td.flows[0].device_addr.as_ref(), td.flows[0].octets, td.flows[0].dst_dbi), (None, None, Some(20)));
        assert_eq!((td.installation_id.as_ref(), td.pce_host.as_ref()), (None, None));
    }

    #[test]
    fn go_parse_mac_forms() {
        let eui48 = Some(vec![0, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(go_parse_mac("00:11:22:33:44:55"), eui48);
        assert_eq!(go_parse_mac("00-11-22-33-44-55"), eui48);
        assert_eq!(go_parse_mac("0011.2233.4455"), eui48);
        assert_eq!(go_parse_mac("AA:bb:CC:dd:EE:ff"), Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(go_parse_mac("02:00:5e:10:00:00:00:01").map(|m| m.len()), Some(8));
        assert_eq!(go_parse_mac("0200.5e10.0000.0001").map(|m| m.len()), Some(8));
        let ipoib = "00:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:10:00:00:00:01";
        assert_eq!(go_parse_mac(ipoib).map(|m| m.len()), Some(20));
        for bad in ["", "bogus", "00:11:22:33:44", "00:11:22:33:44:55:66", "00:11-22:33:44:55", "00:11:22:33:44:5g", "0011.2233.445", "00112233445566"] {
            assert_eq!(go_parse_mac(bad), None, "{bad}");
        }
    }

    #[test]
    fn device_addr_bytes_forms() {
        assert_eq!(device_addr_bytes("192.0.2.1"), Some(vec![192, 0, 2, 1]));
        assert_eq!(device_addr_bytes("::ffff:192.0.2.1"), Some(vec![192, 0, 2, 1]));
        assert_eq!(device_addr_bytes("2001:db8::1").map(|b| b.len()), Some(16));
        assert_eq!(device_addr_bytes("kafka1:9092"), None);
    }
}
