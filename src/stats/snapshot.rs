//! The stats object and the status (docs/stats.md, "Fields" and "Status"): one `Snapshot` built from the
//! counters, serialised as the
//! `FLOWPILOT_STATS` log line (`reporter`) and the HTTP `/stats` body. Field names are snake_case, times RFC 3339 UTC,
//! counters totals since start.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::Serialize;

use super::{rfc3339, CollectorStats, ExporterSnapshot, StatsConfig, UnmanagedStats, UploadSnapshot};
use crate::aggregator::{AggregationStats, Aggregator};
use crate::metrics;
use crate::parsers::{ipfix::IPFIX_STORE, netflow::NETFLOW_STORE};
use crate::spool::Spool;

pub const SCHEMA: &str = "flowpilot.stats/v1";

/// Everything a snapshot reads. Shared as `Arc<SnapshotContext>` by the reporter and the HTTP endpoint.
pub struct SnapshotContext {
    pub version: String,
    pub instance_id: String,
    pub started_at: SystemTime,
    pub aggregator: Arc<Aggregator>,
    /// Files waiting, and (`Spool::stats`) the upload counters.
    pub spool: Arc<Spool>,
    /// `None` when unmanaged-workload creation is off.
    pub unmanaged: Option<Arc<Mutex<UnmanagedStats>>>,
    pub cfg: StatsConfig,
    pub aggregation_minutes: i16,
    /// The collectors to report (`stats::collectors()` once every consumer is registered).
    pub collectors: Vec<Arc<CollectorStats>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub schema: &'static str,
    #[serde(serialize_with = "rfc3339::time")]
    pub time: SystemTime,
    pub version: String,
    #[serde(serialize_with = "rfc3339::time")]
    pub started_at: SystemTime,
    pub uptime_seconds: u64,
    pub instance_id: String,
    /// `starting`, `ok`, `no_flows` or `upload_failing` (`status`).
    pub status: &'static str,
    #[serde(serialize_with = "rfc3339::opt")]
    pub last_flow_at: Option<SystemTime>,
    pub collectors: Vec<CollectorSnapshot>,
    pub aggregation: AggregationStats,
    pub uploads: Uploads,
    /// `null` when disabled.
    pub unmanaged_workloads: Option<UnmanagedStats>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CollectorSnapshot {
    pub name: String,
    pub parser: String,
    pub datagrams: u64,
    pub bytes: u64,
    /// Records handed to the flow filter.
    pub flows_decoded: u64,
    pub flows_forwarded: u64,
    pub flows_dropped: FlowsDropped,
    /// Failure points (see `CollectorCounters::decode_errors`).
    pub decode_errors: u64,
    pub rejected_datagrams: u64,
    /// Templates known for this collector's exporters (NetFlow and IPFIX collectors; 0 otherwise).
    pub templates: usize,
    /// Data sets of this collector's exporters waiting for their template.
    pub waiting_for_template: usize,
    /// Data sets dropped from the wait store since start (the NetFlow and IPFIX stores are process-wide).
    pub template_store_evicted: u64,
    pub rate: Rate,
    pub exporters: Vec<ExporterEntry>,
    /// Exporters left out of `exporters` by the limit.
    pub exporters_omitted: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct FlowsDropped {
    pub empty_address: u64,
    pub special_address: u64,
    pub ipv6_extension: u64,
    pub icmp_with_port: u64,
}

/// Flows per second, the collector meter's 1/5/15-minute moving averages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize)]
pub struct Rate {
    pub m1: f64,
    pub m5: f64,
    pub m15: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ExporterEntry {
    #[serde(flatten)]
    pub exporter: ExporterSnapshot,
    pub templates: usize,
    pub waiting_for_template: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Uploads {
    #[serde(flatten)]
    pub totals: UploadSnapshot,
    /// Files waiting in the data directory (queued or being sent).
    pub queued_files: usize,
    pub queued_bytes: i64,
}

/// Per collector (by position in `SnapshotContext::collectors`), each exporter's flow total at the previous
/// snapshot: the base of "flows in the interval". Kept by the reporter between log lines.
#[derive(Debug, Default)]
pub struct ExporterFlows(HashMap<usize, HashMap<String, u64>>);

/// The snapshot at `now`. `exporter_limit` keeps the exporters with the most flows; with no previous snapshot to
/// compare with, that is the most flows since start.
pub fn snapshot(ctx: &SnapshotContext, now: SystemTime, exporter_limit: Option<usize>) -> Snapshot {
    snapshot_since(ctx, now, exporter_limit, &mut ExporterFlows::default())
}

/// The snapshot at `now`, exporters ordered by their flows since `prev` (most first), which is then updated to now.
pub fn snapshot_since(
    ctx: &SnapshotContext,
    now: SystemTime,
    exporter_limit: Option<usize>,
    prev: &mut ExporterFlows,
) -> Snapshot {
    let templates = TemplateCounts::read(&ctx.collectors);
    let collectors = ctx
        .collectors
        .iter()
        .enumerate()
        .map(|(i, c)| collector(c, now, exporter_limit, prev.0.entry(i).or_default(), &templates))
        .collect();
    let last_flow_at = last_flow_at(ctx);
    let totals = ctx.spool.stats().snapshot();
    let (queued_files, queued_bytes) = ctx.spool.backlog();
    Snapshot {
        schema: SCHEMA,
        time: now,
        version: ctx.version.clone(),
        started_at: ctx.started_at,
        uptime_seconds: since(now, ctx.started_at).as_secs(),
        instance_id: ctx.instance_id.clone(),
        status: status(now, ctx.started_at, &ctx.cfg, last_flow_at, &totals, ctx.aggregation_minutes),
        last_flow_at,
        collectors,
        aggregation: ctx.aggregator.stats(),
        uploads: Uploads { totals, queued_files, queued_bytes },
        unmanaged_workloads: ctx.unmanaged.as_ref().map(|u| u.lock().unwrap_or_else(|e| e.into_inner()).clone()),
    }
}

/// The status at `now` without building the whole snapshot (`/healthz`).
pub fn current_status(ctx: &SnapshotContext, now: SystemTime) -> &'static str {
    let uploads = ctx.spool.stats().snapshot();
    status(now, ctx.started_at, &ctx.cfg, last_flow_at(ctx), &uploads, ctx.aggregation_minutes)
}

fn last_flow_at(ctx: &SnapshotContext) -> Option<SystemTime> {
    ctx.collectors.iter().filter_map(|c| c.last_flow_at()).max()
}

/// Template and wait-store counts per exporter, read once per snapshot (only with a NetFlow or IPFIX collector).
#[derive(Default)]
struct TemplateCounts {
    templates: [HashMap<String, usize>; 2],
    waiting: [HashMap<String, usize>; 2],
    evicted: u64,
}

impl TemplateCounts {
    fn read(collectors: &[Arc<CollectorStats>]) -> Self {
        if !collectors.iter().any(|c| uses_templates(&c.parser)) {
            return Self::default();
        }
        let stores = [&*NETFLOW_STORE, &*IPFIX_STORE];
        Self {
            templates: stores.map(|s| s.templates_by_device()),
            waiting: stores.map(|s| s.stored_by_device()),
            evicted: stores.iter().map(|s| s.evicted()).sum(),
        }
    }

    /// (templates, waiting) of exporter `dev`, both stores summed: the NetFlow parser also takes IPFIX.
    fn of(&self, dev: &str) -> (usize, usize) {
        let sum = |maps: &[HashMap<String, usize>; 2]| maps.iter().filter_map(|m| m.get(dev)).sum();
        (sum(&self.templates), sum(&self.waiting))
    }
}

fn uses_templates(parser: &str) -> bool {
    matches!(parser, "netflow" | "ipfix")
}

fn collector(
    c: &CollectorStats,
    now: SystemTime,
    exporter_limit: Option<usize>,
    prev: &mut HashMap<String, u64>,
    tc: &TemplateCounts,
) -> CollectorSnapshot {
    let templated = uses_templates(&c.parser);
    let (mut templates, mut waiting) = (0, 0);
    // (flows in the interval, entry); a row that restarted below its old total counts from zero.
    let mut rows: Vec<(u64, ExporterEntry)> = c
        .exporters(now)
        .into_iter()
        .map(|e| {
            let (t, w) = if templated { tc.of(&e.address) } else { (0, 0) };
            templates += t;
            waiting += w;
            let interval = e.flows.saturating_sub(prev.get(&e.address).copied().unwrap_or(0));
            (interval, ExporterEntry { exporter: e, templates: t, waiting_for_template: w })
        })
        .collect();
    *prev = rows.iter().map(|(_, e)| (e.exporter.address.clone(), e.exporter.flows)).collect();
    rows.sort_by(|(ia, a), (ib, b)| {
        ib.cmp(ia).then(b.exporter.flows.cmp(&a.exporter.flows)).then_with(|| a.exporter.address.cmp(&b.exporter.address))
    });
    let limit = exporter_limit.unwrap_or(usize::MAX);
    let exporters_omitted = rows.len().saturating_sub(limit);
    rows.truncate(limit);
    let k = c.counters();
    // A lookup only: registering here would bring meters back after the signal handler's `unregister_all`.
    let rate = metrics::get(&c.name).map_or_else(Rate::default, |m| {
        let (_, m1, m5, m15, _) = m.snapshot();
        Rate { m1, m5, m15 }
    });
    CollectorSnapshot {
        name: c.name.clone(),
        parser: c.parser.clone(),
        datagrams: k.datagrams,
        bytes: k.bytes,
        flows_decoded: k.flows,
        flows_forwarded: k.forwarded,
        flows_dropped: FlowsDropped {
            empty_address: k.dropped_empty_address,
            special_address: k.dropped_special_address,
            ipv6_extension: k.dropped_ipv6_extension,
            icmp_with_port: k.dropped_icmp_with_port,
        },
        decode_errors: k.decode_errors,
        rejected_datagrams: k.rejected_datagrams,
        templates,
        waiting_for_template: waiting,
        template_store_evicted: if templated { tc.evicted } else { 0 },
        rate,
        exporters: rows.into_iter().map(|(_, e)| e).collect(),
        exporters_omitted,
    }
}

/// The process status ("Status"): `starting` before the first stats interval has passed; else `upload_failing` when
/// uploads have failed since the last success for longer than one aggregation window; else `no_flows` when no flow
/// was decoded for `idle_warn_seconds` (counted from the start if none ever was); else `ok`.
pub fn status(
    now: SystemTime,
    started_at: SystemTime,
    cfg: &StatsConfig,
    last_flow_at: Option<SystemTime>,
    uploads: &UploadSnapshot,
    aggregation_minutes: i16,
) -> &'static str {
    let window = Duration::from_secs(60 * aggregation_minutes.max(0) as u64);
    if since(now, started_at) < cfg.interval() {
        "starting"
    } else if uploads.first_failure_since_success_at.is_some_and(|t| since(now, t) > window) {
        "upload_failing"
    } else if since(now, last_flow_at.unwrap_or(started_at)) >= Duration::from_secs(cfg.idle_warn_seconds) {
        "no_flows"
    } else {
        "ok"
    }
}

fn since(now: SystemTime, t: SystemTime) -> Duration {
    now.duration_since(t).unwrap_or(Duration::ZERO)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::{Config, Secret};
    use crate::parsers::{decode_datagram, ParserContext, ReceivedDatagram};
    use crate::stats::{Proto, UploadStats};
    use serde_json::Value;
    use std::collections::BTreeSet;
    use std::time::UNIX_EPOCH;

    const T0: Duration = Duration::from_secs(1_800_000_000); // 2027-01-15T08:00:00Z

    pub(crate) fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + T0 + Duration::from_secs(secs)
    }

    /// A context over its own data directory and upload counters, with `collectors`.
    pub(crate) fn context(
        collectors: Vec<Arc<CollectorStats>>,
        cfg: StatsConfig,
    ) -> (SnapshotContext, &'static UploadStats, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let uploads: &'static UploadStats = Box::leak(Box::new(UploadStats::new()));
        let spool = Arc::new(Spool::new(dir.path().to_path_buf(), 24, 500).with_stats(uploads));
        let aggregator = Arc::new(Aggregator::new(spool.clone(), "pce.test:8443", 1, "uuid-1".into(), 10000));
        let ctx = SnapshotContext {
            version: "0.9.0".into(),
            instance_id: "uuid-1".into(),
            started_at: at(0),
            aggregator,
            spool,
            unmanaged: None,
            cfg,
            aggregation_minutes: 10,
            collectors,
        };
        (ctx, uploads, dir)
    }

    /// The keys of `v`, recursively: object keys, and for arrays the keys of their first element.
    fn key_paths(v: &Value, path: &str, out: &mut BTreeSet<String>) {
        match v {
            Value::Object(m) => {
                for (k, v) in m {
                    let p = format!("{path}.{k}");
                    out.insert(p.clone());
                    key_paths(v, &p, out);
                }
            }
            Value::Array(a) => {
                if let Some(first) = a.first() {
                    key_paths(first, &format!("{path}[]"), out);
                }
            }
            _ => {}
        }
    }

    fn keys(v: &Value) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        key_paths(v, "", &mut out);
        out
    }

    #[test]
    fn snapshot_shape() {
        let c = Arc::new(CollectorStats::new("snapshot-shape", "netflow"));
        c.datagram_at("192.0.2.10", Some(Proto::NetflowV9), 1400, 30, 0, at(100));
        let (mut ctx, uploads, _dir) = context(vec![c], StatsConfig::default());
        uploads.on_failure("503", "HTTP 503 Service Unavailable");
        uploads.on_success(30);
        ctx.unmanaged = Some(Arc::new(Mutex::new(UnmanagedStats::default())));
        let v = serde_json::to_value(snapshot(&ctx, at(200), Some(50))).unwrap();
        let example: Value = serde_json::from_str(include_str!("../../tests/fixtures/stats_example.json")).unwrap();
        let (got, want) = (keys(&v), keys(&example));
        assert_eq!(
            got.symmetric_difference(&want).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "key sets differ from tests/fixtures/stats_example.json"
        );
        assert_eq!(v["schema"], "flowpilot.stats/v1");
        assert_eq!((v["time"].as_str(), v["started_at"].as_str()), (Some("2027-01-15T08:03:20Z"), Some("2027-01-15T08:00:00Z")));
        assert_eq!(v["uptime_seconds"], 200);
        assert_eq!(v["last_flow_at"], "2027-01-15T08:01:40Z");
        let col = &v["collectors"][0];
        assert_eq!((col["name"].as_str(), col["flows_decoded"].as_u64()), (Some("snapshot-shape"), Some(30)));
        assert_eq!(col["exporters"][0]["protocols"], serde_json::json!(["netflow_v9"]));
        assert_eq!(col["exporters"][0]["first_seen"], "2027-01-15T08:01:40Z");
        assert_eq!(v["uploads"]["failed"]["503"], 1);
        // Disabled unmanaged workloads are null.
        ctx.unmanaged = None;
        assert_eq!(serde_json::to_value(snapshot(&ctx, at(200), None)).unwrap()["unmanaged_workloads"], Value::Null);
    }

    #[test]
    fn top_50_exporters() {
        let c = Arc::new(CollectorStats::new("top-50", "ipfix"));
        let addr = |i: u64| if i == 59 { "2001:db8::1".to_string() } else { format!("10.0.0.{i}") };
        // Since start, the low addresses lead; in the interval, the high ones.
        for i in 0..60 {
            c.datagram_at(&addr(i), Some(Proto::Ipfix), 100, 1000 - i, 0, at(10));
        }
        let (ctx, _, _dir) = context(vec![c.clone()], StatsConfig::default());
        let mut prev = ExporterFlows::default();
        snapshot_since(&ctx, at(60), Some(50), &mut prev);
        for i in 0..60 {
            c.datagram_at(&addr(i), Some(Proto::Ipfix), 100, i + 1, 0, at(70));
        }
        let s = snapshot_since(&ctx, at(120), Some(50), &mut prev);
        let col = &s.collectors[0];
        assert_eq!((col.exporters.len(), col.exporters_omitted), (50, 10));
        let listed: Vec<&str> = col.exporters.iter().map(|e| e.exporter.address.as_str()).collect();
        let want: Vec<String> = (10..60).rev().map(addr).collect();
        assert_eq!(listed, want);
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["collectors"][0]["exporters"][0]["address"], "2001:db8::1");
        // Without a previous snapshot (HTTP /stats): every exporter, by flows since start.
        let all = snapshot(&ctx, at(120), None);
        let col = &all.collectors[0];
        assert_eq!((col.exporters.len(), col.exporters_omitted), (60, 0));
        assert_eq!(col.exporters[0].exporter.address, "10.0.0.0");
        assert_eq!(col.exporters[59].exporter.address, "2001:db8::1");
    }

    #[test]
    fn templates_per_exporter() {
        let c = Arc::new(CollectorStats::new("templates", "netflow"));
        let (tx, _rx) = crossbeam_channel::unbounded();
        let pctx = ParserContext::new(metrics::Meter::new(), crate::flow::FlowSink::new(tx), c.clone());
        // NetFlow v9: a template (id 256, one field) and a data set for unknown template 300.
        let mut d = vec![0, 9, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        d.extend([0, 0, 0, 12, 1, 0, 0, 1, 0, 8, 0, 4]);
        d.extend([1, 44, 0, 8, 10, 0, 0, 1]);
        let dev = "198.51.100.77"; // unique to this test: the stores are process-wide
        let pd = ReceivedDatagram { device_addr: dev.into(), seq_id: String::new(), transport: "udp".into(), buf: d };
        decode_datagram("netflow", &pd, &pctx);
        let (ctx, _, _dir) = context(vec![c], StatsConfig::default());
        let s = snapshot(&ctx, SystemTime::now(), None);
        let col = &s.collectors[0];
        let e = col.exporters.iter().find(|e| e.exporter.address == dev).unwrap();
        assert_eq!((e.templates, e.waiting_for_template), (1, 1));
        assert_eq!((col.templates, col.waiting_for_template), (1, 1));
    }

    #[test]
    fn snapshot_does_not_register_meters() {
        let c = Arc::new(CollectorStats::new("snapshot-no-meter", "netflow"));
        let (ctx, _, _dir) = context(vec![c], StatsConfig::default());
        let s = snapshot(&ctx, at(100), None);
        assert_eq!(s.collectors[0].rate, Rate::default());
        assert!(metrics::get("snapshot-no-meter").is_none(), "the snapshot registered a meter");
        // A registered meter's rates are read.
        let m = metrics::get_or_register_meter("snapshot-with-meter");
        m.mark(50);
        m.tick();
        let c = Arc::new(CollectorStats::new("snapshot-with-meter", "netflow"));
        let (ctx, _, _dir) = context(vec![c], StatsConfig::default());
        assert!(snapshot(&ctx, at(100), None).collectors[0].rate.m1 > 0.0);
    }

    #[test]
    fn status_rules() {
        let cfg = StatsConfig { interval_seconds: 60, idle_warn_seconds: 300, ..StatsConfig::default() };
        let ok_upload = UploadSnapshot { last_success_at: Some(at(500)), ..Default::default() };
        // Failing since 1000 s: longer than the 10-minute window from 1601 s on.
        let failing = UploadSnapshot {
            last_success_at: Some(at(500)),
            last_error_at: Some(at(1500)),
            first_failure_since_success_at: Some(at(1000)),
            ..Default::default()
        };
        let none = UploadSnapshot::default();
        #[rustfmt::skip]
        let cases: &[(u64, Option<u64>, &UploadSnapshot, &str)] = &[
            // now, last flow, uploads, status
            (59, None, &none, "starting"),
            (59, None, &failing, "starting"),
            (60, None, &none, "ok"),           // no flow for 60 s < 300 s since start
            (299, None, &none, "ok"),
            (300, None, &none, "no_flows"),    // none ever: counted from the start
            (1000, Some(990), &ok_upload, "ok"),
            (1000, Some(700), &ok_upload, "no_flows"),
            (1600, Some(1590), &failing, "ok"),             // failing for exactly one window
            (1601, Some(1590), &failing, "upload_failing"),
            (1601, Some(100), &failing, "upload_failing"),  // beats no_flows
            (1601, None, &failing, "upload_failing"),
        ];
        for &(now, last_flow, uploads, want) in cases {
            let got = status(at(now), at(0), &cfg, last_flow.map(at), uploads, 10);
            assert_eq!(got, want, "now={now} last_flow={last_flow:?}");
        }
        // An interval of 0 (metrics_print_seconds overflow) behaves as 60 s.
        let zero = StatsConfig { interval_seconds: 0, ..cfg.clone() };
        assert_eq!(status(at(59), at(0), &zero, None, &none, 10), "starting");
        assert_eq!(status(at(60), at(0), &zero, None, &none, 10), "ok");
        // The snapshot carries it.
        let (ctx, _, _dir) = context(Vec::new(), cfg);
        assert_eq!(snapshot(&ctx, at(10), None).status, "starting");
        assert_eq!(snapshot(&ctx, at(400), None).status, "no_flows");
    }

    #[test]
    fn secret_not_in_stats() {
        let cfg = Config {
            api_credentials: Some(("api_1".into(), Secret("topsecret".into()))),
            ..Config::default()
        };
        let c = Arc::new(CollectorStats::new("secret", "sflow"));
        c.datagram_at("192.0.2.1", Some(Proto::Sflow), 100, 1, 0, at(10));
        let (ctx, uploads, _dir) = context(vec![c], cfg.stats.clone());
        // What reqwest reports for a URL with credentials, and a status failure.
        uploads.on_failure("error", "error sending request for url (https://api_1:topsecret@pce.test:8443/api/v2/orgs/1/traffic_data)");
        uploads.on_failure("401", "HTTP 401 Unauthorized");
        uploads.on_failure("error", "error sending request for url (https://api_1:topsecret@pce.test:8443/api/v2/orgs/1/traffic_data)");
        let json = serde_json::to_string(&snapshot(&ctx, at(100), None)).unwrap();
        assert!(!json.contains("topsecret"), "{json}");
        // base64("api_1:topsecret"), the basic-auth header value.
        assert!(!json.contains("YXBpXzE6dG9wc2VjcmV0"), "{json}");
        assert!(!json.to_ascii_lowercase().contains("authorization"), "{json}");
        assert!(json.contains("https://***@pce.test:8443"), "{json}");
    }
}
