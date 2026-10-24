//! The stats object in the Prometheus text format, version 0.0.4
//! (docs/stats.md, "Prometheus metrics"). Names carry the
//! `flowpilot_` prefix, counters end in `_total`, exporter series are labelled `collector` and `exporter`. The metric
//! list is in docs/stats.md.

use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use super::snapshot::{CollectorSnapshot, ExporterEntry};
use super::Snapshot;

const STATUSES: [&str; 4] = ["starting", "ok", "no_flows", "upload_failing"];

/// `s` as Prometheus text.
pub fn render(s: &Snapshot) -> String {
    let mut o = Out(String::new());
    let one = |v: Value| vec![(String::new(), v)];

    // Process.
    o.gauge("info", "Version and instance id (always 1).", vec![(
        labels(&[("version", &s.version), ("instance_id", &s.instance_id)]),
        Value::Int(1),
    )]);
    o.gauge("start_time_seconds", "Process start, Unix seconds.", one(ts(s.started_at)));
    o.gauge("uptime_seconds", "Seconds since start.", one(Value::Int(s.uptime_seconds)));
    o.gauge(
        "status",
        "1 for the current status, 0 for the others.",
        STATUSES.iter().map(|st| (labels(&[("status", st)]), Value::Bool(*st == s.status))).collect(),
    );
    o.gauge("last_flow_timestamp_seconds", "Last datagram that carried flows, Unix seconds.", opt(s.last_flow_at, ts));

    // Collectors.
    let cs = &s.collectors;
    let per = |f: fn(&CollectorSnapshot) -> Value| -> Vec<(String, Value)> {
        cs.iter().map(|c| (labels(&[("collector", &c.name)]), f(c))).collect()
    };
    o.gauge(
        "collector_info",
        "Parser of each collector (always 1).",
        cs.iter().map(|c| (labels(&[("collector", &c.name), ("parser", &c.parser)]), Value::Int(1))).collect(),
    );
    o.counter("datagrams_total", "Datagrams received.", per(|c| Value::Int(c.datagrams)));
    o.counter("received_bytes_total", "Bytes of the datagrams received.", per(|c| Value::Int(c.bytes)));
    o.counter("flows_decoded_total", "Flow records handed to the flow filter.", per(|c| Value::Int(c.flows_decoded)));
    o.counter("flows_forwarded_total", "Flows sent on to aggregation.", per(|c| Value::Int(c.flows_forwarded)));
    o.counter(
        "flows_dropped_total",
        "Flows discarded by the filter, by reason.",
        cs.iter()
            .flat_map(|c| {
                let d = c.flows_dropped;
                [
                    ("empty_address", d.empty_address),
                    ("special_address", d.special_address),
                    ("ipv6_extension", d.ipv6_extension),
                    ("icmp_with_port", d.icmp_with_port),
                ]
                .map(|(r, n)| (labels(&[("collector", &c.name), ("reason", r)]), Value::Int(n)))
            })
            .collect(),
    );
    o.counter("decode_errors_total", "Decode failure points.", per(|c| Value::Int(c.decode_errors)));
    o.counter(
        "rejected_datagrams_total",
        "Datagrams from senders not in remote_addrs.",
        per(|c| Value::Int(c.rejected_datagrams)),
    );
    o.gauge("templates", "Templates known for the collector's exporters.", per(|c| Value::Size(c.templates)));
    o.gauge(
        "waiting_for_template",
        "Data sets waiting for their template.",
        per(|c| Value::Size(c.waiting_for_template)),
    );
    o.counter(
        "template_store_evicted_total",
        "Data sets dropped from the template wait store (process-wide).",
        per(|c| Value::Int(c.template_store_evicted)),
    );
    o.gauge(
        "flows_per_second",
        "Flow rate, 1, 5 and 15 minute moving averages.",
        cs.iter()
            .flat_map(|c| {
                [("1m", c.rate.m1), ("5m", c.rate.m5), ("15m", c.rate.m15)]
                    .map(|(w, r)| (labels(&[("collector", &c.name), ("window", w)]), Value::Float(r)))
            })
            .collect(),
    );
    o.gauge("exporters", "Exporters tracked.", per(|c| Value::Size(c.exporters.len() + c.exporters_omitted)));

    // Exporters.
    let rows: Vec<(&str, &ExporterEntry)> =
        cs.iter().flat_map(|c| c.exporters.iter().map(move |e| (c.name.as_str(), e))).collect();
    let per = |f: fn(&ExporterEntry) -> Value| -> Vec<(String, Value)> {
        rows.iter().map(|(c, e)| (labels(&[("collector", c), ("exporter", &e.exporter.address)]), f(e))).collect()
    };
    o.gauge(
        "exporter_protocol_info",
        "Protocols seen from each exporter (always 1).",
        rows.iter()
            .flat_map(|(c, e)| {
                e.exporter.protocols.iter().map(|p| {
                    // The JSON name (`netflow_v9`).
                    let p = serde_json::to_value(p).ok().and_then(|v| v.as_str().map(str::to_string));
                    let p = p.unwrap_or_default();
                    (labels(&[("collector", c), ("exporter", &e.exporter.address), ("protocol", &p)]), Value::Int(1))
                })
            })
            .collect(),
    );
    o.counter("exporter_datagrams_total", "Datagrams from the exporter.", per(|e| Value::Int(e.exporter.datagrams)));
    o.counter("exporter_flows_total", "Flows decoded from the exporter.", per(|e| Value::Int(e.exporter.flows)));
    o.counter(
        "exporter_decode_errors_total",
        "Decode failure points in the exporter's datagrams.",
        per(|e| Value::Int(e.exporter.decode_errors)),
    );
    o.gauge(
        "exporter_first_seen_timestamp_seconds",
        "First datagram from the exporter, Unix seconds.",
        per(|e| ts(e.exporter.first_seen)),
    );
    o.gauge(
        "exporter_last_seen_timestamp_seconds",
        "Last datagram from the exporter, Unix seconds.",
        per(|e| ts(e.exporter.last_seen)),
    );
    o.gauge(
        "exporter_flows_per_second",
        "Flows in the last complete minute / 60.",
        per(|e| Value::Float(e.exporter.flows_per_second)),
    );
    o.gauge("exporter_templates", "Templates known for the exporter.", per(|e| Value::Size(e.templates)));
    o.gauge(
        "exporter_waiting_for_template",
        "The exporter's data sets waiting for their template.",
        per(|e| Value::Size(e.waiting_for_template)),
    );

    // Aggregation.
    let a = &s.aggregation;
    o.gauge(
        "aggregation_window_flows",
        "Flow records merged into the current window.",
        one(Value::Int(a.window_flows)),
    );
    o.gauge("aggregation_window_keys", "Distinct keys in the current window.", one(Value::Size(a.window_keys)));
    o.gauge("aggregation_last_flush_timestamp_seconds", "Last window flush, Unix seconds.", opt(a.last_flush_at, ts));
    o.gauge(
        "aggregation_last_window_records",
        "Aggregated records in the last window.",
        one(Value::Size(a.last_window_records)),
    );
    o.gauge("aggregation_last_window_new_ips", "New IPs in the last window.", one(Value::Size(a.last_window_new_ips)));

    // Uploads.
    let u = &s.uploads.totals;
    o.counter("uploads_succeeded_total", "Files the PCE accepted.", one(Value::Int(u.succeeded)));
    o.counter(
        "uploads_failed_total",
        "Failed upload attempts, by HTTP status or \"error\".",
        u.failed.iter().map(|(k, n)| (labels(&[("kind", k)]), Value::Int(*n))).collect(),
    );
    o.counter("uploaded_records_total", "Records in the files the PCE accepted.", one(Value::Int(u.records_uploaded)));
    o.gauge("upload_last_success_timestamp_seconds", "Last accepted upload, Unix seconds.", opt(u.last_success_at, ts));
    o.gauge("upload_last_error_timestamp_seconds", "Last failed upload, Unix seconds.", opt(u.last_error_at, ts));
    o.gauge(
        "upload_failing_since_timestamp_seconds",
        "First failure after the last success, Unix seconds (absent while uploads succeed).",
        opt(u.first_failure_since_success_at, ts),
    );
    o.counter(
        "upload_files_removed_total",
        "Files deleted unsent, by reason.",
        vec![
            (labels(&[("reason", "size_cap")]), Value::Int(u.removed_by_cap)),
            (labels(&[("reason", "retention")]), Value::Int(u.removed_by_retention)),
        ],
    );
    o.gauge("upload_queued_files", "Files waiting in the data directory.", one(Value::Size(s.uploads.queued_files)));
    o.gauge("upload_queued_bytes", "Bytes waiting in the data directory.", one(Value::Signed(s.uploads.queued_bytes)));

    // Unmanaged workloads (absent when disabled).
    if let Some(w) = &s.unmanaged_workloads {
        o.gauge("unmanaged_dry_run", "1 in dry run.", one(Value::Bool(w.dry_run)));
        o.gauge("unmanaged_known_ips", "IPs that have a workload on the PCE.", one(Value::Size(w.known_ips)));
        o.gauge(
            "unmanaged_last_refresh_timestamp_seconds",
            "Last workload list refresh attempt, Unix seconds.",
            opt(w.last_refresh_at, ts),
        );
        o.gauge("unmanaged_last_refresh_ok", "1 if the last refresh succeeded.", opt(w.last_refresh_ok, Value::Bool));
        let l = &w.last_window;
        o.gauge(
            "unmanaged_last_window",
            "Counts of the last window, by kind.",
            [
                ("candidates", l.candidates),
                ("eligible", l.eligible),
                ("created", l.created),
                ("deferred", l.deferred),
                ("errors", l.errors),
                ("labels_created", l.labels_created),
            ]
            .map(|(k, n)| (labels(&[("count", k)]), Value::Size(n)))
            .into(),
        );
        o.counter("unmanaged_created_total", "Workloads created.", one(Value::Int(w.created_total)));
        o.gauge("unmanaged_created_today", "Creations in the last 24 hours.", one(Value::Size(w.created_today)));
        o.counter(
            "unmanaged_would_create_total",
            "Dry run: IPs listed as would-create, summed over windows.",
            one(Value::Int(w.would_create_total)),
        );
        o.counter(
            "unmanaged_deferred_total",
            "Eligible IPs left for a later window, summed over windows.",
            one(Value::Int(w.deferred_total)),
        );
        o.counter("unmanaged_failed_total", "Errors, summed over windows.", one(Value::Int(w.failed_total)));
        o.gauge("unmanaged_daily_cap", "Creations allowed per 24 hours.", one(Value::Size(w.daily_cap)));
        o.gauge("unmanaged_per_window_cap", "Creations allowed per window.", one(Value::Size(w.per_window_cap)));
        let paused = w.burst_paused_since.is_some();
        o.gauge("unmanaged_burst_paused", "1 while a burst pause is active.", one(Value::Bool(paused)));
        let disabled = w.disabled_reason.is_some();
        o.gauge("unmanaged_disabled", "1 when disabled by a missing label type.", one(Value::Bool(disabled)));
    }
    o.0
}

/// A sample value, printed exactly (integers are not routed through `f64`).
#[derive(Clone, Copy)]
enum Value {
    Int(u64),
    Size(usize),
    Signed(i64),
    Float(f64),
    Bool(bool),
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Value::Int(n) => write!(f, "{n}"),
            Value::Size(n) => write!(f, "{n}"),
            Value::Signed(n) => write!(f, "{n}"),
            Value::Float(x) if x.is_nan() => f.write_str("NaN"),
            Value::Float(x) if x.is_infinite() => f.write_str(if x > 0.0 { "+Inf" } else { "-Inf" }),
            Value::Float(x) => write!(f, "{x}"),
            Value::Bool(b) => f.write_str(if b { "1" } else { "0" }),
        }
    }
}

/// The text so far; one call per metric family keeps a family's samples together.
struct Out(String);

impl Out {
    fn counter(&mut self, name: &str, help: &str, samples: Vec<(String, Value)>) {
        self.family(name, "counter", help, samples);
    }

    fn gauge(&mut self, name: &str, help: &str, samples: Vec<(String, Value)>) {
        self.family(name, "gauge", help, samples);
    }

    /// `# HELP`, `# TYPE` and the samples; nothing for a family without samples.
    fn family(&mut self, name: &str, kind: &str, help: &str, samples: Vec<(String, Value)>) {
        if samples.is_empty() {
            return;
        }
        let o = &mut self.0;
        let _ = writeln!(o, "# HELP flowpilot_{name} {help}");
        let _ = writeln!(o, "# TYPE flowpilot_{name} {kind}");
        for (labels, v) in samples {
            let _ = writeln!(o, "flowpilot_{name}{labels} {v}");
        }
    }
}

/// `{k="v",...}`, values escaped (backslash, double quote, newline).
fn labels(pairs: &[(&str, &str)]) -> String {
    let body: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")))
        .collect();
    format!("{{{}}}", body.join(","))
}

/// Unix seconds.
fn ts(t: SystemTime) -> Value {
    Value::Int(t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()))
}

/// One unlabelled sample, or none for `None`.
fn opt<T>(v: Option<T>, f: impl Fn(T) -> Value) -> Vec<(String, Value)> {
    v.map(|v| vec![(String::new(), f(v))]).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::snapshot::snapshot;
    use crate::stats::snapshot::tests::{at, context};
    use crate::stats::{CollectorStats, Proto, StatsConfig, UnmanagedStats};
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    fn rendered() -> String {
        let c = Arc::new(CollectorStats::new("netflow", "netflow"));
        c.datagram_at("192.0.2.10", Some(Proto::NetflowV9), 1400, 30, 1, at(100));
        c.datagram_at("2001:db8::1", Some(Proto::Ipfix), 200, 5, 0, at(110));
        c.forwarded();
        c.dropped(crate::stats::DropReason::SpecialAddress);
        let (mut ctx, uploads, _dir) = context(vec![c], StatsConfig::default());
        uploads.on_failure("503", "HTTP 503 Service Unavailable");
        uploads.on_success(30);
        ctx.unmanaged = Some(Arc::new(Mutex::new(UnmanagedStats { daily_cap: 100, ..Default::default() })));
        render(&snapshot(&ctx, at(200), None))
    }

    #[test]
    fn render_series() {
        let text = rendered();
        for line in [
            "# TYPE flowpilot_flows_decoded_total counter",
            "flowpilot_flows_decoded_total{collector=\"netflow\"} 35",
            "flowpilot_flows_forwarded_total{collector=\"netflow\"} 1",
            "flowpilot_flows_dropped_total{collector=\"netflow\",reason=\"special_address\"} 1",
            "flowpilot_decode_errors_total{collector=\"netflow\"} 1",
            "flowpilot_exporter_flows_total{collector=\"netflow\",exporter=\"192.0.2.10\"} 30",
            "flowpilot_exporter_flows_total{collector=\"netflow\",exporter=\"2001:db8::1\"} 5",
            "flowpilot_exporter_protocol_info{collector=\"netflow\",exporter=\"2001:db8::1\",protocol=\"ipfix\"} 1",
            "flowpilot_exporter_last_seen_timestamp_seconds{collector=\"netflow\",exporter=\"2001:db8::1\"} 1800000110",
            "flowpilot_status{status=\"no_flows\"} 0",
            "flowpilot_uptime_seconds 200",
            "flowpilot_uploads_succeeded_total 1",
            "flowpilot_uploads_failed_total{kind=\"503\"} 1",
            "flowpilot_uploaded_records_total 30",
            "flowpilot_unmanaged_daily_cap 100",
        ] {
            assert!(text.lines().any(|l| l == line), "missing {line:?} in\n{text}");
        }
    }

    #[test]
    fn render_follows_conventions() {
        let text = rendered();
        let (mut families, mut current) = (BTreeSet::new(), "");
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let (name, kind) = rest.split_once(' ').unwrap();
                assert!(families.insert(name), "family {name} declared twice");
                assert_eq!(kind == "counter", name.ends_with("_total"), "{line}");
                current = name;
            } else if !line.starts_with("# HELP ") {
                let name = line.split(['{', ' ']).next().unwrap();
                assert!(name.starts_with("flowpilot_"), "{line}");
                assert_eq!(name, current, "sample outside its family: {line}");
            }
        }
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn label_values_are_escaped() {
        let c = Arc::new(CollectorStats::new("a\"b\\c\nd", "text"));
        let (ctx, _, _dir) = context(vec![c], StatsConfig::default());
        let text = render(&snapshot(&ctx, at(200), None));
        assert!(text.contains(r#"flowpilot_datagrams_total{collector="a\"b\\c\nd"} 0"#), "{text}");
    }
}
