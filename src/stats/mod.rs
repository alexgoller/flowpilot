//! Stats output (docs/stats.md): the `stats` config key
//! (docs/configuration.md) and the counters: per collector and per exporter (`collector`), uploads
//! (`upload`) and unmanaged workloads (`unmanaged`). Aggregation counters live in `aggregator::AggregationStats`.
//! `snapshot` turns them into the JSON object and the status, `reporter` logs it ("Output 1"), `health` tracks the
//! core threads for `/healthz`, `http` serves `/healthz`, `/stats` and `/metrics` (`prometheus`) ("Output 2").

mod collector;
mod health;
pub mod http;
pub mod prometheus;
pub mod reporter;
pub mod snapshot;
mod unmanaged;
mod upload;

pub use collector::*;
pub use health::*;
pub use snapshot::{snapshot, status, Snapshot, SnapshotContext};
pub use unmanaged::*;
pub use upload::*;

use serde_json::Value;

/// The `stats` key, defaults applied.
#[derive(Clone, Debug, PartialEq)]
pub struct StatsConfig {
    /// How often the `FLOWPILOT_STATS` line is logged (default: `metrics_print_seconds`).
    pub interval_seconds: u64,
    /// The `FLOWPILOT_STATS` log line.
    pub log: bool,
    /// The original per-collector metrics lines.
    pub legacy_metrics: bool,
    /// Address of the HTTP endpoint; `None` = off.
    pub http_listen: Option<String>,
    /// No flow for this long gives the `no_flows` status.
    pub idle_warn_seconds: u64,
}

impl StatsConfig {
    /// The stats interval; 0 (a `metrics_print_seconds` overflow decodes to 0, as in FlowLink) means 60 s.
    pub fn interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(if self.interval_seconds == 0 { 60 } else { self.interval_seconds })
    }
}

impl Default for StatsConfig {
    /// The defaults with the schema's `metrics_print_seconds` default.
    fn default() -> Self {
        decode(&Value::Null, 60).expect("the defaults are valid")
    }
}

/// Decode `doc["stats"]` (`Null` = defaults) after the schema check. `metrics_print_seconds` comes from the main
/// config.
pub fn decode(v: &Value, metrics_print_seconds: i16) -> Result<StatsConfig, Vec<String>> {
    // The schema has checked types and minimums.
    let int = |k: &str| v.get(k).and_then(Value::as_f64).map(|n| n as u64);
    let flag = |k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(true);
    let http_listen = v
        .get("http_listen")
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some(a) = &http_listen {
        if a.parse::<std::net::SocketAddr>().is_err() {
            return Err(vec![format!(
                "stats.http_listen: not an ip:port address: {a}"
            )]);
        }
    }
    Ok(StatsConfig {
        // `metrics_print_seconds` is never negative once validated (overflow decodes to 0).
        interval_seconds: int("interval_seconds")
            .unwrap_or_else(|| u64::try_from(metrics_print_seconds).unwrap_or(0)),
        log: flag("log"),
        legacy_metrics: flag("legacy_metrics"),
        http_listen,
        idle_warn_seconds: int("idle_warn_seconds").unwrap_or(300),
    })
}

/// Serde helpers: times as RFC 3339 UTC ("Output 1"), whole seconds.
pub mod rfc3339 {
    use std::time::SystemTime;

    use chrono::{DateTime, SecondsFormat, Utc};
    use serde::Serializer;

    pub fn format(t: SystemTime) -> String {
        DateTime::<Utc>::from(t).to_rfc3339_opts(SecondsFormat::Secs, true)
    }

    /// `#[serde(serialize_with = "rfc3339::time")]` on a `SystemTime`.
    pub fn time<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format(*t))
    }

    /// `#[serde(serialize_with = "rfc3339::opt")]` on an `Option<SystemTime>`; `None` is `null`.
    pub fn opt<S: Serializer>(t: &Option<SystemTime>, s: S) -> Result<S::Ok, S::Error> {
        match t {
            Some(t) => s.serialize_str(&format(*t)),
            None => s.serialize_none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stats_defaults() {
        assert_eq!(
            decode(&Value::Null, 60).unwrap(),
            StatsConfig {
                interval_seconds: 60,
                log: true,
                legacy_metrics: true,
                http_listen: None,
                idle_warn_seconds: 300,
            }
        );
        assert_eq!(
            decode(&json!({"interval_seconds": 30}), 60)
                .unwrap()
                .interval_seconds,
            30
        );
        // The default interval follows metrics_print_seconds.
        assert_eq!(decode(&Value::Null, 45).unwrap().interval_seconds, 45);
        // An overflowed metrics_print_seconds (0) still gives a usable interval.
        assert_eq!(decode(&Value::Null, 0).unwrap().interval(), std::time::Duration::from_secs(60));
    }

    #[test]
    fn stats_values() {
        let s = decode(
            &json!({"log": false, "legacy_metrics": false, "http_listen": "0.0.0.0:9180", "idle_warn_seconds": 60}),
            60,
        )
        .unwrap();
        assert!(!s.log && !s.legacy_metrics);
        assert_eq!(s.http_listen.as_deref(), Some("0.0.0.0:9180"));
        assert_eq!(s.idle_warn_seconds, 60);
        assert_eq!(
            decode(&json!({"http_listen": "localhost"}), 60).unwrap_err(),
            ["stats.http_listen: not an ip:port address: localhost"]
        );
    }

    #[test]
    fn times_serialize_as_rfc3339() {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000);
        let s = UnmanagedStats { last_refresh_at: Some(t), ..Default::default() };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["last_refresh_at"], "2027-01-15T08:00:00Z");
        assert_eq!(v["burst_paused_since"], Value::Null);
        assert_eq!(v["last_window"]["created"], 0);
    }
}
