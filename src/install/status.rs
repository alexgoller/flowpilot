//! `flowpilot status`: the service state from systemd and the numbers from the local stats endpoint.

use std::fmt::Write as _;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::thread;
use std::time::Duration;

use serde_json::Value;

use super::apply::CONFIG;
use super::args::StatusArgs;
use super::health;
use super::run::stats_listen_of;
use super::system::{RealSystem, System};

macro_rules! say {
    ($w:expr, $($t:tt)*) => {{ let _ = writeln!($w, $($t)*); }};
}

pub fn run_status(args: StatusArgs) -> i32 {
    let mut sys = RealSystem::new("/");
    run_status_with(&mut sys, &mut fetch_stats, &mut std::io::stdout(), &mut std::io::stderr(), args)
}

/// How often a `busy` answer is retried, and the wait between tries.
const BUSY_TRIES: u32 = 3;
const BUSY_WAIT: Duration = Duration::from_millis(500);

/// Reads `/stats` from `listen` (`ip:port`); a `busy` answer is retried a few times.
pub fn fetch_stats(listen: &str) -> Result<Value, String> {
    let addr = connect_addr(listen)?;
    for try_no in 1..=BUSY_TRIES {
        let (code, body) = health::get(addr, "/stats")?;
        let json: Option<Value> = serde_json::from_str(&body).ok();
        match (code, json) {
            (200, Some(stats)) => return Ok(stats),
            (503, Some(j)) if j["status"] == "busy" => {
                if try_no == BUSY_TRIES {
                    return Err(format!("{addr}: the stats endpoint stayed busy"));
                }
                thread::sleep(BUSY_WAIT);
            }
            (code, _) => return Err(format!("{addr}: /stats answered HTTP {code}")),
        }
    }
    unreachable!("the last try returns")
}

/// Where to connect for a `stats.http_listen`: a wildcard bind address is reached on the loopback.
fn connect_addr(listen: &str) -> Result<SocketAddr, String> {
    let mut addr: SocketAddr = listen.parse().map_err(|_| format!("stats.http_listen is not an ip:port address: {listen}"))?;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() { Ipv4Addr::LOCALHOST.into() } else { Ipv6Addr::LOCALHOST.into() });
    }
    Ok(addr)
}

/// `fetch` stands in for the HTTP call. Exit 0 when the service is active and the status is not `unhealthy`; the
/// state of the service goes to `out` even when the config or the endpoint cannot be read (the reason goes to `err`).
pub fn run_status_with(
    sys: &mut dyn System,
    fetch: &mut dyn FnMut(&str) -> Result<Value, String>,
    out: &mut dyn Write,
    err: &mut dyn Write,
    args: StatusArgs,
) -> i32 {
    let service = sys.service_state("flowpilot");
    let config = Path::new(CONFIG);
    let report = |out: &mut dyn Write, stats: Option<&Value>| {
        if args.json {
            say!(out, "{}", serde_json::json!({ "service": service, "stats": stats }));
        } else {
            let _ = write!(out, "{}", render_status(&service, stats));
        }
    };

    let Some(yaml) = sys.read(config) else {
        report(out, None);
        if sys.exists(config) {
            say!(err, "Cannot read {CONFIG} (permission denied); run as root or as a member of group flowpilot: sudo flowpilot status");
        } else {
            say!(err, "{CONFIG} does not exist; FlowPilot is not installed here (see: flowpilot install)");
        }
        return 1;
    };
    let Some(listen) = stats_listen_of(&yaml) else {
        report(out, None);
        say!(err, "The statistics endpoint is off: set stats.http_listen in {CONFIG} to see exporters and uploads.");
        return i32::from(service != "active");
    };
    match fetch(&listen) {
        Ok(stats) => {
            report(out, Some(&stats));
            i32::from(service != "active" || stats["status"] == "unhealthy")
        }
        Err(e) => {
            report(out, None);
            say!(err, "Cannot read the statistics from {listen}: {e}");
            1
        }
    }
}

/// The report for humans; `stats` is `None` when the endpoint could not be read.
pub fn render_status(service: &str, stats: Option<&Value>) -> String {
    let mut o = format!("Service:  {service}\n");
    let Some(s) = stats else {
        if service == "active" {
            o.push_str("Status:   running, but its statistics could not be read\n");
        } else {
            o.push_str("FlowPilot is not running. See why with: journalctl -u flowpilot\n");
        }
        return o;
    };
    let text = |v: &Value| v.as_str().map(str::to_string);
    let when = |v: &Value| text(v).unwrap_or_else(|| "never".into());
    let status = text(&s["status"]).unwrap_or_else(|| "unknown".into());
    let _ = match text(&s["last_flow_at"]) {
        Some(t) => writeln!(o, "Status:   {status} (last flow {t})"),
        None => writeln!(o, "Status:   {status} (no flow seen yet)"),
    };
    if let (Some(version), Some(up)) = (text(&s["version"]), s["uptime_seconds"].as_u64()) {
        let _ = writeln!(o, "Version:  {version}, up {}", duration(up));
    }
    let up = &s["uploads"];
    let _ = writeln!(o, "Last successful upload: {}", when(&up["last_success_at"]));
    if let Some(e) = text(&up["last_error"]) {
        let _ = writeln!(o, "Last upload error:      {e} ({})", when(&up["last_error_at"]));
    }
    for c in s["collectors"].as_array().into_iter().flatten() {
        let _ = writeln!(o, "Collector {} ({}), {:.1} flows/s over 1 min", c["name"].as_str().unwrap_or("?"), c["parser"].as_str().unwrap_or("?"), c["rate"]["m1"].as_f64().unwrap_or(0.0));
        for e in c["exporters"].as_array().into_iter().flatten() {
            let protocols: Vec<&str> = e["protocols"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            let _ = writeln!(
                o,
                "  {}  {}  last seen {}  {:.1} flows/s",
                e["address"].as_str().unwrap_or("?"),
                protocols.join(","),
                when(&e["last_seen"]),
                e["flows_per_second"].as_f64().unwrap_or(0.0)
            );
        }
        match c["exporters_omitted"].as_u64() {
            Some(n) if n > 0 => {
                let _ = writeln!(o, "  (and {n} more exporters not listed)");
            }
            _ => {}
        }
    }
    o
}

/// `4h10m`, `2d3h`, `45s`.
fn duration(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, secs % 86400 / 3600, secs % 3600 / 60);
    match (d, h, m) {
        (0, 0, 0) => format!("{secs}s"),
        (0, 0, m) => format!("{m}m"),
        (0, h, m) => format!("{h}h{m}m"),
        (d, h, _) => format!("{d}d{h}h"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::health::serve;
    use crate::install::system::{FakeSystem, Owner};

    const STATS: &str = include_str!("../../tests/fixtures/install/stats.json");
    const CFG: &str = "stats:\n  http_listen: 127.0.0.1:9180\n";

    fn stats() -> Value {
        serde_json::from_str(STATS).unwrap()
    }

    fn host(config: Option<&str>) -> FakeSystem {
        let mut sys = FakeSystem::new("0.9.0");
        if let Some(c) = config {
            sys.put(CONFIG, c.as_bytes(), 0o640, Owner::ROOT_FLOWPILOT);
        }
        sys
    }

    fn run(sys: &mut FakeSystem, fetch: &mut dyn FnMut(&str) -> Result<Value, String>, json: bool) -> (i32, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_status_with(sys, fetch, &mut out, &mut err, StatusArgs { json });
        (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
    }

    #[test]
    fn render_status_shows_exporters() {
        let text = render_status("active", Some(&stats()));
        for want in [
            "active",
            "ok",
            "2026-10-22T12:00:02Z",
            "netflow-dc1",
            "10.1.0.1",
            "netflow_v9",
            "last seen 2026-10-22T12:09:59Z",
            "243.2 flows/s",
            "2001:db8::1",
            "ipfix",
            "last seen 2026-10-22T12:09:58Z",
            "121.6 flows/s",
            "HTTP 503 Service Unavailable",
        ] {
            assert!(text.contains(want), "missing {want:?} in\n{text}");
        }
    }

    #[test]
    fn render_status_service_down() {
        let text = render_status("inactive", None);
        assert!(text.contains("not running"), "{text}");
        assert!(text.contains("inactive"), "{text}");
        assert!(text.contains("journalctl -u flowpilot"), "{text}");
    }

    #[test]
    fn render_status_never_uploaded() {
        let mut s = stats();
        s["uploads"]["last_success_at"] = Value::Null;
        s["uploads"]["last_error"] = Value::Null;
        let text = render_status("active", Some(&s));
        assert!(text.contains("never"), "{text}");
        assert!(!text.contains("Service Unavailable"), "{text}");
    }

    #[test]
    fn status_json_shape() {
        let mut sys = host(Some(CFG));
        let (code, out, _) = run(&mut sys, &mut |_| Ok(stats()), true);
        assert_eq!(code, 0);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["service"], "active");
        assert_eq!(v["stats"], stats());
        assert_eq!(v.as_object().unwrap().len(), 2);

        sys.service_state = "failed".into();
        let (code, out, _) = run(&mut sys, &mut |_| Err("refused".into()), true);
        assert_eq!(code, 1);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!((v["service"].as_str(), v["stats"].is_null()), (Some("failed"), true));
    }

    #[test]
    fn exit_code_follows_service_and_status() {
        let mut sys = host(Some(CFG));
        assert_eq!(run(&mut sys, &mut |l| { assert_eq!(l, "127.0.0.1:9180"); Ok(stats()) }, false).0, 0);
        let mut bad = stats();
        bad["status"] = "unhealthy".into();
        assert_eq!(run(&mut sys, &mut |_| Ok(bad.clone()), false).0, 1);
        let mut ups = stats();
        ups["status"] = "upload_failing".into();
        assert_eq!(run(&mut sys, &mut |_| Ok(ups.clone()), false).0, 0);
        sys.service_state = "inactive".into();
        let (code, out, _) = run(&mut sys, &mut |_| Err("refused".into()), false);
        assert_eq!(code, 1);
        assert!(out.contains("not running") && out.contains("journalctl -u flowpilot"), "{out}");
    }

    #[test]
    fn active_but_endpoint_unreachable_is_exit_1_with_reason() {
        let mut sys = host(Some(CFG));
        let (code, out, err) = run(&mut sys, &mut |_| Err("127.0.0.1:9180: refused".into()), false);
        assert_eq!(code, 1);
        assert!(out.contains("active"), "{out}");
        assert!(err.contains("refused"), "{err}");
    }

    #[test]
    fn stats_endpoint_not_configured_is_not_a_failure() {
        let mut sys = host(Some("collectors: []\n"));
        let (code, out, err) = run(&mut sys, &mut |_| panic!("no endpoint to ask"), false);
        assert_eq!(code, 0);
        assert!(out.contains("active"), "{out}");
        assert!(err.contains("stats.http_listen"), "{err}");
    }

    #[test]
    fn unreadable_config_suggests_sudo() {
        let mut sys = host(Some(CFG));
        sys.unreadable.push(CONFIG.into());
        let (code, _, err) = run(&mut sys, &mut |_| panic!("no config, no endpoint"), false);
        assert_eq!(code, 1);
        assert!(err.contains("sudo flowpilot status"), "{err}");
    }

    #[test]
    fn missing_config_says_not_installed() {
        let mut sys = host(None);
        sys.service_state = "inactive".into();
        let (code, _, err) = run(&mut sys, &mut |_| panic!("no config"), false);
        assert_eq!(code, 1);
        assert!(err.contains(CONFIG) && err.contains("flowpilot install"), "{err}");
    }

    #[test]
    fn fetch_stats_reads_the_object_and_retries_busy() {
        let addr = serve(vec![(503, r#"{"status":"busy"}"#), (200, STATS)]);
        assert_eq!(fetch_stats(&addr).unwrap(), stats());
    }

    #[test]
    fn fetch_stats_gives_up_after_a_few_busy_answers() {
        let addr = serve(vec![(503, r#"{"status":"busy"}"#); 5]);
        assert!(fetch_stats(&addr).unwrap_err().contains("busy"));
    }

    #[test]
    fn fetch_stats_reports_refused_and_bad_addresses() {
        assert!(fetch_stats("not-an-address").unwrap_err().contains("not-an-address"));
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
        assert!(fetch_stats(&dead).is_err());
    }

    #[test]
    fn wildcard_listen_is_reached_on_loopback() {
        assert_eq!(connect_addr("0.0.0.0:9180").unwrap().to_string(), "127.0.0.1:9180");
        assert_eq!(connect_addr("[::]:9180").unwrap().to_string(), "[::1]:9180");
        assert_eq!(connect_addr("10.0.0.5:9180").unwrap().to_string(), "10.0.0.5:9180");
    }
}
