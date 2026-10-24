//! The `unmanaged_workloads` config key (docs/unmanaged-workloads.md, "Configuration"). The schema fragment (`schema.json`) only checks
//! types and unknown keys; ranges and CIDRs are checked in `decode` so users see the exact lines below.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::Serialize;
use serde_json::Value;

/// `unmanaged_workloads`; `Default` is the documented defaults (also used when the key is absent).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct UnmanagedConfig {
    pub enabled: bool,
    pub dry_run: bool,
    pub networks: Vec<IpNet>,
    pub exclude_networks: Vec<IpNet>,
    pub allow_broad_networks: bool,
    pub min_flows: u64,
    pub flow_window_hours: u32,
    pub max_creates_per_window: usize,
    pub max_creates_per_day: usize,
    pub refresh_hours: u32,
    pub external_data_set: String,
    /// Optional PCE key override (a `$cmd` form is resolved by the worker, not here).
    pub api_key: Option<String>,
    pub dns: DnsConfig,
    pub label_rules: Vec<LabelRule>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DnsConfig {
    pub enabled: bool,
    /// Empty = system resolver.
    pub servers: Vec<IpAddr>,
    pub timeout_ms: u64,
    pub concurrency: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LabelRule {
    pub cidr: IpNet,
    pub labels: BTreeMap<String, String>,
}

impl Default for UnmanagedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dry_run: false,
            networks: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
                .iter()
                .map(|n| n.parse().expect("default network"))
                .collect(),
            exclude_networks: Vec::new(),
            allow_broad_networks: false,
            min_flows: 10,
            flow_window_hours: 24,
            max_creates_per_window: 100,
            max_creates_per_day: 500,
            refresh_hours: 24,
            external_data_set: "flowpilot".into(),
            api_key: None,
            dns: DnsConfig::default(),
            label_rules: Vec::new(),
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            servers: Vec::new(),
            timeout_ms: 2000,
            concurrency: 8,
        }
    }
}

/// Parse one CIDR (IPv4 only, no broader than /8 unless allowed); `at` is the error prefix.
fn cidr(s: &str, at: &str, allow_broad: bool, errs: &mut Vec<String>) -> Option<IpNet> {
    let Ok(net) = s.parse::<IpNet>() else {
        errs.push(format!("{at}: invalid CIDR '{s}'"));
        return None;
    };
    if matches!(net, IpNet::V6(_)) {
        errs.push(format!("{at}: IPv6 is not supported yet"));
        return None;
    }
    if net.prefix_len() < 8 && !allow_broad {
        errs.push(format!(
            "{at}: {net} is broader than /8; set allow_broad_networks: true to allow it"
        ));
        return None;
    }
    Some(net)
}

fn cidr_list(
    v: &Value,
    key: &str,
    allow_broad: bool,
    default: Vec<IpNet>,
    errs: &mut Vec<String>,
) -> Vec<IpNet> {
    let Some(items) = v.get(key).and_then(Value::as_array) else {
        return default;
    };
    items
        .iter()
        .enumerate()
        .filter_map(|(i, s)| {
            cidr(
                s.as_str().unwrap_or_default(),
                &format!("unmanaged_workloads.{key}[{i}]"),
                allow_broad,
                errs,
            )
        })
        .collect()
}

/// An integer key with a lower bound (the schema allows any integer); `None` when absent.
fn int(v: &Value, key: &str, min: i64, at: &str, errs: &mut Vec<String>) -> Option<i64> {
    let n = v.get(key)?.as_i64().unwrap_or(i64::MAX);
    if n < min {
        errs.push(format!("{at}: must be at least {min}"));
        return None;
    }
    Some(n)
}

/// Decode and validate `doc["unmanaged_workloads"]` (`Null` = defaults). `aggregation_minutes` comes
/// from the main config. Collects every semantic error instead of stopping at the first.
pub fn decode(v: &Value, aggregation_minutes: i16) -> Result<UnmanagedConfig, Vec<String>> {
    let d = UnmanagedConfig::default();
    let mut errs = Vec::new();
    let flag = |k: &str, def: bool| v.get(k).and_then(Value::as_bool).unwrap_or(def);
    let allow_broad = flag("allow_broad_networks", d.allow_broad_networks);
    let networks = cidr_list(v, "networks", allow_broad, d.networks, &mut errs);
    let exclude_networks = cidr_list(
        v,
        "exclude_networks",
        allow_broad,
        d.exclude_networks,
        &mut errs,
    );

    let min_flows = int(
        v,
        "min_flows",
        1,
        "unmanaged_workloads.min_flows",
        &mut errs,
    )
    .map_or(d.min_flows, |n| n as u64);
    let flow_window_hours = match v.get("flow_window_hours").map(|n| n.as_i64().unwrap_or(0)) {
        Some(h) if h * 60 < i64::from(aggregation_minutes) => {
            errs.push(format!(
                "unmanaged_workloads.flow_window_hours: must cover at least one aggregation window ({aggregation_minutes} minutes)"
            ));
            d.flow_window_hours
        }
        Some(h) => u32::try_from(h).unwrap_or(u32::MAX),
        None => d.flow_window_hours,
    };
    let mut window_ok = true;
    let per_window = match v.get("max_creates_per_window").map(Value::as_i64) {
        Some(Some(n @ 1..=1000)) => n as usize,
        Some(_) => {
            window_ok = false;
            errs.push(
                "unmanaged_workloads.max_creates_per_window: must be between 1 and 1000".into(),
            );
            d.max_creates_per_window
        }
        None => d.max_creates_per_window,
    };
    let per_day = int(
        v,
        "max_creates_per_day",
        1,
        "unmanaged_workloads.max_creates_per_day",
        &mut errs,
    )
    .map_or(d.max_creates_per_day, |n| n as usize);
    // Not checked against an invalid window cap: the message would quote a bogus value.
    if window_ok && per_day < per_window {
        errs.push(format!(
            "unmanaged_workloads.max_creates_per_day: must be at least max_creates_per_window ({per_window})"
        ));
    }
    let refresh_hours = int(
        v,
        "refresh_hours",
        1,
        "unmanaged_workloads.refresh_hours",
        &mut errs,
    )
    .map_or(d.refresh_hours, |n| u32::try_from(n).unwrap_or(u32::MAX));

    let dv = v.get("dns").unwrap_or(&Value::Null);
    let servers = dv
        .get("servers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(|(i, s)| {
            let s = s.as_str().unwrap_or_default();
            s.parse::<IpAddr>()
                .map_err(|_| {
                    errs.push(format!(
                        "unmanaged_workloads.dns.servers[{i}]: invalid IP address '{s}'"
                    ))
                })
                .ok()
        })
        .collect();
    let timeout_ms = int(
        dv,
        "timeout_ms",
        1,
        "unmanaged_workloads.dns.timeout_ms",
        &mut errs,
    )
    .map_or(d.dns.timeout_ms, |n| n as u64);
    let concurrency = int(
        dv,
        "concurrency",
        1,
        "unmanaged_workloads.dns.concurrency",
        &mut errs,
    )
    .map_or(d.dns.concurrency, |n| n as usize);

    let mut label_rules = Vec::new();
    for (i, r) in v
        .get("label_rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let at = format!("unmanaged_workloads.label_rules[{i}]");
        let labels: BTreeMap<String, String> = r
            .get("labels")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
            .collect();
        if labels.is_empty() {
            errs.push(format!("{at}: has no labels"));
        }
        let net = cidr(
            r.get("cidr").and_then(Value::as_str).unwrap_or_default(),
            &format!("{at}.cidr"),
            allow_broad,
            &mut errs,
        );
        if let Some(cidr) = net {
            label_rules.push(LabelRule { cidr, labels });
        }
    }

    if !errs.is_empty() {
        return Err(errs);
    }
    Ok(UnmanagedConfig {
        enabled: flag("enabled", d.enabled),
        dry_run: flag("dry_run", d.dry_run),
        networks,
        exclude_networks,
        allow_broad_networks: allow_broad,
        min_flows,
        flow_window_hours,
        max_creates_per_window: per_window,
        max_creates_per_day: per_day,
        refresh_hours,
        external_data_set: v
            .get("external_data_set")
            .and_then(Value::as_str)
            .map_or(d.external_data_set, str::to_string),
        api_key: v.get("api_key").and_then(Value::as_str).map(str::to_string),
        dns: DnsConfig {
            enabled: dv
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(d.dns.enabled),
            servers,
            timeout_ms,
            concurrency,
        },
        label_rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn errs(v: Value) -> Vec<String> {
        decode(&v, 10).unwrap_err()
    }

    #[test]
    fn null_gives_defaults() {
        let c = decode(&Value::Null, 10).unwrap();
        assert_eq!(c, UnmanagedConfig::default());
        assert!(!c.enabled);
        assert_eq!(c.networks.len(), 3);
    }

    #[test]
    fn semantic_errors() {
        let cases = [
            (json!({"networks": ["10.0.0.300/8"]}), "unmanaged_workloads.networks[0]: invalid CIDR '10.0.0.300/8'"),
            (json!({"networks": ["fd00::/8"]}), "unmanaged_workloads.networks[0]: IPv6 is not supported yet"),
            (json!({"networks": ["0.0.0.0/0"]}), "unmanaged_workloads.networks[0]: 0.0.0.0/0 is broader than /8; set allow_broad_networks: true to allow it"),
            (json!({"min_flows": 0}), "unmanaged_workloads.min_flows: must be at least 1"),
            (json!({"flow_window_hours": 0}), "unmanaged_workloads.flow_window_hours: must cover at least one aggregation window (10 minutes)"),
            (json!({"max_creates_per_window": 1001}), "unmanaged_workloads.max_creates_per_window: must be between 1 and 1000"),
            (json!({"max_creates_per_day": 50, "max_creates_per_window": 100}), "unmanaged_workloads.max_creates_per_day: must be at least max_creates_per_window (100)"),
            (json!({"label_rules": [{"cidr": "10.0.0.0/8", "labels": {}}]}), "unmanaged_workloads.label_rules[0]: has no labels"),
            (json!({"exclude_networks": ["1.2.3.4/33"]}), "unmanaged_workloads.exclude_networks[0]: invalid CIDR '1.2.3.4/33'"),
            (json!({"exclude_networks": ["fd00::/8"]}), "unmanaged_workloads.exclude_networks[0]: IPv6 is not supported yet"),
            (json!({"exclude_networks": ["0.0.0.0/0"]}), "unmanaged_workloads.exclude_networks[0]: 0.0.0.0/0 is broader than /8; set allow_broad_networks: true to allow it"),
            (json!({"label_rules": [{"cidr": "fd00::/8", "labels": {"a": "b"}}]}), "unmanaged_workloads.label_rules[0].cidr: IPv6 is not supported yet"),
            (json!({"label_rules": [{"cidr": "0.0.0.0/0", "labels": {"a": "b"}}]}), "unmanaged_workloads.label_rules[0].cidr: 0.0.0.0/0 is broader than /8; set allow_broad_networks: true to allow it"),
            (json!({"label_rules": [{"cidr": "x", "labels": {"a": "b"}}]}), "unmanaged_workloads.label_rules[0].cidr: invalid CIDR 'x'"),
        ];
        for (v, line) in cases {
            let e = errs(v.clone());
            assert!(e.contains(&line.to_string()), "{v}: {e:?}");
        }
    }

    #[test]
    fn collects_all_errors() {
        let e = errs(json!({"min_flows": 0, "networks": ["x"], "max_creates_per_window": 0}));
        assert_eq!(e.len(), 3, "{e:?}");
    }

    #[test]
    fn broad_allowed_with_flag() {
        let c = decode(
            &json!({"networks": ["0.0.0.0/0"], "allow_broad_networks": true}),
            10,
        )
        .unwrap();
        assert_eq!(c.networks, ["0.0.0.0/0".parse::<IpNet>().unwrap()]);
    }
}
