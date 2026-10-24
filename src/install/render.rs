//! Renders the files the installer writes: the config, the key file, the systemd unit and the firewall commands.
//! Output is a pure function of the answers, so a re-run can compare bytes with what is on disk.

use serde_yaml::Mapping;

use crate::install::answers::Answers;
use crate::install::args::{CollectorKind, UnmanagedArgs};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Firewall {
    Firewalld,
    Ufw,
    Nftables,
    None,
}

const API_KEY_PATH: &str = "/etc/flowpilot/api_key";
const DATA_DIRECTORY: &str = "/var/lib/flowpilot";

/// Inserts a JSON value under `key`; insertion order is the output order.
fn put(m: &mut Mapping, key: &str, v: impl serde::Serialize) {
    m.insert(key.into(), serde_yaml::to_value(v).expect("a plain value serializes"));
}

fn collector_name(kind: CollectorKind) -> &'static str {
    match kind {
        CollectorKind::Netflow => "netflow",
        CollectorKind::Ipfix => "ipfix",
        CollectorKind::Sflow => "sflow",
        CollectorKind::Text => "text",
    }
}

/// The text parser properties that are set, named as in `env_config`.
fn text_properties(a: &Answers) -> Mapping {
    let t = &a.text;
    let all = [
        ("src_ip", &t.src_ip),
        ("dst_ip", &t.dst_ip),
        ("dst_port", &t.dst_port),
        ("protocol", &t.protocol),
        ("icmp_type", &t.icmp_type),
        ("icmp_code", &t.icmp_code),
        ("octets", &t.octets),
        ("timestamp", &t.timestamp),
        ("timestamp_format", &t.timestamp_format),
        ("only_recs", &t.only_recs),
        ("field_separator", &t.field_separator),
        ("attribute_separator", &t.attribute_separator),
    ];
    let mut m = Mapping::new();
    for (name, v) in all {
        if let Some(v) = v {
            put(&mut m, name, crate::env_config::text_value(name, v.clone()));
        }
    }
    m
}

fn consumers(a: &Answers) -> Vec<Mapping> {
    a.collectors
        .iter()
        .map(|c| {
            let name = collector_name(c.kind);
            let mut udp = Mapping::new();
            put(&mut udp, "ports", &c.ports);
            if let Some(r) = &c.remote_addrs {
                put(&mut udp, "remote_addrs", r);
            }
            let mut connector = Mapping::new();
            put(&mut connector, "type", "udp");
            put(&mut connector, "properties", udp);
            let mut parser = Mapping::new();
            put(&mut parser, "type", name);
            if c.kind == CollectorKind::Text {
                put(&mut parser, "properties", text_properties(a));
            }
            let mut consumer = Mapping::new();
            put(&mut consumer, "name", name);
            put(&mut consumer, "parser", parser);
            put(&mut consumer, "connectors", [connector]);
            consumer
        })
        .collect()
}

fn unmanaged(u: &UnmanagedArgs) -> Mapping {
    let mut m = Mapping::new();
    put(&mut m, "enabled", true);
    if u.dry_run {
        put(&mut m, "dry_run", true);
    }
    if let Some(n) = &u.networks {
        let nets: Vec<&str> = n.split(',').map(str::trim).filter(|x| !x.is_empty()).collect();
        put(&mut m, "networks", nets);
    }
    for (key, v) in [
        ("min_flows", u.min_flows),
        ("max_creates_per_window", u.max_per_window),
        ("max_creates_per_day", u.max_per_day),
    ] {
        if let Some(v) = v {
            put(&mut m, key, v);
        }
    }
    if let Some(r) = &u.label_rules {
        // Rules that do not parse are written as given, so `config::validate` reports them.
        match crate::env_config::label_rules("label_rules", r) {
            Ok(rules) => put(&mut m, "label_rules", rules),
            Err(_) => put(&mut m, "label_rules", r),
        }
    }
    m
}

/// The `config.yaml` for these answers. The API key stays out: the config only names the key file.
pub fn config_yaml(a: &Answers, stats_listen: &str) -> String {
    let mut m = Mapping::new();
    put(&mut m, "pce_addr", &a.pce_addr);
    put(&mut m, "org_id", a.org_id);
    put(&mut m, "api_key", API_KEY_PATH);
    put(&mut m, "verify_pce_cert", a.verify_pce_cert);
    put(&mut m, "data_directory", DATA_DIRECTORY);
    let p = &a.proxy;
    let mut proxy = Mapping::new();
    for (key, v) in [("https_proxy", &p.https), ("http_proxy", &p.http), ("no_proxy", &p.no_proxy)] {
        if !v.is_empty() {
            put(&mut proxy, key, v);
        }
    }
    if !proxy.is_empty() {
        put(&mut m, "proxy_config", proxy);
    }
    put(&mut m, "consumers", consumers(a));
    let mut stats = Mapping::new();
    put(&mut stats, "http_listen", stats_listen);
    put(&mut m, "stats", stats);
    if let Some(u) = &a.unmanaged {
        put(&mut m, "unmanaged_workloads", unmanaged(u));
    }
    serde_yaml::to_string(&m).expect("a mapping serializes")
}

/// The API key file in the `user secret` format `secrets` reads.
pub fn api_key_file(a: &Answers) -> String {
    format!("{} {}\n", a.api_user, a.api_secret.0)
}

/// The ports of every collector, split at commas, in order and without repeats.
fn port_items(a: &Answers) -> Vec<String> {
    let mut items: Vec<String> = Vec::new();
    for item in a.collectors.iter().flat_map(|c| c.ports.split(',')) {
        let item = item.trim().to_string();
        if !item.is_empty() && !items.contains(&item) {
            items.push(item);
        }
    }
    items
}

/// True when a port or the start of a range is below 1024.
fn binds_low_port(a: &Answers) -> bool {
    port_items(a).iter().any(|i| {
        let first = i.split('-').next().unwrap_or("");
        first.trim().parse::<u32>().is_ok_and(|p| p < 1024)
    })
}

/// The systemd unit: the template of docs/operations.md, with the bind capability only for ports below 1024.
pub fn unit(a: &Answers) -> String {
    let mut s = String::from(
        "[Unit]
Description=FlowPilot flow collector
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=flowpilot
Group=flowpilot
Environment=CONFIG_FILE=/etc/flowpilot/config.yaml
ExecStart=/usr/local/bin/flowpilot
Restart=always
RestartSec=10
# On a signal FlowPilot waits 5 s to drain, up to 5 s more for unmanaged workloads to save their state,
# and up to about 32 s more to send the last file.
TimeoutStopSec=60
NoNewPrivileges=no
ProtectSystem=strict
PrivateTmp=yes
ReadWritePaths=/var/lib/flowpilot
",
    );
    if binds_low_port(a) {
        s.push_str("AmbientCapabilities=CAP_NET_BIND_SERVICE\n");
    }
    s.push_str("\n[Install]\nWantedBy=multi-user.target\n");
    s
}

/// The commands that open the collector ports; the installer prints them and never runs them.
pub fn firewall_commands(a: &Answers, fw: Firewall) -> Vec<String> {
    let ports = port_items(a);
    match fw {
        Firewall::Firewalld => {
            let mut v: Vec<String> =
                ports.iter().map(|p| format!("firewall-cmd --permanent --add-port={p}/udp")).collect();
            v.push("firewall-cmd --reload".into());
            v
        }
        Firewall::Ufw => ports.iter().map(|p| format!("ufw allow {}/udp", p.replace('-', ":"))).collect(),
        Firewall::Nftables => {
            ports.iter().map(|p| format!("nft add rule inet filter input udp dport {p} accept")).collect()
        }
        Firewall::None => vec![format!(
            "# no active firewall was found; if the host filters traffic, allow UDP {}",
            ports.join(", ")
        )],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Secret;
    use crate::install::args::{CollectorArg, TextArgs, UnmanagedArgs};

    fn base() -> Answers {
        Answers {
            pce_addr: "pce.example.com:8443".into(),
            org_id: 1,
            api_user: "api_1".into(),
            api_secret: Secret("s3cret".into()),
            collectors: vec![CollectorArg { kind: CollectorKind::Netflow, ports: "2055".into(), remote_addrs: None }],
            text: TextArgs::default(),
            unmanaged: None,
            verify_pce_cert: true,
            proxy: Default::default(),
        }
    }

    fn collector(kind: CollectorKind, ports: &str, remote: Option<&str>) -> CollectorArg {
        CollectorArg { kind, ports: ports.into(), remote_addrs: remote.map(Into::into) }
    }

    fn full() -> Answers {
        let s = |v: &str| Some(v.to_string());
        Answers {
            org_id: 3,
            verify_pce_cert: false,
            collectors: vec![
                collector(CollectorKind::Netflow, "2055", Some("192.0.2.10,192.0.2.11")),
                collector(CollectorKind::Ipfix, "4739", None),
                collector(CollectorKind::Sflow, "6343,6344", None),
                collector(CollectorKind::Text, "514", None),
            ],
            text: TextArgs {
                src_ip: s("src"),
                dst_ip: s("dst"),
                dst_port: s("4"),
                protocol: s("proto"),
                timestamp_format: s("mmm dd yyyy HH:MM:SS"),
                ..Default::default()
            },
            unmanaged: Some(UnmanagedArgs {
                enabled: true,
                dry_run: true,
                networks: s("10.0.0.0/8, 192.168.0.0/16"),
                min_flows: Some(5),
                max_per_window: Some(50),
                max_per_day: None,
                label_rules: s("10.1.0.0/16=app:web,env:prod"),
            }),
            ..base()
        }
    }

    const STATS: &str = "127.0.0.1:9180";

    #[test]
    fn rendered_config_validates() {
        for a in [base(), full()] {
            let text = config_yaml(&a, STATS);
            crate::config::validate(text.as_bytes()).unwrap_or_else(|e| panic!("{e:?}\n{text}"));
        }
        let mut only_text = full();
        only_text.collectors = vec![collector(CollectorKind::Text, "514", None)];
        only_text.unmanaged = None;
        crate::config::validate(config_yaml(&only_text, STATS).as_bytes()).unwrap();
    }

    #[test]
    fn rendered_config_matches_golden() {
        assert_eq!(config_yaml(&full(), STATS), include_str!("../../tests/fixtures/install/config.yaml"));
        assert_eq!(config_yaml(&full(), STATS), config_yaml(&full(), STATS));
    }

    #[test]
    fn unit_matches_golden() {
        assert_eq!(unit(&full()), include_str!("../../tests/fixtures/install/flowpilot.service"));
    }

    #[test]
    fn unit_capability_follows_low_ports() {
        let mut a = base();
        a.collectors.push(collector(CollectorKind::Text, "514", None));
        assert!(unit(&a).contains("AmbientCapabilities=CAP_NET_BIND_SERVICE\n"));
        assert!(!unit(&base()).contains("AmbientCapabilities"));
        let mut range = base();
        range.collectors = vec![collector(CollectorKind::Sflow, "6343,1000-1010", None)];
        assert!(unit(&range).contains("AmbientCapabilities"));
    }

    #[test]
    fn proxy_config_written_only_when_set() {
        assert!(!config_yaml(&base(), STATS).contains("proxy_config"));
        let mut a = base();
        a.proxy.https = "http://proxy.example.com:3128".into();
        a.proxy.no_proxy = "localhost".into();
        let text = config_yaml(&a, STATS);
        assert!(
            text.contains("proxy_config:\n  https_proxy: http://proxy.example.com:3128\n  no_proxy: localhost\n"),
            "{text}"
        );
        let c = crate::config::validate(text.as_bytes()).unwrap();
        assert_eq!(c.proxy_config.https_proxy, "http://proxy.example.com:3128");
        assert_eq!(c.proxy_config.no_proxy, "localhost");
    }

    #[test]
    fn api_key_file_format() {
        assert_eq!(api_key_file(&base()), "api_1 s3cret\n");
    }

    #[test]
    fn firewall_commands_per_tool() {
        let a = base();
        assert_eq!(
            firewall_commands(&a, Firewall::Firewalld),
            ["firewall-cmd --permanent --add-port=2055/udp", "firewall-cmd --reload"]
        );
        assert_eq!(firewall_commands(&a, Firewall::Ufw), ["ufw allow 2055/udp"]);
        assert_eq!(
            firewall_commands(&a, Firewall::Nftables),
            ["nft add rule inet filter input udp dport 2055 accept"]
        );
        let none = firewall_commands(&a, Firewall::None);
        assert_eq!(none.len(), 1);
        assert!(none[0].contains("no active firewall was found"));

        let f = full();
        assert!(firewall_commands(&f, Firewall::Ufw).contains(&"ufw allow 6344/udp".to_string()));
    }

    #[test]
    fn rendered_files_contain_no_secret_except_key_file() {
        let a = full();
        for out in [config_yaml(&a, STATS), unit(&a), firewall_commands(&a, Firewall::Firewalld).join("\n")] {
            assert!(!out.contains("s3cret"));
        }
        assert!(api_key_file(&a).contains("s3cret"));
    }
}
