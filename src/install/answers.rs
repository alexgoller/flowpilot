//! The settings the installer collects, resolved from flags, then `FLOWPILOT_*` variables, then defaults.
//! The API secret is held only as a `Secret`; it never reaches a log line or an argv.

use std::fmt;
use std::io::Read;
use std::path::Path;

use serde_json::Value;

use crate::config::Secret;
use crate::env_config::Env;
use crate::install::args::{CollectorArg, CollectorKind, InstallArgs, TextArgs, UnmanagedArgs};
use crate::stats::redact_proxy_url;

/// Everything the installer asks for, with defaults applied.
#[derive(Clone, Debug, PartialEq)]
pub struct Answers {
    pub pce_addr: String,
    pub org_id: i32,
    pub api_user: String,
    pub api_secret: Secret,
    pub collectors: Vec<CollectorArg>,
    pub text: TextArgs,
    /// `None` when unmanaged-workload creation is off.
    pub unmanaged: Option<UnmanagedArgs>,
    pub verify_pce_cert: bool,
    pub proxy: Proxy,
}

/// `proxy_config` as the installer writes it. Only `https` is asked for (it is the one the PCE connection uses);
/// `http` and `no_proxy` are kept from an existing config. `Debug` hides a user and password in the URLs.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Proxy {
    pub https: String,
    pub http: String,
    pub no_proxy: String,
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy")
            .field("https", &redact_proxy_url(&self.https))
            .field("http", &redact_proxy_url(&self.http))
            .field("no_proxy", &self.no_proxy)
            .finish()
    }
}

const COLLECTORS: [(CollectorKind, &str); 4] = [
    (CollectorKind::Netflow, "NETFLOW"),
    (CollectorKind::Ipfix, "IPFIX"),
    (CollectorKind::Sflow, "SFLOW"),
    (CollectorKind::Text, "TEXT"),
];

/// Every `FLOWPILOT_*` variable `from_args` reads. The daemon reads more (`FLOWPILOT_API_KEY`,
/// `FLOWPILOT_DATA_DIRECTORY`, ...); those are no answer, so one left in root's environment does not turn an upgrade
/// into a fresh set of answers.
pub(crate) const ANSWER_VARS: &[&str] = &[
    "FLOWPILOT_PCE_ADDR",
    "FLOWPILOT_ORG_ID",
    "FLOWPILOT_API_USER",
    "FLOWPILOT_API_SECRET",
    "FLOWPILOT_VERIFY_PCE_CERT",
    "FLOWPILOT_HTTPS_PROXY",
    "FLOWPILOT_NETFLOW_PORTS",
    "FLOWPILOT_NETFLOW_REMOTE_ADDRS",
    "FLOWPILOT_IPFIX_PORTS",
    "FLOWPILOT_IPFIX_REMOTE_ADDRS",
    "FLOWPILOT_SFLOW_PORTS",
    "FLOWPILOT_SFLOW_REMOTE_ADDRS",
    "FLOWPILOT_TEXT_PORTS",
    "FLOWPILOT_TEXT_REMOTE_ADDRS",
    "FLOWPILOT_TEXT_SRC_IP",
    "FLOWPILOT_TEXT_DST_IP",
    "FLOWPILOT_TEXT_DST_PORT",
    "FLOWPILOT_TEXT_PROTOCOL",
    "FLOWPILOT_TEXT_OCTETS",
    "FLOWPILOT_TEXT_ICMP_TYPE",
    "FLOWPILOT_TEXT_ICMP_CODE",
    "FLOWPILOT_TEXT_TIMESTAMP",
    "FLOWPILOT_TEXT_TIMESTAMP_FORMAT",
    "FLOWPILOT_TEXT_ONLY_RECS",
    "FLOWPILOT_TEXT_FIELD_SEPARATOR",
    "FLOWPILOT_TEXT_ATTRIBUTE_SEPARATOR",
    "FLOWPILOT_UNMANAGED_ENABLED",
    "FLOWPILOT_UNMANAGED_DRY_RUN",
    "FLOWPILOT_UNMANAGED_NETWORKS",
    "FLOWPILOT_UNMANAGED_MIN_FLOWS",
    "FLOWPILOT_UNMANAGED_MAX_CREATES_PER_WINDOW",
    "FLOWPILOT_UNMANAGED_MAX_CREATES_PER_DAY",
    "FLOWPILOT_UNMANAGED_LABEL_RULES",
];

/// True when any variable of `ANSWER_VARS` is set and not empty.
pub fn any_answer_var(env: Env) -> bool {
    ANSWER_VARS.iter().any(|name| var(env, name).is_some())
}

/// A variable's value; an empty variable counts as unset (as in `env_config`).
fn var(env: Env, name: &str) -> Option<String> {
    env(name).filter(|v| !v.is_empty())
}

fn parse_var<T: std::str::FromStr>(env: Env, name: &str, what: &str, errors: &mut Vec<String>) -> Option<T> {
    let v = var(env, name)?;
    match v.trim().parse() {
        Ok(n) => Some(n),
        Err(_) => {
            errors.push(format!("{name}: not {what}: {v}"));
            None
        }
    }
}

fn bool_var(env: Env, name: &str, errors: &mut Vec<String>) -> Option<bool> {
    let v = var(env, name)?;
    match v.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => {
            errors.push(format!("{name}: not a boolean: {v}"));
            None
        }
    }
}

/// A file's content, or stdin for `-`.
fn read_source(path: &Path) -> Result<String, String> {
    let mut s = String::new();
    if path == Path::new("-") {
        std::io::stdin().read_to_string(&mut s).map_err(|e| format!("reading stdin: {e}"))?;
    } else {
        s = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(s)
}

/// The answers when nothing is given: organization 1, NetFlow on 2055, the certificate verified, no proxy.
pub fn defaults() -> Answers {
    Answers {
        pce_addr: String::new(),
        org_id: 1,
        api_user: String::new(),
        api_secret: Secret(String::new()),
        collectors: vec![CollectorArg { kind: CollectorKind::Netflow, ports: "2055".into(), remote_addrs: None }],
        text: TextArgs::default(),
        unmanaged: None,
        verify_pce_cert: true,
        proxy: Proxy::default(),
    }
}

pub fn from_args(args: &InstallArgs, env: Env) -> Result<Answers, Vec<String>> {
    from_args_over(args, env, defaults())
}

/// `from_args` with `base` in place of the defaults: each answer is the flag, else the variable, else `base`'s.
pub fn from_args_over(args: &InstallArgs, env: Env, base: Answers) -> Result<Answers, Vec<String>> {
    let mut errors = Vec::new();

    let org_id =
        args.org.or_else(|| parse_var(env, "FLOWPILOT_ORG_ID", "a number", &mut errors)).unwrap_or(base.org_id);
    let verify_pce_cert = args
        .verify_pce_cert
        .or_else(|| bool_var(env, "FLOWPILOT_VERIFY_PCE_CERT", &mut errors))
        .unwrap_or(base.verify_pce_cert);

    // Credentials: a key file gives both; an explicit user or secret file overrides its half.
    let (mut api_user, mut secret) = (base.api_user, base.api_secret.0);
    if let Some(f) = &args.api_key_file {
        match read_source(f) {
            Ok(text) => match crate::secrets::api_key_json(&text) {
                Some((u, s)) => (api_user, secret) = (u.trim().into(), s.trim().into()),
                None => errors.push(format!("{}: not a PCE API key JSON file", f.display())),
            },
            Err(e) => errors.push(e),
        }
    } else {
        api_user = var(env, "FLOWPILOT_API_USER").unwrap_or(api_user);
        secret = var(env, "FLOWPILOT_API_SECRET").unwrap_or(secret);
    }
    if let Some(u) = &args.api_user {
        api_user = u.clone();
    }
    if let Some(f) = &args.api_secret_file {
        match read_source(f) {
            Ok(s) => secret = s,
            Err(e) => errors.push(e),
        }
    }

    // Collectors: flags, else the variables, else the base's, else NetFlow on 2055.
    let mut collectors = args.collectors.clone();
    if collectors.is_empty() {
        for (kind, name) in COLLECTORS {
            if let Some(ports) = var(env, &format!("FLOWPILOT_{name}_PORTS")) {
                let remote_addrs = var(env, &format!("FLOWPILOT_{name}_REMOTE_ADDRS"));
                collectors.push(CollectorArg { kind, ports, remote_addrs });
            }
        }
    }
    if collectors.is_empty() {
        collectors = base.collectors;
    }
    if collectors.is_empty() {
        collectors.push(CollectorArg { kind: CollectorKind::Netflow, ports: "2055".into(), remote_addrs: None });
    }

    let (t, b) = (&args.text, base.text);
    let tv = |flag: &Option<String>, prop: &str, base: Option<String>| {
        flag.clone().or_else(|| var(env, &format!("FLOWPILOT_TEXT_{prop}"))).or(base)
    };
    let text = TextArgs {
        src_ip: tv(&t.src_ip, "SRC_IP", b.src_ip),
        dst_ip: tv(&t.dst_ip, "DST_IP", b.dst_ip),
        dst_port: tv(&t.dst_port, "DST_PORT", b.dst_port),
        protocol: tv(&t.protocol, "PROTOCOL", b.protocol),
        octets: tv(&t.octets, "OCTETS", b.octets),
        icmp_type: tv(&t.icmp_type, "ICMP_TYPE", b.icmp_type),
        icmp_code: tv(&t.icmp_code, "ICMP_CODE", b.icmp_code),
        timestamp: tv(&t.timestamp, "TIMESTAMP", b.timestamp),
        timestamp_format: tv(&t.timestamp_format, "TIMESTAMP_FORMAT", b.timestamp_format),
        only_recs: tv(&t.only_recs, "ONLY_RECS", b.only_recs),
        field_separator: tv(&t.field_separator, "FIELD_SEPARATOR", b.field_separator),
        attribute_separator: tv(&t.attribute_separator, "ATTRIBUTE_SEPARATOR", b.attribute_separator),
    };

    // Unmanaged workloads: on by `--unmanaged`, `--unmanaged-dry-run` (a dry run implies on), the variable or the base.
    let u = &args.unmanaged;
    let b = base.unmanaged.unwrap_or_default();
    let dry_run = u.dry_run || bool_var(env, "FLOWPILOT_UNMANAGED_DRY_RUN", &mut errors).unwrap_or(b.dry_run);
    let enabled = u.enabled || dry_run || bool_var(env, "FLOWPILOT_UNMANAGED_ENABLED", &mut errors).unwrap_or(b.enabled);
    let num = |flag: Option<u64>, name: &str, base: Option<u64>, errors: &mut Vec<String>| {
        flag.or_else(|| parse_var(env, name, "a number", errors)).or(base)
    };
    let unmanaged = enabled.then(|| UnmanagedArgs {
        enabled,
        dry_run,
        networks: u.networks.clone().or_else(|| var(env, "FLOWPILOT_UNMANAGED_NETWORKS")).or(b.networks),
        min_flows: num(u.min_flows, "FLOWPILOT_UNMANAGED_MIN_FLOWS", b.min_flows, &mut errors),
        max_per_window: num(u.max_per_window, "FLOWPILOT_UNMANAGED_MAX_CREATES_PER_WINDOW", b.max_per_window, &mut errors),
        max_per_day: num(u.max_per_day, "FLOWPILOT_UNMANAGED_MAX_CREATES_PER_DAY", b.max_per_day, &mut errors),
        label_rules: u.label_rules.clone().or_else(|| var(env, "FLOWPILOT_UNMANAGED_LABEL_RULES")).or(b.label_rules),
    });

    let https = args.proxy.clone().or_else(|| var(env, "FLOWPILOT_HTTPS_PROXY")).unwrap_or(base.proxy.https);

    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(Answers {
        pce_addr: args.pce.clone().or_else(|| var(env, "FLOWPILOT_PCE_ADDR")).unwrap_or(base.pce_addr),
        org_id,
        api_user: api_user.trim().into(),
        api_secret: Secret(secret.trim().into()),
        collectors,
        text,
        unmanaged,
        verify_pce_cert,
        proxy: Proxy { https, ..base.proxy },
    })
}

/// The answers an existing install was made with: its `config.yaml` and its `api_key` file (`user secret`, or the
/// PCE's key JSON). Used to keep an install as it is (an upgrade, or a re-run that gives no answers).
pub fn from_existing(config_yaml: &[u8], api_key: &[u8]) -> Result<Answers, String> {
    let doc: Value = serde_yaml::from_slice(config_yaml).map_err(|e| format!("not YAML: {e}"))?;
    let pce_addr = doc.get("pce_addr").and_then(Value::as_str).ok_or("no pce_addr")?.to_string();
    let org_id = doc.get("org_id").and_then(Value::as_i64).map_or(Ok(1), i32::try_from).map_err(|_| "org_id out of range")?;
    let verify_pce_cert = doc.get("verify_pce_cert").and_then(Value::as_bool).unwrap_or(true);
    let proxy_key = |k: &str| doc.pointer(&format!("/proxy_config/{k}")).and_then(Value::as_str).unwrap_or("").to_string();
    let proxy = Proxy { https: proxy_key("https_proxy"), http: proxy_key("http_proxy"), no_proxy: proxy_key("no_proxy") };

    let mut collectors = Vec::new();
    let mut text = TextArgs::default();
    for c in doc.get("consumers").and_then(Value::as_array).into_iter().flatten() {
        let kind = match c.pointer("/parser/type").and_then(Value::as_str) {
            Some("netflow") => CollectorKind::Netflow,
            Some("ipfix") => CollectorKind::Ipfix,
            Some("sflow") => CollectorKind::Sflow,
            Some("text") => CollectorKind::Text,
            _ => continue,
        };
        if kind == CollectorKind::Text {
            text = text_args(c.pointer("/parser/properties"));
        }
        let udp = c.get("connectors").and_then(Value::as_array).into_iter().flatten();
        for conn in udp.filter(|conn| conn.get("type").and_then(Value::as_str) == Some("udp")) {
            let Some(ports) = conn.pointer("/properties/ports").and_then(scalar) else { continue };
            let remote_addrs = conn.pointer("/properties/remote_addrs").and_then(scalar);
            collectors.push(CollectorArg { kind, ports, remote_addrs });
        }
    }

    let u = doc.get("unmanaged_workloads").filter(|u| u.get("enabled").and_then(Value::as_bool) == Some(true));
    let unmanaged = u.map(|u| {
        let num = |k: &str| u.get(k).and_then(Value::as_u64);
        UnmanagedArgs {
            enabled: true,
            dry_run: u.get("dry_run").and_then(Value::as_bool).unwrap_or(false),
            networks: u.get("networks").and_then(Value::as_array).map(|n| {
                n.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(",")
            }),
            min_flows: num("min_flows"),
            max_per_window: num("max_creates_per_window"),
            max_per_day: num("max_creates_per_day"),
            // The list form is kept as JSON, which `--unmanaged-label-rules` also takes.
            label_rules: u.get("label_rules").map(|r| r.as_str().map_or_else(|| r.to_string(), str::to_string)),
        }
    });

    let key = String::from_utf8_lossy(api_key);
    let key = key.trim();
    let (api_user, secret) = if key.contains("key_id") {
        crate::secrets::api_key_json(key).ok_or("the API key file is not valid key JSON")?
    } else {
        match key.split_whitespace().collect::<Vec<_>>()[..] {
            [user, secret] => (user.to_string(), secret.to_string()),
            _ => return Err("the API key file is not in the 'user secret' form".into()),
        }
    };

    Ok(Answers {
        pce_addr,
        org_id,
        api_user,
        api_secret: Secret(secret),
        collectors,
        text,
        unmanaged,
        verify_pce_cert,
        proxy,
    })
}

/// A string or a number as text (YAML ports such as `2055` are numbers).
fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn text_args(props: Option<&Value>) -> TextArgs {
    let get = |k: &str| props.and_then(|p| p.get(k)).and_then(scalar);
    TextArgs {
        src_ip: get("src_ip"),
        dst_ip: get("dst_ip"),
        dst_port: get("dst_port"),
        protocol: get("protocol"),
        octets: get("octets"),
        icmp_type: get("icmp_type"),
        icmp_code: get("icmp_code"),
        timestamp: get("timestamp"),
        timestamp_format: get("timestamp_format"),
        only_recs: get("only_recs"),
        field_separator: get("field_separator"),
        attribute_separator: get("attribute_separator"),
    }
}

impl Answers {
    /// What is still needed before the install can go on.
    pub fn missing(&self) -> Vec<&'static str> {
        let mut m = Vec::new();
        if self.pce_addr.is_empty() {
            m.push("pce");
        }
        if self.api_user.is_empty() || self.api_secret.0.is_empty() {
            m.push("api key");
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::args::{CollectorKind, InstallArgs};
    use std::collections::HashMap;

    fn env_of<'a>(m: &'a HashMap<&'static str, &'static str>) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| m.get(k).map(|v| v.to_string())
    }

    #[test]
    fn answers_flags_beat_env_beat_defaults() {
        let env: HashMap<_, _> = [
            ("FLOWPILOT_PCE_ADDR", "env.example.com:8443"),
            ("FLOWPILOT_ORG_ID", "7"),
            ("FLOWPILOT_API_USER", "api_env"),
            ("FLOWPILOT_API_SECRET", "envsecret"),
            ("FLOWPILOT_VERIFY_PCE_CERT", "false"),
            ("FLOWPILOT_TEXT_SRC_IP", "env_src"),
            ("FLOWPILOT_TEXT_DST_IP", "env_dst"),
        ]
        .into();
        let args = InstallArgs { pce: Some("flag.example.com:8443".into()), ..Default::default() };
        let a = from_args(&args, &env_of(&env)).unwrap();
        assert_eq!(a.pce_addr, "flag.example.com:8443");
        assert_eq!((a.org_id, a.api_user.as_str(), a.api_secret.0.as_str()), (7, "api_env", "envsecret"));
        assert!(!a.verify_pce_cert);
        let mut args = args;
        args.org = Some(3);
        args.text.src_ip = Some("flag_src".into());
        let a = from_args(&args, &env_of(&env)).unwrap();
        assert_eq!(a.org_id, 3);
        assert_eq!(a.text.src_ip.as_deref(), Some("flag_src"));
        assert_eq!(a.text.dst_ip.as_deref(), Some("env_dst"));

        // Defaults: org 1, NetFlow on 2055, certificate verified, no unmanaged.
        let none = HashMap::new();
        let a = from_args(&InstallArgs::default(), &env_of(&none)).unwrap();
        assert_eq!(a.org_id, 1);
        assert!(a.verify_pce_cert);
        assert_eq!(a.collectors.len(), 1);
        assert_eq!((a.collectors[0].kind, a.collectors[0].ports.as_str()), (CollectorKind::Netflow, "2055"));
        assert!(a.unmanaged.is_none());
    }

    #[test]
    fn answers_collectors_and_unmanaged_from_env() {
        let env: HashMap<_, _> = [
            ("FLOWPILOT_IPFIX_PORTS", "4739"),
            ("FLOWPILOT_IPFIX_REMOTE_ADDRS", "10.0.0.0/8"),
            ("FLOWPILOT_UNMANAGED_ENABLED", "true"),
            ("FLOWPILOT_UNMANAGED_MIN_FLOWS", "5"),
        ]
        .into();
        let a = from_args(&InstallArgs::default(), &env_of(&env)).unwrap();
        assert_eq!(a.collectors.len(), 1);
        assert_eq!(a.collectors[0].kind, CollectorKind::Ipfix);
        assert_eq!(a.collectors[0].remote_addrs.as_deref(), Some("10.0.0.0/8"));
        let u = a.unmanaged.unwrap();
        assert!(u.enabled);
        assert_eq!(u.min_flows, Some(5));
        let bad: HashMap<_, _> = [("FLOWPILOT_ORG_ID", "x"), ("FLOWPILOT_VERIFY_PCE_CERT", "maybe")].into();
        assert_eq!(from_args(&InstallArgs::default(), &env_of(&bad)).unwrap_err().len(), 2);
    }

    #[test]
    fn answers_trim_pasted_secret() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("secret");
        std::fs::write(&f, "  s3cret\n").unwrap();
        let args = InstallArgs { api_user: Some("api_x".into()), api_secret_file: Some(f), ..Default::default() };
        let a = from_args(&args, &|_| None).unwrap();
        assert_eq!(a.api_secret.0, "s3cret");
        assert_eq!(format!("{:?}", a.api_secret), "\"********\"");
    }

    #[test]
    fn answers_from_pce_json_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("key.json");
        std::fs::write(&f, r#"{"key_id":"k1","auth_username":"api_x","secret":"y"}"#).unwrap();
        let args = InstallArgs { api_key_file: Some(f), ..Default::default() };
        let a = from_args(&args, &|_| None).unwrap();
        assert_eq!((a.api_user.as_str(), a.api_secret.0.as_str()), ("api_x", "y"));

        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, "not json").unwrap();
        let args = InstallArgs { api_key_file: Some(bad), ..Default::default() };
        assert_eq!(from_args(&args, &|_| None).unwrap_err().len(), 1);
    }

    #[test]
    fn answers_over_a_base_keep_what_is_not_given() {
        let mut base = defaults();
        base.pce_addr = "old.example.com:8443".into();
        base.org_id = 4;
        base.api_user = "api_old".into();
        base.collectors[0].ports = "2056".into();
        base.text.src_ip = Some("src".into());
        base.unmanaged = Some(UnmanagedArgs { enabled: true, min_flows: Some(7), ..Default::default() });
        base.verify_pce_cert = false;
        base.proxy = Proxy { https: "http://p:3128".into(), no_proxy: "localhost".into(), ..Default::default() };
        let a = from_args_over(&InstallArgs::default(), &|_| None, base.clone()).unwrap();
        assert_eq!(a, base);

        let args = InstallArgs { pce: Some("new.example.com:8443".into()), proxy: Some("http://q:3128".into()), ..Default::default() };
        let env: HashMap<_, _> = [("FLOWPILOT_UNMANAGED_MIN_FLOWS", "9")].into();
        let a = from_args_over(&args, &env_of(&env), base.clone()).unwrap();
        assert_eq!((a.pce_addr.as_str(), a.org_id, a.api_user.as_str()), ("new.example.com:8443", 4, "api_old"));
        assert_eq!(a.unmanaged.unwrap().min_flows, Some(9));
        assert_eq!((a.proxy.https.as_str(), a.proxy.no_proxy.as_str()), ("http://q:3128", "localhost"));
    }

    #[test]
    fn proxy_from_flag_then_env() {
        let env: HashMap<_, _> = [("FLOWPILOT_HTTPS_PROXY", "http://env-proxy:3128")].into();
        assert_eq!(from_args(&InstallArgs::default(), &env_of(&env)).unwrap().proxy.https, "http://env-proxy:3128");
        let args = InstallArgs { proxy: Some("http://flag-proxy:3128".into()), ..Default::default() };
        assert_eq!(from_args(&args, &env_of(&env)).unwrap().proxy.https, "http://flag-proxy:3128");
        assert_eq!(from_args(&InstallArgs::default(), &|_| None).unwrap().proxy, Proxy::default());
    }

    #[test]
    fn proxy_debug_hides_credentials() {
        let p = Proxy { https: "http://user:pa55@proxy:3128".into(), http: "user:pa55@proxy:3128".into(), ..Default::default() };
        let s = format!("{p:?}");
        assert!(!s.contains("pa55") && !s.contains("user"), "{s}");
        assert!(s.contains("***@proxy:3128"), "{s}");
    }

    #[test]
    fn only_variables_the_installer_reads_count_as_answers() {
        for name in ANSWER_VARS {
            let env: HashMap<_, _> = [(*name, "1")].into();
            assert!(any_answer_var(&env_of(&env)), "{name}");
        }
        assert!(any_answer_var(&env_of(&[("FLOWPILOT_TEXT_SRC_IP", "src")].into())));
        assert!(any_answer_var(&env_of(&[("FLOWPILOT_SFLOW_PORTS", "6343")].into())));
        // Daemon settings the installer does not map, and empty values, are no answer.
        for name in ["FLOWPILOT_API_KEY", "FLOWPILOT_DATA_DIRECTORY", "FLOWPILOT_STATS_HTTP_LISTEN", "FLOWPILOT_NO_PROXY"] {
            let env: HashMap<_, _> = [(name, "x")].into();
            assert!(!any_answer_var(&env_of(&env)), "{name}");
        }
        assert!(!any_answer_var(&env_of(&[("FLOWPILOT_PCE_ADDR", "")].into())));
    }

    #[test]
    fn missing_lists_required_answers() {
        let a = from_args(&InstallArgs::default(), &|_| None).unwrap();
        assert_eq!(a.missing(), vec!["pce", "api key"]);
        let args = InstallArgs { pce: Some("p:443".into()), ..Default::default() };
        assert_eq!(from_args(&args, &|_| None).unwrap().missing(), vec!["api key"]);
    }

    #[test]
    fn from_existing_round_trips_rendered_config() {
        use crate::install::args::{CollectorArg, UnmanagedArgs};
        let s = |v: &str| Some(v.to_string());
        let a = Answers {
            pce_addr: "pce.example.com:8443".into(),
            org_id: 3,
            api_user: "api_1".into(),
            api_secret: Secret("s3cret".into()),
            collectors: vec![
                CollectorArg { kind: CollectorKind::Netflow, ports: "2055".into(), remote_addrs: s("192.0.2.10") },
                CollectorArg { kind: CollectorKind::Text, ports: "514".into(), remote_addrs: None },
            ],
            text: TextArgs { src_ip: s("src"), dst_port: s("4"), timestamp_format: s("mmm dd"), ..Default::default() },
            unmanaged: Some(UnmanagedArgs {
                enabled: true,
                dry_run: true,
                networks: s("10.0.0.0/8,192.168.0.0/16"),
                min_flows: Some(5),
                max_per_window: Some(50),
                max_per_day: None,
                label_rules: s("10.1.0.0/16=app:web,env:prod"),
            }),
            verify_pce_cert: false,
            proxy: Proxy {
                https: "http://u:p@proxy.example.com:3128".into(),
                http: "http://proxy.example.com:3128".into(),
                no_proxy: "localhost".into(),
            },
        };
        let config = crate::install::render::config_yaml(&a, "127.0.0.1:9180");
        let key = crate::install::render::api_key_file(&a);
        let back = from_existing(config.as_bytes(), key.as_bytes()).unwrap();
        assert_eq!(crate::install::render::config_yaml(&back, "127.0.0.1:9180"), config);
        assert_eq!(back.collectors, a.collectors);
        assert_eq!(back.proxy, a.proxy);
        assert_eq!((back.api_user.as_str(), back.api_secret.0.as_str()), ("api_1", "s3cret"));

        let json = r#"{"key_id":"k","auth_username":"api_2","secret":"t"}"#;
        assert_eq!(from_existing(config.as_bytes(), json.as_bytes()).unwrap().api_user, "api_2");
        assert!(from_existing(config.as_bytes(), b"just-one-word\n").is_err());
        assert!(from_existing(b"org_id: 1\n", key.as_bytes()).is_err());
        assert!(from_existing(b": not yaml: [", key.as_bytes()).is_err());
    }
}
