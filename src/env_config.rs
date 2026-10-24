//! Configuration from environment variables (docs/configuration.md,
//! "Environment variables"). `apply` lays `FLOWPILOT_*` variables over the file's document and
//! fills what is still missing from plugger's `PCE_*` variables; the result goes through the same schema validation
//! and decoding as a file (`config::validate_doc`). It also records where every value came from (`Sources`), so
//! errors can name the variable and `-print-config` can show the origin.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::config::Secret;

/// The process environment, injectable for tests. Production: `&|k| std::env::var(k).ok()`.
pub type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

/// Where a configuration value came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    File,
    /// A `FLOWPILOT_*` variable.
    Env(String),
    /// One of plugger's `PCE_*` variables, used because neither a variable nor the file set the value.
    Fallback(String),
    /// FlowPilot's own default when no file is used (the data directory).
    Default,
}

/// Value origins keyed by dotted path: `pce_addr`, `proxy_config.http_proxy`,
/// `consumers[netflow].connectors[0].properties.ports`, `unmanaged_workloads.dns.servers`. Consumers are addressed by
/// name, connectors by index; other arrays are single values.
pub type Sources = BTreeMap<String, Source>;

/// The merged document, ready for schema validation.
#[derive(Debug)]
pub struct Overlay {
    pub doc: Value,
    pub sources: Sources,
    /// API user and secret given directly (`FLOWPILOT_API_USER`/`_SECRET`, or plugger's `PCE_API_KEY`/`_SECRET`).
    pub credentials: Option<(String, Secret)>,
}

/// The data directory when no config file is used.
pub const DEFAULT_DATA_DIRECTORY: &str = "/var/lib/flowpilot";

#[derive(Clone, Copy)]
enum Kind {
    Int,
    Bool,
    Str,
    /// Comma-separated, items trimmed: a JSON array of strings.
    List,
    /// `unmanaged_workloads.label_rules`: compact `cidr=key:value,...;...` or a JSON array.
    LabelRules,
}

/// The general settings: variable, dotted config path, value type.
const GENERAL: [(&str, &str, Kind); 13] = [
    ("FLOWPILOT_PCE_ADDR", "pce_addr", Kind::Str),
    ("FLOWPILOT_ORG_ID", "org_id", Kind::Int),
    ("FLOWPILOT_API_KEY", "api_key", Kind::Str),
    ("FLOWPILOT_VERIFY_PCE_CERT", "verify_pce_cert", Kind::Bool),
    ("FLOWPILOT_DATA_DIRECTORY", "data_directory", Kind::Str),
    (
        "FLOWPILOT_DATA_DIRECTORY_SIZE_MB",
        "data_directory_size_mb",
        Kind::Int,
    ),
    (
        "FLOWPILOT_FILE_RETENTION_HOURS",
        "file_retention_hours",
        Kind::Int,
    ),
    (
        "FLOWPILOT_AGGREGATION_MINUTES",
        "aggregation_minutes",
        Kind::Int,
    ),
    (
        "FLOWPILOT_MAX_FLOWS_PER_POST",
        "max_flows_per_post",
        Kind::Int,
    ),
    (
        "FLOWPILOT_METRICS_PRINT_SECONDS",
        "metrics_print_seconds",
        Kind::Int,
    ),
    (
        "FLOWPILOT_HTTPS_PROXY",
        "proxy_config.https_proxy",
        Kind::Str,
    ),
    ("FLOWPILOT_HTTP_PROXY", "proxy_config.http_proxy", Kind::Str),
    ("FLOWPILOT_NO_PROXY", "proxy_config.no_proxy", Kind::Str),
];

const API_USER: &str = "FLOWPILOT_API_USER";
const API_SECRET: &str = "FLOWPILOT_API_SECRET";

/// Collectors that variables can define; each becomes a consumer of that name.
const COLLECTORS: [&str; 4] = ["netflow", "ipfix", "sflow", "text"];

/// Text parser properties settable as `FLOWPILOT_TEXT_<PROPERTY>`.
const TEXT_PROPERTIES: [&str; 12] = [
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "icmp_type",
    "icmp_code",
    "octets",
    "timestamp",
    "timestamp_format",
    "only_recs",
    "field_separator",
    "attribute_separator",
];

/// `unmanaged_workloads` keys settable as `FLOWPILOT_UNMANAGED_<KEY>` (dots become `_`), with their value type.
const UNMANAGED_KEYS: [(&str, Kind); 17] = [
    ("enabled", Kind::Bool),
    ("dry_run", Kind::Bool),
    ("networks", Kind::List),
    ("exclude_networks", Kind::List),
    ("allow_broad_networks", Kind::Bool),
    ("min_flows", Kind::Int),
    ("flow_window_hours", Kind::Int),
    ("max_creates_per_window", Kind::Int),
    ("max_creates_per_day", Kind::Int),
    ("refresh_hours", Kind::Int),
    ("external_data_set", Kind::Str),
    ("api_key", Kind::Str),
    ("label_rules", Kind::LabelRules),
    ("dns.enabled", Kind::Bool),
    ("dns.servers", Kind::List),
    ("dns.timeout_ms", Kind::Int),
    ("dns.concurrency", Kind::Int),
];

/// `stats` keys settable as `FLOWPILOT_STATS_<KEY>`.
const STATS_KEYS: [(&str, Kind); 5] = [
    ("interval_seconds", Kind::Int),
    ("log", Kind::Bool),
    ("legacy_metrics", Kind::Bool),
    ("http_listen", Kind::Str),
    ("idle_warn_seconds", Kind::Int),
];

/// Keys of a section with their value type.
type Keys = &'static [(&'static str, Kind)];

/// The sections of nested keys: config key, variable prefix, keys.
const SECTIONS: [(&str, &str, Keys); 2] = [
    (
        "unmanaged_workloads",
        "FLOWPILOT_UNMANAGED_",
        &UNMANAGED_KEYS,
    ),
    ("stats", "FLOWPILOT_STATS_", &STATS_KEYS),
];

fn section_var(prefix: &str, key: &str) -> String {
    format!("{prefix}{}", key.replace('.', "_").to_uppercase())
}

/// A variable's value; an empty variable counts as unset.
fn get(env: Env, name: &str) -> Option<String> {
    env(name).filter(|v| !v.is_empty())
}

/// Every `FLOWPILOT_*` variable docs/configuration.md defines.
fn all_vars() -> Vec<String> {
    let mut v: Vec<String> = GENERAL.iter().map(|(name, ..)| name.to_string()).collect();
    v.extend([API_USER, API_SECRET].map(String::from));
    for c in COLLECTORS {
        v.extend(["PORTS", "REMOTE_ADDRS"].map(|s| format!("FLOWPILOT_{}_{s}", c.to_uppercase())));
    }
    v.extend(TEXT_PROPERTIES.map(|p| format!("FLOWPILOT_TEXT_{}", p.to_uppercase())));
    for (_, prefix, keys) in SECTIONS {
        v.extend(keys.iter().map(|(k, _)| section_var(prefix, k)));
    }
    v
}

/// Whether any `FLOWPILOT_*` variable is set (plugger's `PCE_*` do not count).
pub fn any_flowpilot_var(env: Env) -> bool {
    all_vars().iter().any(|v| get(env, v).is_some())
}

/// The `FLOWPILOT_*` names among `names` that no setting reads, sorted and once each: a misspelled variable (say
/// `FLOWPILOT_NETFLOW_PORT`) is otherwise ignored without a word. Only names are looked at, never values.
pub fn unknown_vars<S: AsRef<str>>(names: &[S]) -> Vec<String> {
    let known = all_vars();
    let mut out: Vec<String> = names
        .iter()
        .map(|n| n.as_ref())
        .filter(|n| n.starts_with("FLOWPILOT_") && !known.iter().any(|k| k == n))
        .map(String::from)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// One message per name of `unknown_vars`: `Unknown variable ignored: <NAME>`.
pub fn unknown_var_messages<S: AsRef<str>>(names: &[S]) -> Vec<String> {
    unknown_vars(names).iter().map(|n| format!("Unknown variable ignored: {n}")).collect()
}

/// The names of the process environment (names that are not valid UTF-8 are skipped: none is a known variable).
pub fn process_var_names() -> Vec<String> {
    std::env::vars_os().filter_map(|(k, _)| k.into_string().ok()).collect()
}

/// The variable that sets a dotted config path, e.g. `org_id` -> `FLOWPILOT_ORG_ID`,
/// `consumers[text].parser.properties.src_ip` -> `FLOWPILOT_TEXT_SRC_IP`.
pub fn var_for(path: &str) -> Option<String> {
    if let Some((name, ..)) = GENERAL.iter().find(|(_, p, _)| *p == path) {
        return Some(name.to_string());
    }
    if let Some(rest) = path.strip_prefix("consumers[") {
        let (c, rest) = rest.split_once(']')?;
        if !COLLECTORS.contains(&c) {
            return None;
        }
        let up = c.to_uppercase();
        return match rest {
            ".connectors[0].properties.ports" => Some(format!("FLOWPILOT_{up}_PORTS")),
            ".connectors[0].properties.remote_addrs" => {
                Some(format!("FLOWPILOT_{up}_REMOTE_ADDRS"))
            }
            _ => {
                let p = rest.strip_prefix(".parser.properties.")?;
                (c == "text" && TEXT_PROPERTIES.contains(&p))
                    .then(|| format!("FLOWPILOT_TEXT_{}", p.to_uppercase()))
            }
        };
    }
    SECTIONS.iter().find_map(|(section, prefix, keys)| {
        let k = path.strip_prefix(section)?.strip_prefix('.')?;
        keys.iter()
            .any(|(key, _)| *key == k)
            .then(|| section_var(prefix, k))
    })
}

/// Merges the variables over `file_doc` (the file's YAML as JSON). `Ok(None)` when there is neither a file nor any
/// `FLOWPILOT_*` variable. Errors are complete messages naming the variable.
pub fn apply(file_doc: Option<Value>, env: Env) -> Result<Option<Overlay>, Vec<String>> {
    let has_file = file_doc.is_some();
    if !has_file && !any_flowpilot_var(env) {
        return Ok(None);
    }
    let mut sources = Sources::new();
    let mut doc = file_doc.unwrap_or_else(|| Value::Object(Map::new()));
    record_file(&doc, "", &mut sources);
    if !doc.is_object() {
        // Not a mapping: nothing can be merged; the schema reports the file as it is.
        return Ok(Some(Overlay {
            doc,
            sources,
            credentials: None,
        }));
    }
    let mut errors = Vec::new();
    let mut set = |doc: &mut Value, path: &str, value: Value, source: Source| {
        set_path(doc, path, value);
        sources.insert(path.to_string(), source);
    };

    let sections = SECTIONS.iter().flat_map(|(section, prefix, keys)| {
        keys.iter()
            .map(move |(k, kind)| (section_var(prefix, k), format!("{section}.{k}"), *kind))
    });
    let general = GENERAL.map(|(name, path, kind)| (name.to_string(), path.to_string(), kind));
    for (name, path, kind) in general.into_iter().chain(sections) {
        let Some(raw) = get(env, &name) else { continue };
        match typed(&name, &raw, kind) {
            Ok(v) => set(&mut doc, &path, v, Source::Env(name)),
            Err(e) => errors.push(e),
        }
    }

    // Credentials given directly win over `api_key`; the schema still requires the key, so it is left empty.
    let mut credentials = None;
    match (get(env, API_USER), get(env, API_SECRET)) {
        (Some(user), Some(secret)) => {
            credentials = Some((user, Secret(secret)));
            set(&mut doc, "api_key", "".into(), Source::Env(API_USER.into()));
        }
        (None, None) => {}
        _ => errors.push(format!("{API_USER} and {API_SECRET} must be set together")),
    }

    // Plugger's variables fill only what neither a variable nor the file set.
    if is_unset(&doc, "pce_addr") {
        if let Some(host) = get(env, "PCE_HOST") {
            let addr = match get(env, "PCE_PORT") {
                Some(port) => format!("{host}:{port}"),
                None => host,
            };
            set(
                &mut doc,
                "pce_addr",
                addr.into(),
                Source::Fallback("PCE_HOST".into()),
            );
        }
    }
    if is_unset(&doc, "org_id") {
        if let Some(raw) = get(env, "PCE_ORG_ID") {
            match typed("PCE_ORG_ID", &raw, Kind::Int) {
                Ok(v) => set(&mut doc, "org_id", v, Source::Fallback("PCE_ORG_ID".into())),
                Err(e) => errors.push(e),
            }
        }
    }
    if credentials.is_none() && is_unset(&doc, "api_key") {
        if let (Some(user), Some(secret)) = (get(env, "PCE_API_KEY"), get(env, "PCE_API_SECRET")) {
            credentials = Some((user, Secret(secret)));
            set(
                &mut doc,
                "api_key",
                "".into(),
                Source::Fallback("PCE_API_KEY".into()),
            );
        }
    }

    if !has_file && is_unset(&doc, "data_directory") {
        set(
            &mut doc,
            "data_directory",
            DEFAULT_DATA_DIRECTORY.into(),
            Source::Default,
        );
    }

    collectors(&mut doc, env, &mut sources, &mut errors);

    if errors.is_empty() {
        Ok(Some(Overlay {
            doc,
            sources,
            credentials,
        }))
    } else {
        Err(errors)
    }
}

/// A variable's text as the JSON value the config key takes.
fn typed(name: &str, raw: &str, kind: Kind) -> Result<Value, String> {
    let t = raw.trim();
    match kind {
        Kind::Str => Ok(raw.into()),
        Kind::Int => t
            .parse::<i64>()
            .map(Value::from)
            .map_err(|_| format!("{name}: not an integer: {raw}")),
        Kind::Bool => match t.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true.into()),
            "false" | "0" | "no" => Ok(false.into()),
            _ => Err(format!("{name}: not a boolean: {raw}")),
        },
        Kind::List => Ok(list(raw).into()),
        Kind::LabelRules => label_rules(name, raw),
    }
}

/// A comma-separated list, items trimmed.
fn list(raw: &str) -> Vec<&str> {
    raw.split(',').map(str::trim).collect()
}

/// `FLOWPILOT_UNMANAGED_LABEL_RULES`: a JSON array as in YAML when it starts with `[`, else the compact form
/// `cidr=key:value,key:value;cidr=...` (spaces around the parts ignored). The schema and the decoder check the rules
/// further.
pub(crate) fn label_rules(name: &str, raw: &str) -> Result<Value, String> {
    let t = raw.trim();
    if t.starts_with('[') {
        return serde_json::from_str(t).map_err(|e| format!("{name}: invalid JSON: {e}"));
    }
    let bad =
        |rule: &str| format!("{name}: invalid rule '{rule}', expected cidr=key:value,key:value");
    let rule = |r: &str| -> Result<Value, String> {
        let (cidr, labels) = r.split_once('=').ok_or_else(|| bad(r))?;
        let labels = labels
            .split(',')
            .map(
                |l| match l.split_once(':').map(|(k, v)| (k.trim(), v.trim())) {
                    Some((k, v)) if !k.is_empty() && !v.is_empty() => Ok((k.to_string(), v.into())),
                    _ => Err(bad(r)),
                },
            )
            .collect::<Result<Map<_, _>, _>>()?;
        match cidr.trim() {
            "" => Err(bad(r)),
            cidr => Ok(json!({"cidr": cidr, "labels": labels})),
        }
    };
    // A trailing `;` is allowed.
    t.split(';')
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(rule)
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

/// The collector variables: each `FLOWPILOT_<C>_PORTS` defines a consumer `<c>` with a UDP connector, or, when the
/// file has a consumer of that name, the variables are applied over it property by property (docs/configuration.md, "Collectors").
fn collectors(doc: &mut Value, env: Env, sources: &mut Sources, errors: &mut Vec<String>) {
    for c in COLLECTORS {
        let up = c.to_uppercase();
        let ports_var = format!("FLOWPILOT_{up}_PORTS");
        let ports = match get(env, &ports_var).map(|raw| ports(&ports_var, &raw)) {
            Some(Err(e)) => {
                errors.push(e);
                continue;
            }
            Some(Ok(p)) => Some(p),
            None => None,
        };
        let remote_var = format!("FLOWPILOT_{up}_REMOTE_ADDRS");
        let remote = match get(env, &remote_var).map(|raw| remote_addrs(&remote_var, &raw)) {
            Some(Err(e)) => {
                errors.push(e);
                continue;
            }
            Some(Ok(a)) => Some(a),
            None => None,
        };
        let text: Vec<(String, &str, Value)> = TEXT_PROPERTIES
            .iter()
            .filter(|_| c == "text")
            .filter_map(|p| {
                let var = format!("FLOWPILOT_TEXT_{}", p.to_uppercase());
                let raw = get(env, &var)?;
                Some((var, *p, text_value(p, raw)))
            })
            .collect();
        if ports.is_none() && remote.is_none() && text.is_empty() {
            continue;
        }

        if doc.get("consumers").is_none_or(Value::is_null) {
            doc["consumers"] = json!([]);
        }
        // Not a list: the schema reports it.
        let Some(consumers) = doc["consumers"].as_array_mut() else {
            continue;
        };
        let existing = consumers
            .iter()
            .position(|x| x.get("name").and_then(Value::as_str) == Some(c));
        let at = |rest: &str| format!("consumers[{c}].{rest}");
        let consumer = match existing {
            Some(i) => &mut consumers[i],
            None if ports.is_none() => {
                let given = remote
                    .iter()
                    .map(|_| &remote_var)
                    .chain(text.iter().map(|t| &t.0));
                errors.extend(given.map(|v| format!("{v} is set but {ports_var} is missing")));
                continue;
            }
            None => {
                let mut parser = json!({"type": c});
                if c == "text" {
                    // Present, so the schema reports the required properties that no variable sets.
                    parser["properties"] = json!({});
                }
                consumers.push(json!({"name": c, "parser": parser,
                                      "connectors": [{"type": "udp", "properties": {}}]}));
                for p in ["name", "parser.type", "connectors[0].type"] {
                    sources.insert(at(p), Source::Env(ports_var.clone()));
                }
                consumers.last_mut().expect("just pushed")
            }
        };

        let connector = [
            (&ports_var, ports, "ports"),
            (&remote_var, remote, "remote_addrs"),
        ];
        if connector.iter().any(|(_, v, _)| v.is_some()) {
            let udp = consumer
                .get("connectors")
                .and_then(Value::as_array)
                .and_then(|cs| {
                    cs.iter()
                        .position(|x| x.get("type").and_then(Value::as_str) == Some("udp"))
                });
            let Some(i) = udp else {
                let var = connector
                    .iter()
                    .find(|(_, v, _)| v.is_some())
                    .expect("one is set")
                    .0;
                errors.push(format!(
                    "{var}: consumer {c} in the config file has no udp connector"
                ));
                continue;
            };
            for (var, value, key) in connector {
                let Some(value) = value else { continue };
                set_path(
                    &mut consumer["connectors"][i],
                    &format!("properties.{key}"),
                    value.into(),
                );
                sources.insert(
                    at(&format!("connectors[{i}].properties.{key}")),
                    Source::Env(var.clone()),
                );
            }
        }
        for (var, p, value) in text {
            set_path(consumer, &format!("parser.properties.{p}"), value);
            sources.insert(at(&format!("parser.properties.{p}")), Source::Env(var));
        }
    }
}

/// `_PORTS`: comma-separated decimal ports 0-65535, normalized to `a,b`. Checked here so a bad port is a config
/// error naming the variable, not a connector that silently does not start.
fn ports(name: &str, raw: &str) -> Result<String, String> {
    let items = list(raw);
    match items
        .iter()
        .find(|p| !p.bytes().all(|b| b.is_ascii_digit()) || p.parse::<u16>().is_err())
    {
        Some(bad) => Err(format!("{name}: invalid port: {bad}")),
        None => Ok(items.join(",")),
    }
}

/// `_REMOTE_ADDRS`: comma-separated IP addresses (no CIDRs, as the connector requires), normalized to `a,b`.
fn remote_addrs(name: &str, raw: &str) -> Result<String, String> {
    let items = list(raw);
    match items
        .iter()
        .find(|a| a.parse::<std::net::IpAddr>().is_err())
    {
        Some(bad) => Err(format!("{name}: invalid address: {bad}")),
        None => Ok(items.join(",")),
    }
}

/// A text parser property: all digits is a field number (an integer, as in YAML), anything else an attribute name.
/// Untrimmed, so a single-space separator survives. The four string-only properties stay strings.
pub(crate) fn text_value(property: &str, raw: String) -> Value {
    let string_only = matches!(
        property,
        "timestamp_format" | "only_recs" | "field_separator" | "attribute_separator"
    );
    if string_only || raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return raw.into();
    }
    raw.parse::<u64>().map_or(Value::String(raw), Value::from)
}

/// Absent or null (null counts as unset, like the schema defaults do).
fn is_unset(doc: &Value, path: &str) -> bool {
    path.split('.')
        .try_fold(doc, |v, k| v.get(k))
        .is_none_or(Value::is_null)
}

/// Sets a dotted path of plain object keys, creating (or replacing non-object) intermediate objects.
fn set_path(doc: &mut Value, path: &str, value: Value) {
    let mut cur = doc;
    let mut keys = path.split('.').peekable();
    while let Some(k) = keys.next() {
        if !cur.is_object() {
            *cur = Value::Object(Map::new());
        }
        let m = cur.as_object_mut().expect("just made an object");
        if keys.peek().is_none() {
            m.insert(k.to_string(), value);
            return;
        }
        cur = m.entry(k).or_insert(Value::Null);
    }
}

/// Records `Source::File` for every non-null value of the file document.
fn record_file(v: &Value, path: &str, out: &mut Sources) {
    let join = |k: &str| {
        if path.is_empty() {
            k.to_string()
        } else {
            format!("{path}.{k}")
        }
    };
    match v {
        Value::Null => {}
        Value::Object(m) => m.iter().for_each(|(k, v)| match (k.as_str(), v) {
            ("consumers", Value::Array(items)) => {
                for (i, c) in items.iter().enumerate() {
                    record_file(c, &format!("{}[{}]", join(k), consumer_key(c, i)), out);
                }
            }
            ("connectors", Value::Array(items)) => {
                for (i, c) in items.iter().enumerate() {
                    record_file(c, &format!("{}[{i}]", join(k)), out);
                }
            }
            _ => record_file(v, &join(k), out),
        }),
        _ if path.is_empty() => {}
        _ => {
            out.insert(path.to_string(), Source::File);
        }
    }
}

/// A consumer's key in a source path: its name, or its index when it has none.
pub fn consumer_key(c: &Value, index: usize) -> String {
    c.get("name")
        .and_then(Value::as_str)
        .map_or_else(|| index.to_string(), str::to_string)
}

/// The `Sources` key for a validation error's field (`consumers.0.connectors.1.properties.ports` ->
/// `consumers[netflow].connectors[1].properties.ports`).
pub fn source_path(field: &str, doc: &Value) -> String {
    let mut out = String::new();
    let mut parts = field.split('.').peekable();
    let mut cur = Some(doc);
    while let Some(p) = parts.next() {
        cur = cur.and_then(|v| v.get(p));
        let index = parts.peek().and_then(|n| n.parse::<usize>().ok());
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(p);
        if let (Some(i), Some(arr)) = (index, cur) {
            parts.next();
            let item = arr.get(i);
            let key = match (p, item) {
                ("consumers", Some(c)) => consumer_key(c, i),
                _ => i.to_string(),
            };
            out.push_str(&format!("[{key}]"));
            cur = item;
        }
    }
    out
}

/// The variable behind a source path, when it came from one; an indexed item (`dns.servers[2]`) belongs to its list.
pub fn variable_of<'a>(sources: &'a Sources, path: &str) -> Option<&'a str> {
    let mut p = path;
    loop {
        match sources.get(p) {
            Some(Source::Env(v) | Source::Fallback(v)) => return Some(v),
            Some(_) => return None,
            None => p = p.strip_suffix(']').and_then(|q| q.rsplit_once('['))?.0,
        }
    }
}

/// For a schema `<key> is required` error at source path `path`: the variable that sets the missing key, when the
/// consumer it belongs to was made by variables (`FLOWPILOT_TEXT_SRC_IP` for a text consumer from
/// `FLOWPILOT_TEXT_PORTS`). A consumer from the file is reported with the config key, as before.
pub fn missing_variable(sources: &Sources, path: &str, key: &str) -> Option<String> {
    let var = var_for(&format!("{path}.{key}"))?;
    let (consumer, _) = path.split_once("].")?;
    matches!(
        sources.get(&format!("{consumer}].name")),
        Some(Source::Env(_))
    )
    .then_some(var)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    fn run(file: Option<Value>, vars: &[(&str, &str)]) -> Result<Option<Overlay>, Vec<String>> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        apply(file, &move |k: &str| map.get(k).cloned())
    }

    fn ok(file: Option<Value>, vars: &[(&str, &str)]) -> Overlay {
        run(file, vars).unwrap().expect("an overlay")
    }

    fn file() -> Value {
        json!({"pce_addr": "a:1", "org_id": 2, "api_key": "$cat k", "data_directory": "/tmp"})
    }

    fn env(v: &str) -> Source {
        Source::Env(v.into())
    }

    #[test]
    fn general_vars_override_file() {
        let o = ok(Some(file()), &[("FLOWPILOT_ORG_ID", "7")]);
        assert_eq!(o.doc["org_id"], 7);
        assert_eq!(o.sources["org_id"], env("FLOWPILOT_ORG_ID"));
        assert_eq!(o.sources["pce_addr"], Source::File);
        let o = ok(
            Some(file()),
            &[
                ("FLOWPILOT_HTTP_PROXY", "http://p:3128"),
                ("FLOWPILOT_PCE_ADDR", "b:2"),
            ],
        );
        assert_eq!(o.doc["proxy_config"]["http_proxy"], "http://p:3128");
        assert_eq!(
            o.sources["proxy_config.http_proxy"],
            env("FLOWPILOT_HTTP_PROXY")
        );
        assert_eq!(o.doc["pce_addr"], "b:2");
    }

    #[test]
    fn empty_var_is_unset() {
        let o = ok(Some(file()), &[("FLOWPILOT_ORG_ID", "")]);
        assert_eq!(o.doc["org_id"], 2);
        assert_eq!(o.sources["org_id"], Source::File);
    }

    #[test]
    fn pce_fallbacks_only_fill_gaps() {
        let plugger = [
            ("FLOWPILOT_NETFLOW_PORTS", "2055"),
            ("PCE_HOST", "pce.example"),
            ("PCE_PORT", "8443"),
            ("PCE_ORG_ID", "3"),
            ("PCE_API_KEY", "u"),
            ("PCE_API_SECRET", "s"),
        ];
        let o = ok(None, &plugger);
        assert_eq!(o.doc["pce_addr"], "pce.example:8443");
        assert_eq!(o.doc["org_id"], 3);
        assert_eq!(o.credentials, Some(("u".into(), Secret("s".into()))));
        assert_eq!(o.sources["pce_addr"], Source::Fallback("PCE_HOST".into()));
        assert_eq!(o.sources["org_id"], Source::Fallback("PCE_ORG_ID".into()));

        let o = ok(Some(json!({"pce_addr": "f:1"})), &plugger);
        assert_eq!(o.doc["pce_addr"], "f:1");
        assert_eq!(o.sources["pce_addr"], Source::File);

        let o = ok(
            None,
            &[
                ("FLOWPILOT_NETFLOW_PORTS", "2055"),
                ("PCE_HOST", "pce.example"),
            ],
        );
        assert_eq!(o.doc["pce_addr"], "pce.example");

        // A variable beats the fallback; the file's key beats the credential fallback.
        let o = ok(None, &[("FLOWPILOT_ORG_ID", "9"), ("PCE_ORG_ID", "3")]);
        assert_eq!(o.doc["org_id"], 9);
        let o = ok(Some(file()), &plugger);
        assert_eq!(o.credentials, None);
        assert_eq!(o.doc["api_key"], "$cat k");
    }

    #[test]
    fn direct_credentials() {
        let o = ok(
            None,
            &[("FLOWPILOT_API_USER", "u"), ("FLOWPILOT_API_SECRET", "s")],
        );
        assert_eq!(o.credentials, Some(("u".into(), Secret("s".into()))));
        assert_eq!(o.doc["api_key"], "");
        assert_eq!(o.sources["api_key"], env("FLOWPILOT_API_USER"));
        // They win over an api_key and over the plugger fallback.
        let o = ok(
            Some(file()),
            &[
                ("FLOWPILOT_API_USER", "u"),
                ("FLOWPILOT_API_SECRET", "s"),
                ("PCE_API_KEY", "x"),
                ("PCE_API_SECRET", "y"),
            ],
        );
        assert_eq!(o.credentials, Some(("u".into(), Secret("s".into()))));
        for one in ["FLOWPILOT_API_USER", "FLOWPILOT_API_SECRET"] {
            let e = run(None, &[(one, "v")]).unwrap_err();
            assert!(
                e.iter().any(|l| l
                    .contains("FLOWPILOT_API_USER and FLOWPILOT_API_SECRET must be set together")),
                "{e:?}"
            );
        }
    }

    #[test]
    fn typed_values() {
        let o = ok(None, &[("FLOWPILOT_VERIFY_PCE_CERT", "No")]);
        assert_eq!(o.doc["verify_pce_cert"], false);
        let o = ok(
            None,
            &[
                ("FLOWPILOT_VERIFY_PCE_CERT", "1"),
                ("FLOWPILOT_MAX_FLOWS_PER_POST", "2500"),
            ],
        );
        assert_eq!(
            (
                o.doc["verify_pce_cert"].clone(),
                o.doc["max_flows_per_post"].clone()
            ),
            (json!(true), json!(2500))
        );
        assert_eq!(
            run(None, &[("FLOWPILOT_ORG_ID", "x")]).unwrap_err(),
            ["FLOWPILOT_ORG_ID: not an integer: x"]
        );
        assert_eq!(
            run(None, &[("FLOWPILOT_VERIFY_PCE_CERT", "maybe")]).unwrap_err(),
            ["FLOWPILOT_VERIFY_PCE_CERT: not a boolean: maybe"]
        );
    }

    #[test]
    fn no_file_defaults_data_directory() {
        let o = ok(None, &[("FLOWPILOT_ORG_ID", "1")]);
        assert_eq!(o.doc["data_directory"], "/var/lib/flowpilot");
        assert_eq!(o.sources["data_directory"], Source::Default);
        let o = ok(None, &[("FLOWPILOT_DATA_DIRECTORY", "/d")]);
        assert_eq!(o.sources["data_directory"], env("FLOWPILOT_DATA_DIRECTORY"));
        // With a file, a missing data_directory stays missing (the schema reports it, as today).
        assert!(ok(Some(json!({})), &[]).doc.get("data_directory").is_none());
    }

    #[test]
    fn nothing_set_returns_none() {
        assert!(run(None, &[]).unwrap().is_none());
        assert!(run(
            None,
            &[
                ("PCE_HOST", "h"),
                ("PCE_API_KEY", "u"),
                ("PCE_API_SECRET", "s")
            ]
        )
        .unwrap()
        .is_none());
        assert!(run(None, &[("FLOWPILOT_ORG_ID", "")]).unwrap().is_none());
    }

    #[test]
    fn file_values_and_nested_paths_are_recorded() {
        let doc = json!({
            "pce_addr": "a:1",
            "consumers": [{"name": "netflow", "parser": {"type": "netflow"},
                           "connectors": [{"type": "udp", "properties": {"ports": "2055"}}]}],
            "unmanaged_workloads": {"dns": {"servers": ["10.0.0.53"]}},
        });
        let o = ok(Some(doc.clone()), &[]);
        assert_eq!(o.doc, doc, "nothing set: the file document is unchanged");
        for p in [
            "pce_addr",
            "consumers[netflow].connectors[0].properties.ports",
            "consumers[netflow].parser.type",
            "unmanaged_workloads.dns.servers",
        ] {
            assert_eq!(
                o.sources.get(p),
                Some(&Source::File),
                "{p}: {:?}",
                o.sources
            );
        }
    }

    #[test]
    fn variable_names() {
        assert_eq!(var_for("org_id").as_deref(), Some("FLOWPILOT_ORG_ID"));
        assert_eq!(
            var_for("proxy_config.no_proxy").as_deref(),
            Some("FLOWPILOT_NO_PROXY")
        );
        assert_eq!(
            var_for("consumers[text].parser.properties.src_ip").as_deref(),
            Some("FLOWPILOT_TEXT_SRC_IP")
        );
        assert_eq!(
            var_for("consumers[netflow].connectors[0].properties.ports").as_deref(),
            Some("FLOWPILOT_NETFLOW_PORTS")
        );
        assert_eq!(var_for("pce_kafka.installation_id"), None);
        assert!(any_flowpilot_var(
            &|k: &str| (k == "FLOWPILOT_NO_PROXY").then(|| "x".to_string())
        ));
        assert!(!any_flowpilot_var(&|_: &str| Some(String::new())));
        assert_eq!(
            var_for("unmanaged_workloads.dns.servers").as_deref(),
            Some("FLOWPILOT_UNMANAGED_DNS_SERVERS")
        );
        assert_eq!(
            var_for("stats.http_listen").as_deref(),
            Some("FLOWPILOT_STATS_HTTP_LISTEN")
        );
        assert!(any_flowpilot_var(&|k: &str| (k
            == "FLOWPILOT_UNMANAGED_DNS_TIMEOUT_MS")
            .then(|| "1".to_string())));
    }

    #[test]
    fn credentials_are_masked_in_debug() {
        let o = ok(
            None,
            &[
                ("FLOWPILOT_API_USER", "u"),
                ("FLOWPILOT_API_SECRET", "topsecret"),
            ],
        );
        let dbg = format!("{o:?}");
        assert!(
            !dbg.contains("topsecret") && dbg.contains("********"),
            "{dbg}"
        );
    }

    fn errors(file: Option<Value>, vars: &[(&str, &str)]) -> Vec<String> {
        run(file, vars).expect_err("errors")
    }

    #[test]
    fn ports_create_consumer() {
        let o = ok(None, &[("FLOWPILOT_NETFLOW_PORTS", "2055, 9995")]);
        assert_eq!(
            o.doc["consumers"],
            json!([{"name": "netflow", "parser": {"type": "netflow"},
                    "connectors": [{"type": "udp", "properties": {"ports": "2055,9995"}}]}])
        );
        let ports = "consumers[netflow].connectors[0].properties.ports";
        assert_eq!(o.sources[ports], env("FLOWPILOT_NETFLOW_PORTS"));
        assert_eq!(
            o.sources["consumers[netflow].name"],
            env("FLOWPILOT_NETFLOW_PORTS")
        );
    }

    #[test]
    fn bad_port_is_config_error() {
        for bad in ["abc", "70000", "2055,", "-1", "0x10"] {
            let e = errors(None, &[("FLOWPILOT_IPFIX_PORTS", bad)]);
            let item = bad.rsplit(',').next().unwrap();
            assert_eq!(e, [format!("FLOWPILOT_IPFIX_PORTS: invalid port: {item}")]);
        }
        let o = ok(None, &[("FLOWPILOT_SFLOW_PORTS", "0,65535")]);
        assert_eq!(
            o.doc["consumers"][0]["connectors"][0]["properties"]["ports"],
            "0,65535"
        );
    }

    fn consumer(name: &str, props: Value) -> Value {
        json!({"name": name, "parser": {"type": name},
               "connectors": [{"type": "udp", "properties": props}]})
    }

    #[test]
    fn merge_into_file_consumer() {
        let file = json!({"consumers": [
            consumer("sflow", json!({"ports": "6343"})),
            consumer("netflow", json!({"ports": "2055", "remote_addrs": "10.0.0.1"})),
            consumer("other", json!({"ports": "1"})),
        ]});
        let o = ok(
            Some(file.clone()),
            &[
                ("FLOWPILOT_NETFLOW_PORTS", "9995"),
                ("FLOWPILOT_TEXT_PORTS", "514"),
                ("FLOWPILOT_TEXT_SRC_IP", "1"),
                ("FLOWPILOT_IPFIX_PORTS", "4739"),
            ],
        );
        let c = o.doc["consumers"].as_array().unwrap();
        let names: Vec<&str> = c.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["sflow", "netflow", "other", "ipfix", "text"]);
        assert_eq!(
            c[1]["connectors"][0]["properties"],
            json!({"ports": "9995", "remote_addrs": "10.0.0.1"})
        );
        assert_eq!(c[0], file["consumers"][0]);
        assert_eq!(c[2], file["consumers"][2]);
        assert_eq!(
            o.sources["consumers[netflow].connectors[0].properties.remote_addrs"],
            Source::File
        );
        assert_eq!(
            o.sources["consumers[netflow].connectors[0].properties.ports"],
            env("FLOWPILOT_NETFLOW_PORTS")
        );
        assert_eq!(
            o.sources["consumers[sflow].connectors[0].properties.ports"],
            Source::File
        );
        // The variables address the consumer's UDP connector, not an earlier one of another type.
        let file = json!({"consumers": [{"name": "sflow", "parser": {"type": "sflow"},
            "connectors": [{"type": "tcp"}, {"type": "udp", "properties": {"ports": "1"}}]}]});
        let o = ok(Some(file), &[("FLOWPILOT_SFLOW_PORTS", "6343")]);
        assert_eq!(
            o.doc["consumers"][0]["connectors"][1]["properties"]["ports"],
            "6343"
        );
        assert_eq!(
            o.doc["consumers"][0]["connectors"][0],
            json!({"type": "tcp"})
        );
        let file = json!({"consumers": [{"name": "sflow", "parser": {"type": "sflow"},
            "connectors": [{"type": "tcp"}]}]});
        assert_eq!(
            errors(Some(file), &[("FLOWPILOT_SFLOW_PORTS", "6343")]),
            ["FLOWPILOT_SFLOW_PORTS: consumer sflow in the config file has no udp connector"]
        );
    }

    #[test]
    fn patch_without_ports() {
        let file = json!({"consumers": [consumer("netflow", json!({"ports": "2055"}))]});
        let o = ok(
            Some(file),
            &[("FLOWPILOT_NETFLOW_REMOTE_ADDRS", "10.0.0.2, 10.0.0.3")],
        );
        assert_eq!(
            o.doc["consumers"][0]["connectors"][0]["properties"],
            json!({"ports": "2055", "remote_addrs": "10.0.0.2,10.0.0.3"})
        );
        assert_eq!(
            o.sources["consumers[netflow].connectors[0].properties.remote_addrs"],
            env("FLOWPILOT_NETFLOW_REMOTE_ADDRS")
        );
        // Checked like the ports: the connector would otherwise not start, with only a log line.
        for bad in ["10.0.0.0/8", "host", "10.0.0.2,"] {
            let e = errors(
                None,
                &[
                    ("FLOWPILOT_NETFLOW_PORTS", "2055"),
                    ("FLOWPILOT_NETFLOW_REMOTE_ADDRS", bad),
                ],
            );
            let item = bad.rsplit(',').next().unwrap();
            assert_eq!(
                e,
                [format!(
                    "FLOWPILOT_NETFLOW_REMOTE_ADDRS: invalid address: {item}"
                )]
            );
        }
        let e = errors(None, &[("FLOWPILOT_NETFLOW_REMOTE_ADDRS", "10.0.0.2")]);
        assert!(
            e.iter().any(|l| l.contains(
                "FLOWPILOT_NETFLOW_REMOTE_ADDRS is set but FLOWPILOT_NETFLOW_PORTS is missing"
            )),
            "{e:?}"
        );
        let e = errors(
            Some(json!({"consumers": []})),
            &[("FLOWPILOT_TEXT_SRC_IP", "3")],
        );
        assert_eq!(
            e,
            ["FLOWPILOT_TEXT_SRC_IP is set but FLOWPILOT_TEXT_PORTS is missing"]
        );
    }

    #[test]
    fn text_properties() {
        let o = ok(
            None,
            &[
                ("FLOWPILOT_TEXT_PORTS", "514"),
                ("FLOWPILOT_TEXT_SRC_IP", "3"),
                ("FLOWPILOT_TEXT_DST_IP", "src"),
                ("FLOWPILOT_TEXT_DST_PORT", "dpt"),
                ("FLOWPILOT_TEXT_PROTOCOL", "proto"),
                ("FLOWPILOT_TEXT_FIELD_SEPARATOR", " "),
                ("FLOWPILOT_TEXT_ONLY_RECS", "1234"),
            ],
        );
        let c = &o.doc["consumers"][0];
        assert_eq!(c["name"], "text");
        assert_eq!(c["parser"]["type"], "text");
        let p = &c["parser"]["properties"];
        assert_eq!(p["src_ip"], json!(3));
        assert_eq!(p["dst_ip"], json!("src"));
        assert_eq!(p["field_separator"], json!(" "));
        // A string-only property stays a string even when it is all digits.
        assert_eq!(p["only_recs"], json!("1234"));
        assert_eq!(
            o.sources["consumers[text].parser.properties.field_separator"],
            env("FLOWPILOT_TEXT_FIELD_SEPARATOR")
        );
    }

    fn env_of(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn unknown_flowpilot_vars_listed() {
        let names = [
            "FLOWPILOT_NETFLOW_PORT",
            "FLOWPILOT_NETFLOW_PORTS",
            "FLOWPILOT_STATS_INTERVAL",
            "FLOWPILOT_STATS_INTERVAL_SECONDS",
            "FLOWPILOT_API_SECRET",
            "FLOWPILOT_UNMANAGED_DNS_SERVERS",
            "PCE_HOST",
            "HOME",
            "flowpilot_org_id",
            "FLOWPILOT_NETFLOW_PORT",
        ];
        assert_eq!(unknown_vars(&names), ["FLOWPILOT_NETFLOW_PORT", "FLOWPILOT_STATS_INTERVAL"]);
        assert_eq!(
            unknown_var_messages(&names),
            [
                "Unknown variable ignored: FLOWPILOT_NETFLOW_PORT",
                "Unknown variable ignored: FLOWPILOT_STATS_INTERVAL"
            ]
        );
        // Every documented variable is known.
        assert!(unknown_vars(&all_vars()).is_empty());
        assert!(unknown_vars::<&str>(&[]).is_empty());
    }

    /// The log lines of a failed `config::load_from`.
    fn load_errors(path: &str, vars: &[(&str, &str)]) -> Vec<String> {
        match crate::config::load_from(path, &env_of(vars)) {
            Err(crate::config::LoadError::Log(lines)) => lines,
            Err(other) => panic!("{other:?}"),
            Ok(l) => panic!("expected a failure, got {:?}", l.config),
        }
    }

    #[test]
    fn text_missing_required_names_var() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let base = [
            ("FLOWPILOT_PCE_ADDR", "pce:8443"),
            ("FLOWPILOT_API_KEY", "$cat k"),
            ("FLOWPILOT_DATA_DIRECTORY", d),
            ("FLOWPILOT_TEXT_PORTS", "514"),
            ("FLOWPILOT_TEXT_DST_IP", "dst"),
            ("FLOWPILOT_TEXT_DST_PORT", "dpt"),
            ("FLOWPILOT_TEXT_PROTOCOL", "proto"),
        ];
        let lines = load_errors("", &base);
        assert!(
            lines.contains(
                &"\t- [FLOWPILOT_TEXT_SRC_IP (consumers.0.parser.properties): src_ip is required]"
                    .to_string()
            ),
            "{lines:?}"
        );
        // Ports alone: all four are reported by variable.
        let lines = load_errors("", &base[..4]);
        for v in ["SRC_IP", "DST_IP", "DST_PORT", "PROTOCOL"] {
            assert!(
                lines
                    .iter()
                    .any(|l| l.contains(&format!("FLOWPILOT_TEXT_{v} ("))),
                "{v}: {lines:?}"
            );
        }
        // A text consumer from the file keeps the config key, even with a variable merged into it.
        let path = dir.path().join("c.yaml");
        std::fs::write(
            &path,
            "consumers:\n  - name: text\n    connectors:\n      - type: udp\n    parser:\n      type: text\n      properties:\n        dst_ip: 4\n        dst_port: 5\n        protocol: 6\n",
        )
        .unwrap();
        let lines = load_errors(path.to_str().unwrap(), &base[..4]);
        assert!(
            lines.contains(&"\t- [consumers.0.parser.properties: src_ip is required]".to_string()),
            "{lines:?}"
        );
        // A nested schema error about a variable's value names it (here an array item from JSON label rules).
        let mut vars = base.to_vec();
        vars.extend([
            ("FLOWPILOT_TEXT_SRC_IP", "src"),
            (
                "FLOWPILOT_UNMANAGED_LABEL_RULES",
                r#"[{"cidr":"10.0.0.0/8"}]"#,
            ),
        ]);
        let lines = load_errors("", &vars);
        assert_eq!(
            lines[1..],
            ["\t- [FLOWPILOT_UNMANAGED_LABEL_RULES (unmanaged_workloads.label_rules.0): labels is required]"]
        );
    }

    #[test]
    fn unmanaged_vars() {
        let o = ok(
            None,
            &[
                ("FLOWPILOT_UNMANAGED_ENABLED", "true"),
                ("FLOWPILOT_UNMANAGED_NETWORKS", "10.0.0.0/8, 192.168.0.0/16"),
                ("FLOWPILOT_UNMANAGED_MIN_FLOWS", "5"),
                ("FLOWPILOT_UNMANAGED_DNS_SERVERS", "10.0.0.53"),
                ("FLOWPILOT_UNMANAGED_EXTERNAL_DATA_SET", "fp"),
            ],
        );
        assert_eq!(
            o.doc["unmanaged_workloads"],
            json!({"enabled": true, "networks": ["10.0.0.0/8", "192.168.0.0/16"], "min_flows": 5,
                   "dns": {"servers": ["10.0.0.53"]}, "external_data_set": "fp"})
        );
        assert_eq!(
            o.sources["unmanaged_workloads.dns.servers"],
            env("FLOWPILOT_UNMANAGED_DNS_SERVERS")
        );
        // Over the file: only the variable's key changes.
        let file = json!({"unmanaged_workloads": {"enabled": false, "min_flows": 9}});
        let o = ok(Some(file), &[("FLOWPILOT_UNMANAGED_ENABLED", "yes")]);
        assert_eq!(
            o.doc["unmanaged_workloads"],
            json!({"enabled": true, "min_flows": 9})
        );
        assert_eq!(
            errors(None, &[("FLOWPILOT_UNMANAGED_MIN_FLOWS", "many")]),
            ["FLOWPILOT_UNMANAGED_MIN_FLOWS: not an integer: many"]
        );
    }

    #[test]
    fn label_rules_compact_and_json() {
        let want = json!([
            {"cidr": "10.1.0.0/16", "labels": {"app": "web", "env": "prod"}},
            {"cidr": "10.2.0.0/24", "labels": {"app": "db"}},
        ]);
        let rules = |v: &str| {
            ok(None, &[("FLOWPILOT_UNMANAGED_LABEL_RULES", v)]).doc["unmanaged_workloads"]
                ["label_rules"]
                .clone()
        };
        assert_eq!(
            rules("10.1.0.0/16=app:web,env:prod;10.2.0.0/24=app:db"),
            want
        );
        assert_eq!(
            rules(" 10.1.0.0/16 = app: web , env:prod ; 10.2.0.0/24=app:db; "),
            want
        );
        assert_eq!(
            rules(r#"[{"cidr":"10.1.0.0/16","labels":{"app":"web"}}]"#),
            json!([{"cidr": "10.1.0.0/16", "labels": {"app": "web"}}])
        );
        for bad in [
            "10.1.0.0/16=app",
            "10.1.0.0/16",
            "10.1.0.0/16=:web",
            "[{",
            "x=a:b;=c:d",
        ] {
            let e = errors(None, &[("FLOWPILOT_UNMANAGED_LABEL_RULES", bad)]);
            assert!(
                e.len() == 1 && e[0].starts_with("FLOWPILOT_UNMANAGED_LABEL_RULES: "),
                "{bad}: {e:?}"
            );
        }
    }

    #[test]
    fn stats_vars() {
        let o = ok(
            None,
            &[
                ("FLOWPILOT_STATS_HTTP_LISTEN", "127.0.0.1:9180"),
                ("FLOWPILOT_STATS_LEGACY_METRICS", "false"),
                ("FLOWPILOT_STATS_INTERVAL_SECONDS", "30"),
            ],
        );
        assert_eq!(
            o.doc["stats"],
            json!({"http_listen": "127.0.0.1:9180", "legacy_metrics": false, "interval_seconds": 30})
        );
        assert_eq!(
            o.sources["stats.legacy_metrics"],
            env("FLOWPILOT_STATS_LEGACY_METRICS")
        );
    }
}
