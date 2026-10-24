//! Configuration types and loading (docs/configuration.md). Loading/validation is implemented in
//! `load_and_validate`.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use jsonschema::Validator;
use serde::Serialize;
use serde_json::Value;

use crate::env_config::{self, Env, Source, Sources};
use crate::secrets::go_abs;
use crate::stats::StatsConfig;
use crate::unmanaged::config::UnmanagedConfig;

/// Parser or connector properties (string to string). Numeric YAML values arrive as decimal strings.
pub type Properties = BTreeMap<String, String>;

/// A parser or connector entry.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Info {
    pub kind: String,
    pub properties: Properties,
}

/// One entry of `consumers`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Consumer {
    pub name: String,
    pub parser: Info,
    pub connectors: Vec<Info>,
}

/// `proxy_config`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HttpProxy {
    pub https_proxy: String,
    pub http_proxy: String,
    pub no_proxy: String,
}

/// `pce_kafka` (PCE Kafka/Integrations mode is deferred; parsed for validation only).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PceKafka {
    pub installation_id: String,
    pub env_override: String,
    pub kafka_info: String,
}

/// The whole configuration. Integer widths match FlowLink's (overflow silently becomes 0).
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub pce_addr: String,
    pub api_key: String,
    pub org_id: i32,
    pub verify_pce_cert: bool,
    pub aggregation_minutes: i16,
    pub data_directory: String,
    pub data_directory_size_mb: i16,
    pub file_retention_hours: i16,
    pub metrics_print_seconds: i16,
    pub max_flows_per_post: i64,
    pub pce_kafka: PceKafka,
    pub consumers: Vec<Consumer>,
    pub proxy_config: HttpProxy,
    /// FlowPilot extension (not in FlowLink's schema): automatic unmanaged workload creation.
    pub unmanaged_workloads: UnmanagedConfig,
    /// The `unmanaged_workloads` key appears in the file (only then is it printed with `-debug`).
    pub unmanaged_workloads_present: bool,
    /// FlowPilot extension: the `stats` key, defaults applied.
    pub stats: StatsConfig,
    /// API user and secret given directly by variables; when set they are used instead of `api_key`.
    pub api_credentials: Option<(String, Secret)>,
}

/// A secret that never shows in `Debug` output.
#[derive(Clone, PartialEq)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("\"********\"")
    }
}

impl Config {
    /// The PCE API user and secret: the direct credentials, else resolved from `api_key` (exits on failure).
    pub fn credentials(&self) -> (String, String) {
        match &self.api_credentials {
            Some((user, secret)) => (user.clone(), secret.0.clone()),
            None => crate::secrets::api_credentials(&self.api_key),
        }
    }
}

impl Default for Config {
    /// The schema defaults (docs/configuration.md); required keys empty.
    fn default() -> Self {
        Self {
            pce_addr: String::new(),
            api_key: String::new(),
            org_id: 1,
            verify_pce_cert: true,
            aggregation_minutes: 10,
            data_directory: String::new(),
            data_directory_size_mb: 500,
            file_retention_hours: 24,
            metrics_print_seconds: 60,
            max_flows_per_post: 10000,
            pce_kafka: PceKafka::default(),
            consumers: Vec::new(),
            proxy_config: HttpProxy::default(),
            unmanaged_workloads: UnmanagedConfig::default(),
            unmanaged_workloads_present: false,
            stats: StatsConfig::default(),
            api_credentials: None,
        }
    }
}

/// Loads and validates the config: logs and exits 1 on any problem.
pub fn load_and_validate(path: &str) -> Config {
    load(path).unwrap_or_else(|e| e.exit())
}

/// A start-up failure: what FlowLink logs before exiting 1.
#[derive(Debug, PartialEq)]
pub(crate) enum LoadError {
    /// `log_line` of each line.
    Log(Vec<String>),
    /// An error logged by `log::check_error`.
    Check(String),
}

impl LoadError {
    fn exit(self) -> ! {
        match self {
            LoadError::Log(lines) => lines.iter().for_each(|l| crate::log_line!(l)),
            LoadError::Check(err) => {
                crate::log::check_error(Some(err));
            }
        }
        std::process::exit(1)
    }
}

fn fail(line: String) -> LoadError {
    LoadError::Log(vec![line])
}

/// A loaded configuration and where each value came from.
pub(crate) struct Loaded {
    pub config: Config,
    pub sources: Sources,
    /// `-print-config` only: the data directory does not exist yet and a start would create it.
    pub dir_pending: bool,
}

/// `load_and_validate` without the exit.
pub(crate) fn load(path: &str) -> Result<Config, LoadError> {
    // FlowPilot extension: name misspelled variables (before loading, so the hint precedes a resulting error).
    env_config::unknown_var_messages(&env_config::process_var_names()).iter().for_each(|m| crate::log_line!(m));
    load_from(path, &|k| std::env::var(k).ok()).map(|l| l.config)
}

/// `load` with the environment injected: the file (if `path` is set) with the `FLOWPILOT_*`/`PCE_*` variables
/// laid over it (`env_config::apply`). Without a file and without variables it fails as FlowLink does.
pub(crate) fn load_from(path: &str, env: Env) -> Result<Loaded, LoadError> {
    load_with(path, env, true)
}

/// `load_from`; without `create` (`-print-config`) a missing data directory that a start would create is left alone
/// and reported in `dir_pending`.
fn load_with(path: &str, env: Env, create: bool) -> Result<Loaded, LoadError> {
    let file_doc = if path.is_empty() {
        None
    } else {
        let abs = go_abs(path); // as in FlowLink, the OS error is not printed
        let data =
            std::fs::read(&abs).map_err(|_| fail(format!("Unable to read config file: {abs}")))?;
        if data.is_empty() {
            return Err(fail(format!("Config file: {abs} is empty.")));
        }
        Some(parse_yaml(&data)?)
    };
    let overlay = env_config::apply(file_doc, env).map_err(|errs| invalid(errs.iter()))?;
    let Some(overlay) = overlay else {
        return Err(fail("No config file provided".into()));
    };
    let mut config = validate_doc(overlay.doc, &overlay.sources)?;
    config.api_credentials = overlay.credentials;
    let dir = go_abs(&config.data_directory);
    let mut dir_pending = false;
    if created_by_us(overlay.sources.get("data_directory")) && !std::path::Path::new(&dir).exists() {
        // FlowPilot extension: a directory from a variable or the default is created; one from a file is not.
        if !create {
            dir_pending = true;
        } else if create_data_directory(&dir).is_ok() {
            crate::log_line!("Created data directory:", dir);
        }
    }
    if !dir_pending && !writable(&dir) {
        return Err(fail(format!("Data directory: {dir} is not writable.")));
    }
    print_config(&config);
    Ok(Loaded { config, sources: overlay.sources, dir_pending })
}

fn created_by_us(source: Option<&Source>) -> bool {
    matches!(source, Some(Source::Env(_) | Source::Fallback(_) | Source::Default))
}

/// With parents; the directory itself gets mode 0750 regardless of the umask.
fn create_data_directory(dir: &str) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new().recursive(true).mode(0o750).create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750))
}

/// `access(dir, W_OK)`, as in FlowLink; a missing directory is "not writable".
fn writable(dir: &str) -> bool {
    std::ffi::CString::new(dir).is_ok_and(|p| unsafe { libc::access(p.as_ptr(), libc::W_OK) } == 0)
}

/// Validates a config file alone, without the exit (the installer checks
/// the config it renders with it).
pub(crate) fn validate(data: &[u8]) -> Result<Config, LoadError> {
    validate_doc(parse_yaml(data)?, &Sources::new())
}

/// The raw YAML as JSON, validated before defaults are applied (as in FlowLink); a parse failure goes
/// through `log::check_error`.
fn parse_yaml(data: &[u8]) -> Result<Value, LoadError> {
    yaml_to_json(data).map_err(LoadError::Check)
}

/// Validate the document, then apply the schema defaults and decode with
/// ghodss/`encoding/json` semantics. An error about a value that came from a variable names it
/// (`FLOWPILOT_ORG_ID (org_id): ...`); all others read as before.
pub(crate) fn validate_doc(mut doc: Value, sources: &Sources) -> Result<Config, LoadError> {
    // A failure of the validator itself cannot happen: the embedded schema is fixed.
    let errors = schema_errors(&doc);
    if !errors.is_empty() {
        // As in FlowLink, each error is wrapped in `[...]` and `/1` is deleted (it
        // turns gojsonschema's big.Rat limits such as `5/1` into `5`).
        let named: Vec<String> = errors.iter().map(|e| name_variable(e, &doc, sources)).collect();
        return Err(invalid(named.iter().map(|e| e.replace("/1", ""))));
    }
    apply_defaults(&mut doc);
    let mut config = decode(&doc); // decode errors are ignored, as in FlowLink
                                   // FlowLink extension: semantic checks of `unmanaged_workloads`, reported like schema errors.
    config.unmanaged_workloads = crate::unmanaged::config::decode(
        doc.get("unmanaged_workloads").unwrap_or(&Value::Null),
        config.aggregation_minutes,
    )
    .map_err(|errs| invalid(errs.iter().map(|e| name_variable(e, &doc, sources))))?;
    // FlowPilot extension: `stats`, the same way.
    config.stats = crate::stats::decode(
        doc.get("stats").unwrap_or(&Value::Null),
        config.metrics_print_seconds,
    )
    .map_err(|errs| invalid(errs.iter().map(|e| name_variable(e, &doc, sources))))?;
    Ok(config)
}

/// The validation failure: FlowLink's header, then each error wrapped in `[...]`.
fn invalid<S: std::fmt::Display>(errors: impl Iterator<Item = S>) -> LoadError {
    let mut lines = vec!["The FlowPilot configuration file is not valid. see errors :".to_string()];
    lines.extend(errors.map(|e| format!("\t- [{e}]")));
    LoadError::Log(lines)
}

/// `<field>: <msg>` -> `<VAR> (<field>): <msg>` when the field's value came from a variable, or, for
/// `<key> is required`, when the variable for the missing key is what the variables-made object lacks.
fn name_variable(error: &str, doc: &Value, sources: &Sources) -> String {
    let Some((field, msg)) = error.split_once(": ") else {
        return error.to_string();
    };
    let path = env_config::source_path(field, doc);
    let var = env_config::variable_of(sources, &path)
        .map(str::to_string)
        .or_else(|| env_config::missing_variable(sources, &path, msg.strip_suffix(" is required")?));
    match var {
        Some(var) => format!("{var} ({field}): {msg}"),
        None => error.to_string(),
    }
}

// ---- YAML -> JSON (ghodss `YAMLToJSON`) -------------------------------------------------------

/// First YAML document only (yaml.v2 `Unmarshal`), merge keys applied, converted to JSON.
/// Divergence: serde_yaml follows YAML 1.2 (`yes`/`on` stay strings, duplicate keys are an error)
/// and its error texts differ from yaml.v2's.
fn yaml_to_json(data: &[u8]) -> Result<Value, String> {
    use serde::Deserialize;
    let mut value = match serde_yaml::Deserializer::from_slice(data).next() {
        Some(doc) => serde_yaml::Value::deserialize(doc).map_err(|e| e.to_string())?,
        None => serde_yaml::Value::Null,
    };
    value.apply_merge().map_err(|e| e.to_string())?;
    to_json(&value)
}

fn to_json(v: &serde_yaml::Value) -> Result<Value, String> {
    use serde_yaml::Value as Y;
    Ok(match v {
        Y::Null => Value::Null,
        Y::Bool(b) => Value::Bool(*b),
        Y::Number(n) => json_number(n)?,
        Y::String(s) => Value::String(s.clone()),
        Y::Sequence(items) => Value::Array(items.iter().map(to_json).collect::<Result<_, _>>()?),
        Y::Mapping(m) => Value::Object(
            m.iter()
                .map(|(k, v)| Ok((json_key(k)?, to_json(v)?)))
                .collect::<Result<_, String>>()?,
        ),
        Y::Tagged(t) => to_json(&t.value)?,
    })
}

/// `json.Marshal` of a YAML number: integral floats print as integers (`10.0` -> `10`), NaN/Inf
/// are marshal errors.
fn json_number(n: &serde_yaml::Number) -> Result<Value, String> {
    if let Some(i) = n.as_i64() {
        return Ok(i.into());
    }
    if let Some(u) = n.as_u64() {
        return Ok(u.into());
    }
    let f = n.as_f64().unwrap_or(f64::NAN);
    if !f.is_finite() {
        let s = if f.is_nan() {
            "NaN"
        } else if f > 0.0 {
            "+Inf"
        } else {
            "-Inf"
        };
        return Err(format!("json: unsupported value: {s}"));
    }
    if f.fract() == 0.0 && f.abs() < 9.2e18 {
        return Ok((f as i64).into());
    }
    Ok(serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number))
}

/// ghodss map-key conversion: scalars are formatted, anything else is an error.
fn json_key(k: &serde_yaml::Value) -> Result<String, String> {
    use serde_yaml::Value as Y;
    match k {
        Y::String(s) => Ok(s.clone()),
        Y::Bool(b) => Ok(b.to_string()),
        Y::Number(n) => Ok(match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => i.to_string(),
            (_, Some(u)) => u.to_string(),
            _ => go_format_g(n.as_f64().unwrap_or(f64::NAN)),
        }),
        Y::Tagged(t) => json_key(&t.value),
        other => Err(format!("Unsupported map key of type: {other:?}")),
    }
}

// ---- schema validation (gojsonschema emulation) ----------------------------------------------

/// FlowPilot's own schema. Same keys, types, limits and structure as FlowLink's
/// `flowlink_config_schema.json`, so the same configs pass and fail; the descriptions are ours.
const SCHEMA: &str = include_str!("config_schema.json");

const UNMANAGED_SCHEMA: &str = include_str!("unmanaged/schema.json");

const STATS_SCHEMA: &str = include_str!("stats/schema.json");

fn schema() -> &'static (Value, Validator) {
    static S: OnceLock<(Value, Validator)> = OnceLock::new();
    S.get_or_init(|| {
        let mut v: Value = serde_json::from_str(SCHEMA).expect("embedded schema is JSON");
        // FlowPilot extensions: `unmanaged_workloads` and `stats`.
        v["properties"]["unmanaged_workloads"] =
            serde_json::from_str(UNMANAGED_SCHEMA).expect("unmanaged schema is JSON");
        v["properties"]["stats"] =
            serde_json::from_str(STATS_SCHEMA).expect("stats schema is JSON");
        let validator = jsonschema::draft4::new(&v).expect("embedded schema compiles");
        (v, validator)
    })
}

/// gojsonschema `ResultError.String()` (`"<field>: <description>"`) for every error.
fn schema_errors(doc: &Value) -> Vec<String> {
    let (schema, validator) = schema();
    let mut out = Vec::new();
    collect_errors(schema, validator, doc, "", &mut out);
    out
}

/// Divergence (documented): descriptions are ported from gojsonschema's locale for the keywords
/// the shipped schema uses; anything else falls back to the jsonschema crate's wording. Error
/// order follows the jsonschema crate, not gojsonschema's traversal.
fn collect_errors(
    schema: &Value,
    validator: &Validator,
    instance: &Value,
    prefix: &str,
    out: &mut Vec<String>,
) {
    use jsonschema::error::ValidationErrorKind as K;
    for e in validator.iter_errors(instance) {
        let ptr = format!("{prefix}{}", e.instance_path.as_str());
        let field = go_field(&ptr);
        let msg = match &e.kind {
            K::Required { property } => {
                format!("{} is required", property.as_str().unwrap_or_default())
            }
            K::AdditionalProperties { unexpected } => {
                // gojsonschema reports one error per property.
                out.extend(
                    unexpected
                        .iter()
                        .map(|p| format!("{field}: Additional property {p} is not allowed")),
                );
                continue;
            }
            K::Minimum { limit } => format!("Must be greater than or equal to {limit}"),
            K::Maximum { limit } => format!("Must be less than or equal to {limit}"),
            K::MinItems { limit } => format!("Array must have at least {limit} items"),
            K::MaxItems { limit } => format!("Array must have at most {limit} items"),
            K::Enum { options } => {
                let allowed: Vec<String> = options
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(Value::to_string)
                    .collect();
                format!(
                    "{field} must be one of the following: {}",
                    allowed.join(", ")
                )
            }
            K::Type { .. } => {
                let expected = match schema.pointer(e.schema_path.as_str()) {
                    Some(Value::Array(ts)) => {
                        format!(
                            "[{}]",
                            ts.iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join(",")
                        )
                    }
                    Some(Value::String(t)) => t.clone(),
                    _ => String::new(),
                };
                format!(
                    "Invalid type. Expected: {expected}, given: {}",
                    go_type(&e.instance)
                )
            }
            K::OneOfNotValid | K::OneOfMultipleValid => {
                out.push(format!(
                    "{field}: Must validate one and only one schema (oneOf)"
                ));
                if matches!(e.kind, K::OneOfNotValid) {
                    // gojsonschema then merges the errors of the best-matching branch; "best" is
                    // approximated as the branch with the fewest errors (first on a tie).
                    let branches = schema
                        .pointer(e.schema_path.as_str())
                        .and_then(Value::as_array);
                    let best = branches
                        .into_iter()
                        .flatten()
                        .filter_map(|b| Some((b, jsonschema::draft4::new(b).ok()?)))
                        .min_by_key(|(_, v)| v.iter_errors(&e.instance).count());
                    if let Some((b, v)) = best {
                        collect_errors(b, &v, &e.instance, &ptr, out);
                    }
                }
                continue;
            }
            _ => e.to_string(),
        };
        out.push(format!("{field}: {msg}"));
    }
}

/// gojsonschema field naming: `(root)` or the dotted path with array indices.
fn go_field(ptr: &str) -> String {
    if ptr.is_empty() {
        return "(root)".into();
    }
    ptr[1..]
        .split('/')
        .map(|s| s.replace("~1", "/").replace("~0", "~"))
        .collect::<Vec<_>>()
        .join(".")
}

/// gojsonschema type names (whole numbers are `integer`).
fn go_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n)
            if n.is_i64() || n.is_u64() || n.as_f64().is_some_and(|f| f.fract() == 0.0) =>
        {
            "integer"
        }
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ---- defaults ---------------------------------------------------------------------------------

/// The schema defaults: the seven defaults are applied only to keys that are absent or null. Debug
/// lines in schema order (FlowLink's order is random); FlowLink's other debug dumps of the defaults
/// are not reproduced.
fn apply_defaults(doc: &mut Value) {
    let defaults: [(&str, &str, Value); 7] = [
        ("org_id", "integer", 1.into()),
        ("verify_pce_cert", "boolean", true.into()),
        ("aggregation_minutes", "integer", 10.into()),
        ("data_directory_size_mb", "integer", 500.into()),
        ("file_retention_hours", "integer", 24.into()),
        ("metrics_print_seconds", "integer", 60.into()),
        ("max_flows_per_post", "integer", 10000.into()),
    ];
    let Value::Object(m) = doc else { return };
    for (key, kind, value) in defaults {
        // The debug line FlowLink logs for each default.
        let (n, b) = (
            value.as_i64().unwrap_or(0),
            value.as_bool().unwrap_or(false),
        );
        crate::debug_log!("default value:", format!("{{{key} {kind} 0  {n} {b} []}}"));
        if m.get(key).is_none_or(Value::is_null) {
            crate::debug_log!("New field is a", kind);
            m.insert(key.to_string(), value);
        }
    }
}

// ---- decoding (ghodss Unmarshal semantics) ----------------------------------------------------

/// `encoding/json` field lookup: every key equal to the tag under case folding sets the field and
/// keys arrive sorted (ghodss re-marshals the map), so the last match wins. Nulls are no-ops.
fn field<'a>(obj: &'a Value, tag: &str) -> Option<&'a Value> {
    obj.as_object()?
        .iter()
        .rev()
        .find(|(k, v)| k.eq_ignore_ascii_case(tag) && !v.is_null())
        .map(|(_, v)| v)
}

/// ghodss scalar -> string conversion for string targets: ints decimal, floats
/// `FormatFloat('g', -1)`, bools `true`/`false`. Numbers pass through float64 like FlowLink's
/// `map[string]interface{}` round trip.
fn go_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => {
            let f = n.as_f64()?;
            Some(if f == 0.0 {
                "0".into()
            } else if f.fract() == 0.0 && f.abs() < 1e21 {
                format!("{f}")
            } else {
                go_format_g(f)
            })
        }
        _ => None,
    }
}

fn string_field(obj: &Value, tag: &str) -> String {
    field(obj, tag).and_then(go_string).unwrap_or_default()
}

/// As in FlowLink, non-integers and values that overflow the field width decode to 0.
fn int_field<T: TryFrom<i64> + Default>(obj: &Value, tag: &str) -> T {
    let Some(f) = field(obj, tag).and_then(Value::as_f64) else {
        return T::default();
    };
    if f.fract() != 0.0 || f.abs() >= 9.2e18 {
        return T::default();
    }
    T::try_from(f as i64).unwrap_or_default()
}

fn decode_info(v: &Value) -> Info {
    // Map elements of any non-scalar type decode to "" (the entry is still created).
    let properties = field(v, "properties")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), go_string(v).unwrap_or_default()))
                .collect()
        })
        .unwrap_or_default();
    Info {
        kind: string_field(v, "type"),
        properties,
    }
}

fn decode(doc: &Value) -> Config {
    let empty = Value::Null;
    let obj = |tag| field(doc, tag).unwrap_or(&empty);
    let (proxy, kafka) = (obj("proxy_config"), obj("pce_kafka"));
    let consumers = obj("consumers").as_array().into_iter().flatten();
    Config {
        pce_addr: string_field(doc, "pce_addr"),
        api_key: string_field(doc, "api_key"),
        org_id: int_field(doc, "org_id"),
        verify_pce_cert: field(doc, "verify_pce_cert")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        aggregation_minutes: int_field(doc, "aggregation_minutes"),
        data_directory: string_field(doc, "data_directory"),
        data_directory_size_mb: int_field(doc, "data_directory_size_mb"),
        file_retention_hours: int_field(doc, "file_retention_hours"),
        metrics_print_seconds: int_field(doc, "metrics_print_seconds"),
        max_flows_per_post: int_field(doc, "max_flows_per_post"),
        pce_kafka: PceKafka {
            installation_id: string_field(kafka, "installation_id"),
            env_override: string_field(kafka, "env_override"),
            kafka_info: string_field(kafka, "kafka_info"),
        },
        consumers: consumers
            .map(|c| Consumer {
                name: string_field(c, "name"),
                parser: decode_info(field(c, "parser").unwrap_or(&empty)),
                connectors: field(c, "connectors")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(decode_info)
                    .collect(),
            })
            .collect(),
        proxy_config: HttpProxy {
            https_proxy: string_field(proxy, "https_proxy"),
            http_proxy: string_field(proxy, "http_proxy"),
            no_proxy: string_field(proxy, "no_proxy"),
        },
        unmanaged_workloads: UnmanagedConfig::default(), // filled in by `validate`
        unmanaged_workloads_present: doc.get("unmanaged_workloads").is_some(),
        stats: StatsConfig::default(), // filled in by `validate`
        api_credentials: None,         // filled in by `load_from`
    }
}

/// Go `strconv.FormatFloat(f, 'g', -1, 64)`: shortest digits, `%e` form when the exponent is
/// < -4 or >= 6 (with at least two exponent digits).
/// Ported from the Go standard library (`strconv`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
pub(crate) fn go_format_g(f: f64) -> String {
    if !f.is_finite() {
        return (if f.is_nan() {
            "NaN"
        } else if f > 0.0 {
            "+Inf"
        } else {
            "-Inf"
        })
        .into();
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0" } else { "0" }.into();
    }
    let sci = format!("{:e}", f.abs()); // e.g. "1.2345675e6"
    let (mant, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let sign = if f < 0.0 { "-" } else { "" };
    if !(-4..6).contains(&exp) {
        let (d0, rest) = digits.split_at(1);
        let frac = if rest.is_empty() {
            String::new()
        } else {
            format!(".{rest}")
        };
        let esign = if exp < 0 { '-' } else { '+' };
        return format!("{sign}{d0}{frac}e{esign}{:02}", exp.abs());
    }
    if exp < 0 {
        return format!("{sign}0.{}{digits}", "0".repeat((-exp - 1) as usize));
    }
    let int_len = exp as usize + 1;
    if digits.len() <= int_len {
        format!("{sign}{digits}{}", "0".repeat(int_len - digits.len()))
    } else {
        format!("{sign}{}.{}", &digits[..int_len], &digits[int_len..])
    }
}

/// `-print-config`: loads the configuration as a start would and prints it with the origin of every value. Returns
/// the exit code; the config goes to stdout, the validation lines of a failure to stderr.
pub fn print_effective(path: &str, env: Env, var_names: &[String]) -> i32 {
    let (code, out) = effective(path, env, var_names);
    if code == 0 {
        print!("{out}");
    } else {
        eprint!("{out}");
    }
    code
}

/// The text and exit code of `print_effective`.
/// `var_names` are the names in the environment: unknown `FLOWPILOT_*` ones are listed first, as YAML comments.
pub(crate) fn effective(path: &str, env: Env, var_names: &[String]) -> (i32, String) {
    let warnings: String = env_config::unknown_var_messages(var_names).iter().map(|m| format!("# {m}\n")).collect();
    let (code, out) = match load_with(path, env, false) {
        Ok(loaded) => (0, render_effective(&loaded)),
        Err(LoadError::Log(lines)) => (1, lines.iter().map(|l| format!("{l}\n")).collect()),
        Err(LoadError::Check(err)) => (1, format!("{err}\n")),
    };
    (code, warnings + &out)
}

/// The effective configuration as YAML in schema key order, one value per line, each followed by a comment with its
/// origin: `file`, the variable, `<VAR> (plugger)` for a fallback, `default`. The API secret is masked and the
/// content of `api_key` is never shown (it is a path or `$command`, printed as given).
pub(crate) fn render_effective(l: &Loaded) -> String {
    use std::fmt::Write;
    let (c, src) = (&l.config, &l.sources);
    let mut out = String::new();
    // `key: value  # origin` at `indent` spaces; `path` is the Sources key (empty: no comment).
    let mut line = |indent: usize, key: &str, value: String, path: &str| {
        let origin = if path.is_empty() {
            String::new()
        } else {
            format!("  # {}", origin(src.get(path)))
        };
        let sep = if value.is_empty() { "" } else { " " };
        let _ = writeln!(out, "{:indent$}{key}:{sep}{value}{origin}", "");
    };
    let q = |s: &str| yaml_string(s);
    line(0, "pce_addr", q(&c.pce_addr), "pce_addr");
    match &c.api_credentials {
        Some((user, _)) => {
            line(0, "api_user", q(user), "api_key");
            line(0, "api_secret", "'********'".into(), "api_key");
        }
        None => line(0, "api_key", q(&c.api_key), "api_key"),
    }
    line(0, "org_id", c.org_id.to_string(), "org_id");
    line(0, "verify_pce_cert", c.verify_pce_cert.to_string(), "verify_pce_cert");
    line(0, "aggregation_minutes", c.aggregation_minutes.to_string(), "aggregation_minutes");
    line(0, "data_directory", q(&c.data_directory), "data_directory");
    line(0, "data_directory_size_mb", c.data_directory_size_mb.to_string(), "data_directory_size_mb");
    line(0, "file_retention_hours", c.file_retention_hours.to_string(), "file_retention_hours");
    line(0, "metrics_print_seconds", c.metrics_print_seconds.to_string(), "metrics_print_seconds");
    line(0, "max_flows_per_post", c.max_flows_per_post.to_string(), "max_flows_per_post");
    let p = &c.proxy_config;
    let proxies = [
        ("https_proxy", &p.https_proxy),
        ("http_proxy", &p.http_proxy),
        ("no_proxy", &p.no_proxy),
    ];
    if proxies.iter().any(|(_, v)| !v.is_empty()) {
        line(0, "proxy_config", String::new(), "");
        for (k, v) in proxies.iter().filter(|(_, v)| !v.is_empty()) {
            // A proxy URL may carry `user:pass@`: never print it.
            line(2, k, q(&crate::stats::redact_proxy_url(v)), &format!("proxy_config.{k}"));
        }
    }
    if !c.consumers.is_empty() {
        line(0, "consumers", String::new(), "");
        for (i, d) in c.consumers.iter().enumerate() {
            let key = if d.name.is_empty() { i.to_string() } else { d.name.clone() };
            let at = |rest: &str| format!("consumers[{key}].{rest}");
            line(2, "- name", q(&d.name), &at("name"));
            line(4, "parser", String::new(), "");
            line(6, "type", q(&d.parser.kind), &at("parser.type"));
            if !d.parser.properties.is_empty() {
                line(6, "properties", String::new(), "");
                for (k, v) in &d.parser.properties {
                    line(8, k, q(v), &at(&format!("parser.properties.{k}")));
                }
            }
            line(4, "connectors", String::new(), "");
            for (n, conn) in d.connectors.iter().enumerate() {
                line(6, "- type", q(&conn.kind), &at(&format!("connectors[{n}].type")));
                if !conn.properties.is_empty() {
                    line(8, "properties", String::new(), "");
                    for (k, v) in &conn.properties {
                        line(10, k, q(v), &at(&format!("connectors[{n}].properties.{k}")));
                    }
                }
            }
        }
    }
    if c.unmanaged_workloads_present {
        let u = &c.unmanaged_workloads;
        let at = |k: &str| format!("unmanaged_workloads.{k}");
        let list = |v: Vec<String>| format!("[{}]", v.join(", "));
        line(0, "unmanaged_workloads", String::new(), "");
        line(2, "enabled", u.enabled.to_string(), &at("enabled"));
        line(2, "dry_run", u.dry_run.to_string(), &at("dry_run"));
        line(2, "networks", list(u.networks.iter().map(|n| n.to_string()).collect()), &at("networks"));
        line(2, "exclude_networks", list(u.exclude_networks.iter().map(|n| n.to_string()).collect()), &at("exclude_networks"));
        line(2, "allow_broad_networks", u.allow_broad_networks.to_string(), &at("allow_broad_networks"));
        line(2, "min_flows", u.min_flows.to_string(), &at("min_flows"));
        line(2, "flow_window_hours", u.flow_window_hours.to_string(), &at("flow_window_hours"));
        line(2, "max_creates_per_window", u.max_creates_per_window.to_string(), &at("max_creates_per_window"));
        line(2, "max_creates_per_day", u.max_creates_per_day.to_string(), &at("max_creates_per_day"));
        line(2, "refresh_hours", u.refresh_hours.to_string(), &at("refresh_hours"));
        line(2, "external_data_set", q(&u.external_data_set), &at("external_data_set"));
        if let Some(k) = &u.api_key {
            line(2, "api_key", q(k), &at("api_key"));
        }
        line(2, "dns", String::new(), "");
        line(4, "enabled", u.dns.enabled.to_string(), &at("dns.enabled"));
        line(4, "servers", list(u.dns.servers.iter().map(|s| s.to_string()).collect()), &at("dns.servers"));
        line(4, "timeout_ms", u.dns.timeout_ms.to_string(), &at("dns.timeout_ms"));
        line(4, "concurrency", u.dns.concurrency.to_string(), &at("dns.concurrency"));
        let rules = u.label_rules.iter().map(|r| {
            let labels: Vec<String> = r.labels.iter().map(|(k, v)| format!("{}: {}", q(k), q(v))).collect();
            format!("{{cidr: {}, labels: {{{}}}}}", r.cidr, labels.join(", "))
        });
        line(2, "label_rules", list(rules.collect()), &at("label_rules"));
    }
    let s = &c.stats;
    let at = |k: &str| format!("stats.{k}");
    line(0, "stats", String::new(), "");
    line(2, "interval_seconds", s.interval_seconds.to_string(), &at("interval_seconds"));
    line(2, "log", s.log.to_string(), &at("log"));
    line(2, "legacy_metrics", s.legacy_metrics.to_string(), &at("legacy_metrics"));
    if let Some(a) = &s.http_listen {
        line(2, "http_listen", q(a), &at("http_listen"));
    }
    line(2, "idle_warn_seconds", s.idle_warn_seconds.to_string(), &at("idle_warn_seconds"));
    if l.dir_pending {
        out = out
            .lines()
            .map(|l| match l.starts_with("data_directory:") {
                true => format!("{l} (will be created at start)\n"),
                false => format!("{l}\n"),
            })
            .collect();
    }
    out
}

/// The comment for a value's origin.
fn origin(s: Option<&Source>) -> String {
    match s {
        Some(Source::File) => "file".into(),
        Some(Source::Env(v)) => v.clone(),
        Some(Source::Fallback(v)) => format!("{v} (plugger)"),
        Some(Source::Default) | None => "default".into(),
    }
}

/// A YAML scalar for a string, quoted only when needed.
fn yaml_string(s: &str) -> String {
    serde_yaml::to_string(s).map_or_else(|_| format!("{s:?}"), |y| y.trim_end().to_string())
}

/// Debug-only dump of the effective config as indented JSON (one space), keys in the same order as
/// FlowLink's debug output; empty optional keys are left out.
fn print_config(c: &Config) {
    if crate::log::debug() {
        debug_dump(c).iter().for_each(|m| crate::log_line!(m));
    }
}

/// The messages of `print_config`. The API secret has no field here: `api_key` is a path or `$command`, never its
/// content.
fn debug_dump(c: &Config) -> Vec<String> {
    let mut out = Vec::new();
    let consumers: Vec<ConsumerJ> = c
        .consumers
        .iter()
        .map(|d| ConsumerJ {
            name: &d.name,
            parser: InfoJ::of(&d.parser),
            connectors: d.connectors.iter().map(InfoJ::of).collect(),
        })
        .collect();
    let k = &c.pce_kafka;
    let p = &c.proxy_config;
    let j = ConfigJ {
        pce_addr: &c.pce_addr,
        api_key: &c.api_key,
        org_id: c.org_id,
        verify_pce_cert: c.verify_pce_cert,
        aggregation_minutes: c.aggregation_minutes,
        data_directory: &c.data_directory,
        data_directory_size_mb: c.data_directory_size_mb,
        file_retention_hours: c.file_retention_hours,
        metrics_print_seconds: c.metrics_print_seconds,
        max_flows_per_post: c.max_flows_per_post,
        pce_kafka: KafkaJ {
            installation_id: &k.installation_id,
            env_override: &k.env_override,
            kafka_info: &k.kafka_info,
        },
        consumers,
        proxy_config: ProxyJ {
            https_proxy: &p.https_proxy,
            http_proxy: &p.http_proxy,
            no_proxy: &p.no_proxy,
        },
        integrations_kafka_configuration: KafkaConfigJ::default(),
    };
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(
        &mut buf,
        serde_json::ser::PrettyFormatter::with_indent(b" "),
    );
    if j.serialize(&mut ser).is_ok() {
        out.push(format!(
            "config: struct: Config:\n{}",
            String::from_utf8_lossy(&buf)
        ));
    }
    out.extend(unmanaged_debug(c));
    out
}

/// The `-debug` dump of `unmanaged_workloads`, only when the key is in the file, so output without the
/// feature stays as before. `api_key` here is the override's source (a literal or `$cmd`), printed like the main
/// key.
fn unmanaged_debug(c: &Config) -> Option<String> {
    if !c.unmanaged_workloads_present {
        return None;
    }
    let u = serde_json::to_string_pretty(&c.unmanaged_workloads).ok()?;
    Some(format!("config: unmanaged_workloads:\n{u}"))
}

#[derive(Serialize)]
struct InfoJ<'a> {
    #[serde(rename = "type", skip_serializing_if = "str::is_empty")]
    kind: &'a str,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    properties: &'a Properties,
}

impl<'a> InfoJ<'a> {
    fn of(i: &'a Info) -> Self {
        Self {
            kind: &i.kind,
            properties: &i.properties,
        }
    }
}

#[derive(Serialize)]
struct ConsumerJ<'a> {
    name: &'a str,
    parser: InfoJ<'a>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    connectors: Vec<InfoJ<'a>>,
}

#[derive(Serialize)]
struct KafkaJ<'a> {
    installation_id: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    env_override: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    kafka_info: &'a str,
}

#[derive(Serialize)]
struct ProxyJ<'a> {
    https_proxy: &'a str,
    http_proxy: &'a str,
    no_proxy: &'a str,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct KafkaConfigJ {
    bootstrap_servers: String,
    topic: String,
    connection_string: String,
    max_objects_per_message: i64,
}

#[derive(Serialize)]
struct ConfigJ<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    pce_addr: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    api_key: &'a str,
    org_id: i32,
    verify_pce_cert: bool,
    aggregation_minutes: i16,
    #[serde(skip_serializing_if = "str::is_empty")]
    data_directory: &'a str,
    data_directory_size_mb: i16,
    file_retention_hours: i16,
    metrics_print_seconds: i16,
    max_flows_per_post: i64,
    pce_kafka: KafkaJ<'a>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    consumers: Vec<ConsumerJ<'a>>,
    proxy_config: ProxyJ<'a>,
    integrations_kafka_configuration: KafkaConfigJ,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The schema accepts exactly what FlowLink's does: equal once every `description` is removed.
    #[test]
    fn schema_matches_flowlink_structure() {
        fn strip(v: &mut Value) {
            match v {
                Value::Object(m) => {
                    m.remove("description");
                    m.values_mut().for_each(strip);
                }
                Value::Array(a) => a.iter_mut().for_each(strip),
                _ => {}
            }
        }
        let parse = |s: &str| -> Value {
            let mut v = serde_json::from_str(s).unwrap();
            strip(&mut v);
            v
        };
        let Some(original) = vendor_file("flowlink_config_schema.json") else {
            return;
        };
        assert_eq!(parse(SCHEMA), parse(&original));
    }

    /// A file from the FlowLink RPM, extracted by `make original`. It is not in the repository, so the tests
    /// that compare against it skip when it is missing.
    fn vendor_file(name: &str) -> Option<String> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("original/usr/local/illumio")
            .join(name);
        let text = std::fs::read_to_string(&path).ok();
        if text.is_none() {
            eprintln!("skipped: {} not present (run `make original`)", path.display());
        }
        text
    }

    /// A minimal valid config with `extra` appended at the top level.
    fn cfg(extra: &str) -> String {
        format!(
            "pce_addr: pce:8443\napi_key: $cat k\ndata_directory: /tmp\n{extra}\nconsumers:\n  - name: n\n    connectors:\n      - type: udp\n    parser:\n      type: netflow\n"
        )
    }

    fn errors(yaml: &str) -> Vec<String> {
        match validate(yaml.as_bytes()) {
            Err(LoadError::Log(lines)) => {
                assert_eq!(
                    lines[0],
                    "The FlowPilot configuration file is not valid. see errors :"
                );
                lines[1..].to_vec()
            }
            other => panic!("expected validation failure, got {other:?}"),
        }
    }

    const UW_FULL: &str = "unmanaged_workloads:
  enabled: true
  dry_run: false
  networks: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
  exclude_networks: []
  allow_broad_networks: false
  min_flows: 10
  flow_window_hours: 24
  max_creates_per_window: 100
  max_creates_per_day: 500
  refresh_hours: 24
  external_data_set: flowpilot
  api_key: \"$/usr/local/bin/get-pce-key\"
  dns:
    enabled: true
    servers: []
    timeout_ms: 2000
    concurrency: 8
  label_rules:
    - cidr: 10.0.0.0/8
      labels: { loc: dc1 }
    - cidr: 10.20.0.0/16
      labels: { env: prod, app: billing }";

    #[test]
    fn absent_key_gives_disabled_defaults() {
        let c = validate(cfg("").as_bytes()).unwrap();
        assert_eq!(
            c.unmanaged_workloads,
            crate::unmanaged::config::UnmanagedConfig::default()
        );
        assert!(!c.unmanaged_workloads.enabled);
        assert_eq!(c.unmanaged_workloads.networks.len(), 3);
    }

    #[test]
    fn unmanaged_debug_dump_only_when_key_present() {
        assert_eq!(unmanaged_debug(&validate(cfg("").as_bytes()).unwrap()), None);
        let dump = unmanaged_debug(&validate(cfg(UW_FULL).as_bytes()).unwrap()).unwrap();
        assert!(dump.starts_with("config: unmanaged_workloads:\n{"), "{dump}");
    }

    #[test]
    fn full_example_decodes() {
        let c = validate(cfg(UW_FULL).as_bytes()).unwrap();
        let u = &c.unmanaged_workloads;
        assert!(u.enabled);
        assert_eq!(u.label_rules.len(), 2);
        assert_eq!(u.max_creates_per_day, 500);
        assert_eq!(u.api_key.as_deref(), Some("$/usr/local/bin/get-pce-key"));
    }

    #[test]
    fn unknown_subkey_is_schema_error() {
        let e = errors(&cfg("unmanaged_workloads:\n  enabeld: true"));
        assert!(e.iter().any(|l| l.contains("enabeld")), "{e:?}");
    }

    #[test]
    fn semantic_errors_are_logged_with_header() {
        let e = errors(&cfg("unmanaged_workloads:\n  min_flows: 0"));
        assert_eq!(
            e,
            ["\t- [unmanaged_workloads.min_flows: must be at least 1]"]
        );
        let yaml = cfg("aggregation_minutes: 30\nunmanaged_workloads:\n  flow_window_hours: 0");
        assert_eq!(
            errors(&yaml),
            ["\t- [unmanaged_workloads.flow_window_hours: must cover at least one aggregation window (30 minutes)]"]
        );
    }

    #[test]
    fn stats_key_in_file() {
        let c = validate(cfg("metrics_print_seconds: 20").as_bytes()).unwrap();
        assert_eq!(c.stats.interval_seconds, 20, "defaults to metrics_print_seconds");
        assert!(c.stats.log && c.stats.http_listen.is_none());
        let c = validate(cfg("stats:\n  http_listen: 127.0.0.1:9180\n  log: false").as_bytes()).unwrap();
        assert_eq!(c.stats.http_listen.as_deref(), Some("127.0.0.1:9180"));
        assert!(!c.stats.log);
        assert_eq!(
            errors(&cfg("stats:\n  interval_seconds: 2")),
            ["\t- [stats.interval_seconds: Must be greater than or equal to 5]"]
        );
        let e = errors(&cfg("stats:\n  intervall_seconds: 30"));
        assert!(e.iter().any(|l| l.contains("intervall_seconds")), "{e:?}");
        assert_eq!(
            errors(&cfg("stats:\n  http_listen: nowhere")),
            ["\t- [stats.http_listen: not an ip:port address: nowhere]"]
        );
    }

    #[test]
    fn service_config_validates_with_defaults() {
        let Some(service) = vendor_file("config.yaml.service") else {
            return;
        };
        let c = validate(service.as_bytes()).unwrap();
        assert_eq!(c.pce_addr, "pce.example.com:8443");
        assert_eq!(c.api_key, "$cat /etc/illumio-flowlink/api_info");
        assert_eq!(c.data_directory, "/var/lib/illumio-flowlink/data");
        assert_eq!(
            (c.org_id, c.verify_pce_cert, c.aggregation_minutes),
            (1, true, 10)
        );
        assert_eq!(
            (
                c.data_directory_size_mb,
                c.file_retention_hours,
                c.metrics_print_seconds
            ),
            (500, 24, 60)
        );
        assert_eq!(c.max_flows_per_post, 10000);
        assert_eq!(c.consumers.len(), 4);
        assert_eq!(c.consumers[0].name, "netflow");
        assert_eq!(c.consumers[0].parser.kind, "netflow");
        assert_eq!(
            c.consumers[0].connectors,
            vec![Info {
                kind: "udp".into(),
                properties: Properties::new()
            }]
        );
        let syslog = &c.consumers[3];
        assert_eq!(syslog.connectors[0].properties["ports"], "6514");
        assert_eq!(syslog.parser.properties["timestamp"], "date_time, 1");
        assert_eq!(syslog.parser.properties.len(), 6);
        assert_eq!(c.proxy_config, HttpProxy::default());
        assert_eq!(c.pce_kafka, PceKafka::default());
    }

    #[test]
    fn example_config_validates() {
        let Some(example) = vendor_file("config.yaml.example") else {
            return;
        };
        let c = validate(example.as_bytes()).unwrap();
        assert_eq!(c.aggregation_minutes, 5);
        assert_eq!(c.org_id, 1);
        assert_eq!(c.data_directory, ".");
        let names: Vec<&str> = c.consumers.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["syslog", "netflow", "kafka", "aws"]);
        assert_eq!(c.consumers[2].connectors[0].properties["version"], "1.2.0");
        assert_eq!(
            c.consumers[3].connectors[0].properties["log_groupname"],
            "test"
        );
        assert_eq!(c.consumers[3].parser.kind, "aws");
    }

    #[test]
    fn explicit_values_are_kept() {
        let c = validate(cfg("verify_pce_cert: false\norg_id: 7\nmax_flows_per_post: 2500\nproxy_config:\n  http_proxy: http://p:3128").as_bytes()).unwrap();
        assert!(!c.verify_pce_cert);
        assert_eq!((c.org_id, c.max_flows_per_post), (7, 2500));
        assert_eq!(c.proxy_config.http_proxy, "http://p:3128");
    }

    #[test]
    fn missing_required_key() {
        let yaml = cfg("").replace("pce_addr: pce:8443\n", "");
        assert_eq!(errors(&yaml), ["\t- [(root): pce_addr is required]"]);
    }

    #[test]
    fn additional_property() {
        assert_eq!(
            errors(&cfg("foo: 1")),
            ["\t- [(root): Additional property foo is not allowed]"]
        );
    }

    #[test]
    fn aggregation_minutes_out_of_range() {
        assert_eq!(
            errors(&cfg("aggregation_minutes: 3")),
            ["\t- [aggregation_minutes: Must be greater than or equal to 5]"]
        );
        assert_eq!(
            errors(&cfg("aggregation_minutes: 61")),
            ["\t- [aggregation_minutes: Must be less than or equal to 60]"]
        );
    }

    #[test]
    fn enum_and_type_messages() {
        let yaml = cfg("").replace("type: netflow", "type: bogus");
        assert_eq!(
            errors(&yaml),
            [
                r#"	- [consumers.0.parser.type: consumers.0.parser.type must be one of the following: "text", "ipfix", "netflow", "sflow", "aws"]"#
            ]
        );
        assert_eq!(
            errors(&cfg("org_id: abc")),
            ["\t- [org_id: Invalid type. Expected: integer, given: string]"]
        );
    }

    #[test]
    fn one_of_reports_best_branch() {
        let yaml = cfg("").replace(
            "      - type: udp\n",
            "      - type: udp\n        properties:\n          ports: 5\n",
        );
        assert_eq!(
            errors(&yaml),
            [
                "\t- [consumers.0.connectors.0.properties: Must validate one and only one schema (oneOf)]",
                "\t- [consumers.0.connectors.0.properties.ports: Invalid type. Expected: string, given: integer]",
            ]
        );
    }

    #[test]
    fn numeric_and_bool_properties_become_strings() {
        let yaml = cfg("").replace(
            "      type: netflow\n",
            "      type: text\n      properties:\n        src_ip: 3\n        dst_ip: 4\n        dst_port: dport\n        protocol: 5\n",
        );
        let c = validate(yaml.as_bytes()).unwrap();
        let p = &c.consumers[0].parser.properties;
        assert_eq!(
            (
                p["src_ip"].as_str(),
                p["dst_ip"].as_str(),
                p["protocol"].as_str()
            ),
            ("3", "4", "5")
        );
        // Parser objects accept unknown keys, so an integer/bool `instances` style value is
        // converted the ghodss way too.
        let yaml = cfg("").replace("      - type: udp\n", "      - type: kafka\n        properties:\n          version: 1\n          brokers: b\n          group: g\n          topics: t\n          instances: 4\n");
        assert!(
            validate(yaml.as_bytes()).is_err(),
            "version must be a string"
        );
        let yaml = yaml.replace("version: 1", "version: \"1\"");
        let c = validate(yaml.as_bytes()).unwrap();
        assert_eq!(c.consumers[0].connectors[0].properties["instances"], "4");
    }

    #[test]
    fn narrow_int_overflow_becomes_zero() {
        let c = validate(
            cfg("metrics_print_seconds: 40000\norg_id: 3000000000\ndata_directory_size_mb: 32767")
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            (c.metrics_print_seconds, c.org_id, c.data_directory_size_mb),
            (0, 0, 32767)
        );
    }

    #[test]
    fn integral_float_counts_as_integer() {
        let c = validate(cfg("aggregation_minutes: 12.0").as_bytes()).unwrap();
        assert_eq!(c.aggregation_minutes, 12);
    }

    #[test]
    fn keys_match_case_insensitively_where_schema_allows() {
        let yaml = cfg("").replace("      type: netflow", "      TYPE: sflow");
        assert_eq!(
            validate(yaml.as_bytes()).unwrap().consumers[0].parser.kind,
            "sflow"
        );
    }

    #[test]
    fn yaml_errors_go_through_check_error() {
        match validate(b"a: [1\n") {
            Err(LoadError::Check(_)) => {}
            other => panic!("{other:?}"),
        }
        // Only the first YAML document is used (yaml.v2 Unmarshal).
        assert!(validate(format!("{}---\nfoo: 1\n", cfg("")).as_bytes()).is_ok());
    }

    #[test]
    fn non_object_root() {
        assert_eq!(
            errors("   \n"),
            ["\t- [(root): Invalid type. Expected: object, given: null]"]
        );
    }

    #[test]
    fn load_failures() {
        let log = |l: &str| Err(LoadError::Log(vec![l.to_string()]));
        // The real process environment is not used: FLOWPILOT_* in a developer's shell must not change the result.
        let load = |p: &str| load_from(p, &env_of(&[])).map(|l| l.config);
        assert_eq!(load(""), log("No config file provided"));
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        assert_eq!(
            load(&format!("{d}/missing.yaml")),
            log(&format!("Unable to read config file: {d}/missing.yaml"))
        );
        let empty = dir.path().join("empty.yaml");
        std::fs::write(&empty, "").unwrap();
        assert_eq!(
            load(empty.to_str().unwrap()),
            log(&format!("Config file: {d}/empty.yaml is empty."))
        );
        let bad = dir.path().join("bad.yaml");
        std::fs::write(
            &bad,
            cfg("").replace(
                "data_directory: /tmp",
                &format!("data_directory: {d}/nodir/../nodir"),
            ),
        )
        .unwrap();
        assert_eq!(
            load(bad.to_str().unwrap()),
            log(&format!("Data directory: {d}/nodir is not writable."))
        );
        let good = dir.path().join("good.yaml");
        std::fs::write(
            &good,
            cfg("").replace("data_directory: /tmp", &format!("data_directory: {d}")),
        )
        .unwrap();
        assert_eq!(load(good.to_str().unwrap()).unwrap().data_directory, d);
    }

    fn env_of(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: std::collections::HashMap<String, String> =
            vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| map.get(k).cloned()
    }

    fn log_lines(r: Result<Loaded, LoadError>) -> Vec<String> {
        match r {
            Err(LoadError::Log(lines)) => lines,
            Err(other) => panic!("{other:?}"),
            Ok(l) => panic!("expected a failure, got {:?}", l.config),
        }
    }

    #[test]
    fn env_error_names_variable() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let vars = [
            ("FLOWPILOT_PCE_ADDR", "pce:8443"),
            ("FLOWPILOT_API_KEY", "$cat k"),
            ("FLOWPILOT_DATA_DIRECTORY", d),
            ("FLOWPILOT_ORG_ID", "0"),
        ];
        let lines = log_lines(load_from("", &env_of(&vars)));
        assert!(
            lines.contains(&"\t- [FLOWPILOT_ORG_ID (org_id): Must be greater than or equal to 1]".to_string()),
            "{lines:?}"
        );
        // Plugger's fallback is named the same way.
        let vars = [vars[0], vars[1], vars[2], ("PCE_ORG_ID", "0")];
        let lines = log_lines(load_from("", &env_of(&vars)));
        assert!(lines.contains(&"\t- [PCE_ORG_ID (org_id): Must be greater than or equal to 1]".to_string()), "{lines:?}");
        // A malformed variable is reported with the usual header.
        let lines = log_lines(load_from("", &env_of(&[("FLOWPILOT_ORG_ID", "x")])));
        assert_eq!(
            lines,
            ["The FlowPilot configuration file is not valid. see errors :", "\t- [FLOWPILOT_ORG_ID: not an integer: x]"]
        );
    }

    #[test]
    fn file_only_errors_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        for yaml in [cfg("aggregation_minutes: 3"), cfg("unmanaged_workloads:\n  min_flows: 0"), "   \n".into()] {
            std::fs::write(&path, &yaml).unwrap();
            let via_load = log_lines(load_from(path.to_str().unwrap(), &env_of(&[])));
            assert_eq!(Err(LoadError::Log(via_load)), validate(yaml.as_bytes()).map(|_| ()));
        }
        assert_eq!(
            log_lines(load_from("", &env_of(&[("PCE_HOST", "h")]))),
            ["No config file provided"]
        );
    }

    #[test]
    fn env_only_config_loads_with_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let vars = [
            ("FLOWPILOT_DATA_DIRECTORY", d),
            ("PCE_HOST", "pce.example"),
            ("PCE_PORT", "8443"),
            ("PCE_API_KEY", "u"),
            ("PCE_API_SECRET", "topsecret"),
        ];
        // Without a collector the schema rejects it (consumers come with Task 2); with a file consumer it loads.
        let path = dir.path().join("c.yaml");
        std::fs::write(&path, "consumers:\n  - name: n\n    connectors:\n      - type: udp\n    parser:\n      type: netflow\n").unwrap();
        let l = load_from(path.to_str().unwrap(), &env_of(&vars)).unwrap();
        assert_eq!(l.config.pce_addr, "pce.example:8443");
        assert_eq!(l.config.data_directory, d);
        assert_eq!(l.sources["data_directory"], Source::Env("FLOWPILOT_DATA_DIRECTORY".into()));
        let (user, secret) = l.config.api_credentials.clone().unwrap();
        assert_eq!((user.as_str(), secret.0.as_str()), ("u", "topsecret"));
        let dbg = format!("{:?}", l.config);
        assert!(!dbg.contains("topsecret") && dbg.contains("********"), "{dbg}");
    }

    #[test]
    fn creates_env_data_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a/b");
        let path = dir.path().join("c.yaml");
        std::fs::write(&path, cfg("").replace("data_directory: /tmp\n", "")).unwrap();
        let vars = [("FLOWPILOT_DATA_DIRECTORY", target.to_str().unwrap())];
        let l = load_from(path.to_str().unwrap(), &env_of(&vars)).unwrap();
        assert_eq!(l.config.data_directory, target.to_str().unwrap());
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o750);
    }

    #[test]
    fn does_not_create_file_directory() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let path = dir.path().join("c.yaml");
        std::fs::write(&path, cfg("").replace("data_directory: /tmp", &format!("data_directory: {d}/missing"))).unwrap();
        assert_eq!(
            log_lines(load_from(path.to_str().unwrap(), &env_of(&[("FLOWPILOT_ORG_ID", "2")]))),
            [format!("Data directory: {d}/missing is not writable.")]
        );
        assert!(!dir.path().join("missing").exists());
    }

    #[test]
    fn go_float_formatting() {
        assert_eq!(go_format_g(1.5), "1.5");
        assert_eq!(go_format_g(0.0001), "0.0001");
        assert_eq!(go_format_g(0.00001), "1e-05");
        assert_eq!(go_format_g(123456.5), "123456.5");
        assert_eq!(go_format_g(1234567.5), "1.2345675e+06");
        assert_eq!(go_format_g(1e21), "1e+21");
        assert_eq!(go_format_g(-2.25), "-2.25");
    }

    #[test]
    fn print_config_shows_sources_and_masks() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let vars = [
            ("FLOWPILOT_API_USER", "u"),
            ("FLOWPILOT_API_SECRET", "topsecret"),
            ("FLOWPILOT_NETFLOW_PORTS", "2055"),
            ("FLOWPILOT_PCE_ADDR", "p:1"),
            ("FLOWPILOT_DATA_DIRECTORY", d),
            ("FLOWPILOT_STATS_HTTP_LISTEN", "127.0.0.1:9180"),
        ];
        let (code, out) = effective("", &env_of(&vars), &[]);
        assert_eq!(code, 0, "{out}");
        assert!(!out.contains("topsecret"), "{out}");
        let doc: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(doc["pce_addr"].as_str(), Some("p:1"));
        assert_eq!(doc["api_user"].as_str(), Some("u"));
        assert_eq!(doc["api_secret"].as_str(), Some("********"));
        assert_eq!(doc["consumers"][0]["name"].as_str(), Some("netflow"));
        assert_eq!(doc["consumers"][0]["connectors"][0]["properties"]["ports"].as_str(), Some("2055"));
        assert_eq!(doc["stats"]["http_listen"].as_str(), Some("127.0.0.1:9180"));
        let has = |needle: &str| out.lines().any(|l| l.contains(needle));
        assert!(has("api_user: u  # FLOWPILOT_API_USER"), "{out}");
        assert!(has("api_secret: '********'"), "{out}");
        assert!(has("ports: '2055'  # FLOWPILOT_NETFLOW_PORTS"), "{out}");
        assert!(has("org_id: 1  # default"), "{out}");
        assert!(has("pce_addr: p:1  # FLOWPILOT_PCE_ADDR"), "{out}");
        // Plugger fallbacks and file values are labelled too.
        let path = dir.path().join("c.yaml");
        std::fs::write(&path, "aggregation_minutes: 7\nconsumers:\n  - name: n\n    connectors:\n      - type: udp\n    parser:\n      type: netflow\n").unwrap();
        let vars = [("FLOWPILOT_DATA_DIRECTORY", d), ("PCE_HOST", "h"), ("PCE_API_KEY", "x"), ("PCE_API_SECRET", "y")];
        let (code, out) = effective(path.to_str().unwrap(), &env_of(&vars), &[]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("aggregation_minutes: 7  # file"), "{out}");
        assert!(out.contains("pce_addr: h  # PCE_HOST (plugger)"), "{out}");
        assert!(out.contains("api_user: x  # PCE_API_KEY (plugger)"), "{out}");
        assert!(out.contains("api_secret: '********'  # PCE_API_KEY (plugger)"), "{out}");
    }

    #[test]
    fn print_config_redacts_proxy_userinfo() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let vars = [
            ("FLOWPILOT_PCE_ADDR", "p:1"),
            ("FLOWPILOT_API_KEY", "$cat k"),
            ("FLOWPILOT_DATA_DIRECTORY", d),
            ("FLOWPILOT_NETFLOW_PORTS", "2055"),
            ("FLOWPILOT_HTTPS_PROXY", "http://user:pass@proxy:3128"),
            ("FLOWPILOT_NO_PROXY", "localhost"),
        ];
        let (code, out) = effective("", &env_of(&vars), &[]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("https_proxy: http://***@proxy:3128  # FLOWPILOT_HTTPS_PROXY"), "{out}");
        assert!(out.contains("no_proxy: localhost  # FLOWPILOT_NO_PROXY"), "{out}");
        assert!(!out.contains("pass") && !out.contains("user:"), "{out}");
    }

    #[test]
    fn print_config_lists_unknown_variables() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let vars = [
            ("FLOWPILOT_PCE_ADDR", "p:1"),
            ("FLOWPILOT_API_KEY", "$cat k"),
            ("FLOWPILOT_DATA_DIRECTORY", d),
            ("FLOWPILOT_NETFLOW_PORTS", "2055"),
            ("FLOWPILOT_NETFLOW_PORT", "9995"),
        ];
        let names: Vec<String> = vars.iter().map(|(k, _)| k.to_string()).chain(["PATH".into()]).collect();
        let (code, out) = effective("", &env_of(&vars), &names);
        assert_eq!(code, 0, "{out}");
        assert!(out.starts_with("# Unknown variable ignored: FLOWPILOT_NETFLOW_PORT\npce_addr: "), "{out}");
        assert!(!out.contains("9995"), "{out}");
        // Still valid YAML.
        let doc: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(doc["pce_addr"].as_str(), Some("p:1"));
        // On an error too, before the error.
        let (code, out) = effective("", &env_of(&[]), &["FLOWPILOT_NETFLOW_PORT".into()]);
        assert_eq!(code, 1);
        assert_eq!(out, "# Unknown variable ignored: FLOWPILOT_NETFLOW_PORT\nNo config file provided\n");
    }

    #[test]
    fn print_config_invalid_exits_1() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let vars = [
            ("FLOWPILOT_PCE_ADDR", "p:1"),
            ("FLOWPILOT_API_KEY", "$cat k"),
            ("FLOWPILOT_DATA_DIRECTORY", d),
            ("FLOWPILOT_NETFLOW_PORTS", "2055"),
            ("FLOWPILOT_ORG_ID", "0"),
        ];
        let (code, out) = effective("", &env_of(&vars), &[]);
        assert_eq!(code, 1);
        assert!(out.contains("FLOWPILOT_ORG_ID (org_id): Must be greater than or equal to 1"), "{out}");
        assert_eq!(print_effective("", &env_of(&vars), &[]), 1);
        // Nothing configured at all.
        assert_eq!(effective("", &env_of(&[]), &[]), (1, "No config file provided\n".to_string()));
    }

    #[test]
    fn debug_print_has_no_secret() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let vars = [
            ("FLOWPILOT_PCE_ADDR", "p:1"),
            ("FLOWPILOT_API_USER", "u"),
            ("FLOWPILOT_API_SECRET", "topsecret"),
            ("FLOWPILOT_DATA_DIRECTORY", d),
            ("FLOWPILOT_NETFLOW_PORTS", "2055"),
        ];
        let l = load_from("", &env_of(&vars)).unwrap();
        let dump = debug_dump(&l.config).join("\n");
        assert!(!dump.contains("api_key") && !dump.contains("********"), "{dump}"); // omitempty: nothing of the credentials
        assert!(!dump.contains("topsecret"), "{dump}");
    }

    #[test]
    fn print_config_does_not_create_directory() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("fresh/sub");
        let d = d.to_str().unwrap();
        let vars = [("FLOWPILOT_PCE_ADDR", "p:1"), ("FLOWPILOT_API_KEY", "$cat k"),
            ("FLOWPILOT_NETFLOW_PORTS", "2055"), ("FLOWPILOT_DATA_DIRECTORY", d)];
        let (code, out) = effective("", &env_of(&vars), &[]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains(&format!("data_directory: {d}  # FLOWPILOT_DATA_DIRECTORY (will be created at start)")), "{out}");
        assert!(!std::path::Path::new(d).exists());
        // A start still creates it.
        load_from("", &env_of(&vars)).unwrap();
        assert!(std::path::Path::new(d).exists());
        // A missing directory from a file stays an error.
        let path = dir.path().join("c.yaml");
        let missing = dir.path().join("nope");
        std::fs::write(&path, format!("pce_addr: p:1\napi_key: $cat k\ndata_directory: {}\nconsumers:\n  - name: n\n    connectors:\n      - type: udp\n    parser:\n      type: netflow\n", missing.display())).unwrap();
        let (code, out) = effective(path.to_str().unwrap(), &env_of(&[]), &[]);
        assert_eq!(code, 1);
        assert!(out.contains("is not writable."), "{out}");
    }
}
