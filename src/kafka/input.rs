//! Kafka input connector (`connectors: - type: kafka`): its properties and TLS material.
//!
//! Only parsing and validation live here; nothing connects.

use std::fmt;

use crate::config::Properties;
use crate::kafka::producer::split_brokers;
use crate::kafka::tls;

/// Client id when `client_id` is not set.
pub const DEFAULT_CLIENT_ID: &str = "Illumio-flowlink";

/// A sarama-style Kafka version: `[major, minor, very minor, patch]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KafkaVersion(pub [u32; 4]);

/// FlowLink's version grammar: at least 5 characters, then `0.a.b.c` when it starts with `0`, else
/// `a.b.c` (ASCII digits only). Any well-formed version is accepted, known to Kafka or not.
pub fn parse_version(s: &str) -> Result<KafkaVersion, String> {
    let err = || format!("invalid version `{s}`");
    if s.len() < 5 {
        return Err(err());
    }
    let parts: Vec<&str> = s.split('.').collect();
    let (want, rest) = if s.starts_with('0') { (4, &parts[1..]) } else { (3, &parts[..]) };
    if parts.len() != want || (want == 4 && parts[0] != "0") {
        return Err(err());
    }
    let mut v = [0u32; 4];
    let offset = want - 3;
    for (i, p) in rest.iter().enumerate() {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return Err(err());
        }
        // Divergence: a number that does not fit is an invalid version; FlowLink's scan leaves it
        // unset.
        v[offset + i] = p.parse().map_err(|_| err())?;
    }
    Ok(KafkaVersion(v))
}

/// PEM text cut at each `-----BEGIN`, as FlowLink does: each element runs from one marker to just
/// before the next, text before the first marker is dropped, order is kept.
pub fn split_pem_blocks(s: &str) -> Vec<String> {
    const MARKER: &str = "-----BEGIN";
    let starts: Vec<usize> = s.match_indices(MARKER).map(|(i, _)| i).collect();
    starts.iter().enumerate().map(|(n, &i)| s[i..*starts.get(n + 1).unwrap_or(&s.len())].to_string()).collect()
}

/// TLS material for the broker connections, as PEM. The brokers are verified against
/// `roots_pem` (the system roots, see `tls::system_roots_pem`) with a hostname check, as in
/// FlowLink.
#[derive(Clone, PartialEq)]
pub struct TlsPem {
    /// The client certificate; `None` when `broker_certs` and `broker_keys` hold no PEM block.
    pub client: Option<ClientPem>,
    pub roots_pem: String,
}

/// The client certificate offered to the brokers: one certificate block and its key block.
#[derive(Clone, PartialEq)]
pub struct ClientPem {
    pub cert_pem: String,
    pub key_pem: String,
}

// PEM never goes into Debug output (the key is a secret; the rest is noise).
impl fmt::Debug for TlsPem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsPem").field("client", &self.client).finish_non_exhaustive()
    }
}

impl fmt::Debug for ClientPem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientPem").finish_non_exhaustive()
    }
}

/// One Kafka connector entry's settings.
#[derive(Debug, Clone, PartialEq)]
pub struct InputSettings {
    /// `brokers` as configured; the source of `device_addr` and of log lines.
    pub brokers_raw: String,
    /// `split_brokers(brokers_raw)`.
    pub brokers: Vec<String>,
    /// The first comma-separated entry of `brokers_raw`, untrimmed, as in FlowLink.
    pub device_addr: String,
    pub group: String,
    /// `topics` split on `,`, trimmed, empty entries dropped.
    pub topics: Vec<String>,
    pub instances: usize,
    /// One client id per instance.
    pub client_ids: Vec<String>,
    pub version: KafkaVersion,
    /// `None`: plaintext.
    pub tls_pem: Option<TlsPem>,
}

/// Why a connector entry does not run.
#[derive(Debug, Clone, PartialEq)]
pub enum InputError {
    /// Log these lines; this connector does not start.
    Invalid(Vec<String>),
    /// Log these lines and exit 1.
    Exit(Vec<String>),
}

/// Parse one Kafka connector entry. `read` resolves a file property (a file path or `$command`).
/// An invalid `version` is logged here through `log::check_error` (so `-debug` exits); every other
/// line is left to the caller.
pub fn parse_settings(props: &Properties, read: &dyn Fn(&str) -> String) -> Result<InputSettings, InputError> {
    let missing: Vec<String> = ["brokers", "version", "group", "topics"]
        .iter()
        .filter(|p| !props.contains_key(**p))
        .map(|p| format!("Missing kafka property: {p}"))
        .collect();
    let get = |k: &str| props.get(k).cloned().unwrap_or_default();
    let version = parse_version(&get("version"));
    // As in FlowLink, a bad version does not start the connector.
    let bad_version = crate::log::check_error(version.as_ref().err());
    if !missing.is_empty() || bad_version {
        return Err(InputError::Invalid(missing));
    }
    let version = version.expect("checked above");

    let brokers_raw = get("brokers");
    let device_addr = brokers_raw.split(',').next().unwrap_or_default().to_string();
    let instances = instances(props.get("instances").map(String::as_str), brokers_raw.split(',').count())?;
    let tls_pem = tls_pem(props, read).map_err(InputError::Exit)?;
    let client_id = props.get("client_id").map_or(DEFAULT_CLIENT_ID, String::as_str);
    let client_ids =
        if instances > 1 { (0..instances).map(|i| format!("{client_id}-{i}")).collect() } else { vec![client_id.to_string()] };

    Ok(InputSettings {
        brokers: split_brokers(&brokers_raw),
        brokers_raw,
        device_addr,
        group: get("group"),
        topics: split_brokers(&get("topics")),
        instances,
        client_ids,
        version,
        tls_pem,
    })
}

/// `instances`: absent, non-numeric or 0 → one per broker entry (empty entries counted).
fn instances(value: Option<&str>, broker_entries: usize) -> Result<usize, InputError> {
    let n = match value.map(str::parse::<i64>) {
        None => 0,
        Some(Ok(n)) => n,
        Some(Err(_)) => {
            crate::log_line!("Invalid kafka instances value, must be numeric. Using default instances.");
            0
        }
    };
    match n {
        0 => Ok(broker_entries),
        // Divergence: FlowLink panics on a negative count.
        n if n < 0 => Err(InputError::Invalid(vec![format!("Invalid kafka instances value: {n}")])),
        n => usize::try_from(n).map_err(|_| InputError::Invalid(vec![format!("Invalid kafka instances value: {n}")])),
    }
}

/// TLS iff `broker_certs` is set. Errors are the lines to log before exiting 1.
fn tls_pem(props: &Properties, read: &dyn Fn(&str) -> String) -> Result<Option<TlsPem>, Vec<String>> {
    let Some(certs) = props.get("broker_certs") else { return Ok(None) };
    let Some(keys) = props.get("broker_keys") else {
        return Err(vec!["Missing script for broker certificate keys.".into()]);
    };
    // Divergence: FlowLink logs these blocks, private keys included, with -debug; FlowPilot never does.
    let certs = split_pem_blocks(&read(certs));
    let keys = split_pem_blocks(&read(keys));
    if certs.len() != keys.len() {
        return Err(vec!["Number of broker certs doesn't match number of broker keys.".into()]);
    }
    // Divergence: FlowLink falls back to plaintext when a pair does not load; FlowPilot exits.
    for (cert, key) in certs.iter().zip(&keys) {
        tls::client_auth_config(cert, key).map_err(|e| vec![format!("Error: {e}")])?;
    }
    // Divergence: one client certificate is offered, the first pair; the others are only checked.
    // No pair at all (FlowLink's accidental case): TLS with system roots and no client certificate.
    let client = certs.into_iter().zip(keys).next().map(|(cert_pem, key_pem)| ClientPem { cert_pem, key_pem });
    Ok(Some(TlsPem { client, roots_pem: tls::system_roots_pem() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &str = include_str!("../../tests/fixtures/kafka/client.pem");
    const KEY: &str = include_str!("../../tests/fixtures/kafka/client.key");
    const OTHER_CERT: &str = include_str!("../../tests/fixtures/kafka/other.pem");
    const OTHER_KEY: &str = include_str!("../../tests/fixtures/kafka/other.key");

    fn props(kv: &[(&str, &str)]) -> Properties {
        kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn base(extra: &[(&str, &str)]) -> Properties {
        let mut p = props(&[("brokers", "k1:9092,k2:9092"), ("version", "2.8.1"), ("group", "g"), ("topics", "t")]);
        p.extend(props(extra));
        p
    }

    fn no_read(_: &str) -> String {
        unreachable!("no file property expected")
    }

    /// Reads `certs` / `keys` sources by name.
    fn files<'a>(certs: &'a str, keys: &'a str) -> impl Fn(&str) -> String + 'a {
        move |src| match src {
            "certs" => certs.to_string(),
            "keys" => keys.to_string(),
            other => panic!("unexpected source {other}"),
        }
    }

    fn tls_props() -> Properties {
        base(&[("broker_certs", "certs"), ("broker_keys", "keys")])
    }

    fn exit_lines(r: Result<InputSettings, InputError>) -> Vec<String> {
        match r {
            Err(InputError::Exit(lines)) => lines,
            other => panic!("expected Exit, got {other:?}"),
        }
    }

    #[test]
    fn version_grammar() {
        for ok in ["2.8.1", "3.2.0", "0.10.2.0", "9.9.9"] {
            assert!(parse_version(ok).is_ok(), "{ok}");
        }
        for bad in ["2.8", "v2.8.1", "2.8.1.0", "", "0.10.2", "2.8.1\n", "2.8.x", "1.2.99999999999"] {
            assert_eq!(parse_version(bad).unwrap_err(), format!("invalid version `{bad}`"));
        }
        assert_eq!(parse_version("2.8.1").unwrap(), KafkaVersion([2, 8, 1, 0]));
        assert_eq!(parse_version("0.10.2.0").unwrap(), KafkaVersion([0, 10, 2, 0]));
        assert_eq!(parse_version("0.11.0.2").unwrap(), KafkaVersion([0, 11, 0, 2]));
    }

    #[test]
    fn defaults_instances_and_client_ids() {
        let s = parse_settings(&base(&[]), &no_read).ok().unwrap();
        assert_eq!((s.instances, s.client_ids.clone()), (2, vec!["Illumio-flowlink-0".to_string(), "Illumio-flowlink-1".into()]));
        assert_eq!((s.group.as_str(), s.version, s.tls_pem), ("g", KafkaVersion([2, 8, 1, 0]), None));

        let s = parse_settings(&base(&[("instances", "1"), ("client_id", "c")]), &no_read).ok().unwrap();
        assert_eq!((s.instances, s.client_ids), (1, vec!["c".to_string()]));
        let s = parse_settings(&base(&[("instances", "3"), ("client_id", "c")]), &no_read).ok().unwrap();
        assert_eq!(s.client_ids, ["c-0", "c-1", "c-2"]);
        assert_eq!(parse_settings(&base(&[("instances", "0")]), &no_read).ok().unwrap().instances, 2);

        let mut lines = Vec::new();
        let captured = crate::log::capture(|| lines.push(parse_settings(&base(&[("instances", "x")]), &no_read).ok().unwrap().instances));
        assert_eq!(lines, [2]);
        assert_eq!(captured, ["Invalid kafka instances value, must be numeric. Using default instances."]);

        assert_eq!(
            parse_settings(&base(&[("instances", "-1")]), &no_read).unwrap_err(),
            InputError::Invalid(vec!["Invalid kafka instances value: -1".into()])
        );
    }

    #[test]
    fn brokers_trimmed_device_addr_raw() {
        let p = props(&[("brokers", " k1:9092, k2:9092,"), ("version", "2.8.1"), ("group", "g"), ("topics", "a, b")]);
        let s = parse_settings(&p, &no_read).ok().unwrap();
        assert_eq!(s.brokers, ["k1:9092", "k2:9092"]);
        assert_eq!(s.brokers_raw, " k1:9092, k2:9092,");
        assert_eq!(s.device_addr, " k1:9092");
        assert_eq!(s.instances, 3);
        assert_eq!(s.topics, ["a", "b"]);
        let p = props(&[("brokers", "a:9092,"), ("version", "2.8.1"), ("group", "g"), ("topics", ",x,,")]);
        let s = parse_settings(&p, &no_read).ok().unwrap();
        assert_eq!((s.instances, s.topics), (2, vec!["x".to_string()]));
    }

    #[test]
    fn missing_properties_reported_in_order() {
        let mut r = None;
        let logged = crate::log::capture(|| r = Some(parse_settings(&Properties::new(), &no_read)));
        assert_eq!(logged, ["Error: invalid version ``"]);
        assert_eq!(
            r.unwrap().unwrap_err(),
            InputError::Invalid(vec![
                "Missing kafka property: brokers".into(),
                "Missing kafka property: version".into(),
                "Missing kafka property: group".into(),
                "Missing kafka property: topics".into(),
            ])
        );
        let r = parse_settings(&props(&[("brokers", "b"), ("version", "2.8.1")]), &no_read).unwrap_err();
        assert_eq!(r, InputError::Invalid(vec!["Missing kafka property: group".into(), "Missing kafka property: topics".into()]));
    }

    #[test]
    fn invalid_version_logs_and_does_not_start() {
        let mut r = None;
        let logged = crate::log::capture(|| r = Some(parse_settings(&base(&[("version", "2.8")]), &no_read)));
        assert_eq!(logged, ["Error: invalid version `2.8`"]);
        assert_eq!(r.unwrap().unwrap_err(), InputError::Invalid(vec![]));
    }

    #[test]
    fn tls_material_rules() {
        let only_certs = base(&[("broker_certs", "certs")]);
        assert_eq!(exit_lines(parse_settings(&only_certs, &no_read)), ["Missing script for broker certificate keys."]);

        let two = format!("{CERT}{OTHER_CERT}");
        assert_eq!(
            exit_lines(parse_settings(&tls_props(), &files(&two, KEY))),
            ["Number of broker certs doesn't match number of broker keys."]
        );

        let garbage = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let lines = exit_lines(parse_settings(&tls_props(), &files(garbage, KEY)));
        assert!(lines.len() == 1 && lines[0].starts_with("Error: "), "{lines:?}");
        // A key that does not belong to its certificate.
        let lines = exit_lines(parse_settings(&tls_props(), &files(CERT, OTHER_KEY)));
        assert!(lines.len() == 1 && lines[0].starts_with("Error: "), "{lines:?}");
        // The second pair is checked too, although only the first is offered.
        let lines = exit_lines(parse_settings(&tls_props(), &files(&two, &format!("{KEY}{KEY}"))));
        assert!(lines.len() == 1 && lines[0].starts_with("Error: "), "{lines:?}");

        let s = parse_settings(&tls_props(), &files(CERT, KEY)).ok().unwrap();
        let tls = s.tls_pem.unwrap();
        let client = tls.client.unwrap();
        assert_eq!((client.cert_pem.as_str(), client.key_pem.as_str()), (CERT, KEY));
        // The system roots (their order may vary between loads).
        let sorted = |pem: &str| {
            let mut b = split_pem_blocks(pem);
            b.sort();
            b
        };
        assert_eq!(sorted(&tls.roots_pem), sorted(&crate::kafka::tls::system_roots_pem()));

        let s = parse_settings(&tls_props(), &files(&two, &format!("{KEY}{OTHER_KEY}"))).ok().unwrap();
        assert_eq!(s.tls_pem.unwrap().client.unwrap().cert_pem, CERT);

        let s = parse_settings(&tls_props(), &files("", "")).ok().unwrap();
        assert_eq!(s.tls_pem.unwrap().client, None);
    }

    #[test]
    fn key_material_never_in_debug_or_logs() {
        let mut r = None;
        let logged = crate::log::capture(|| r = Some(parse_settings(&tls_props(), &files(CERT, KEY))));
        let s = r.unwrap().ok().unwrap();
        let key_body = KEY.lines().nth(1).unwrap();
        assert!(!format!("{s:?}").contains(key_body));
        assert!(format!("{s:?}").contains("TlsPem"));
        assert!(logged.iter().all(|l| !l.contains(key_body)), "{logged:?}");
    }

    #[test]
    fn pem_blocks_split_like_flowlink() {
        assert_eq!(
            split_pem_blocks("junk-----BEGIN A-----\nx\n-----BEGIN B-----\ny\n"),
            ["-----BEGIN A-----\nx\n", "-----BEGIN B-----\ny\n"]
        );
        assert!(split_pem_blocks("").is_empty());
        assert!(split_pem_blocks("no marker here").is_empty());
        assert_eq!(split_pem_blocks(&format!("{CERT}{OTHER_CERT}")), [CERT, OTHER_CERT]);
    }
}
