//! Integrations bootstrap: asks the gateway for the Kafka settings (servers, topic, SASL connection
//! string, batch size) that this PCE uses.

use std::fmt;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONNECTION};
use serde::de::{Deserializer, MapAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;

use crate::config::{Config, Secret};
use crate::kafka::gateway::{gateway_host, NO_GATEWAY};
use crate::{debug_log, log_line};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// The Kafka settings the gateway hands out.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IntegrationsConfig {
    pub bootstrap_servers: String,
    pub topic: String,
    pub connection_string: Secret,
    pub max_objects_per_message: i64,
}

/// The config request URL. As in FlowLink, the host is everything before the first `:` of `pce_addr`
/// (this breaks IPv6 literals) and nothing is URL-encoded.
pub fn integrations_url(gw: &str, pce_addr: &str, org_id: i32) -> String {
    let host = pce_addr.split(':').next().unwrap_or("");
    format!("https://{gw}/integrations/api/v1/config/flowlink-kafka?pceHost={host}&orgId={org_id}")
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn type_error(v: &Value, field: &str, ty: &str) -> String {
    format!("json: cannot unmarshal {} into field {field} of type {ty}", kind(v))
}

struct ConfigVisitor;

impl<'de> Visitor<'de> for ConfigVisitor {
    type Value = Result<IntegrationsConfig, String>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON object")
    }

    // Keys match ASCII case-insensitively and are applied in document order (last wins), `null`
    // leaves a field alone and unknown keys are skipped, as with Go's JSON decoder. A type
    // mismatch is remembered (the first one is reported) while the rest is still read.
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut c = IntegrationsConfig::default();
        let mut err: Option<String> = None;
        while let Some(key) = map.next_key::<String>()? {
            let v: Value = map.next_value()?;
            if v.is_null() {
                continue;
            }
            let mut set_str = |dst: &mut String, name: &str| match &v {
                Value::String(s) => *dst = s.clone(),
                _ => {
                    err.get_or_insert_with(|| type_error(&v, name, "string"));
                }
            };
            if key.eq_ignore_ascii_case("bootstrapServers") {
                set_str(&mut c.bootstrap_servers, "bootstrapServers");
            } else if key.eq_ignore_ascii_case("topic") {
                set_str(&mut c.topic, "topic");
            } else if key.eq_ignore_ascii_case("connectionString") {
                set_str(&mut c.connection_string.0, "connectionString");
            } else if key.eq_ignore_ascii_case("maxObjectsPerMessage") {
                match v.as_i64() {
                    Some(n) => c.max_objects_per_message = n,
                    None => {
                        let e = match &v {
                            Value::Number(_) => "json: number is not an integer in range for field maxObjectsPerMessage of type int".to_string(),
                            _ => type_error(&v, "maxObjectsPerMessage", "int"),
                        };
                        err.get_or_insert(e);
                    }
                }
            }
        }
        Ok(match err {
            Some(e) => Err(e),
            None => Ok(c),
        })
    }
}

struct Parsed(Result<IntegrationsConfig, String>);

impl<'de> Deserialize<'de> for Parsed {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(ConfigVisitor).map(Parsed)
    }
}

pub(crate) fn parse_integrations_json(text: &str) -> Result<IntegrationsConfig, String> {
    match serde_json::from_str::<Parsed>(text) {
        Ok(Parsed(r)) => r,
        Err(e) if e.is_syntax() || e.is_eof() => Err(format!("json: invalid input at line {} column {}", e.line(), e.column())),
        Err(_) => Err("json: cannot unmarshal a non-object value into the Integrations config".to_string()),
    }
}

/// Turns the response into the config, or the log lines of the failure.
pub(crate) fn resolve(
    status: u16,
    body: &str,
    kafka_info: &str,
    read_info: impl FnOnce(&str) -> String,
) -> Result<IntegrationsConfig, Vec<String>> {
    let cfg = match status {
        200 => parse_integrations_json(body)
            .map_err(|e| vec![format!("Unable to process Integrations Kafka config: {e}")])?,
        404 => {
            if kafka_info.is_empty() {
                return Err(vec!["No valid Integrations kafka config".to_string()]);
            }
            // As in FlowLink, a failure prints the 404 body, not the info.
            parse_integrations_json(&read_info(kafka_info))
                .map_err(|e| vec![format!("Unable to process Integrations kafka config: {body} \nerr: {e}")])?
        }
        _ => return Err(vec![format!("Invalid Integrations kafka config response: {body}")]),
    };
    if cfg.bootstrap_servers.is_empty() {
        return Err(vec!["No Integrations kafka Servers configured".to_string()]);
    }
    Ok(cfg)
}

/// One GET of the config. `map_url` exists for tests (plain-HTTP server).
fn fetch_with(url: &str, user: &str, token: &str, verify_cert: bool, map_url: fn(String) -> String) -> Result<(u16, String), Vec<String>> {
    let client = Client::builder()
        .http1_only()
        .timeout(REQUEST_TIMEOUT)
        .danger_accept_invalid_certs(!verify_cert)
        .build()
        .map_err(|e| vec![format!("Error creating Integrations API request: {e}")])?;
    let resp = client
        .get(map_url(url.to_string()))
        .basic_auth(user, Some(token))
        .header(ACCEPT, "application/json")
        .header(CONNECTION, "close")
        .send()
        .map_err(|e| vec![format!("Error sending Integrations kafka config request: {e}")])?;
    let status = resp.status().as_u16();
    log_line!("Response Code", status);
    let body = resp
        .text()
        .map_err(|e| vec![format!("Error reading Integrations kafka config reponse body: {e}")])?;
    Ok((status, body))
}

pub(crate) fn fetch(url: &str, user: &str, token: &str, verify_cert: bool) -> Result<(u16, String), Vec<String>> {
    fetch_with(url, user, token, verify_cert, |u| u)
}

fn exit_with(lines: Vec<String>) -> ! {
    for l in lines {
        log_line!(l);
    }
    std::process::exit(1)
}

/// Fetches the Kafka settings from the gateway. Logs and exits 1 on any failure.
pub fn bootstrap(cfg: &Config, user: &str, token: &str) -> IntegrationsConfig {
    log_line!("Getting integrations kafka config");
    let gw = gateway_host(&cfg.pce_kafka).unwrap_or_else(|_| exit_with(vec![NO_GATEWAY.to_string()]));
    let url = integrations_url(&gw, &cfg.pce_addr, cfg.org_id);
    debug_log!("url:", url);
    let (status, body) = fetch(&url, user, token, cfg.verify_pce_cert).unwrap_or_else(|l| exit_with(l));
    let ic = resolve(status, &body, &cfg.pce_kafka.kafka_info, crate::secrets::key_source).unwrap_or_else(|l| exit_with(l));
    // Divergence: FlowLink also dumps the response and the connection string here; we never do.
    debug_log!("config.Kafka:", format!("{{{} {} ******** {}}}", ic.bootstrap_servers, ic.topic, ic.max_objects_per_message));
    ic
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn url_strips_port_and_keeps_org() {
        assert_eq!(integrations_url("gw.example.test", "pce.example.com:8443", 7),
            "https://gw.example.test/integrations/api/v1/config/flowlink-kafka?pceHost=pce.example.com&orgId=7");
        assert!(integrations_url("g", "pce.example.com", 1).contains("pceHost=pce.example.com&"));
    }

    #[test]
    fn integrations_json_follows_go_rules() {
        let c = parse_integrations_json(r#"{"BootstrapServers":"a:9093","topic":"t","connectionstring":"cs","maxObjectsPerMessage":5000,"x":1}"#).unwrap();
        assert_eq!((c.bootstrap_servers.as_str(), c.topic.as_str(), c.connection_string.0.as_str(), c.max_objects_per_message), ("a:9093", "t", "cs", 5000));
        assert_eq!(parse_integrations_json(r#"{"topic":"a","TOPIC":"b"}"#).unwrap().topic, "b");
        assert_eq!(parse_integrations_json(r#"{"topic":"a","topic":null}"#).unwrap().topic, "a");
        assert_eq!(parse_integrations_json(r#"{"topic":null}"#).unwrap().topic, "");
        assert_eq!(parse_integrations_json(r#"{}"#).unwrap().max_objects_per_message, 0);
        assert_eq!(parse_integrations_json(r#"{"maxObjectsPerMessage":-3}"#).unwrap().max_objects_per_message, -3);
        for bad in [r#"{"maxObjectsPerMessage":"500"}"#, r#"{"maxObjectsPerMessage":5.5}"#,
            r#"{"maxObjectsPerMessage":18446744073709551615}"#, r#"[]"#, r#"{"topic":1}"#, "{"] {
            assert!(parse_integrations_json(bad).is_err(), "{bad}");
        }
        let e = parse_integrations_json(r#"{"connectionString":"s3cr3t","topic":7}"#).unwrap_err();
        assert_eq!(e, "json: cannot unmarshal number into field topic of type string");
        let e = parse_integrations_json(r#"{"connectionString":"s3cr3t","maxObjectsPerMessage":"x"}"#).unwrap_err();
        assert_eq!(e, "json: cannot unmarshal string into field maxObjectsPerMessage of type int");
        assert!(!parse_integrations_json(r#"{"connectionString":"s3cr3t""#).unwrap_err().contains("s3cr3t"));
    }

    #[test]
    fn resolve_statuses() {
        let ok = r#"{"bootstrapServers":"a:9093","topic":"t","connectionString":"Endpoint=sb://x/;SharedAccessKey=s3cr3t","maxObjectsPerMessage":10}"#;
        assert_eq!(resolve(200, ok, "", |_| unreachable!()).unwrap().topic, "t");
        assert_eq!(resolve(404, "nf", "info", |p| { assert_eq!(p, "info"); ok.to_string() }).unwrap().max_objects_per_message, 10);
        assert_eq!(resolve(404, "nf", "", |_| unreachable!()).unwrap_err(), ["No valid Integrations kafka config"]);
        assert_eq!(resolve(500, "boom", "", |_| unreachable!()).unwrap_err(), ["Invalid Integrations kafka config response: boom"]);
        assert_eq!(resolve(200, r#"{"bootstrapServers":""}"#, "", |_| unreachable!()).unwrap_err(), ["No Integrations kafka Servers configured"]);
        let bad = resolve(200, r#"{"connectionString":"s3cr3t","maxObjectsPerMessage":"x"}"#, "", |_| unreachable!()).unwrap_err();
        assert!(bad[0].starts_with("Unable to process Integrations Kafka config: ") && !bad[0].contains("s3cr3t"));
        let bad404 = resolve(404, "nf", "info", |_| "{".into()).unwrap_err();
        assert_eq!(bad404[0].split(" \nerr: ").next(), Some("Unable to process Integrations kafka config: nf"));
        assert!(!bad404[0].contains("info"));
    }

    #[test]
    fn debug_of_config_masks_secret() {
        let c = parse_integrations_json(r#"{"connectionString":"s3cr3t"}"#).unwrap();
        assert!(!format!("{c:?}").contains("s3cr3t"));
    }

    /// One-shot plain-HTTP server answering with `status` and `body`; sends the request head.
    fn serve(status: u16, body: &'static str) -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut head = String::new();
            loop {
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                head += &line;
            }
            tx.send(head).unwrap();
            write!(s, "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        });
        (addr, rx)
    }

    #[test]
    fn fetch_sends_basic_auth_and_accept() {
        let (addr, rx) = serve(200, r#"{"topic":"t"}"#);
        let url = format!("https://{addr}/integrations/api/v1/config/flowlink-kafka?pceHost=p&orgId=1");
        let (status, body) = fetch_with(&url, "api_1", "secret", true, |u| u.replacen("https://", "http://", 1)).unwrap();
        assert_eq!((status, body.as_str()), (200, r#"{"topic":"t"}"#));
        let head = rx.recv().unwrap().to_ascii_lowercase();
        assert!(head.starts_with("get /integrations/api/v1/config/flowlink-kafka?pceHost=p&orgId=1 http/1.1".to_ascii_lowercase().as_str()), "{head}");
        assert!(head.contains("accept: application/json\r\n"), "{head}");
        assert!(head.contains("authorization: basic yxbpxze6c2vjcmv0\r\n"), "{head}");
        assert!(head.contains("connection: close\r\n"), "{head}");
    }
}
