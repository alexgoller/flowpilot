//! PCE REST client for unmanaged workload creation (docs/unmanaged-workloads.md, "PCE access"): labels, async exports, the per-IP
//! pre-create check and `bulk_create`. Blocking, one request at a time; every failure is returned, never logged here.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use reqwest::blocking::{Client, RequestBuilder, Response};
use serde_json::{json, Value};

use crate::uploader::{PceTarget, API_VERSION};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Async export: poll the job every 2 s for up to 10 min.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const POLL_LIMIT: Duration = Duration::from_secs(600);
const TOKEN_LABEL_EXISTS: &str = "label_key_and_value_must_be_unique";
const MSG_WORKLOAD_EXISTS: &str = "external_reference_not_unique";
/// Prefix of the `Other` error for a `bulk_create` reply whose item count differs from the request.
const RESULT_MISMATCH: &str = "bulk_create result count mismatch";

#[derive(Clone, Debug, PartialEq)]
pub struct Label {
    pub href: String,
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NewWorkload {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub label_hrefs: Vec<String>,
    pub external_data_set: String,
}

impl NewWorkload {
    /// The `bulk_create` item: name and external reference are the IP; hostname only when DNS resolved.
    pub fn to_json(&self) -> Value {
        let ip = self.ip.to_string();
        let mut w = json!({
            "name": ip,
            "interfaces": [{"name": "umw0", "address": ip}],
            "labels": self.label_hrefs.iter().map(|h| json!({"href": h})).collect::<Vec<_>>(),
            "external_data_set": self.external_data_set,
            "external_data_reference": ip,
        });
        if let Some(h) = &self.hostname {
            w["hostname"] = json!(h);
        }
        w
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum CreateResult {
    Created,
    AlreadyExists,
    Failed(String),
}

#[derive(Debug, PartialEq)]
pub enum PceError {
    /// 401 / 403.
    Auth(u16),
    /// The documented duplicate-label token.
    Exists,
    /// 429, 5xx and timeout errors: retry at the next window.
    Transient(String),
    /// The request never got an answer: name resolution, TCP connect or TLS certificate failure.
    /// Retried like `Transient`; the installer's PCE check tells the cases apart.
    Unreachable(NetFailure, String),
    Other(String),
}

impl PceError {
    /// The request may have been applied on the PCE although it reported failure (timeout, dropped
    /// connection, 5xx, or a reply that doesn't match the request).
    pub fn is_ambiguous(&self) -> bool {
        match self {
            PceError::Transient(_) | PceError::Unreachable(..) => true,
            PceError::Other(s) => s.starts_with(RESULT_MISMATCH),
            PceError::Auth(_) | PceError::Exists => false,
        }
    }
}

/// Why a request got no answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetFailure {
    Resolve,
    Connect,
    Certificate,
}

/// Classifies a failed send from the error's source chain; `None` for anything else (timeouts, ...).
fn net_failure(e: &reqwest::Error) -> Option<(NetFailure, String)> {
    let mut text = e.to_string();
    let mut src = std::error::Error::source(e);
    while let Some(s) = src {
        text += &format!(": {s}");
        src = s.source();
    }
    let low = text.to_ascii_lowercase();
    let kind = if low.contains("certificate") || low.contains("unknownissuer") || low.contains("invalid peer") {
        NetFailure::Certificate
    } else if low.contains("dns error") || low.contains("failed to lookup") || low.contains("name or service not known") {
        NetFailure::Resolve
    } else if e.is_connect() {
        NetFailure::Connect
    } else {
        return None;
    };
    Some((kind, text))
}

pub trait PceApi: Send + 'static {
    fn label_dimensions(&self) -> Result<BTreeSet<String>, PceError>;
    /// All labels, via async export.
    fn labels(&self) -> Result<Vec<Label>, PceError>;
    /// Exact key and value match (the PCE filter is a substring match).
    fn find_label(&self, key: &str, value: &str) -> Result<Option<Label>, PceError>;
    /// `Exists` on a duplicate.
    fn create_label(&self, key: &str, value: &str) -> Result<Label, PceError>;
    /// Addresses of all interfaces of all workloads, via async export.
    fn workload_ips(&self) -> Result<BTreeSet<IpAddr>, PceError>;
    /// `GET /workloads?ip_address=<ip>`, then an exact compare on the interface addresses.
    fn has_workload(&self, ip: IpAddr) -> Result<bool, PceError>;
    /// Same order as the input; at most 1000 items.
    fn bulk_create(&self, batch: &[NewWorkload]) -> Result<Vec<CreateResult>, PceError>;
}

pub struct HttpPce {
    client: Client,
    /// `https://<pce>/api/v2`; async `Location` / `result.href` paths hang off it.
    api_root: String,
    /// `<api_root>/orgs/<org>`.
    base: String,
    user: String,
    token: String,
    poll_interval: Duration,
}

impl HttpPce {
    /// Built like `Uploader::client()`: http1 only, 60 s timeout; proxies come from the environment.
    pub fn new(target: &PceTarget) -> reqwest::Result<Self> {
        Ok(Self::with_client(target, Self::builder(target).build()?))
    }

    /// `new`, but through exactly `proxy` (`None`: direct), whatever the environment says. The installer's check
    /// uses it to reach the PCE the way the installed service will.
    pub fn with_proxy(target: &PceTarget, proxy: Option<reqwest::Proxy>) -> reqwest::Result<Self> {
        let b = Self::builder(target);
        let b = match proxy {
            Some(p) => b.proxy(p),
            None => b.no_proxy(),
        };
        Ok(Self::with_client(target, b.build()?))
    }

    fn builder(target: &PceTarget) -> reqwest::blocking::ClientBuilder {
        Client::builder().http1_only().timeout(REQUEST_TIMEOUT).danger_accept_invalid_certs(!target.verify_cert)
    }

    fn with_client(target: &PceTarget, client: Client) -> Self {
        let api_root = format!("https://{}/api/v{API_VERSION}", target.pce_addr);
        Self {
            client,
            base: format!("{api_root}/orgs/{}", target.org_id),
            api_root,
            user: target.api_user.clone(),
            token: target.api_token.clone(),
            poll_interval: POLL_INTERVAL,
        }
    }

    /// Test hook: plain http, for an in-process mock.
    #[cfg(test)]
    pub(crate) fn plain_http(mut self) -> Self {
        self.api_root = self.api_root.replacen("https://", "http://", 1);
        self.base = self.base.replacen("https://", "http://", 1);
        self
    }

    fn get(&self, url: &str) -> RequestBuilder {
        self.client.get(url).basic_auth(&self.user, Some(&self.token))
    }

    /// Send and map the status; returns the body of a 2xx response.
    fn send(&self, req: RequestBuilder) -> Result<(u16, Response), PceError> {
        let resp = req.send().map_err(|e| match net_failure(&e) {
            Some((kind, text)) => PceError::Unreachable(kind, text),
            None => PceError::Transient(e.to_string()),
        })?;
        let status = resp.status().as_u16();
        if resp.status().is_success() {
            return Ok((status, resp));
        }
        Err(match status {
            401 | 403 => PceError::Auth(status),
            429 | 500..=599 => PceError::Transient(format!("HTTP {status}")),
            _ => {
                let body = resp.text().unwrap_or_default();
                if body.contains(TOKEN_LABEL_EXISTS) {
                    PceError::Exists
                } else {
                    PceError::Other(format!("HTTP {status}: {}", body.chars().take(300).collect::<String>()))
                }
            }
        })
    }

    fn json(&self, req: RequestBuilder) -> Result<Value, PceError> {
        let (_, resp) = self.send(req)?;
        let text = resp.text().map_err(|e| PceError::Transient(e.to_string()))?;
        serde_json::from_str(&text).map_err(|e| PceError::Other(format!("invalid JSON: {e}")))
    }

    /// `GET <path>` with `Prefer: respond-async`: follow the job until it is done, then fetch the datafile.
    fn export(&self, path: &str) -> Result<Vec<Value>, PceError> {
        let (status, resp) = self.send(self.get(&format!("{}/{path}", self.base)).header("Prefer", "respond-async"))?;
        if status != 202 {
            // The PCE answered synchronously.
            let text = resp.text().map_err(|e| PceError::Transient(e.to_string()))?;
            return array(serde_json::from_str(&text).map_err(|e| PceError::Other(format!("invalid JSON: {e}")))?);
        }
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| PceError::Other("async export: no Location header".into()))?
            .to_string();
        let job_url = format!("{}{location}", self.api_root);
        let deadline = Instant::now() + POLL_LIMIT;
        loop {
            let job = self.json(self.get(&job_url))?;
            match job["status"].as_str() {
                Some("done") => {
                    let href = job["result"]["href"]
                        .as_str()
                        .ok_or_else(|| PceError::Other("async export: job without result href".into()))?;
                    return array(self.json(self.get(&format!("{}{href}", self.api_root)))?);
                }
                Some("failed") => return Err(PceError::Other("async export job failed".into())),
                _ => {}
            }
            if Instant::now() >= deadline {
                return Err(PceError::Transient("async export timed out".into()));
            }
            std::thread::sleep(self.poll_interval);
        }
    }
}

fn array(v: Value) -> Result<Vec<Value>, PceError> {
    match v {
        Value::Array(a) => Ok(a),
        _ => Err(PceError::Other("expected a JSON array".into())),
    }
}

fn label_from(v: &Value) -> Option<Label> {
    Some(Label { href: v["href"].as_str()?.into(), key: v["key"].as_str()?.into(), value: v["value"].as_str()?.into() })
}

fn interface_ips(workload: &Value) -> impl Iterator<Item = IpAddr> + '_ {
    workload["interfaces"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|i| i["address"].as_str()?.parse().ok())
}

impl PceApi for HttpPce {
    fn label_dimensions(&self) -> Result<BTreeSet<String>, PceError> {
        let items = array(self.json(self.get(&format!("{}/label_dimensions", self.base)))?)?;
        Ok(items.iter().filter(|d| d["deleted"] != json!(true)).filter_map(|d| d["key"].as_str().map(String::from)).collect())
    }

    fn labels(&self) -> Result<Vec<Label>, PceError> {
        Ok(self.export("labels")?.iter().filter_map(label_from).collect())
    }

    fn find_label(&self, key: &str, value: &str) -> Result<Option<Label>, PceError> {
        let items = array(self.json(self.get(&format!("{}/labels", self.base)).query(&[("key", key), ("value", value)]))?)?;
        Ok(items.iter().filter_map(label_from).find(|l| l.key == key && l.value == value))
    }

    fn create_label(&self, key: &str, value: &str) -> Result<Label, PceError> {
        let req = self
            .client
            .post(format!("{}/labels", self.base))
            .basic_auth(&self.user, Some(&self.token))
            .header("Content-Type", "application/json")
            .body(json!({"key": key, "value": value}).to_string());
        label_from(&self.json(req)?).ok_or_else(|| PceError::Other("label response without href/key/value".into()))
    }

    fn workload_ips(&self) -> Result<BTreeSet<IpAddr>, PceError> {
        Ok(self.export("workloads")?.iter().flat_map(interface_ips).collect())
    }

    fn has_workload(&self, ip: IpAddr) -> Result<bool, PceError> {
        let ip_s = ip.to_string();
        let items = array(self.json(self.get(&format!("{}/workloads", self.base)).query(&[("ip_address", ip_s.as_str())]))?)?;
        // The filter can match partially: compare exactly.
        Ok(items.iter().any(|w| interface_ips(w).any(|a| a == ip)))
    }

    fn bulk_create(&self, batch: &[NewWorkload]) -> Result<Vec<CreateResult>, PceError> {
        let body = Value::Array(batch.iter().map(NewWorkload::to_json).collect()).to_string();
        let req = self
            .client
            .put(format!("{}/workloads/bulk_create", self.base))
            .basic_auth(&self.user, Some(&self.token))
            .header("Content-Type", "application/json")
            .body(body);
        let items = array(self.json(req)?)?;
        if items.len() != batch.len() {
            return Err(PceError::Other(format!("{RESULT_MISMATCH}: {} results for {} items", items.len(), batch.len())));
        }
        Ok(items
            .iter()
            .map(|r| match r["status"].as_str() {
                Some("created") => CreateResult::Created,
                _ if r["message"] == json!(MSG_WORKLOAD_EXISTS) => CreateResult::AlreadyExists,
                s => CreateResult::Failed(r["message"].as_str().or(s).unwrap_or("unknown").to_string()),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc::Receiver;
    use std::thread;

    /// One canned reply: status, extra headers, body.
    type Reply = (u16, Vec<(&'static str, &'static str)>, String);

    fn reply(status: u16, body: &str) -> Reply {
        (status, vec![], body.to_string())
    }

    /// Minimal HTTP/1.1 server answering each request with the next reply; records request heads and bodies.
    fn serve(replies: Vec<Reply>) -> (String, Receiver<(String, String)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            for (status, headers, body) in replies {
                let (mut s, _) = listener.accept().unwrap();
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut head = String::new();
                let mut len = 0;
                loop {
                    let mut line = String::new();
                    r.read_line(&mut line).unwrap();
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                    if line == "\r\n" {
                        break;
                    }
                    head += &line;
                }
                let mut req_body = vec![0; len];
                r.read_exact(&mut req_body).unwrap();
                tx.send((head, String::from_utf8(req_body).unwrap())).unwrap();
                let extra: String = headers.iter().map(|(k, v)| format!("{k}: {v}\r\n")).collect();
                write!(s, "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        (addr, rx)
    }

    /// Test hook: plain http against the mock, 10 ms export polling.
    fn client_for(addr: &str) -> HttpPce {
        let target = PceTarget { pce_addr: addr.into(), org_id: 1, api_user: "api_1".into(), api_token: "secret".into(), verify_cert: true };
        let mut pce = HttpPce::new(&target).unwrap();
        pce.api_root = pce.api_root.replacen("https://", "http://", 1);
        pce.base = pce.base.replacen("https://", "http://", 1);
        pce.poll_interval = Duration::from_millis(10);
        pce
    }

    fn nw(ip: &str, hostname: Option<&str>) -> NewWorkload {
        NewWorkload { ip: ip.parse().unwrap(), hostname: hostname.map(String::from), label_hrefs: vec!["/orgs/1/labels/5".into()], external_data_set: "flowpilot".into() }
    }

    #[test]
    fn new_workload_json_exact() {
        assert_eq!(
            nw("10.1.2.3", Some("h1")).to_json(),
            json!({"name":"10.1.2.3","hostname":"h1","interfaces":[{"name":"umw0","address":"10.1.2.3"}],
                   "labels":[{"href":"/orgs/1/labels/5"}],"external_data_set":"flowpilot","external_data_reference":"10.1.2.3"})
        );
        assert!(nw("10.1.2.3", None).to_json().get("hostname").is_none());
    }

    #[test]
    fn bulk_create_sends_put_and_maps_items() {
        let resp = r#"[{"external_data_set":"flowpilot","external_data_reference":"10.0.0.1","status":"created","href":"/orgs/1/workloads/a"},
            {"external_data_set":"flowpilot","external_data_reference":"10.0.0.2","status":"validation_failure","message":"external_reference_not_unique"},
            {"external_data_set":"flowpilot","external_data_reference":"10.0.0.3","status":"validation_failure","message":"bad interface"}]"#;
        let (addr, rx) = serve(vec![reply(200, resp)]);
        let pce = client_for(&addr);
        let batch = [nw("10.0.0.1", None), nw("10.0.0.2", None), nw("10.0.0.3", Some("h"))];
        let out = pce.bulk_create(&batch).unwrap();
        assert_eq!(out, vec![CreateResult::Created, CreateResult::AlreadyExists, CreateResult::Failed("bad interface".into())]);
        let (head, body) = rx.recv().unwrap();
        assert!(head.starts_with("PUT /api/v2/orgs/1/workloads/bulk_create HTTP/1.1"));
        assert!(head.to_ascii_lowercase().contains("authorization: basic yxbpxze6c2vjcmv0")); // base64("api_1:secret")
        let sent: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(sent.as_array().unwrap().len(), 3);
        assert_eq!(sent[2]["hostname"], "h");
    }

    #[test]
    fn bulk_create_count_mismatch_is_ambiguous() {
        let (addr, _rx) = serve(vec![reply(200, "[]")]);
        let err = client_for(&addr).bulk_create(&[nw("10.0.0.1", None)]).unwrap_err();
        assert!(err.is_ambiguous(), "{err:?}");
        assert!(PceError::Transient("timeout".into()).is_ambiguous());
        assert!(!PceError::Other("bad request".into()).is_ambiguous());
        assert!(!PceError::Auth(403).is_ambiguous());
    }

    #[test]
    fn async_export_follows_job() {
        let job = |status: &str| format!(r#"{{"href":"/orgs/1/jobs/j1","status":"{status}","result":{{"href":"/orgs/1/datafiles/d1"}}}}"#);
        let data = r#"[{"interfaces":[{"address":"10.0.0.1"},{"address":"10.0.0.2"}]},{"interfaces":[{"address":"192.168.1.5"}]},{"interfaces":[]}]"#;
        let (addr, rx) = serve(vec![
            (202, vec![("Location", "/orgs/1/jobs/j1"), ("Retry-After", "5")], String::new()),
            reply(200, &job("pending")),
            reply(200, &job("done")),
            reply(200, data),
        ]);
        let ips = client_for(&addr).workload_ips().unwrap();
        let expect: BTreeSet<IpAddr> = ["10.0.0.1", "10.0.0.2", "192.168.1.5"].iter().map(|s| s.parse().unwrap()).collect();
        assert_eq!(ips, expect);
        let heads: Vec<String> = (0..4).map(|_| rx.recv().unwrap().0).collect();
        assert!(heads[0].starts_with("GET /api/v2/orgs/1/workloads HTTP/1.1"));
        assert!(heads[0].to_ascii_lowercase().contains("prefer: respond-async"));
        assert!(heads[1].starts_with("GET /api/v2/orgs/1/jobs/j1 HTTP/1.1"));
        assert!(heads[3].starts_with("GET /api/v2/orgs/1/datafiles/d1 HTTP/1.1"));
    }

    #[test]
    fn status_mapping() {
        let (addr, _rx) = serve(vec![reply(403, ""), reply(503, ""), reply(429, ""), reply(406, r#"[{"token":"other"}]"#)]);
        let pce = client_for(&addr);
        assert_eq!(pce.label_dimensions(), Err(PceError::Auth(403)));
        assert!(matches!(pce.label_dimensions(), Err(PceError::Transient(_))));
        assert!(matches!(pce.label_dimensions(), Err(PceError::Transient(_))));
        assert!(matches!(pce.label_dimensions(), Err(PceError::Other(_))));
        // Connection refused: bind, note the port, close.
        let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
        assert!(matches!(client_for(&dead).label_dimensions(), Err(PceError::Unreachable(NetFailure::Connect, _))));
    }

    #[test]
    fn create_label_duplicate_is_exists() {
        let dup = r#"[{"token":"label_key_and_value_must_be_unique","message":"Label key and value must be unique"}]"#;
        let created = r#"{"href":"/orgs/1/labels/9","key":"app","value":"x"}"#;
        let (addr, rx) = serve(vec![reply(406, dup), reply(201, created)]);
        let pce = client_for(&addr);
        assert_eq!(pce.create_label("role", "Web"), Err(PceError::Exists));
        assert_eq!(pce.create_label("app", "x"), Ok(Label { href: "/orgs/1/labels/9".into(), key: "app".into(), value: "x".into() }));
        let (head, body) = rx.recv().unwrap();
        assert!(head.starts_with("POST /api/v2/orgs/1/labels HTTP/1.1"));
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), json!({"key":"role","value":"Web"}));
    }

    #[test]
    fn find_label_compares_exactly() {
        let body = r#"[{"href":"/l/1","key":"role","value":"Webserver"},{"href":"/l/2","key":"role","value":"Web"},{"href":"/l/3","key":"app","value":"Web"}]"#;
        let (addr, rx) = serve(vec![reply(200, body), reply(200, body)]);
        let pce = client_for(&addr);
        assert_eq!(pce.find_label("role", "Web").unwrap().unwrap().href, "/l/2");
        assert_eq!(pce.find_label("role", "web").unwrap(), None);
        assert!(rx.recv().unwrap().0.starts_with("GET /api/v2/orgs/1/labels?key=role&value=Web HTTP/1.1"));
    }

    #[test]
    fn has_workload_exact_compare() {
        let partial = r#"[{"interfaces":[{"address":"10.0.0.15"}]}]"#;
        let exact = r#"[{"interfaces":[{"address":"10.0.0.1"}]}]"#;
        let (addr, rx) = serve(vec![reply(200, partial), reply(200, exact), reply(200, "[]")]);
        let pce = client_for(&addr);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(pce.has_workload(ip), Ok(false));
        assert_eq!(pce.has_workload(ip), Ok(true));
        assert_eq!(pce.has_workload(ip), Ok(false));
        let head = rx.recv().unwrap().0;
        assert!(head.starts_with("GET /api/v2/orgs/1/workloads?ip_address=10.0.0.1 HTTP/1.1"));
        assert!(!head.contains("include_deleted"));
    }
}
