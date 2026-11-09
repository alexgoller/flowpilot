//! Spool senders (docs/operations.md, "Upload behaviour"): REST upload to the PCE, or one Kafka message per file in
//! PCE Kafka mode.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{CONNECTION, CONTENT_ENCODING, CONTENT_TYPE};

use crate::credentials::Credentials;
use crate::log::shutdown;
use crate::log_line;
use crate::spool::{SpoolFile, Spool, MAX_SENDERS};

/// PCE API version in the upload path.
pub const API_VERSION: u32 = 2;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_BACKOFF_SECS: u64 = 120;

/// One Kafka message per spool file (PCE Kafka mode). Ok = (partition, offset) after the broker's ack.
pub trait MessageSink: Send + Sync {
    fn send(&self, value: &[u8]) -> Result<(i32, i64), String>;
    /// Flush and close at shutdown; `KafkaProducer` overrides it, test fakes keep the no-op.
    fn close(&self, _within: std::time::Duration) {}
}

/// Connection settings for the PCE.
#[derive(Clone, Debug)]
pub struct PceTarget {
    pub pce_addr: String,
    pub org_id: i32,
    /// Shared with the other users of the PCE API; read again after a 401.
    pub credentials: Arc<Credentials>,
    pub verify_cert: bool,
}

impl PceTarget {
    /// The upload URL: `/traffic_data/flowlink`, or `/traffic_data` once `legacy` (after a 404).
    pub fn url(&self, legacy: bool) -> String {
        let suffix = if legacy { "" } else { "/flowlink" };
        format!("https://{}/api/v{API_VERSION}/orgs/{}/traffic_data{suffix}", self.pce_addr, self.org_id)
    }
}

/// Where the senders put each spool file.
pub enum Transport {
    /// REST upload to the PCE.
    Pce(PceTarget),
    /// PCE Kafka mode: one message per file, through the shared producer.
    Kafka(Arc<dyn MessageSink>),
}

pub struct Uploader {
    spool: Arc<Spool>,
    transport: Transport,
    /// Set after a 404 on `/flowlink`: all senders switch to `/traffic_data` for good, as in FlowLink.
    legacy_url: AtomicBool,
}

/// What happened to one file.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Done,
    Retry,
}

impl Uploader {
    pub fn new(spool: Arc<Spool>, target: PceTarget) -> Self {
        Self { spool, transport: Transport::Pce(target), legacy_url: AtomicBool::new(false) }
    }

    /// Senders for PCE Kafka mode; the stats report `transport: "kafka"` from here on.
    pub fn kafka(spool: Arc<Spool>, sink: Arc<dyn MessageSink>) -> Self {
        spool.stats().set_transport("kafka");
        Self { spool, transport: Transport::Kafka(sink), legacy_url: AtomicBool::new(false) }
    }

    /// Start the senders. The startup directory scan must already have run.
    pub fn start(self: &Arc<Self>) -> Vec<thread::JoinHandle<()>> {
        (0..MAX_SENDERS)
            .map(|_| {
                let up = self.clone();
                thread::spawn(move || up.sender_loop())
            })
            .collect()
    }

    /// The PCE settings; only the REST transport has them.
    fn target(&self) -> &PceTarget {
        match &self.transport {
            Transport::Pce(t) => t,
            Transport::Kafka(_) => unreachable!("no PCE target in Kafka mode"),
        }
    }

    /// One sender: take spool files and upload them, one at a time.
    fn sender_loop(&self) {
        // No HTTP client in Kafka mode.
        let client = match &self.transport {
            Transport::Pce(t) => match client(t) {
                Ok(c) => Some(c),
                Err(e) => {
                    log_line!("Error creating request:", e);
                    return;
                }
            },
            Transport::Kafka(_) => None,
        };
        while !shutdown() {
            let fd = self.spool.get();
            let path = self.spool.path(&fd);
            let data = match std::fs::read(&path) {
                Ok(d) => d,
                Err(e) => {
                    log_line!("Unable to read file:", path.display(), e);
                    self.spool.delete(&fd);
                    continue;
                }
            };
            if fd.size == 0 || data.is_empty() {
                log_line!("Ignoring zero length file:", path.display());
                self.spool.delete(&fd);
                continue;
            }
            self.spool.sending.fetch_add(1, Ordering::SeqCst);
            self.send_with_retry(client.as_ref(), &fd, &data);
            self.spool.sending.fetch_sub(1, Ordering::SeqCst);
            thread::sleep(Duration::from_secs(1)); // pacing toward the PCE, as in FlowLink
        }
    }

    /// Retry loop: backoff 10, 20, … 120 s; retention re-checked before each attempt. `client` is `None` in Kafka mode.
    fn send_with_retry(&self, client: Option<&Client>, fd: &SpoolFile, data: &[u8]) {
        let path = self.spool.path(fd);
        let kafka = matches!(self.transport, Transport::Kafka(_));
        let mut sleep_secs = 10;
        loop {
            if self.spool.expired(fd) {
                self.spool.stats().on_removed_by_retention();
                self.spool.delete(fd);
                return;
            }
            log_line!("Sending file:", path.display(), "kafkaSync:", kafka);
            if self.attempt(client, fd, data) == Outcome::Done {
                return;
            }
            log_line!("Sleeping", sleep_secs, "seconds before retrying send of files.");
            for _ in 0..sleep_secs {
                if shutdown() {
                    return;
                }
                thread::sleep(Duration::from_secs(1));
            }
            if sleep_secs < MAX_BACKOFF_SECS {
                sleep_secs += 10;
            }
        }
    }

    /// One attempt over the transport. In Kafka mode the file is deleted only after the broker's ack.
    fn attempt(&self, client: Option<&Client>, fd: &SpoolFile, data: &[u8]) -> Outcome {
        match &self.transport {
            Transport::Pce(_) => self.post(client.expect("the PCE transport has an HTTP client"), fd, data, |u| u),
            // As in FlowLink, every Kafka error retries until the file's retention ends.
            Transport::Kafka(sink) => match sink.send(data) {
                Ok((partition, offset)) => {
                    log_line!("Sent kafka message to partition:", partition, "offset:", offset);
                    self.spool.stats().on_success(fd.records);
                    self.spool.delete(fd);
                    Outcome::Done
                }
                Err(e) => {
                    // The sink's error texts are already redacted.
                    log_line!("Failed to send kafka message:", e);
                    self.spool.stats().on_failure("error", &e);
                    Outcome::Retry
                }
            },
        }
    }

    /// One POST, including the immediate re-POST after the `/flowlink` 404 fallback, and after a 401 that made the
    /// credentials change. `map_url` exists for tests (plain-HTTP server).
    fn post(&self, client: &Client, fd: &SpoolFile, data: &[u8], map_url: fn(String) -> String) -> Outcome {
        let mut reread = false;
        loop {
            let target = self.target();
            let url = target.url(self.legacy_url.load(Ordering::SeqCst));
            let (user, token) = target.credentials.current();
            let resp = client
                .post(map_url(url.clone()))
                .basic_auth(&user, Some(&token))
                .header(CONTENT_TYPE, "application/x-protobuf")
                .header(CONTENT_ENCODING, "gzip")
                .header(CONNECTION, "close")
                .body(data.to_vec())
                .send();
            let resp = match resp {
                Ok(r) => r,
                Err(e) => {
                    log_line!("Error sending request:", e);
                    // The logged text only (no source chain); the stats redact any URL userinfo.
                    self.spool.stats().on_failure("error", &e.to_string());
                    return Outcome::Retry;
                }
            };
            let status = resp.status().as_u16();
            log_line!("Response Code", status);
            // The status line only: the body is the PCE's, and the request (with its credentials) is never quoted.
            let failed = || self.spool.stats().on_failure(&status.to_string(), &format!("HTTP {}", resp.status()));
            match status {
                204 => {
                    self.spool.stats().on_success(fd.records);
                    self.spool.delete(fd);
                    return Outcome::Done;
                }
                404 if url.ends_with("/flowlink") => {
                    self.legacy_url.store(true, Ordering::SeqCst);
                }
                // Not accepted, yet deleted like a success (as FlowLink does).
                404 => {
                    failed();
                    self.spool.delete(fd);
                    return Outcome::Done;
                }
                // FlowPilot extension: the secret may have been rotated. Once per file, at once when it changed.
                401 => {
                    failed();
                    if let Ok(body) = resp.text() {
                        log_line!("Response body:", body);
                    }
                    if reread || !target.credentials.refresh(&token) {
                        return Outcome::Retry;
                    }
                    reread = true;
                }
                _ => {
                    failed();
                    if let Ok(body) = resp.text() {
                        log_line!("Response body:", body);
                    }
                    return Outcome::Retry;
                }
            }
        }
    }
}

/// HTTP/1.1 only, `Connection: close` per request, as in FlowLink; proxy from the environment.
fn client(target: &PceTarget) -> reqwest::Result<Client> {
    Client::builder()
        .http1_only()
        .timeout(REQUEST_TIMEOUT)
        .danger_accept_invalid_certs(!target.verify_cert)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;
    use crate::stats::UploadStats;

    #[test]
    fn url_format_and_fallback() {
        let target = PceTarget { pce_addr: "pce.example.com:8443".into(), org_id: 3, credentials: Credentials::fixed("u", "t"), verify_cert: true };
        assert_eq!(target.url(false), "https://pce.example.com:8443/api/v2/orgs/3/traffic_data/flowlink");
        assert_eq!(target.url(true), "https://pce.example.com:8443/api/v2/orgs/3/traffic_data");
    }

    /// Minimal HTTP/1.1 server answering each request with the next status; records request heads.
    fn serve(statuses: Vec<u16>) -> (String, std::sync::mpsc::Receiver<(String, Vec<u8>)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            for status in statuses {
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
                let mut body = vec![0; len];
                r.read_exact(&mut body).unwrap();
                tx.send((head, body)).unwrap();
                write!(s, "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            }
        });
        (addr, rx)
    }

    #[test]
    fn post_sends_headers_and_handles_404_fallback() {
        let (addr, rx) = serve(vec![404, 204]);
        let dir = tempfile::tempdir().unwrap();
        let spool = Arc::new(Spool::new(dir.path().to_path_buf(), 24, 500));
        spool.add(b"gzdata", 7, false);
        let fd = spool.get();
        let up = Uploader::new(spool.clone(), PceTarget { pce_addr: addr, org_id: 1, credentials: Credentials::fixed("api_1", "secret"), verify_cert: true });
        let client = Client::builder().http1_only().build().unwrap();
        let outcome = up.post(&client, &fd, b"gzdata", |u| u.replacen("https://", "http://", 1));
        assert_eq!(outcome, Outcome::Done);
        let (head1, body1) = rx.recv().unwrap();
        assert!(head1.starts_with("POST /api/v2/orgs/1/traffic_data/flowlink HTTP/1.1"));
        let lower = head1.to_ascii_lowercase();
        assert!(lower.contains("content-type: application/x-protobuf"));
        assert!(lower.contains("content-encoding: gzip"));
        assert!(lower.contains("connection: close"));
        assert!(lower.contains("authorization: basic yxbpxze6c2vjcmv0")); // base64("api_1:secret")
        assert_eq!(body1, b"gzdata");
        let (head2, _) = rx.recv().unwrap();
        assert!(head2.starts_with("POST /api/v2/orgs/1/traffic_data HTTP/1.1"));
        assert!(!spool.path(&fd).exists());
    }

    /// An uploader on a spool with one queued file of 7 records and its own counters.
    fn setup(addr: String) -> (Uploader, SpoolFile, &'static UploadStats, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let st: &'static UploadStats = Box::leak(Box::new(UploadStats::new()));
        let spool = Arc::new(Spool::new(dir.path().to_path_buf(), 24, 500).with_stats(st));
        spool.add(b"gzdata", 7, false);
        let fd = spool.get();
        let target = PceTarget { pce_addr: addr, org_id: 1, credentials: Credentials::fixed("api_1", "secret"), verify_cert: true };
        (Uploader::new(spool, target), fd, st, dir)
    }

    fn plain(u: String) -> String {
        u.replacen("https://", "http://", 1)
    }

    #[test]
    fn success_counts_upload_and_records() {
        let (addr, _rx) = serve(vec![204]);
        let (up, fd, st, _dir) = setup(addr);
        let client = Client::builder().http1_only().build().unwrap();
        assert_eq!(up.post(&client, &fd, b"gzdata", plain), Outcome::Done);
        let s = st.snapshot();
        assert_eq!((s.succeeded, s.records_uploaded, s.failed.len()), (1, 7, 0));
        assert!(s.last_success_at.is_some() && s.last_error.is_none());
        assert_eq!(up.spool.backlog(), (0, 0));
    }

    #[test]
    fn http_error_status_counts_failure_by_status() {
        let (addr, _rx) = serve(vec![500, 204]);
        let (up, fd, st, _dir) = setup(addr);
        let client = Client::builder().http1_only().build().unwrap();
        assert_eq!(up.post(&client, &fd, b"gzdata", plain), Outcome::Retry);
        let s = st.snapshot();
        assert_eq!((s.succeeded, s.failed.get("500").copied()), (0, Some(1)));
        let err = s.last_error.unwrap();
        assert!(err.contains("500"), "{err}");
        assert!(!err.contains("secret"), "{err}");
        assert!(s.last_error_at.is_some() && s.first_failure_since_success_at.is_some());
        // A later success clears the failure streak but keeps the last error.
        assert_eq!(up.post(&client, &fd, b"gzdata", plain), Outcome::Done);
        let s = st.snapshot();
        assert_eq!((s.succeeded, s.records_uploaded), (1, 7));
        assert!(s.first_failure_since_success_at.is_none() && s.last_error.is_some());
    }

    /// A key file holding `api_1 secret`, read again at every 401.
    fn rotating_key(dir: &tempfile::TempDir) -> (std::path::PathBuf, Arc<Credentials>) {
        use crate::credentials::Origin;
        let key = dir.path().join("api_info");
        std::fs::write(&key, "api_1 secret\n").unwrap();
        let origin = Origin::ApiKey(key.to_str().unwrap().into());
        (key, Credentials::load_with(origin, Duration::ZERO, Duration::from_secs(5)).unwrap())
    }

    #[test]
    fn unauthorized_rereads_credentials_and_retries_at_once() {
        let (addr, rx) = serve(vec![401, 204]);
        let (mut up, fd, st, dir) = setup(addr);
        let (key, creds) = rotating_key(&dir);
        if let Transport::Pce(t) = &mut up.transport {
            t.credentials = creds.clone();
        }
        std::fs::write(&key, "api_1 rotated\n").unwrap();
        let client = Client::builder().http1_only().build().unwrap();
        let logs = crate::log::capture(|| assert_eq!(up.post(&client, &fd, b"gzdata", plain), Outcome::Done));
        let (head1, _) = rx.recv().unwrap();
        let (head2, body2) = rx.recv().unwrap();
        assert!(head1.to_ascii_lowercase().contains("authorization: basic yxbpxze6c2vjcmv0")); // api_1:secret
        assert!(head2.to_ascii_lowercase().contains("authorization: basic yxbpxze6cm90yxrlza==")); // api_1:rotated
        assert!(head2.starts_with("POST /api/v2/orgs/1/traffic_data/flowlink HTTP/1.1"));
        assert_eq!(body2, b"gzdata");
        assert!(logs.contains(&"API credentials changed".to_string()), "{logs:?}");
        assert!(!format!("{logs:?}").contains("rotated"), "{logs:?}");
        let s = st.snapshot();
        assert_eq!((s.succeeded, s.failed.get("401").copied()), (1, Some(1)));
    }

    #[test]
    fn unauthorized_with_unchanged_credentials_backs_off() {
        let (addr, rx) = serve(vec![401, 401]);
        let (mut up, fd, st, dir) = setup(addr);
        let (_key, creds) = rotating_key(&dir);
        if let Transport::Pce(t) = &mut up.transport {
            t.credentials = creds;
        }
        let client = Client::builder().http1_only().build().unwrap();
        let logs = crate::log::capture(|| assert_eq!(up.post(&client, &fd, b"gzdata", plain), Outcome::Retry));
        assert!(logs.contains(&"API credentials unchanged".to_string()), "{logs:?}");
        rx.recv().unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err(), "retried without a change");
        assert_eq!(st.snapshot().failed.get("401").copied(), Some(1));
        // Fixed credentials: no re-read at all.
        let (up, fd, _st, _dir) = setup(String::new());
        let (addr, rx) = serve(vec![401]);
        let up = Uploader::new(up.spool.clone(), PceTarget { pce_addr: addr, org_id: 1, credentials: Credentials::fixed("u", "t"), verify_cert: true });
        let logs = crate::log::capture(|| assert_eq!(up.post(&client, &fd, b"gzdata", plain), Outcome::Retry));
        assert!(!logs.iter().any(|l| l.contains("API credentials")), "{logs:?}");
        rx.recv().unwrap();
    }

    #[test]
    fn rotated_twice_retries_only_once() {
        use crate::credentials::Origin;
        // Every read prints a new secret: the retry gets a 401 too, and the re-read changes them again; back off
        // all the same.
        let (addr, rx) = serve(vec![401, 401]);
        let (mut up, fd, st, dir) = setup(addr);
        let d = dir.path().display();
        let cmd = crate::credentials::tests::script(
            dir.path(),
            "key",
            &format!("n=$(cat {d}/n 2>/dev/null || echo 0); n=$((n+1)); echo $n > {d}/n; echo api_1 s$n"),
        );
        let creds = Credentials::load_with(Origin::ApiKey(format!("${cmd}")), Duration::ZERO, Duration::from_secs(5)).unwrap();
        if let Transport::Pce(t) = &mut up.transport {
            t.credentials = creds;
        }
        let client = Client::builder().http1_only().build().unwrap();
        assert_eq!(up.post(&client, &fd, b"gzdata", plain), Outcome::Retry);
        rx.recv().unwrap();
        rx.recv().unwrap();
        let s = st.snapshot();
        assert_eq!((s.failed.get("401").copied(), s.failed.get("error")), (Some(2), None));
    }

    #[test]
    fn connection_error_counts_as_error() {
        // A port that was free a moment ago: nothing listens there.
        let addr = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
        let (up, fd, st, _dir) = setup(addr);
        let client = Client::builder().http1_only().build().unwrap();
        assert_eq!(up.post(&client, &fd, b"gzdata", plain), Outcome::Retry);
        let s = st.snapshot();
        assert_eq!(s.failed.get("error").copied(), Some(1));
        let err = s.last_error.unwrap();
        assert!(!err.is_empty() && !err.contains("secret"), "{err}");
    }

    #[test]
    fn expired_file_is_counted_as_removed_by_retention() {
        let dir = tempfile::tempdir().unwrap();
        let st: &'static UploadStats = Box::leak(Box::new(UploadStats::new()));
        let spool = Arc::new(Spool::new(dir.path().to_path_buf(), 0, 500).with_stats(st)); // 0 h retention
        spool.add(b"gzdata", 7, false);
        let fd = spool.get();
        let target = PceTarget { pce_addr: "127.0.0.1:9".into(), org_id: 1, credentials: Credentials::fixed("u", "t"), verify_cert: true };
        let up = Uploader::new(spool, target);
        up.send_with_retry(Some(&Client::new()), &fd, b"gzdata");
        assert_eq!(st.snapshot().removed_by_retention, 1);
        assert_eq!(up.spool.backlog(), (0, 0));
    }

    /// A sink that records each value and answers every send with the same result.
    struct FakeSink(Mutex<Vec<Vec<u8>>>, Result<(i32, i64), String>);
    impl MessageSink for FakeSink {
        fn send(&self, v: &[u8]) -> Result<(i32, i64), String> {
            self.0.lock().unwrap().push(v.to_vec());
            self.1.clone()
        }
    }

    /// A Kafka uploader on a spool with one queued file of 7 records and its own counters.
    fn setup_kafka(result: Result<(i32, i64), String>) -> (Uploader, Arc<FakeSink>, SpoolFile, &'static UploadStats, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let st: &'static UploadStats = Box::leak(Box::new(UploadStats::new()));
        let spool = Arc::new(Spool::new(dir.path().to_path_buf(), 24, 500).with_stats(st));
        spool.add(b"gzdata", 7, false);
        let fd = spool.get();
        let sink = Arc::new(FakeSink(Mutex::new(Vec::new()), result));
        (Uploader::kafka(spool, sink.clone()), sink, fd, st, dir)
    }

    #[test]
    fn kafka_success_sends_file_bytes_and_deletes() {
        let (up, sink, fd, st, _dir) = setup_kafka(Ok((2, 41)));
        let logs = crate::log::capture(|| up.send_with_retry(None, &fd, b"gzdata"));
        assert_eq!(*sink.0.lock().unwrap(), vec![b"gzdata".to_vec()]);
        assert!(!up.spool.path(&fd).exists());
        assert_eq!(up.spool.backlog(), (0, 0));
        let s = st.snapshot();
        assert_eq!((s.succeeded, s.records_uploaded, s.failed.len()), (1, 7, 0));
        assert_eq!(s.transport, "kafka");
        let path = up.spool.path(&fd).display().to_string();
        assert_eq!(logs, vec![
            format!("Sending file: {path} kafkaSync: true"),
            "Sent kafka message to partition: 2 offset: 41".to_string(),
        ]);
    }

    #[test]
    fn failed_kafka_send_keeps_file() {
        let (up, sink, fd, st, _dir) = setup_kafka(Err("kafka: broker down".into()));
        let logs = crate::log::capture(|| assert_eq!(up.attempt(None, &fd, b"gzdata"), Outcome::Retry));
        assert_eq!(sink.0.lock().unwrap().len(), 1);
        assert!(up.spool.path(&fd).exists());
        let s = st.snapshot();
        assert_eq!((s.succeeded, s.failed.get("error").copied()), (0, Some(1)));
        assert_eq!(s.last_error.as_deref(), Some("kafka: broker down"));
        assert!(s.first_failure_since_success_at.is_some());
        assert_eq!(logs, vec!["Failed to send kafka message: kafka: broker down".to_string()]);
    }

    #[test]
    fn kafka_failure_counts_error_without_secret() {
        // The error text as `KafkaProducer` hands it out: through its one error-mapping path.
        let err = crate::kafka::producer::error_text("auth failed: s3cr3t", "s3cr3t");
        let (up, _sink, fd, st, _dir) = setup_kafka(Err(err));
        let logs = crate::log::capture(|| assert_eq!(up.attempt(None, &fd, b"gzdata"), Outcome::Retry));
        let s = st.snapshot();
        assert_eq!(s.last_error.as_deref(), Some("auth failed: ********"));
        assert_eq!(s.failed.get("error").copied(), Some(1));
        assert_eq!(logs, vec!["Failed to send kafka message: auth failed: ********".to_string()]);
        assert!(!format!("{s:?}{logs:?}").contains("s3cr3t"));
    }

    #[test]
    fn pce_uploader_reports_pce_transport() {
        let (addr, _rx) = serve(vec![204]);
        let (up, fd, st, _dir) = setup(addr);
        assert_eq!(st.snapshot().transport, "pce");
        let logs = crate::log::capture(|| assert_eq!(up.post(&Client::new(), &fd, b"gzdata", plain), Outcome::Done));
        assert_eq!(logs, vec!["Response Code 204".to_string()]);
        assert_eq!(st.snapshot().transport, "pce");
    }
}
