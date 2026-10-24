//! PCE upload senders (docs/operations.md, "Upload behaviour"). Kafka output is deferred.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{CONNECTION, CONTENT_ENCODING, CONTENT_TYPE};

use crate::log::shutdown;
use crate::log_line;
use crate::spool::{SpoolFile, Spool, MAX_SENDERS};

/// PCE API version in the upload path.
pub const API_VERSION: u32 = 2;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_BACKOFF_SECS: u64 = 120;

/// Connection settings for the PCE.
#[derive(Clone, Debug)]
pub struct PceTarget {
    pub pce_addr: String,
    pub org_id: i32,
    pub api_user: String,
    pub api_token: String,
    pub verify_cert: bool,
}

pub struct Uploader {
    spool: Arc<Spool>,
    target: PceTarget,
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
        Self { spool, target, legacy_url: AtomicBool::new(false) }
    }

    /// The upload URL.
    pub fn url(&self) -> String {
        let suffix = if self.legacy_url.load(Ordering::SeqCst) { "" } else { "/flowlink" };
        format!("https://{}/api/v{API_VERSION}/orgs/{}/traffic_data{suffix}", self.target.pce_addr, self.target.org_id)
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

    /// HTTP/1.1 only, `Connection: close` per request, as in FlowLink; proxy from the environment.
    fn client(&self) -> reqwest::Result<Client> {
        Client::builder()
            .http1_only()
            .timeout(REQUEST_TIMEOUT)
            .danger_accept_invalid_certs(!self.target.verify_cert)
            .build()
    }

    /// One sender: take spool files and upload them, one at a time.
    fn sender_loop(&self) {
        let client = match self.client() {
            Ok(c) => c,
            Err(e) => {
                log_line!("Error creating request:", e);
                return;
            }
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
            self.send_with_retry(&client, &fd, &data);
            self.spool.sending.fetch_sub(1, Ordering::SeqCst);
            thread::sleep(Duration::from_secs(1)); // pacing toward the PCE, as in FlowLink
        }
    }

    /// Retry loop: backoff 10, 20, … 120 s; retention re-checked before each attempt.
    fn send_with_retry(&self, client: &Client, fd: &SpoolFile, data: &[u8]) {
        let path = self.spool.path(fd);
        let mut sleep_secs = 10;
        loop {
            if self.spool.expired(fd) {
                self.spool.stats().on_removed_by_retention();
                self.spool.delete(fd);
                return;
            }
            log_line!("Sending file:", path.display(), "kafkaSync:", false);
            if self.post(client, fd, data, |u| u) == Outcome::Done {
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

    /// One POST, including the immediate re-POST after the `/flowlink` 404 fallback.
    /// `map_url` exists for tests (plain-HTTP server).
    fn post(&self, client: &Client, fd: &SpoolFile, data: &[u8], map_url: fn(String) -> String) -> Outcome {
        loop {
            let url = self.url();
            let resp = client
                .post(map_url(url.clone()))
                .basic_auth(&self.target.api_user, Some(&self.target.api_token))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use crate::stats::UploadStats;

    #[test]
    fn url_format_and_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let up = Uploader::new(
            Arc::new(Spool::new(dir.path().to_path_buf(), 24, 500)),
            PceTarget { pce_addr: "pce.example.com:8443".into(), org_id: 3, api_user: "u".into(), api_token: "t".into(), verify_cert: true },
        );
        assert_eq!(up.url(), "https://pce.example.com:8443/api/v2/orgs/3/traffic_data/flowlink");
        up.legacy_url.store(true, Ordering::SeqCst);
        assert_eq!(up.url(), "https://pce.example.com:8443/api/v2/orgs/3/traffic_data");
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
        let up = Uploader::new(spool.clone(), PceTarget { pce_addr: addr, org_id: 1, api_user: "api_1".into(), api_token: "secret".into(), verify_cert: true });
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
        let target = PceTarget { pce_addr: addr, org_id: 1, api_user: "api_1".into(), api_token: "secret".into(), verify_cert: true };
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
        let target = PceTarget { pce_addr: "127.0.0.1:9".into(), org_id: 1, api_user: "u".into(), api_token: "t".into(), verify_cert: true };
        let up = Uploader::new(spool, target);
        up.send_with_retry(&Client::new(), &fd, b"gzdata");
        assert_eq!(st.snapshot().removed_by_retention, 1);
        assert_eq!(up.spool.backlog(), (0, 0));
    }
}
