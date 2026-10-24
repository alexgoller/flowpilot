//! Upload counters (docs/stats.md, `uploads`). One process-wide `UploadStats` (`uploads()`), updated by the senders and the spool; uploads are rare, so
//! one mutex holds everything. Files and bytes waiting come from `Spool::backlog`.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};
use std::time::SystemTime;

use serde::Serialize;

use super::rfc3339;

static UPLOADS: UploadStats = UploadStats::new();

/// The process-wide upload counters.
pub fn uploads() -> &'static UploadStats {
    &UPLOADS
}

/// Upload totals since start.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct UploadSnapshot {
    pub succeeded: u64,
    /// By HTTP status (`"500"`) or `"error"` (no response).
    pub failed: BTreeMap<String, u64>,
    pub records_uploaded: u64,
    #[serde(serialize_with = "rfc3339::opt")]
    pub last_success_at: Option<SystemTime>,
    /// Status line or transport error text; never request headers, so never the credentials.
    pub last_error: Option<String>,
    #[serde(serialize_with = "rfc3339::opt")]
    pub last_error_at: Option<SystemTime>,
    /// The first failure after the last success (`None` once an upload succeeds again).
    #[serde(serialize_with = "rfc3339::opt")]
    pub first_failure_since_success_at: Option<SystemTime>,
    /// Files deleted unsent to honour `data_directory_size_mb`.
    #[serde(rename = "removed_by_size_cap")]
    pub removed_by_cap: u64,
    /// Files deleted unsent because they outlived `file_retention_hours`.
    pub removed_by_retention: u64,
}

pub struct UploadStats(Mutex<UploadSnapshot>);

impl UploadStats {
    pub const fn new() -> Self {
        Self(Mutex::new(UploadSnapshot {
            succeeded: 0,
            failed: BTreeMap::new(),
            records_uploaded: 0,
            last_success_at: None,
            last_error: None,
            last_error_at: None,
            first_failure_since_success_at: None,
            removed_by_cap: 0,
            removed_by_retention: 0,
        }))
    }

    fn lock(&self) -> MutexGuard<'_, UploadSnapshot> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A file the PCE accepted.
    pub fn on_success(&self, records: u64) {
        let mut s = self.lock();
        s.succeeded += 1;
        s.records_uploaded += records;
        s.last_success_at = Some(SystemTime::now());
        s.first_failure_since_success_at = None;
    }

    /// A failed attempt; `kind` is the HTTP status as text or `"error"`. URL userinfo in `message` is redacted.
    pub fn on_failure(&self, kind: &str, message: &str) {
        let now = SystemTime::now();
        let mut s = self.lock();
        *s.failed.entry(kind.to_string()).or_default() += 1;
        s.last_error = Some(redact_userinfo(message));
        s.last_error_at = Some(now);
        s.first_failure_since_success_at.get_or_insert(now);
    }

    pub fn on_removed_by_cap(&self) {
        self.lock().removed_by_cap += 1;
    }

    pub fn on_removed_by_retention(&self) {
        self.lock().removed_by_retention += 1;
    }

    pub fn snapshot(&self) -> UploadSnapshot {
        self.lock().clone()
    }
}

/// Replaces the userinfo of every URL in `text` (`scheme://user:pass@host` or `scheme://user@host`) with `***`, so a
/// credentialed proxy URL in an error text never reaches the stats.
pub fn redact_userinfo(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(head);
        // Only what ends an authority by the URL grammar: a ')' (or other punctuation) may be part of the password.
        let end = tail.find(|c: char| matches!(c, '/' | '?' | '#') || c.is_whitespace()).unwrap_or(tail.len());
        let authority = &tail[..end];
        match authority.rfind('@') {
            Some(at) => {
                out.push_str("***");
                out.push_str(&authority[at..]);
            }
            None => out.push_str(authority),
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// `redact_userinfo` for one proxy setting, which may also be written without a scheme (`user:pass@host:3128`).
pub fn redact_proxy_url(url: &str) -> String {
    match url.rfind('@') {
        Some(at) if !url.contains("://") => format!("***{}", &url[at..]),
        _ => redact_userinfo(url),
    }
}

impl Default for UploadStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_url_userinfo_is_redacted_with_or_without_scheme() {
        assert_eq!(redact_proxy_url("http://u:p@proxy:3128"), "http://***@proxy:3128");
        assert_eq!(redact_proxy_url("u:p@proxy:3128"), "***@proxy:3128");
        assert_eq!(redact_proxy_url("proxy:3128"), "proxy:3128");
    }

    #[test]
    fn last_error_redacts_userinfo() {
        let st = UploadStats::new();
        st.on_failure("error", "error sending request for url (https://u:p@proxy:3128/): proxy at http://admin@p2 failed");
        let err = st.snapshot().last_error.unwrap();
        assert_eq!(err, "error sending request for url (https://***@proxy:3128/): proxy at http://***@p2 failed");
        assert!(!err.contains("u:p") && !err.contains("admin"));
        // Text without userinfo is kept as is.
        let plain = "error sending request for url (https://pce.example.com:8443/api/v2/orgs/1/traffic_data)";
        assert_eq!(redact_userinfo(plain), plain);
        assert_eq!(redact_userinfo("HTTP 500 Internal Server Error"), "HTTP 500 Internal Server Error");
        // An '@' in the path is not userinfo.
        assert_eq!(redact_userinfo("http://h/a@b"), "http://h/a@b");
        // A ')' in the password does not end the authority.
        let r = redact_userinfo("proxy https://u:pa)ss@h:3128 failed");
        assert_eq!(r, "proxy https://***@h:3128 failed");
        assert!(!r.contains("ss@") && !r.contains("pa)"));
        // A URL closed by ')' without a path keeps the ')'.
        assert_eq!(redact_userinfo("(url https://u:p@h:3128)"), "(url https://***@h:3128)");
    }
}
