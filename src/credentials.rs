//! The PCE API credentials, shared by the senders and the unmanaged-workload worker (docs/configuration.md,
//! "api_user and api_secret_command"). Read once at start-up; read again when the PCE answers 401, so a rotated
//! secret is picked up without a restart.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::log_line;
use crate::secrets::{self, Failure, COMMAND_TIMEOUT};

/// At most one re-read per this interval.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Where the credentials come from.
#[derive(Clone, PartialEq)]
pub enum Origin {
    /// Given directly (`FLOWPILOT_API_USER`/`_SECRET`, plugger's variables, an `unmanaged_workloads.api_key`
    /// override): never read again.
    Fixed { user: String, token: String },
    /// `api_key`: a file or a `$command`.
    ApiKey(String),
    /// `api_user` with `api_secret_command`.
    SecretCommand { user: String, command: String },
}

pub struct Credentials {
    origin: Origin,
    /// User and token.
    current: Mutex<(String, String)>,
    /// When the credentials were last read; held for a whole re-read, so concurrent callers wait for it.
    last_read: Mutex<Instant>,
    min_interval: Duration,
    timeout: Duration,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials(********)")
    }
}

impl Credentials {
    /// Credentials that never change.
    pub fn fixed(user: impl Into<String>, token: impl Into<String>) -> Arc<Self> {
        let (user, token) = (user.into(), token.into());
        let current = Mutex::new((user.clone(), token.clone()));
        Arc::new(Self {
            origin: Origin::Fixed { user, token },
            current,
            last_read: Mutex::new(Instant::now()),
            min_interval: REFRESH_INTERVAL,
            timeout: COMMAND_TIMEOUT,
        })
    }

    /// The start-up read.
    pub(crate) fn load(origin: Origin) -> Result<Arc<Self>, Failure> {
        Self::load_with(origin, REFRESH_INTERVAL, COMMAND_TIMEOUT)
    }

    /// `load` with the re-read interval and the command limit injectable (tests).
    pub(crate) fn load_with(origin: Origin, min_interval: Duration, timeout: Duration) -> Result<Arc<Self>, Failure> {
        // As in FlowLink, an `api_key` `$command` has no limit at start-up.
        let current = read(&origin, matches!(origin, Origin::SecretCommand { .. }).then_some(timeout))?;
        Ok(Arc::new(Self {
            origin,
            current: Mutex::new(current),
            last_read: Mutex::new(Instant::now()),
            min_interval,
            timeout,
        }))
    }

    /// User and token.
    pub fn current(&self) -> (String, String) {
        self.current.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// After a 401 for a request sent with `seen_token`: reads the credentials again. True when they differ from what
    /// that request used (another caller may already have replaced them). Never more than one read per interval;
    /// a failed read is logged and the old credentials stay. Fixed credentials: a no-op.
    pub fn refresh(&self, seen_token: &str) -> bool {
        if matches!(self.origin, Origin::Fixed { .. }) {
            return false;
        }
        let mut last = self.last_read.lock().unwrap_or_else(PoisonError::into_inner);
        if self.current().1 != seen_token {
            return true;
        }
        if last.elapsed() < self.min_interval {
            return false;
        }
        log_line!("PCE answered 401, reading the API credentials again");
        let result = read(&self.origin, Some(self.timeout));
        *last = Instant::now();
        match result {
            Ok(new) => {
                let mut cur = self.current.lock().unwrap_or_else(PoisonError::into_inner);
                let changed = *cur != new;
                *cur = new;
                log_line!(if changed { "API credentials changed" } else { "API credentials unchanged" });
                changed
            }
            Err(f) => {
                f.report();
                false
            }
        }
    }
}

/// One read of `origin`; commands are killed after `timeout` when one is given.
fn read(origin: &Origin, timeout: Option<Duration>) -> Result<(String, String), Failure> {
    match origin {
        Origin::Fixed { user, token } => Ok((user.clone(), token.clone())),
        Origin::ApiKey(key) => secrets::credentials_within(key, timeout),
        Origin::SecretCommand { user, command } => {
            Ok((user.clone(), secrets::secret_command(command, timeout.unwrap_or(COMMAND_TIMEOUT))?))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// An executable script in `dir`; returns its path.
    pub(crate) fn script(dir: &std::path::Path, name: &str, body: &str) -> String {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.to_str().unwrap().to_string()
    }

    /// A script printing the content of `<dir>/secret` and counting its runs in `<dir>/runs`.
    pub(crate) fn secret_script(dir: &std::path::Path) -> String {
        std::fs::write(dir.join("secret"), "s1\n").unwrap();
        let d = dir.display();
        script(dir, "get-secret", &format!("echo run >> {d}/runs\ncat {d}/secret"))
    }

    fn runs(dir: &std::path::Path) -> usize {
        std::fs::read_to_string(dir.join("runs")).unwrap_or_default().lines().count()
    }

    fn command(dir: &std::path::Path) -> Origin {
        Origin::SecretCommand { user: "api_1".into(), command: secret_script(dir) }
    }

    #[test]
    fn secret_command_runs_once_at_start_up() {
        let dir = tempfile::tempdir().unwrap();
        let c = Credentials::load(command(dir.path())).unwrap();
        assert_eq!(c.current(), ("api_1".into(), "s1".into()));
        assert_eq!(runs(dir.path()), 1);
    }

    #[test]
    fn secret_command_gets_arguments_and_path_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secret");
        std::fs::write(&p, "  tok \n").unwrap();
        let o = Origin::SecretCommand { user: "u".into(), command: format!("cat   {}", p.display()) };
        assert_eq!(Credentials::load(o).unwrap().current(), ("u".into(), "tok".into()));
    }

    #[test]
    fn secret_command_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let slow = script(dir.path(), "slow", "sleep 5\necho late");
        let o = Origin::SecretCommand { user: "u".into(), command: slow.clone() };
        let t = Instant::now();
        let err = Credentials::load_with(o, REFRESH_INTERVAL, Duration::from_millis(200)).unwrap_err();
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        assert_eq!(err, Failure::Timeout { program: slow.clone(), after: Duration::from_millis(200) });
        let logs = crate::log::capture(|| err.report());
        assert_eq!(logs, vec![format!("Command timed out after 0.2 seconds: {slow}")]);
        let logs = crate::log::capture(|| {
            Failure::Timeout { program: "vault".into(), after: COMMAND_TIMEOUT }.report()
        });
        assert_eq!(logs, vec!["Command timed out after 30 seconds: vault".to_string()]);
    }

    #[test]
    fn secret_command_output_must_be_one_word() {
        let dir = tempfile::tempdir().unwrap();
        for (name, body) in [("empty", "true"), ("blank", "echo '   '"), ("two", "echo 'a b'"), ("lines", "printf 'a\\nb\\n'")] {
            let o = Origin::SecretCommand { user: "u".into(), command: script(dir.path(), name, body) };
            assert_eq!(
                Credentials::load(o).unwrap_err(),
                Failure::Message("API secret command printed no usable secret"),
                "{name}"
            );
        }
    }

    #[test]
    fn secret_command_failure_reports_stderr_not_stdout() {
        let dir = tempfile::tempdir().unwrap();
        let bad = script(dir.path(), "bad", "echo leaked-stdout\necho denied >&2\nexit 2");
        let o = Origin::SecretCommand { user: "u".into(), command: bad };
        let err = Credentials::load(o).unwrap_err();
        assert_eq!(err, Failure::Command("denied\n".into()));
        let logs = crate::log::capture(|| err.report());
        assert!(!format!("{logs:?}").contains("leaked-stdout"), "{logs:?}");
    }

    #[test]
    fn refresh_unchanged_and_changed() {
        let dir = tempfile::tempdir().unwrap();
        let c = Credentials::load_with(command(dir.path()), Duration::ZERO, COMMAND_TIMEOUT).unwrap();
        let logs = crate::log::capture(|| assert!(!c.refresh("s1")));
        assert_eq!(logs, ["PCE answered 401, reading the API credentials again", "API credentials unchanged"]);
        std::fs::write(dir.path().join("secret"), "s2\n").unwrap();
        let logs = crate::log::capture(|| assert!(c.refresh("s1")));
        assert_eq!(logs, ["PCE answered 401, reading the API credentials again", "API credentials changed"]);
        assert_eq!(c.current(), ("api_1".into(), "s2".into()));
        assert!(!format!("{logs:?}").contains("s2"));
        assert_eq!(runs(dir.path()), 3);
        // A caller that still holds the old token: already replaced, nothing runs.
        assert!(c.refresh("s1"));
        assert_eq!(runs(dir.path()), 3);
    }

    #[test]
    fn refresh_is_rate_limited() {
        let dir = tempfile::tempdir().unwrap();
        let c = Credentials::load_with(command(dir.path()), Duration::from_millis(300), COMMAND_TIMEOUT).unwrap();
        // Within the interval of the start-up read: nothing runs.
        let logs = crate::log::capture(|| assert!(!c.refresh("s1")));
        assert!(logs.is_empty(), "{logs:?}");
        assert_eq!(runs(dir.path()), 1);
        std::thread::sleep(Duration::from_millis(350));
        assert!(!c.refresh("s1"));
        assert!(!c.refresh("s1"));
        assert_eq!(runs(dir.path()), 2);
        assert_eq!(REFRESH_INTERVAL, Duration::from_secs(60));
    }

    #[test]
    fn concurrent_refreshes_run_the_command_once() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().display();
        std::fs::write(dir.path().join("secret"), "s1\n").unwrap();
        let slow = script(dir.path(), "slow-secret", &format!("echo run >> {d}/runs\nsleep 0.3\ncat {d}/secret"));
        let o = Origin::SecretCommand { user: "u".into(), command: slow };
        let c = Credentials::load_with(o, Duration::ZERO, COMMAND_TIMEOUT).unwrap();
        std::fs::write(dir.path().join("secret"), "s2\n").unwrap();
        let senders: Vec<_> = (0..5)
            .map(|_| {
                let c = c.clone();
                std::thread::spawn(move || c.refresh("s1"))
            })
            .collect();
        assert!(senders.into_iter().all(|h| h.join().unwrap()));
        assert_eq!(runs(dir.path()), 2); // start-up and one re-read
        assert_eq!(c.current().1, "s2");
    }

    #[test]
    fn failed_refresh_keeps_old_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().display();
        // Succeeds once, then fails.
        let flaky = script(
            dir.path(),
            "flaky",
            &format!("if [ -e {d}/ran ]; then echo vault sealed >&2; exit 1; fi\ntouch {d}/ran\necho s1"),
        );
        let o = Origin::SecretCommand { user: "u".into(), command: flaky };
        let c = Credentials::load_with(o, Duration::ZERO, COMMAND_TIMEOUT).unwrap();
        let logs = crate::log::capture(|| assert!(!c.refresh("s1")));
        assert_eq!(logs, ["PCE answered 401, reading the API credentials again", "Command failed: vault sealed\n"]);
        assert_eq!(c.current(), ("u".into(), "s1".into()));
    }

    #[test]
    fn api_key_sources_are_reread() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("api_info");
        std::fs::write(&key, "api_1 t1\n").unwrap();
        let path = key.to_str().unwrap().to_string();
        let c = Credentials::load_with(Origin::ApiKey(path.clone()), Duration::ZERO, COMMAND_TIMEOUT).unwrap();
        assert_eq!(c.current(), ("api_1".into(), "t1".into()));
        std::fs::write(&key, "api_1 t2\n").unwrap();
        assert!(c.refresh("t1"));
        assert_eq!(c.current().1, "t2");
        // A `$command` too.
        let c = Credentials::load_with(Origin::ApiKey(format!("$cat {path}")), Duration::ZERO, COMMAND_TIMEOUT).unwrap();
        std::fs::write(&key, "api_1 t3\n").unwrap();
        assert!(c.refresh("t2"));
        assert_eq!(c.current().1, "t3");
    }

    #[test]
    fn fixed_credentials_never_change() {
        let c = Credentials::fixed("u", "s");
        let logs = crate::log::capture(|| assert!(!c.refresh("s")));
        assert!(logs.is_empty());
        assert_eq!(c.current(), ("u".into(), "s".into()));
        assert_eq!(format!("{c:?}"), "Credentials(********)");
    }
}
