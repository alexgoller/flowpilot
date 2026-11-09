//! `api_key` sources (a file, or a `$command`) and API-key handling (docs/configuration.md, `api_key`),
//! plus the small Go-compatible `path/filepath` / `os` helpers the start-up code needs.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};
use std::sync::{mpsc, Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// How long `api_secret_command` (and an `api_key` source re-read after a 401) may run.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// `$cmd args` runs a command (no shell), anything else reads a file.
pub fn key_source(s: &str) -> String {
    read_key_source(s).unwrap_or_else(|f| f.exit())
}

/// Derive the API user and token from `config.api_key`. Exits 1 on failure.
pub fn api_credentials(api_key: &str) -> (String, String) {
    credentials(api_key).unwrap_or_else(|f| f.exit())
}

/// What FlowLink logs before exiting 1.
#[derive(Debug, PartialEq)]
pub(crate) enum Failure {
    /// A failed `$command`: `Command failed: <stderr>`.
    Command(String),
    /// An unreadable file: `log::check_error(err)` then `Error reading file: <path as given>`.
    Read { err: String, path: String },
    /// A single `log_line` line.
    Message(&'static str),
    /// A command that ran longer than its limit and was killed: `Command timed out after <n> seconds: <program>`.
    Timeout { program: String, after: Duration },
}

/// The text `report` logs (the first line only for an unreadable file); for the installer.
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Command(stderr) => write!(f, "Command failed: {stderr}"),
            Failure::Read { err, .. } => write!(f, "Error: {err}"),
            Failure::Message(m) => f.write_str(m),
            Failure::Timeout { program, after } => {
                write!(f, "Command timed out after {} seconds: {program}", after.as_secs_f64())
            }
        }
    }
}

impl Failure {
    pub(crate) fn exit(self) -> ! {
        match self {
            // As in FlowLink, stderr (not the error) is logged, verbatim incl. its trailing newline.
            Failure::Command(stderr) => crate::log_line!("Command failed:", stderr),
            Failure::Read { err, path } => {
                // As in FlowLink, in debug mode check_error exits before the second line.
                crate::log::check_error(Some(err));
                crate::log_line!("Error reading file:", path);
            }
            Failure::Message(m) => crate::log_line!(m),
            t @ Failure::Timeout { .. } => t.report(),
        }
        std::process::exit(1)
    }

    /// Logs the failure without exiting (a re-read at run time). Same texts; never the command's output.
    pub(crate) fn report(self) {
        match self {
            Failure::Command(stderr) => crate::log_line!("Command failed:", stderr),
            Failure::Read { err, path } => {
                crate::log_line!("Error:", err);
                crate::log_line!("Error reading file:", path);
            }
            Failure::Message(m) => crate::log_line!(m),
            t @ Failure::Timeout { .. } => crate::log_line!(t),
        }
    }
}

/// The value of an `api_key`-style source: `$command` output or file contents.
pub(crate) fn read_key_source(s: &str) -> Result<String, Failure> {
    read_key_source_within(s, None)
}

/// `read_key_source`; a `$command` is killed at `limit` when one is given.
fn read_key_source_within(s: &str, limit: Option<Limit>) -> Result<String, Failure> {
    match s.strip_prefix('$') {
        Some(cmd) => run_command(cmd, limit),
        None => read_key_file(s),
    }
}

/// `api_secret_command`: the command line itself (no leading `$`), run like a `$command` but killed after `timeout`.
/// Its output is the secret: one word, nothing else.
pub(crate) fn secret_command(cmdline: &str, timeout: Duration) -> Result<String, Failure> {
    let secret = run_command(cmdline, Some(Limit::new(timeout)))?;
    if secret.is_empty() || secret.contains(char::is_whitespace) {
        return Err(Failure::Message("API secret command printed no usable secret"));
    }
    Ok(secret)
}

/// Runs a `$command`: whitespace split, PATH lookup, stdin /dev/null, trimmed stdout; killed at `limit`.
fn run_command(cmdline: &str, limit: Option<Limit>) -> Result<String, Failure> {
    let f: Vec<&str> = cmdline.split_whitespace().collect();
    // Divergence: FlowLink panics (exit 2) on an empty command; we log `Command failed: ` and exit 1.
    let Some((name, args)) = f.split_first() else {
        return Err(Failure::Command(String::new()));
    };
    // A lookup or start failure has no stderr: `Command failed: `.
    let path = look_path(name).ok_or_else(|| Failure::Command(String::new()))?;
    let mut cmd = Command::new(path);
    cmd.arg0(name).args(args).stdin(Stdio::null());
    let out = match limit {
        None => cmd.output().map_err(|_| Failure::Command(String::new()))?,
        Some(limit) => output_within(cmd, limit).map_err(|f| match f {
            Failure::Timeout { after, .. } => Failure::Timeout { program: name.to_string(), after },
            f => f,
        })?,
    };
    if !out.status.success() {
        return Err(Failure::Command(
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// A time limit for commands: one deadline for everything run under it (both runs of a two-word `$command`).
#[derive(Clone, Copy)]
pub(crate) struct Limit {
    after: Duration,
    deadline: Instant,
}

impl Limit {
    pub(crate) fn new(after: Duration) -> Self {
        Self { after, deadline: Instant::now() + after }
    }
}

/// How long to wait for the pipes once the command has exited.
const EXIT_GRACE: Duration = Duration::from_secs(1);

/// `Command::output` with a limit. The command runs in its own process group: at the limit the group is killed, so
/// whatever it started (a script's `sleep`, say) stops too. Once the command has exited, its pipes are read for at
/// most `EXIT_GRACE` more: a process it left running may hold them, and is neither waited for nor stopped (with the
/// command reaped, its group id is no longer safe to signal).
fn output_within(mut cmd: Command, limit: Limit) -> Result<Output, Failure> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|_| Failure::Command(String::new()))?;
    let kill = |child: &mut std::process::Child| {
        // SAFETY: plain syscall. The group id is the child's pid (`process_group(0)`), and the child is not reaped
        // yet, so the id cannot have been reused.
        unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
        let _ = child.kill();
        let _ = child.wait();
    };
    let stdout = Pipe::read(child.stdout.take().expect("piped stdout"));
    let stderr = Pipe::read(child.stderr.take().expect("piped stderr"));
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < limit.deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                kill(&mut child);
                return Err(Failure::Timeout { program: String::new(), after: limit.after });
            }
            Err(_) => {
                kill(&mut child);
                return Err(Failure::Command(String::new()));
            }
        }
    };
    let until = Instant::now() + EXIT_GRACE;
    Ok(Output { status, stdout: stdout.take(until), stderr: stderr.take(until) })
}

/// A pipe read to its end by a thread of its own.
struct Pipe {
    buf: Arc<Mutex<Vec<u8>>>,
    closed: mpsc::Receiver<()>,
}

impl Pipe {
    fn read(mut r: impl Read + Send + 'static) -> Self {
        let buf: Arc<Mutex<Vec<u8>>> = Arc::default();
        let (tx, closed) = mpsc::channel();
        let out = buf.clone();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 8192];
            loop {
                match r.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => out.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            let _ = tx.send(());
        });
        Self { buf, closed }
    }

    /// Everything, when the pipe closes before `until`; else what came so far.
    fn take(self, until: Instant) -> Vec<u8> {
        let _ = self.closed.recv_timeout(until.saturating_duration_since(Instant::now()));
        std::mem::take(&mut *self.buf.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// Go `exec.LookPath`: names containing `/` are used as is; otherwise search `$PATH` (empty
/// entries mean `.`), and refuse a hit relative to the cwd (Go >= 1.19 `ErrDot`).
/// Ported from the Go standard library (`os/exec`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
fn look_path(name: &str) -> Option<String> {
    let executable = |p: &str| {
        std::fs::metadata(p).is_ok_and(|m| !m.is_dir() && m.permissions().mode() & 0o111 != 0)
    };
    if name.contains('/') {
        return executable(name).then(|| name.to_string());
    }
    let path = std::env::var("PATH").unwrap_or_default();
    if path.is_empty() {
        return None;
    }
    let hit = path
        .split(':')
        .map(|d| go_join(if d.is_empty() { "." } else { d }, name))
        .find(|p| executable(p))?;
    hit.starts_with('/').then_some(hit)
}

/// Reads a key file: cwd-relative, trimmed.
fn read_key_file(path: &str) -> Result<String, Failure> {
    let abs = go_abs(path);
    let b = go_read(&abs).map_err(|err| Failure::Read {
        err,
        path: path.to_string(),
    })?;
    Ok(String::from_utf8_lossy(&b).trim().to_string())
}

/// API key handling.
pub(crate) fn credentials(api_key: &str) -> Result<(String, String), Failure> {
    credentials_within(api_key, None)
}

/// `credentials`; a `$command` is killed after `timeout` when one is given. The limit covers both runs of the
/// two-word form together.
pub(crate) fn credentials_within(api_key: &str, timeout: Option<Duration>) -> Result<(String, String), Failure> {
    let limit = timeout.map(Limit::new);
    let read_key_source = |s: &str| read_key_source_within(s, limit);
    let key = read_key_source(api_key)?;
    if key.contains("key_id") {
        // As in FlowLink: substring detection; user = auth_username, token = secret.
        return api_key_json(&key).ok_or(Failure::Message("Invalid API key json file"));
    }
    // As in FlowLink, the source is evaluated a second time (a `$` command runs twice).
    let again = read_key_source(api_key)?;
    match again.split_whitespace().collect::<Vec<_>>()[..] {
        [user, token] => Ok((user.trim().to_string(), token.trim().to_string())),
        _ => Err(Failure::Message("Unable to obtain api key information")),
    }
}

/// `json.Unmarshal` into `{key_id, auth_username, secret string}`: extra fields ignored, keys
/// matched case-insensitively, `null` leaves a field empty, any other non-string is an error.
pub(crate) fn api_key_json(key: &str) -> Option<(String, String)> {
    let v: serde_json::Value = serde_json::from_str(key).ok()?;
    if v.is_null() {
        return Some(Default::default());
    }
    let obj = v.as_object()?;
    let get = |tag: &str| -> Option<String> {
        let found = obj
            .iter()
            .rev()
            .find(|(k, _)| k.eq_ignore_ascii_case(tag))
            .map(|(_, v)| v);
        match found {
            None | Some(serde_json::Value::Null) => Some(String::new()),
            Some(v) => v.as_str().map(str::to_string),
        }
    };
    get("key_id")?;
    Some((get("auth_username")?, get("secret")?))
}

// ---- Go os / path/filepath helpers -----------------------------------------------------------

/// Go `filepath.Clean`.
/// Ported from the Go standard library (`path/filepath`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
pub(crate) fn go_clean(p: &str) -> String {
    let rooted = p.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." if out.last().is_some_and(|s| *s != "..") => {
                out.pop();
            }
            ".." if rooted => {}
            s => out.push(s),
        }
    }
    let joined = out.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".into(),
        (false, false) => joined,
    }
}

/// Go `filepath.Join(dir, name)` (empty elements ignored, result cleaned).
/// Ported from the Go standard library (`path/filepath`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
pub(crate) fn go_join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        go_clean(name)
    } else {
        go_clean(&format!("{dir}/{name}"))
    }
}

/// Go `filepath.Abs` (relative to the process cwd, cleaned, symlinks not resolved).
/// Ported from the Go standard library (`path/filepath`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
pub(crate) fn go_abs(path: &str) -> String {
    if path.starts_with('/') {
        return go_clean(path);
    }
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    go_join(&cwd, path)
}

/// Go `*PathError` text: `<op> <path>: <errno text>` with Linux-style lower-case errno strings.
pub(crate) fn go_path_error(op: &str, path: &str, e: &std::io::Error) -> String {
    let msg = match e.raw_os_error() {
        Some(code) => {
            let s = std::io::Error::from_raw_os_error(code).to_string();
            let s = s.split(" (os error").next().unwrap_or(&s).to_string();
            let mut c = s.chars();
            c.next()
                .map(|f| f.to_lowercase().chain(c).collect())
                .unwrap_or_default()
        }
        None => e.to_string(),
    };
    format!("{op} {path}: {msg}")
}

/// Go `os.ReadFile` with Go's error text (`open …` or `read …`).
pub(crate) fn go_read(path: &str) -> Result<Vec<u8>, String> {
    let mut f = std::fs::File::open(path).map_err(|e| go_path_error("open", path, &e))?;
    let mut b = Vec::new();
    f.read_to_end(&mut b)
        .map_err(|e| go_path_error("read", path, &e))?;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &tempfile::TempDir, name: &str, content: &str) -> String {
        let p = dir.path().join(name);
        std::fs::write(&p, content).unwrap();
        p.to_str().unwrap().to_string()
    }

    #[test]
    fn file_and_command_sources_are_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(&dir, "k", "  user token \n");
        assert_eq!(read_key_source(&p).unwrap(), "user token");
        assert_eq!(read_key_source(&format!("$cat {p}")).unwrap(), "user token");
        assert_eq!(
            read_key_source(&format!("$  cat   {p}  ")).unwrap(),
            "user token"
        );
    }

    #[test]
    fn command_failures() {
        // Divergence: no panic on an empty command.
        assert_eq!(read_key_source("$"), Err(Failure::Command(String::new())));
        assert_eq!(
            read_key_source("$no-such-command-xyz"),
            Err(Failure::Command(String::new()))
        );
        match read_key_source("$cat /nonexistent/file") {
            Err(Failure::Command(stderr)) => {
                assert!(stderr.contains("/nonexistent/file"), "{stderr}")
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn missing_file_reports_go_error_and_given_path() {
        assert_eq!(
            read_key_source("/nonexistent/api_info"),
            Err(Failure::Read {
                err: "open /nonexistent/api_info: no such file or directory".into(),
                path: "/nonexistent/api_info".into()
            })
        );
    }

    #[test]
    fn api_key_json_form() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            &dir,
            "k.json",
            r#"{"key_id":"k1","auth_username":"api_123","secret":"s3cr3t","extra":1}"#,
        );
        let want = ("api_123".to_string(), "s3cr3t".to_string());
        assert_eq!(credentials(&format!("$cat {p}")).unwrap(), want);
        assert_eq!(credentials(&p).unwrap(), want);
        let bad = write(&dir, "bad.json", r#"{"key_id": 5, "secret": "x"}"#);
        assert_eq!(
            credentials(&bad),
            Err(Failure::Message("Invalid API key json file"))
        );
        let broken = write(&dir, "broken.json", "key_id oops");
        assert_eq!(
            credentials(&broken),
            Err(Failure::Message("Invalid API key json file"))
        );
    }

    #[test]
    fn api_key_two_token_form() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(&dir, "k", "api_1\ttoken1\n");
        assert_eq!(
            credentials(&format!("$cat {p}")).unwrap(),
            ("api_1".into(), "token1".into())
        );
        let three = write(&dir, "k3", "a b c");
        assert_eq!(
            credentials(&three),
            Err(Failure::Message("Unable to obtain api key information"))
        );
    }

    #[test]
    fn non_json_source_is_evaluated_twice() {
        // As in FlowLink.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("runs");
        let script = write(
            &dir,
            "key.sh",
            &format!("#!/bin/sh\necho run >> {}\necho u t\n", log.display()),
        );
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            credentials(&format!("${script}")).unwrap(),
            ("u".into(), "t".into())
        );
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "run\nrun\n");
    }

    fn script(dir: &tempfile::TempDir, name: &str, body: &str) -> String {
        let p = write(dir, name, &format!("#!/bin/sh\n{body}\n"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn limited_command_reads_more_than_a_pipe_buffer() {
        let dir = tempfile::tempdir().unwrap();
        let big = script(&dir, "big", "head -c 200000 /dev/zero | tr '\\0' a\nhead -c 100000 /dev/zero >&2");
        let out = secret_command(&big, Duration::from_secs(10)).unwrap();
        assert_eq!(out.len(), 200000);
        assert!(out.bytes().all(|b| b == b'a'));
    }

    #[test]
    fn limited_command_does_not_wait_for_what_it_leaves_running() {
        // A background process still holds stdout after the command exits: its output so far counts, and the wait
        // ends shortly after the command's exit, not at the limit. The background process is not killed.
        let dir = tempfile::tempdir().unwrap();
        let pid = dir.path().join("pid");
        let left = script(&dir, "left", &format!("sleep 60 &\necho $! > {}\necho s1", pid.display()));
        let t = Instant::now();
        assert_eq!(secret_command(&left, Duration::from_secs(20)).unwrap(), "s1");
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
        let pid: i32 = std::fs::read_to_string(&pid).unwrap().trim().parse().unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, 0, "the background process was killed");
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }

    #[test]
    fn limit_kills_the_whole_process_group() {
        let dir = tempfile::tempdir().unwrap();
        let pid = dir.path().join("pid");
        let hang = script(&dir, "hang", &format!("sleep 60 &\necho $! > {}\nwait", pid.display()));
        let t = Instant::now();
        let err = secret_command(&hang, Duration::from_secs(1)).unwrap_err();
        assert!(matches!(err, Failure::Timeout { .. }), "{err:?}");
        assert!(t.elapsed() < Duration::from_secs(4), "{:?}", t.elapsed());
        let pid: i32 = std::fs::read_to_string(&pid).unwrap().trim().parse().unwrap();
        // Killed, then reaped by init once orphaned.
        let gone = (0..40).any(|_| {
            std::thread::sleep(Duration::from_millis(50));
            (unsafe { libc::kill(pid, 0) }) != 0
        });
        assert!(gone, "the background sleep survived");
    }

    #[test]
    fn go_path_helpers() {
        assert_eq!(go_clean("/a/./b/../c/"), "/a/c");
        assert_eq!(go_clean("/../x"), "/x");
        assert_eq!(go_clean("../a/.."), "..");
        assert_eq!(go_clean(""), ".");
        assert_eq!(go_join(".", ".uuid"), ".uuid");
        assert_eq!(go_join("", ".uuid"), ".uuid");
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(go_abs("x/../y"), format!("{}/y", cwd.display()));
        assert_eq!(go_abs(""), cwd.display().to_string());
    }
}
