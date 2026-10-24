//! `api_key` sources (a file, or a `$command`) and API-key handling (docs/configuration.md, `api_key`),
//! plus the small Go-compatible `path/filepath` / `os` helpers the start-up code needs.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

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
}

impl Failure {
    fn exit(self) -> ! {
        match self {
            // As in FlowLink, stderr (not the error) is logged, verbatim incl. its trailing newline.
            Failure::Command(stderr) => crate::log_line!("Command failed:", stderr),
            Failure::Read { err, path } => {
                // As in FlowLink, in debug mode check_error exits before the second line.
                crate::log::check_error(Some(err));
                crate::log_line!("Error reading file:", path);
            }
            Failure::Message(m) => crate::log_line!(m),
        }
        std::process::exit(1)
    }
}

/// The value of an `api_key`-style source: `$command` output or file contents.
pub(crate) fn read_key_source(s: &str) -> Result<String, Failure> {
    match s.strip_prefix('$') {
        Some(cmd) => run_command(cmd),
        None => read_key_file(s),
    }
}

/// Runs a `$command`: whitespace split, PATH lookup, stdin /dev/null, trimmed stdout.
fn run_command(cmdline: &str) -> Result<String, Failure> {
    let f: Vec<&str> = cmdline.split_whitespace().collect();
    // Divergence: FlowLink panics (exit 2) on an empty command; we log `Command failed: ` and exit 1.
    let Some((name, args)) = f.split_first() else {
        return Err(Failure::Command(String::new()));
    };
    // A lookup or start failure has no stderr: `Command failed: `.
    let path = look_path(name).ok_or_else(|| Failure::Command(String::new()))?;
    let out = Command::new(path)
        .arg0(name)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|_| Failure::Command(String::new()))?;
    if !out.status.success() {
        return Err(Failure::Command(
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
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
