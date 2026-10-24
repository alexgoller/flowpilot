//! `flowpilot install` (and `upgrade`, the same command): answers, live check, plan, apply, health, and an automatic
//! switch back to the previous binary when an upgrade does not come up healthy.
//!
//! Without `--reconfigure` and without any answer (flag or `FLOWPILOT_*` variable), an existing install keeps its
//! config and key file as they are: only the binary and the unit follow this version. Given answers are rendered and
//! compared byte for byte with what is installed, so a re-run with the same answers changes nothing.

use std::io::Write;

use crate::env_config::Env;
use crate::install::answers::{self, Answers};
use crate::install::apply::{self, Action, Current, PlanOptions, CONFIG};
use crate::install::args::{CollectorKind, InstallArgs};
use crate::install::check::{check_pce, key_format, CheckError};
use crate::install::health::{wait_healthy, HEALTH_TIMEOUT};
use crate::install::render::{self, Firewall};
use crate::install::system::{RealSystem, System};
use crate::install::wizard::{self, DialoguerPrompter, Prompter, WizardError};

/// Everything `run_install_with` talks to, injectable so tests drive it against a `FakeSystem`.
pub struct Deps<'a> {
    pub sys: &'a mut dyn System,
    pub check: &'a mut dyn FnMut(&Answers) -> Result<(), CheckError>,
    /// `wait_healthy` with the install's timeout.
    pub health: &'a mut dyn FnMut(&str) -> Result<String, String>,
    pub prompter: &'a mut dyn Prompter,
    pub env: Env<'a>,
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

pub fn run_install(args: InstallArgs) -> i32 {
    let mut sys = RealSystem::new(args.root.clone().unwrap_or_else(|| "/".into()));
    let env = |k: &str| std::env::var(k).ok();
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    run_install_with(
        &mut Deps {
            sys: &mut sys,
            check: &mut check_pce,
            health: &mut |listen| wait_healthy(listen, HEALTH_TIMEOUT),
            prompter: &mut DialoguerPrompter,
            env: &env,
            out: &mut out,
            err: &mut err,
        },
        args,
    )
}

/// Writes a line; a closed stdout or stderr is no reason to stop an install half-way.
macro_rules! say {
    ($w:expr, $($t:tt)*) => {{ let _ = writeln!($w, $($t)*); }};
}

/// The stats ports tried, in order, when the config does not name one.
const STATS_PORTS: std::ops::Range<u16> = 9180..9190;

pub fn run_install_with(d: &mut Deps, args: InstallArgs) -> i32 {
    if !d.sys.is_root() {
        say!(d.err, "flowpilot install must run as root; try: sudo flowpilot install");
        return 1;
    }
    if !d.sys.has_systemd() {
        say!(d.err, "flowpilot install needs a host running systemd; this one does not.");
        return 1;
    }
    let current = match Current::read(d.sys) {
        Ok(c) => c,
        Err(e) => {
            say!(d.err, "{e}");
            return 1;
        }
    };
    let existing_listen = current.config.as_deref().and_then(stats_listen_of);
    let keep = current.config.is_some() && !args.reconfigure && !answers_given(&args, d.env);

    if args.skip_pce_check {
        say!(d.err, "WARNING: PCE connection and API key were NOT checked (--skip-pce-check)");
    }
    let mut unchecked = |_: &Answers| Ok(());
    let check: &mut dyn FnMut(&Answers) -> Result<(), CheckError> =
        if args.skip_pce_check { &mut unchecked } else { &mut *d.check };

    // The answers, checked against the PCE; the config they render, validated as the daemon would.
    let (a, stats_listen) = if keep {
        let config = current.config.as_deref().unwrap_or_default();
        let a = match answers::from_existing(config, current.key.as_deref().unwrap_or_default()) {
            Ok(a) => a,
            Err(e) => {
                say!(d.err, "The existing install cannot be read ({CONFIG}: {e}); run again with --reconfigure to replace it.");
                return 1;
            }
        };
        proxy_note(d.err, d.env, &a);
        if let Err(e) = check(&a) {
            say!(d.err, "{e}");
            return 1;
        }
        (a, existing_listen)
    } else {
        // The wizard offers what is installed as its defaults; `--yes` takes only what this run gives.
        let base = if args.yes { answers::defaults() } else { installed_defaults(&current) };
        let start = match answers::from_args_over(&args, d.env, base) {
            Ok(a) => a,
            Err(errors) => {
                errors.iter().for_each(|e| say!(d.err, "{e}"));
                return 2;
            }
        };
        let Some(listen) = existing_listen.or_else(|| free_stats_listen(d.sys)) else {
            say!(d.err, "No free port for the stats endpoint in 127.0.0.1:{}-{}.", STATS_PORTS.start, STATS_PORTS.end - 1);
            return 1;
        };
        // A key the key file cannot hold is refused before the PCE sees it.
        let mut vetted = |a: &Answers| key_format(a).and_then(|()| check(a));
        let a = if args.yes {
            let missing = start.missing();
            if !missing.is_empty() {
                say!(d.err, "Missing with --yes: {} (see flowpilot install --help).", missing.join(", "));
                return 2;
            }
            if let Err(e) = vet(&start, &listen) {
                say!(d.err, "{e}");
                return 2;
            }
            proxy_note(d.err, d.env, &start);
            if let Err(e) = vetted(&start) {
                say!(d.err, "{e}");
                return 1;
            }
            start
        } else {
            proxy_note(d.err, d.env, &start);
            let a = match wizard::ask_with(d.prompter, start, &mut vetted) {
                Ok(a) => a,
                Err(e @ WizardError::CheckFailed(CheckError::KeyFormat)) => {
                    say!(d.err, "{e}");
                    return 2;
                }
                Err(e @ WizardError::CheckFailed(_)) => {
                    say!(d.err, "{e}");
                    return 1;
                }
                Err(e) => {
                    say!(d.err, "{e}");
                    return 2;
                }
            };
            if let Err(e) = vet(&a, &listen) {
                say!(d.err, "{e}");
                return 2;
            }
            a
        };
        (a, Some(listen))
    };

    let options = PlanOptions {
        keep_config: keep,
        stats_listen: stats_listen.clone().unwrap_or_default(),
        backup_stamp: chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string(),
    };
    let actions = apply::plan(&a, &current, &options);
    let root_prefixed = args.root.as_deref().is_some_and(|r| r != std::path::Path::new("/"));
    if actions.is_empty() {
        // Nothing to change, but a re-run (Ansible's, say) must not report success for a service that is down.
        let healthy = match &stats_listen {
            _ if root_prefixed => Ok("health check skipped (--root)".to_string()),
            Some(listen) => (d.health)(listen).map(|status| format!("status: {status}")),
            None => match d.sys.service_state(apply::USER).as_str() {
                "active" => Ok("active".to_string()),
                state => Err(format!("the service is {state}")),
            },
        };
        return match healthy {
            Ok(how) => {
                say!(d.out, "FlowPilot is installed and unchanged ({how}).");
                0
            }
            Err(e) => {
                say!(d.err, "FlowPilot is installed and unchanged, but it is not healthy ({e}). See: journalctl -u flowpilot");
                1
            }
        };
    }
    if !args.yes {
        say!(d.out, "The installer will:");
        actions.iter().for_each(|x| say!(d.out, "  - {x}"));
        match d.prompter.confirm("Go ahead?", true) {
            Ok(true) => {}
            Ok(false) => {
                say!(d.err, "{}", WizardError::Aborted);
                return 2;
            }
            Err(e) => {
                say!(d.err, "{e}");
                return 2;
            }
        }
    }
    // The listen address to wait on; `None` when the wait is skipped.
    let wait_on = stats_listen.as_deref().filter(|_| !root_prefixed);
    let upgrade = current.binary_sha256.is_some();
    match apply::execute(d.sys, &actions) {
        Ok(report) => report.notes.iter().for_each(|n| say!(d.out, "{n}")),
        Err(stopped) => {
            stopped.report.notes.iter().for_each(|n| say!(d.out, "{n}"));
            let done = &actions[..stopped.done];
            // A failed `InstallBinary` may have moved the old binary to `.prev` without putting the new one in place.
            let swapped = done.contains(&Action::InstallBinary)
                || (actions[stopped.done] == Action::InstallBinary && !d.sys.exists(std::path::Path::new(apply::BIN)));
            if upgrade && swapped {
                roll_back(d, &stopped.error.to_string(), wait_on, current.binary_version.as_deref(), done);
            } else {
                say!(d.err, "{}", stopped.error);
            }
            return 1;
        }
    }

    match &stats_listen {
        _ if root_prefixed => say!(d.out, "health check skipped (--root)"),
        None => say!(d.out, "The config has no stats.http_listen, so the service's health was not checked."),
        Some(listen) => {
            say!(d.out, "Waiting for FlowPilot to report healthy on {listen} ...");
            match (d.health)(listen) {
                Ok(status) => say!(d.out, "FlowPilot is running (status: {status})."),
                Err(e) => {
                    if upgrade && actions.contains(&Action::InstallBinary) {
                        let why = format!("The new version did not report healthy ({e})");
                        roll_back(d, &why, Some(listen), current.binary_version.as_deref(), &actions);
                    } else {
                        say!(d.err, "FlowPilot did not report healthy ({e}). See: journalctl -u flowpilot");
                    }
                    return 1;
                }
            }
        }
    }
    next_steps(d, &a);
    0
}

/// After an upgrade that failed (`why`) once the binary was replaced: the previous binary back, restarted, and waited
/// for again on `listen`. `done` are the actions carried out; a config they rewrote stays, and its backup is named.
fn roll_back(d: &mut Deps, why: &str, listen: Option<&str>, old_version: Option<&str>, done: &[Action]) {
    let old = old_version.unwrap_or("the previous version");
    say!(d.err, "{why}; switching back to {old}.");
    if let Err(e) = apply::restore_previous(d.sys) {
        say!(d.err, "{e}. See: journalctl -u flowpilot");
        return;
    }
    match listen.map(|l| (d.health)(l)) {
        Some(Ok(status)) => say!(d.err, "upgrade rolled back to {old} (status: {status}). See: journalctl -u flowpilot"),
        Some(Err(e)) => {
            say!(d.err, "upgrade rolled back to {old}, but it is not healthy either ({e}). See: journalctl -u flowpilot")
        }
        None => say!(d.err, "upgrade rolled back to {old}. See: journalctl -u flowpilot"),
    }
    let wrote_config = done.iter().any(|x| matches!(x, Action::WriteFile { path, .. } if path == std::path::Path::new(CONFIG)));
    let backup = done.iter().find_map(|x| match x {
        Action::BackupConfig { to } => Some(to.display().to_string()),
        _ => None,
    });
    match (wrote_config, backup) {
        (true, Some(to)) => say!(
            d.err,
            "Only the binary was switched back: the config this run wrote was kept, and the previous config is saved as {to}."
        ),
        (true, None) => say!(d.err, "Only the binary was switched back: the config this run wrote was kept."),
        _ => {}
    }
}

/// The firewall commands to run by hand, and what to do next.
fn next_steps(d: &mut Deps, a: &Answers) {
    let fw = d.sys.active_firewall();
    let lines = render::firewall_commands(a, fw);
    if fw == Firewall::None {
        lines.iter().for_each(|l| say!(d.out, "Note: {}", l.trim_start_matches("# ")));
    } else {
        say!(d.out, "Open the collector ports (the installer never changes the firewall):");
        lines.iter().for_each(|l| say!(d.out, "  {l}"));
    }
    let listening: Vec<String> = a
        .collectors
        .iter()
        .map(|c| {
            let kind = match c.kind {
                CollectorKind::Netflow => "NetFlow",
                CollectorKind::Ipfix => "IPFIX",
                CollectorKind::Sflow => "sFlow",
                CollectorKind::Text => "text",
            };
            format!("{kind} on UDP {}", c.ports)
        })
        .collect();
    say!(d.out, "Point the exporters at this host: {}.", listening.join(", "));
    say!(d.out, "Check it with: flowpilot status   Logs: journalctl -u flowpilot");
}

/// The installed answers without the secret (the wizard asks for it again and never shows it), or the defaults when
/// nothing readable is installed.
fn installed_defaults(current: &Current) -> Answers {
    let installed = current.config.as_deref().map(|c| answers::from_existing(c, current.key.as_deref().unwrap_or_default()));
    match installed {
        Some(Ok(mut a)) => {
            a.api_secret = crate::config::Secret(String::new());
            a
        }
        _ => answers::defaults(),
    }
}

/// True when the run gives any answer: a flag, or a `FLOWPILOT_*` variable the installer reads.
fn answers_given(args: &InstallArgs, env: Env) -> bool {
    args.pce.is_some()
        || args.org.is_some()
        || args.api_user.is_some()
        || args.api_secret_file.is_some()
        || args.api_key_file.is_some()
        || !args.collectors.is_empty()
        || args.text != Default::default()
        || args.unmanaged != Default::default()
        || args.verify_pce_cert.is_some()
        || args.proxy.is_some()
        || answers::any_answer_var(env)
}

/// A note when this shell sets a proxy and the answers do not: the service does not inherit the shell's variables, so
/// the check does not use them either. The value is never shown (it may hold a password).
fn proxy_note(err: &mut dyn Write, env: Env, a: &Answers) {
    let ambient = ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"].iter().any(|k| env(k).is_some_and(|v| !v.is_empty()));
    if ambient && a.proxy.https.is_empty() {
        say!(
            err,
            "Note: the proxy set in this shell (HTTPS_PROXY or ALL_PROXY) is not used: the service does not inherit it, \
             so the PCE check goes direct too. If the PCE can only be reached through a proxy, pass --proxy."
        );
    }
}

/// What a final answer must pass before anything is checked or written.
fn vet(a: &Answers, stats_listen: &str) -> Result<(), String> {
    key_format(a).map_err(|e| e.to_string())?;
    let config = render::config_yaml(a, stats_listen);
    match crate::config::validate(config.as_bytes()) {
        Ok(_) => Ok(()),
        Err(crate::config::LoadError::Log(lines)) => Err(lines.join("\n")),
        Err(crate::config::LoadError::Check(err)) => Err(format!("The rendered config is not valid: {err}")),
    }
}

/// `stats.http_listen` of a config.
pub(crate) fn stats_listen_of(config: &[u8]) -> Option<String> {
    let doc: serde_json::Value = serde_yaml::from_slice(config).ok()?;
    doc.pointer("/stats/http_listen")?.as_str().map(str::to_string)
}

fn free_stats_listen(sys: &dyn System) -> Option<String> {
    STATS_PORTS.clone().find(|p| sys.port_free(*p)).map(|p| format!("127.0.0.1:{p}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::apply::{BIN, BIN_PREV, CONFIG, KEY, UNIT};
    use crate::install::args::parse_install;
    use crate::install::render;
    use crate::install::system::{FakeSystem, Owner};
    use crate::install::wizard::WizardError;

    /// Fails the test if the run asks anything (every test here passes `--yes`).
    struct NoPrompts;

    impl Prompter for NoPrompts {
        fn text(&mut self, q: &str, _: Option<&str>) -> Result<String, WizardError> {
            panic!("asked {q}")
        }
        fn secret(&mut self, q: &str) -> Result<String, WizardError> {
            panic!("asked {q}")
        }
        fn confirm(&mut self, q: &str, _: bool) -> Result<bool, WizardError> {
            panic!("asked {q}")
        }
    }

    struct Run {
        code: i32,
        /// stdout and stderr, in that order.
        output: String,
        checks: usize,
        health_calls: usize,
    }

    /// Runs `flowpilot install <argv>` against `sys`; the PCE check answers `check`, each health wait the next of
    /// `health` (then healthy).
    fn run(
        sys: &mut FakeSystem,
        argv: &[&str],
        check: Result<(), CheckError>,
        health: Vec<Result<String, String>>,
    ) -> Run {
        run_prompted(sys, argv, check, health, &mut NoPrompts)
    }

    fn run_prompted(
        sys: &mut FakeSystem,
        argv: &[&str],
        check: Result<(), CheckError>,
        health: Vec<Result<String, String>>,
        prompter: &mut dyn Prompter,
    ) -> Run {
        run_full(sys, argv, check, health, prompter, &|_| None)
    }

    fn run_full(
        sys: &mut FakeSystem,
        argv: &[&str],
        check: Result<(), CheckError>,
        health: Vec<Result<String, String>>,
        prompter: &mut dyn Prompter,
        env: Env,
    ) -> Run {
        let args = parse_install(&argv.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let mut checks = 0;
        let mut check_fn = |_: &Answers| {
            checks += 1;
            match &check {
                Ok(()) => Ok(()),
                Err(CheckError::Auth(c)) => Err(CheckError::Auth(*c)),
                Err(e) => Err(CheckError::Other(e.to_string())),
            }
        };
        let mut health = health.into_iter();
        let mut health_fn = |_: &str| health.next().unwrap_or(Ok("no_flows".into()));
        let mut health_calls = 0;
        let mut health_fn = |l: &str| {
            health_calls += 1;
            health_fn(l)
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_install_with(
            &mut Deps {
                sys,
                check: &mut check_fn,
                health: &mut health_fn,
                prompter,
                env,
                out: &mut out,
                err: &mut err,
            },
            args,
        );
        let output = format!("{}{}", String::from_utf8_lossy(&out), String::from_utf8_lossy(&err));
        Run { code, output, checks, health_calls }
    }

    const FLAGS: &[&str] = &["--yes", "--pce", "pce.example.com:8443", "--api-user", "api_1", "--api-secret-file"];

    /// `--yes` with the full answers; the secret comes from a file in `dir`.
    fn flags(dir: &tempfile::TempDir, extra: &[&str]) -> Vec<String> {
        let f = dir.path().join("secret");
        std::fs::write(&f, "s3cret\n").unwrap();
        let mut v: Vec<String> = FLAGS.iter().map(|s| s.to_string()).collect();
        v.push(f.to_str().unwrap().into());
        v.extend(extra.iter().map(|s| s.to_string()));
        v
    }

    fn argv(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    fn host() -> FakeSystem {
        let mut sys = FakeSystem::new("0.9.0");
        sys.put("/sbin/nologin", b"", 0o755, Owner::ROOT);
        sys
    }

    #[test]
    fn fresh_install_writes_everything_and_reports_health() {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = host();
        let r = run(&mut sys, &argv(&flags(&dir, &[])), Ok(()), vec![]);
        assert_eq!(r.code, 0, "{}", r.output);
        assert_eq!(r.checks, 1);
        assert_eq!(sys.file(KEY).unwrap().data, b"api_1 s3cret\n");
        let config = String::from_utf8(sys.file(CONFIG).unwrap().data.clone()).unwrap();
        assert!(config.contains("http_listen: 127.0.0.1:9180"), "{config}");
        assert!(!config.contains("s3cret"));
        assert_eq!(sys.log.last().unwrap(), "run systemctl enable --now flowpilot");
        assert!(r.output.contains("no_flows"), "{}", r.output);
        assert!(r.output.contains("firewall-cmd --permanent --add-port=2055/udp"), "{}", r.output);
        assert!(r.output.contains("flowpilot status"), "{}", r.output);
        assert!(!r.output.contains("s3cret"));
    }

    #[test]
    fn stats_listen_takes_next_free_port() {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = host();
        sys.busy_ports = vec![9180, 9181];
        assert_eq!(run(&mut sys, &argv(&flags(&dir, &[])), Ok(()), vec![]).code, 0);
        assert!(String::from_utf8_lossy(&sys.file(CONFIG).unwrap().data).contains("http_listen: 127.0.0.1:9182"));
    }

    #[test]
    fn rerun_same_answers_is_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = host();
        let a = flags(&dir, &[]);
        assert_eq!(run(&mut sys, &argv(&a), Ok(()), vec![]).code, 0);
        let before = sys.log.len();
        let r = run(&mut sys, &argv(&a), Ok(()), vec![]);
        assert_eq!(r.code, 0, "{}", r.output);
        assert_eq!(sys.log[before..], [] as [String; 0]);
        assert!(r.output.contains("unchanged"), "{}", r.output);
        assert_eq!(r.health_calls, 1);
    }

    #[test]
    fn rerun_with_an_unhealthy_service_is_exit_1() {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = host();
        let a = flags(&dir, &[]);
        assert_eq!(run(&mut sys, &argv(&a), Ok(()), vec![]).code, 0);
        let before = sys.log.len();
        let r = run(&mut sys, &argv(&a), Ok(()), vec![Err("connection refused".into())]);
        assert_eq!(r.code, 1, "{}", r.output);
        assert_eq!(sys.log[before..], [] as [String; 0]);
        assert!(r.output.contains("connection refused") && r.output.contains("journalctl -u flowpilot"), "{}", r.output);
    }

    #[test]
    fn rerun_without_stats_listen_asks_systemd() {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = host();
        assert_eq!(run(&mut sys, &argv(&flags(&dir, &[])), Ok(()), vec![]).code, 0);
        let config = String::from_utf8(sys.file(CONFIG).unwrap().data.clone()).unwrap();
        let config = config.replace("stats:\n  http_listen: 127.0.0.1:9180\n", "");
        sys.put(CONFIG, config.as_bytes(), 0o640, Owner::ROOT_FLOWPILOT);
        sys.service_state = "failed".into();
        let r = run(&mut sys, &["--yes"], Ok(()), vec![]);
        assert_eq!((r.code, r.health_calls), (1, 0), "{}", r.output);
        assert!(r.output.contains("failed"), "{}", r.output);
        sys.service_state = "active".into();
        assert_eq!(run(&mut sys, &["--yes"], Ok(()), vec![]).code, 0);
    }

    #[test]
    fn reconfigure_backs_up_config() {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = host();
        assert_eq!(run(&mut sys, &argv(&flags(&dir, &[])), Ok(()), vec![]).code, 0);
        let old = sys.file(CONFIG).unwrap().data.clone();
        let before = sys.log.len();
        let r = run(&mut sys, &argv(&flags(&dir, &["--reconfigure", "--netflow", "2056"])), Ok(()), vec![]);
        assert_eq!(r.code, 0, "{}", r.output);
        let new = &sys.log[before..];
        let backup = new.iter().position(|l| l.starts_with("write /etc/flowpilot/config.yaml.")).expect("a backup");
        let write = new.iter().position(|l| l.starts_with("write /etc/flowpilot/config.yaml ")).expect("a write");
        assert!(backup < write, "{new:?}");
        // config.yaml.<UTC yyyymmddTHHMMSSZ>.bak
        let name = new[backup].split(' ').nth(1).unwrap().strip_prefix("/etc/flowpilot/config.yaml.").unwrap();
        let stamp = name.strip_suffix(".bak").unwrap();
        assert_eq!(stamp.len(), 16, "{stamp}");
        assert!(stamp[..8].bytes().all(|b| b.is_ascii_digit()) && &stamp[8..9] == "T" && stamp.ends_with('Z'), "{stamp}");
        assert!(stamp[9..15].bytes().all(|b| b.is_ascii_digit()), "{stamp}");
        let path = format!("/etc/flowpilot/config.yaml.{name}");
        assert_eq!(sys.file(&path).unwrap().data, old);
        assert!(r.output.contains(&path), "{}", r.output);
        assert_eq!(new.last().unwrap(), "run systemctl restart flowpilot");
    }

    /// A host installed by an older binary whose config was then edited by hand.
    fn hand_edited_host() -> (FakeSystem, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = FakeSystem::new("2.0.0");
        sys.put("/sbin/nologin", b"", 0o755, Owner::ROOT);
        assert_eq!(run(&mut sys, &argv(&flags(&dir, &[])), Ok(()), vec![]).code, 0);
        let mut config = sys.file(CONFIG).unwrap().data.clone();
        config.splice(0..0, b"# edited by hand\n".iter().copied());
        sys.put(CONFIG, &config, 0o640, Owner::ROOT_FLOWPILOT);
        sys.self_bin = b"binary 0.9.0".to_vec();
        sys.log.clear();
        (sys, config)
    }

    #[test]
    fn existing_config_kept_without_reconfigure() {
        let (mut sys, config) = hand_edited_host();
        let r = run(&mut sys, &["--yes"], Ok(()), vec![]);
        assert_eq!(r.code, 0, "{}", r.output);
        assert_eq!(
            sys.log,
            [
                "copy-self /usr/local/bin/flowpilot.new",
                "rename /usr/local/bin/flowpilot /usr/local/bin/flowpilot.prev",
                "rename /usr/local/bin/flowpilot.new /usr/local/bin/flowpilot",
                "run restorecon -F /usr/local/bin/flowpilot",
                "run systemctl restart flowpilot",
            ]
        );
        assert_eq!(sys.file(CONFIG).unwrap().data, config);
        assert_eq!(sys.file(BIN).unwrap().data, b"binary 0.9.0");
    }

    #[test]
    fn daemon_variable_in_the_environment_keeps_the_config() {
        let (mut sys, config) = hand_edited_host();
        let env = |k: &str| (k == "FLOWPILOT_DATA_DIRECTORY").then(|| "/srv/flows".to_string());
        let r = run_full(&mut sys, &["--yes"], Ok(()), vec![], &mut NoPrompts, &env);
        assert_eq!(r.code, 0, "{}", r.output);
        assert_eq!(sys.file(CONFIG).unwrap().data, config);
    }

    #[test]
    fn proxy_answer_is_written_and_shell_proxy_noted() {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = host();
        let env = |k: &str| (k == "HTTPS_PROXY").then(|| "http://u:pa55@shell-proxy:3128".to_string());
        let r = run_full(&mut sys, &argv(&flags(&dir, &[])), Ok(()), vec![], &mut NoPrompts, &env);
        assert_eq!(r.code, 0, "{}", r.output);
        assert!(r.output.contains("pass --proxy"), "{}", r.output);
        assert!(!r.output.contains("pa55") && !r.output.contains("shell-proxy"), "{}", r.output);
        assert!(!String::from_utf8_lossy(&sys.file(CONFIG).unwrap().data).contains("proxy_config"));

        let mut sys = host();
        let a = flags(&dir, &["--proxy", "http://u:pa55@proxy.example.com:3128"]);
        let r = run_full(&mut sys, &argv(&a), Ok(()), vec![], &mut NoPrompts, &env);
        assert_eq!(r.code, 0, "{}", r.output);
        assert!(!r.output.contains("pass --proxy") && !r.output.contains("pa55"), "{}", r.output);
        let config = String::from_utf8_lossy(&sys.file(CONFIG).unwrap().data).into_owned();
        assert!(config.contains("proxy_config:\n  https_proxy: http://u:pa55@proxy.example.com:3128\n"), "{config}");
        // An upgrade keeps it (the check then goes through it, see answers::from_existing and check_pce).
        sys.self_bin = b"binary 2.0.2".to_vec();
        let r = run(&mut sys, &["--yes"], Ok(()), vec![]);
        assert_eq!(r.code, 0, "{}", r.output);
        assert_eq!(String::from_utf8_lossy(&sys.file(CONFIG).unwrap().data), config);
    }

    #[test]
    fn upgrade_failure_rolls_back() {
        let (mut sys, _) = hand_edited_host();
        let r = run(&mut sys, &["--yes"], Ok(()), vec![Err("connection refused".into())]);
        assert_eq!(r.code, 1, "{}", r.output);
        let restart = sys.log.iter().position(|l| l == "run systemctl restart flowpilot").unwrap();
        let after = &sys.log[restart + 1..];
        let back = after.iter().position(|l| l == "rename /usr/local/bin/flowpilot.prev /usr/local/bin/flowpilot");
        let reset = after.iter().position(|l| l == "run systemctl reset-failed flowpilot");
        let again = after.iter().rposition(|l| l == "run systemctl restart flowpilot");
        assert!(back.is_some() && reset > back && again > reset, "{:?}", sys.log);
        assert_eq!(sys.file(BIN).unwrap().data, b"binary 2.0.0");
        assert!(sys.file(BIN_PREV).is_none());
        assert!(r.output.contains("upgrade rolled back to 2.0.0"), "{}", r.output);
    }

    #[test]
    fn upgrade_step_failure_restores_the_previous_binary() {
        let (mut sys, _) = hand_edited_host();
        sys.fail_once.push("systemctl restart flowpilot".into());
        let r = run(&mut sys, &["--yes"], Ok(()), vec![]);
        assert_eq!(r.code, 1, "{}", r.output);
        let failed = sys.log.iter().position(|l| l == "run systemctl restart flowpilot").unwrap();
        assert_eq!(
            sys.log[failed + 1..],
            [
                "rename /usr/local/bin/flowpilot.prev /usr/local/bin/flowpilot",
                "run systemctl reset-failed flowpilot",
                "run systemctl restart flowpilot",
            ]
        );
        assert_eq!(sys.file(BIN).unwrap().data, b"binary 2.0.0");
        assert!(r.output.contains("Could not restart the flowpilot service"), "{}", r.output);
        assert!(r.output.contains("switching back to 2.0.0"), "{}", r.output);
        assert!(r.output.contains("upgrade rolled back to 2.0.0"), "{}", r.output);
        assert_eq!(r.health_calls, 1);
    }

    #[test]
    fn failed_step_before_the_binary_or_on_a_fresh_install_is_not_rolled_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = host();
        sys.fail_once.push("systemctl daemon-reload".into());
        let r = run(&mut sys, &argv(&flags(&dir, &[])), Ok(()), vec![]);
        assert_eq!(r.code, 1, "{}", r.output);
        assert!(!sys.log.iter().any(|l| l.contains(BIN_PREV)), "{:?}", sys.log);
        assert!(!r.output.contains("switching back"), "{}", r.output);
    }

    #[test]
    fn rollback_names_the_config_backup() {
        let (mut sys, _) = hand_edited_host();
        let dir = tempfile::tempdir().unwrap();
        let r = run(&mut sys, &argv(&flags(&dir, &["--netflow", "2056"])), Ok(()), vec![Err("connection refused".into())]);
        assert_eq!(r.code, 1, "{}", r.output);
        assert_eq!(sys.file(BIN).unwrap().data, b"binary 2.0.0");
        let backup = sys.files.keys().find_map(|k| k.to_str().filter(|k| k.ends_with(".bak")).map(str::to_string)).unwrap();
        let rolled = r.output.lines().skip_while(|l| !l.contains("switching back")).collect::<Vec<_>>().join("\n");
        assert!(rolled.contains(&format!("the previous config is saved as {backup}")), "{}", r.output);
        assert!(rolled.contains("kept"), "{}", r.output);
    }

    #[test]
    fn failed_health_on_fresh_install_is_exit_1_without_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = host();
        let r = run(&mut sys, &argv(&flags(&dir, &[])), Ok(()), vec![Err("connection refused".into())]);
        assert_eq!(r.code, 1);
        assert!(r.output.contains("journalctl -u flowpilot"), "{}", r.output);
        assert!(!sys.log.iter().any(|l| l.contains(BIN_PREV)));
    }

    #[test]
    fn failed_check_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = host();
        let r = run(&mut sys, &argv(&flags(&dir, &[])), Err(CheckError::Auth(401)), vec![]);
        assert_eq!(r.code, 1);
        assert_eq!(sys.log, [] as [String; 0]);
        assert!(r.output.contains("401"), "{}", r.output);
    }

    #[test]
    fn skip_pce_check_warns_and_does_not_check() {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = host();
        let r = run(&mut sys, &argv(&flags(&dir, &["--skip-pce-check"])), Err(CheckError::Auth(401)), vec![]);
        assert_eq!(r.code, 0, "{}", r.output);
        assert_eq!(r.checks, 0);
        assert!(r.output.contains("PCE connection and API key were NOT checked (--skip-pce-check)"));
    }

    #[test]
    fn not_root_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = host();
        sys.root = false;
        let r = run(&mut sys, &argv(&flags(&dir, &[])), Ok(()), vec![]);
        assert_eq!(r.code, 1);
        assert_eq!((sys.log.len(), r.checks), (0, 0));
        assert!(r.output.contains("root"), "{}", r.output);

        let mut sys = host();
        sys.systemd = false;
        assert_eq!(run(&mut sys, &argv(&flags(&dir, &[])), Ok(()), vec![]).code, 1);
        assert!(sys.log.is_empty());
    }

    #[test]
    fn usage_errors_are_exit_2_and_change_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = host();
        // Missing answers.
        let r = run(&mut sys, &["--yes"], Ok(()), vec![]);
        assert_eq!(r.code, 2, "{}", r.output);
        assert!(r.output.contains("pce"), "{}", r.output);
        // A space in the secret: the key file splits on whitespace.
        let f = dir.path().join("spaced");
        std::fs::write(&f, "two words\n").unwrap();
        let spaced = ["--yes", "--pce", "p:443", "--api-user", "api_1", "--api-secret-file", f.to_str().unwrap()];
        let r = run(&mut sys, &spaced, Ok(()), vec![]);
        assert_eq!((r.code, r.checks), (2, 0), "{}", r.output);
        // A rendered config the daemon would reject.
        let r = run(&mut sys, &argv(&flags(&dir, &["--unmanaged", "--unmanaged-networks", "not-a-cidr"])), Ok(()), vec![]);
        assert_eq!((r.code, r.checks), (2, 0), "{}", r.output);
        assert!(sys.log.is_empty());
    }

    #[test]
    fn firewall_none_prints_a_note_not_a_command() {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = host();
        sys.firewall = render::Firewall::None;
        let r = run(&mut sys, &argv(&flags(&dir, &[])), Ok(()), vec![]);
        assert_eq!(r.code, 0);
        assert!(!r.output.contains("# no active firewall"), "{}", r.output);
        assert!(r.output.contains("no active firewall was found"), "{}", r.output);
    }

    #[test]
    fn unit_left_as_installed_by_upgrade() {
        let (mut sys, _) = hand_edited_host();
        let unit = sys.file(UNIT).unwrap().data.clone();
        run(&mut sys, &["--yes"], Ok(()), vec![]);
        assert_eq!(sys.file(UNIT).unwrap().data, unit);
    }

    /// The wizard's answers: the PCE address, the user, the secrets in order; every other question its default,
    /// every confirmation yes.
    struct Wizard {
        secrets: Vec<&'static str>,
        asked_secret: usize,
    }

    impl Prompter for Wizard {
        fn text(&mut self, q: &str, default: Option<&str>) -> Result<String, WizardError> {
            Ok(match q {
                "PCE address (host:port)" => "pce.example.com:8443".into(),
                "API user" => "api_1".into(),
                _ => default.unwrap_or("").into(),
            })
        }
        fn secret(&mut self, _: &str) -> Result<String, WizardError> {
            self.asked_secret += 1;
            Ok(self.secrets.remove(0).into())
        }
        fn confirm(&mut self, q: &str, default: bool) -> Result<bool, WizardError> {
            Ok(match q {
                "Change the answers and check again?" | "Go ahead?" => true,
                _ => default,
            })
        }
    }

    #[test]
    fn wizard_spaced_secret_is_reasked_before_any_check() {
        let mut sys = host();
        let mut p = Wizard { secrets: vec!["two words", "good"], asked_secret: 0 };
        let r = run_prompted(&mut sys, &[], Ok(()), vec![], &mut p);
        assert_eq!(r.code, 0, "{}", r.output);
        assert_eq!((r.checks, p.asked_secret), (1, 2));
        assert_eq!(sys.file(KEY).unwrap().data, b"api_1 good\n");
        assert!(!sys.files.values().any(|f| String::from_utf8_lossy(&f.data).contains("two words")));
    }

    /// Takes every default and records it; a new secret; every confirmation its default, the plan yes.
    #[derive(Default)]
    struct Defaults {
        asked: Vec<(String, String)>,
        secrets: usize,
    }

    impl Prompter for Defaults {
        fn text(&mut self, q: &str, default: Option<&str>) -> Result<String, WizardError> {
            self.asked.push((q.into(), default.unwrap_or("").into()));
            Ok(default.unwrap_or("").into())
        }
        fn secret(&mut self, _: &str) -> Result<String, WizardError> {
            self.secrets += 1;
            Ok("n3w-secret".into())
        }
        fn confirm(&mut self, q: &str, default: bool) -> Result<bool, WizardError> {
            Ok(q == "Go ahead?" || default)
        }
    }

    #[test]
    fn wizard_reconfigure_starts_from_the_installed_answers() {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = host();
        let first = flags(&dir, &["--org", "4", "--netflow", "2056@192.0.2.10"]);
        assert_eq!(run(&mut sys, &argv(&first), Ok(()), vec![]).code, 0);
        let mut p = Defaults::default();
        let r = run_prompted(&mut sys, &["--reconfigure"], Ok(()), vec![], &mut p);
        assert_eq!(r.code, 0, "{}", r.output);
        let default = |q: &str| p.asked.iter().find(|(x, _)| x == q).map(|(_, d)| d.as_str());
        assert_eq!(default("PCE address (host:port)"), Some("pce.example.com:8443"));
        assert_eq!(default("Organization id"), Some("4"));
        assert_eq!(default("API user"), Some("api_1"));
        assert_eq!(default("NetFlow ports (comma-separated)"), Some("2056"));
        assert_eq!(default("NetFlow: accept only from these addresses (empty = any)"), Some("192.0.2.10"));
        // The secret is asked again, never offered.
        assert_eq!(p.secrets, 1);
        assert!(p.asked.iter().all(|(_, d)| !d.contains("s3cret")), "{:?}", p.asked);
        assert_eq!(sys.file(KEY).unwrap().data, b"api_1 n3w-secret\n");
    }

    #[test]
    fn root_prefix_skips_the_health_wait() {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = host();
        let r = run(&mut sys, &argv(&flags(&dir, &["--root", "/tmp/fp-root"])), Ok(()), vec![]);
        assert_eq!(r.code, 0, "{}", r.output);
        assert_eq!(r.health_calls, 0);
        assert!(r.output.contains("health check skipped (--root)"), "{}", r.output);
    }
}
