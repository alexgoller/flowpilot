//! `flowpilot uninstall [--purge]` and `flowpilot rollback`.
//!
//! Uninstall removes the service, the unit and the binaries and reports each item as removed or already absent, so it
//! can be run again after a partial removal. Config, key and data stay unless `--purge`, which asks first.

use std::io::{IsTerminal, Write};
use std::path::Path;

use crate::install::apply::{self, BIN, BIN_PREV, CONFIG, CONFIG_DIR, DATA_DIR, UNIT, USER};
use crate::install::args::UninstallArgs;
use crate::install::health::{wait_healthy, HEALTH_TIMEOUT};
use crate::install::run::stats_listen_of;
use crate::install::system::{RealSystem, System};
use crate::install::wizard::{DialoguerPrompter, Prompter, WizardError};

/// Writes a line; a closed stdout or stderr is no reason to stop half-way.
macro_rules! say {
    ($w:expr, $($t:tt)*) => {{ let _ = writeln!($w, $($t)*); }};
}

pub fn run_uninstall(args: UninstallArgs) -> i32 {
    let mut sys = RealSystem::new(args.root.clone().unwrap_or_else(|| "/".into()));
    let interactive = std::io::stdin().is_terminal();
    run_uninstall_with(&mut sys, &mut DialoguerPrompter, interactive, &mut std::io::stdout(), &mut std::io::stderr(), args)
}

pub fn run_uninstall_with(
    sys: &mut dyn System,
    prompter: &mut dyn Prompter,
    interactive: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
    args: UninstallArgs,
) -> i32 {
    if !sys.is_root() {
        say!(err, "flowpilot uninstall must run as root; try: sudo flowpilot uninstall");
        return 1;
    }
    // Asked before anything is touched: a refusal or a "no" leaves the host as it was.
    if args.purge && !args.yes {
        if !interactive {
            say!(err, "--purge deletes {CONFIG_DIR}, {DATA_DIR} and the {USER} user; add --yes to do that without asking.");
            return 2;
        }
        let q = format!("Also delete {CONFIG_DIR} (config and API key), {DATA_DIR} and the {USER} user? This cannot be undone");
        match prompter.confirm(&q, false) {
            Ok(true) => {}
            Ok(false) => {
                say!(err, "{}", WizardError::Aborted);
                return 2;
            }
            Err(e) => {
                say!(err, "{e}");
                return 2;
            }
        }
    }

    let mut failed = false;
    // A missing unit makes `systemctl disable` exit 5; a host without systemctl has nothing to stop either.
    match sys.run(&["systemctl", "disable", "--now", USER]) {
        Ok(0) => say!(out, "service: stopped and disabled"),
        Ok(code) => say!(out, "service: not running or not installed (systemctl exited with {code})"),
        Err(e) => say!(out, "service: not stopped ({e})"),
    }
    remove(sys, out, err, &mut failed, UNIT, "unit");
    match sys.run(&["systemctl", "daemon-reload"]) {
        Ok(0) => {}
        Ok(code) => say!(err, "systemctl daemon-reload exited with {code}"),
        Err(e) => say!(err, "systemctl daemon-reload: {e}"),
    }
    remove(sys, out, err, &mut failed, BIN, "binary");
    remove(sys, out, err, &mut failed, BIN_PREV, "previous binary");

    if args.purge {
        remove(sys, out, err, &mut failed, CONFIG_DIR, "config");
        remove(sys, out, err, &mut failed, DATA_DIR, "data");
        if sys.user_exists(USER) {
            match sys.run(&["userdel", USER]) {
                Ok(0) => say!(out, "user: removed ({USER})"),
                Ok(code) => {
                    say!(err, "user: userdel {USER} exited with {code}");
                    failed = true;
                }
                Err(e) => {
                    say!(err, "user: userdel {USER}: {e}");
                    failed = true;
                }
            }
        } else {
            say!(out, "user: already absent ({USER})");
        }
    } else {
        say!(out, "Kept {CONFIG_DIR} and {DATA_DIR}; --purge removes them and the {USER} user.");
    }
    i32::from(failed)
}

/// Removes `path` if it is there and says which; a removal that fails is reported and sets `failed`.
fn remove(sys: &mut dyn System, out: &mut dyn Write, err: &mut dyn Write, failed: &mut bool, path: &str, what: &str) {
    if !sys.exists(Path::new(path)) {
        say!(out, "{what}: already absent ({path})");
        return;
    }
    match sys.remove(Path::new(path)) {
        Ok(()) => say!(out, "{what}: removed ({path})"),
        Err(e) => {
            say!(err, "{what}: cannot remove {path}: {e}");
            *failed = true;
        }
    }
}

pub fn run_rollback() -> i32 {
    let mut sys = RealSystem::new("/");
    run_rollback_with(&mut sys, &mut |listen| wait_healthy(listen, HEALTH_TIMEOUT), &mut std::io::stdout(), &mut std::io::stderr())
}

pub fn run_rollback_with(
    sys: &mut dyn System,
    health: &mut dyn FnMut(&str) -> Result<String, String>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    if !sys.is_root() {
        say!(err, "flowpilot rollback must run as root; try: sudo flowpilot rollback");
        return 1;
    }
    if !sys.exists(Path::new(BIN_PREV)) {
        say!(err, "no previous version to roll back to");
        return 1;
    }
    if let Err(e) = apply::swap_previous(sys) {
        say!(err, "{e}");
        return 1;
    }
    say!(out, "Switched {BIN} back to the previous version (the one replaced is kept as {BIN_PREV}).");
    let Some(listen) = sys.read(Path::new(CONFIG)).as_deref().and_then(stats_listen_of) else {
        say!(out, "The config has no stats.http_listen, so the service's health was not checked.");
        return 0;
    };
    say!(out, "Waiting for FlowPilot to report healthy on {listen} ...");
    match health(&listen) {
        Ok(status) => {
            say!(out, "FlowPilot is running (status: {status}).");
            0
        }
        Err(e) => {
            say!(err, "FlowPilot did not report healthy after the rollback ({e}). See: journalctl -u flowpilot");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::system::{FakeSystem, Owner};

    struct Answer(Option<bool>);

    impl Prompter for Answer {
        fn text(&mut self, q: &str, _: Option<&str>) -> Result<String, WizardError> {
            panic!("asked {q}")
        }
        fn secret(&mut self, q: &str) -> Result<String, WizardError> {
            panic!("asked {q}")
        }
        fn confirm(&mut self, q: &str, default: bool) -> Result<bool, WizardError> {
            assert!(!default, "a purge must default to no: {q}");
            Ok(self.0.take().unwrap_or_else(|| panic!("asked {q}")))
        }
    }

    /// A fully installed host with a previous binary.
    fn installed() -> FakeSystem {
        let mut sys = FakeSystem::new("0.9.0");
        sys.put(BIN, b"binary 0.9.0", 0o755, Owner::ROOT);
        sys.put(BIN_PREV, b"binary 2.0.0", 0o755, Owner::ROOT);
        sys.put(UNIT, b"[Unit]", 0o644, Owner::ROOT);
        sys.put(CONFIG, b"stats:\n  http_listen: 127.0.0.1:9180\n", 0o640, Owner::ROOT_FLOWPILOT);
        sys.put("/etc/flowpilot/api_key", b"u s\n", 0o640, Owner::ROOT_FLOWPILOT);
        sys.put("/var/lib/flowpilot/state", b"x", 0o640, Owner::FLOWPILOT);
        sys.dirs.insert(CONFIG_DIR.into(), (0o750, Owner::ROOT_FLOWPILOT));
        sys.dirs.insert(DATA_DIR.into(), (0o750, Owner::FLOWPILOT));
        sys.users.insert(USER.into());
        sys
    }

    fn uninstall(sys: &mut FakeSystem, args: UninstallArgs, interactive: bool, answer: Option<bool>) -> (i32, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_uninstall_with(sys, &mut Answer(answer), interactive, &mut out, &mut err, args);
        (code, format!("{}{}", String::from_utf8_lossy(&out), String::from_utf8_lossy(&err)))
    }

    fn rollback(sys: &mut FakeSystem, health: Result<String, String>) -> (i32, String, Vec<String>) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut asked = Vec::new();
        let code = run_rollback_with(
            sys,
            &mut |l| {
                asked.push(l.to_string());
                health.clone()
            },
            &mut out,
            &mut err,
        );
        (code, format!("{}{}", String::from_utf8_lossy(&out), String::from_utf8_lossy(&err)), asked)
    }

    #[test]
    fn uninstall_keeps_config_and_data() {
        let mut sys = installed();
        let (code, output) = uninstall(&mut sys, UninstallArgs::default(), false, None);
        assert_eq!(code, 0, "{output}");
        assert_eq!(
            sys.log,
            [
                "run systemctl disable --now flowpilot",
                "remove /etc/systemd/system/flowpilot.service",
                "run systemctl daemon-reload",
                "remove /usr/local/bin/flowpilot",
                "remove /usr/local/bin/flowpilot.prev",
            ]
        );
        assert!(sys.exists(Path::new(CONFIG)) && sys.exists(Path::new(DATA_DIR)) && sys.user_exists(USER));
        assert!(output.contains("Kept /etc/flowpilot"), "{output}");
    }

    #[test]
    fn purge_removes_everything_after_confirmation() {
        let mut sys = installed();
        let args = UninstallArgs { purge: true, ..Default::default() };
        let (code, output) = uninstall(&mut sys, args.clone(), true, Some(true));
        assert_eq!(code, 0, "{output}");
        assert!(sys.files.is_empty() && sys.dirs.is_empty(), "{:?}", sys.files.keys());
        assert_eq!(sys.log.last().unwrap(), "run userdel flowpilot");
        assert!(output.contains("config: removed") && output.contains("data: removed"), "{output}");

        // Declined: nothing happens.
        let mut sys = installed();
        let (code, _) = uninstall(&mut sys, args.clone(), true, Some(false));
        assert_eq!(code, 2);
        assert!(sys.log.is_empty());

        // --yes never asks.
        let mut sys = installed();
        let (code, output) = uninstall(&mut sys, UninstallArgs { yes: true, ..args }, false, None);
        assert_eq!(code, 0, "{output}");
        assert!(sys.files.is_empty());
    }

    #[test]
    fn purge_without_yes_noninteractive_refuses() {
        let mut sys = installed();
        let args = UninstallArgs { purge: true, ..Default::default() };
        let (code, output) = uninstall(&mut sys, args, false, None);
        assert_eq!(code, 2, "{output}");
        assert!(sys.log.is_empty() && sys.files.len() == 6, "{:?}", sys.log);
        assert!(output.contains("--yes"), "{output}");
    }

    #[test]
    fn uninstall_tolerates_missing_unit() {
        let mut sys = installed();
        sys.files.remove(Path::new(UNIT));
        sys.files.remove(Path::new(BIN_PREV));
        let (code, output) = uninstall(&mut sys, UninstallArgs::default(), false, None);
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("unit: already absent"), "{output}");
        assert!(output.contains("previous binary: already absent"), "{output}");
        assert!(output.contains("binary: removed"), "{output}");
        assert!(!sys.exists(Path::new(BIN)));

        // Run again, purging, then once more on the empty host: still 0.
        let purge = UninstallArgs { purge: true, yes: true, root: None };
        let (code, output) = uninstall(&mut sys, purge.clone(), false, None);
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("user: removed"), "{output}");
        sys.users.clear();
        let (code, output) = uninstall(&mut sys, purge, false, None);
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("user: already absent") && output.contains("config: already absent"), "{output}");
    }

    #[test]
    fn uninstall_needs_root() {
        let mut sys = installed();
        sys.root = false;
        assert_eq!(uninstall(&mut sys, UninstallArgs::default(), false, None).0, 1);
        assert!(sys.log.is_empty());
    }

    #[test]
    fn rollback_swaps_prev() {
        let mut sys = installed();
        let (code, output, asked) = rollback(&mut sys, Ok("ok".into()));
        assert_eq!(code, 0, "{output}");
        assert_eq!(sys.file(BIN).unwrap().data, b"binary 2.0.0");
        assert_eq!(sys.file(BIN_PREV).unwrap().data, b"binary 0.9.0");
        assert_eq!(sys.log.last().unwrap(), "run systemctl restart flowpilot");
        assert!(sys.log.contains(&"run systemctl reset-failed flowpilot".to_string()));
        assert_eq!(asked, ["127.0.0.1:9180"]);
        assert!(output.contains("status: ok"), "{output}");

        // Unhealthy: exit 1, still swapped.
        let mut sys = installed();
        let (code, output, _) = rollback(&mut sys, Err("connection refused".into()));
        assert_eq!(code, 1);
        assert!(output.contains("connection refused") && output.contains("journalctl"), "{output}");

        // No stats.http_listen: nothing to wait for.
        let mut sys = installed();
        sys.put(CONFIG, b"{}\n", 0o640, Owner::ROOT_FLOWPILOT);
        let (code, output, asked) = rollback(&mut sys, Ok("ok".into()));
        assert_eq!((code, asked.len()), (0, 0));
        assert!(output.contains("health was not checked"), "{output}");
    }

    #[test]
    fn rollback_without_prev_fails() {
        let mut sys = installed();
        sys.files.remove(Path::new(BIN_PREV));
        let (code, output, _) = rollback(&mut sys, Ok("ok".into()));
        assert_eq!(code, 1);
        assert!(output.contains("no previous version to roll back to"), "{output}");
        assert!(sys.log.is_empty());
    }
}
