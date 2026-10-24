//! What an install changes on the host: `plan` compares the wanted files with `Current` and lists the actions,
//! `execute` carries them out in order. A plan for a host that already matches is empty ("unchanged").

use std::fmt;
use std::path::{Path, PathBuf};

use crate::install::answers::Answers;
use crate::install::render;
use crate::install::system::{Owner, System};

pub const BIN: &str = "/usr/local/bin/flowpilot";
pub const BIN_PREV: &str = "/usr/local/bin/flowpilot.prev";
/// Where a new binary is copied before it is renamed over `BIN`.
const BIN_NEW: &str = "/usr/local/bin/flowpilot.new";
const BIN_SWAP: &str = "/usr/local/bin/flowpilot.swap";
pub const CONFIG_DIR: &str = "/etc/flowpilot";
pub const CONFIG: &str = "/etc/flowpilot/config.yaml";
pub const KEY: &str = "/etc/flowpilot/api_key";
pub const DATA_DIR: &str = "/var/lib/flowpilot";
pub const UNIT: &str = "/etc/systemd/system/flowpilot.service";
pub const USER: &str = "flowpilot";

#[derive(Clone, PartialEq, Eq)]
pub enum Action {
    CreateUser,
    Mkdir { path: PathBuf, mode: u32, owner: Owner },
    WriteFile { path: PathBuf, contents: Vec<u8>, mode: u32, owner: Owner },
    /// Copies the current config to `to` before it is rewritten.
    BackupConfig { to: PathBuf },
    /// Copies the running binary to `BIN`, keeping the one there as `BIN_PREV`.
    InstallBinary,
    Restorecon(PathBuf),
    DaemonReload,
    EnableNow,
    Restart,
}

/// Like the derived form, but a file's contents (the key file holds the secret) show only as a length.
impl fmt::Debug for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::CreateUser => f.write_str("CreateUser"),
            Action::Mkdir { path, mode, owner } => write!(f, "Mkdir({}, {mode:04o}, {owner})", path.display()),
            Action::WriteFile { path, contents, mode, owner } => {
                write!(f, "WriteFile({}, {} bytes, {mode:04o}, {owner})", path.display(), contents.len())
            }
            Action::BackupConfig { to } => write!(f, "BackupConfig({})", to.display()),
            Action::InstallBinary => f.write_str("InstallBinary"),
            Action::Restorecon(p) => write!(f, "Restorecon({})", p.display()),
            Action::DaemonReload => f.write_str("DaemonReload"),
            Action::EnableNow => f.write_str("EnableNow"),
            Action::Restart => f.write_str("Restart"),
        }
    }
}

/// One line of the summary shown before the changes are made.
impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::CreateUser => write!(f, "create the system user {USER}"),
            Action::Mkdir { path, mode, owner } => write!(f, "create {} ({mode:04o} {owner})", path.display()),
            Action::WriteFile { path, mode, owner, .. } => write!(f, "write {} ({mode:04o} {owner})", path.display()),
            Action::BackupConfig { to } => write!(f, "save the current config as {}", to.display()),
            Action::InstallBinary => write!(f, "install this binary as {BIN} (the one there is kept as {BIN_PREV})"),
            Action::Restorecon(p) => write!(f, "restore the SELinux label of {}", p.display()),
            Action::DaemonReload => f.write_str("reload systemd"),
            Action::EnableNow => write!(f, "enable and start the {USER} service"),
            Action::Restart => write!(f, "restart the {USER} service"),
        }
    }
}

/// The installed state the plan compares with. Holds the key file, so it has no `Debug`.
#[derive(Clone, Default, PartialEq)]
pub struct Current {
    pub config: Option<Vec<u8>>,
    pub key: Option<Vec<u8>>,
    pub unit: Option<Vec<u8>>,
    /// SHA-256 of the installed binary.
    pub binary_sha256: Option<[u8; 32]>,
    /// SHA-256 of the binary running the installer.
    pub running_sha256: [u8; 32],
    /// What the installed binary prints for `-version`.
    pub binary_version: Option<String>,
    pub user: bool,
    pub config_dir: bool,
    pub data_dir: bool,
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    d.as_ref().try_into().expect("SHA-256 is 32 bytes")
}

impl Current {
    pub fn read(sys: &mut dyn System) -> Result<Current, String> {
        let running = sys.self_bytes().map_err(|e| format!("cannot read the running binary: {e}"))?;
        let installed = sys.read(Path::new(BIN));
        let binary_version = match installed {
            Some(_) => sys.capture(&[BIN, "-version"]).ok().and_then(|out| {
                out.lines().find_map(|l| l.strip_prefix("FlowPilot version:")).map(|v| v.trim().to_string())
            }),
            None => None,
        };
        Ok(Current {
            config: sys.read(Path::new(CONFIG)),
            key: sys.read(Path::new(KEY)),
            unit: sys.read(Path::new(UNIT)),
            binary_sha256: installed.as_deref().map(sha256),
            running_sha256: sha256(&running),
            binary_version,
            user: sys.user_exists(USER),
            config_dir: sys.exists(Path::new(CONFIG_DIR)),
            data_dir: sys.exists(Path::new(DATA_DIR)),
        })
    }
}

/// The choices `plan` needs besides the answers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlanOptions {
    /// Leave the config and key file as they are (an upgrade or a re-run that gives no answers).
    pub keep_config: bool,
    /// `stats.http_listen` of the rendered config.
    pub stats_listen: String,
    /// The UTC time in the backup name, `yyyymmddTHHMMSSZ`.
    pub backup_stamp: String,
}

/// The actions, in order: user, directories, binary, key, config, unit, then systemd. Each one only when the host
/// differs: the binary by content (SHA-256), the files byte for byte with what the answers render.
pub fn plan(a: &Answers, current: &Current, o: &PlanOptions) -> Vec<Action> {
    let mut v = Vec::new();
    if !current.user {
        v.push(Action::CreateUser);
    }
    if !current.config_dir {
        v.push(Action::Mkdir { path: p(CONFIG_DIR), mode: 0o750, owner: Owner::ROOT_FLOWPILOT });
    }
    // The daemon does not create it, and the unit's ReadWritePaths needs it to exist.
    if !current.data_dir {
        v.push(Action::Mkdir { path: p(DATA_DIR), mode: 0o750, owner: Owner::FLOWPILOT });
    }
    let mut restart = false;
    if current.binary_sha256 != Some(current.running_sha256) {
        v.push(Action::InstallBinary);
        v.push(Action::Restorecon(p(BIN)));
        restart = true;
    }
    if !o.keep_config {
        let key = render::api_key_file(a).into_bytes();
        let config = render::config_yaml(a, &o.stats_listen).into_bytes();
        if current.config.as_ref().is_some_and(|c| *c != config) {
            v.push(Action::BackupConfig { to: p(&format!("{CONFIG}.{}.bak", o.backup_stamp)) });
        }
        if current.key.as_ref() != Some(&key) {
            v.push(Action::WriteFile { path: p(KEY), contents: key, mode: 0o640, owner: Owner::ROOT_FLOWPILOT });
            restart = true;
        }
        if current.config.as_ref() != Some(&config) {
            v.push(Action::WriteFile { path: p(CONFIG), contents: config, mode: 0o640, owner: Owner::ROOT_FLOWPILOT });
            restart = true;
        }
    }
    let unit = render::unit(a).into_bytes();
    if current.unit.as_ref() != Some(&unit) {
        v.push(Action::WriteFile { path: p(UNIT), contents: unit, mode: 0o644, owner: Owner::ROOT });
        v.push(Action::DaemonReload);
        restart = true;
    }
    if current.unit.is_none() {
        v.push(Action::EnableNow);
    } else if restart {
        v.push(Action::Restart);
    }
    v
}

/// What `execute` did that is worth telling: skipped steps and where the old config went.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub notes: Vec<String>,
}

/// The step that failed and why; the steps before it stay done.
#[derive(Debug, PartialEq, Eq)]
pub struct ApplyError {
    pub step: String,
    pub error: String,
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Could not {}: {}", self.step, self.error)
    }
}

/// `execute` stopped: `actions[..done]` were carried out, `actions[done]` failed.
#[derive(Debug, PartialEq, Eq)]
pub struct Stopped {
    pub done: usize,
    /// The notes of the steps that were done.
    pub report: Report,
    pub error: ApplyError,
}

pub fn execute(sys: &mut dyn System, actions: &[Action]) -> Result<Report, Stopped> {
    let mut report = Report::default();
    for (done, a) in actions.iter().enumerate() {
        if let Err(error) = step(sys, a, &mut report) {
            return Err(Stopped { done, report, error: ApplyError { step: a.to_string(), error } });
        }
    }
    Ok(report)
}

fn step(sys: &mut dyn System, a: &Action, report: &mut Report) -> Result<(), String> {
    let io = |e: std::io::Error| e.to_string();
    match a {
        Action::CreateUser => {
            let shell = if sys.exists(Path::new("/sbin/nologin")) { "/sbin/nologin" } else { "/usr/sbin/nologin" };
            command(sys, &["useradd", "--system", "--user-group", "--no-create-home", "--shell", shell, USER])
        }
        Action::Mkdir { path, mode, owner } => sys.mkdir(path, *mode, *owner).map_err(io),
        Action::WriteFile { path, contents, mode, owner } => sys.write_atomic(path, contents, *mode, *owner).map_err(io),
        Action::BackupConfig { to } => {
            let old = sys.read(Path::new(CONFIG)).ok_or(format!("{CONFIG} cannot be read"))?;
            sys.write_atomic(to, &old, 0o640, Owner::ROOT_FLOWPILOT).map_err(io)?;
            report.notes.push(format!(
                "The previous config is saved as {}; comments and hand edits in it are not carried over.",
                to.display()
            ));
            Ok(())
        }
        Action::InstallBinary => {
            // Copied next to the target, then renamed over it: the path never holds a partial binary.
            sys.copy_self_to(Path::new(BIN_NEW)).map_err(io)?;
            if sys.exists(Path::new(BIN)) {
                sys.rename(Path::new(BIN), Path::new(BIN_PREV)).map_err(io)?;
            }
            sys.rename(Path::new(BIN_NEW), Path::new(BIN)).map_err(io)
        }
        Action::Restorecon(path) => {
            let path = path.to_string_lossy();
            match sys.run(&["restorecon", "-F", &path]) {
                Ok(0) => {}
                Ok(code) => report.notes.push(format!("restorecon -F {path} exited with {code}; check the label with ls -Z.")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    report.notes.push(format!("restorecon not found: the SELinux label of {path} was not restored."))
                }
                Err(e) => return Err(e.to_string()),
            }
            Ok(())
        }
        Action::DaemonReload => command(sys, &["systemctl", "daemon-reload"]),
        Action::EnableNow => command(sys, &["systemctl", "enable", "--now", USER]),
        Action::Restart => command(sys, &["systemctl", "restart", USER]),
    }
}

/// Runs a command that must succeed.
fn command(sys: &mut dyn System, argv: &[&str]) -> Result<(), String> {
    match sys.run(argv) {
        Ok(0) => Ok(()),
        Ok(code) => Err(format!("{} exited with {code}", argv.join(" "))),
        Err(e) => Err(format!("{}: {e}", argv[0])),
    }
}

/// Puts `BIN_PREV` back as `BIN` and restarts the service (after an upgrade that did not come up healthy).
pub fn restore_previous(sys: &mut dyn System) -> Result<(), ApplyError> {
    sys.rename(Path::new(BIN_PREV), Path::new(BIN))
        .map_err(|e| ApplyError { step: format!("put {BIN_PREV} back as {BIN}"), error: e.to_string() })?;
    restart_clean(sys)
}

/// Exchanges `BIN` and `BIN_PREV` and restarts the service (`flowpilot rollback`): unlike `restore_previous` the
/// binary it replaces is kept as `.prev`, so a second rollback undoes the first.
pub fn swap_previous(sys: &mut dyn System) -> Result<(), ApplyError> {
    let (bin, prev, tmp) = (Path::new(BIN), Path::new(BIN_PREV), Path::new(BIN_SWAP));
    let fail = |step: &str, e: std::io::Error| ApplyError { step: step.into(), error: e.to_string() };
    sys.rename(bin, tmp).map_err(|e| fail(&format!("move {BIN} aside"), e))?;
    if let Err(e) = sys.rename(prev, bin) {
        let _ = sys.rename(tmp, bin);
        return Err(fail(&format!("put {BIN_PREV} back as {BIN}"), e));
    }
    sys.rename(tmp, prev).map_err(|e| fail(&format!("keep the replaced binary as {BIN_PREV}"), e))?;
    restart_clean(sys)
}

fn restart_clean(sys: &mut dyn System) -> Result<(), ApplyError> {
    // A crash-looping new version may have used up the unit's start limit; a restart would then be refused.
    let _ = sys.run(&["systemctl", "reset-failed", USER]);
    command(sys, &["systemctl", "restart", USER])
        .map_err(|error| ApplyError { step: Action::Restart.to_string(), error })
}

fn p(s: &str) -> PathBuf {
    Path::new(s).to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Secret;
    use crate::install::args::{CollectorArg, CollectorKind, TextArgs};
    use crate::install::system::FakeSystem;

    pub(crate) fn answers() -> Answers {
        Answers {
            pce_addr: "pce.example.com:8443".into(),
            org_id: 1,
            api_user: "api_1".into(),
            api_secret: Secret("s3cret".into()),
            collectors: vec![CollectorArg { kind: CollectorKind::Netflow, ports: "2055".into(), remote_addrs: None }],
            text: TextArgs::default(),
            unmanaged: None,
            verify_pce_cert: true,
            proxy: Default::default(),
        }
    }

    fn opts() -> PlanOptions {
        PlanOptions { keep_config: false, stats_listen: "127.0.0.1:9180".into(), backup_stamp: "20261024T101500Z".into() }
    }

    fn fresh() -> Current {
        Current { running_sha256: sha256(b"binary 0.9.0"), ..Default::default() }
    }

    /// The host after `plan(answers(), fresh())` ran.
    fn installed(a: &Answers) -> Current {
        Current {
            config: Some(render::config_yaml(a, "127.0.0.1:9180").into_bytes()),
            key: Some(render::api_key_file(a).into_bytes()),
            unit: Some(render::unit(a).into_bytes()),
            binary_sha256: Some(sha256(b"binary 0.9.0")),
            running_sha256: sha256(b"binary 0.9.0"),
            binary_version: Some("0.9.0".into()),
            user: true,
            config_dir: true,
            data_dir: true,
        }
    }

    #[test]
    fn fresh_install_plan() {
        let a = answers();
        let got = plan(&a, &fresh(), &opts());
        let want = vec![
            Action::CreateUser,
            Action::Mkdir { path: p(CONFIG_DIR), mode: 0o750, owner: Owner::ROOT_FLOWPILOT },
            Action::Mkdir { path: p(DATA_DIR), mode: 0o750, owner: Owner::FLOWPILOT },
            Action::InstallBinary,
            Action::Restorecon(p(BIN)),
            Action::WriteFile {
                path: p(KEY),
                contents: b"api_1 s3cret\n".to_vec(),
                mode: 0o640,
                owner: Owner::ROOT_FLOWPILOT,
            },
            Action::WriteFile {
                path: p(CONFIG),
                contents: render::config_yaml(&a, "127.0.0.1:9180").into_bytes(),
                mode: 0o640,
                owner: Owner::ROOT_FLOWPILOT,
            },
            Action::WriteFile { path: p(UNIT), contents: render::unit(&a).into_bytes(), mode: 0o644, owner: Owner::ROOT },
            Action::DaemonReload,
            Action::EnableNow,
        ];
        assert_eq!(got, want);
    }

    #[test]
    fn rerun_plan_is_empty() {
        assert_eq!(plan(&answers(), &installed(&answers()), &opts()), vec![]);
    }

    #[test]
    fn changed_answers_back_up_then_rewrite_and_restart() {
        let mut a = answers();
        a.collectors[0].ports = "2056".into();
        let got = plan(&a, &installed(&answers()), &opts());
        assert_eq!(got[0], Action::BackupConfig { to: p("/etc/flowpilot/config.yaml.20261024T101500Z.bak") });
        assert!(matches!(&got[1], Action::WriteFile { path, .. } if path == Path::new(CONFIG)));
        assert_eq!(got.last(), Some(&Action::Restart));
        // Only the config changed: no key, no unit, no daemon-reload.
        assert_eq!(got.len(), 3, "{got:?}");
    }

    #[test]
    fn low_port_rewrites_unit_and_reloads() {
        let mut a = answers();
        a.collectors[0].ports = "514".into();
        let got = plan(&a, &installed(&answers()), &opts());
        let unit = got.iter().position(|x| matches!(x, Action::WriteFile { path, .. } if path == Path::new(UNIT)));
        let reload = got.iter().position(|x| *x == Action::DaemonReload);
        assert!(unit.is_some() && reload > unit, "{got:?}");
        assert_eq!(got.last(), Some(&Action::Restart));
    }

    #[test]
    fn new_binary_with_kept_config() {
        let mut cur = installed(&answers());
        cur.config = Some(b"# hand edited\npce_addr: other:443\n".to_vec());
        cur.running_sha256 = sha256(b"binary 2.0.2");
        let o = PlanOptions { keep_config: true, ..opts() };
        assert_eq!(plan(&answers(), &cur, &o), vec![Action::InstallBinary, Action::Restorecon(p(BIN)), Action::Restart]);
    }

    #[test]
    fn action_debug_hides_contents() {
        let w = Action::WriteFile { path: p(KEY), contents: b"api_1 s3cret\n".to_vec(), mode: 0o640, owner: Owner::ROOT_FLOWPILOT };
        let s = format!("{w:?} {w}");
        assert!(!s.contains("s3cret"), "{s}");
    }

    #[test]
    fn execute_fresh_plan_on_fake() {
        let a = answers();
        let mut sys = FakeSystem::new("0.9.0");
        sys.put("/sbin/nologin", b"", 0o755, Owner::ROOT);
        sys.missing.push("restorecon");
        let actions = plan(&a, &fresh(), &opts());
        let report = execute(&mut sys, &actions).unwrap();
        assert_eq!(
            sys.log,
            [
                "run useradd --system --user-group --no-create-home --shell /sbin/nologin flowpilot",
                "mkdir /etc/flowpilot 0750 root:flowpilot",
                "mkdir /var/lib/flowpilot 0750 flowpilot:flowpilot",
                "copy-self /usr/local/bin/flowpilot.new",
                "rename /usr/local/bin/flowpilot.new /usr/local/bin/flowpilot",
                "write /etc/flowpilot/api_key 0640 root:flowpilot",
                "write /etc/flowpilot/config.yaml 0640 root:flowpilot",
                "write /etc/systemd/system/flowpilot.service 0644 root:root",
                "run systemctl daemon-reload",
                "run systemctl enable --now flowpilot",
            ]
        );
        assert!(report.notes.iter().any(|n| n.contains("restorecon")), "{report:?}");
        assert_eq!(sys.file(KEY).unwrap().data, b"api_1 s3cret\n");
    }

    #[test]
    fn execute_reports_how_far_it_got() {
        let mut sys = FakeSystem::new("2.0.2");
        sys.put(BIN, b"binary 0.9.0", 0o755, Owner::ROOT);
        sys.fail_once.push("systemctl daemon-reload".into());
        let actions = [Action::InstallBinary, Action::Restorecon(p(BIN)), Action::DaemonReload, Action::Restart];
        let stopped = execute(&mut sys, &actions).unwrap_err();
        assert_eq!(stopped.done, 2);
        assert_eq!(stopped.error.step, "reload systemd");
        assert!(stopped.error.to_string().contains("systemctl daemon-reload exited with 1"), "{}", stopped.error);
        assert!(!sys.log.iter().any(|l| l == "run systemctl restart flowpilot"), "{:?}", sys.log);
    }

    #[test]
    fn execute_uses_usr_sbin_nologin_when_only_that_exists() {
        let mut sys = FakeSystem::new("0.9.0");
        sys.put("/usr/sbin/nologin", b"", 0o755, Owner::ROOT);
        execute(&mut sys, &[Action::CreateUser]).unwrap();
        assert_eq!(sys.log, ["run useradd --system --user-group --no-create-home --shell /usr/sbin/nologin flowpilot"]);
    }

    #[test]
    fn execute_backup_copies_old_config_and_keeps_prev_binary() {
        let mut sys = FakeSystem::new("2.0.2");
        sys.put(CONFIG, b"old: 1\n", 0o640, Owner::ROOT_FLOWPILOT);
        sys.put(BIN, b"binary 0.9.0", 0o755, Owner::ROOT);
        let to = p("/etc/flowpilot/config.yaml.20261024T101500Z.bak");
        let report = execute(&mut sys, &[Action::BackupConfig { to: to.clone() }, Action::InstallBinary]).unwrap();
        assert_eq!(sys.files[&to].data, b"old: 1\n");
        assert_eq!(sys.file(BIN_PREV).unwrap().data, b"binary 0.9.0");
        assert_eq!(sys.file(BIN).unwrap().data, b"binary 2.0.2");
        assert!(report.notes.iter().any(|n| n.contains("config.yaml.20261024T101500Z.bak")));
    }
}
