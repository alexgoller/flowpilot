//! The host as the installer sees it: files, the flowpilot user, commands, root and systemd. `RealSystem` acts on the
//! machine; `FakeSystem` (tests) keeps everything in memory and records each change, so no test touches the host.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::install::render::Firewall;

/// Who owns a file or directory, by user and group name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    pub user: &'static str,
    pub group: &'static str,
}

impl Owner {
    pub const ROOT: Owner = Owner { user: "root", group: "root" };
    /// Root-owned, readable by the service through its group.
    pub const ROOT_FLOWPILOT: Owner = Owner { user: "root", group: "flowpilot" };
    pub const FLOWPILOT: Owner = Owner { user: "flowpilot", group: "flowpilot" };
}

impl std::fmt::Display for Owner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.user, self.group)
    }
}

pub trait System {
    /// A file's content; `None` when it is missing or unreadable.
    fn read(&self, p: &Path) -> Option<Vec<u8>>;
    /// True when anything (file, directory, link) is at `p`.
    fn exists(&self, p: &Path) -> bool;
    /// Writes a temporary file next to `p` with `mode` and `owner`, then renames it over `p`.
    fn write_atomic(&mut self, p: &Path, data: &[u8], mode: u32, owner: Owner) -> io::Result<()>;
    /// Creates `p` (and missing parents) and sets its mode and owner.
    fn mkdir(&mut self, p: &Path, mode: u32, owner: Owner) -> io::Result<()>;
    /// The running binary's content.
    fn self_bytes(&self) -> io::Result<Vec<u8>>;
    /// Copies the running binary to `p`, mode 0755, owned by root.
    fn copy_self_to(&mut self, p: &Path) -> io::Result<()>;
    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()>;
    /// Removes a file, or a directory with everything in it.
    fn remove(&mut self, p: &Path) -> io::Result<()>;
    /// Runs a command; its exit code. A missing program is `Err` of kind `NotFound`. Never pass a secret in `argv`.
    fn run(&mut self, argv: &[&str]) -> io::Result<i32>;
    /// Runs a command and returns its standard output; a non-zero exit is an error.
    fn capture(&mut self, argv: &[&str]) -> io::Result<String>;
    fn user_exists(&self, name: &str) -> bool;
    fn is_root(&self) -> bool;
    fn has_systemd(&self) -> bool;
    /// `systemctl is-active <unit>`: `active`, `inactive`, `failed`, ...; `unknown` when it cannot be asked.
    fn service_state(&self, unit: &str) -> String;
    fn active_firewall(&self) -> Firewall;
    /// True when `127.0.0.1:port` can be bound now.
    fn port_free(&self, port: u16) -> bool;
}

/// The machine. Every file path is prefixed by `root` (`/` normally; `--root` is a test and dry-run prefix). With a
/// root other than `/` no command runs: `run` prints `would run: <argv>` and succeeds, `capture` fails, and no
/// firewall is detected, so trying the installer out never changes the host itself.
pub struct RealSystem {
    pub root: PathBuf,
}

impl RealSystem {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        RealSystem { root: root.into() }
    }

    /// True for a `--root` other than `/`: commands are only printed.
    pub fn dry_run(&self) -> bool {
        self.root != Path::new("/")
    }

    fn host(&self, p: &Path) -> PathBuf {
        self.root.join(p.strip_prefix("/").unwrap_or(p))
    }

    fn command(argv: &[&str]) -> io::Result<Command> {
        let (prog, args) = argv.split_first().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty command"))?;
        let mut c = Command::new(prog);
        // The secret may have come in by variable; children have no use for it.
        c.args(args).stdin(Stdio::null()).env_remove("FLOWPILOT_API_SECRET");
        Ok(c)
    }
}

fn not_found(what: &str, name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("no {what} named {name}"))
}

fn uid_of(name: &str) -> io::Result<u32> {
    let c = CString::new(name).map_err(|_| not_found("user", name))?;
    // SAFETY: getpwnam takes a NUL-terminated name; the result is read at once, before any other passwd call.
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        return Err(not_found("user", name));
    }
    Ok(unsafe { (*pw).pw_uid })
}

fn gid_of(name: &str) -> io::Result<u32> {
    let c = CString::new(name).map_err(|_| not_found("group", name))?;
    // SAFETY: as in `uid_of`, for the group database.
    let gr = unsafe { libc::getgrnam(c.as_ptr()) };
    if gr.is_null() {
        return Err(not_found("group", name));
    }
    Ok(unsafe { (*gr).gr_gid })
}

fn chown(p: &Path, owner: Owner) -> io::Result<()> {
    std::os::unix::fs::chown(p, Some(uid_of(owner.user)?), Some(gid_of(owner.group)?))
}

/// The temporary sibling `p` is written to before the rename.
fn temp_of(p: &Path) -> PathBuf {
    let mut name = p.file_name().unwrap_or_default().to_os_string();
    name.push(".flowpilot-new");
    p.with_file_name(name)
}

impl System for RealSystem {
    fn read(&self, p: &Path) -> Option<Vec<u8>> {
        fs::read(self.host(p)).ok()
    }

    fn exists(&self, p: &Path) -> bool {
        fs::symlink_metadata(self.host(p)).is_ok()
    }

    fn write_atomic(&mut self, p: &Path, data: &[u8], mode: u32, owner: Owner) -> io::Result<()> {
        let target = self.host(p);
        let tmp = temp_of(&target);
        let _ = fs::remove_file(&tmp);
        // Created 0600 and only opened up to `mode` once the owner is set: a secret is never readable by others.
        let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        let result = (|| {
            f.write_all(data)?;
            std::os::unix::fs::fchown(&f, Some(uid_of(owner.user)?), Some(gid_of(owner.group)?))?;
            f.set_permissions(fs::Permissions::from_mode(mode))?;
            f.sync_all()?;
            fs::rename(&tmp, &target)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result?;
        if let Some(dir) = target.parent() {
            File::open(dir)?.sync_all()?;
        }
        Ok(())
    }

    fn mkdir(&mut self, p: &Path, mode: u32, owner: Owner) -> io::Result<()> {
        let p = self.host(p);
        fs::create_dir_all(&p)?;
        chown(&p, owner)?;
        fs::set_permissions(&p, fs::Permissions::from_mode(mode))
    }

    fn self_bytes(&self) -> io::Result<Vec<u8>> {
        fs::read(std::env::current_exe()?)
    }

    fn copy_self_to(&mut self, p: &Path) -> io::Result<()> {
        let data = self.self_bytes()?;
        self.write_atomic(p, &data, 0o755, Owner::ROOT)
    }

    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(self.host(from), self.host(to))
    }

    fn remove(&mut self, p: &Path) -> io::Result<()> {
        let p = self.host(p);
        if fs::symlink_metadata(&p)?.is_dir() {
            fs::remove_dir_all(p)
        } else {
            fs::remove_file(p)
        }
    }

    fn run(&mut self, argv: &[&str]) -> io::Result<i32> {
        if self.dry_run() {
            println!("would run: {}", argv.join(" "));
            return Ok(0);
        }
        let status = Self::command(argv)?.status()?;
        Ok(status.code().unwrap_or(-1))
    }

    fn capture(&mut self, argv: &[&str]) -> io::Result<String> {
        if self.dry_run() {
            println!("would run: {}", argv.join(" "));
            return Err(io::Error::other("not run under --root"));
        }
        let out = Self::command(argv)?.stderr(Stdio::null()).output()?;
        if !out.status.success() {
            return Err(io::Error::other(format!("{} exited with {}", argv[0], out.status)));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn user_exists(&self, name: &str) -> bool {
        uid_of(name).is_ok()
    }

    fn is_root(&self) -> bool {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }

    fn has_systemd(&self) -> bool {
        // sd_booted(3): systemd is PID 1 exactly when this directory exists.
        Path::new("/run/systemd/system").is_dir()
    }

    fn service_state(&self, unit: &str) -> String {
        if self.dry_run() {
            return "unknown".into();
        }
        // Exits non-zero for every state but `active`, so the word on stdout is read whatever the exit code.
        let out = Self::command(&["systemctl", "is-active", unit]).and_then(|mut c| c.stderr(Stdio::null()).output());
        out.ok().and_then(|o| String::from_utf8_lossy(&o.stdout).lines().next().map(|l| l.trim().to_string())).filter(|l| !l.is_empty()).unwrap_or_else(|| "unknown".into())
    }

    fn active_firewall(&self) -> Firewall {
        if self.dry_run() {
            return Firewall::None;
        }
        let quiet = |argv: &[&str]| {
            Self::command(argv)
                .and_then(|mut c| c.stdout(Stdio::null()).stderr(Stdio::null()).status())
                .is_ok_and(|s| s.success())
        };
        if quiet(&["systemctl", "is-active", "--quiet", "firewalld"]) {
            return Firewall::Firewalld;
        }
        let ufw = Self::command(&["ufw", "status"]).and_then(|mut c| c.stderr(Stdio::null()).output());
        if ufw.is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("Status: active")) {
            return Firewall::Ufw;
        }
        if quiet(&["systemctl", "is-active", "--quiet", "nftables"]) {
            return Firewall::Nftables;
        }
        Firewall::None
    }

    fn port_free(&self, port: u16) -> bool {
        std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_prefix_never_runs_commands() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("executed");
        let mut sys = RealSystem::new(dir.path());
        let m = marker.to_str().unwrap();
        assert_eq!(sys.run(&["touch", m]).unwrap(), 0);
        assert_eq!(sys.run(&["systemctl", "daemon-reload"]).unwrap(), 0);
        assert!(sys.capture(&["touch", m]).is_err());
        assert!(!marker.exists());
        assert_eq!(sys.active_firewall(), Firewall::None);
        // Paths land under the root.
        assert_eq!(sys.host(Path::new("/etc/flowpilot/config.yaml")), dir.path().join("etc/flowpilot/config.yaml"));
        assert!(!RealSystem::new("/").dry_run());
    }
}

#[cfg(test)]
pub use fake::FakeSystem;

#[cfg(test)]
mod fake {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct FakeFile {
        pub data: Vec<u8>,
        pub mode: u32,
        pub owner: Owner,
    }

    /// An in-memory host. `log` records every change and command, one line each, in order; reads are not recorded.
    /// A fake binary's content is `binary <version>`; `<binary> -version` answers with that version.
    pub struct FakeSystem {
        pub files: BTreeMap<PathBuf, FakeFile>,
        pub dirs: BTreeMap<PathBuf, (u32, Owner)>,
        pub log: Vec<String>,
        pub root: bool,
        pub systemd: bool,
        pub users: BTreeSet<String>,
        pub self_bin: Vec<u8>,
        pub firewall: Firewall,
        /// Programs that are not installed.
        pub missing: Vec<&'static str>,
        pub busy_ports: Vec<u16>,
        /// What `systemctl is-active` answers.
        pub service_state: String,
        /// Files that exist but cannot be read by this user.
        pub unreadable: Vec<PathBuf>,
        /// Commands (argv joined by spaces) that exit 1 the next time they run, once each.
        pub fail_once: Vec<String>,
    }

    impl FakeSystem {
        /// A fresh root systemd host running binary `version`.
        pub fn new(version: &str) -> Self {
            FakeSystem {
                files: BTreeMap::new(),
                dirs: BTreeMap::new(),
                log: Vec::new(),
                root: true,
                systemd: true,
                users: BTreeSet::new(),
                self_bin: format!("binary {version}").into_bytes(),
                firewall: Firewall::Firewalld,
                missing: Vec::new(),
                busy_ports: Vec::new(),
                service_state: "active".into(),
                unreadable: Vec::new(),
                fail_once: Vec::new(),
            }
        }

        pub fn put(&mut self, p: &str, data: &[u8], mode: u32, owner: Owner) {
            self.files.insert(p.into(), FakeFile { data: data.to_vec(), mode, owner });
        }

        pub fn file(&self, p: &str) -> Option<&FakeFile> {
            self.files.get(Path::new(p))
        }
    }

    impl System for FakeSystem {
        fn read(&self, p: &Path) -> Option<Vec<u8>> {
            self.files.get(p).filter(|_| !self.unreadable.iter().any(|u| u == p)).map(|f| f.data.clone())
        }

        fn exists(&self, p: &Path) -> bool {
            self.files.contains_key(p) || self.dirs.contains_key(p)
        }

        fn write_atomic(&mut self, p: &Path, data: &[u8], mode: u32, owner: Owner) -> io::Result<()> {
            self.log.push(format!("write {} {mode:04o} {owner}", p.display()));
            self.files.insert(p.into(), FakeFile { data: data.to_vec(), mode, owner });
            Ok(())
        }

        fn mkdir(&mut self, p: &Path, mode: u32, owner: Owner) -> io::Result<()> {
            self.log.push(format!("mkdir {} {mode:04o} {owner}", p.display()));
            self.dirs.insert(p.into(), (mode, owner));
            Ok(())
        }

        fn self_bytes(&self) -> io::Result<Vec<u8>> {
            Ok(self.self_bin.clone())
        }

        fn copy_self_to(&mut self, p: &Path) -> io::Result<()> {
            self.log.push(format!("copy-self {}", p.display()));
            self.files.insert(p.into(), FakeFile { data: self.self_bin.clone(), mode: 0o755, owner: Owner::ROOT });
            Ok(())
        }

        fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
            self.log.push(format!("rename {} {}", from.display(), to.display()));
            let f = self.files.remove(from).ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            self.files.insert(to.into(), f);
            Ok(())
        }

        fn remove(&mut self, p: &Path) -> io::Result<()> {
            self.log.push(format!("remove {}", p.display()));
            let found = self.files.remove(p).is_some() | self.dirs.remove(p).is_some();
            self.files.retain(|k, _| !k.starts_with(p));
            self.dirs.retain(|k, _| !k.starts_with(p));
            if found { Ok(()) } else { Err(io::ErrorKind::NotFound.into()) }
        }

        fn run(&mut self, argv: &[&str]) -> io::Result<i32> {
            if self.missing.contains(&argv[0]) {
                return Err(io::ErrorKind::NotFound.into());
            }
            let line = argv.join(" ");
            self.log.push(format!("run {line}"));
            if let Some(i) = self.fail_once.iter().position(|f| *f == line) {
                self.fail_once.remove(i);
                return Ok(1);
            }
            if argv[0] == "useradd" {
                self.users.insert(argv[argv.len() - 1].to_string());
            }
            Ok(0)
        }

        fn capture(&mut self, argv: &[&str]) -> io::Result<String> {
            let bin = self.read(Path::new(argv[0])).ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            let text = String::from_utf8_lossy(&bin);
            let version = text.strip_prefix("binary ").ok_or_else(|| io::Error::other("not a fake binary"))?;
            Ok(format!("FlowPilot version: {version}\n"))
        }

        fn user_exists(&self, name: &str) -> bool {
            self.users.contains(name)
        }

        fn is_root(&self) -> bool {
            self.root
        }

        fn has_systemd(&self) -> bool {
            self.systemd
        }

        fn active_firewall(&self) -> Firewall {
            self.firewall
        }

        fn service_state(&self, _: &str) -> String {
            self.service_state.clone()
        }

        fn port_free(&self, port: u16) -> bool {
            !self.busy_ports.contains(&port)
        }
    }
}
