//! Go `flag` compatible command line, accepting the same flags and syntax as FlowLink.

use crate::install::args::{self, InstallArgs, StatusArgs, UninstallArgs, Usage};

/// What the command line asks for: the daemon (Go-compatible flags) or an installer subcommand.
#[derive(Debug)]
pub enum Command {
    Daemon(Flags),
    Install(Box<InstallArgs>),
    Uninstall(UninstallArgs),
    Rollback,
    Status(StatusArgs),
    /// Bad subcommand flags or `--help`: print `text` (stdout for code 0, else stderr) and exit with `code`.
    Usage { code: i32, text: String },
}

/// Routes on `args[1]` only: an exact subcommand name goes to the installer side, anything else to
/// the unchanged daemon parser.
pub fn dispatch(args: &[String]) -> Command {
    let rest = args.get(2..).unwrap_or(&[]);
    let to_usage = |u: Usage| Command::Usage { code: u.code, text: u.text };
    match args.get(1).map(String::as_str) {
        Some("install" | "upgrade") => args::parse_install(rest).map_or_else(to_usage, |a| Command::Install(Box::new(a))),
        Some("uninstall") => args::parse_uninstall(rest).map_or_else(to_usage, Command::Uninstall),
        Some("rollback") => args::parse_rollback(rest).map_or_else(to_usage, |()| Command::Rollback),
        Some("status") => args::parse_status(rest).map_or_else(to_usage, Command::Status),
        _ => Command::Daemon(parse(args)),
    }
}

/// Parsed flags. Unknown flags print usage and exit 2; `-h`/`-help` print usage and exit 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub version: bool,
    pub debug: bool,
    pub print_config: bool,
}

/// `flag.Parse()` with `ExitOnError`. `args` is the full argv (`args[0]` names the program in the
/// usage text), like `std::env::args()`.
pub fn parse(args: &[String]) -> Flags {
    match try_parse(args) {
        Outcome::Run(flags) => flags,
        Outcome::Exit { code, stderr } => {
            eprint!("{stderr}");
            std::process::exit(code)
        }
    }
}

/// Result of parsing: run with flags, or print `stderr` and exit with `code`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Run(Flags),
    Exit { code: i32, stderr: String },
}

/// Go `FlagSet.parseOne` loop over `args[1..]`.
/// Ported from the Go standard library (`flag`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
pub(crate) fn try_parse(args: &[String]) -> Outcome {
    let argv0 = args.first().map_or("flowpilot", String::as_str);
    let fail = |msg: String| Outcome::Exit {
        code: 2,
        stderr: format!("{msg}\n{}", usage(argv0)),
    };
    let mut flags = Flags::default();
    for s in args.iter().skip(1) {
        // A non-flag (including "" and "-") stops parsing; "--" is consumed and stops parsing.
        if s.len() < 2 || !s.starts_with('-') {
            break;
        }
        let name = match s.strip_prefix("--") {
            Some("") => break,
            Some(rest) => rest,
            None => &s[1..],
        };
        if name.is_empty() || name.starts_with('-') || name.starts_with('=') {
            return fail(format!("bad flag syntax: {s}"));
        }
        let (name, value) = match name.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (name, None),
        };
        let target = match name {
            "version" => &mut flags.version,
            "debug" => &mut flags.debug,
            "print-config" => &mut flags.print_config,
            "help" | "h" => {
                return Outcome::Exit {
                    code: 0,
                    stderr: usage(argv0),
                }
            }
            _ => return fail(format!("flag provided but not defined: -{name}")),
        };
        *target = match value.map(parse_bool) {
            None => true,
            Some(Some(b)) => b,
            Some(None) => {
                return fail(format!(
                    "invalid boolean value {:?} for -{name}: parse error",
                    value.unwrap_or("")
                ))
            }
        };
    }
    Outcome::Run(flags)
}

/// `strconv.ParseBool`.
fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// Go `flag.Usage` / `PrintDefaults` for the bool flags (sorted, zero defaults omitted).
/// Ported from the Go standard library (`flag`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
fn usage(argv0: &str) -> String {
    format!("Usage of {argv0}:\n  -debug\n    \tTurn on debug logging\n  -print-config\n    \tPrint the effective configuration and where each value came from, then exit\n  -version\n    \tPrint FlowPilot version\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Outcome {
        let mut v = vec!["/usr/local/bin/flowpilot".to_string()];
        v.extend(args.iter().map(|s| s.to_string()));
        try_parse(&v)
    }

    fn flags(version: bool, debug: bool) -> Outcome {
        Outcome::Run(Flags { version, debug, print_config: false })
    }

    const USAGE: &str =
        "Usage of /usr/local/bin/flowpilot:\n  -debug\n    \tTurn on debug logging\n  -print-config\n    \tPrint the effective configuration and where each value came from, then exit\n  -version\n    \tPrint FlowPilot version\n";

    #[test]
    fn dispatch_keeps_daemon_path() {
        for argv in [vec!["flowpilot"], vec!["flowpilot", ""], vec!["flowpilot", "-debug"], vec!["flowpilot", "-version"], vec!["flowpilot", "-print-config"]] {
            let a: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
            assert!(matches!(dispatch(&a), Command::Daemon(_)), "{argv:?}");
        }
    }

    #[test]
    fn dispatch_subcommands() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(matches!(dispatch(&a(&["fp", "install", "--yes", "--pce", "p:8443"])), Command::Install(i) if i.yes && i.pce.as_deref() == Some("p:8443")));
        assert!(matches!(dispatch(&a(&["fp", "upgrade"])), Command::Install(_)));
        assert!(matches!(dispatch(&a(&["fp", "uninstall", "--purge"])), Command::Uninstall(u) if u.purge));
        assert!(matches!(dispatch(&a(&["fp", "rollback"])), Command::Rollback));
        assert!(matches!(dispatch(&a(&["fp", "status", "--json"])), Command::Status(s) if s.json));
        assert!(matches!(dispatch(&a(&["fp", "install", "--bogus"])), Command::Usage { code: 2, .. }));
        assert!(matches!(dispatch(&a(&["fp", "status", "-h"])), Command::Usage { code: 0, .. }));
    }

    #[test]
    fn flag_table() {
        let cases: &[(&[&str], Outcome)] = &[
            (&[], flags(false, false)),
            (&["-debug"], flags(false, true)),
            (&["--debug"], flags(false, true)),
            (&["-version", "-debug"], flags(true, true)),
            (&["-debug=true"], flags(false, true)),
            (&["-debug=false"], flags(false, false)),
            (&["-debug", "-debug=0"], flags(false, false)),
            (&["--version=T"], flags(true, false)),
            // The ctl script passes an empty argument: a non-flag that stops parsing.
            (&[""], flags(false, false)),
            (&["", "-debug"], flags(false, false)),
            (&["-debug", ""], flags(false, true)),
            (&["x", "-version"], flags(false, false)),
            (&["-", "-version"], flags(false, false)),
            (&["--", "-version"], flags(false, false)),
            // `-debug false` sets debug and stops at the positional "false".
            (&["-debug", "false", "-version"], flags(false, true)),
        ];
        for (args, want) in cases {
            assert_eq!(&run(args), want, "{args:?}");
        }
    }

    #[test]
    fn print_config_flag() {
        let on = Outcome::Run(Flags { print_config: true, ..Flags::default() });
        assert_eq!(run(&["-print-config"]), on);
        assert_eq!(run(&["--print-config=true"]), on);
        assert_eq!(run(&["-print-config=false"]), flags(false, false));
        assert!(usage("x").contains("-print-config"));
    }

    #[test]
    fn help_and_errors() {
        let help = Outcome::Exit {
            code: 0,
            stderr: USAGE.into(),
        };
        assert_eq!(run(&["-h"]), help);
        assert_eq!(run(&["--help"]), help);
        let err = |m: &str| Outcome::Exit {
            code: 2,
            stderr: format!("{m}\n{USAGE}"),
        };
        assert_eq!(
            run(&["-config", "x"]),
            err("flag provided but not defined: -config")
        );
        assert_eq!(
            run(&["--foo=1"]),
            err("flag provided but not defined: -foo")
        );
        assert_eq!(
            run(&["-debug=maybe"]),
            err("invalid boolean value \"maybe\" for -debug: parse error")
        );
        assert_eq!(run(&["---x"]), err("bad flag syntax: ---x"));
        assert_eq!(run(&["-=x"]), err("bad flag syntax: -=x"));
    }
}
