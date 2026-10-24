//! Flag parsing for the installer subcommands (`install`, `upgrade`, `uninstall`, `status`).
//! Parsing returns `Err(Usage)` for bad flags and for `--help`; the caller prints and exits.

use std::path::PathBuf;

use lexopt::prelude::*;

/// What to print, and the exit code, instead of running the subcommand.
#[derive(Debug, PartialEq, Eq)]
pub struct Usage {
    pub code: i32,
    pub text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectorKind {
    Netflow,
    Ipfix,
    Sflow,
    Text,
}

/// One `--netflow|--ipfix|--sflow|--text PORTS[@ADDRS]` occurrence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectorArg {
    pub kind: CollectorKind,
    pub ports: String,
    pub remote_addrs: Option<String>,
}

impl CollectorArg {
    fn parse(kind: CollectorKind, v: &str) -> Self {
        match v.split_once('@') {
            Some((p, a)) => CollectorArg { kind, ports: p.to_string(), remote_addrs: Some(a.to_string()) },
            None => CollectorArg { kind, ports: v.to_string(), remote_addrs: None },
        }
    }
}

/// The `--text-*` parser settings, one field per flag.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TextArgs {
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<String>,
    pub protocol: Option<String>,
    pub octets: Option<String>,
    pub icmp_type: Option<String>,
    pub icmp_code: Option<String>,
    pub timestamp: Option<String>,
    pub timestamp_format: Option<String>,
    pub only_recs: Option<String>,
    pub field_separator: Option<String>,
    pub attribute_separator: Option<String>,
}

/// The `--unmanaged*` settings, one field per flag.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnmanagedArgs {
    pub enabled: bool,
    pub dry_run: bool,
    pub networks: Option<String>,
    pub min_flows: Option<u64>,
    pub max_per_window: Option<u64>,
    pub max_per_day: Option<u64>,
    pub label_rules: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InstallArgs {
    pub pce: Option<String>,
    pub org: Option<i32>,
    pub api_user: Option<String>,
    /// `-` reads the secret from stdin. There is deliberately no flag carrying the secret itself.
    pub api_secret_file: Option<PathBuf>,
    pub api_key_file: Option<PathBuf>,
    pub collectors: Vec<CollectorArg>,
    pub text: TextArgs,
    pub unmanaged: UnmanagedArgs,
    /// `Some(false)` after `--no-verify-pce-cert`.
    pub verify_pce_cert: Option<bool>,
    /// `--proxy`: the HTTPS proxy to the PCE, written to `proxy_config.https_proxy`.
    pub proxy: Option<String>,
    pub yes: bool,
    pub reconfigure: bool,
    pub skip_pce_check: bool,
    /// Test and dry-run prefix for every host path; hidden from help. With a root other than `/` no host command
    /// runs (each is printed as `would run: ...`) and the health wait is skipped.
    pub root: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UninstallArgs {
    pub purge: bool,
    pub yes: bool,
    pub root: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatusArgs {
    pub json: bool,
}

const INSTALL_USAGE: &str = "\
Usage: flowpilot install|upgrade [flags]
  --pce HOST:PORT              PCE address
  --org N                      organization id
  --api-user USER              API user (api_...)
  --api-secret-file PATH       file holding the API secret ('-' reads stdin)
  --api-key-file PATH          API key JSON as downloaded from the PCE
  --netflow PORTS[@ADDRS]      add a NetFlow collector
  --ipfix PORTS[@ADDRS]        add an IPFIX collector
  --sflow PORTS[@ADDRS]        add an sFlow collector
  --text PORTS[@ADDRS]         add a text collector
  --text-src-ip F              text parser: source IP field
  --text-dst-ip F              text parser: destination IP field
  --text-dst-port F            text parser: destination port field
  --text-protocol F            text parser: protocol field
  --text-octets F              text parser: octets field
  --text-icmp-type F           text parser: ICMP type field
  --text-icmp-code F           text parser: ICMP code field
  --text-timestamp F           text parser: timestamp field
  --text-timestamp-format S    text parser: timestamp format
  --text-only-recs S           text parser: only records matching S
  --text-field-separator S     text parser: field separator
  --text-attribute-separator S text parser: attribute separator
  --unmanaged                  enable unmanaged-workload creation
  --unmanaged-dry-run          log what would be created, create nothing
  --unmanaged-networks CIDRS   networks eligible for creation
  --unmanaged-min-flows N      minimum flows before creating
  --unmanaged-max-per-window N creation cap per window
  --unmanaged-max-per-day N    creation cap per day
  --unmanaged-label-rules RULES label rules
  --no-verify-pce-cert         do not verify the PCE TLS certificate
  --proxy URL                  HTTPS proxy to the PCE (written to the config)
  --yes                        never prompt
  --reconfigure                replace the existing configuration
  --skip-pce-check             do not contact the PCE
  -h, --help                   show this help
";

const UNINSTALL_USAGE: &str = "\
Usage: flowpilot uninstall [flags]
  --purge       also remove configuration, data and the flowpilot user
  --yes         never prompt
  -h, --help    show this help
";

const STATUS_USAGE: &str = "\
Usage: flowpilot status [flags]
  --json        machine-readable output
  -h, --help    show this help
";

/// Every install flag that takes a value (the rest are switches).
const VALUE_FLAGS: &[&str] = &[
    "pce", "org", "proxy", "api-user", "api-secret-file", "api-key-file", "root", "netflow", "ipfix", "sflow", "text",
    "text-src-ip", "text-dst-ip", "text-dst-port", "text-protocol", "text-octets", "text-icmp-type",
    "text-icmp-code", "text-timestamp", "text-timestamp-format", "text-only-recs", "text-field-separator",
    "text-attribute-separator", "unmanaged-networks", "unmanaged-min-flows", "unmanaged-max-per-window",
    "unmanaged-max-per-day", "unmanaged-label-rules",
];

fn help(text: &str) -> Usage {
    Usage { code: 0, text: text.to_string() }
}

fn fail(e: lexopt::Error, text: &str) -> Usage {
    Usage { code: 2, text: format!("flowpilot: {e}\n{text}") }
}

fn num<T: std::str::FromStr>(flag: &str, v: &str, text: &str) -> Result<T, Usage> {
    v.parse().map_err(|_| fail(lexopt::Error::Custom(format!("invalid value {v:?} for {flag}").into()), text))
}

/// `args` are the words after the subcommand.
pub fn parse_install(args: &[String]) -> Result<InstallArgs, Usage> {
    let u = INSTALL_USAGE;
    let mut a = InstallArgs::default();
    let mut p = lexopt::Parser::from_args(args.iter().map(String::as_str));
    while let Some(arg) = p.next().map_err(|e| fail(e, u))? {
        match arg {
            Short('h') | Long("help") => return Err(help(u)),
            Long("yes") => a.yes = true,
            Long("reconfigure") => a.reconfigure = true,
            Long("skip-pce-check") => a.skip_pce_check = true,
            Long("no-verify-pce-cert") => a.verify_pce_cert = Some(false),
            Long("unmanaged") => a.unmanaged.enabled = true,
            Long("unmanaged-dry-run") => a.unmanaged.dry_run = true,
            Long(name) => {
                let name = name.to_string();
                if !VALUE_FLAGS.contains(&name.as_str()) {
                    return Err(fail(lexopt::Error::UnexpectedOption(format!("--{name}")), u));
                }
                let v = p.value().map_err(|e| fail(e, u))?;
                let v = v.into_string().map_err(|o| fail(lexopt::Error::NonUnicodeValue(o), u))?;
                let some = || Some(v.clone());
                let path = || Some(PathBuf::from(&v));
                match name.as_str() {
                    "pce" => a.pce = some(),
                    "org" => a.org = Some(num(&name, &v, u)?),
                    "proxy" => a.proxy = some(),
                    "api-user" => a.api_user = some(),
                    "api-secret-file" => a.api_secret_file = path(),
                    "api-key-file" => a.api_key_file = path(),
                    "root" => a.root = path(),
                    "netflow" => a.collectors.push(CollectorArg::parse(CollectorKind::Netflow, &v)),
                    "ipfix" => a.collectors.push(CollectorArg::parse(CollectorKind::Ipfix, &v)),
                    "sflow" => a.collectors.push(CollectorArg::parse(CollectorKind::Sflow, &v)),
                    "text" => a.collectors.push(CollectorArg::parse(CollectorKind::Text, &v)),
                    "text-src-ip" => a.text.src_ip = some(),
                    "text-dst-ip" => a.text.dst_ip = some(),
                    "text-dst-port" => a.text.dst_port = some(),
                    "text-protocol" => a.text.protocol = some(),
                    "text-octets" => a.text.octets = some(),
                    "text-icmp-type" => a.text.icmp_type = some(),
                    "text-icmp-code" => a.text.icmp_code = some(),
                    "text-timestamp" => a.text.timestamp = some(),
                    "text-timestamp-format" => a.text.timestamp_format = some(),
                    "text-only-recs" => a.text.only_recs = some(),
                    "text-field-separator" => a.text.field_separator = some(),
                    "text-attribute-separator" => a.text.attribute_separator = some(),
                    "unmanaged-networks" => a.unmanaged.networks = some(),
                    "unmanaged-min-flows" => a.unmanaged.min_flows = Some(num(&name, &v, u)?),
                    "unmanaged-max-per-window" => a.unmanaged.max_per_window = Some(num(&name, &v, u)?),
                    "unmanaged-max-per-day" => a.unmanaged.max_per_day = Some(num(&name, &v, u)?),
                    "unmanaged-label-rules" => a.unmanaged.label_rules = some(),
                    _ => return Err(fail(lexopt::Error::UnexpectedOption(format!("--{name}")), u)),
                }
            }
            other => return Err(fail(other.unexpected(), u)),
        }
    }
    Ok(a)
}

pub fn parse_uninstall(args: &[String]) -> Result<UninstallArgs, Usage> {
    let u = UNINSTALL_USAGE;
    let mut a = UninstallArgs::default();
    let mut p = lexopt::Parser::from_args(args.iter().map(String::as_str));
    while let Some(arg) = p.next().map_err(|e| fail(e, u))? {
        match arg {
            Short('h') | Long("help") => return Err(help(u)),
            Long("purge") => a.purge = true,
            Long("yes") => a.yes = true,
            Long("root") => a.root = Some(PathBuf::from(p.value().map_err(|e| fail(e, u))?)),
            other => return Err(fail(other.unexpected(), u)),
        }
    }
    Ok(a)
}

pub fn parse_status(args: &[String]) -> Result<StatusArgs, Usage> {
    let u = STATUS_USAGE;
    let mut a = StatusArgs::default();
    let mut p = lexopt::Parser::from_args(args.iter().map(String::as_str));
    while let Some(arg) = p.next().map_err(|e| fail(e, u))? {
        match arg {
            Short('h') | Long("help") => return Err(help(u)),
            Long("json") => a.json = true,
            other => return Err(fail(other.unexpected(), u)),
        }
    }
    Ok(a)
}

/// `rollback` takes no flags.
pub fn parse_rollback(args: &[String]) -> Result<(), Usage> {
    let u = "Usage: flowpilot rollback\n  -h, --help    show this help\n";
    let mut p = lexopt::Parser::from_args(args.iter().map(String::as_str));
    match p.next().map_err(|e| fail(e, u))? {
        None => Ok(()),
        Some(Short('h') | Long("help")) => Err(help(u)),
        Some(other) => Err(fail(other.unexpected(), u)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn collector_arg_parses_ports_and_addrs() {
        let a = parse_install(&v(&["--netflow", "2055,9995@10.0.0.1,10.0.0.2", "--sflow", "6343"])).unwrap();
        assert_eq!(a.collectors[0].kind, CollectorKind::Netflow);
        assert_eq!(a.collectors[0].ports, "2055,9995");
        assert_eq!(a.collectors[0].remote_addrs.as_deref(), Some("10.0.0.1,10.0.0.2"));
        assert_eq!(a.collectors[1], CollectorArg { kind: CollectorKind::Sflow, ports: "6343".into(), remote_addrs: None });
    }

    #[test]
    fn unknown_install_flag_is_error() {
        let e = parse_install(&v(&["--bogus", "x"])).unwrap_err();
        assert_eq!(e.code, 2);
        assert!(e.text.contains("unexpected argument '--bogus'") || e.text.contains("--bogus"), "{}", e.text);
        assert!(!e.text.contains("missing argument"), "{}", e.text);
        assert!(e.text.contains("Usage: flowpilot install"));
    }

    #[test]
    fn install_flags_fill_fields() {
        let a = parse_install(&v(&[
            "--org=3", "--api-secret-file", "-", "--text-src-ip", "1", "--unmanaged", "--unmanaged-min-flows", "5",
            "--no-verify-pce-cert", "--root", "/r", "--proxy", "http://proxy.example.com:3128",
        ]))
        .unwrap();
        assert_eq!(a.proxy.as_deref(), Some("http://proxy.example.com:3128"));
        assert_eq!(a.org, Some(3));
        assert_eq!(a.api_secret_file, Some(PathBuf::from("-")));
        assert_eq!(a.text.src_ip.as_deref(), Some("1"));
        assert!(a.unmanaged.enabled);
        assert_eq!(a.unmanaged.min_flows, Some(5));
        assert_eq!(a.verify_pce_cert, Some(false));
        assert_eq!(a.root, Some(PathBuf::from("/r")));
    }

    #[test]
    fn bad_number_and_missing_value_are_errors() {
        assert_eq!(parse_install(&v(&["--org", "x"])).unwrap_err().code, 2);
        assert_eq!(parse_install(&v(&["--pce"])).unwrap_err().code, 2);
        assert_eq!(parse_install(&v(&["stray"])).unwrap_err().code, 2);
    }

    #[test]
    fn help_is_exit_zero_and_hides_root() {
        for u in [parse_install(&v(&["-h"])).unwrap_err(), parse_uninstall(&v(&["--help"])).unwrap_err(), parse_status(&v(&["-h"])).unwrap_err()] {
            assert_eq!(u.code, 0);
            assert!(!u.text.contains("--root"));
        }
    }
}
