//! The interactive questions, in this order: PCE, key, collectors, unmanaged workloads, certificate.
//! After a failed PCE check only the step that failed is asked again.

use std::fmt;

use dialoguer::{Confirm, Input, Password};

use crate::config::Secret;
use crate::install::answers::Answers;
use crate::install::args::{CollectorArg, CollectorKind, UnmanagedArgs};
use crate::install::check::{check_pce, CheckError};
use crate::stats::redact_proxy_url;
use crate::unmanaged::config::UnmanagedConfig;

/// Why the wizard stopped without answers that passed the PCE check.
#[derive(Debug, PartialEq, Eq)]
pub enum WizardError {
    /// The user interrupted a question.
    Aborted,
    /// The user declined to change the answers after the check failed.
    CheckFailed(CheckError),
    /// The terminal could not be read, e.g. stdin is closed or not a terminal.
    Input(String),
}

impl fmt::Display for WizardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WizardError::Aborted => write!(f, "Installation cancelled."),
            WizardError::CheckFailed(e) => write!(f, "{e} Fix the answers and run the installer again."),
            WizardError::Input(e) => write!(
                f,
                "Cannot read the answers ({e}); run in a terminal or pass every setting as a flag with --yes."
            ),
        }
    }
}

type Ask<T> = Result<T, WizardError>;

pub trait Prompter {
    /// A line of text; Enter takes `default`.
    fn text(&mut self, q: &str, default: Option<&str>) -> Ask<String>;
    /// Hidden input.
    fn secret(&mut self, q: &str) -> Ask<String>;
    fn confirm(&mut self, q: &str, default: bool) -> Ask<bool>;
}

/// The terminal prompter.
pub struct DialoguerPrompter;

fn input_error(e: dialoguer::Error) -> WizardError {
    let dialoguer::Error::IO(io) = e;
    if io.kind() == std::io::ErrorKind::Interrupted {
        WizardError::Aborted
    } else {
        WizardError::Input(io.to_string())
    }
}

impl Prompter for DialoguerPrompter {
    fn text(&mut self, q: &str, default: Option<&str>) -> Ask<String> {
        let mut i = Input::<String>::new().with_prompt(q).allow_empty(true);
        if let Some(d) = default.filter(|d| !d.is_empty()) {
            i = i.default(d.to_string());
        }
        i.interact_text().map_err(input_error)
    }

    fn secret(&mut self, q: &str) -> Ask<String> {
        Password::new().with_prompt(q).allow_empty_password(true).interact().map_err(input_error)
    }

    fn confirm(&mut self, q: &str, default: bool) -> Ask<bool> {
        Confirm::new().with_prompt(q).default(default).interact().map_err(input_error)
    }
}

/// Asks the questions and checks the PCE until it answers or the user gives up.
pub fn ask(p: &mut dyn Prompter, start: Answers) -> Result<Answers, WizardError> {
    ask_with(p, start, &mut check_pce)
}

/// `ask` with the PCE check injectable (also how `--skip-pce-check` passes a check that always succeeds).
pub fn ask_with(
    p: &mut dyn Prompter,
    start: Answers,
    check: &mut dyn FnMut(&Answers) -> Result<(), CheckError>,
) -> Result<Answers, WizardError> {
    let mut a = start;
    pce_address(p, &mut a)?;
    proxy(p, &mut a)?;
    key(p, &mut a, false)?;
    collectors(p, &mut a)?;
    unmanaged(p, &mut a)?;
    certificate(p, &mut a)?;
    while let Err(e) = check(&a) {
        eprintln!("{e}");
        if !p.confirm("Change the answers and check again?", true)? {
            return Err(WizardError::CheckFailed(e));
        }
        match e {
            CheckError::Auth(_) | CheckError::KeyFormat => key(p, &mut a, true)?,
            CheckError::Resolve(_) | CheckError::Connect(_) | CheckError::Certificate(_) | CheckError::Other(_) => {
                pce_address(p, &mut a)?;
                proxy(p, &mut a)?;
                certificate(p, &mut a)?;
            }
        }
    }
    Ok(a)
}

fn some(s: String) -> Option<String> {
    Some(s.trim().to_string()).filter(|s| !s.is_empty())
}

fn pce_address(p: &mut dyn Prompter, a: &mut Answers) -> Ask<()> {
    a.pce_addr = p.text("PCE address (host:port)", Some(&a.pce_addr))?.trim().to_string();
    if let Ok(n) = p.text("Organization id", Some(&a.org_id.to_string()))?.trim().parse() {
        a.org_id = n;
    }
    Ok(())
}

const PROXY_Q: &str = "HTTPS proxy to the PCE (host:port or URL, none = no proxy)";

/// The proxy is shown without its user and password; Enter keeps it as it is.
fn proxy(p: &mut dyn Prompter, a: &mut Answers) -> Ask<()> {
    let shown = redact_proxy_url(&a.proxy.https);
    let reply = p.text(PROXY_Q, Some(&shown).filter(|s| !s.is_empty()).map(String::as_str))?;
    let reply = reply.trim();
    if reply != shown {
        a.proxy.https = if reply.eq_ignore_ascii_case("none") { String::new() } else { reply.to_string() };
    }
    Ok(())
}

/// The secret is asked when missing, or when the PCE refused the one given (`again`).
fn key(p: &mut dyn Prompter, a: &mut Answers, again: bool) -> Ask<()> {
    a.api_user = p.text("API user", Some(&a.api_user))?.trim().to_string();
    if again || a.api_secret.0.is_empty() {
        a.api_secret = Secret(p.secret("API secret")?.trim().to_string());
    }
    Ok(())
}

fn collectors(p: &mut dyn Prompter, a: &mut Answers) -> Ask<()> {
    let current = std::mem::take(&mut a.collectors);
    for (kind, name) in [
        (CollectorKind::Netflow, "NetFlow"),
        (CollectorKind::Ipfix, "IPFIX"),
        (CollectorKind::Sflow, "sFlow"),
        (CollectorKind::Text, "text"),
    ] {
        let had = current.iter().find(|c| c.kind == kind);
        if !p.confirm(&format!("Receive {name}?"), had.is_some())? {
            continue;
        }
        let default_ports = match kind {
            CollectorKind::Netflow => "2055",
            CollectorKind::Ipfix => "4739",
            CollectorKind::Sflow => "6343",
            CollectorKind::Text => "514",
        };
        let ports = p.text(&format!("{name} ports (comma-separated)"), Some(had.map_or(default_ports, |c| &c.ports)))?;
        let from = p.text(
            &format!("{name}: accept only from these addresses (empty = any)"),
            had.and_then(|c| c.remote_addrs.as_deref()),
        )?;
        a.collectors.push(CollectorArg { kind, ports: ports.trim().to_string(), remote_addrs: some(from) });
    }
    if a.collectors.iter().any(|c| c.kind == CollectorKind::Text) {
        text_fields(p, a)?;
    }
    Ok(())
}

fn text_fields(p: &mut dyn Prompter, a: &mut Answers) -> Ask<()> {
    let t = &mut a.text;
    for (q, field) in [
        ("Text: source IP field", &mut t.src_ip),
        ("Text: destination IP field", &mut t.dst_ip),
        ("Text: destination port field", &mut t.dst_port),
        ("Text: protocol field", &mut t.protocol),
        ("Text: octets field", &mut t.octets),
        ("Text: ICMP type field", &mut t.icmp_type),
        ("Text: ICMP code field", &mut t.icmp_code),
        ("Text: timestamp field", &mut t.timestamp),
        ("Text: timestamp format", &mut t.timestamp_format),
        ("Text: only records matching", &mut t.only_recs),
        ("Text: field separator", &mut t.field_separator),
        ("Text: attribute separator", &mut t.attribute_separator),
    ] {
        *field = some(p.text(q, field.as_deref())?);
    }
    Ok(())
}

/// A number question; an unparsable reply keeps the current value.
fn number(p: &mut dyn Prompter, q: &str, current: Option<u64>, default: u64) -> Ask<u64> {
    let cur = current.unwrap_or(default);
    Ok(p.text(q, Some(&cur.to_string()))?.trim().parse().unwrap_or(cur))
}

fn unmanaged(p: &mut dyn Prompter, a: &mut Answers) -> Ask<()> {
    if !p.confirm("Create unmanaged workloads for unknown sources?", a.unmanaged.is_some())? {
        a.unmanaged = None;
        return Ok(());
    }
    let d = UnmanagedConfig::default();
    let mut u = a.unmanaged.take().unwrap_or(UnmanagedArgs { enabled: true, ..Default::default() });
    u.enabled = true;
    u.dry_run = p.confirm("Dry run (only log what would be created)?", u.dry_run)?;
    u.networks = some(p.text("Networks eligible for creation (CIDRs, empty = defaults)", u.networks.as_deref())?);
    u.min_flows = Some(number(p, "Flows a source needs before it is created", u.min_flows, d.min_flows)?);
    u.max_per_window = Some(number(p, "Most workloads created per window", u.max_per_window, d.max_creates_per_window as u64)?);
    u.max_per_day = Some(number(p, "Most workloads created per day", u.max_per_day, d.max_creates_per_day as u64)?);
    u.label_rules = some(p.text("Label rules (cidr=key:value,key:value;..., empty = none)", u.label_rules.as_deref())?);
    a.unmanaged = Some(u);
    Ok(())
}

fn certificate(p: &mut dyn Prompter, a: &mut Answers) -> Ask<()> {
    a.verify_pce_cert = p.confirm("Verify the PCE TLS certificate?", a.verify_pce_cert)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::answers::from_args;
    use crate::install::args::InstallArgs;

    use crate::install::check::CheckError;
    use std::collections::VecDeque;

    /// Answers by question text; falls back to the default. Records every question.
    struct Script {
        asked: Vec<String>,
        secrets: VecDeque<String>,
        /// What `confirm` answers to the retry question (other confirms answer their default).
        retry: bool,
    }

    impl Prompter for Script {
        fn text(&mut self, q: &str, default: Option<&str>) -> Ask<String> {
            self.asked.push(q.into());
            Ok(match q {
                "PCE address (host:port)" => "pce.example.com:8443".into(),
                "API user" => "api_x".into(),
                _ => default.unwrap_or("").into(),
            })
        }
        fn secret(&mut self, q: &str) -> Ask<String> {
            self.asked.push(q.into());
            Ok(self.secrets.pop_front().unwrap())
        }
        fn confirm(&mut self, q: &str, default: bool) -> Ask<bool> {
            self.asked.push(q.into());
            Ok(match q {
                "Change the answers and check again?" => self.retry,
                "Receive text?" => true,
                _ => default,
            })
        }
    }

    #[test]
    fn wizard_reasks_only_failed_step() {
        let start = from_args(&InstallArgs::default(), &|_| None).unwrap();
        let mut p = Script { asked: vec![], secrets: ["wrong".to_string(), "right".to_string()].into(), retry: true };
        let mut calls = 0;
        let a = ask_with(&mut p, start, &mut |a| {
            calls += 1;
            if a.api_secret.0 == "wrong" { Err(CheckError::Auth(401)) } else { Ok(()) }
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(a.api_secret.0, "right");
        let n = |q: &str| p.asked.iter().filter(|s| *s == q).count();
        assert_eq!(n("PCE address (host:port)"), 1);
        assert_eq!(n("API secret"), 2);
    }

    #[test]
    fn wizard_reasks_address_after_connect_failure() {
        let start = from_args(&InstallArgs::default(), &|_| None).unwrap();
        let mut p = Script { asked: vec![], secrets: ["s".to_string()].into(), retry: true };
        let mut first = true;
        ask_with(&mut p, start, &mut |_| {
            if std::mem::take(&mut first) { Err(CheckError::Connect("refused".into())) } else { Ok(()) }
        })
        .unwrap();
        let n = |q: &str| p.asked.iter().filter(|s| *s == q).count();
        assert_eq!(n("PCE address (host:port)"), 2);
        assert_eq!(n("API secret"), 1);
    }

    #[test]
    fn declined_retry_returns_check_failed() {
        let start = from_args(&InstallArgs::default(), &|_| None).unwrap();
        let mut p = Script { asked: vec![], secrets: ["s".to_string()].into(), retry: false };
        let err = ask_with(&mut p, start, &mut |_| Err(CheckError::Auth(401))).unwrap_err();
        assert_eq!(err, WizardError::CheckFailed(CheckError::Auth(401)));
        assert!(err.to_string().contains("401"));
    }

    /// A prompter whose terminal is gone: the first question fails.
    struct Dead;

    impl Prompter for Dead {
        fn text(&mut self, _: &str, _: Option<&str>) -> Ask<String> {
            Err(WizardError::Input("not a terminal".into()))
        }
        fn secret(&mut self, _: &str) -> Ask<String> {
            Err(WizardError::Input("not a terminal".into()))
        }
        fn confirm(&mut self, _: &str, _: bool) -> Ask<bool> {
            Err(WizardError::Input("not a terminal".into()))
        }
    }

    #[test]
    fn input_error_stops_the_wizard() {
        let start = from_args(&InstallArgs::default(), &|_| None).unwrap();
        let mut calls = 0;
        let err = ask_with(&mut Dead, start, &mut |_| {
            calls += 1;
            Err(CheckError::Auth(401))
        })
        .unwrap_err();
        assert!(matches!(err, WizardError::Input(_)));
        assert!(calls <= 1);
    }

    /// Answers the proxy question with `reply`; every other question as `Script` does.
    struct ProxyReply(&'static str, Script);

    impl Prompter for ProxyReply {
        fn text(&mut self, q: &str, default: Option<&str>) -> Ask<String> {
            if q == PROXY_Q {
                self.1.asked.push(format!("{q} [{}]", default.unwrap_or("")));
                return Ok(if self.0.is_empty() { default.unwrap_or("").into() } else { self.0.into() });
            }
            self.1.text(q, default)
        }
        fn secret(&mut self, q: &str) -> Ask<String> {
            self.1.secret(q)
        }
        fn confirm(&mut self, q: &str, default: bool) -> Ask<bool> {
            self.1.confirm(q, default)
        }
    }

    fn proxy_after(reply: &'static str, current: &str) -> (String, Vec<String>) {
        let mut start = from_args(&InstallArgs::default(), &|_| None).unwrap();
        start.proxy.https = current.into();
        let mut p = ProxyReply(reply, Script { asked: vec![], secrets: ["s".to_string()].into(), retry: true });
        let a = ask_with(&mut p, start, &mut |_| Ok(())).unwrap();
        (a.proxy.https, p.1.asked)
    }

    #[test]
    fn proxy_question_defaults_to_none_and_hides_credentials() {
        assert_eq!(proxy_after("", "").0, "");
        assert_eq!(proxy_after("proxy.example.com:3128", "").0, "proxy.example.com:3128");
        // Enter keeps a proxy with credentials, which the question shows without them.
        let (kept, asked) = proxy_after("", "http://u:pa55@proxy:3128");
        assert_eq!(kept, "http://u:pa55@proxy:3128");
        assert!(asked.iter().all(|q| !q.contains("pa55")), "{asked:?}");
        assert!(asked.iter().any(|q| q.contains("http://***@proxy:3128")), "{asked:?}");
        assert_eq!(proxy_after("none", "http://proxy:3128").0, "");
    }

    #[test]
    fn text_default_port_and_unmanaged_questions() {
        let start = from_args(&InstallArgs::default(), &|_| None).unwrap();
        let mut p = Script { asked: vec![], secrets: ["s".to_string()].into(), retry: true };
        // The script turns text on; unmanaged is on from the start.
        let mut a = start;
        a.unmanaged = Some(UnmanagedArgs { enabled: true, ..Default::default() });
        let a = ask_with(&mut p, a, &mut |_| Ok(())).unwrap();
        let u = a.unmanaged.unwrap();
        assert_eq!((u.min_flows, u.max_per_window, u.max_per_day), (Some(10), Some(100), Some(500)));
        assert!(p.asked.iter().any(|q| q.starts_with("Label rules")));
        let text = a.collectors.iter().find(|c| c.kind == CollectorKind::Text).unwrap();
        assert_eq!(text.ports, "514");
    }
}
