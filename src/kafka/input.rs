//! Kafka input connector (`connectors: - type: kafka`, text parser only): its properties and TLS
//! material, and the consumer threads that hand each message to the parser as one datagram.

use std::fmt;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;

use crate::config::Properties;
use crate::kafka::group::{GroupConsumer, GroupSettings, InMessage, Member};
use crate::kafka::producer::split_brokers;
use crate::kafka::tls;
use crate::metrics::{get_or_register_meter, Meter};
use crate::parsers::{Parser, ReceivedDatagram};
use crate::stats::ThreadGuard;
use crate::{debug_log, log_line};

/// Client id when `client_id` is not set.
pub const DEFAULT_CLIENT_ID: &str = "Illumio-flowlink";

/// A sarama-style Kafka version: `[major, minor, very minor, patch]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KafkaVersion(pub [u32; 4]);

/// FlowLink's version grammar: at least 5 characters, then `0.a.b.c` when it starts with `0`, else
/// `a.b.c` (ASCII digits only). Any well-formed version is accepted, known to Kafka or not.
pub fn parse_version(s: &str) -> Result<KafkaVersion, String> {
    let err = || format!("invalid version `{s}`");
    if s.len() < 5 {
        return Err(err());
    }
    let parts: Vec<&str> = s.split('.').collect();
    let (want, rest) = if s.starts_with('0') { (4, &parts[1..]) } else { (3, &parts[..]) };
    if parts.len() != want || (want == 4 && parts[0] != "0") {
        return Err(err());
    }
    let mut v = [0u32; 4];
    let offset = want - 3;
    for (i, p) in rest.iter().enumerate() {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return Err(err());
        }
        // Divergence: a number that does not fit is an invalid version; FlowLink's scan leaves it
        // unset.
        v[offset + i] = p.parse().map_err(|_| err())?;
    }
    Ok(KafkaVersion(v))
}

/// PEM text cut at each `-----BEGIN`, as FlowLink does: each element runs from one marker to just
/// before the next, text before the first marker is dropped, order is kept.
pub fn split_pem_blocks(s: &str) -> Vec<String> {
    const MARKER: &str = "-----BEGIN";
    let starts: Vec<usize> = s.match_indices(MARKER).map(|(i, _)| i).collect();
    starts.iter().enumerate().map(|(n, &i)| s[i..*starts.get(n + 1).unwrap_or(&s.len())].to_string()).collect()
}

/// TLS material for the broker connections, as PEM. The brokers are verified against
/// `roots_pem` (the system roots, see `tls::system_roots_pem`) with a hostname check, as in
/// FlowLink.
#[derive(Clone, PartialEq)]
pub struct TlsPem {
    /// The client certificate; `None` when `broker_certs` and `broker_keys` hold no PEM block.
    pub client: Option<ClientPem>,
    pub roots_pem: String,
}

/// The client certificate offered to the brokers: one certificate block and its key block.
#[derive(Clone, PartialEq)]
pub struct ClientPem {
    pub cert_pem: String,
    pub key_pem: String,
}

// PEM never goes into Debug output (the key is a secret; the rest is noise).
impl fmt::Debug for TlsPem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsPem").field("client", &self.client).finish_non_exhaustive()
    }
}

impl fmt::Debug for ClientPem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientPem").finish_non_exhaustive()
    }
}

/// One Kafka connector entry's settings.
#[derive(Debug, Clone, PartialEq)]
pub struct InputSettings {
    /// `brokers` as configured; the source of `device_addr` and of log lines.
    pub brokers_raw: String,
    /// `split_brokers(brokers_raw)`.
    pub brokers: Vec<String>,
    /// The first comma-separated entry of `brokers_raw`, untrimmed, as in FlowLink.
    pub device_addr: String,
    pub group: String,
    /// `topics` split on `,`, trimmed, empty entries dropped.
    pub topics: Vec<String>,
    pub instances: usize,
    /// One client id per instance.
    pub client_ids: Vec<String>,
    pub version: KafkaVersion,
    /// `None`: plaintext.
    pub tls_pem: Option<TlsPem>,
}

/// Why a connector entry does not run.
#[derive(Debug, Clone, PartialEq)]
pub enum InputError {
    /// Log these lines; this connector does not start.
    Invalid(Vec<String>),
    /// Log these lines and exit 1.
    Exit(Vec<String>),
}

/// Parse one Kafka connector entry. `read` resolves a file property (a file path or `$command`).
/// An invalid `version` is logged here through `log::check_error` (so `-debug` exits); every other
/// line is left to the caller.
pub fn parse_settings(props: &Properties, read: &dyn Fn(&str) -> String) -> Result<InputSettings, InputError> {
    let missing: Vec<String> = ["brokers", "version", "group", "topics"]
        .iter()
        .filter(|p| !props.contains_key(**p))
        .map(|p| format!("Missing kafka property: {p}"))
        .collect();
    let get = |k: &str| props.get(k).cloned().unwrap_or_default();
    let version = parse_version(&get("version"));
    // As in FlowLink, a bad version does not start the connector.
    let bad_version = crate::log::check_error(version.as_ref().err());
    if !missing.is_empty() || bad_version {
        return Err(InputError::Invalid(missing));
    }
    let version = version.expect("checked above");

    let brokers_raw = get("brokers");
    let device_addr = brokers_raw.split(',').next().unwrap_or_default().to_string();
    let instances = instances(props.get("instances").map(String::as_str), brokers_raw.split(',').count())?;
    let tls_pem = tls_pem(props, read).map_err(InputError::Exit)?;
    let client_id = props.get("client_id").map_or(DEFAULT_CLIENT_ID, String::as_str);
    let client_ids =
        if instances > 1 { (0..instances).map(|i| format!("{client_id}-{i}")).collect() } else { vec![client_id.to_string()] };

    Ok(InputSettings {
        brokers: split_brokers(&brokers_raw),
        brokers_raw,
        device_addr,
        group: get("group"),
        topics: split_brokers(&get("topics")),
        instances,
        client_ids,
        version,
        tls_pem,
    })
}

/// `instances`: absent, non-numeric or 0 → one per broker entry (empty entries counted).
fn instances(value: Option<&str>, broker_entries: usize) -> Result<usize, InputError> {
    let n = match value.map(str::parse::<i64>) {
        None => 0,
        Some(Ok(n)) => n,
        Some(Err(_)) => {
            crate::log_line!("Invalid kafka instances value, must be numeric. Using default instances.");
            0
        }
    };
    match n {
        0 => Ok(broker_entries),
        // Divergence: FlowLink panics on a negative count.
        n if n < 0 => Err(InputError::Invalid(vec![format!("Invalid kafka instances value: {n}")])),
        n => usize::try_from(n).map_err(|_| InputError::Invalid(vec![format!("Invalid kafka instances value: {n}")])),
    }
}

/// TLS iff `broker_certs` is set. Errors are the lines to log before exiting 1.
fn tls_pem(props: &Properties, read: &dyn Fn(&str) -> String) -> Result<Option<TlsPem>, Vec<String>> {
    let Some(certs) = props.get("broker_certs") else { return Ok(None) };
    let Some(keys) = props.get("broker_keys") else {
        return Err(vec!["Missing script for broker certificate keys.".into()]);
    };
    // Divergence: FlowLink logs these blocks, private keys included, with -debug; FlowPilot never does.
    let certs = split_pem_blocks(&read(certs));
    let keys = split_pem_blocks(&read(keys));
    if certs.len() != keys.len() {
        return Err(vec!["Number of broker certs doesn't match number of broker keys.".into()]);
    }
    // Divergence: FlowLink falls back to plaintext when a pair does not load; FlowPilot exits.
    for (cert, key) in certs.iter().zip(&keys) {
        tls::client_auth_config(cert, key).map_err(|e| vec![format!("Error: {e}")])?;
    }
    // Divergence: one client certificate is offered, the first pair; the others are only checked.
    // No pair at all (FlowLink's accidental case): TLS with system roots and no client certificate.
    let client = certs.into_iter().zip(keys).next().map(|(cert_pem, key_pem)| ClientPem { cert_pem, key_pem });
    Ok(Some(TlsPem { client, roots_pem: tls::system_roots_pem() }))
}

/// How long one poll waits; also how soon an idle consumer notices shutdown.
const POLL_WAIT: Duration = Duration::from_secs(1);

/// Starts the consumer threads of one Kafka connector entry; false when it does not start.
pub fn start(parser: Arc<dyn Parser>, props: &Properties) -> bool {
    let s = match parse_settings(props, &crate::secrets::key_source) {
        Ok(s) => s,
        Err(InputError::Invalid(lines)) => {
            lines.iter().for_each(|l| log_line!(l));
            return false;
        }
        Err(InputError::Exit(lines)) => {
            lines.iter().for_each(|l| log_line!(l));
            std::process::exit(1);
        }
    };
    // As in FlowLink: one parser channel for all instances, 10 workers per instance.
    let ch = parser.start_workers(10 * s.instances);
    // Shared by all Kafka connectors; the consumer's own meter is marked by the parser.
    let kafka_meter = get_or_register_meter("kafka");
    for i in 0..s.instances {
        let group = GroupSettings::for_instance(&s, i);
        let inst = Instance { client_id: group.client_id.clone(), brokers_raw: s.brokers_raw.clone(), device_addr: s.device_addr.clone() };
        let (ch, kafka_meter) = (ch.clone(), kafka_meter.clone());
        // A std thread of its own: `GroupConsumer` blocks on the shared Kafka runtime, which must
        // not happen on one of the runtime's workers.
        thread::spawn(move || {
            let _guard = ThreadGuard::core("kafka consumer");
            let mut connect = || GroupConsumer::connect(&group).map(|g| Box::new(g) as Box<dyn Member>);
            run_instance(&mut connect, &ch, &inst, &kafka_meter, &crate::log::shutdown, Timing::FLOWLINK);
        });
    }
    true
}

/// What one consumer instance logs and stamps on its datagrams.
#[derive(Debug, Clone)]
pub(crate) struct Instance {
    pub client_id: String,
    /// `brokers` as configured, for the log lines.
    pub brokers_raw: String,
    pub device_addr: String,
}

/// Connection retry timing.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timing {
    /// The wait between two connection attempts.
    pub retry: Duration,
    /// After failing this long the process exits 1.
    pub give_up: Duration,
}

impl Timing {
    pub const FLOWLINK: Timing = Timing { retry: Duration::from_secs(60), give_up: Duration::from_secs(20 * 60) };
}

/// True once connecting has failed for `limit`; checked after a failure, before the wait.
pub(crate) fn give_up(elapsed: Duration, limit: Duration) -> bool {
    elapsed >= limit
}

/// One consumer instance until shutdown: connect (with retry), consume, and on a client error close
/// the member and connect again.
pub(crate) fn run_instance(
    connect: &mut dyn FnMut() -> Result<Box<dyn Member>, String>,
    ch: &Sender<ReceivedDatagram>,
    inst: &Instance,
    kafka_meter: &Meter,
    stop: &dyn Fn() -> bool,
    timing: Timing,
) {
    while !stop() {
        let start = Instant::now();
        let Some(mut member) = connect_with_retry(connect, &inst.brokers_raw, stop, &mut thread::sleep, &|| start.elapsed(), timing)
        else {
            break;
        };
        log_line!("Client:", inst.client_id, "connected to kafka brokers:", inst.brokers_raw);
        let result = consume(member.as_mut(), ch, &inst.device_addr, &inst.client_id, kafka_meter, stop);
        // Commits the marks and leaves the group. Fix: FlowLink never closes its consumer group,
        // and leaks one on every client error.
        member.close();
        match result {
            Err(e) => log_line!("Client error:", e),
            Ok(()) => break,
        }
    }
    log_line!("kafka exiting");
}

/// Calls `connect` until it succeeds, logging each error and waiting `timing.retry` (in 1 s steps)
/// between attempts. `None` once `stop()`; exits 1 when the attempts have failed for
/// `timing.give_up`.
pub(crate) fn connect_with_retry<C>(
    connect: &mut dyn FnMut() -> Result<C, String>,
    brokers_raw: &str,
    stop: &dyn Fn() -> bool,
    sleep: &mut dyn FnMut(Duration),
    elapsed: &dyn Fn() -> Duration,
    timing: Timing,
) -> Option<C> {
    const STEP: Duration = Duration::from_secs(1);
    loop {
        if stop() {
            return None;
        }
        match connect() {
            Ok(c) => return Some(c),
            Err(e) => log_line!(e),
        }
        if give_up(elapsed(), timing.give_up) {
            log_line!("Unable to connect to kafka brokers:", brokers_raw, "for 20 minutes. Exiting.");
            std::process::exit(1);
        }
        // Divergence: FlowLink sleeps the whole minute without looking at the shutdown flag.
        let mut left = timing.retry;
        while !left.is_zero() {
            if stop() {
                return None;
            }
            let step = left.min(STEP);
            sleep(step);
            left -= step;
        }
    }
}

/// Polls `member` and hands every message to the parser until `stop()` (Ok) or a poll error (Err).
/// Ok as well when the parser channel is closed.
pub(crate) fn consume(
    member: &mut dyn Member,
    ch: &Sender<ReceivedDatagram>,
    device_addr: &str,
    client_id: &str,
    kafka_meter: &Meter,
    stop: &dyn Fn() -> bool,
) -> Result<(), String> {
    while !stop() {
        // Every message of a poll is handed over and marked before the next poll.
        for m in member.poll(POLL_WAIT)? {
            // Fix: FlowLink drops the message it receives at shutdown; here it is handed over. The
            // parsers drain the channel before the process exits.
            debug_log!(
                client_id,
                ": Message claimed: value: '",
                String::from_utf8_lossy(&m.value),
                "', timestamp:",
                m.timestamp.map(|t| t.to_rfc3339()).unwrap_or_default(),
                ", topic:",
                m.topic
            );
            // Blocks while the parser channel is full. A member blocked here for longer than the
            // group's rebalance timeout (60 s) loses its partitions; the messages it has not marked
            // yet are delivered again (at-least-once).
            if ch.send(to_datagram(&m, device_addr)).is_err() {
                return Ok(());
            }
            // Marked only once the parser has it (at-least-once), as in FlowLink.
            member.mark(&m);
            kafka_meter.mark(1);
        }
    }
    Ok(())
}

/// One message as one text datagram: the first configured broker as device address, no sequence
/// id, the whole value.
pub(crate) fn to_datagram(m: &InMessage, device_addr: &str) -> ReceivedDatagram {
    // Divergence: FlowLink truncates the value at 65 536 bytes without notice; it is passed whole.
    ReceivedDatagram { device_addr: device_addr.to_string(), seq_id: String::new(), transport: "kafka".into(), buf: m.value.clone() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::Receiver;

    const CERT: &str = include_str!("../../tests/fixtures/kafka/client.pem");
    const KEY: &str = include_str!("../../tests/fixtures/kafka/client.key");
    const OTHER_CERT: &str = include_str!("../../tests/fixtures/kafka/other.pem");
    const OTHER_KEY: &str = include_str!("../../tests/fixtures/kafka/other.key");

    fn props(kv: &[(&str, &str)]) -> Properties {
        kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn base(extra: &[(&str, &str)]) -> Properties {
        let mut p = props(&[("brokers", "k1:9092,k2:9092"), ("version", "2.8.1"), ("group", "g"), ("topics", "t")]);
        p.extend(props(extra));
        p
    }

    fn no_read(_: &str) -> String {
        unreachable!("no file property expected")
    }

    /// Reads `certs` / `keys` sources by name.
    fn files<'a>(certs: &'a str, keys: &'a str) -> impl Fn(&str) -> String + 'a {
        move |src| match src {
            "certs" => certs.to_string(),
            "keys" => keys.to_string(),
            other => panic!("unexpected source {other}"),
        }
    }

    fn tls_props() -> Properties {
        base(&[("broker_certs", "certs"), ("broker_keys", "keys")])
    }

    fn exit_lines(r: Result<InputSettings, InputError>) -> Vec<String> {
        match r {
            Err(InputError::Exit(lines)) => lines,
            other => panic!("expected Exit, got {other:?}"),
        }
    }

    #[test]
    fn version_grammar() {
        for ok in ["2.8.1", "3.2.0", "0.10.2.0", "9.9.9"] {
            assert!(parse_version(ok).is_ok(), "{ok}");
        }
        for bad in ["2.8", "v2.8.1", "2.8.1.0", "", "0.10.2", "2.8.1\n", "2.8.x", "1.2.99999999999"] {
            assert_eq!(parse_version(bad).unwrap_err(), format!("invalid version `{bad}`"));
        }
        assert_eq!(parse_version("2.8.1").unwrap(), KafkaVersion([2, 8, 1, 0]));
        assert_eq!(parse_version("0.10.2.0").unwrap(), KafkaVersion([0, 10, 2, 0]));
        assert_eq!(parse_version("0.11.0.2").unwrap(), KafkaVersion([0, 11, 0, 2]));
    }

    #[test]
    fn defaults_instances_and_client_ids() {
        let s = parse_settings(&base(&[]), &no_read).ok().unwrap();
        assert_eq!((s.instances, s.client_ids.clone()), (2, vec!["Illumio-flowlink-0".to_string(), "Illumio-flowlink-1".into()]));
        assert_eq!((s.group.as_str(), s.version, s.tls_pem), ("g", KafkaVersion([2, 8, 1, 0]), None));

        let s = parse_settings(&base(&[("instances", "1"), ("client_id", "c")]), &no_read).ok().unwrap();
        assert_eq!((s.instances, s.client_ids), (1, vec!["c".to_string()]));
        let s = parse_settings(&base(&[("instances", "3"), ("client_id", "c")]), &no_read).ok().unwrap();
        assert_eq!(s.client_ids, ["c-0", "c-1", "c-2"]);
        assert_eq!(parse_settings(&base(&[("instances", "0")]), &no_read).ok().unwrap().instances, 2);

        let mut lines = Vec::new();
        let captured = crate::log::capture(|| lines.push(parse_settings(&base(&[("instances", "x")]), &no_read).ok().unwrap().instances));
        assert_eq!(lines, [2]);
        assert_eq!(captured, ["Invalid kafka instances value, must be numeric. Using default instances."]);

        assert_eq!(
            parse_settings(&base(&[("instances", "-1")]), &no_read).unwrap_err(),
            InputError::Invalid(vec!["Invalid kafka instances value: -1".into()])
        );
    }

    #[test]
    fn brokers_trimmed_device_addr_raw() {
        let p = props(&[("brokers", " k1:9092, k2:9092,"), ("version", "2.8.1"), ("group", "g"), ("topics", "a, b")]);
        let s = parse_settings(&p, &no_read).ok().unwrap();
        assert_eq!(s.brokers, ["k1:9092", "k2:9092"]);
        assert_eq!(s.brokers_raw, " k1:9092, k2:9092,");
        assert_eq!(s.device_addr, " k1:9092");
        assert_eq!(s.instances, 3);
        assert_eq!(s.topics, ["a", "b"]);
        let p = props(&[("brokers", "a:9092,"), ("version", "2.8.1"), ("group", "g"), ("topics", ",x,,")]);
        let s = parse_settings(&p, &no_read).ok().unwrap();
        assert_eq!((s.instances, s.topics), (2, vec!["x".to_string()]));
    }

    #[test]
    fn missing_properties_reported_in_order() {
        let mut r = None;
        let logged = crate::log::capture(|| r = Some(parse_settings(&Properties::new(), &no_read)));
        assert_eq!(logged, ["Error: invalid version ``"]);
        assert_eq!(
            r.unwrap().unwrap_err(),
            InputError::Invalid(vec![
                "Missing kafka property: brokers".into(),
                "Missing kafka property: version".into(),
                "Missing kafka property: group".into(),
                "Missing kafka property: topics".into(),
            ])
        );
        let r = parse_settings(&props(&[("brokers", "b"), ("version", "2.8.1")]), &no_read).unwrap_err();
        assert_eq!(r, InputError::Invalid(vec!["Missing kafka property: group".into(), "Missing kafka property: topics".into()]));
    }

    #[test]
    fn invalid_version_logs_and_does_not_start() {
        let mut r = None;
        let logged = crate::log::capture(|| r = Some(parse_settings(&base(&[("version", "2.8")]), &no_read)));
        assert_eq!(logged, ["Error: invalid version `2.8`"]);
        assert_eq!(r.unwrap().unwrap_err(), InputError::Invalid(vec![]));
    }

    #[test]
    fn tls_material_rules() {
        let only_certs = base(&[("broker_certs", "certs")]);
        assert_eq!(exit_lines(parse_settings(&only_certs, &no_read)), ["Missing script for broker certificate keys."]);

        let two = format!("{CERT}{OTHER_CERT}");
        assert_eq!(
            exit_lines(parse_settings(&tls_props(), &files(&two, KEY))),
            ["Number of broker certs doesn't match number of broker keys."]
        );

        let garbage = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let lines = exit_lines(parse_settings(&tls_props(), &files(garbage, KEY)));
        assert!(lines.len() == 1 && lines[0].starts_with("Error: "), "{lines:?}");
        // A key that does not belong to its certificate.
        let lines = exit_lines(parse_settings(&tls_props(), &files(CERT, OTHER_KEY)));
        assert!(lines.len() == 1 && lines[0].starts_with("Error: "), "{lines:?}");
        // The second pair is checked too, although only the first is offered.
        let lines = exit_lines(parse_settings(&tls_props(), &files(&two, &format!("{KEY}{KEY}"))));
        assert!(lines.len() == 1 && lines[0].starts_with("Error: "), "{lines:?}");

        let s = parse_settings(&tls_props(), &files(CERT, KEY)).ok().unwrap();
        let tls = s.tls_pem.unwrap();
        let client = tls.client.unwrap();
        assert_eq!((client.cert_pem.as_str(), client.key_pem.as_str()), (CERT, KEY));
        // The system roots (their order may vary between loads).
        let sorted = |pem: &str| {
            let mut b = split_pem_blocks(pem);
            b.sort();
            b
        };
        assert_eq!(sorted(&tls.roots_pem), sorted(&crate::kafka::tls::system_roots_pem()));

        let s = parse_settings(&tls_props(), &files(&two, &format!("{KEY}{OTHER_KEY}"))).ok().unwrap();
        assert_eq!(s.tls_pem.unwrap().client.unwrap().cert_pem, CERT);

        let s = parse_settings(&tls_props(), &files("", "")).ok().unwrap();
        assert_eq!(s.tls_pem.unwrap().client, None);
    }

    #[test]
    fn key_material_never_in_debug_or_logs() {
        let mut r = None;
        let logged = crate::log::capture(|| r = Some(parse_settings(&tls_props(), &files(CERT, KEY))));
        let s = r.unwrap().ok().unwrap();
        let key_body = KEY.lines().nth(1).unwrap();
        assert!(!format!("{s:?}").contains(key_body));
        assert!(format!("{s:?}").contains("TlsPem"));
        assert!(logged.iter().all(|l| !l.contains(key_body)), "{logged:?}");
    }

    // ---- run loop ----

    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    fn msg(offset: i64, value: &str) -> InMessage {
        InMessage { topic: "t".into(), partition: 0, offset, timestamp: None, value: value.into() }
    }

    #[derive(Default)]
    struct Seen {
        polls: usize,
        /// (offset, datagrams in the channel when the message was marked)
        marked: Vec<(i64, usize)>,
        closed: usize,
    }

    /// Hands out `batches`, then empty polls (sleeping the poll's wait when `idle`).
    struct FakeMember {
        batches: VecDeque<Result<Vec<InMessage>, String>>,
        idle: bool,
        seen: Arc<Mutex<Seen>>,
        rx: Receiver<ReceivedDatagram>,
    }

    impl Member for FakeMember {
        fn poll(&mut self, d: Duration) -> Result<Vec<InMessage>, String> {
            self.seen.lock().unwrap().polls += 1;
            match self.batches.pop_front() {
                Some(b) => b,
                None => {
                    if self.idle {
                        std::thread::sleep(d);
                    }
                    Ok(vec![])
                }
            }
        }

        fn mark(&mut self, m: &InMessage) {
            self.seen.lock().unwrap().marked.push((m.offset, self.rx.len()));
        }

        fn close(self: Box<Self>) {
            self.seen.lock().unwrap().closed += 1;
        }
    }

    fn instance() -> Instance {
        Instance { client_id: "c".into(), brokers_raw: "k1:9092,k2:9092".into(), device_addr: "k1:9092".into() }
    }

    #[test]
    fn message_becomes_one_datagram() {
        let m = InMessage { topic: "t".into(), partition: 0, offset: 5, timestamp: None, value: vec![b'x'; 70_000] };
        let d = to_datagram(&m, "k1:9092");
        assert_eq!((d.device_addr.as_str(), d.transport.as_str(), d.seq_id.as_str(), d.buf.len()), ("k1:9092", "kafka", "", 70_000));
        assert_eq!(d.buf, m.value);
    }

    #[test]
    fn connect_retries_every_60s_and_exits_after_20min() {
        // Fails three times, then connects: three 60 s waits, in 1 s steps.
        let clock = std::cell::Cell::new(Duration::ZERO);
        let mut sleeps = Vec::new();
        let mut attempts = 0;
        let mut connect = || {
            attempts += 1;
            if attempts <= 3 { Err(format!("no broker {attempts}")) } else { Ok(42) }
        };
        let mut r = None;
        let logged = crate::log::capture(|| {
            r = connect_with_retry(
                &mut connect,
                "k1:9092",
                &|| false,
                &mut |d| {
                    sleeps.push(d);
                    clock.set(clock.get() + d);
                },
                &|| clock.get(),
                Timing::FLOWLINK,
            )
        });
        assert_eq!(r, Some(42));
        assert_eq!(logged, ["no broker 1", "no broker 2", "no broker 3"]);
        assert_eq!(sleeps.len(), 180);
        assert!(sleeps.iter().all(|d| *d == Duration::from_secs(1)));
        assert_eq!(clock.get(), Duration::from_secs(180));

        // Stop during the second wait: no further attempt, None.
        let clock = std::cell::Cell::new(Duration::ZERO);
        let mut attempts = 0;
        let r: Option<()> = connect_with_retry(
            &mut || {
                attempts += 1;
                Err("down".into())
            },
            "k1:9092",
            &|| clock.get() >= Duration::from_secs(90),
            &mut |d| clock.set(clock.get() + d),
            &|| clock.get(),
            Timing::FLOWLINK,
        );
        assert_eq!(r, None);
        assert_eq!(attempts, 2);
        assert_eq!(clock.get(), Duration::from_secs(90));

        // The give-up check: FlowLink's values, at or after the limit.
        assert_eq!((Timing::FLOWLINK.retry, Timing::FLOWLINK.give_up), (Duration::from_secs(60), Duration::from_secs(1200)));
        assert!(!give_up(Duration::from_secs(19 * 60 + 59), Timing::FLOWLINK.give_up));
        assert!(give_up(Duration::from_secs(20 * 60), Timing::FLOWLINK.give_up));
        assert!(give_up(Duration::from_secs(21 * 60), Timing::FLOWLINK.give_up));
    }

    #[test]
    fn consume_marks_after_handoff_and_counts_meter() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let mut m = FakeMember {
            batches: VecDeque::from([Ok(vec![msg(0, "a b"), msg(1, "c d")])]),
            idle: false,
            seen: seen.clone(),
            rx: rx.clone(),
        };
        let meter = Meter::new();
        let stop = || seen.lock().unwrap().polls >= 2;
        assert_eq!(consume(&mut m, &tx, "k1:9092", "c", &meter, &stop), Ok(()));
        let got: Vec<ReceivedDatagram> = rx.try_iter().collect();
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].buf.as_slice(), got[1].buf.as_slice()), (&b"a b"[..], &b"c d"[..]));
        assert!(got.iter().all(|d| d.device_addr == "k1:9092" && d.transport == "kafka"));
        // Each message is marked only once it is in the channel.
        assert_eq!(seen.lock().unwrap().marked, [(0, 1), (1, 2)]);
        assert_eq!(meter.count(), 2);
        assert_eq!(seen.lock().unwrap().closed, 0, "consume does not close");
    }

    #[test]
    fn consume_returns_poll_error() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let mut m = FakeMember { batches: VecDeque::from([Err("boom".to_string())]), idle: false, seen, rx };
        assert_eq!(consume(&mut m, &tx, "k1:9092", "c", &Meter::new(), &|| false), Err("boom".to_string()));
    }

    #[test]
    fn idle_consumer_stops_on_shutdown() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let mut connects = 0;
        let mut connect = || -> Result<Box<dyn Member>, String> {
            connects += 1;
            Ok(Box::new(FakeMember { batches: VecDeque::new(), idle: true, seen: seen.clone(), rx: rx.clone() }))
        };
        let start = Instant::now();
        let stop = || start.elapsed() >= Duration::from_millis(1500);
        let logged = crate::log::capture(|| run_instance(&mut connect, &tx, &instance(), &Meter::new(), &stop, Timing::FLOWLINK));
        let took = start.elapsed();
        assert!(took >= Duration::from_millis(1500) && took < Duration::from_secs(3), "{took:?}");
        assert_eq!(connects, 1);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.closed, 1);
        assert!(seen.polls >= 2, "{}", seen.polls);
        assert_eq!(logged, ["Client: c connected to kafka brokers: k1:9092,k2:9092", "kafka exiting"]);
    }

    #[test]
    fn poll_error_closes_member_and_reconnects() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let mut connects = 0;
        let mut connect = || -> Result<Box<dyn Member>, String> {
            connects += 1;
            let batches = if connects == 1 { VecDeque::from([Err("broker gone".to_string())]) } else { VecDeque::new() };
            Ok(Box::new(FakeMember { batches, idle: false, seen: seen.clone(), rx: rx.clone() }))
        };
        // Stops at the second member's first (empty) poll.
        let stop = || seen.lock().unwrap().polls >= 2;
        let logged = crate::log::capture(|| run_instance(&mut connect, &tx, &instance(), &Meter::new(), &stop, Timing::FLOWLINK));
        assert_eq!(connects, 2);
        assert_eq!(seen.lock().unwrap().closed, 2, "the failed member is closed before reconnecting");
        assert_eq!(
            logged,
            [
                "Client: c connected to kafka brokers: k1:9092,k2:9092",
                "Client error: broker gone",
                "Client: c connected to kafka brokers: k1:9092,k2:9092",
                "kafka exiting",
            ]
        );
    }

    #[test]
    fn stop_before_connect_logs_kafka_exiting() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let mut connect = || -> Result<Box<dyn Member>, String> { panic!("no connect after stop") };
        let logged = crate::log::capture(|| run_instance(&mut connect, &tx, &instance(), &Meter::new(), &|| true, Timing::FLOWLINK));
        assert_eq!(logged, ["kafka exiting"]);
    }

    #[test]
    fn pem_blocks_split_like_flowlink() {
        assert_eq!(
            split_pem_blocks("junk-----BEGIN A-----\nx\n-----BEGIN B-----\ny\n"),
            ["-----BEGIN A-----\nx\n", "-----BEGIN B-----\ny\n"]
        );
        assert!(split_pem_blocks("").is_empty());
        assert!(split_pem_blocks("no marker here").is_empty());
        assert_eq!(split_pem_blocks(&format!("{CERT}{OTHER_CERT}")), [CERT, OTHER_CERT]);
    }
}
