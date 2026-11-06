//! Kafka consumer group against the test broker. Skipped unless `FLOWPILOT_TEST_KAFKA` names the
//! PLAINTEXT listener; the mTLS test also needs `FLOWPILOT_TEST_KAFKA_TLS` (the SSL listener, client
//! certificate required) and the test CA as `SSL_CERT_FILE`:
//!
//!     tests/kafka/broker.sh up host
//!     SSL_CERT_FILE=target/kafka-certs/ca.pem FLOWPILOT_TEST_KAFKA=localhost:9092 \
//!         FLOWPILOT_TEST_KAFKA_TLS=localhost:9094 cargo test --test kafka_group
//!     tests/kafka/broker.sh down

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use flowpilot::kafka::group::{GroupConsumer, GroupSettings, InMessage};
use flowpilot::kafka::input::{parse_version, ClientPem, TlsPem};
use flowpilot::kafka::{runtime, tls};
use rskafka::client::partition::{Compression, UnknownTopicHandling};
use rskafka::client::{Client, ClientBuilder};
use rskafka::record::Record;

const PARTITIONS: i32 = 4;

fn certs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/kafka-certs")
}

fn read_cert(f: &str) -> String {
    std::fs::read_to_string(certs().join(f)).unwrap_or_else(|e| panic!("target/kafka-certs/{f}: {e}"))
}

/// The value of `var`, or `None` (test skipped) when it is unset.
fn env_broker(var: &str, test: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(b) if !b.is_empty() => Some(b),
        _ => {
            eprintln!("skipped: {test} needs {var} (tests/kafka/broker.sh up host)");
            None
        }
    }
}

/// A name no other run has used.
fn unique(prefix: &str) -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("{prefix}-{nanos}")
}

fn settings(broker: &str, group: &str, topic: &str, client_id: &str) -> GroupSettings {
    GroupSettings {
        brokers: vec![broker.to_string()],
        group: group.to_string(),
        topics: vec![topic.to_string()],
        client_id: client_id.to_string(),
        version: parse_version("2.8.1").unwrap(),
        tls: None,
    }
}

/// Test-side admin and producer (plain rskafka).
struct Admin(Client);

impl Admin {
    fn connect(broker: &str, tls: Option<Arc<rustls::ClientConfig>>) -> Admin {
        runtime().block_on(async {
            let mut b = ClientBuilder::new(vec![broker.to_string()]);
            if let Some(t) = tls {
                b = b.tls_config(t);
            }
            Admin(b.build().await.expect("admin client"))
        })
    }

    fn create_topic(&self, topic: &str) {
        runtime().block_on(async {
            self.0.controller_client().unwrap().create_topic(topic, PARTITIONS, 1, 10_000).await.expect("create topic")
        })
    }

    /// Produces `values` to `partition`.
    fn produce(&self, topic: &str, partition: i32, values: &[String]) {
        runtime().block_on(async {
            let pc = self.0.partition_client(topic, partition, UnknownTopicHandling::Retry).await.expect("partition client");
            let records = values
                .iter()
                .map(|v| Record { key: None, value: Some(v.as_bytes().to_vec()), headers: BTreeMap::new(), timestamp: chrono::Utc::now() })
                .collect();
            pc.produce(records, Compression::NoCompression).await.expect("produce");
        })
    }

    /// `n` messages per partition, valued `p<partition>-<i>` with `i` from `first`.
    fn produce_each(&self, topic: &str, first: usize, n: usize) {
        for p in 0..PARTITIONS {
            let values: Vec<String> = (first..first + n).map(|i| format!("p{p}-{i}")).collect();
            self.produce(topic, p, &values);
        }
    }
}

fn text(m: &InMessage) -> String {
    String::from_utf8(m.value.clone()).unwrap()
}

/// Polls (marking every message) until `n` messages arrived or `limit` passed.
fn consume(c: &mut GroupConsumer, n: usize, limit: Duration) -> Vec<InMessage> {
    let start = Instant::now();
    let mut got = Vec::new();
    while got.len() < n && start.elapsed() < limit {
        for m in c.poll(Duration::from_millis(500)).expect("poll") {
            c.mark(&m);
            got.push(m);
        }
    }
    got
}

#[test]
fn new_group_starts_at_oldest() {
    let Some(b) = env_broker("FLOWPILOT_TEST_KAFKA", "new_group_starts_at_oldest") else { return };
    let topic = unique("oldest");
    let admin = Admin::connect(&b, None);
    admin.create_topic(&topic);
    admin.produce_each(&topic, 0, 5);

    let mut c = GroupConsumer::connect(&settings(&b, &unique("g"), &topic, "t-0")).expect("connect");
    let got = consume(&mut c, 20, Duration::from_secs(30));
    c.close();

    assert_eq!(got.len(), 20, "{:?}", got.iter().map(text).collect::<Vec<_>>());
    for p in 0..PARTITIONS {
        let mine: Vec<&InMessage> = got.iter().filter(|m| m.partition == p).collect();
        let values: Vec<String> = mine.iter().map(|m| text(m)).collect();
        assert_eq!(values, (0..5).map(|i| format!("p{p}-{i}")).collect::<Vec<_>>(), "partition {p}");
        assert_eq!(mine.iter().map(|m| m.offset).collect::<Vec<_>>(), [0, 1, 2, 3, 4], "partition {p}");
        assert!(mine.iter().all(|m| m.topic == topic && m.timestamp.is_some()));
    }
}

/// One member on its own thread: polls and marks until `stop`, publishing what it got and its
/// assignment.
struct Member {
    got: Arc<Mutex<Vec<InMessage>>>,
    assigned: Arc<Mutex<Vec<(String, i32)>>>,
    thread: std::thread::JoinHandle<()>,
}

fn spawn_member(mut c: GroupConsumer, stop: Arc<AtomicBool>) -> Member {
    let got = Arc::new(Mutex::new(Vec::new()));
    let assigned = Arc::new(Mutex::new(Vec::new()));
    let (g, a) = (got.clone(), assigned.clone());
    let thread = std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            for m in c.poll(Duration::from_millis(500)).expect("poll") {
                c.mark(&m);
                g.lock().unwrap().push(m);
            }
            *a.lock().unwrap() = c.assignment();
        }
        c.close();
    });
    Member { got, assigned, thread }
}

#[test]
fn two_members_split_partitions() {
    let Some(b) = env_broker("FLOWPILOT_TEST_KAFKA", "two_members_split_partitions") else { return };
    let (topic, group) = (unique("split"), unique("g"));
    let admin = Admin::connect(&b, None);
    admin.create_topic(&topic);

    let stop = Arc::new(AtomicBool::new(false));
    let a = spawn_member(GroupConsumer::connect(&settings(&b, &group, &topic, "t-0")).expect("connect A"), stop.clone());
    let m_b = spawn_member(GroupConsumer::connect(&settings(&b, &group, &topic, "t-1")).expect("connect B"), stop.clone());

    // Both members joined and the 4 partitions are split between them.
    let start = Instant::now();
    let (asg_a, asg_b) = loop {
        let (x, y) = (a.assigned.lock().unwrap().clone(), m_b.assigned.lock().unwrap().clone());
        if !x.is_empty() && !y.is_empty() && x.len() + y.len() == PARTITIONS as usize {
            break (x, y);
        }
        assert!(start.elapsed() < Duration::from_secs(60), "no split: A {x:?}, B {y:?}");
        std::thread::sleep(Duration::from_millis(200));
    };
    eprintln!("assignment A {asg_a:?}, B {asg_b:?}");
    // Range: contiguous halves.
    let parts = |v: &[(String, i32)]| v.iter().map(|(_, p)| *p).collect::<Vec<_>>();
    let mut halves = [parts(&asg_a), parts(&asg_b)];
    halves.sort();
    assert_eq!(halves, [vec![0, 1], vec![2, 3]]);

    admin.produce_each(&topic, 0, 25);
    let start = Instant::now();
    while a.got.lock().unwrap().len() + m_b.got.lock().unwrap().len() < 100 && start.elapsed() < Duration::from_secs(30) {
        std::thread::sleep(Duration::from_millis(200));
    }
    // Time for any duplicate to show up.
    std::thread::sleep(Duration::from_secs(2));
    stop.store(true, Ordering::SeqCst);
    a.thread.join().unwrap();
    m_b.thread.join().unwrap();

    let got_a: Vec<String> = a.got.lock().unwrap().iter().map(text).collect();
    let got_b: Vec<String> = m_b.got.lock().unwrap().iter().map(text).collect();
    assert!(!got_a.is_empty() && !got_b.is_empty(), "A {} B {}", got_a.len(), got_b.len());
    let all: Vec<&String> = got_a.iter().chain(&got_b).collect();
    let distinct: BTreeSet<&String> = all.iter().copied().collect();
    assert_eq!(all.len(), 100, "duplicates or losses: A {got_a:?} B {got_b:?}");
    assert_eq!(distinct.len(), 100);
    // Each member only got its own partitions.
    for (got, asg) in [(&a.got, &asg_a), (&m_b.got, &asg_b)] {
        let mine: BTreeSet<i32> = asg.iter().map(|(_, p)| *p).collect();
        assert!(got.lock().unwrap().iter().all(|m| mine.contains(&m.partition)));
    }
}

#[test]
fn committed_offsets_resume() {
    let Some(b) = env_broker("FLOWPILOT_TEST_KAFKA", "committed_offsets_resume") else { return };
    let (topic, group) = (unique("resume"), unique("g"));
    let admin = Admin::connect(&b, None);
    admin.create_topic(&topic);
    admin.produce_each(&topic, 0, 5);

    let mut c = GroupConsumer::connect(&settings(&b, &group, &topic, "t-0")).expect("connect");
    assert_eq!(consume(&mut c, 20, Duration::from_secs(30)).len(), 20);
    // close() commits the marks although the 1 s commit tick may not have come yet.
    c.close();

    admin.produce(&topic, 0, &["late-0".into(), "late-1".into(), "late-2".into()]);
    admin.produce(&topic, 3, &["late-3".into(), "late-4".into()]);
    let mut c = GroupConsumer::connect(&settings(&b, &group, &topic, "t-0")).expect("reconnect");
    let mut got = consume(&mut c, 5, Duration::from_secs(30));
    // Nothing else arrives.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        got.extend(c.poll(Duration::from_millis(500)).expect("poll"));
    }
    c.close();
    let mut values: Vec<String> = got.iter().map(text).collect();
    values.sort();
    assert_eq!(values, ["late-0", "late-1", "late-2", "late-3", "late-4"]);
    assert!(got.iter().filter(|m| m.partition == 0).map(|m| m.offset).eq([5, 6, 7]));
}

#[test]
fn unmarked_messages_are_delivered_again() {
    let Some(b) = env_broker("FLOWPILOT_TEST_KAFKA", "unmarked_messages_are_delivered_again") else { return };
    let (topic, group) = (unique("unmarked"), unique("g"));
    let admin = Admin::connect(&b, None);
    admin.create_topic(&topic);
    admin.produce(&topic, 1, &["a".into(), "b".into(), "c".into()]);

    let mut c = GroupConsumer::connect(&settings(&b, &group, &topic, "t-0")).expect("connect");
    let start = Instant::now();
    let mut got = Vec::new();
    while got.len() < 3 && start.elapsed() < Duration::from_secs(30) {
        got.extend(c.poll(Duration::from_millis(500)).expect("poll"));
    }
    assert_eq!(got.len(), 3);
    // Only the first is handed off; at-least-once: b and c come again.
    c.mark(&got[0]);
    c.close();

    let mut c = GroupConsumer::connect(&settings(&b, &group, &topic, "t-0")).expect("reconnect");
    let again = consume(&mut c, 2, Duration::from_secs(30));
    c.close();
    assert_eq!(again.iter().map(text).collect::<Vec<_>>(), ["b", "c"]);
}

#[test]
fn tls_client_cert() {
    let Some(b) = env_broker("FLOWPILOT_TEST_KAFKA_TLS", "tls_client_cert") else { return };
    assert!(
        std::env::var("SSL_CERT_FILE").is_ok_and(|f| f.ends_with("ca.pem")),
        "set SSL_CERT_FILE=target/kafka-certs/ca.pem so the test CA is the trust store"
    );
    let (cert, key) = (read_cert("client.pem"), read_cert("client.key"));
    let topic = unique("tls");
    let admin = Admin::connect(&b, Some(tls::client_auth_config(&cert, &key).unwrap()));
    admin.create_topic(&topic);
    admin.produce(&topic, 2, &["over-tls".into()]);

    let mut s = settings(&b, &unique("g"), &topic, "t-0");
    s.tls = Some(TlsPem { client: Some(ClientPem { cert_pem: cert, key_pem: key.clone() }), roots_pem: tls::system_roots_pem() });
    let mut c = GroupConsumer::connect(&s).expect("connect with client cert");
    let got = consume(&mut c, 1, Duration::from_secs(30));
    c.close();
    assert_eq!(got.iter().map(text).collect::<Vec<_>>(), ["over-tls"]);
    assert_eq!(got[0].partition, 2);

    // The key never shows in Debug output.
    let key_body = key.lines().nth(1).unwrap();
    assert!(!format!("{s:?}").contains(key_body));

    s.tls = Some(TlsPem { client: None, roots_pem: tls::system_roots_pem() });
    s.group = unique("g");
    let err = GroupConsumer::connect(&s).expect_err("connect without a client certificate succeeded");
    eprintln!("without client cert: {err}");
    assert!(err.contains("CertificateRequired"), "{err}");
}

#[test]
fn old_version_rejected() {
    let Some(b) = env_broker("FLOWPILOT_TEST_KAFKA", "old_version_rejected") else { return };
    let mut s = settings(&b, &unique("g"), "any", "t-0");
    s.version = parse_version("0.10.1.0").unwrap();
    let err = GroupConsumer::connect(&s).expect_err("old version accepted");
    assert_eq!(err, "kafka: invalid configuration (consumer groups require Version to be >= V0_10_2_0)");
}
