//! Kafka consumer group for the input connector: a thin blocking adapter over krafka, run on the
//! shared Kafka runtime.
//!
//! Offsets are committed for marked messages only (at-least-once): every second on the poll path,
//! before partitions are revoked in a rebalance, and on `close`. Library logging goes through
//! `tracing`; FlowPilot installs no subscriber, so it stays silent.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use krafka::auth::{AuthConfig, TlsConfig};
use krafka::consumer::{
    AutoOffsetReset, Consumer, ConsumerRebalanceListener, OffsetAndMetadata, PartitionAssignmentStrategy, TopicPartition,
};
use krafka::{ConsumerRecord, Kafka};

use crate::debug_log;
use crate::kafka::input::{InputSettings, KafkaVersion, TlsPem};
use crate::kafka::runtime;

/// The oldest version with consumer groups.
pub const MIN_GROUP_VERSION: KafkaVersion = KafkaVersion([0, 10, 2, 0]);
/// `connect`'s error for an older `version`, as FlowLink logs it.
pub const OLD_VERSION_ERROR: &str =
    "kafka: invalid configuration (consumer groups require Version to be >= V0_10_2_0)";
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(10);
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);
/// How long a rebalance may take.
// Divergence: krafka sends `max_poll_interval` as the rebalance timeout, so a member that does not
// poll for this long also leaves the group (its partitions go to the others and come back on the
// next poll, at-least-once). FlowLink's client has no such limit.
pub const REBALANCE_TIMEOUT: Duration = Duration::from_secs(60);
/// Marked offsets are committed this often, before a revocation and on close.
// Divergence: the periodic commit runs on the poll path (at the first poll after the interval), not
// on a timer of its own; the run loop polls at least every second.
pub const COMMIT_INTERVAL: Duration = Duration::from_secs(1);
pub const FETCH_MAX_WAIT: Duration = Duration::from_millis(500);
/// Bytes fetched per partition and request. Larger messages still arrive whole.
pub const FETCH_BYTES: i32 = 1 << 20;

/// Where and how to consume: one instance of a Kafka connector.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupSettings {
    pub brokers: Vec<String>,
    pub group: String,
    pub topics: Vec<String>,
    pub client_id: String,
    /// Only gates consumer groups.
    // Divergence: krafka negotiates the protocol versions with the brokers; FlowLink's client
    // picks them from this version.
    pub version: KafkaVersion,
    /// `None`: plaintext.
    pub tls: Option<TlsPem>,
}

impl GroupSettings {
    /// The settings of instance `instance` (`0..s.instances`) of a connector.
    pub fn for_instance(s: &InputSettings, instance: usize) -> GroupSettings {
        GroupSettings {
            brokers: s.brokers.clone(),
            group: s.group.clone(),
            topics: s.topics.clone(),
            client_id: s.client_ids[instance].clone(),
            version: s.version,
            tls: s.tls_pem.clone(),
        }
    }
}

/// One consumed message.
#[derive(Debug, Clone, PartialEq)]
pub struct InMessage {
    pub topic: String,
    pub partition: i32,
    pub offset: i64,
    /// `None` when the record carries no timestamp.
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
    /// The whole value. Divergence: FlowLink truncates values at 65 536 bytes.
    pub value: Vec<u8>,
}

impl InMessage {
    fn from_record(r: ConsumerRecord) -> InMessage {
        InMessage {
            topic: r.topic.to_string(),
            partition: r.partition,
            offset: r.offset,
            timestamp: if r.timestamp < 0 { None } else { chrono::DateTime::from_timestamp_millis(r.timestamp) },
            value: r.value.map(|v| v.to_vec()).unwrap_or_default(),
        }
    }
}

/// What the run loop needs of a group member, so it can be tested with a fake.
pub trait Member: Send {
    fn poll(&mut self, max_wait: Duration) -> Result<Vec<InMessage>, String>;
    fn mark(&mut self, m: &InMessage);
    fn close(self: Box<Self>);
}

/// Next offset to commit per partition: the marked message's offset + 1.
type Marks = HashMap<(String, i32), i64>;

/// Records `m` as processed: its offset + 1 is the partition's next commit unless a later message
/// of the partition is already marked.
fn add_mark(marks: &mut Marks, m: &InMessage) {
    let next = marks.entry((m.topic.clone(), m.partition)).or_insert(m.offset + 1);
    *next = (*next).max(m.offset + 1);
}

/// Removes and returns the marks of `partitions` (all of them when `None`).
fn take_marks(marks: &mut Marks, partitions: Option<&[TopicPartition]>) -> Marks {
    match partitions {
        None => std::mem::take(marks),
        Some(ps) => ps.iter().filter_map(|tp| marks.remove_entry(&(tp.topic.clone(), tp.partition))).collect(),
    }
}

/// Puts back marks whose commit failed, unless a later mark arrived in the meantime.
fn restore_marks(marks: &mut Marks, failed: Marks) {
    for (k, v) in failed {
        marks.entry(k).or_insert(v);
    }
}

/// The marks shared with the rebalance listener, which commits them before a revocation.
struct Committer {
    marks: Mutex<Marks>,
    consumer: OnceLock<Weak<Consumer>>,
}

impl Committer {
    /// Commits the marks of `partitions` (all when `None`); failed ones stay marked.
    async fn commit(&self, consumer: &Consumer, partitions: Option<&[TopicPartition]>) -> Result<(), String> {
        let taken = take_marks(&mut self.marks.lock().unwrap(), partitions);
        if taken.is_empty() {
            return Ok(());
        }
        let offsets: Vec<(TopicPartition, OffsetAndMetadata)> = taken
            .iter()
            .map(|((t, p), o)| (TopicPartition::new(t.clone(), *p), OffsetAndMetadata::new(*o)))
            .collect();
        consumer.commit_offsets(offsets).await.map_err(|e| {
            restore_marks(&mut self.marks.lock().unwrap(), taken);
            e.to_string()
        })
    }
}

impl ConsumerRebalanceListener for Committer {
    async fn on_partitions_assigned(&self, _: &[TopicPartition]) {}

    async fn on_partitions_revoked(&self, partitions: &[TopicPartition]) {
        let Some(consumer) = self.consumer.get().and_then(Weak::upgrade) else { return };
        if let Err(e) = self.commit(&consumer, Some(partitions)).await {
            debug_log!("Kafka offset commit failed:", e);
        }
    }

    /// Another member may own these now: their marks are dropped, not committed.
    async fn on_partitions_lost(&self, partitions: &[TopicPartition]) {
        take_marks(&mut self.marks.lock().unwrap(), Some(partitions));
    }
}

/// A member of a consumer group.
pub struct GroupConsumer {
    consumer: Arc<Consumer>,
    committer: Arc<Committer>,
    last_commit: Instant,
    // The client the consumer was built from, closed with it.
    _kafka: Kafka,
}

impl fmt::Debug for GroupConsumer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupConsumer").finish_non_exhaustive()
    }
}

/// krafka's security settings: TLS against `roots_pem` only, with the client certificate if any.
fn auth_config(tls: Option<&TlsPem>) -> AuthConfig {
    match tls {
        None => AuthConfig::plaintext(),
        Some(t) => {
            let mut c = TlsConfig::new().with_ca_cert_pem(t.roots_pem.as_bytes().to_vec());
            if let Some(client) = &t.client {
                c = c.with_client_cert_pem(client.cert_pem.as_bytes().to_vec(), client.key_pem.as_bytes().to_vec());
            }
            AuthConfig::ssl(c)
        }
    }
}

impl GroupConsumer {
    /// Connects to the brokers and subscribes to the topics. Err: the text that is logged as is.
    // Divergence: krafka joins the group on the first `poll`, not here; join errors come from
    // `poll`, which the run loop handles like a lost connection.
    pub fn connect(s: &GroupSettings) -> Result<GroupConsumer, String> {
        if s.version.0 < MIN_GROUP_VERSION.0 {
            return Err(OLD_VERSION_ERROR.to_string());
        }
        let committer = Arc::new(Committer { marks: Mutex::new(Marks::new()), consumer: OnceLock::new() });
        let (kafka, consumer) = runtime().block_on(async {
            let kafka = Kafka::builder(s.brokers.join(","))
                .client_id(s.client_id.as_str())
                .security(auth_config(s.tls.as_ref()))
                .connect()
                .await
                .map_err(|e| e.to_string())?;
            let consumer = kafka
                .consumer(s.group.as_str())
                .auto_offset_reset(AutoOffsetReset::Earliest)
                .enable_auto_commit(false)
                .partition_assignment_strategy(PartitionAssignmentStrategy::Range)
                .session_timeout(SESSION_TIMEOUT)
                .heartbeat_interval(HEARTBEAT_INTERVAL)
                .max_poll_interval(REBALANCE_TIMEOUT)
                .fetch_max_wait(FETCH_MAX_WAIT)
                .max_partition_fetch_bytes(FETCH_BYTES)
                .rebalance_listener(committer.clone())
                .build()
                .await
                .map_err(|e| e.to_string())?;
            consumer.subscribe(&s.topics).await.map_err(|e| e.to_string())?;
            Ok::<_, String>((kafka, Arc::new(consumer)))
        })?;
        committer.consumer.set(Arc::downgrade(&consumer)).expect("set once");
        Ok(GroupConsumer { consumer, committer, last_commit: Instant::now(), _kafka: kafka })
    }

    /// Up to `max_wait`; heartbeats, rebalances and the 1 s offset commit happen inside. Ok(empty)
    /// on timeout.
    pub fn poll(&mut self, max_wait: Duration) -> Result<Vec<InMessage>, String> {
        let commit = self.last_commit.elapsed() >= COMMIT_INTERVAL;
        if commit {
            self.last_commit = Instant::now();
        }
        let (consumer, committer) = (&self.consumer, &self.committer);
        runtime().block_on(async {
            if commit {
                // As in FlowLink, a failed commit is not an error of the consumer; it is retried at
                // the next commit.
                if let Err(e) = committer.commit(consumer, None).await {
                    debug_log!("Kafka offset commit failed:", e);
                }
            }
            let records = consumer.poll(max_wait).await.map_err(|e| e.to_string())?;
            Ok(records.into_iter().map(InMessage::from_record).collect())
        })
    }

    /// Marks `m` processed: offset m.offset + 1 is committed at the next commit (at-least-once).
    pub fn mark(&mut self, m: &InMessage) {
        add_mark(&mut self.committer.marks.lock().unwrap(), m);
    }

    /// The partitions assigned to this member, sorted.
    pub fn assignment(&self) -> Vec<(String, i32)> {
        let mut v: Vec<(String, i32)> = runtime()
            .block_on(self.consumer.assignment())
            .into_iter()
            .flat_map(|(t, ps)| ps.into_iter().map(move |p| (t.clone(), p)))
            .collect();
        v.sort();
        v
    }

    /// Commits marked offsets, leaves the group, closes connections (FlowLink never closes: fix).
    pub fn close(self) {
        runtime().block_on(async {
            if let Err(e) = self.committer.commit(&self.consumer, None).await {
                debug_log!("Kafka offset commit failed:", e);
            }
            if let Err(e) = self.consumer.close().await {
                debug_log!("Kafka consumer close:", e);
            }
        });
    }
}

impl Member for GroupConsumer {
    fn poll(&mut self, max_wait: Duration) -> Result<Vec<InMessage>, String> {
        GroupConsumer::poll(self, max_wait)
    }

    fn mark(&mut self, m: &InMessage) {
        GroupConsumer::mark(self, m)
    }

    fn close(self: Box<Self>) {
        (*self).close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kafka::input::{parse_version, ClientPem};

    fn msg(topic: &str, partition: i32, offset: i64) -> InMessage {
        InMessage { topic: topic.into(), partition, offset, timestamp: None, value: vec![] }
    }

    fn settings(version: &str) -> GroupSettings {
        GroupSettings {
            // Nothing listens here; the version check comes before any I/O.
            brokers: vec!["127.0.0.1:1".into()],
            group: "g".into(),
            topics: vec!["t".into()],
            client_id: "c".into(),
            version: parse_version(version).unwrap(),
            tls: None,
        }
    }

    #[test]
    fn old_version_rejected_before_any_io() {
        for old in ["0.10.1.0", "0.10.1.1", "0.9.0.1", "0.8.2.2"] {
            assert_eq!(GroupConsumer::connect(&settings(old)).unwrap_err(), OLD_VERSION_ERROR, "{old}");
        }
        // 0.10.2.0 and later pass the check and fail only on the connection.
        for ok in ["0.10.2.0", "0.11.0.0", "2.8.1"] {
            assert_ne!(GroupConsumer::connect(&settings(ok)).unwrap_err(), OLD_VERSION_ERROR, "{ok}");
        }
    }

    #[test]
    fn marks_keep_the_highest_next_offset_per_partition() {
        let mut m = Marks::new();
        add_mark(&mut m, &msg("t", 0, 4));
        add_mark(&mut m, &msg("t", 0, 2));
        add_mark(&mut m, &msg("t", 1, 0));
        add_mark(&mut m, &msg("u", 0, 9));
        assert_eq!(m.len(), 3);
        assert_eq!((m[&("t".into(), 0)], m[&("t".into(), 1)], m[&("u".into(), 0)]), (5, 1, 10));
    }

    #[test]
    fn take_marks_by_partition_and_restore_keeps_newer() {
        let mut m = Marks::new();
        for (t, p, o) in [("t", 0, 4), ("t", 1, 7), ("u", 0, 1)] {
            add_mark(&mut m, &msg(t, p, o));
        }
        let taken = take_marks(&mut m, Some(&[TopicPartition::new("t", 1), TopicPartition::new("t", 3)]));
        assert_eq!(taken, Marks::from([(("t".into(), 1), 8)]));
        assert_eq!(m.len(), 2);

        // A later mark made while the commit was in flight wins over the failed one.
        add_mark(&mut m, &msg("t", 1, 9));
        restore_marks(&mut m, taken);
        assert_eq!(m[&("t".into(), 1)], 10);
        restore_marks(&mut m, Marks::from([(("v".into(), 2), 3)]));
        assert_eq!(m[&("v".into(), 2)], 3);

        let all = take_marks(&mut m, None);
        assert_eq!(all.len(), 4);
        assert!(m.is_empty());
    }

    #[test]
    fn record_becomes_whole_message() {
        let value = vec![b'x'; 70_000];
        let mut r = ConsumerRecord::new("t", 3, 42, None, Some(value.into()));
        r.timestamp = 1_700_000_000_123;
        let m = InMessage::from_record(r.clone());
        assert_eq!((m.topic.as_str(), m.partition, m.offset, m.value.len()), ("t", 3, 42, 70_000));
        assert_eq!(m.timestamp.unwrap().timestamp_millis(), 1_700_000_000_123);
        r.timestamp = -1;
        r.value = None;
        let m = InMessage::from_record(r);
        assert_eq!((m.timestamp, m.value.len()), (None, 0));
    }

    #[test]
    fn for_instance_takes_the_instance_client_id_and_tls() {
        let tls = TlsPem { client: Some(ClientPem { cert_pem: "C".into(), key_pem: "K".into() }), roots_pem: "R".into() };
        let s = InputSettings {
            brokers_raw: "k1:9092,k2:9092".into(),
            brokers: vec!["k1:9092".into(), "k2:9092".into()],
            device_addr: "k1:9092".into(),
            group: "g".into(),
            topics: vec!["a".into(), "b".into()],
            instances: 2,
            client_ids: vec!["c-0".into(), "c-1".into()],
            version: parse_version("2.8.1").unwrap(),
            tls_pem: Some(tls.clone()),
        };
        let g = GroupSettings::for_instance(&s, 1);
        assert_eq!(
            g,
            GroupSettings {
                brokers: s.brokers.clone(),
                group: "g".into(),
                topics: s.topics.clone(),
                client_id: "c-1".into(),
                version: s.version,
                tls: Some(tls),
            }
        );
        assert_eq!(GroupSettings::for_instance(&s, 0).client_id, "c-0");
    }

    #[test]
    fn key_never_in_debug() {
        let tls = TlsPem { client: Some(ClientPem { cert_pem: "CERT".into(), key_pem: "SECRET-KEY".into() }), roots_pem: "R".into() };
        let s = GroupSettings { tls: Some(tls.clone()), ..settings("2.8.1") };
        assert!(!format!("{s:?}").contains("SECRET-KEY"));
        assert!(!format!("{:?}", auth_config(Some(&tls))).contains("SECRET-KEY"));
    }

    #[test]
    fn auth_config_plaintext_or_tls() {
        assert!(format!("{:?}", auth_config(None)).to_lowercase().contains("plaintext"));
        let tls = TlsPem { client: None, roots_pem: "R".into() };
        let d = format!("{:?}", auth_config(Some(&tls)));
        assert!(d.contains("TlsConfig") && d.contains("client_identity: None"), "{d}");
        let tls = TlsPem { client: Some(ClientPem { cert_pem: "C".into(), key_pem: "K".into() }), roots_pem: "R".into() };
        assert!(!format!("{:?}", auth_config(Some(&tls))).contains("client_identity: None"));
    }
}
