//! PCE Kafka producer: one message per spool file, synchronous (the caller waits for the broker's
//! ack), SASL PLAIN over TLS as Azure Event Hubs expects.
//!
//! Library logging goes through `tracing`; FlowPilot installs no subscriber, so it stays silent.
//! No proxy is used for Kafka connections, as in FlowLink.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Display;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rskafka::client::error::Error as KafkaError;
use rskafka::client::partition::{Compression, PartitionClient, UnknownTopicHandling};
use rskafka::client::{Client, ClientBuilder, Credentials, SaslConfig};
use rskafka::record::Record;
use rskafka::BackoffConfig;
use tokio::time::timeout;

use crate::config::Secret;
use crate::kafka::{redact, runtime, tls};
use crate::uploader::MessageSink;

/// SASL PLAIN user name for an Event Hubs connection string.
pub const SASL_USER: &str = "$ConnectionString";
/// Largest message value sent; larger ones are refused before any I/O.
// Divergence: rskafka has no produce-side size limit (FlowLink's client has one), so FlowPilot
// checks the size itself.
pub const MAX_MESSAGE_BYTES: usize = 1_000_000;
/// How long the broker may take to ack a message.
// Divergence: FlowLink waits 10 s; rskafka hard-codes 30 s.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound on every network operation.
// Divergence: rskafka has no dial/read/write timeouts; each call is wrapped in a tokio timeout.
pub const NET_TIMEOUT: Duration = Duration::from_secs(30);
/// Retries of a failed request, `RETRY_BACKOFF` apart.
// Divergence: rskafka counts no retries; they are bounded by a backoff deadline of about
// `RETRIES` x `RETRY_BACKOFF` (its default has no deadline and retries a SASL failure for ever).
pub const RETRIES: u32 = 5;
pub const RETRY_BACKOFF: Duration = Duration::from_millis(100);
/// Client id sent to the broker, as in FlowLink (set with `ClientBuilder::client_id`).
pub const CLIENT_ID: &str = "sarama";

/// Where and how to produce.
#[derive(Clone, Debug)]
pub struct ProducerSettings {
    pub brokers: Vec<String>,
    pub topic: String,
    pub connection_string: Secret,
    pub org_id: i32,
    pub verify_cert: bool,
}

/// `bootstrapServers` as a broker list: split on `,`, trimmed, empties dropped.
pub fn split_brokers(s: &str) -> Vec<String> {
    s.split(',').map(str::trim).filter(|b| !b.is_empty()).map(str::to_string).collect()
}

/// The message key: `<org_id>+<local wall time>Z`. As in FlowLink, the `Z` is literal and the time
/// is local, not UTC.
pub fn message_key<Tz: chrono::TimeZone>(org_id: i32, now: &chrono::DateTime<Tz>) -> String
where
    Tz::Offset: Display,
{
    format!("{org_id}+{}", now.format("%Y-%m-%dT%H:%M:%SZ"))
}

/// FlowLink's key hash partitioner: FNV-1a 32 of the key, as `i32` modulo `partitions`, negated
/// if negative.
pub fn key_hash_partition(key: &[u8], partitions: i32) -> i32 {
    let mut h: u32 = 2_166_136_261;
    for &b in key {
        h ^= u32::from(b);
        h = h.wrapping_mul(16_777_619);
    }
    let p = (h as i32) % partitions;
    if p < 0 {
        -p
    } else {
        p
    }
}

/// Refuses values over `MAX_MESSAGE_BYTES` before any I/O.
fn check_size(len: usize) -> Result<(), String> {
    if len > MAX_MESSAGE_BYTES {
        return Err(format!("message of {len} bytes is larger than {MAX_MESSAGE_BYTES} bytes"));
    }
    Ok(())
}

/// Every error text leaves this module through here, so the connection string never shows.
fn error_text(e: impl Display, secret: &str) -> String {
    redact(&e.to_string(), secret)
}

/// Errors after which the cached partition connections are dropped, so the next send reconnects.
fn is_connection_error(e: &KafkaError) -> bool {
    matches!(e, KafkaError::Connection(_) | KafkaError::Request(_) | KafkaError::RetryFailed(_) | KafkaError::Timeout)
}

fn backoff() -> BackoffConfig {
    BackoffConfig {
        init_backoff: RETRY_BACKOFF,
        // A fixed 100 ms step (rskafka needs `base` > 1; the cap keeps every step at `RETRY_BACKOFF`).
        max_backoff: RETRY_BACKOFF,
        base: 2.0,
        // Divergence: a deadline in place of a retry count (see `RETRIES`). Half a step of slack
        // keeps float rounding from cutting off the last retry.
        deadline: Some(RETRY_BACKOFF * RETRIES + RETRY_BACKOFF / 2),
    }
}

/// The PCE Kafka producer, shared by the spool senders.
pub struct KafkaProducer {
    /// `None` after `close`.
    client: Mutex<Option<Arc<Client>>>,
    topic: String,
    /// The topic's partition ids, sorted.
    partitions: Vec<i32>,
    org_id: i32,
    secret: String,
    /// One client per partition, built on first use.
    partition_clients: Mutex<HashMap<i32, Arc<PartitionClient>>>,
}

impl KafkaProducer {
    /// Connects, authenticates and reads the topic's partitions.
    pub fn connect(s: ProducerSettings) -> Result<Self, String> {
        let secret = s.connection_string.0;
        if s.brokers.is_empty() {
            return Err("no Kafka bootstrap servers".to_string());
        }
        // Divergence: rskafka always produces with acks = all (FlowLink: leader only).
        let builder = ClientBuilder::new(s.brokers)
            .client_id(CLIENT_ID)
            .tls_config(tls::server_config(s.verify_cert))
            .sasl_config(SaslConfig::Plain(Credentials::new(SASL_USER.to_string(), secret.clone())))
            .backoff_config(backoff());
        let topic = s.topic;
        let (client, partitions) = runtime().block_on(async {
            let client = match timeout(NET_TIMEOUT, builder.build()).await {
                Ok(r) => r.map_err(|e| error_text(e, &secret))?,
                Err(_) => return Err(format!("no connection to Kafka within {}s", NET_TIMEOUT.as_secs())),
            };
            let topics = match timeout(NET_TIMEOUT, client.list_topics()).await {
                Ok(r) => r.map_err(|e| error_text(e, &secret))?,
                Err(_) => return Err(format!("no Kafka metadata within {}s", NET_TIMEOUT.as_secs())),
            };
            let partitions: Vec<i32> = match topics.into_iter().find(|t| t.name == topic) {
                Some(t) => t.partitions.into_iter().collect(),
                None => return Err(error_text(format!("Kafka topic {topic} not found"), &secret)),
            };
            if partitions.is_empty() {
                return Err(error_text(format!("Kafka topic {topic} has no partitions"), &secret));
            }
            Ok((client, partitions))
        })?;
        Ok(Self {
            client: Mutex::new(Some(Arc::new(client))),
            topic,
            partitions,
            org_id: s.org_id,
            secret,
            partition_clients: Mutex::new(HashMap::new()),
        })
    }

    async fn partition_client(&self, partition: i32) -> Result<Arc<PartitionClient>, String> {
        if let Some(pc) = self.partition_clients.lock().unwrap().get(&partition) {
            return Ok(pc.clone());
        }
        let client = self.client.lock().unwrap().clone().ok_or("Kafka producer is closed")?;
        let pc = client
            .partition_client(self.topic.clone(), partition, UnknownTopicHandling::Error)
            .await
            .map_err(|e| self.failed(e))?;
        let pc = Arc::new(pc);
        self.partition_clients.lock().unwrap().insert(partition, pc.clone());
        Ok(pc)
    }

    async fn produce(&self, partition: i32, record: Record) -> Result<i64, String> {
        let pc = self.partition_client(partition).await?;
        // No compression, as in FlowLink (the value is already gzip).
        let offsets = pc.produce(vec![record], Compression::NoCompression).await.map_err(|e| self.failed(e))?;
        offsets.first().copied().ok_or_else(|| "Kafka returned no offset".to_string())
    }

    /// The redacted error text; drops the partition connections on a connection error.
    fn failed(&self, e: KafkaError) -> String {
        if is_connection_error(&e) {
            self.partition_clients.lock().unwrap().clear();
        }
        error_text(e, &self.secret)
    }
}

impl MessageSink for KafkaProducer {
    fn send(&self, value: &[u8]) -> Result<(i32, i64), String> {
        check_size(value.len())?;
        let key = message_key(self.org_id, &chrono::Local::now());
        let partition = self.partitions[key_hash_partition(key.as_bytes(), self.partitions.len() as i32) as usize];
        let record = Record {
            key: Some(key.into_bytes()),
            value: Some(value.to_vec()),
            headers: BTreeMap::new(),
            timestamp: chrono::Utc::now(),
        };
        let budget = ACK_TIMEOUT + RETRY_BACKOFF * RETRIES;
        match runtime().block_on(async { timeout(budget, self.produce(partition, record)).await }) {
            Ok(r) => r.map(|offset| (partition, offset)),
            Err(_) => {
                self.partition_clients.lock().unwrap().clear();
                Err(format!("no ack from Kafka within {}ms", budget.as_millis()))
            }
        }
    }

    /// Nothing is buffered (each send waits for its ack), so closing only drops the connections.
    fn close(&self, _within: Duration) {
        self.partition_clients.lock().unwrap().clear();
        self.client.lock().unwrap().take();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn key_is_local_wall_time_with_literal_z() {
        let t = chrono::FixedOffset::east_opt(3600).unwrap().with_ymd_and_hms(2026, 11, 5, 15, 3, 7).unwrap();
        assert_eq!(message_key(1234, &t), "1234+2026-11-05T15:03:07Z");
    }

    #[test]
    fn partition_matches_flowlink_hash() {
        assert_eq!(key_hash_partition(b"", 8), 3);
        assert_eq!(key_hash_partition(b"a", 8), 4);
        assert_eq!(key_hash_partition(b"1234+2026-11-05T14:03:07Z", 3), 2);
    }

    #[test]
    fn broker_list_is_trimmed() {
        assert_eq!(split_brokers("k1:9093, k2:9093,"), ["k1:9093", "k2:9093"]);
        assert!(split_brokers(" , ").is_empty());
    }

    #[test]
    fn oversized_message_is_refused() {
        assert_eq!(check_size(1_000_001), Err("message of 1000001 bytes is larger than 1000000 bytes".to_string()));
        assert_eq!(check_size(MAX_MESSAGE_BYTES), Ok(()));
    }

    #[test]
    fn errors_never_contain_the_connection_string() {
        let cs = "Endpoint=sb://x/;SharedAccessKey=s3cr3t";
        let server = || KafkaError::ServerError {
            protocol_error: rskafka::client::error::ProtocolError::SaslAuthenticationFailed,
            error_message: Some(format!("SASL auth failed for {cs}")),
            request: rskafka::client::error::RequestContext::Topic(cs.to_string()),
            response: None,
            is_virtual: false,
        };
        assert!(server().to_string().contains(cs), "the test error must carry the secret");
        let text = error_text(server(), cs);
        assert!(!text.contains(cs) && !text.contains("s3cr3t"), "{text}");
        assert!(text.contains("SASL auth failed for ********"), "{text}");

        // Nested inside the retry wrapper rskafka returns once the backoff deadline is hit.
        let retried = KafkaError::RetryFailed(rskafka::BackoffError::DeadlineExceded {
            deadline: Duration::from_millis(550),
            source: Box::new(server()),
        });
        assert!(retried.to_string().contains(cs));
        let text = error_text(retried, cs);
        assert!(!text.contains("s3cr3t") && text.starts_with("All retries failed"), "{text}");

        assert_eq!(error_text(KafkaError::InvalidResponse("no secret".into()), ""), "Invalid response: no secret");
    }

    #[test]
    fn connection_errors_reset_the_partition_clients() {
        assert!(is_connection_error(&KafkaError::Timeout));
        assert!(!is_connection_error(&KafkaError::InvalidResponse(String::new())));
    }

    #[test]
    fn retries_are_bounded() {
        let b = backoff();
        assert_eq!(b.init_backoff, RETRY_BACKOFF);
        assert_eq!(b.max_backoff, RETRY_BACKOFF);
        assert!(b.base > 1.0);
        assert_eq!(b.deadline, Some(Duration::from_millis(550)));
    }
}
