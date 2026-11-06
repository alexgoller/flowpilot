//! PCE Kafka (Integrations) mode: flows are sent to the PCE through a Kafka gateway instead of the
//! REST upload.
//!
//! The Kafka client is async (rskafka on tokio). FlowPilot's threads stay blocking: they call
//! `runtime().block_on(..)` on one shared runtime. Divergence: the spec talks of channels between the
//! senders and the client; here it is one runtime with the blocking senders unchanged, to the same
//! effect (the calling sender waits for the broker's ack).

pub mod gateway;
pub mod bootstrap;
pub mod producer;
pub mod tls;

use std::sync::{Arc, OnceLock};

use crate::aggregator::KafkaHeader;
use crate::config::Config;
use crate::log::go_slice;
use crate::uploader::MessageSink;
use crate::{debug_log, log_line};
use producer::{split_brokers, KafkaProducer, ProducerSettings};

/// What Kafka mode hands the aggregator and the senders.
pub struct KafkaOutput {
    pub sink: Arc<dyn MessageSink>,
    /// The gateway's `maxObjectsPerMessage`.
    pub max_objects_per_message: i64,
}

/// Integrations bootstrap, then the producer. Logs and exits 1 on any failure; as in FlowLink there
/// is no retry (systemd restarts the service).
pub fn start_output(cfg: &Config, user: &str, token: &str) -> KafkaOutput {
    let ic = bootstrap::bootstrap(cfg, user, token);
    let brokers = split_brokers(&ic.bootstrap_servers);
    debug_log!("brokers:", go_slice(&brokers));
    let settings = ProducerSettings {
        brokers,
        topic: ic.topic,
        connection_string: ic.connection_string,
        org_id: cfg.org_id,
        verify_cert: cfg.verify_pce_cert,
    };
    match KafkaProducer::connect(settings) {
        Ok(p) => {
            log_line!("KafkaProducer setup");
            KafkaOutput { sink: Arc::new(p), max_objects_per_message: ic.max_objects_per_message }
        }
        Err(e) => {
            log_line!("Unable to create Kafka Producer:", e);
            std::process::exit(1);
        }
    }
}

/// The aggregator's flows-per-file limit and batch header. In Kafka mode the gateway's
/// `maxObjectsPerMessage` replaces `max_flows_per_post` unchecked, as in FlowLink (0 or less: one
/// file per window), and `pce_host` is `pce_addr`, the same value the aggregator gets.
pub fn output_wiring(cfg: &Config, out: Option<&KafkaOutput>) -> (i64, Option<KafkaHeader>) {
    match out {
        None => (cfg.max_flows_per_post, None),
        Some(o) => (
            o.max_objects_per_message,
            Some(KafkaHeader {
                org_id: cfg.org_id,
                installation_id: cfg.pce_kafka.installation_id.clone(),
                pce_host: cfg.pce_addr.clone(),
            }),
        ),
    }
}

/// The shared Kafka runtime: 2 worker threads named `kafka`, built on first use. `block_on` on it
/// is allowed from any thread that is not itself a runtime thread, which is every FlowPilot thread.
pub fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("kafka")
            .enable_all()
            .build()
            .expect("Kafka runtime")
    })
}

/// `text` with every occurrence of a non-empty `secret` replaced by `********`.
pub fn redact(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        text.to_string()
    } else {
        text.replace(secret, "********")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NullSink;
    impl MessageSink for NullSink {
        fn send(&self, _: &[u8]) -> Result<(i32, i64), String> {
            Ok((0, 0))
        }
    }

    fn cfg() -> Config {
        Config {
            pce_addr: "pce:8443".into(),
            org_id: 3,
            max_flows_per_post: 7000,
            pce_kafka: crate::config::PceKafka { installation_id: "inst-1".into(), ..Default::default() },
            ..Config::default()
        }
    }

    #[test]
    fn output_wiring_rest_mode_keeps_max_and_no_header() {
        assert_eq!(output_wiring(&cfg(), None), (7000, None));
    }

    #[test]
    fn output_wiring_kafka_mode_takes_gateway_max_unchecked_and_header() {
        let out = KafkaOutput { sink: Arc::new(NullSink), max_objects_per_message: 0 };
        let header = KafkaHeader { org_id: 3, installation_id: "inst-1".into(), pce_host: "pce:8443".into() };
        assert_eq!(output_wiring(&cfg(), Some(&out)), (0, Some(header)));
        let out = KafkaOutput { sink: Arc::new(NullSink), max_objects_per_message: -5 };
        assert_eq!(output_wiring(&cfg(), Some(&out)).0, -5);
    }

    #[test]
    fn redact_replaces_every_occurrence() {
        assert_eq!(redact("a s3 b s3", "s3"), "a ******** b ********");
        assert_eq!(redact("no secret", ""), "no secret");
    }

    #[test]
    fn runtime_is_shared_and_runs_futures() {
        assert!(std::ptr::eq(runtime(), runtime()));
        let name = runtime().block_on(async {
            tokio::spawn(async { std::thread::current().name().map(str::to_string) }).await.unwrap()
        });
        assert_eq!(name.as_deref(), Some("kafka"));
    }
}
