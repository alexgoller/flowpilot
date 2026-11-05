//! PCE Kafka producer against the test broker. Skipped unless `FLOWPILOT_TEST_KAFKA_SASL` names the
//! broker's SASL_SSL listener:
//!
//!     tests/kafka/broker.sh up host
//!     FLOWPILOT_TEST_KAFKA_SASL=localhost:9093 cargo test --test kafka_producer
//!     tests/kafka/broker.sh down

use std::path::PathBuf;

use flowpilot::config::Secret;
use flowpilot::kafka::producer::{split_brokers, KafkaProducer, ProducerSettings};
use flowpilot::kafka::tls;
use flowpilot::uploader::MessageSink;

const TOPIC: &str = "flowpilot";

fn certs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/kafka-certs")
}

/// The broker address, or `None` (test skipped) when the variable is unset.
fn broker(test: &str) -> Option<String> {
    match std::env::var("FLOWPILOT_TEST_KAFKA_SASL") {
        Ok(b) if !b.is_empty() => Some(b),
        _ => {
            eprintln!("skipped: {test} needs FLOWPILOT_TEST_KAFKA_SASL (tests/kafka/broker.sh up host)");
            None
        }
    }
}

fn settings(broker: &str, password: &str, verify_cert: bool) -> ProducerSettings {
    ProducerSettings {
        brokers: split_brokers(broker),
        topic: TOPIC.to_string(),
        connection_string: Secret(password.to_string()),
        org_id: 1,
        verify_cert,
    }
}

fn connection_string() -> String {
    std::fs::read_to_string(certs().join("connection_string")).expect("target/kafka-certs/connection_string")
}

#[test]
fn produce_over_sasl_ssl_returns_offset() {
    let Some(b) = broker("produce_over_sasl_ssl_returns_offset") else { return };
    let p = KafkaProducer::connect(settings(&b, &connection_string(), false)).expect("connect");
    let mut value = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03".to_vec();
    value.extend_from_slice(&[0u8; 2038]);
    let (partition, offset) = p.send(&value).expect("send");
    assert!((0..3).contains(&partition), "partition {partition}");
    assert!(offset >= 0, "offset {offset}");
    // A second message on the same partition gets a later offset; across partitions it is just valid.
    let (p2, o2) = p.send(&value).expect("second send");
    assert!(o2 >= 0 && (p2 != partition || o2 > offset), "{partition}/{offset} then {p2}/{o2}");
    // Over the size limit: refused before any I/O.
    assert!(p.send(&vec![0u8; 1_000_001]).unwrap_err().contains("larger than 1000000 bytes"));
    p.close(std::time::Duration::from_secs(1));
    assert!(p.send(&value).unwrap_err().contains("closed"));
}

#[test]
fn wrong_password_fails_without_leaking_it() {
    let Some(b) = broker("wrong_password_fails_without_leaking_it") else { return };
    let started = std::time::Instant::now();
    let err = match KafkaProducer::connect(settings(&b, "wrong-s3cr3t", false)) {
        Ok(_) => panic!("connect with a wrong password succeeded"),
        Err(e) => e,
    };
    eprintln!("wrong password: {err}");
    assert!(!err.contains("wrong-s3cr3t"), "{err}");
    assert!(err.to_lowercase().contains("sasl"), "{err}");
    // The retries are bounded (rskafka's default would retry for ever).
    assert!(started.elapsed() < std::time::Duration::from_secs(30), "{:?}", started.elapsed());
}

#[test]
fn verify_cert_rejects_self_signed() {
    let Some(b) = broker("verify_cert_rejects_self_signed") else { return };
    let err = match KafkaProducer::connect(settings(&b, &connection_string(), true)) {
        Ok(_) => panic!("connect accepted the self-signed broker certificate"),
        Err(e) => e,
    };
    eprintln!("verify_cert: {err}");
    assert!(err.to_lowercase().contains("certificate") || err.contains("UnknownIssuer"), "{err}");
}

#[test]
fn unknown_topic_is_refused() {
    let Some(b) = broker("unknown_topic_is_refused") else { return };
    let mut s = settings(&b, &connection_string(), false);
    s.topic = "no-such-topic".to_string();
    let err = KafkaProducer::connect(s).err().expect("unknown topic accepted");
    assert_eq!(err, "Kafka topic no-such-topic not found");
}

#[test]
fn client_auth_config_loads_the_test_client_certificate() {
    if broker("client_auth_config_loads_the_test_client_certificate").is_none() {
        return;
    }
    let read = |f: &str| std::fs::read_to_string(certs().join(f)).unwrap();
    let c = tls::client_auth_config(&read("client.pem"), &read("client.key")).expect("client cert");
    assert!(c.client_auth_cert_resolver.has_certs());
    // A key that does not match the certificate is refused.
    assert!(tls::client_auth_config(&read("client.pem"), &read("server.key")).is_err());
}
