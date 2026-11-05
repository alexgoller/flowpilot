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

use std::sync::OnceLock;

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
