//! Parser contract and parser start-up.

pub mod ipfix;
pub mod netflow;
pub mod sflow;
pub mod text;

use std::sync::Arc;

use crossbeam_channel::Sender;

use crate::config::Info;
use crate::flow::FlowSink;
use crate::log_line;
use crate::metrics::Meter;
use crate::stats::CollectorStats;

/// One received datagram. `buf` holds exactly the received bytes.
#[derive(Clone, Debug, Default)]
pub struct ReceivedDatagram {
    pub device_addr: String,
    pub seq_id: String,
    pub transport: String,
    pub buf: Vec<u8>,
}

/// A parser. `start_workers` starts `n` worker threads that all consume the returned
/// channel and feed decoded flows into the parser's `FlowSink`.
pub trait Parser: Send + Sync + 'static {
    fn type_name(&self) -> &'static str;
    fn default_port(&self) -> u16;
    fn supports_connector(&self, conn_type: &str) -> bool;
    fn start_workers(self: Arc<Self>, n: usize) -> Sender<ReceivedDatagram>;
    /// The collector's counters (the connectors count rejected datagrams into them).
    fn stats(&self) -> Arc<CollectorStats>;
}

/// Everything a parser setup function needs besides its config.
#[derive(Clone)]
pub struct ParserContext {
    pub meter: Meter,
    pub sink: FlowSink,
    pub stats: Arc<CollectorStats>,
}

impl ParserContext {
    /// A context whose sink counts into `stats` too.
    pub fn new(meter: Meter, sink: FlowSink, stats: Arc<CollectorStats>) -> Self {
        Self { meter, sink: sink.with_stats(stats.clone()), stats }
    }
}

/// Starts the parser named by `p`: exact match on the parser type.
/// `aws` is deferred in this build and takes the unsupported path.
pub fn start_consumer(p: &Info, connectors: &[Info], ctx: ParserContext) -> bool {
    match p.kind.as_str() {
        "sflow" => sflow::setup(&p.properties, connectors, ctx),
        "text" => text::setup(&p.properties, connectors, ctx),
        "ipfix" => ipfix::setup(&p.properties, connectors, ctx),
        "netflow" => netflow::setup(&p.properties, connectors, ctx),
        _ => {
            log_line!(p.kind, "parser not supported.");
            false
        }
    }
}

/// Helper for parser setup functions: try every configured connector and report whether at least
/// one started.
pub fn connect_all(parser: Arc<dyn Parser>, connectors: &[Info]) -> bool {
    let started = connectors.iter().filter(|c| crate::connectors::start_connector(parser.clone(), &c.kind, &c.properties)).count();
    started != 0
}

/// Decodes one datagram synchronously with the parser named `kind` (`netflow`, `ipfix` or `sflow`),
/// sending its flows to `ctx.sink`. Template state is the process-wide store the workers use.
/// Not part of the collector: an entry point for the fuzz targets and the conformance harness.
#[doc(hidden)]
pub fn decode_datagram(kind: &str, pd: &ReceivedDatagram, ctx: &ParserContext) {
    match kind {
        "netflow" => netflow::NetflowParser::decode_one(ctx, pd),
        "ipfix" => ipfix::IpfixParser::decode_one(ctx, pd),
        "sflow" => sflow::process(pd, ctx),
        _ => panic!("decode_datagram: unknown parser {kind}"),
    }
}
