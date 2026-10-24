//! Entry point: the startup sequence and the signal handler.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime};

use signal_hook::consts::{SIGINT, SIGQUIT, SIGTERM};
use signal_hook::iterator::Signals;

use flowpilot::aggregator::{self, Aggregator, FLOW_CHANNEL_CAPACITY};
use flowpilot::flow::FlowSink;
use flowpilot::log::{DEBUG, SHUTDOWN};
use flowpilot::parsers::{start_consumer, ParserContext};
use flowpilot::spool::Spool;
use flowpilot::uploader::{PceTarget, Uploader};
use flowpilot::unmanaged;
use flowpilot::{cli, config, instance_id, log_line, metrics, stats};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Set once the aggregator exists, so a signal can flush the current window.
static AGGREGATOR: OnceLock<Arc<Aggregator>> = OnceLock::new();

/// The unmanaged-workload worker, when enabled; the signal handler hands it the final window.
static UNMANAGED: OnceLock<unmanaged::worker::Handle> = OnceLock::new();

fn main() {
    let args: Vec<String> = std::env::args().collect(); // includes argv[0] for the usage text
    let code = match cli::dispatch(&args) {
        cli::Command::Daemon(flags) => {
            daemon(flags);
            0
        }
        cli::Command::Install(a) => flowpilot::install::run_install(*a),
        cli::Command::Uninstall(a) => flowpilot::install::run_uninstall(a),
        cli::Command::Rollback => flowpilot::install::run_rollback(),
        cli::Command::Status(a) => flowpilot::install::run_status(a),
        cli::Command::Usage { code: 0, text } => {
            print!("{text}");
            0
        }
        cli::Command::Usage { code, text } => {
            eprint!("{text}");
            code
        }
    };
    std::process::exit(code);
}

/// The collector daemon.
fn daemon(flags: cli::Flags) {
    if flags.print_config {
        let path = std::env::var("CONFIG_FILE").unwrap_or_default();
        let names = flowpilot::env_config::process_var_names();
        std::process::exit(config::print_effective(&path, &|k| std::env::var(k).ok(), &names));
    }
    start_signal_handler();
    if flags.version {
        println!("FlowPilot version: {VERSION}");
        std::process::exit(0);
    }
    DEBUG.store(flags.debug, Ordering::Relaxed);
    let started_at = SystemTime::now();
    log_line!("******************** Starting FlowPilot version:", VERSION);

    let cfg = config::load_and_validate(&std::env::var("CONFIG_FILE").unwrap_or_default());
    apply_proxy_env(&cfg.proxy_config);

    let (api_user, api_token) = cfg.credentials();
    let instance = instance_id::load_or_create(&cfg.data_directory);
    if !cfg.pce_kafka.installation_id.is_empty() {
        // Deferred: the PCE Kafka (Integrations) bootstrap.
        log_line!("PCE Kafka (Integrations) mode is not supported in this build");
        std::process::exit(1);
    }

    // Bound before any collector starts, so a bad address or a port in use stops the start instead of leaving a
    // missing endpoint; served once the stats context exists.
    let stats_http = cfg.stats.http_listen.as_deref().map(|addr| match stats::http::bind(addr) {
        Ok(ep) => (addr, ep),
        Err(e) => http_failed(addr, e),
    });

    let dir = std::fs::canonicalize(&cfg.data_directory).unwrap_or_else(|_| PathBuf::from(&cfg.data_directory));
    let spool = Arc::new(Spool::new(dir.clone(),cfg.file_retention_hours, cfg.data_directory_size_mb));
    let agg = Arc::new(Aggregator::new(spool.clone(), &cfg.pce_addr, cfg.org_id, instance.clone(), cfg.max_flows_per_post));
    let (tx, rx) = crossbeam_channel::bounded(FLOW_CHANNEL_CAPACITY);
    agg.start(rx);
    let _ = AGGREGATOR.set(agg.clone());

    let sink = FlowSink::new(tx);
    let mut started = 0;
    for c in &cfg.consumers {
        log_line!("Starting Data Consumer:", c.name);
        let stats = stats::register_collector(&c.name, &c.parser.kind);
        let ctx = ParserContext::new(metrics::get_or_register_meter(&c.name), sink.clone(), stats);
        if start_consumer(&c.parser, &c.connectors, ctx) {
            started += 1;
        }
    }
    if started == 0 {
        std::process::exit(1); // silent, like FlowLink
    }
    if cfg.stats.legacy_metrics {
        metrics::start_logger(Duration::from_secs(cfg.metrics_print_seconds.max(0) as u64));
    }

    // Divergence: an unreadable data directory is fatal instead of a silent hang.
    if let Err(e) = spool.scan() {
        log_line!("Error:", e);
        std::process::exit(1);
    }
    let target = PceTarget {
        pce_addr: cfg.pce_addr.clone(),
        org_id: cfg.org_id,
        api_user,
        api_token,
        verify_cert: cfg.verify_pce_cert,
    };
    // The unmanaged-workload counters, for the stats output.
    let unmanaged_stats = unmanaged::worker::start(&cfg, &target, &dir).map(|(h, stats)| {
        let _ = UNMANAGED.set(h);
        stats
    });
    Arc::new(Uploader::new(spool.clone(), target)).start();
    let stats_ctx = Arc::new(stats::SnapshotContext {
        version: VERSION.to_string(),
        instance_id: instance,
        started_at,
        aggregator: agg.clone(),
        spool,
        unmanaged: unmanaged_stats,
        cfg: cfg.stats.clone(),
        aggregation_minutes: cfg.aggregation_minutes,
        collectors: stats::collectors(),
    });
    if let Some((addr, ep)) = stats_http {
        if let Err(e) = ep.start(stats_ctx.clone()) {
            http_failed(addr, e);
        }
    }
    stats::reporter::start(stats_ctx);
    let _guard = stats::ThreadGuard::core("report_flows");
    aggregator::report_flows(&agg, cfg.aggregation_minutes, |report| {
        if let Some(h) = UNMANAGED.get() {
            h.submit(report);
        }
    });
}

fn http_failed(addr: &str, e: std::io::Error) -> ! {
    log_line!(format!("Error: stats HTTP endpoint {addr}: {e}"));
    std::process::exit(1);
}

/// The first SIGINT/SIGTERM/SIGQUIT stops intake, drains, flushes the window and exits 0 (FlowLink
/// exits 1, see docs/differences-from-flowlink.md). Later signals are ignored, as in FlowLink.
fn start_signal_handler() {
    let mut signals = Signals::new([SIGINT, SIGTERM, SIGQUIT]).expect("install signal handlers");
    thread::spawn(move || {
        log_line!("Waiting for signal");
        if signals.forever().next().is_none() {
            return;
        }
        log_line!("Got signal");
        SHUTDOWN.store(true, Ordering::SeqCst);
        log_line!("Telling connectors to stop");
        metrics::unregister_all();
        log_line!("Allowing parsers to drain");
        thread::sleep(Duration::from_secs(5));
        log_line!("Writing flows");
        if let Some(agg) = AGGREGATOR.get() {
            let report = agg.write_flows();
            if let Some(h) = UNMANAGED.get() {
                h.shutdown(report, Duration::from_secs(5));
            }
        }
        std::process::exit(0);
    });
}

/// Proxy detection and configuration. FlowLink's proxy quirks are kept (docs/differences-from-flowlink.md,
/// "Preserved on purpose").
fn apply_proxy_env(pc: &config::HttpProxy) {
    let http_env = std::env::var("HTTP_PROXY").unwrap_or_default();
    let https_env = std::env::var("HTTPS_PROXY").unwrap_or_default();
    let no_env = std::env::var("NO_PROXY").unwrap_or_default();
    if !http_env.is_empty() {
        log_line!("Detected http Proxy:", stats::redact_proxy_url(&http_env));
    }
    if !https_env.is_empty() {
        log_line!("Detected https Proxy:", stats::redact_proxy_url(&http_env)); // prints HTTP_PROXY, like FlowLink
    }
    if !no_env.is_empty() {
        log_line!("Detected No Proxy list:", no_env);
    }
    if !pc.http_proxy.is_empty() {
        log_line!("HTTP Proxy configured:", stats::redact_proxy_url(&pc.http_proxy));
        std::env::set_var("HTTP_PROXY", &pc.http_proxy);
        std::env::set_var("http_proxy", &pc.http_proxy);
    }
    if !pc.https_proxy.is_empty() {
        log_line!("HTTPS Proxy configured:", stats::redact_proxy_url(&pc.https_proxy));
        std::env::set_var("HTTPS_PROXY", &pc.https_proxy);
        std::env::set_var("https_proxy", &pc.http_proxy); // HTTP proxy value on purpose, like FlowLink
    }
    if !pc.no_proxy.is_empty() {
        log_line!("NO PROXY list configured:", pc.no_proxy);
        std::env::set_var("NO_PROXY", &pc.no_proxy);
        std::env::set_var("no_proxy", &pc.no_proxy);
    }
}
