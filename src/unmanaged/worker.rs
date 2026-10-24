//! The worker thread: runs the engine off the flow pipeline's path. `submit` never blocks.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};

use super::dns;
use super::engine::Engine;
use super::pce::{HttpPce, PceApi};
use super::state::StateFiles;
use crate::aggregator::WindowReport;
use crate::config::Config;
use crate::stats::UnmanagedStats;
use crate::uploader::PceTarget;
use crate::{log_line, secrets};

/// Reports waiting for the worker; a full queue means the PCE is slow and the window is skipped.
const QUEUE_CAPACITY: usize = 2;

type Log = Box<dyn Fn(&str) + Send + Sync>;

enum Msg {
    Window(WindowReport),
    /// The final report; the worker acks once it is persisted.
    Shutdown(WindowReport, Sender<()>),
}

pub struct Handle {
    tx: Sender<Msg>,
    /// Set by `shutdown` before the final report is queued: reports still queued ahead of it are counted and
    /// persisted but never create.
    stopping: Arc<AtomicBool>,
    log: Log,
}

impl Handle {
    /// Queues a window report. Never blocks: a full queue drops this report (its counts are lost, the next window
    /// is unaffected).
    pub fn submit(&self, report: WindowReport) {
        if let Err(TrySendError::Full(_)) = self.tx.try_send(Msg::Window(report)) {
            (self.log)("Unmanaged workloads: worker busy, skipping this window's report");
        }
    }

    /// Hands over the last report and waits at most `wait` for it to be persisted.
    pub fn shutdown(&self, report: WindowReport, wait: Duration) {
        let deadline = Instant::now() + wait;
        self.stopping.store(true, Ordering::SeqCst);
        let (ack_tx, ack_rx) = bounded(1);
        if self.tx.send_timeout(Msg::Shutdown(report, ack_tx), wait).is_err() {
            (self.log)("Unmanaged workloads: worker did not accept the final report");
            return;
        }
        if ack_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())).is_err() {
            (self.log)("Unmanaged workloads: worker did not finish before shutdown");
        }
    }
}

pub fn spawn_engine<P: PceApi>(engine: Engine<P>) -> Handle {
    spawn_with_log(engine, Box::new(|l| log_line!(l)))
}

fn spawn_with_log<P: PceApi>(mut engine: Engine<P>, log: Log) -> Handle {
    let (tx, rx) = bounded(QUEUE_CAPACITY);
    let stopping = Arc::new(AtomicBool::new(false));
    let flag = stopping.clone();
    thread::Builder::new()
        .name("unmanaged-workloads".into())
        .spawn(move || run(&mut engine, &rx, &flag))
        .expect("spawn unmanaged workloads thread");
    Handle { tx, stopping, log }
}

fn run<P: PceApi>(engine: &mut Engine<P>, rx: &Receiver<Msg>, stopping: &AtomicBool) {
    for msg in rx {
        match msg {
            // Queued ahead of the final report during shutdown: counted and persisted, nothing created.
            Msg::Window(report) if stopping.load(Ordering::SeqCst) => engine.on_shutdown(&report, now()),
            // The engine logs the window summary itself.
            Msg::Window(report) => {
                engine.on_window(&report, now());
            }
            Msg::Shutdown(report, ack) => {
                engine.on_shutdown(&report, now());
                let _ = ack.send(());
                return;
            }
        }
    }
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// Starts the worker when the feature is enabled. `target` holds the upload credentials (the direct
/// `FLOWPILOT_API_USER`/`_SECRET` ones when set, see `Config::credentials`), used unless
/// `unmanaged_workloads.api_key` overrides them (resolved here, so a bad key exits at startup like the main one).
/// A PCE client that cannot be built disables the feature but never the flow pipeline. Returns the worker and the
/// engine's counters.
pub fn start(cfg: &Config, target: &PceTarget, dir: &Path) -> Option<(Handle, Arc<Mutex<UnmanagedStats>>)> {
    let uw = &cfg.unmanaged_workloads;
    if !uw.enabled {
        return None;
    }
    let mut target = target.clone();
    if let Some(key) = &uw.api_key {
        (target.api_user, target.api_token) = secrets::api_credentials(key);
    }
    let networks: Vec<String> = uw.networks.iter().map(ToString::to_string).collect();
    log_line!(format!("Unmanaged workloads enabled (dry run: {}), networks {}", uw.dry_run, networks.join(",")));
    let pce = match HttpPce::new(&target) {
        Ok(p) => p,
        Err(e) => {
            log_line!(format!("Unmanaged workloads: cannot build the PCE client: {e}"));
            return None;
        }
    };
    let files = StateFiles::new(dir, &cfg.pce_addr, cfg.org_id);
    let engine = Engine::new(uw.clone(), pce, dns::from_config(&uw.dns), files);
    let stats = engine.stats();
    Some((spawn_engine(engine), stats))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unmanaged::config::UnmanagedConfig;
    use crate::unmanaged::engine::tests::FakePce;
    use crate::unmanaged::pce::{CreateResult, Label, NewWorkload, PceError};
    use crate::unmanaged::state::StateFiles;
    use std::collections::BTreeSet;
    use std::net::IpAddr;
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    /// Delegates to `FakePce`, but `label_dimensions` (the first call of a window) waits until the test drops the gate.
    struct Stuck {
        inner: FakePce,
        gate: Mutex<Receiver<()>>,
    }

    impl PceApi for Stuck {
        fn label_dimensions(&self) -> Result<BTreeSet<String>, PceError> {
            let _ = self.gate.lock().unwrap().recv(); // Err once the sender is dropped
            self.inner.label_dimensions()
        }
        fn labels(&self) -> Result<Vec<Label>, PceError> {
            self.inner.labels()
        }
        fn find_label(&self, key: &str, value: &str) -> Result<Option<Label>, PceError> {
            self.inner.find_label(key, value)
        }
        fn create_label(&self, key: &str, value: &str) -> Result<Label, PceError> {
            self.inner.create_label(key, value)
        }
        fn workload_ips(&self) -> Result<BTreeSet<IpAddr>, PceError> {
            self.inner.workload_ips()
        }
        fn has_workload(&self, ip: IpAddr) -> Result<bool, PceError> {
            self.inner.has_workload(ip)
        }
        fn bulk_create(&self, batch: &[NewWorkload]) -> Result<Vec<CreateResult>, PceError> {
            self.inner.bulk_create(batch)
        }
    }

    fn report(ip: &str, n: u64) -> WindowReport {
        WindowReport { new_ips: Vec::new(), ip_flow_counts: [(ip.to_string(), n)].into() }
    }

    fn engine<P: PceApi>(pce: P, dir: &Path) -> Engine<P> {
        let cfg = UnmanagedConfig { enabled: true, ..Default::default() };
        Engine::new(cfg, pce, None, StateFiles::new(dir, "pce", 1))
    }

    #[test]
    fn submit_never_blocks_when_worker_is_stuck() {
        let dir = tempfile::tempdir().unwrap();
        let (gate_tx, gate_rx): (Sender<()>, Receiver<()>) = channel();
        let eng = engine(Stuck { inner: FakePce::new(), gate: Mutex::new(gate_rx) }, dir.path());
        let logs: Arc<Mutex<Vec<String>>> = Arc::default();
        let sink = logs.clone();
        let h = spawn_with_log(eng, Box::new(move |l| sink.lock().unwrap().push(l.to_string())));

        h.submit(report("10.0.0.1", 5)); // taken by the worker, which then sticks in the PCE call
        std::thread::sleep(Duration::from_millis(200));
        let t = Instant::now();
        for _ in 0..10 {
            h.submit(report("10.0.0.1", 5));
        }
        assert!(t.elapsed() < Duration::from_millis(100), "submit blocked for {:?}", t.elapsed());
        // capacity 2: the 10 submits queue 2 and drop 8
        let busy = "Unmanaged workloads: worker busy, skipping this window's report";
        assert_eq!(logs.lock().unwrap().iter().filter(|l| l.as_str() == busy).count(), 8);
        drop(gate_tx);
    }

    #[test]
    fn shutdown_drains_queued_reports_without_creating() {
        let dir = tempfile::tempdir().unwrap();
        let pce = FakePce::new();
        let (gate_tx, gate_rx): (Sender<()>, Receiver<()>) = channel();
        let eng = engine(Stuck { inner: pce.clone(), gate: Mutex::new(gate_rx) }, dir.path());
        let h = spawn_engine(eng);
        h.submit(report("10.0.0.1", 5)); // the worker sticks in this window's first PCE call
        std::thread::sleep(Duration::from_millis(200));
        h.submit(report("10.0.0.2", 20)); // queued; eligible on its own
        h.submit(report("10.0.0.3", 20));
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            drop(gate_tx);
        });
        h.shutdown(report("10.0.0.4", 1), Duration::from_secs(5));
        release.join().unwrap();
        assert!(pce.calls("has_workload").is_empty() && pce.calls("bulk_create").is_empty());
        let saved = std::fs::read_to_string(dir.path().join("pce-org1-uw_candidates.json")).unwrap();
        for ip in ["10.0.0.2", "10.0.0.3", "10.0.0.4"] {
            assert!(saved.contains(ip), "{saved}");
        }
    }

    #[test]
    fn shutdown_waits_for_persist() {
        let dir = tempfile::tempdir().unwrap();
        let h = spawn_engine(engine(FakePce::new(), dir.path()));
        h.shutdown(report("10.9.8.7", 3), Duration::from_secs(2));
        let saved = std::fs::read_to_string(dir.path().join("pce-org1-uw_candidates.json")).unwrap();
        assert!(saved.contains("10.9.8.7"), "{saved}");
    }
}
