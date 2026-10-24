//! Per-window orchestration of unmanaged workload creation (docs/unmanaged-workloads.md): count, refresh, select, pre-create check,
//! reverse DNS, labels, `bulk_create`. Runs on the worker thread; every failure is logged and retried next window.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::config::UnmanagedConfig;
use super::dns::{resolve_all, ReverseDns};
use super::net::{LabelRules, NetworkFilter};
use super::pce::{CreateResult, NewWorkload, PceApi, PceError};
use super::plan::{candidate_counts, select, Pause};
use super::state::{KnownState, StateFiles};
use super::window::FlowWindow;
use crate::aggregator::WindowReport;
use crate::stats::{LastWindow, UnmanagedStats};

const HOUR_SECS: i64 = 3600;
/// The PCE's `bulk_create` limit.
const BULK_CHUNK: usize = 1000;

pub type LogSink = Box<dyn FnMut(&str) + Send>;

pub struct Engine<P: PceApi> {
    cfg: UnmanagedConfig,
    pce: P,
    dns: Option<Arc<dyn ReverseDns>>,
    files: StateFiles,
    known: KnownState,
    window: FlowWindow,
    filter: NetworkFilter,
    rules: LabelRules,
    /// `(key, value)` → href; filled by the refresh and by label creation, never evicted otherwise.
    labels: HashMap<(String, String), String>,
    types_checked: bool,
    /// A full refresh succeeded in this process; only then may the known set be used up to twice `refresh_hours`.
    refreshed: bool,
    /// Set (with its log line) when a label rule uses a type the PCE lacks; nothing is created after that.
    disabled: Option<String>,
    /// The daily-cap warning was logged and no creation has succeeded since.
    cap_warned: bool,
    known_dirty: bool,
    /// IPs whose window total reached `min_flows` since `select` last ran (for the burst pause). Windows that stop
    /// before `select` (paused, label check failed) add to it, so their crossings are still checked.
    crossed: BTreeSet<IpAddr>,
    /// Error lines logged in the current window: each is logged at most once per window.
    logged: HashSet<String>,
    log: LogSink,
    /// Read by the stats output; written at the end of each window, after each refresh attempt and when a burst
    /// pause starts or ends.
    stats: Arc<Mutex<UnmanagedStats>>,
}

#[derive(Debug, Default, PartialEq)]
pub struct Summary {
    pub candidates: usize,
    pub eligible: usize,
    pub created: usize,
    pub deferred: usize,
    pub resolved: usize,
    pub looked_up: usize,
    pub labels_created: usize,
    pub errors: usize,
    pub dry_run: bool,
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = if self.dry_run { "Unmanaged workloads (dry run):" } else { "Unmanaged workloads:" };
        write!(
            f,
            "{prefix} {} candidates, {} eligible, {} created, {} deferred, {}/{} resolved, {} {} created, {} errors",
            self.candidates,
            self.eligible,
            self.created,
            self.deferred,
            self.resolved,
            self.looked_up,
            self.labels_created,
            if self.labels_created == 1 { "label" } else { "labels" },
            self.errors
        )
    }
}

/// The permission a refused call needs, for the 401/403 message.
fn permission(call: &str) -> &'static str {
    match call {
        "workload_ips" | "has_workload" => "read workloads",
        "label_dimensions" | "labels" | "find_label" => "read labels",
        "create_label" => "create labels",
        _ => "create workloads",
    }
}

fn describe(e: &PceError) -> String {
    match e {
        PceError::Auth(s) => format!("HTTP {s}"),
        PceError::Exists => "already exists".into(),
        PceError::Transient(s) | PceError::Unreachable(_, s) | PceError::Other(s) => s.clone(),
    }
}

impl<P: PceApi> Engine<P> {
    /// Loads the persisted known set and flow window; no PCE call happens before the first window.
    pub fn new(cfg: UnmanagedConfig, pce: P, dns: Option<Arc<dyn ReverseDns>>, files: StateFiles) -> Self {
        Self::with_stats(cfg, pce, dns, files, Arc::default())
    }

    /// `new`, reporting into `stats` (filled with the settings and the persisted state here).
    pub fn with_stats(
        cfg: UnmanagedConfig,
        pce: P,
        dns: Option<Arc<dyn ReverseDns>>,
        files: StateFiles,
        stats: Arc<Mutex<UnmanagedStats>>,
    ) -> Self {
        let known = files.load_known();
        {
            let mut s = lock(&stats);
            s.dry_run = cfg.dry_run;
            s.daily_cap = cfg.max_creates_per_day;
            s.per_window_cap = cfg.max_creates_per_window;
            s.known_ips = known.ips.len();
            // The persisted list came from a successful refresh.
            s.last_refresh_at = known.last_full_refresh.map(system_time);
            s.last_refresh_ok = known.last_full_refresh.map(|_| true);
        }
        Self {
            filter: NetworkFilter::new(&cfg.networks, &cfg.exclude_networks),
            rules: LabelRules::new(&cfg.label_rules),
            known,
            window: files.load_window(),
            cfg,
            pce,
            dns,
            files,
            labels: HashMap::new(),
            types_checked: false,
            refreshed: false,
            disabled: None,
            cap_warned: false,
            known_dirty: false,
            crossed: BTreeSet::new(),
            logged: HashSet::new(),
            log: Box::new(|l| crate::log_line!(l)),
            stats,
        }
    }

    /// The counters this engine updates.
    pub fn stats(&self) -> Arc<Mutex<UnmanagedStats>> {
        self.stats.clone()
    }

    /// Replaces the log sink so tests can capture lines.
    #[cfg(test)]
    pub(crate) fn set_log(&mut self, log: LogSink) {
        self.log = log;
    }

    /// Logs through the engine's sink (`log_line!` by default).
    pub(crate) fn log(&mut self, line: &str) {
        (self.log)(line);
    }

    pub fn on_window(&mut self, report: &WindowReport, now: i64) -> Summary {
        self.logged.clear();
        self.count(report, now);
        let mut sum = Summary { dry_run: self.cfg.dry_run, ..Default::default() };
        if self.disabled.is_none() {
            sum.candidates = self.window.totals().len();
            self.create_phase(&mut sum, now);
        }
        self.persist(&mut sum);
        if self.disabled.is_none() {
            self.log(&sum.to_string());
        }
        self.update_stats(&sum, now);
        sum
    }

    fn update_stats(&mut self, sum: &Summary, now: i64) {
        let created_today = self.known.created_in_last_day(now);
        let mut s = lock(&self.stats);
        s.last_window = LastWindow {
            candidates: sum.candidates,
            eligible: sum.eligible,
            created: sum.created,
            deferred: sum.deferred,
            errors: sum.errors,
            labels_created: sum.labels_created,
        };
        s.created_total += sum.created as u64;
        s.deferred_total += sum.deferred as u64;
        s.failed_total += sum.errors as u64;
        s.created_today = created_today;
        s.known_ips = self.known.ips.len();
        s.disabled_reason.clone_from(&self.disabled);
    }

    /// The last window during shutdown: counted and persisted, nothing sent to the PCE.
    pub fn on_shutdown(&mut self, report: &WindowReport, now: i64) {
        self.logged.clear();
        self.count(report, now);
        self.persist(&mut Summary::default());
    }

    fn count(&mut self, report: &WindowReport, now: i64) {
        let slice = candidate_counts(&report.ip_flow_counts, &self.filter, &self.known.ips);
        self.window.expire(now, i64::from(self.cfg.flow_window_hours) * HOUR_SECS);
        let before = self.window.totals();
        let min = self.cfg.min_flows;
        self.crossed.extend(
            slice
                .iter()
                .filter(|&(ip, &n)| {
                    let b = before.get(ip).copied().unwrap_or(0);
                    b < min && b + n >= min
                })
                .map(|(&ip, _)| ip),
        );
        if !slice.is_empty() {
            self.window.add(now, slice);
        }
    }

    fn create_phase(&mut self, sum: &mut Summary, now: i64) {
        if !self.types_checked && !self.check_label_types(sum) {
            return;
        }
        let refresh = i64::from(self.cfg.refresh_hours) * HOUR_SECS;
        // A refresh stamped in the future (clock moved back) counts as due.
        if self.known.last_full_refresh.is_none_or(|t| !(0..refresh).contains(&(now - t))) {
            self.refresh(sum, now);
        }
        // A persisted set is trusted only while younger than refresh_hours; after a refresh in this process, up to
        // twice that. A future stamp is never trusted.
        let (max_age, hours) = if self.refreshed {
            (2 * refresh, 2 * i64::from(self.cfg.refresh_hours))
        } else {
            (refresh - 1, i64::from(self.cfg.refresh_hours))
        };
        if self.known.last_full_refresh.is_none_or(|t| !(0..=max_age).contains(&(now - t))) {
            self.log(&format!("Unmanaged workloads: creation paused, no workload list newer than {hours}h"));
            return;
        }

        let created_last_day = self.known.created_in_last_day(now);
        let sel = select(&self.window.totals(), &self.crossed, &self.known.ips, &self.cfg, &self.filter, created_last_day);
        self.crossed.clear();
        (sum.eligible, sum.deferred) = (sel.eligible, sel.deferred);
        {
            let mut s = lock(&self.stats);
            if matches!(sel.pause, Some(Pause::Burst { .. })) {
                s.burst_paused_since.get_or_insert(system_time(now));
            } else {
                s.burst_paused_since = None;
            }
        }
        match &sel.pause {
            Some(Pause::Burst { crossed, networks }) => {
                let nets = networks.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
                let d = self.cfg.max_creates_per_day;
                self.log(&format!(
                    "Unmanaged workloads: burst pause, {crossed} IPs became eligible in one window (more than \
                     max_creates_per_day {d}) in {nets}; check networks/exclude_networks"
                ));
            }
            Some(Pause::DailyCap) if !self.cap_warned => {
                self.cap_warned = true;
                let d = self.cfg.max_creates_per_day;
                self.log(&format!(
                    "Unmanaged workloads: daily cap of {d} reached, creation resumes as the 24h window frees up"
                ));
            }
            _ => {}
        }
        let mut create: Vec<IpAddr> = sel.create.iter().map(|&(ip, _)| ip).collect();
        if create.is_empty() || !self.precreate_check(&mut create, sum) || create.is_empty() {
            return;
        }

        let names = self.resolve(&create, sum);
        self.ensure_labels(&create, sum);
        if self.cfg.dry_run {
            lock(&self.stats).would_create_total += create.len() as u64;
            // Labels that would be created count as resolved, so every selected IP is listed.
            for ip in create {
                let labels: Vec<String> = self.rules.labels_for(ip).iter().map(|(k, v)| format!("{k}={v}")).collect();
                let labels = if labels.is_empty() { "-".to_string() } else { labels.join(",") };
                let host = names.get(&ip).map_or("-", String::as_str);
                self.log(&format!(
                    "Unmanaged workloads (dry run): would create workload {ip} hostname={host} labels={labels}"
                ));
            }
            return;
        }
        // IPs whose labels could not all be resolved are skipped this window.
        let batch: Vec<NewWorkload> = create
            .iter()
            .filter_map(|&ip| {
                let hrefs = self.rules.labels_for(ip).into_iter().map(|kv| self.labels.get(&kv).cloned());
                Some(NewWorkload {
                    ip,
                    hostname: names.get(&ip).cloned(),
                    label_hrefs: hrefs.collect::<Option<_>>()?,
                    external_data_set: self.cfg.external_data_set.clone(),
                })
            })
            .collect();
        self.create(&batch, sum, now);
    }

    /// Validates the rules' label types once; false stops this window (error or disabled).
    fn check_label_types(&mut self, sum: &mut Summary) -> bool {
        let dims = match self.pce.label_dimensions() {
            Ok(d) => d,
            Err(e) => {
                self.fail(sum, "label_dimensions", &e);
                return false;
            }
        };
        self.types_checked = true;
        let Some(key) = self.rules.label_types().into_iter().find(|k| !dims.contains(k)) else {
            return true;
        };
        let cidr = self.rules.rule_using(&key).map(|c| c.to_string()).unwrap_or_default();
        let msg = format!(
            "Unmanaged workloads disabled: label rule {cidr} uses label type '{key}', which does not exist on the PCE"
        );
        self.log(&msg);
        self.disabled = Some(msg);
        false
    }

    /// Full reload of labels and workload IPs; on failure the previous state is kept.
    fn refresh(&mut self, sum: &mut Summary, now: i64) {
        let ok = self.try_refresh(sum, now);
        let mut s = lock(&self.stats);
        (s.last_refresh_at, s.last_refresh_ok) = (Some(system_time(now)), Some(ok));
        s.known_ips = self.known.ips.len();
    }

    fn try_refresh(&mut self, sum: &mut Summary, now: i64) -> bool {
        let labels = match self.pce.labels() {
            Ok(l) => l,
            Err(e) => {
                self.fail(sum, "labels", &e);
                return false;
            }
        };
        let ips = match self.pce.workload_ips() {
            Ok(i) => i,
            Err(e) => {
                self.fail(sum, "workload_ips", &e);
                return false;
            }
        };
        self.labels = labels.into_iter().map(|l| ((l.key, l.value), l.href)).collect();
        self.known.ips = ips;
        self.known.last_full_refresh = Some(now);
        self.refreshed = true;
        self.window.forget(&self.known.ips);
        self.known_dirty = true;
        sum.candidates = self.window.totals().len();
        true
    }

    /// Drops IPs that got a workload since the last refresh (marking them known). False: a check failed and
    /// nothing may be created this window.
    fn precreate_check(&mut self, create: &mut Vec<IpAddr>, sum: &mut Summary) -> bool {
        let mut found = BTreeSet::new();
        let mut ok = true;
        for &ip in create.iter() {
            match self.pce.has_workload(ip) {
                Ok(true) => {
                    found.insert(ip);
                }
                Ok(false) => {}
                Err(e) => {
                    self.fail(sum, "has_workload", &e);
                    ok = false;
                    break;
                }
            }
        }
        create.retain(|ip| !found.contains(ip));
        self.mark_known(found);
        ok
    }

    fn resolve(&self, create: &[IpAddr], sum: &mut Summary) -> HashMap<IpAddr, String> {
        let Some(dns) = &self.dns else { return HashMap::new() };
        let timeout = Duration::from_millis(self.cfg.dns.timeout_ms);
        let names = resolve_all(dns, create, self.cfg.dns.concurrency, timeout);
        (sum.looked_up, sum.resolved) = (create.len(), names.len());
        names
    }

    /// Creates (or, on `Exists`, looks up) each label the batch needs that is not cached. Each label is tried at
    /// most once per window; one that stays unresolved leaves its IPs uncreated until the next window.
    fn ensure_labels(&mut self, create: &[IpAddr], sum: &mut Summary) {
        let needed: BTreeSet<(String, String)> = create
            .iter()
            .flat_map(|&ip| self.rules.labels_for(ip))
            .filter(|kv| !self.labels.contains_key(kv))
            .collect();
        for (key, value) in needed {
            if self.cfg.dry_run {
                self.log(&format!("Unmanaged workloads (dry run): would create label {key}={value}"));
                continue;
            }
            let label = match self.pce.create_label(&key, &value) {
                Ok(l) => {
                    sum.labels_created += 1;
                    l
                }
                Err(PceError::Exists) => match self.pce.find_label(&key, &value) {
                    Ok(Some(l)) => l,
                    Ok(None) => {
                        self.fail_line(
                            sum,
                            format!(
                                "Unmanaged workloads: label {key}={value} exists on the PCE but could not be \
                                 resolved; skipping IPs that need it"
                            ),
                        );
                        continue;
                    }
                    Err(e) => {
                        self.fail(sum, "find_label", &e);
                        continue;
                    }
                },
                Err(e) => {
                    self.fail(sum, "create_label", &e);
                    continue;
                }
            };
            self.labels.insert((key, value), label.href);
        }
    }

    /// `bulk_create` in chunks; a failed call leaves its chunk and the rest as candidates for the next window.
    /// An ambiguous failure may still have created the chunk, so it is charged to the daily cap all the same.
    /// The known set is saved right after each chunk that changed it, so an unclean stop never loses the cap ledger.
    fn create(&mut self, batch: &[NewWorkload], sum: &mut Summary, now: i64) {
        for chunk in batch.chunks(BULK_CHUNK) {
            let results = match self.pce.bulk_create(chunk) {
                Ok(r) => r,
                Err(e) => {
                    if e.is_ambiguous() {
                        self.known.created_at.extend(std::iter::repeat_n(now, chunk.len()));
                        self.known_dirty = true;
                        let _ = self.save_known(sum);
                    }
                    self.fail(sum, "bulk_create", &e);
                    break;
                }
            };
            let mut newly = BTreeSet::new();
            for (w, r) in chunk.iter().zip(results) {
                match r {
                    CreateResult::Created => {
                        newly.insert(w.ip);
                        self.known.created_at.push(now);
                        sum.created += 1;
                    }
                    CreateResult::AlreadyExists => {
                        newly.insert(w.ip);
                    }
                    CreateResult::Failed(msg) => {
                        self.fail_line(sum, format!("Unmanaged workloads: bulk_create failed for {}: {msg}", w.ip))
                    }
                }
            }
            self.mark_known(newly);
            // Without a saved ledger, further chunks could exceed the cap after an unclean stop.
            if !self.save_known(sum) {
                break;
            }
        }
        if sum.created > 0 {
            self.cap_warned = false;
        }
    }

    fn mark_known(&mut self, ips: BTreeSet<IpAddr>) {
        if ips.is_empty() {
            return;
        }
        self.window.forget(&ips);
        self.known.ips.extend(ips);
        self.known_dirty = true;
    }

    /// Saves the window every time (it gains a slice nearly every window) and the known set when it changed.
    fn persist(&mut self, sum: &mut Summary) {
        if let Err(e) = self.files.save_window(&self.window) {
            self.fail_line(sum, format!("Unmanaged workloads: saving the flow window failed: {e}"));
        }
        let _ = self.save_known(sum);
    }

    /// Saves the known set if it changed since the last save. False: the save failed (logged).
    fn save_known(&mut self, sum: &mut Summary) -> bool {
        if !self.known_dirty {
            return true;
        }
        match self.files.save_known(&self.known) {
            Ok(()) => {
                self.known_dirty = false;
                true
            }
            Err(e) => {
                self.fail_line(sum, format!("Unmanaged workloads: saving the known workloads failed: {e}"));
                false
            }
        }
    }

    fn fail(&mut self, sum: &mut Summary, call: &str, e: &PceError) {
        let line = match e {
            PceError::Auth(s) => format!(
                "Unmanaged workloads: PCE refused {call} with HTTP {s}; the API key needs permission to {}",
                permission(call)
            ),
            _ => format!("Unmanaged workloads: {call} failed: {}", describe(e)),
        };
        self.fail_line(sum, line);
    }

    /// Counts an error; the line is logged once per window.
    fn fail_line(&mut self, sum: &mut Summary, line: String) {
        sum.errors += 1;
        if self.logged.insert(line.clone()) {
            self.log(&line);
        }
    }
}

fn lock(stats: &Mutex<UnmanagedStats>) -> MutexGuard<'_, UnmanagedStats> {
    stats.lock().unwrap_or_else(|e| e.into_inner())
}

/// Unix seconds (as the engine keeps time) as a `SystemTime`.
fn system_time(secs: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64)
}

#[cfg(test)]
#[path = "engine_tests.rs"]
pub(crate) mod tests;
