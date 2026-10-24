//! Unmanaged-workload counters (docs/stats.md, `unmanaged_workloads`). A plain struct behind the engine's `Arc<Mutex<_>>`: the worker thread writes it at the end of
//! each window, after each refresh attempt and when a burst pause starts or ends; the stats output clones it.

use std::time::SystemTime;

use serde::Serialize;

use super::rfc3339;

/// Counts of the last window (as in its summary log line).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct LastWindow {
    pub candidates: usize,
    pub eligible: usize,
    /// 0 in dry run.
    pub created: usize,
    pub deferred: usize,
    pub errors: usize,
    pub labels_created: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct UnmanagedStats {
    pub dry_run: bool,
    /// IPs that have a workload on the PCE (last refresh plus creations since).
    pub known_ips: usize,
    /// The last refresh attempt; at start, the persisted list's refresh time (outcome `true`).
    #[serde(serialize_with = "rfc3339::opt")]
    pub last_refresh_at: Option<SystemTime>,
    pub last_refresh_ok: Option<bool>,
    pub last_window: LastWindow,
    /// Totals since start, summed over windows.
    pub created_total: u64,
    /// Creations in the last 24 h (what the daily cap is charged; includes ambiguous `bulk_create` failures).
    pub created_today: usize,
    /// Dry run: IPs listed as "would create", per window (an IP is listed again every window it stays eligible).
    pub would_create_total: u64,
    /// Eligible IPs left for a later window by the caps, per window.
    pub deferred_total: u64,
    /// Errors (failed PCE calls, failed creations, failed saves), per window.
    pub failed_total: u64,
    pub daily_cap: usize,
    pub per_window_cap: usize,
    /// The window whose crossings triggered the burst pause; `None` once a window selects without one.
    #[serde(serialize_with = "rfc3339::opt")]
    pub burst_paused_since: Option<SystemTime>,
    /// The disable message, when a label rule uses a label type the PCE lacks.
    pub disabled_reason: Option<String>,
}
