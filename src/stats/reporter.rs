//! The `FLOWPILOT_STATS` log line (docs/stats.md, "Reading the log line"):
//! every `interval_seconds`, the snapshot with the 50 exporters that had the most flows in the interval.

use std::sync::Arc;
use std::thread;
use std::time::SystemTime;

use super::snapshot::{snapshot_since, ExporterFlows, SnapshotContext};
use crate::log::shutdown;
use crate::log_line;

/// Exporters listed per collector in the log line.
pub const LOG_EXPORTERS: usize = 50;

/// Start the log-line thread (nothing when `stats.log` is off). Stops at shutdown.
pub fn start(ctx: Arc<SnapshotContext>) {
    if !ctx.cfg.log {
        return;
    }
    let every = ctx.cfg.interval();
    thread::spawn(move || {
        let mut prev = ExporterFlows::default();
        loop {
            thread::sleep(every);
            if shutdown() {
                return;
            }
            let s = snapshot_since(&ctx, SystemTime::now(), Some(LOG_EXPORTERS), &mut prev);
            match serde_json::to_string(&s) {
                Ok(json) => log_line!("FLOWPILOT_STATS", json),
                Err(e) => log_line!("Error:", e),
            }
        }
    });
}
