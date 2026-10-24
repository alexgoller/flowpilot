//! Health of the core threads (docs/stats.md, "What /healthz checks"). A `ThreadGuard` lives in every core thread (aggregator, parser workers, UDP readers, the
//! `report_flows` loop); dropping it outside shutdown, by returning or by a panic unwinding, marks the process
//! unhealthy. `report_flows` beats once per window, so a stalled flush shows too.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static HEALTH: Health = Health::new();

/// Core threads that ended and the last heartbeat.
pub(crate) struct Health {
    dead: Mutex<Vec<&'static str>>,
    /// Unix seconds of the last heartbeat; 0 = none yet.
    heartbeat: AtomicU64,
}

impl Health {
    pub(crate) const fn new() -> Self {
        Self { dead: Mutex::new(Vec::new()), heartbeat: AtomicU64::new(0) }
    }

    fn thread_ended(&self, name: &'static str) {
        crate::log_line!("Error: core thread ended:", name);
        let mut dead = self.dead.lock().unwrap_or_else(|e| e.into_inner());
        if !dead.contains(&name) {
            dead.push(name); // several workers share a name
        }
    }

    pub(crate) fn beat(&self, now: SystemTime) {
        self.heartbeat.store(unix(now), Ordering::Relaxed);
    }

    pub(crate) fn check(&self, now: SystemTime, aggregation_minutes: i16) -> Result<(), String> {
        let dead = self.dead.lock().unwrap_or_else(|e| e.into_inner());
        if !dead.is_empty() {
            return Err(format!("core thread ended: {}", dead.join(", ")));
        }
        // No heartbeat yet: the aggregation loop has not started.
        let last = self.heartbeat.load(Ordering::Relaxed);
        let age = unix(now).saturating_sub(last);
        let limit = 2 * 60 * aggregation_minutes.max(0) as u64 + SLACK.as_secs();
        if last != 0 && age > limit {
            return Err(format!("aggregation loop stalled: last heartbeat {age} s ago"));
        }
        Ok(())
    }
}

/// Held by a core thread for its whole life.
pub struct ThreadGuard {
    name: &'static str,
    health: &'static Health,
    shutdown: &'static AtomicBool,
}

impl ThreadGuard {
    /// A guard for the core thread `name` (reported by `health`).
    pub fn core(name: &'static str) -> Self {
        Self { name, health: &HEALTH, shutdown: &crate::log::SHUTDOWN }
    }
}

impl Drop for ThreadGuard {
    fn drop(&mut self) {
        if !self.shutdown.load(Ordering::SeqCst) {
            self.health.thread_ended(self.name);
        }
    }
}

/// One iteration of the `report_flows` loop.
pub fn heartbeat() {
    HEALTH.beat(SystemTime::now());
}

/// `Err` naming the reason when a core thread has ended outside shutdown, or the last heartbeat is older than
/// `2 × aggregation_minutes + 60 s`.
pub fn health(now: SystemTime, aggregation_minutes: i16) -> Result<(), String> {
    HEALTH.check(now, aggregation_minutes)
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Allowed on top of two aggregation windows (one window plus the flush time is normal).
const SLACK: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;

    fn leak<T>(t: T) -> &'static T {
        Box::leak(Box::new(t))
    }

    #[test]
    fn health_detects_dead_thread() {
        let now = SystemTime::now();
        let (health, shutdown) = (leak(Health::new()), leak(AtomicBool::new(false)));
        let guard = |name| ThreadGuard { name, health, shutdown };
        assert_eq!(health.check(now, 10), Ok(()));
        // Inside shutdown, threads end on purpose.
        shutdown.store(true, Ordering::SeqCst);
        drop(guard("aggregator"));
        assert_eq!(health.check(now, 10), Ok(()));
        // Outside shutdown, also by a panic.
        shutdown.store(false, Ordering::SeqCst);
        let g = guard("udp reader");
        let _ = std::thread::spawn(move || {
            let _g = g;
            panic!("boom");
        })
        .join();
        let err = health.check(now, 10).unwrap_err();
        assert!(err.contains("udp reader"), "{err}");
        drop(guard("aggregator"));
        drop(guard("aggregator"));
        let err = health.check(now, 10).unwrap_err();
        assert_eq!(err, "core thread ended: udp reader, aggregator");
    }

    #[test]
    fn health_detects_stalled_heartbeat() {
        let t0 = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let health = Health::new();
        // No heartbeat yet: the loop has not started, nothing is stalled.
        assert_eq!(health.check(t0, 10), Ok(()));
        health.beat(t0);
        // 2 × 10 min + 60 s.
        assert_eq!(health.check(t0 + Duration::from_secs(1260), 10), Ok(()));
        let err = health.check(t0 + Duration::from_secs(1261), 10).unwrap_err();
        assert!(err.contains("1261"), "{err}");
        health.beat(t0 + Duration::from_secs(1261));
        assert_eq!(health.check(t0 + Duration::from_secs(1300), 10), Ok(()));
    }
}
