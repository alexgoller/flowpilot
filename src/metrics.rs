//! Minimal port of the rcrowley/go-metrics Meter, registry and `metrics.Log` output
//! (the `meter <name>` lines FlowLink logs).
//!
//! Ported from rcrowley/go-metrics (https://github.com/rcrowley/go-metrics), BSD-2-Clause,
//! Copyright 2012 Richard Crowley. See NOTICE.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const TICK: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct Ewma {
    alpha: f64,
    rate: f64, // per second
    init: bool,
}

impl Ewma {
    fn new(minutes: f64) -> Self {
        Self { alpha: 1.0 - (-5.0 / 60.0 / minutes).exp(), rate: 0.0, init: false }
    }

    fn tick(&mut self, count: i64) {
        let instant = count as f64 / TICK.as_secs_f64();
        if self.init {
            self.rate += self.alpha * (instant - self.rate);
        } else {
            self.rate = instant;
            self.init = true;
        }
    }
}

#[derive(Debug)]
struct MeterState {
    count: i64,
    uncounted: i64,
    rates: [Ewma; 3],
    start: Instant,
}

/// go-metrics `StandardMeter`: total count, 1/5/15-minute EWMA rates ticked every 5 s, mean rate.
/// Ported from rcrowley/go-metrics, BSD-2-Clause, Copyright 2012 Richard Crowley. See NOTICE.
#[derive(Clone, Debug)]
pub struct Meter(Arc<Mutex<MeterState>>);

impl Meter {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(MeterState {
            count: 0,
            uncounted: 0,
            rates: [Ewma::new(1.0), Ewma::new(5.0), Ewma::new(15.0)],
            start: Instant::now(),
        })))
    }

    pub fn mark(&self, n: i64) {
        let mut s = self.lock();
        s.count += n;
        s.uncounted += n;
    }

    pub fn count(&self) -> i64 {
        self.lock().count
    }

    pub(crate) fn tick(&self) {
        let mut s = self.lock();
        let n = std::mem::take(&mut s.uncounted);
        for r in s.rates.iter_mut() {
            r.tick(n);
        }
    }

    /// (count, rate1, rate5, rate15, mean)
    pub(crate) fn snapshot(&self) -> (i64, f64, f64, f64, f64) {
        let s = self.lock();
        let elapsed = s.start.elapsed().as_secs_f64();
        let mean = if elapsed > 0.0 { s.count as f64 / elapsed } else { 0.0 };
        (s.count, s.rates[0].rate, s.rates[1].rate, s.rates[2].rate, mean)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MeterState> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for Meter {
    fn default() -> Self {
        Self::new()
    }
}

fn registry() -> &'static Mutex<BTreeMap<String, Meter>> {
    static REG: OnceLock<Mutex<BTreeMap<String, Meter>>> = OnceLock::new();
    REG.get_or_init(|| {
        // go-metrics meter arbiter: one ticker for all meters.
        thread::spawn(|| loop {
            thread::sleep(TICK);
            let meters: Vec<Meter> = registry().lock().unwrap().values().cloned().collect();
            meters.iter().for_each(Meter::tick);
        });
        Mutex::new(BTreeMap::new())
    })
}

/// `metrics.GetOrRegisterMeter(name, nil)`: consumers with the same name share one meter.
pub fn get_or_register_meter(name: &str) -> Meter {
    registry().lock().unwrap().entry(name.to_string()).or_default().clone()
}

/// The meter registered as `name`, without registering one (stats read the rates; a lookup must not bring a meter
/// back after `unregister_all`).
pub(crate) fn get(name: &str) -> Option<Meter> {
    registry().lock().unwrap().get(name).cloned()
}

/// `metrics.DefaultRegistry.UnregisterAll()` (signal handler).
pub fn unregister_all() {
    registry().lock().unwrap().clear();
}

/// The six lines go-metrics `LogScaled` prints per meter, with `[`, `]` and newlines stripped
/// (as FlowLink logs them). The meter name loses brackets too.
/// Ported from rcrowley/go-metrics, BSD-2-Clause, Copyright 2012 Richard Crowley. See NOTICE.
pub fn format_meter(name: &str, m: &Meter) -> Vec<String> {
    let (count, r1, r5, r15, mean) = m.snapshot();
    let name: String = name.chars().filter(|c| !matches!(c, '[' | ']' | '\n')).collect();
    vec![
        format!("meter {name}"),
        format!("  count:       {count:9}"),
        format!("  1-min rate:  {r1:12.2}"),
        format!("  5-min rate:  {r5:12.2}"),
        format!("  15-min rate: {r15:12.2}"),
        format!("  mean rate:   {mean:12.2}"),
    ]
}

/// Logs every registered meter every `every`, like go-metrics `metrics.Log`. A zero interval never prints
/// (`time.Tick(0)` returns nil in Go).
/// Ported from rcrowley/go-metrics, BSD-2-Clause, Copyright 2012 Richard Crowley. See NOTICE.
pub fn start_logger(every: Duration) {
    if every.is_zero() {
        return;
    }
    thread::spawn(move || loop {
        thread::sleep(every);
        let meters: Vec<(String, Meter)> =
            registry().lock().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        for (name, m) in meters {
            for line in format_meter(&name, &m) {
                crate::log_line!(line);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ewma_first_tick_sets_instant_rate() {
        let m = Meter::new();
        m.mark(50);
        m.tick();
        let (count, r1, r5, r15, _) = m.snapshot();
        assert_eq!(count, 50);
        assert_eq!((r1, r5, r15), (10.0, 10.0, 10.0));
        m.tick(); // no new events: rates decay
        let (_, r1, r5, _, _) = m.snapshot();
        assert!(r1 < 10.0 && r5 < 10.0 && r1 < r5);
    }

    #[test]
    fn meter_lines_match_go_layout() {
        let m = Meter::new();
        m.mark(42);
        let lines = format_meter("net[flow]", &m);
        assert_eq!(lines[0], "meter netflow");
        assert_eq!(lines[1], "  count:              42");
        assert_eq!(lines[2], "  1-min rate:          0.00");
    }
}
