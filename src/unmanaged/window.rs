//! Sliding window of per-IP flow counts in hourly buckets: one slice per UTC hour with flows, which bounds the
//! slices at about `flow_window_hours + 1`.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Slice {
    /// Unix seconds when the latest batch merged into this slice ended.
    end: i64,
    counts: BTreeMap<IpAddr, u64>,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct FlowWindow {
    slices: Vec<Slice>,
}

impl FlowWindow {
    /// Merges into the last slice when `end` falls in the same UTC hour, otherwise starts a new slice. Files
    /// written before hourly buckets (one slice per batch) load and expire the same way.
    pub fn add(&mut self, end: i64, counts: BTreeMap<IpAddr, u64>) {
        let hour = end.div_euclid(3600);
        match self.slices.last_mut() {
            Some(last) if last.end.div_euclid(3600) == hour => {
                last.end = last.end.max(end);
                for (ip, n) in counts {
                    *last.counts.entry(ip).or_insert(0) += n;
                }
            }
            _ => self.slices.push(Slice { end, counts }),
        }
    }

    /// Drop slices that left the window (`end <= now - window_secs`) or lie in the future (clock moved back).
    pub fn expire(&mut self, now: i64, window_secs: i64) {
        self.slices.retain(|s| s.end > now - window_secs && s.end <= now);
    }

    pub fn totals(&self) -> HashMap<IpAddr, u64> {
        let mut out = HashMap::new();
        for s in &self.slices {
            for (ip, n) in &s.counts {
                *out.entry(*ip).or_insert(0) += n;
            }
        }
        out
    }

    /// Remove IPs from every slice, then drop slices left empty.
    pub fn forget(&mut self, ips: &BTreeSet<IpAddr>) {
        for s in &mut self.slices {
            s.counts.retain(|ip, _| !ips.contains(ip));
        }
        self.slices.retain(|s| !s.counts.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn counts(v: &[(&str, u64)]) -> BTreeMap<IpAddr, u64> {
        v.iter().map(|(a, n)| (ip(a), *n)).collect()
    }

    #[test]
    fn totals_sum_slices() {
        let mut w = FlowWindow::default();
        w.add(1, counts(&[("10.0.0.1", 2), ("10.0.0.2", 1)]));
        w.add(2, counts(&[("10.0.0.1", 3)]));
        let t = w.totals();
        assert_eq!(t[&ip("10.0.0.1")], 5);
        assert_eq!(t[&ip("10.0.0.2")], 1);
    }

    #[test]
    fn adds_in_the_same_utc_hour_share_a_slice() {
        let mut w = FlowWindow::default();
        w.add(7_200, counts(&[("10.0.0.1", 2)]));
        w.add(10_799, counts(&[("10.0.0.1", 3), ("10.0.0.2", 1)]));
        assert_eq!(w.slices.len(), 1);
        assert_eq!(w.slices[0].end, 10_799);
        assert_eq!(w.totals(), HashMap::from([(ip("10.0.0.1"), 5), (ip("10.0.0.2"), 1)]));
    }

    #[test]
    fn adds_in_different_hours_make_two_slices() {
        let mut w = FlowWindow::default();
        w.add(10_799, counts(&[("10.0.0.1", 2)]));
        w.add(10_800, counts(&[("10.0.0.1", 3)]));
        assert_eq!(w.slices.iter().map(|s| s.end).collect::<Vec<_>>(), [10_799, 10_800]);
        assert_eq!(w.totals()[&ip("10.0.0.1")], 5);
    }

    #[test]
    fn expire_drops_future_and_old_entries() {
        let mut w = FlowWindow::default();
        for end in [10_000, 13_601, 100_001] {
            w.add(end, counts(&[("10.0.0.1", 1)]));
        }
        w.expire(100_000, 86_400);
        assert_eq!(w.slices.iter().map(|s| s.end).collect::<Vec<_>>(), [13_601]);
    }

    #[test]
    fn forget_removes_ip_and_empty_slices() {
        let mut w = FlowWindow::default();
        w.add(1, counts(&[("10.0.0.1", 2)]));
        w.add(3_601, counts(&[("10.0.0.1", 1), ("10.0.0.2", 4)]));
        w.forget(&BTreeSet::from([ip("10.0.0.1")]));
        assert_eq!(w.slices.len(), 1);
        assert_eq!(w.totals(), HashMap::from([(ip("10.0.0.2"), 4)]));
    }
}
