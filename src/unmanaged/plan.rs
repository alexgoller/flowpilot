//! Candidate selection: eligibility, per-window and per-day caps, burst pause. Pure, no I/O.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use ipnet::IpNet;

use super::config::UnmanagedConfig;
use super::net::{parse_ipv4, NetworkFilter};

/// Why creation is paused for this window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pause {
    /// More IPs became eligible in this window than the daily cap: likely a scan or misconfiguration, create
    /// nothing this window.
    Burst {
        crossed: usize,
        networks: Vec<IpNet>,
    },
    /// The daily budget is used up.
    DailyCap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub create: Vec<(IpAddr, u64)>,
    pub eligible: usize,
    pub deferred: usize,
    pub pause: Option<Pause>,
}

/// Per-window flow counts restricted to IPv4 addresses the filter accepts and that are not yet known.
pub fn candidate_counts(
    report_counts: &HashMap<String, u64>,
    filter: &NetworkFilter,
    known: &BTreeSet<IpAddr>,
) -> BTreeMap<IpAddr, u64> {
    report_counts
        .iter()
        .filter_map(|(k, &n)| {
            let ip = parse_ipv4(k)?;
            (filter.accepts(ip) && !known.contains(&ip)).then_some((ip, n))
        })
        .collect()
}

/// `crossed`: the IPs whose total reached `min_flows` with this window's slice (it was below before). Only they
/// count toward the burst pause; a standing backlog drains through the caps.
pub fn select(
    totals: &HashMap<IpAddr, u64>,
    crossed: &BTreeSet<IpAddr>,
    known: &BTreeSet<IpAddr>,
    cfg: &UnmanagedConfig,
    filter: &NetworkFilter,
    created_last_day: usize,
) -> Selection {
    let mut eligible: Vec<(IpAddr, u64)> = totals
        .iter()
        .filter(|(ip, &n)| n >= cfg.min_flows && !known.contains(ip))
        .map(|(&ip, &n)| (ip, n))
        .collect();
    let count = eligible.len();

    let new: Vec<IpAddr> = eligible
        .iter()
        .map(|&(ip, _)| ip)
        .filter(|ip| crossed.contains(ip))
        .collect();
    if new.len() > cfg.max_creates_per_day {
        let networks: BTreeSet<IpNet> = new.iter().filter_map(|&ip| filter.containing(ip)).collect();
        return Selection {
            create: Vec::new(),
            eligible: count,
            deferred: 0,
            pause: Some(Pause::Burst {
                crossed: new.len(),
                networks: networks.into_iter().collect(),
            }),
        };
    }

    let budget = cfg
        .max_creates_per_window
        .min(cfg.max_creates_per_day.saturating_sub(created_last_day));
    if budget == 0 && count > 0 {
        return Selection {
            create: Vec::new(),
            eligible: count,
            deferred: count,
            pause: Some(Pause::DailyCap),
        };
    }

    eligible.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    eligible.truncate(budget);
    Selection {
        deferred: count - eligible.len(),
        create: eligible,
        eligible: count,
        pause: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn filter(cfg: &UnmanagedConfig) -> NetworkFilter {
        NetworkFilter::new(&cfg.networks, &cfg.exclude_networks)
    }

    fn cfg() -> UnmanagedConfig {
        UnmanagedConfig::default()
    }

    #[test]
    fn select_threshold_and_known() {
        let cfg = cfg();
        let totals: HashMap<IpAddr, u64> = [
            (ip("10.0.0.1"), 9),
            (ip("10.0.0.2"), 10),
            (ip("10.0.0.3"), 50),
        ]
        .into();
        let known: BTreeSet<IpAddr> = [ip("10.0.0.3")].into();
        let s = select(&totals, &BTreeSet::new(), &known, &cfg, &filter(&cfg), 0);
        assert_eq!(s.create, vec![(ip("10.0.0.2"), 10)]);
        assert_eq!(s.eligible, 1);
        assert_eq!(s.deferred, 0);
        assert_eq!(s.pause, None);
    }

    #[test]
    fn select_orders_by_count_and_caps_window() {
        let mut cfg = cfg();
        cfg.max_creates_per_window = 2;
        let totals: HashMap<IpAddr, u64> = [
            (ip("10.0.0.1"), 10),
            (ip("10.0.0.2"), 30),
            (ip("10.0.0.3"), 20),
            (ip("10.0.0.4"), 30),
            (ip("10.0.0.5"), 15),
        ]
        .into();
        let s = select(&totals, &BTreeSet::new(), &BTreeSet::new(), &cfg, &filter(&cfg), 0);
        assert_eq!(s.create, vec![(ip("10.0.0.2"), 30), (ip("10.0.0.4"), 30)]);
        assert_eq!(s.eligible, 5);
        assert_eq!(s.deferred, 3);
        assert_eq!(s.pause, None);
    }

    #[test]
    fn select_daily_cap_remaining_budget() {
        let mut cfg = cfg();
        cfg.max_creates_per_day = 500;
        let totals: HashMap<IpAddr, u64> = [
            (ip("10.0.0.1"), 10),
            (ip("10.0.0.2"), 20),
            (ip("10.0.0.3"), 30),
        ]
        .into();
        let s = select(&totals, &BTreeSet::new(), &BTreeSet::new(), &cfg, &filter(&cfg), 499);
        assert_eq!(s.create, vec![(ip("10.0.0.3"), 30)]);
        assert_eq!(s.deferred, 2);
        assert_eq!(s.pause, None);
    }

    #[test]
    fn select_daily_cap_reached() {
        let mut cfg = cfg();
        cfg.max_creates_per_day = 500;
        let totals: HashMap<IpAddr, u64> = [(ip("10.0.0.1"), 10)].into();
        let s = select(&totals, &BTreeSet::new(), &BTreeSet::new(), &cfg, &filter(&cfg), 500);
        assert!(s.create.is_empty());
        assert_eq!(s.eligible, 1);
        assert_eq!(s.pause, Some(Pause::DailyCap));
    }

    fn many(n: u32) -> HashMap<IpAddr, u64> {
        (0..n).map(|i| (IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + i)), 10)).collect()
    }

    #[test]
    fn select_burst_pause_counts_new_crossings() {
        let cfg = cfg();
        assert_eq!(cfg.max_creates_per_day, 500);
        let totals = many(501);
        let crossed: BTreeSet<IpAddr> = totals.keys().copied().collect();
        let s = select(&totals, &crossed, &BTreeSet::new(), &cfg, &filter(&cfg), 0);
        assert!(s.create.is_empty());
        assert_eq!(s.eligible, 501);
        assert_eq!(
            s.pause,
            Some(Pause::Burst {
                crossed: 501,
                networks: vec!["10.0.0.0/8".parse().unwrap()]
            })
        );
    }

    #[test]
    fn select_backlog_above_daily_cap_drains_without_burst() {
        let cfg = cfg();
        let totals = many(600);
        // A few new crossings on top of a standing backlog: no burst, the caps apply.
        let crossed: BTreeSet<IpAddr> = totals.keys().take(5).copied().collect();
        let s = select(&totals, &crossed, &BTreeSet::new(), &cfg, &filter(&cfg), 0);
        assert_eq!(s.pause, None);
        assert_eq!((s.create.len(), s.eligible, s.deferred), (100, 600, 500));
        // Known IPs among the crossings do not count toward a burst.
        let known: BTreeSet<IpAddr> = totals.keys().copied().collect();
        let s = select(&totals, &known, &known, &cfg, &filter(&cfg), 0);
        assert_eq!((s.pause, s.eligible), (None, 0));
    }

    #[test]
    fn select_ignores_unparseable_and_v6_ips() {
        let cfg = cfg();
        let counts: HashMap<String, u64> = [
            ("", 5),
            ("fd00::1", 5),
            ("abc", 5),
            ("8.8.8.8", 5),
            ("10.0.0.1", 7),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        let got = candidate_counts(&counts, &filter(&cfg), &BTreeSet::new());
        assert_eq!(got, BTreeMap::from([(ip("10.0.0.1"), 7)]));
    }
}
