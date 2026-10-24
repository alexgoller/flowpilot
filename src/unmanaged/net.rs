//! Network eligibility filter and CIDR label rules for unmanaged workloads.

use super::config::LabelRule;
use ipnet::IpNet;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::str::FromStr;

/// Some only for a plain dotted-quad IPv4 literal (no IPv6, names or leading zeros).
pub fn parse_ipv4(s: &str) -> Option<IpAddr> {
    std::net::Ipv4Addr::from_str(s).ok().map(IpAddr::V4)
}

fn is_v4(ip: IpAddr) -> bool {
    ip.is_ipv4()
}

#[derive(Clone, Debug)]
pub struct NetworkFilter {
    include: Vec<IpNet>,
    exclude: Vec<IpNet>,
}

impl NetworkFilter {
    pub fn new(include: &[IpNet], exclude: &[IpNet]) -> Self {
        Self {
            include: include.iter().map(IpNet::trunc).collect(),
            exclude: exclude.iter().map(IpNet::trunc).collect(),
        }
    }

    /// In an include network, in no exclude network, IPv4 only.
    pub fn accepts(&self, ip: IpAddr) -> bool {
        is_v4(ip) && self.containing(ip).is_some() && !self.exclude.iter().any(|n| n.contains(&ip))
    }

    /// The most specific include network holding `ip`.
    pub fn containing(&self, ip: IpAddr) -> Option<IpNet> {
        if !is_v4(ip) {
            return None;
        }
        self.include
            .iter()
            .filter(|n| n.contains(&ip))
            .max_by_key(|n| n.prefix_len())
            .copied()
    }
}

#[derive(Clone, Debug)]
pub struct LabelRules {
    rules: Vec<LabelRule>,
}

impl LabelRules {
    pub fn new(rules: &[LabelRule]) -> Self {
        Self {
            rules: rules
                .iter()
                .map(|r| LabelRule { cidr: r.cidr.trunc(), labels: r.labels.clone() })
                .collect(),
        }
    }

    /// Longest matching prefix wins per label type; shorter rules fill the gaps.
    pub fn labels_for(&self, ip: IpAddr) -> BTreeMap<String, String> {
        let mut hits: Vec<&LabelRule> = self.rules.iter().filter(|r| r.cidr.contains(&ip)).collect();
        hits.sort_by_key(|r| std::cmp::Reverse(r.cidr.prefix_len()));
        let mut out = BTreeMap::new();
        for r in hits {
            for (k, v) in &r.labels {
                out.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        out
    }

    pub fn label_types(&self) -> BTreeSet<String> {
        self.rules.iter().flat_map(|r| r.labels.keys().cloned()).collect()
    }

    /// CIDR of the first rule using label type `key`.
    pub fn rule_using(&self, key: &str) -> Option<IpNet> {
        self.rules.iter().find(|r| r.labels.contains_key(key)).map(|r| r.cidr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> IpNet {
        s.parse().unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn rule(c: &str, l: &[(&str, &str)]) -> LabelRule {
        LabelRule {
            cidr: n(c),
            labels: l.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }
    fn map(l: &[(&str, &str)]) -> BTreeMap<String, String> {
        l.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn filter_default_rfc1918() {
        let f = NetworkFilter::new(&[n("10.0.0.0/8"), n("172.16.0.0/12"), n("192.168.0.0/16")], &[]);
        assert!(f.accepts(ip("10.1.2.3")));
        assert!(f.accepts(ip("192.168.0.1")));
        assert!(!f.accepts(ip("8.8.8.8")));
        assert!(!f.accepts(ip("172.32.0.1")));
    }

    #[test]
    fn filter_exclude_wins() {
        let f = NetworkFilter::new(&[n("10.0.0.0/8")], &[n("10.9.0.0/16")]);
        assert!(!f.accepts(ip("10.9.1.1")));
        assert!(f.accepts(ip("10.8.1.1")));
    }

    #[test]
    fn filter_rejects_v6_and_junk() {
        assert_eq!(parse_ipv4("fd00::1"), None);
        assert_eq!(parse_ipv4("host"), None);
        assert_eq!(parse_ipv4(""), None);
        assert_eq!(parse_ipv4("10.0.0.01"), None);
        assert_eq!(parse_ipv4("10.0.0.256"), None);
        assert_eq!(parse_ipv4("10.1.2.3"), Some(ip("10.1.2.3")));
        let f = NetworkFilter::new(&[n("fd00::/8"), n("10.0.0.0/8")], &[]);
        assert!(!f.accepts(ip("fd00::1")));
    }

    #[test]
    fn filter_containing_most_specific() {
        let f = NetworkFilter::new(&[n("10.0.0.0/8"), n("10.20.0.0/16")], &[]);
        assert_eq!(f.containing(ip("10.20.1.1")), Some(n("10.20.0.0/16")));
        assert_eq!(f.containing(ip("10.30.1.1")), Some(n("10.0.0.0/8")));
        assert_eq!(f.containing(ip("8.8.8.8")), None);
    }

    #[test]
    fn host_bits_are_normalised() {
        let f = NetworkFilter::new(&[n("10.0.0.5/8")], &[]);
        assert!(f.accepts(ip("10.200.0.1")));
        assert_eq!(f.containing(ip("10.1.1.1")), Some(n("10.0.0.0/8")));
        let r = LabelRules::new(&[rule("10.0.0.5/8", &[("env", "dev")])]);
        assert_eq!(r.labels_for(ip("10.9.9.9")), map(&[("env", "dev")]));
        assert_eq!(r.rule_using("env"), Some(n("10.0.0.0/8")));
    }

    #[test]
    fn labels_longest_prefix_wins_and_fills() {
        let r = LabelRules::new(&[
            rule("10.0.0.0/8", &[("loc", "dc1"), ("env", "dev")]),
            rule("10.20.0.0/16", &[("env", "prod"), ("app", "billing")]),
        ]);
        assert_eq!(
            r.labels_for(ip("10.20.1.1")),
            map(&[("app", "billing"), ("env", "prod"), ("loc", "dc1")])
        );
        assert_eq!(r.labels_for(ip("10.30.1.1")), map(&[("env", "dev"), ("loc", "dc1")]));
        assert!(r.labels_for(ip("192.168.1.1")).is_empty());
        let types: Vec<_> = r.label_types().into_iter().collect();
        assert_eq!(types, ["app", "env", "loc"]);
        assert_eq!(r.rule_using("app"), Some(n("10.20.0.0/16")));
        assert_eq!(r.rule_using("env"), Some(n("10.0.0.0/8")));
        assert_eq!(r.rule_using("nope"), None);
    }

    #[test]
    fn labels_equal_prefix_first_listed_wins() {
        let r = LabelRules::new(&[
            rule("10.1.0.0/16", &[("env", "first")]),
            rule("10.1.0.0/16", &[("env", "second")]),
        ]);
        assert_eq!(r.labels_for(ip("10.1.2.3")), map(&[("env", "first")]));
    }
}
