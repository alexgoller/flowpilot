//! Reverse DNS for unmanaged workload hostnames: bounded concurrency, bounded time.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::Resolver;

use super::config::DnsConfig;

pub trait ReverseDns: Send + Sync + 'static {
    fn lookup(&self, ip: IpAddr) -> Option<String>;
}

/// The system resolver (`getnameinfo` with `NI_NAMEREQD`: no answer means no name, never the IP literal).
pub struct SystemDns;

impl ReverseDns for SystemDns {
    fn lookup(&self, ip: IpAddr) -> Option<String> {
        let IpAddr::V4(v4) = ip else { return None };
        // Host buffer is NI_MAXHOST (1025) bytes, the largest name getnameinfo can return.
        // SAFETY: sockaddr_in is plain data, zeroed is a valid starting value; getnameinfo only reads `sa`
        // and writes at most `host.len()` bytes into `host`.
        unsafe {
            let mut sa: libc::sockaddr_in = std::mem::zeroed();
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            {
                sa.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
            }
            let mut host = [0 as libc::c_char; 1025];
            let rc = libc::getnameinfo(
                &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                host.as_mut_ptr(),
                host.len() as libc::socklen_t,
                std::ptr::null_mut(),
                0,
                libc::NI_NAMEREQD,
            );
            if rc != 0 {
                return None;
            }
            Some(std::ffi::CStr::from_ptr(host.as_ptr()).to_string_lossy().into_owned())
        }
    }
}

/// Explicit DNS servers, queried over UDP with TCP fallback. hickory's sync `Resolver` serialises lookups behind
/// one runtime mutex, so each lookup builds its own; hickory's timeout (attempts = 1) then bounds every lookup.
pub struct ServerDns {
    config: ResolverConfig,
    opts: ResolverOpts,
}

impl ServerDns {
    pub fn new(servers: &[IpAddr], timeout: Duration) -> io::Result<Self> {
        Ok(Self::with_port(servers, 53, timeout))
    }

    fn with_port(servers: &[IpAddr], port: u16, timeout: Duration) -> Self {
        let group = NameServerConfigGroup::from_ips_clear(servers, port, true);
        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = 1;
        opts.cache_size = 0;
        Self { config: ResolverConfig::from_parts(None, vec![], group), opts }
    }
}

impl ReverseDns for ServerDns {
    fn lookup(&self, ip: IpAddr) -> Option<String> {
        let resolver = Resolver::new(self.config.clone(), self.opts.clone()).ok()?;
        let answer = resolver.reverse_lookup(ip).ok()?;
        answer.iter().next().map(|n| n.to_utf8())
    }
}

/// None when DNS is disabled; no configured servers means the system resolver.
pub fn from_config(cfg: &DnsConfig) -> Option<Arc<dyn ReverseDns>> {
    if !cfg.enabled {
        return None;
    }
    if cfg.servers.is_empty() {
        return Some(Arc::new(SystemDns));
    }
    match ServerDns::new(&cfg.servers, Duration::from_millis(cfg.timeout_ms)) {
        Ok(d) => Some(Arc::new(d)),
        Err(e) => {
            crate::log_line!("Unmanaged workloads: DNS resolver setup failed:", e, "- using the system resolver");
            Some(Arc::new(SystemDns))
        }
    }
}

/// Drops the trailing root dot and rejects empty names and IP literals (a resolver echoing the address back).
pub fn clean_hostname(ip: IpAddr, name: &str) -> Option<String> {
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() || name.parse::<IpAddr>().is_ok() || name == ip.to_string() {
        return None;
    }
    Some(name.to_string())
}

/// Resolves `ips` with `concurrency` workers; each lookup gets at most `timeout`. A hung lookup is abandoned
/// (its thread is left to finish on its own), so this returns in bounded time. Only resolved IPs are returned.
pub fn resolve_all(
    dns: &Arc<dyn ReverseDns>,
    ips: &[IpAddr],
    concurrency: usize,
    timeout: Duration,
) -> HashMap<IpAddr, String> {
    let (work_tx, work_rx) = crossbeam_channel::unbounded::<IpAddr>();
    let (out_tx, out_rx) = crossbeam_channel::unbounded::<(IpAddr, String)>();
    for ip in ips {
        let _ = work_tx.send(*ip);
    }
    drop(work_tx);
    let workers = concurrency.clamp(1, ips.len().max(1));
    let handles: Vec<_> = (0..workers)
        .map(|_| {
            let (work_rx, out_tx, dns) = (work_rx.clone(), out_tx.clone(), dns.clone());
            std::thread::spawn(move || {
                while let Ok(ip) = work_rx.recv() {
                    let (tx, rx) = crossbeam_channel::bounded(1);
                    let d = dns.clone();
                    std::thread::spawn(move || {
                        let _ = tx.send(d.lookup(ip));
                    });
                    if let Ok(Some(name)) = rx.recv_timeout(timeout) {
                        if let Some(h) = clean_hostname(ip, &name) {
                            let _ = out_tx.send((ip, h));
                        }
                    }
                }
            })
        })
        .collect();
    drop(out_tx);
    for h in handles {
        let _ = h.join();
    }
    out_rx.try_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn clean_hostname_strips_trailing_dot() {
        assert_eq!(clean_hostname(ip("10.1.2.3"), "web1.corp."), Some("web1.corp".into()));
    }

    #[test]
    fn clean_hostname_rejects_ip_literal_and_empty() {
        assert_eq!(clean_hostname(ip("10.1.2.3"), "10.1.2.3"), None);
        assert_eq!(clean_hostname(ip("10.1.2.3"), ""), None);
        assert_eq!(clean_hostname(ip("10.1.2.3"), "."), None);
    }

    struct Slow;
    impl ReverseDns for Slow {
        fn lookup(&self, ip: IpAddr) -> Option<String> {
            if ip == "10.0.0.1".parse::<IpAddr>().unwrap() {
                std::thread::sleep(Duration::from_secs(10));
                Some("never.corp".into())
            } else {
                Some("a.corp.".into())
            }
        }
    }

    #[test]
    fn resolve_all_bounds_time() {
        let dns: Arc<dyn ReverseDns> = Arc::new(Slow);
        let start = Instant::now();
        let out = resolve_all(&dns, &[ip("10.0.0.1"), ip("10.0.0.2")], 2, Duration::from_millis(200));
        assert!(start.elapsed() < Duration::from_secs(1), "took {:?}", start.elapsed());
        assert_eq!(out, HashMap::from([(ip("10.0.0.2"), "a.corp".to_string())]));
    }

    #[derive(Default)]
    struct Counting {
        cur: AtomicUsize,
        peak: AtomicUsize,
    }
    impl ReverseDns for Counting {
        fn lookup(&self, _ip: IpAddr) -> Option<String> {
            let now = self.cur.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(20));
            self.cur.fetch_sub(1, Ordering::SeqCst);
            Some("h.corp".into())
        }
    }

    #[test]
    fn resolve_all_respects_concurrency() {
        let c = Arc::new(Counting::default());
        let dns: Arc<dyn ReverseDns> = c.clone();
        let ips: Vec<IpAddr> = (1..=20).map(|i| ip(&format!("10.0.0.{i}"))).collect();
        let out = resolve_all(&dns, &ips, 3, Duration::from_secs(1));
        assert_eq!(out.len(), 20);
        let peak = c.peak.load(Ordering::SeqCst);
        assert!((1..=3).contains(&peak), "peak {peak}");
    }

    #[test]
    fn from_config_disabled_is_none_and_empty_servers_is_some() {
        let off = DnsConfig { enabled: false, ..DnsConfig::default() };
        assert!(from_config(&off).is_none());
        assert!(from_config(&DnsConfig::default()).is_some());
    }

    #[test]
    fn server_dns_lookups_do_not_serialise() {
        // A socket that is bound but never answers: every lookup runs into hickory's own 300 ms timeout.
        let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = blackhole.local_addr().unwrap().port();
        let dns: Arc<dyn ReverseDns> =
            Arc::new(ServerDns::with_port(&[ip("127.0.0.1")], port, Duration::from_millis(300)));
        let ips: Vec<IpAddr> = (1..=4).map(|i| ip(&format!("10.0.0.{i}"))).collect();
        let start = Instant::now();
        // The resolve_all timeout is generous so only hickory's timeout ends a lookup.
        let out = resolve_all(&dns, &ips, 4, Duration::from_secs(5));
        assert!(out.is_empty());
        // Serialised lookups would need 4 x 300 ms = 1.2 s or more.
        assert!(start.elapsed() < Duration::from_millis(1000), "took {:?}", start.elapsed());
    }

    #[test]
    #[ignore]
    fn system_dns_localhost() {
        assert!(SystemDns.lookup(ip("127.0.0.1")).is_some());
    }
}
