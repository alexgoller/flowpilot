//! Data-source connectors. Only UDP is implemented;
//! `tcp`, `kafka` and `aws` are deferred and rejected like an unknown connector type.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use crate::config::Properties;
use crate::log::{check_error, go_slice, debug_hex, shutdown};
use crate::parsers::{Parser, ReceivedDatagram};
use crate::stats::{CollectorStats, ThreadGuard};
use crate::{debug_log, log_line};

const READ_BUFFER: usize = 256_000;
const MAX_DATAGRAM: usize = 65_536;

/// Starts one connector of `conn_type` for `parser`; false when it cannot be started.
pub fn start_connector(parser: Arc<dyn Parser>, conn_type: &str, properties: &Properties) -> bool {
    if !parser.supports_connector(conn_type) {
        log_line!("Parser", parser.type_name(), "does not support connector", conn_type);
        return false;
    }
    if conn_type != "udp" {
        // Deliberate divergence: FlowLink starts tcp/kafka/aws here (deferred scope).
        log_line!("Unsupported connector:", conn_type);
        return false;
    }

    let mut ports: Vec<u16> = Vec::new();
    let mut allowed: Vec<String> = Vec::new();
    let mut valid = true;
    for (key, value) in properties {
        match key.as_str() {
            "ports" => {
                for part in value.split(',') {
                    match parse_go_uint16(part.trim()) {
                        Some(p) => ports.push(p),
                        None => {
                            log_line!("Invalid port", part, "specified in 'port' property:", value);
                            valid = false;
                        }
                    }
                }
            }
            "remote_addrs" => {
                for part in value.split(',') {
                    let a = part.trim();
                    if a.parse::<IpAddr>().is_err() || a.contains('/') {
                        log_line!("Invalid remote IP address:", a, "for", conn_type, "connector.");
                        valid = false;
                        continue;
                    }
                    if !allowed.iter().any(|x| x == a) {
                        allowed.push(a.to_string());
                    }
                }
            }
            _ => log_line!("Unsupported", conn_type, "connector property:", key),
        }
    }
    if !valid {
        log_line!("Parser", parser.type_name(), conn_type, "connector not starting.");
        return false;
    }
    if ports.is_empty() {
        ports.push(parser.default_port());
    }

    let allowed: Arc<HashSet<String>> = Arc::new(allowed.iter().cloned().collect());
    let dropped: Arc<Mutex<HashSet<String>>> = Arc::default();
    let n = thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    for port in ports {
        let mut msg = format!("Listening for {} messages on {} port: {}", parser.type_name(), conn_type, port);
        if !allowed.is_empty() {
            let mut keys: Vec<&String> = allowed.iter().collect();
            keys.sort();
            msg += &format!(" from remote addresses: {}", go_slice(&keys));
        }
        log_line!(msg);

        let sock = match bind_udp(port) {
            Ok(s) => s,
            Err(e) => {
                check_error(Some(format!("listen udp :{port}: bind: {}", go_errno(&e))));
                return false;
            }
        };
        let ch = parser.clone().start_workers(2 * n);
        for _ in 0..2 * n {
            let sock = match sock.try_clone() {
                Ok(s) => s,
                Err(e) => {
                    check_error(Some(e));
                    return false;
                }
            };
            let (ch, allowed, dropped, stats) = (ch.clone(), allowed.clone(), dropped.clone(), parser.stats());
            thread::spawn(move || {
                let _guard = ThreadGuard::core("udp reader");
                read_udp(sock, ch, allowed, dropped, stats)
            });
        }
    }
    true
}

/// Go `strconv.ParseUint(s, 10, 16)`: plain decimal digits only.
fn parse_go_uint16(s: &str) -> Option<u16> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Go `net.ListenUDP("udp", ":port")`: dual-stack wildcard, falling back to IPv4.
fn bind_udp(port: u16) -> io::Result<UdpSocket> {
    let v6 = || -> io::Result<Socket> {
        let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        s.set_only_v6(false)?;
        s.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).into())?;
        Ok(s)
    };
    let s = match v6() {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => return Err(e),
        Err(_) => {
            let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            s.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port).into())?;
            s
        }
    };
    if let Err(e) = s.set_recv_buffer_size(READ_BUFFER) {
        check_error(Some(e));
    }
    // Poll shutdown once a second (FlowLink only notices quit after the next datagram).
    s.set_read_timeout(Some(Duration::from_secs(1)))?;
    Ok(s.into())
}

/// Go's lower-case errno text for the common bind errors.
fn go_errno(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(libc::EADDRINUSE) => "address already in use".into(),
        Some(libc::EACCES) => "permission denied".into(),
        Some(libc::EADDRNOTAVAIL) => "cannot assign requested address".into(),
        _ => {
            let s = e.to_string();
            s.split(" (os error").next().unwrap_or(&s).to_lowercase()
        }
    }
}

/// Go `IP.String()` of the sender: IPv4-mapped addresses as dotted quads.
fn peer_host(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(a) => a.ip().to_string(),
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None if a.scope_id() != 0 => format!("{}%{}", a.ip(), a.scope_id()),
            None => a.ip().to_string(),
        },
    }
}

/// One of `2*NumCPU` readers on the shared socket. Datagrams from senders not
/// in `remote_addrs` are counted in the parser's stats.
fn read_udp(
    sock: UdpSocket,
    ch: crossbeam_channel::Sender<ReceivedDatagram>,
    allowed: Arc<HashSet<String>>,
    dropped: Arc<Mutex<HashSet<String>>>,
    stats: Arc<CollectorStats>,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        if shutdown() {
            log_line!("udp exiting");
            return;
        }
        let (n, raddr) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => continue,
            Err(_) => {
                log_line!("Error receiving from UDP socket");
                continue;
            }
        };
        let host = peer_host(&raddr);
        if !allowed.is_empty() && !allowed.contains(&host) {
            if dropped.lock().unwrap().insert(host.clone()) {
                log_line!("Dropping unwanted UDP flows from", host);
            }
            stats.rejected(&host);
            continue;
        }
        debug_log!("Received", n, "bytes from remote UDP address", host);
        if n > 0 {
            debug_hex("", &buf[..n]);
            let pd = ReceivedDatagram { device_addr: host, seq_id: String::new(), transport: "udp".into(), buf: buf[..n].to_vec() };
            if ch.send(pd).is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_parsing_is_decimal_only() {
        assert_eq!(parse_go_uint16("6514"), Some(6514));
        assert_eq!(parse_go_uint16("0"), Some(0));
        assert_eq!(parse_go_uint16("65536"), None);
        assert_eq!(parse_go_uint16("+1"), None);
        assert_eq!(parse_go_uint16("1000-1010"), None);
        assert_eq!(parse_go_uint16(""), None);
    }

    #[test]
    fn peer_host_unmaps_ipv4() {
        let a: SocketAddr = "[::ffff:10.1.2.3]:5000".parse().unwrap();
        assert_eq!(peer_host(&a), "10.1.2.3");
        let b: SocketAddr = "[2001:db8::1]:5000".parse().unwrap();
        assert_eq!(peer_host(&b), "2001:db8::1");
    }
}
