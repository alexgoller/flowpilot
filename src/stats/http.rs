//! The stats HTTP endpoint (docs/stats.md, "HTTP endpoint"):
//! `GET /healthz`, `/stats` and `/metrics`, read-only. One accept thread and a thread per connection, at most
//! `MAX_CONNECTIONS` at once, each closed `REQUEST_TIMEOUT` after it was accepted at the latest (reading and writing
//! together): a slow, silent or trickling client holds only its own thread and only for that long, and a snapshot is
//! built before anything is written, so no lock the collectors take is held while a client reads.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use super::snapshot::{current_status, snapshot};
use super::{prometheus, SnapshotContext};

/// Connections served at once; more are answered `503` and closed.
pub const MAX_CONNECTIONS: usize = 8;
/// Time from accepting a connection to closing it at the latest, reading the request and writing the answer included.
/// An absolute bound, not one per read: a client trickling a byte every few seconds must not keep a slot.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest request head (request line and headers) read.
pub const MAX_HEAD: usize = 8 * 1024;

/// The health check `/healthz` asks: `Err(reason)` when a core thread has died or stalled.
pub type HealthCheck = Arc<dyn Fn(SystemTime) -> Result<(), String> + Send + Sync>;

/// A bound endpoint, not yet serving: binding is separate so that main can stop the start on a bad address before any
/// collector runs, and serve once the stats context exists.
pub struct Endpoint(TcpListener);

/// Bind `addr`, a literal `ip:port` (host names are not resolved).
pub fn bind(addr: &str) -> io::Result<Endpoint> {
    let addr: SocketAddr = addr
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not an ip:port address"))?;
    TcpListener::bind(addr).map(Endpoint)
}

impl Endpoint {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    /// Serve on a thread, `/healthz` asking `stats::health`.
    pub fn start(self, ctx: Arc<SnapshotContext>) -> io::Result<()> {
        let minutes = ctx.aggregation_minutes;
        self.start_with(ctx, Arc::new(move |now| super::health(now, minutes)))
    }

    fn start_with(self, ctx: Arc<SnapshotContext>, health: HealthCheck) -> io::Result<()> {
        let listener = self.0;
        let active = Arc::new(AtomicUsize::new(0));
        thread::Builder::new().name("stats http".into()).spawn(move || {
            for conn in listener.incoming() {
                let accepted = Instant::now();
                let Ok(stream) = conn else {
                    // Out of descriptors and the like: do not spin.
                    thread::sleep(Duration::from_millis(100));
                    continue;
                };
                // Only this thread adds, so the check cannot race.
                if active.load(SeqCst) >= MAX_CONNECTIONS {
                    refuse(stream);
                    continue;
                }
                active.fetch_add(1, SeqCst);
                let slot = Slot(active.clone());
                let (ctx, health) = (ctx.clone(), health.clone());
                // A failed spawn drops the closure, and with it the slot.
                let _ = thread::Builder::new().name("stats http conn".into()).spawn(move || {
                    let _slot = slot;
                    handle(stream, accepted + REQUEST_TIMEOUT, &ctx, &health);
                });
            }
        })?;
        Ok(())
    }
}

/// Bind `addr` (errors surface here) and serve on a thread.
pub fn serve(addr: &str, ctx: Arc<SnapshotContext>) -> io::Result<()> {
    bind(addr)?.start(ctx)
}

/// One of the `MAX_CONNECTIONS`, given back on drop.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, SeqCst);
    }
}

/// Answer `503` `{"status":"busy"}` without blocking the accept thread: all slots are taken, which says nothing about
/// the collector's health (an unhealthy `/healthz` answers `{"status":"unhealthy","reason":...}`).
fn refuse(mut s: TcpStream) {
    if s.set_nonblocking(true).is_err() {
        return;
    }
    let _ = s.write_all(&response(503, "application/json", r#"{"status":"busy"}"#, ""));
    // Read what has arrived, so that closing does not reset the connection before the client reads the answer.
    let _ = s.read(&mut [0; MAX_HEAD]);
    let _ = s.shutdown(Shutdown::Write);
}

/// Serve one connection; give up at `deadline`.
fn handle(mut s: TcpStream, deadline: Instant, ctx: &SnapshotContext, health: &HealthCheck) {
    let out = match read_head(&mut s, deadline) {
        Head::Complete(head) => route(&head, ctx, health),
        Head::TooLarge => response(431, "text/plain", "request head too large\n", ""),
        Head::Closed => return, // closed, timed out or failed: nobody to answer
    };
    if write_by(&mut s, &out, deadline).is_ok() {
        let _ = s.shutdown(Shutdown::Write);
    }
}

/// The time left until `deadline`, `None` once it has passed (a zero timeout is an error for the socket calls).
fn remaining(deadline: Instant) -> Option<Duration> {
    deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
}

/// `write_all`, each write bounded by the time left until `deadline`.
fn write_by(s: &mut TcpStream, mut buf: &[u8], deadline: Instant) -> io::Result<()> {
    while !buf.is_empty() {
        let left = remaining(deadline).ok_or(io::ErrorKind::TimedOut)?;
        s.set_write_timeout(Some(left))?;
        match s.write(buf) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

enum Head {
    Complete(String),
    TooLarge,
    Closed,
}

/// Read up to the blank line that ends the request head, by `deadline`.
fn read_head(s: &mut TcpStream, deadline: Instant) -> Head {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0; 1024];
    loop {
        let Some(left) = remaining(deadline) else { return Head::Closed };
        if s.set_read_timeout(Some(left)).is_err() {
            return Head::Closed;
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return Head::Closed,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        let end = buf.windows(4).position(|w| w == b"\r\n\r\n").or_else(|| buf.windows(2).position(|w| w == b"\n\n"));
        match end {
            Some(i) if i <= MAX_HEAD => return Head::Complete(String::from_utf8_lossy(&buf[..i]).into_owned()),
            _ if buf.len() > MAX_HEAD => return Head::TooLarge,
            _ => {}
        }
    }
}

/// The response to a complete request head.
fn route(head: &str, ctx: &SnapshotContext, health: &HealthCheck) -> Vec<u8> {
    const JSON: &str = "application/json";
    let mut words = head.lines().next().unwrap_or("").split_whitespace();
    let (Some(method), Some(target), Some(version), None) = (words.next(), words.next(), words.next(), words.next())
    else {
        return response(400, "text/plain", "bad request\n", "");
    };
    if !version.starts_with("HTTP/") {
        return response(400, "text/plain", "bad request\n", "");
    }
    if method != "GET" {
        return response(405, "text/plain", "method not allowed\n", "Allow: GET\r\n");
    }
    let now = SystemTime::now();
    match target.split('?').next().unwrap_or("") {
        "/healthz" => match health(now) {
            Ok(()) => response(200, JSON, &serde_json::json!({"status": current_status(ctx, now)}).to_string(), ""),
            Err(reason) => {
                response(503, JSON, &serde_json::json!({"status": "unhealthy", "reason": reason}).to_string(), "")
            }
        },
        "/stats" => match serde_json::to_string(&snapshot(ctx, now, None)) {
            Ok(body) => response(200, JSON, &body, ""),
            Err(e) => response(500, "text/plain", &format!("{e}\n"), ""),
        },
        "/metrics" => {
            let body = prometheus::render(&snapshot(ctx, now, None));
            response(200, "text/plain; version=0.0.4; charset=utf-8", &body, "")
        }
        _ => response(404, "text/plain", "not found\n", ""),
    }
}

/// A complete `Connection: close` response; `extra` is further header lines, each ending in CRLF.
fn response(code: u16, content_type: &str, body: &str, extra: &str) -> Vec<u8> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        _ => "Service Unavailable",
    };
    let len = body.len();
    let mut out = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {len}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n{extra}\r\n"
    )
    .into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::snapshot::tests::context;
    use crate::stats::{CollectorStats, Proto, StatsConfig};
    use std::time::Instant;

    /// An endpoint on a free port over one `netflow` collector; `health` answers `/healthz`.
    fn start(health: Result<(), String>) -> (SocketAddr, tempfile::TempDir) {
        let c = Arc::new(CollectorStats::new("netflow", "netflow"));
        // The handlers read the real clock: started an hour ago, a flow just now.
        let now = SystemTime::now();
        c.datagram_at("192.0.2.10", Some(Proto::NetflowV9), 1400, 30, 0, now);
        let (mut ctx, _, dir) = context(vec![c], StatsConfig::default());
        ctx.started_at = now - Duration::from_secs(3600);
        let ep = bind("127.0.0.1:0").unwrap();
        let addr = ep.local_addr().unwrap();
        ep.start_with(Arc::new(ctx), Arc::new(move |_| health.clone())).unwrap();
        (addr, dir)
    }

    /// Send `request`, return (status code, head, body).
    fn send(addr: SocketAddr, request: &str) -> (u16, String, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(request.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        let (head, body) = out.split_once("\r\n\r\n").unwrap();
        let code = head.split(' ').nth(1).unwrap().parse().unwrap();
        (code, head.to_string(), body.to_string())
    }

    fn get(addr: SocketAddr, path: &str) -> (u16, String, String) {
        send(addr, &format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n"))
    }

    #[test]
    fn healthz_ok() {
        let (addr, _dir) = start(Ok(()));
        let (code, head, body) = get(addr, "/healthz");
        assert_eq!(code, 200);
        assert!(head.contains("Content-Type: application/json"), "{head}");
        assert!(head.contains("Connection: close"), "{head}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v, serde_json::json!({"status": "ok"}));
    }

    #[test]
    fn healthz_unhealthy() {
        let (addr, _dir) = start(Err("core thread ended: aggregator".into()));
        let (code, _, body) = get(addr, "/healthz");
        assert_eq!(code, 503);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v, serde_json::json!({"status": "unhealthy", "reason": "core thread ended: aggregator"}));
    }

    #[test]
    fn stats_json_parses() {
        let (addr, _dir) = start(Ok(()));
        let (code, head, body) = get(addr, "/stats?pretty");
        assert_eq!(code, 200);
        assert!(head.contains("Content-Type: application/json"), "{head}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["schema"], "flowpilot.stats/v1");
        assert_eq!(v["collectors"][0]["exporters"][0]["address"], "192.0.2.10");
    }

    #[test]
    fn metrics_has_counters() {
        let (addr, _dir) = start(Ok(()));
        let (code, head, body) = get(addr, "/metrics");
        assert_eq!(code, 200);
        assert!(head.contains("Content-Type: text/plain; version=0.0.4"), "{head}");
        assert!(body.contains("flowpilot_flows_decoded_total{collector=\"netflow\"} 30"), "{body}");
    }

    #[test]
    fn unknown_path_404() {
        let (addr, _dir) = start(Ok(()));
        assert_eq!(get(addr, "/nope").0, 404);
        assert_eq!(get(addr, "/").0, 404);
    }

    #[test]
    fn post_405() {
        let (addr, _dir) = start(Ok(()));
        let (code, head, _) = send(addr, "POST /stats HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(code, 405);
        assert!(head.contains("Allow: GET"), "{head}");
    }

    #[test]
    fn oversized_head_431() {
        let (addr, _dir) = start(Ok(()));
        let big = format!("GET /stats HTTP/1.1\r\nX-Pad: {}\r\n\r\n", "a".repeat(9000));
        assert_eq!(send(addr, &big).0, 431);
        assert_eq!(send(addr, "garbage\r\n\r\n").0, 400);
    }

    #[test]
    fn silent_client_does_not_block() {
        let (addr, _dir) = start(Ok(()));
        let silent: Vec<TcpStream> = (0..MAX_CONNECTIONS).map(|_| TcpStream::connect(addr).unwrap()).collect();
        // The ninth is refused at once.
        let t = Instant::now();
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("HTTP/1.1 503 "), "{out}");
        assert!(out.ends_with(r#"{"status":"busy"}"#), "{out}");
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        // After the request timeout the silent connections are closed and requests are served again.
        std::thread::sleep(REQUEST_TIMEOUT + Duration::from_millis(500));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(b"GET /healthz HTTP/1.1\r\n\r\n").unwrap();
            let mut out = String::new();
            let _ = s.read_to_string(&mut out);
            if out.starts_with("HTTP/1.1 200 ") {
                break;
            }
            assert!(Instant::now() < deadline, "still refused: {out}");
            std::thread::sleep(Duration::from_millis(100));
        }
        drop(silent);
    }

    #[test]
    fn trickling_clients_cut_off_at_deadline() {
        let (addr, _dir) = start(Ok(()));
        // Fill every slot with a client sending one byte a second, never finishing its head.
        let t = Instant::now();
        let trickle: Vec<_> = (0..MAX_CONNECTIONS)
            .map(|_| {
                let mut s = TcpStream::connect(addr).unwrap();
                std::thread::spawn(move || {
                    let start = Instant::now();
                    // Instead of sleeping between bytes, wait a second for the server to close the connection.
                    s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                    for b in b"GET /healthz HTTP/1.1\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
                        if s.write_all(&[*b]).is_err() {
                            break;
                        }
                        match s.read(&mut [0; 64]) {
                            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
                            _ => break, // closed (0 bytes or a reset)
                        }
                    }
                    start.elapsed()
                })
            })
            .collect();
        for h in trickle {
            let closed_after = h.join().unwrap();
            assert!(closed_after < REQUEST_TIMEOUT + Duration::from_secs(2), "held for {closed_after:?}");
        }
        assert!(t.elapsed() < REQUEST_TIMEOUT + Duration::from_secs(3), "{:?}", t.elapsed());
        // The slots are free again: a probe is served.
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let (code, _, body) = get(addr, "/healthz");
            if code == 200 {
                break;
            }
            assert!(Instant::now() < deadline, "still refused: {body}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[test]
    fn bad_listen_address_errors() {
        assert!(bind("not-an-address").is_err());
        assert!(bind("localhost:9180").is_err(), "host names are not resolved");
        // A port in use.
        let taken = TcpListener::bind("127.0.0.1:0").unwrap();
        let err = bind(&taken.local_addr().unwrap().to_string()).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        let (ctx, _, _dir) = context(Vec::new(), StatsConfig::default());
        assert!(serve("not-an-address", Arc::new(ctx)).is_err());
    }
}
