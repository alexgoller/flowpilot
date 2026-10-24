//! Waiting for the service to come up: polls FlowPilot's own `GET /healthz` on the local stats endpoint.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

/// How long an install waits for the service to report healthy.
pub const HEALTH_TIMEOUT: Duration = Duration::from_secs(60);

/// Polls `http://<listen>/healthz` until it answers 200 (any status counts, `no_flows` included: exporters are
/// pointed at the host after the install) and returns the status. A refused connection, `busy` or `unhealthy`
/// is retried until `timeout`; then the last reason is the error.
pub fn wait_healthy(listen: &str, timeout: Duration) -> Result<String, String> {
    let addr: SocketAddr = listen.parse().map_err(|_| format!("stats.http_listen is not an ip:port address: {listen}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        let why = match probe(addr) {
            Ok(status) => return Ok(status),
            Err(why) => why,
        };
        if Instant::now() + POLL >= deadline {
            return Err(why);
        }
        thread::sleep(POLL);
    }
}

const POLL: Duration = Duration::from_millis(500);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// One `GET <path>` on the local stats endpoint: the HTTP status code and the body.
pub(crate) fn get(addr: SocketAddr, path: &str) -> Result<(u16, String), String> {
    let mut s = TcpStream::connect_timeout(&addr, REQUEST_TIMEOUT).map_err(|e| format!("{addr}: {e}"))?;
    s.set_read_timeout(Some(REQUEST_TIMEOUT)).and_then(|_| s.set_write_timeout(Some(REQUEST_TIMEOUT))).map_err(|e| e.to_string())?;
    write!(s, "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").map_err(|e| format!("{addr}: {e}"))?;
    let mut reply = Vec::new();
    s.read_to_end(&mut reply).map_err(|e| format!("{addr}: {e}"))?;
    let reply = String::from_utf8_lossy(&reply);
    let (head, body) = reply.split_once("\r\n\r\n").unwrap_or((&reply, ""));
    let code = head.split(' ').nth(1).and_then(|c| c.parse().ok()).ok_or_else(|| format!("{addr}: not an HTTP answer"))?;
    Ok((code, body.to_string()))
}

/// One `GET /healthz`: the status of a 200, else why not (yet).
fn probe(addr: SocketAddr) -> Result<String, String> {
    let (code, body) = get(addr, "/healthz")?;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let field = |k: &str| json.get(k).and_then(|v| v.as_str()).map(str::to_string);
    match (code, field("status")) {
        (200, status) => Ok(status.unwrap_or_else(|| "ok".into())),
        (_, Some(status)) => Err(match field("reason") {
            Some(reason) => format!("{status}: {reason}"),
            None => status,
        }),
        (code, None) => Err(format!("/healthz answered HTTP {code}")),
    }
}

/// Answers one request per entry of `replies`, in order, then stops listening.
#[cfg(test)]
pub(crate) fn serve(replies: Vec<(u16, &'static str)>) -> String {
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for (status, body) in replies {
            let (mut s, _) = l.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            while r.read_line(&mut line).is_ok_and(|n| n > 0) && line != "\r\n" {
                line.clear();
            }
            let _ = write!(s, "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
    });
    addr
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::time::Instant;

    #[test]
    fn wait_healthy_accepts_no_flows() {
        let addr = serve(vec![(200, r#"{"status":"no_flows"}"#)]);
        assert_eq!(wait_healthy(&addr, Duration::from_secs(10)), Ok("no_flows".into()));
    }

    #[test]
    fn wait_healthy_retries_busy() {
        let addr = serve(vec![(503, r#"{"status":"busy"}"#), (200, r#"{"status":"ok"}"#)]);
        assert_eq!(wait_healthy(&addr, Duration::from_secs(10)), Ok("ok".into()));
    }

    #[test]
    fn wait_healthy_gives_up_with_last_reason() {
        let addr = serve(vec![(503, r#"{"status":"unhealthy","reason":"aggregator stalled"}"#); 50]);
        let started = Instant::now();
        let e = wait_healthy(&addr, Duration::from_millis(1500)).unwrap_err();
        assert!(e.contains("aggregator stalled"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(5));

        let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
        assert!(wait_healthy(&dead, Duration::from_millis(600)).is_err());
    }
}
