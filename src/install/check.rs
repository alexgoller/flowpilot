//! The live PCE check: one authenticated request, so a typo in the address, the certificate setting or the key
//! shows before anything is installed.

use std::fmt;

use crate::install::answers::{Answers, Proxy};
use crate::stats::redact_userinfo;
use crate::uploader::PceTarget;
use crate::unmanaged::pce::{HttpPce, NetFailure, PceApi, PceError};

#[derive(Debug, PartialEq, Eq)]
pub enum CheckError {
    Resolve(String),
    Connect(String),
    Certificate(String),
    /// The HTTP status: 401 or 403.
    Auth(u16),
    /// The user or secret cannot be written to the `user secret` key file (it holds whitespace); found before any
    /// request.
    KeyFormat,
    Other(String),
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckError::Resolve(e) => write!(f, "The PCE address does not resolve; check the host name ({e})."),
            CheckError::Connect(e) => write!(f, "Cannot connect to the PCE; check the port and any firewall in between ({e})."),
            CheckError::Certificate(e) => write!(
                f,
                "The PCE certificate is not trusted; install its CA on this host or pass --no-verify-pce-cert ({e})."
            ),
            CheckError::Auth(code) => write!(f, "The PCE rejected the API key (HTTP {code}); check the user, the secret and the organization."),
            CheckError::KeyFormat => write!(f, "The API user and secret cannot contain spaces."),
            CheckError::Other(e) => write!(f, "The PCE check failed: {e}."),
        }
    }
}

/// `KeyFormat` when the user or secret holds whitespace: the key file is `user secret`, split at whitespace.
pub fn key_format(a: &Answers) -> Result<(), CheckError> {
    if a.api_user.contains(char::is_whitespace) || a.api_secret.0.contains(char::is_whitespace) {
        return Err(CheckError::KeyFormat);
    }
    Ok(())
}

/// The live check, through the proxy the answers write into the config and nothing else: the installed service does
/// not inherit this shell's `HTTPS_PROXY` or `ALL_PROXY`, so a check that used them could pass where the service fails.
pub fn check_pce(a: &Answers) -> Result<(), CheckError> {
    check_with(a, |t| HttpPce::with_proxy(t, service_proxy(&a.proxy)?))
}

/// The proxy the service uses for the PCE: the daemon sets `HTTPS_PROXY` from `proxy_config.https_proxy` (and
/// `NO_PROXY` from `no_proxy`) and the HTTP client reads them. A value without a scheme means `http://`, as there.
pub(crate) fn service_proxy(p: &Proxy) -> reqwest::Result<Option<reqwest::Proxy>> {
    if p.https.is_empty() {
        return Ok(None);
    }
    let url = if p.https.contains("://") { p.https.clone() } else { format!("http://{}", p.https) };
    let no_proxy = reqwest::NoProxy::from_string(&p.no_proxy);
    Ok(Some(reqwest::Proxy::https(url)?.no_proxy(no_proxy)))
}

/// `check_pce` with the client builder injectable; tests point it at a plain-http mock.
pub(crate) fn check_with(a: &Answers, build: impl FnOnce(&PceTarget) -> reqwest::Result<HttpPce>) -> Result<(), CheckError> {
    let target = PceTarget {
        pce_addr: a.pce_addr.clone(),
        org_id: a.org_id,
        api_user: a.api_user.clone(),
        api_token: a.api_secret.0.clone(),
        verify_cert: a.verify_pce_cert,
    };
    // An error text can name the proxy, user and password included.
    let r = |e: String| redact_userinfo(&e);
    let pce = build(&target).map_err(|e| CheckError::Other(r(e.to_string())))?;
    match pce.label_dimensions() {
        Ok(_) => Ok(()),
        Err(PceError::Auth(code)) => Err(CheckError::Auth(code)),
        Err(PceError::Unreachable(NetFailure::Resolve, e)) => Err(CheckError::Resolve(r(e))),
        Err(PceError::Unreachable(NetFailure::Connect, e)) => Err(CheckError::Connect(r(e))),
        Err(PceError::Unreachable(NetFailure::Certificate, e)) => Err(CheckError::Certificate(r(e))),
        Err(PceError::Transient(e) | PceError::Other(e)) => Err(CheckError::Other(r(e))),
        Err(PceError::Exists) => Err(CheckError::Other("unexpected reply".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Secret;
    use crate::install::args::{TextArgs};
    use crate::unmanaged::pce::HttpPce;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    fn answers(addr: &str) -> crate::install::answers::Answers {
        crate::install::answers::Answers {
            pce_addr: addr.into(),
            org_id: 1,
            api_user: "api_1".into(),
            api_secret: Secret("secret".into()),
            collectors: vec![],
            text: TextArgs::default(),
            unmanaged: None,
            verify_pce_cert: true,
            proxy: Default::default(),
        }
    }

    /// One-shot HTTP server answering a single request with `status` and `body`.
    fn serve(status: u16, body: &'static str) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            loop {
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            write!(s, "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        });
        addr
    }

    fn plain(a: &crate::install::answers::Answers) -> Result<(), CheckError> {
        check_with(a, |t| HttpPce::new(t).map(HttpPce::plain_http))
    }

    #[test]
    fn check_pce_ok_against_mock() {
        let addr = serve(200, r#"[{"key":"role"}]"#);
        assert_eq!(plain(&answers(&addr)), Ok(()));
    }

    #[test]
    fn check_pce_auth_error() {
        let addr = serve(401, "");
        assert_eq!(plain(&answers(&addr)), Err(CheckError::Auth(401)));
    }

    #[test]
    fn check_pce_connect_error() {
        let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
        assert!(matches!(plain(&answers(&dead)), Err(CheckError::Connect(_))));
    }

    #[test]
    fn check_pce_resolve_error() {
        assert!(matches!(check_pce(&answers("no-such-host.invalid:8443")), Err(CheckError::Resolve(_))));
    }

    /// Accepts one connection and returns its first line (a proxied https request starts with `CONNECT`).
    fn first_line() -> (String, std::thread::JoinHandle<String>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let h = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut line = String::new();
            BufReader::new(s).read_line(&mut line).unwrap();
            line
        });
        (addr, h)
    }

    #[test]
    fn check_goes_through_the_answered_proxy() {
        let (proxy, seen) = first_line();
        let mut a = answers("pce.example.com:8443");
        a.proxy.https = proxy;
        // The proxy closes the connection without an answer: the check fails, but it went there.
        assert!(check_pce(&a).is_err());
        assert!(seen.join().unwrap().starts_with("CONNECT pce.example.com:8443 "));
    }

    #[test]
    fn service_proxy_follows_the_answers() {
        assert!(service_proxy(&Proxy::default()).unwrap().is_none());
        let p = Proxy { https: "proxy.example.com:3128".into(), no_proxy: "localhost".into(), ..Default::default() };
        assert!(service_proxy(&p).unwrap().is_some());
        // `http_proxy` alone does not proxy HTTPS for the daemon either.
        let http_only = Proxy { http: "http://proxy.example.com:3128".into(), ..Default::default() };
        assert!(service_proxy(&http_only).unwrap().is_none());
    }

    #[test]
    fn errors_read_as_one_sentence() {
        assert!(CheckError::Auth(403).to_string().contains("403"));
        assert!(CheckError::Certificate("x".into()).to_string().contains("--no-verify-pce-cert"));
    }
}
