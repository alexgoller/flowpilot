//! The installer's PCE check ignores this shell's proxy variables, as the installed service does (systemd does not
//! pass them on). A test binary of its own: it sets process-wide variables, which would race with other tests.

use std::net::TcpListener;
use std::time::{Duration, Instant};

use flowpilot::config::Secret;
use flowpilot::install::answers::{Answers, Proxy};
use flowpilot::install::args::TextArgs;
use flowpilot::install::check::{check_pce, CheckError};

/// True when `l` gets a connection within `wait`.
fn connected(l: &TcpListener, wait: Duration) -> bool {
    l.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        if l.accept().is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn check_ignores_proxy_variables_of_the_shell() {
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", proxy.local_addr().unwrap());
    for k in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy"] {
        std::env::set_var(k, &url);
    }
    std::env::remove_var("NO_PROXY");
    std::env::remove_var("no_proxy");
    let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
    let a = Answers {
        pce_addr: dead,
        org_id: 1,
        api_user: "api_1".into(),
        api_secret: Secret("secret".into()),
        collectors: vec![],
        text: TextArgs::default(),
        unmanaged: None,
        verify_pce_cert: true,
        proxy: Proxy::default(),
    };
    let r = check_pce(&a);
    assert!(matches!(r, Err(CheckError::Connect(_))), "{r:?}");
    assert!(!connected(&proxy, Duration::from_millis(300)), "the check went through the shell's proxy");
}
