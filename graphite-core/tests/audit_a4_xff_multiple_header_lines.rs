//! A4-02 (2026-09-29 audit, with `GRAPHITE_TRUST_PROXY`): a second
//! `X-Forwarded-For` line cannot choose the rate-limit bucket.
//!
//! `server::client_ip` read `X-Forwarded-For` with `HeaderMap::get`, which
//! returns only the first field line. HTTP (RFC 9110 §5.3) defines several
//! field lines of one name as one comma-joined list in order, and a proxy
//! that adds its own line rather than rewriting the client's (HAProxy's
//! `option forwardfor`) leaves the client's chosen line first and the observed
//! address on a second line. With `GRAPHITE_TRUST_PROXY=1` the server took the
//! rightmost entry of the first line, the client's own, so the client picked
//! its bucket on every request and the per-IP limiter, which runs before auth
//! on every route, was a no-op: the 2026-09-05 leftmost-XFF HIGH, back through
//! a second header line.
//!
//! The fix: `client_ip` joins every header line with `get_all`, in order,
//! before counting hops from the right; a line that is not text makes the
//! chain untrusted and the peer address is used. Entries of the form
//! `ip:port` and `[v6]:port` parse to their client.
//!
//! The control pins that the limiter refuses the same client's second request
//! on the proxy's line alone; the test pins that five requests the trusted
//! proxy attributes to one client share one bucket however the client varies
//! its own line. The server runs in-process on loopback in dev mode, and this
//! file is its own test binary, so the process-wide environment it sets is its
//! own.
#![cfg(feature = "server")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

fn start_server(extra_env: &[(&str, &str)]) -> SocketAddr {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "graphite-a4-xff-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for k in [
        "GRAPHITE_API_KEY",
        "GRAPHITE_ADMIN_API_KEY",
        "GRAPHITE_RPC_URL",
        "GRAPHITE_RPC_WITNESS_URL",
        "GRAPHITE_PLUGINS_DIR",
        "GRAPHITE_PLUGIN_EVENTS_FILE",
        "GRAPHITE_WALLET_PROFILE",
        "GRAPHITE_ALLOW_PERMISSIVE_PROFILES",
        "GRAPHITE_TRUST_PROXY",
        "GRAPHITE_RATE_LIMIT",
        "GRAPHITE_AUDIT_ROTATE_BYTES",
        "GRAPHITE_AUDIT_MAX_ARCHIVES",
        "GRAPHITE_MAX_CONCURRENT",
        "GRAPHITE_ALLOW_DURABLE_NONCE",
        "GRAPHITE_CORS_ORIGINS",
    ] {
        std::env::remove_var(k);
    }
    std::env::set_var("GRAPHITE_DEV_MODE", "1");
    std::env::set_var("GRAPHITE_DATA_DIR", &dir);
    std::env::set_var("GRAPHITE_REGISTRY_STATE", dir.join("no-registry.json"));
    for (k, v) in extra_env {
        std::env::set_var(k, v);
    }
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        if let Err(e) = rt.block_on(graphite_core::server::run_server(addr)) {
            eprintln!("server exited: {e}");
        }
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return addr;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("server did not start");
}

/// One `GET /health` with the given raw header lines; returns the status.
fn health_status(addr: SocketAddr, header_lines: &[&str]) -> u16 {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut req = String::from("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    for h in header_lines {
        req.push_str(h);
        req.push_str("\r\n");
    }
    req.push_str("Connection: close\r\n\r\n");
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out);
    text.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {text:?}"))
}

#[test]
fn a_second_forwarded_for_line_cannot_choose_the_rate_limit_bucket() {
    // One trusted hop; 0.1 req/s => a bucket holds exactly one token and
    // refills in ten seconds, so a second request from the same client inside
    // this test is always refused.
    let addr = start_server(&[
        ("GRAPHITE_TRUST_PROXY", "1"),
        ("GRAPHITE_RATE_LIMIT", "0.1"),
    ]);

    // Control: the proxy's line alone. The limiter works — the second request
    // from the client the proxy observed is refused.
    assert_eq!(health_status(addr, &["X-Forwarded-For: 198.51.100.7"]), 200);
    assert_eq!(
        health_status(addr, &["X-Forwarded-For: 198.51.100.7"]),
        429,
        "control: the limiter must refuse the same client's second request"
    );

    // Attack: the client sends its own X-Forwarded-For line; a proxy that
    // adds (rather than rewrites) puts the observed address on a SECOND line.
    // Every request is from 198.51.100.8 as far as the trusted proxy knows.
    let mut statuses = Vec::new();
    for i in 1..=5 {
        let forged = format!("X-Forwarded-For: 203.0.113.{i}");
        statuses.push(health_status(
            addr,
            &[forged.as_str(), "X-Forwarded-For: 198.51.100.8"],
        ));
    }
    let refused = statuses.iter().filter(|s| **s == 429).count();
    assert!(
        refused >= 4,
        "five requests the trusted proxy attributes to ONE client (198.51.100.8) must share one \
         bucket (4 of 5 refused); got statuses {statuses:?} — the client-supplied first \
         X-Forwarded-For line chose a fresh bucket for each"
    );
}
