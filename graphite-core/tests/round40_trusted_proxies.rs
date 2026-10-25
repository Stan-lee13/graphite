//! Round 40 (R39-CB-8): `X-Forwarded-For` is believed only from the proxies
//! `GRAPHITE_TRUSTED_PROXIES` names.
//!
//! Campaign 10 (Round 39), MISCONFIG rows: with `GRAPHITE_TRUST_PROXY=1` the
//! header was honoured from ANY peer. A host that reached the Core without
//! passing the proxy — in the production compose file, the AI layer on the
//! backend network — sent a different entry on each request and got a fresh
//! rate-limit bucket each time: 8 of 8 spoofed requests answered 200 where the
//! same peer without the header was refused 429 from its third.
//!
//! Each server here runs at 0.1 request/s, so a bucket holds one token and a
//! second request inside the test from the same key is refused.
#![cfg(feature = "server")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

fn start_server(tag: &str, extra_env: &[(&str, &str)]) -> SocketAddr {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "graphite-r40-proxies-{tag}-{}-{}",
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
        "GRAPHITE_TRUST_PROXY",
        "GRAPHITE_TRUSTED_PROXIES",
        "GRAPHITE_RATE_LIMIT",
        "GRAPHITE_MAX_CONNECTIONS_PER_IP",
        "GRAPHITE_CORS_ORIGINS",
    ] {
        std::env::remove_var(k);
    }
    std::env::set_var("GRAPHITE_DEV_MODE", "1");
    std::env::set_var("GRAPHITE_DATA_DIR", &dir);
    std::env::set_var("GRAPHITE_REGISTRY_STATE", dir.join("no-registry.json"));
    std::env::set_var("GRAPHITE_RATE_LIMIT", "0.1");
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
            // The environment is read before the server binds; the next
            // server may change it now.
            return addr;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("server did not start");
}

fn request(xff: Option<&str>) -> String {
    let mut req = String::from("GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    if let Some(v) = xff {
        req.push_str(&format!("X-Forwarded-For: {v}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");
    req
}

fn status_of(raw: &[u8]) -> u16 {
    let text = String::from_utf8_lossy(raw);
    text.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {text:?}"))
}

/// One `GET /metrics` from 127.0.0.1 (`/health` is exempt from the limiter).
fn status(addr: SocketAddr, xff: Option<&str>) -> u16 {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(request(xff).as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    status_of(&out)
}

/// The same from another loopback address, when the host lets a socket bind
/// one (Linux routes all of 127.0.0.0/8 to loopback).
fn status_from(source: &str, addr: SocketAddr, xff: Option<&str>) -> Option<u16> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let sock = tokio::net::TcpSocket::new_v4().ok()?;
        sock.bind(format!("{source}:0").parse().unwrap()).ok()?;
        let mut s = sock.connect(addr).await.ok()?;
        s.write_all(request(xff).as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await;
        Some(status_of(&out))
    })
}

#[test]
fn only_a_listed_proxy_chooses_the_rate_limit_key() {
    let spoofed = |i: usize| format!("198.51.100.{}", 10 + i);

    // Attack: a hop count, and a list that does not name this peer (the
    // client here is 127.0.0.1; the proxy is elsewhere). A spoofed entry per
    // request must not escape the limit: the peer is the key.
    let not_listed = start_server(
        "not-listed",
        &[
            ("GRAPHITE_TRUST_PROXY", "1"),
            ("GRAPHITE_TRUSTED_PROXIES", "192.0.2.1,2001:db8::/32"),
        ],
    );
    let statuses: Vec<u16> = (0..8)
        .map(|i| status(not_listed, Some(&spoofed(i))))
        .collect();
    assert_eq!(statuses[0], 200, "{statuses:?}");
    assert!(
        statuses[1..].iter().all(|s| *s == 429),
        "a peer that is not a listed proxy chose its own bucket with X-Forwarded-For: {statuses:?}"
    );
    // ...and with no header at all it is the same bucket.
    assert_eq!(status(not_listed, None), 429);

    // Benign: the listed proxy. Each entry it appends is a different client
    // with its own bucket, and one client's second request is refused.
    let listed = start_server(
        "listed",
        &[
            ("GRAPHITE_TRUST_PROXY", "1"),
            ("GRAPHITE_TRUSTED_PROXIES", "127.0.0.1"),
        ],
    );
    let statuses: Vec<u16> = (0..8).map(|i| status(listed, Some(&spoofed(i)))).collect();
    assert!(
        statuses.iter().all(|s| *s == 200),
        "a listed proxy's clients each have their own bucket: {statuses:?}"
    );
    assert_eq!(
        status(listed, Some(&spoofed(0))),
        429,
        "control: the limiter still refuses one client's second request"
    );

    // One server, two peers: the listed proxy at 127.0.0.1 is believed, a
    // host at 127.0.0.2 beside it is not.
    let both = start_server(
        "both",
        &[
            ("GRAPHITE_TRUST_PROXY", "1"),
            ("GRAPHITE_TRUSTED_PROXIES", "127.0.0.1/32"),
        ],
    );
    match status_from("127.0.0.2", both, Some(&spoofed(0))) {
        Some(first) => {
            assert_eq!(first, 200);
            let rest: Vec<u16> = (1..6)
                .map(|i| status_from("127.0.0.2", both, Some(&spoofed(i))).unwrap())
                .collect();
            assert!(
                rest.iter().all(|s| *s == 429),
                "the unlisted neighbour rotated buckets: {rest:?}"
            );
            // Its spoofed entries did not land in those clients' buckets:
            // the proxy's clients are untouched.
            for i in 0..5 {
                assert_eq!(status(both, Some(&spoofed(i))), 200, "client {i}");
            }
        }
        None => eprintln!("127.0.0.2 is not bindable here; the two-server cases above stand"),
    }
}
