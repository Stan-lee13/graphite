//! W21 (external review, verified 2026-10-03): a connection's lifetime is
//! bounded.
//!
//! The accept loop bounds how long a request head may take to arrive and how
//! many connections are open, but nothing bounded a connection after that: a
//! client that never read its response, or an idle keep-alive, held its
//! connection slot and its per-peer slot for as long as it liked. Each
//! connection is now closed after `GRAPHITE_CONNECTION_LIFETIME_SECS`.
//!
//! Here the lifetime is 2 s and the server's header-read timeout is 5 s: an
//! idle keep-alive connection must be closed by the lifetime, at ~2 s, not
//! left open past 3.5 s.
#![cfg(feature = "server")]

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

/// One server for every test in this binary: its configuration is
/// process-global environment, and two Cores cannot share a data directory.
fn start_server() -> SocketAddr {
    static SERVER: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();
    *SERVER.get_or_init(start_server_once)
}

fn start_server_once() -> SocketAddr {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "graphite-w21-lifetime-{}-{}",
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
        "GRAPHITE_MAX_CONCURRENT",
        "GRAPHITE_CORS_ORIGINS",
    ] {
        std::env::remove_var(k);
    }
    std::env::set_var("GRAPHITE_DEV_MODE", "1");
    std::env::set_var("GRAPHITE_DATA_DIR", &dir);
    std::env::set_var("GRAPHITE_REGISTRY_STATE", dir.join("no-registry.json"));
    std::env::set_var("GRAPHITE_CONNECTION_LIFETIME_SECS", "2");
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
        if let Ok(mut s) = TcpStream::connect(addr) {
            let _ = s
                .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
            let mut out = Vec::new();
            let _ = s.read_to_end(&mut out);
            if out.starts_with(b"HTTP/1.1 200") {
                return addr;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("server did not start");
}

#[test]
fn an_idle_keep_alive_connection_is_closed_at_its_lifetime() {
    let addr = start_server();
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .unwrap();
    // Read the one response; the connection stays open (keep-alive).
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 4096];
    let n = s.read(&mut buf).unwrap();
    assert!(
        buf[..n].starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&buf[..n])
    );
    let opened = Instant::now();

    // Idle from here. The server must close it at its lifetime.
    s.set_read_timeout(Some(Duration::from_millis(3500)))
        .unwrap();
    let closed = match s.read(&mut buf) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => false,
        Err(_) => true, // reset
    };
    assert!(
        closed,
        "an idle connection was still open {:?} after its response",
        opened.elapsed()
    );
    assert!(
        opened.elapsed() >= Duration::from_millis(1000),
        "closed after {:?}: before its lifetime, so not by the lifetime",
        opened.elapsed()
    );
}

/// Round 41 full-codebase audit: the lifetime DROPPED the connection, so a
/// busy keep-alive lost the request in flight (behind Caddy, a 502 and no
/// verdict). A request whose body is still arriving when the 2 s lifetime
/// passes must be answered in full, and the connection closed after it.
#[test]
fn a_request_in_flight_at_the_lifetime_is_answered() {
    let addr = start_server();
    let mut s = TcpStream::connect(addr).unwrap();
    let body = br#"{"not":"a verification input"}"#;
    s.write_all(
        format!(
            "POST /verify HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )
    .unwrap();
    let opened = Instant::now();
    // Half the body now, the rest after the lifetime has passed.
    s.write_all(&body[..10]).unwrap();
    std::thread::sleep(Duration::from_millis(2600));
    // Before the fix the connection is gone by now: this write or the read
    // below fails, or the read sees EOF with no response.
    let _ = s.write_all(&body[10..]);
    s.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&out);
    assert!(
        opened.elapsed() >= Duration::from_secs(2),
        "the body finished arriving after the lifetime"
    );
    assert!(
        text.starts_with("HTTP/1.1 "),
        "the request in flight at the lifetime got no response: {text:?}"
    );
    assert!(
        text.to_ascii_lowercase().contains("connection: close"),
        "the answer closes the connection: {text}"
    );
}
