//! Round 30 (§4.6, G-08): the server as a client on the wire sees it —
//! startup refusals for an L8 posture the operator cannot have, and request
//! framing an attacker controls.
//!
//! One test function: `run_server` reads the process environment, so the
//! startup cases run in sequence, each against its own data directory, and
//! the wire cases against one server started last.
#![cfg(feature = "server")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

const VERIFY_KEY: &str = "round30-wire-verify-key-0123456789abcdef";
const OPERATOR_KEY: &str = "round30-wire-operator-key-0123456789abcdef";

fn fresh_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "graphite-r30-wire-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn free_addr() -> SocketAddr {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    format!("127.0.0.1:{port}").parse().unwrap()
}

fn base_env(tag: &str) {
    for k in [
        "GRAPHITE_DEV_MODE",
        "GRAPHITE_RPC_URL",
        "GRAPHITE_RPC_WITNESS_URL",
        "GRAPHITE_RPC_PROVIDER",
        "GRAPHITE_RPC_WITNESS_PROVIDER",
        "GRAPHITE_L8_HIGH_ASSURANCE",
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
        "GRAPHITE_QUARANTINE_ON_UPGRADE",
        "GRAPHITE_LEARN_FROM_POLICY_REFUSALS",
    ] {
        std::env::remove_var(k);
    }
    let dir = fresh_dir(tag);
    std::env::set_var("GRAPHITE_API_KEY", VERIFY_KEY);
    std::env::set_var("GRAPHITE_ADMIN_API_KEY", OPERATOR_KEY);
    std::env::set_var("GRAPHITE_DATA_DIR", &dir);
    std::env::set_var("GRAPHITE_REGISTRY_STATE", dir.join("no-registry.json"));
}

/// `run_server` with the current environment, expected to refuse before it
/// serves; returns the refusal.
fn refusal() -> String {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    match rt.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(20),
            graphite_core::server::run_server(free_addr()),
        )
        .await
    }) {
        Ok(Err(e)) => e.to_string(),
        Ok(Ok(())) => panic!("the server started and stopped instead of refusing"),
        Err(_) => panic!("the server started instead of refusing"),
    }
}

fn start() -> SocketAddr {
    let addr = free_addr();
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

/// Send raw bytes, return the status line (or "" when the server closed
/// without answering).
fn raw(addr: SocketAddr, request: &[u8]) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let _ = s.write_all(request);
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out)
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

#[test]
fn the_server_refuses_what_it_cannot_honour_and_frames_strictly() {
    // ── startup: the L8 posture ──────────────────────────────────────────
    // High assurance with no RPC at all.
    base_env("ha-none");
    std::env::set_var("GRAPHITE_L8_HIGH_ASSURANCE", "1");
    let why = refusal();
    assert!(
        why.contains("GRAPHITE_L8_HIGH_ASSURANCE") && why.contains("witness"),
        "{why}"
    );

    // A typo is not "off".
    base_env("ha-typo");
    std::env::set_var("GRAPHITE_L8_HIGH_ASSURANCE", "yes");
    let why = refusal();
    assert!(why.contains("GRAPHITE_L8_HIGH_ASSURANCE"), "{why}");

    // A witness that is the same machine as the primary.
    base_env("ha-twin");
    std::env::set_var("GRAPHITE_L8_HIGH_ASSURANCE", "1");
    std::env::set_var("GRAPHITE_RPC_URL", "http://127.0.0.1:1");
    std::env::set_var("GRAPHITE_RPC_WITNESS_URL", "http://127.0.0.2:1");
    std::env::set_var("GRAPHITE_RPC_PROVIDER", "A");
    std::env::set_var("GRAPHITE_RPC_WITNESS_PROVIDER", "B");
    let why = refusal();
    assert!(why.contains("not an independent provider"), "{why}");

    // Distinct providers that the operator has not named.
    base_env("ha-unnamed");
    std::env::set_var("GRAPHITE_L8_HIGH_ASSURANCE", "1");
    std::env::set_var("GRAPHITE_RPC_URL", "https://203.0.113.5");
    std::env::set_var("GRAPHITE_RPC_WITNESS_URL", "https://198.51.100.7");
    let why = refusal();
    assert!(why.contains("GRAPHITE_RPC_PROVIDER"), "{why}");

    // ── startup: the URL policy ──────────────────────────────────────────
    for endpoint in [
        "http://169.254.169.254/latest/meta-data",
        "http://[::ffff:169.254.169.254]/",
        "http://0.0.0.0:8899",
    ] {
        base_env("forbidden");
        std::env::set_var("GRAPHITE_RPC_URL", endpoint);
        let why = refusal();
        assert!(
            why.contains("GRAPHITE_RPC_URL") && why.contains("address"),
            "{why}"
        );
        assert!(!why.contains("169.254"), "the address is not echoed: {why}");
    }

    // ── the wire ─────────────────────────────────────────────────────────
    base_env("wire");
    let addr = start();
    let auth = format!("Authorization: Bearer {VERIFY_KEY}\r\n");

    // A chunked body past the limit is refused, whatever the chunks say.
    let mut chunked = format!(
        "POST /verify HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}Content-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let chunk = vec![b' '; 64 * 1024];
    for _ in 0..20 {
        chunked.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        chunked.extend_from_slice(&chunk);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    let status = raw(addr, &chunked);
    assert!(
        status.contains(" 413 "),
        "oversized chunked body: {status:?}"
    );

    // Two Content-Length values, or Content-Length beside Transfer-Encoding:
    // the framing a proxy and this server could read differently. Never
    // served.
    for framing in [
        "Content-Length: 2\r\nContent-Length: 3\r\n",
        "Content-Length: 2\r\nTransfer-Encoding: chunked\r\n",
        "Transfer-Encoding: chunked, identity\r\n",
    ] {
        let req = format!(
            "POST /verify/execution HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}Content-Type: application/json\r\n{framing}Connection: close\r\n\r\n{{}}"
        );
        let status = raw(addr, req.as_bytes());
        assert!(
            !status.contains(" 200 ") && !status.contains(" 422 "),
            "{framing:?} reached a handler: {status:?}"
        );
    }

    // Two Authorization headers, on the wire.
    let req = format!(
        "GET /api/graph HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}{auth}Connection: close\r\n\r\n"
    );
    assert!(raw(addr, req.as_bytes()).contains(" 401 "));

    // The operator surface, with the verify key, by any spelling.
    for path in [
        "/admin/quarantine",
        "//admin/quarantine",
        "/admin/./quarantine",
    ] {
        let req =
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}Connection: close\r\n\r\n");
        let status = raw(addr, req.as_bytes());
        assert!(!status.contains(" 200 "), "{path}: {status:?}");
    }
    // ...and with the operator key, it answers.
    let req = format!(
        "GET /admin/quarantine HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {OPERATOR_KEY}\r\nConnection: close\r\n\r\n"
    );
    assert!(raw(addr, req.as_bytes()).contains(" 200 "));
}
