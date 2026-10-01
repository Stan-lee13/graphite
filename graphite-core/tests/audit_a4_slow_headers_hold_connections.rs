//! A4-03 (2026-09-29 audit): a client that never finishes its request head is
//! disconnected.
//!
//! The server's 10 s request timeout is tower-http's `TimeoutLayer`, which
//! starts only once hyper has parsed a complete request head. hyper reads the
//! head under `header_read_timeout`, which needs a timer to take effect, and
//! axum 0.8's `serve` gave hyper none, so no head timeout applied ("has
//! default, but no timer set"); nothing capped connections either. An
//! unauthenticated client sending a partial request line, or nothing at all,
//! held a socket, a file descriptor and a task indefinitely; the rate limiter,
//! auth and the body timeout never ran, because no request existed yet.
//! Enough of them exhaust the process's descriptors and `accept` fails for
//! everyone.
//!
//! The fix is the server's own hyper-util accept loop, `serve_hardened`:
//! HTTP/1.1 with a `TokioTimer`, a `HEADER_READ_TIMEOUT` of 5 s, a connection
//! semaphore (`GRAPHITE_MAX_CONNECTIONS`, default 1,024) that closes a
//! connection past the cap at accept, `TCP_NODELAY`, and graceful shutdown.
//!
//! The test opens connections that send nothing, a partial request line, and
//! a request line plus one header with the blank line withheld, and pins that
//! the server has closed or answered each of them 15 s later.
#![cfg(feature = "server")]

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

fn start_server() -> SocketAddr {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "graphite-a4-slowhdr-{}-{}",
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
            // Wait for a real answer, not just an accepting socket.
            let _ = s.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
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

/// Whether the server has closed or answered this connection (vs. still
/// holding it open, silent).
fn server_let_go(s: &mut TcpStream) -> bool {
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = [0u8; 512];
    match s.read(&mut buf) {
        Ok(_) => true, // EOF (0) or a response (e.g. 408)
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => false,
        Err(_) => true, // reset
    }
}

#[test]
fn a_client_that_never_finishes_its_request_head_is_disconnected() {
    let addr = start_server();

    // Three shapes of the same thing: nothing sent, a partial request line,
    // and a request line plus one header with the terminating blank line
    // withheld.
    let partials: [&[u8]; 3] = [
        b"",
        b"GET /hea",
        b"POST /verify HTTP/1.1\r\nHost: 127.0.0.1\r\n",
    ];
    let mut conns: Vec<TcpStream> = partials
        .iter()
        .map(|p| {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(p).unwrap();
            s
        })
        .collect();

    // The server's header-read timeout is 5 s and REQUEST_TIMEOUT 10 s. Wait
    // past the latter with slack.
    std::thread::sleep(Duration::from_secs(15));

    let still_open: Vec<usize> = conns
        .iter_mut()
        .enumerate()
        .filter_map(|(i, s)| (!server_let_go(s)).then_some(i))
        .collect();
    assert!(
        still_open.is_empty(),
        "connections {still_open:?} (of {:?}) are still held open, unanswered, 15 s after they \
         stopped sending — no timeout applies before a request head is complete, so unauthenticated \
         clients can hold sockets indefinitely",
        partials
            .iter()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect::<Vec<_>>()
    );
}
