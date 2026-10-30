//! Round 40 (R39-CB-13): the RPC client never goes through an environment
//! proxy.
//!
//! The client was built with redirects off and the connect-time address guard
//! (`GuardedResolver`), but honoured `HTTP_PROXY` / `HTTPS_PROXY` /
//! `ALL_PROXY`. Through a proxy the guard judges only the proxy's address and
//! the proxy resolves the RPC host itself, so the guard no longer stands
//! between Graphite and the endpoint. RPC egress is direct
//! (docs/ops/install.md).
//!
//! Here every proxy variable names a loopback "proxy" that would answer a
//! valid JSON-RPC reply of its own. The client must reach the mock RPC
//! directly, and the proxy must see nothing. One test in this file: the
//! process environment is shared.
#![cfg(feature = "rpc")]

use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// A loopback HTTP server answering every request with `{"result": slot}`;
/// counts the connections it accepted.
fn answering(slot: u64) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            counter.fetch_add(1, Ordering::SeqCst);
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            // Read the head, then the body its Content-Length names.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let body_start = loop {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => break None,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break Some(i + 4);
                }
            };
            let Some(start) = body_start else { continue };
            let head = String::from_utf8_lossy(&buf[..start]).to_ascii_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            while buf.len() < start + len {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            let body = format!(r#"{{"jsonrpc":"2.0","result":{slot},"id":1}}"#);
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (port, seen)
}

#[test]
fn the_rpc_client_ignores_environment_proxies() {
    let (rpc_port, rpc_seen) = answering(42);
    let (proxy_port, proxy_seen) = answering(999);
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    for k in ["NO_PROXY", "no_proxy"] {
        std::env::remove_var(k);
    }
    for k in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        std::env::set_var(k, &proxy);
    }

    let client = SolanaRpcClient::new(RpcConfig {
        endpoint: format!("http://127.0.0.1:{rpc_port}"),
        timeout: Duration::from_secs(10),
        max_retries: 0,
        ..Default::default()
    });
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let slot = rt.block_on(client.get_slot());

    assert_eq!(
        proxy_seen.load(Ordering::SeqCst),
        0,
        "the RPC request went to the environment proxy (slot {slot:?})"
    );
    assert_eq!(slot.ok(), Some(42), "answered by the RPC itself");
    assert!(rpc_seen.load(Ordering::SeqCst) >= 1);
}
