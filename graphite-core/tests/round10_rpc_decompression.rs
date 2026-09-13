//! Requires the `rpc` feature.
#![cfg(feature = "rpc")]

//! Round 10: a compressed RPC response that decompresses past the cap.
//!
//! `reqwest` decompresses gzip and brotli transparently, so a peer can send a
//! few kilobytes on the wire that become tens of megabytes in memory. The
//! response cap (`MAX_RPC_RESPONSE_BYTES`, 32 MiB) is applied to the chunks
//! `reqwest` yields — which are DECOMPRESSED bytes — so the bomb is abandoned
//! at the cap rather than allocated. This pins that, with a gzip body that
//! inflates 1000:1, and pins that a pathologically nested JSON body is a
//! parse error rather than a stack overflow.

use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use std::io::{Read, Write};
use std::net::TcpListener;

fn serve_once(headers: &'static str, body: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = vec![0u8; 65536];
            let _ = stream.read(&mut buf);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
    });
    format!("http://{addr}")
}

fn client(endpoint: String) -> SolanaRpcClient {
    SolanaRpcClient::new(RpcConfig {
        endpoint,
        timeout: std::time::Duration::from_secs(20),
        max_retries: 0,
        ..Default::default()
    })
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    let mut e = GzEncoder::new(Vec::new(), Compression::best());
    e.write_all(bytes).unwrap();
    e.finish().unwrap()
}

/// 64 MiB of JSON on the wire as ~64 KB of gzip. Refused at the cap, in
/// well under the time it would take to allocate and parse it.
#[tokio::test]
async fn a_gzip_bomb_is_abandoned_at_the_decompressed_cap() {
    let mut plain = br#"{"jsonrpc":"2.0","id":1,"result":""#.to_vec();
    plain.resize(plain.len() + 64 * 1024 * 1024, b'a');
    plain.extend_from_slice(br#""}"#);
    let compressed = gzip(&plain);
    let ratio = plain.len() / compressed.len();
    assert!(
        ratio > 100,
        "the bomb must actually be a bomb: ratio {ratio}"
    );

    let endpoint = serve_once("Content-Encoding: gzip\r\n", compressed.clone());
    let started = std::time::Instant::now();
    let err = client(endpoint)
        .get_slot()
        .await
        .expect_err("a 64 MiB body must be refused");
    let elapsed = started.elapsed();
    let msg = err.to_string();
    assert!(msg.contains("too large"), "{msg}");
    println!(
        "round10: {} bytes on the wire → {} MiB decompressed (ratio {ratio}): refused in {:?}",
        compressed.len(),
        plain.len() / (1024 * 1024),
        elapsed
    );
    assert!(elapsed.as_secs() < 10, "{elapsed:?}");
}

/// A body that fits the cap but nests 100,000 levels deep is a parse error,
/// not a stack overflow: serde_json's recursion limit stands in front of the
/// stack.
#[tokio::test]
async fn pathological_nesting_is_a_parse_error_not_a_crash() {
    let depth = 100_000;
    let mut body = br#"{"jsonrpc":"2.0","id":1,"result":"#.to_vec();
    body.extend(std::iter::repeat_n(b'[', depth));
    body.extend(std::iter::repeat_n(b']', depth));
    body.push(b'}');
    let endpoint = serve_once("", body);
    let err = client(endpoint)
        .get_slot()
        .await
        .expect_err("nesting must not parse");
    let msg = err.to_string();
    println!("round10: 100,000-deep nesting: {msg}");
    assert!(!msg.is_empty());
}
