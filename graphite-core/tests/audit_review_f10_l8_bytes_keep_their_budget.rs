//! F10 (review of the 2026-09-29 audit's fix A4-05): a silent inclusion
//! witness does not starve L8's `getTransaction`.
//!
//! A4-05 put every RPC call L8 makes under one `RpcBudget`: the primary's and
//! the witness's `getSignatureStatuses` run together, and `getTransaction`
//! gets what is left. `tokio::join!` waits for BOTH status calls, so a witness
//! that never answers held the join for the whole budget, and the bytes fetch
//! that followed had nothing left. The chain's bytes came back "unavailable"
//! and attribution fell back to the caller's keys, although the primary had
//! answered every call at once.
//!
//! The fix gives the status calls at most half the budget, so the bytes fetch
//! always has the other half.
//!
//! The test builds the clients as `run_server` does (3 s per call, one retry,
//! the default budget) against a primary that answers everything at once and a
//! witness that never answers, and pins that the chain's bytes are fetched and
//! bound: `chain_transaction_sha256` is the digest of the signed transaction
//! the primary served.
#![cfg(feature = "rpc")]

use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::tx_artifact::bound_artifact_sha256;
use graphite_core::verification::{ExecutionKeys, GraphiteCore};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

/// server.rs `run_server`: `PER_CALL` and `RETRIES` (private consts).
const PER_CALL: Duration = Duration::from_secs(3);
const RETRIES: u32 = 1;

fn compact_u16(mut v: usize, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// A legacy System transfer signed by a key this test holds, so the bytes
/// bind to their signature the way L8 requires. Returns (bytes, signature).
fn signed_transfer() -> (Vec<u8>, String) {
    use ed25519_dalek::Signer;
    let payer = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut message = vec![1u8, 0, 1]; // one signer; the program is read-only
    compact_u16(3, &mut message);
    message.extend_from_slice(&payer.verifying_key().to_bytes());
    message.extend_from_slice(&[0x55u8; 32]); // recipient
    message.extend_from_slice(&[0u8; 32]); // System Program
    message.extend_from_slice(&[0x09u8; 32]); // recent blockhash
    compact_u16(1, &mut message);
    message.push(2); // program index
    compact_u16(2, &mut message);
    message.extend_from_slice(&[0, 1]);
    let mut data = vec![2u8, 0, 0, 0];
    data.extend_from_slice(&1_000u64.to_le_bytes());
    compact_u16(data.len(), &mut message);
    message.extend_from_slice(&data);

    let signature = payer.sign(&message).to_bytes();
    let mut tx = Vec::new();
    compact_u16(1, &mut tx);
    tx.extend_from_slice(&signature);
    tx.extend_from_slice(&message);
    (tx, bs58::encode(signature).into_string())
}

/// A primary that answers at once: the signature finalized in slot 12345, and
/// `getTransaction` serving `tx`.
fn primary(tx: Vec<u8>) -> String {
    use base64::Engine;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.encode(tx);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let encoded = encoded.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = if req.contains("getSignatureStatuses") {
                    r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":12400},"value":[{"slot":12345,"confirmations":null,"confirmationStatus":"finalized","err":null,"status":{"Ok":null}}]}}"#.to_string()
                } else if req.contains("getTransaction") {
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"slot":12345,"transaction":["{encoded}","base64"],"meta":{{"err":null}}}}}}"#
                    )
                } else {
                    r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string()
                };
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            });
        }
    });
    format!("http://{addr}")
}

/// A witness that reads every request and never answers.
fn silent_witness() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                let _ = stream.read(&mut buf);
                std::thread::sleep(Duration::from_secs(60));
            });
        }
    });
    format!("http://{addr}")
}

fn server_client(endpoint: &str) -> SolanaRpcClient {
    SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        timeout: PER_CALL,
        max_retries: RETRIES,
        ..Default::default()
    })
}

#[tokio::test]
async fn a_silent_witness_does_not_starve_the_bytes_fetch() {
    let (tx, signature) = signed_transfer();
    let expected = bound_artifact_sha256(&tx, &signature).expect("the test's bytes are bound");

    let mut core = GraphiteCore::new();
    core.attach_rpc_client(server_client(&primary(tx)));
    core.attach_inclusion_witness(server_client(&silent_witness()))
        .unwrap();

    let started = Instant::now();
    let audit = core
        .audit_execution(&signature, ExecutionKeys::default(), None)
        .await;
    eprintln!(
        "L8 after {:.1}s: chain digest {:?}; bytes unavailable: {:?}; witness: {:?}",
        started.elapsed().as_secs_f64(),
        audit.chain_transaction_sha256,
        audit.chain_bytes_unavailable,
        audit.inclusion_witness.as_ref().map(|w| &w.detail)
    );
    assert_eq!(
        audit.chain_transaction_sha256.as_deref(),
        Some(expected.as_str()),
        "the primary served bound bytes at once, but getTransaction had no budget left after \
         the join waited out the silent witness ({:?}) — attribution fell back to the caller's keys",
        audit.chain_bytes_unavailable
    );
    assert!(audit.chain_bytes_unavailable.is_none());
}
