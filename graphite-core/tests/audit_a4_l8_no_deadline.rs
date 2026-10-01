//! A4-05 (2026-09-29 audit): L8's reconciliation finishes inside the server's
//! request timeout.
//!
//! `/verify` bounds every RPC call it makes with one shared deadline
//! (`RpcBudget`, 6 s), which a compile-time assertion keeps inside the
//! server's 10 s `REQUEST_TIMEOUT`; past it, the timeout wins with a bare 408
//! and nothing on the audit trail. `audit_execution` had no such budget: the
//! primary's `getSignatureStatuses`, the witness's `getSignatureStatuses` and
//! `getTransaction` ran one after another, each with the server's per-call
//! timeout (3 s) and one retry. A slow witness and a slow `getTransaction`
//! took about 12 s; tower's `TimeoutLayer` then answered 408 and dropped the
//! handler before `execution_handler` appended its row, so a
//! `BlockedButExecuted`, which is what this reconciliation computes, was
//! neither returned, recorded nor counted in
//! `graphite_execution_discrepancies_total`.
//!
//! The fix runs `audit_execution` under an `RpcBudget`: the two status calls
//! run concurrently (`tokio::join!`) within it and `getTransaction` gets what
//! is left. An exhausted budget is `RpcError::Timeout`, which gives an
//! `Unavailable` row, never a lost one.
//!
//! The test builds the clients exactly as `run_server` does, against a primary
//! whose `getTransaction` never answers and a witness that never answers, and
//! pins that the reconciliation is `BlockedButExecuted` and finishes inside
//! `REQUEST_TIMEOUT`.
#![cfg(feature = "rpc")]

use graphite_core::durable::{audit_path, AuditLog, AuditRecord, LifecycleEvent};
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::verification::{ExecutionKeys, ExecutionReconciliation, GraphiteCore};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

/// server.rs: `REQUEST_TIMEOUT` (private) — 10 s.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// server.rs `run_server`: `PER_CALL` and `RETRIES` (private consts).
const PER_CALL: Duration = Duration::from_secs(3);
const RETRIES: u32 = 1;

/// A mock that answers `getSignatureStatuses` at once (confirmed, success)
/// when `answer_status`, and otherwise reads the request and never answers.
fn mock(answer_status: bool) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                if answer_status && req.contains("getSignatureStatuses") {
                    let body = r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":2},"value":[{"slot":900,"confirmations":null,"confirmationStatus":"finalized","err":null,"status":{"Ok":null}}]}}"#;
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    );
                } else {
                    // Slow upstream: hold the connection, answer nothing.
                    std::thread::sleep(Duration::from_secs(60));
                }
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
async fn l8_reconciliation_finishes_inside_the_request_timeout() {
    let dir = std::env::temp_dir().join(format!(
        "graphite-a4-l8-deadline-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let log = AuditLog::open(audit_path(&dir)).unwrap();
    assert!(log.append(&AuditRecord {
        event_type: LifecycleEvent::Verification,
        timestamp: graphite_core::durable::now_utc_rfc3339(),
        audit_trail_id: "gr-a4-blocked".to_string(),
        content_hash: "48c65c638aceb5de".to_string(),
        transaction_sha256: None,
        program_id: "11111111111111111111111111111111".to_string(),
        instruction_name: "Transfer".to_string(),
        protocol_name: "System Program".to_string(),
        manifest_version: Some("1.0.0".to_string()),
        approved: false,
        confidence: 0.3,
        risk_status: "Blocked".to_string(),
        policy_verdict: "Rejected".to_string(),
        l3_status: "inconclusive".to_string(),
        l8_status: "inconclusive".to_string(),
        wallet_profile: None,
    }));

    let primary = mock(true); // status fast, getTransaction slow
    let witness = mock(false); // everything slow
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(server_client(&primary));
    core.attach_inclusion_witness(server_client(&witness))
        .unwrap();

    let sig = bs58::encode([7u8; 64]).into_string();
    let started = Instant::now();
    let audit = core
        .audit_execution(
            &sig,
            ExecutionKeys {
                audit_trail_id: Some("gr-a4-blocked"),
                ..Default::default()
            },
            Some(&log),
        )
        .await;
    let elapsed = started.elapsed();
    let _ = std::fs::remove_dir_all(&dir);

    // What the server records for this reconciliation.
    eprintln!(
        "reconciliation after {:.1}s: {:?} (discrepancy = {})",
        elapsed.as_secs_f64(),
        audit.reconciliation,
        audit.reconciliation.is_discrepancy()
    );
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::BlockedButExecuted,
        "precondition: the primary saw a blocked transaction finalized"
    );
    assert!(
        elapsed < REQUEST_TIMEOUT,
        "L8 took {:.1}s with the server's own RPC configuration; past REQUEST_TIMEOUT ({}s) the \
         server answers 408 and records nothing — this BlockedButExecuted would be lost",
        elapsed.as_secs_f64(),
        REQUEST_TIMEOUT.as_secs()
    );
}
