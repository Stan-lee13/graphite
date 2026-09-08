//! Requires the `rpc` feature: L8 reconciles against the chain, which needs a
//! client.
#![cfg(feature = "rpc")]

//! L8 reconciliation: does what Graphite decided actually govern what happened?
//!
//! `verify_execution` reports chain status, which is a lookup the caller could
//! do themselves. The control is the RECONCILIATION — joining that status to
//! the append-only record of what Graphite decided for the same transaction.
//!
//! Until 2026-09-07 none of this was reachable in production: `verify_execution`
//! lived in the library, was unit-tested, and was called from no HTTP route and
//! no CLI command, while every verification response said "audit_trail_id bound
//! to transaction for future L8 replay". One of the eight advertised layers was
//! documented, tested and unreachable.
//!
//! The outcome that matters is `BlockedButExecuted`: a transaction Graphite
//! refused that was submitted anyway. It means the gate was bypassed rather than
//! obeyed, and nothing inside a verification request can detect it, because it
//! happens entirely outside one.

use graphite_core::durable::{audit_path, AuditLog, AuditRecord, LifecycleEvent};
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::verification::{ExecutionReconciliation, GraphiteCore};
use std::io::{Read, Write};
use std::net::TcpListener;

/// A one-shot mock cluster. `body` is the JSON-RPC response it answers with.
fn mock_rpc(body: &'static str) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), handle)
}

const CONFIRMED_OK: &str = r#"{"jsonrpc":"2.0","result":{"context":{"slot":2},"value":[{"slot":12345,"confirmations":0,"err":null,"status":{"Ok":null}}]},"id":1}"#;
const CONFIRMED_FAILED: &str = r#"{"jsonrpc":"2.0","result":{"context":{"slot":2},"value":[{"slot":12345,"confirmations":0,"err":{"InstructionError":[0,"Custom"]},"status":{"Err":"x"}}]},"id":1}"#;
const NOT_FOUND: &str =
    r#"{"jsonrpc":"2.0","result":{"context":{"slot":2},"value":[null]},"id":1}"#;

const SIG: &str = "5sigAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "graphite-l8-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|x| x.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Write a verification record with the given verdict, as `/verify` would.
fn record(log: &AuditLog, content_hash: &str, approved: bool) {
    log.append(&AuditRecord {
        event_type: LifecycleEvent::Verification,
        timestamp: "2026-09-07T00:00:00Z".to_string(),
        audit_trail_id: format!("gr-test-{content_hash}"),
        content_hash: content_hash.to_string(),
        program_id: "11111111111111111111111111111111".to_string(),
        instruction_name: "Transfer".to_string(),
        protocol_name: "System Program".to_string(),
        manifest_version: Some("1.0.0".to_string()),
        approved,
        confidence: if approved { 0.9 } else { 0.2 },
        risk_status: if approved { "Clear" } else { "Blocked" }.to_string(),
        policy_verdict: if approved { "Approved" } else { "Rejected" }.to_string(),
        l3_status: "inconclusive".to_string(),
        l8_status: "inconclusive".to_string(),
    });
}

fn core_with(endpoint: String) -> GraphiteCore {
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint,
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    }));
    core
}

/// THE case. Graphite said no; the chain says it happened anyway.
#[tokio::test]
async fn a_blocked_transaction_that_executed_is_a_discrepancy() {
    let dir = temp_dir("blocked-exec");
    let log = AuditLog::open(audit_path(&dir)).unwrap();
    record(&log, "hash_blocked", false);

    let (endpoint, h) = mock_rpc(CONFIRMED_OK);
    let core = core_with(endpoint);
    let audit = core
        .audit_execution(SIG, Some("hash_blocked"), Some(&log))
        .await;
    h.join().unwrap();

    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::BlockedButExecuted,
        "a blocked transaction found on chain must be reported as a bypass"
    );
    assert!(
        audit.reconciliation.is_discrepancy(),
        "this is the one outcome that should page someone"
    );
    assert_eq!(audit.recorded_approved, Some(false));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same chain status against an APPROVED record is the ordinary case, which
/// is what makes the test above meaningful rather than "any confirmation alarms".
#[tokio::test]
async fn an_approved_transaction_that_executed_is_not_a_discrepancy() {
    let dir = temp_dir("approved-exec");
    let log = AuditLog::open(audit_path(&dir)).unwrap();
    record(&log, "hash_ok", true);

    let (endpoint, h) = mock_rpc(CONFIRMED_OK);
    let audit = core_with(endpoint)
        .audit_execution(SIG, Some("hash_ok"), Some(&log))
        .await;
    h.join().unwrap();

    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::ApprovedAndExecuted
    );
    assert!(!audit.reconciliation.is_discrepancy());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Approved then failed on chain is not a security failure — Graphite verifies
/// intent and structure, not that a transaction will succeed — and must not be
/// reported as one.
#[tokio::test]
async fn an_approved_transaction_that_failed_on_chain_is_reported_but_not_alarmed() {
    let dir = temp_dir("approved-failed");
    let log = AuditLog::open(audit_path(&dir)).unwrap();
    record(&log, "hash_fail", true);

    let (endpoint, h) = mock_rpc(CONFIRMED_FAILED);
    let audit = core_with(endpoint)
        .audit_execution(SIG, Some("hash_fail"), Some(&log))
        .await;
    h.join().unwrap();

    match &audit.reconciliation {
        ExecutionReconciliation::ApprovedButFailedOnChain { error } => {
            assert!(
                error.is_some(),
                "the on-chain error must be carried through"
            );
        }
        other => panic!("expected ApprovedButFailedOnChain, got {other:?}"),
    }
    assert!(!audit.reconciliation.is_discrepancy());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Blocked and correctly absent from the chain: the gate worked.
#[tokio::test]
async fn a_blocked_transaction_the_chain_never_saw_is_clean() {
    let dir = temp_dir("blocked-absent");
    let log = AuditLog::open(audit_path(&dir)).unwrap();
    record(&log, "hash_b2", false);

    let (endpoint, h) = mock_rpc(NOT_FOUND);
    let audit = core_with(endpoint)
        .audit_execution(SIG, Some("hash_b2"), Some(&log))
        .await;
    h.join().unwrap();

    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::BlockedAndNotExecuted
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// An APPROVED transaction the chain has not seen is pending or undispatched —
/// NotFound, never "blocked and not executed". Absence of a record is not
/// evidence of non-execution.
#[tokio::test]
async fn an_approved_transaction_the_chain_has_not_seen_is_not_found() {
    let dir = temp_dir("approved-absent");
    let log = AuditLog::open(audit_path(&dir)).unwrap();
    record(&log, "hash_pending", true);

    let (endpoint, h) = mock_rpc(NOT_FOUND);
    let audit = core_with(endpoint)
        .audit_execution(SIG, Some("hash_pending"), Some(&log))
        .await;
    h.join().unwrap();

    assert_eq!(audit.reconciliation, ExecutionReconciliation::NotFound);
    let _ = std::fs::remove_dir_all(&dir);
}

/// An unreachable cluster must never look like a verdict. This is the
/// fail-closed property: an unavailable check says it is unavailable.
#[tokio::test]
async fn an_unreachable_cluster_is_unavailable_never_a_confirmation() {
    let dir = temp_dir("rpc-down");
    let log = AuditLog::open(audit_path(&dir)).unwrap();
    record(&log, "hash_down", false);

    // Port 1 refuses immediately.
    let audit = core_with("http://127.0.0.1:1".to_string())
        .audit_execution(SIG, Some("hash_down"), Some(&log))
        .await;

    match &audit.reconciliation {
        ExecutionReconciliation::Unavailable { reason } => {
            // The endpoint must never appear in the reason: a managed provider
            // embeds its API key in the URL.
            assert!(
                !reason.contains("127.0.0.1:1") && !reason.contains("http://"),
                "the RPC endpoint leaked into the reason: {reason}"
            );
        }
        other => panic!("an unreachable cluster must be Unavailable, got {other:?}"),
    }
    assert!(!audit.reconciliation.is_discrepancy());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Without a content_hash there is nothing to reconcile against, and the result
/// must say so rather than implying the transaction checked out.
#[tokio::test]
async fn no_content_hash_means_no_reconciliation_not_a_pass() {
    let (endpoint, h) = mock_rpc(CONFIRMED_OK);
    let audit = core_with(endpoint).audit_execution(SIG, None, None).await;
    h.join().unwrap();

    match &audit.reconciliation {
        ExecutionReconciliation::Unavailable { reason } => {
            assert!(reason.contains("content_hash"), "{reason}");
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

/// A hash with no verification on file is honestly "we never saw this", which is
/// distinct from both a pass and a discrepancy.
#[tokio::test]
async fn an_execution_graphite_never_verified_is_reported_as_such() {
    let dir = temp_dir("unseen");
    let log = AuditLog::open(audit_path(&dir)).unwrap();
    record(&log, "some_other_hash", true);

    let (endpoint, h) = mock_rpc(CONFIRMED_OK);
    let audit = core_with(endpoint)
        .audit_execution(SIG, Some("never_seen_hash"), Some(&log))
        .await;
    h.join().unwrap();

    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::NoVerificationOnRecord
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A transaction verified twice is governed by the LAST verdict before
/// submission. Reading the first would let an attacker launder a later block
/// behind an earlier approval of the same content hash.
#[tokio::test]
async fn the_most_recent_verdict_for_a_content_hash_is_the_one_that_governs() {
    let dir = temp_dir("re-verified");
    let log = AuditLog::open(audit_path(&dir)).unwrap();
    record(&log, "hash_twice", true); // approved first...
    record(&log, "hash_twice", false); // ...then blocked

    let (endpoint, h) = mock_rpc(CONFIRMED_OK);
    let audit = core_with(endpoint)
        .audit_execution(SIG, Some("hash_twice"), Some(&log))
        .await;
    h.join().unwrap();

    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::BlockedButExecuted,
        "the latest verdict was BLOCK, so executing it is still a bypass"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
