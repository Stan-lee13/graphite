//! R1 (review of the 2026-09-29 audit): L8 concludes "the approved
//! transaction executed" only from the chain's own bytes.
//!
//! `audit_execution` finds the verification on record by the chain's bytes
//! when `getTransaction` returns them (bound to the signature, digested), and
//! otherwise by a key the CALLER supplies: `audit_trail_id`, then
//! `transaction_sha256`, then `content_hash`. Its `Confirmed` arm returned
//! `ApprovedAndExecuted` for any approved record and a successful,
//! cluster-backed status — whichever way the record was found. So a random,
//! unrelated, successful signature presented with the key of any approval
//! reconciled as "the approved transaction executed": an attestation the
//! caller could manufacture.
//!
//! The fix: a positive conclusion about an approved record needs
//! `attribution == Chain`; without the chain's bytes it is `Unavailable`,
//! saying why. A blocked record still alarms (`BlockedButExecuted`) on any
//! sighting — the two claims are not symmetric.
//!
//! The mock cluster answers `getSignatureStatuses` (finalized, success) for
//! every signature and `getTransaction` per test: null, an error, or real
//! signed bytes.
#![cfg(feature = "rpc")]

use graphite_core::durable::{audit_path, AuditLog, AuditRecord, LifecycleEvent};
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::tx_artifact::bound_artifact_sha256;
use graphite_core::verification::{
    ExecutionAttribution, ExecutionKeys, ExecutionReconciliation, GraphiteCore,
};
use std::io::{Read, Write};
use std::net::TcpListener;

#[derive(Clone)]
enum Bytes {
    Null,
    Error,
    Signed(Vec<u8>),
}

fn cluster(bytes: Bytes) -> String {
    use base64::Engine;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let bytes = bytes.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = if req.contains("getSignatureStatuses") {
                    r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":12400},"value":[{"slot":12345,"confirmations":null,"confirmationStatus":"finalized","err":null,"status":{"Ok":null}}]}}"#.to_string()
                } else if req.contains("getTransaction") {
                    match &bytes {
                        Bytes::Null => r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
                        Bytes::Error => {
                            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"internal"}}"#
                                .to_string()
                        }
                        Bytes::Signed(b) => format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"slot":12345,"transaction":["{}","base64"],"meta":{{"err":null}}}}}}"#,
                            base64::engine::general_purpose::STANDARD.encode(b)
                        ),
                    }
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

fn core_at(endpoint: &str) -> GraphiteCore {
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        timeout: std::time::Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    }));
    core
}

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

/// A legacy System transfer signed by a key this test holds: (bytes, signature).
fn signed_transfer() -> (Vec<u8>, String) {
    use ed25519_dalek::Signer;
    let payer = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut message = vec![1u8, 0, 1];
    compact_u16(3, &mut message);
    message.extend_from_slice(&payer.verifying_key().to_bytes());
    message.extend_from_slice(&[0x55u8; 32]);
    message.extend_from_slice(&[0u8; 32]);
    message.extend_from_slice(&[0x09u8; 32]);
    compact_u16(1, &mut message);
    message.push(2);
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

fn record(id: &str, content_hash: &str, tx_sha: Option<&str>, approved: bool) -> AuditRecord {
    AuditRecord {
        event_type: LifecycleEvent::Verification,
        timestamp: graphite_core::durable::now_utc_rfc3339(),
        audit_trail_id: id.to_string(),
        content_hash: content_hash.to_string(),
        transaction_sha256: tx_sha.map(str::to_string),
        program_id: "11111111111111111111111111111111".to_string(),
        instruction_name: "Transfer".to_string(),
        protocol_name: "System Program".to_string(),
        manifest_version: Some("1.0.0".to_string()),
        approved,
        confidence: if approved { 0.9 } else { 0.3 },
        risk_status: if approved { "Clear" } else { "Blocked" }.to_string(),
        policy_verdict: if approved { "Approved" } else { "Rejected" }.to_string(),
        l3_status: "passed".to_string(),
        l8_status: "inconclusive".to_string(),
        wallet_profile: None,
    }
}

fn trail(records: &[AuditRecord]) -> (AuditLog, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "graphite-r1-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let log = AuditLog::open(audit_path(&dir)).unwrap();
    for r in records {
        assert!(log.append(r));
    }
    (log, dir)
}

const APPROVED_TX: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

/// A random, unrelated signature: 64 bytes nobody signed.
fn unrelated_signature() -> String {
    bs58::encode([0x77u8; 64]).into_string()
}

fn not_approved_and_executed(r: &ExecutionReconciliation, case: &str) {
    assert!(
        !matches!(r, ExecutionReconciliation::ApprovedAndExecuted),
        "{case}: an approval found only by a caller key reconciled as ApprovedAndExecuted"
    );
    assert!(
        matches!(r, ExecutionReconciliation::Unavailable { .. }),
        "{case}: expected Unavailable, got {r:?}"
    );
}

/// A, B, C, G: an approved record, a finalized successful status, no chain
/// bytes, and each caller key in turn — for a signature that has nothing to
/// do with the approved transaction.
#[tokio::test]
async fn an_approval_named_only_by_a_caller_key_is_not_an_execution_of_it() {
    let (log, dir) = trail(&[record(
        "gr-r1-ok",
        "1111111111111111",
        Some(APPROVED_TX),
        true,
    )]);
    let core = core_at(&cluster(Bytes::Null));
    let sig = unrelated_signature();
    for (case, keys) in [
        (
            "A content_hash",
            ExecutionKeys {
                content_hash: Some("1111111111111111"),
                ..Default::default()
            },
        ),
        (
            "B audit_trail_id",
            ExecutionKeys {
                audit_trail_id: Some("gr-r1-ok"),
                ..Default::default()
            },
        ),
        (
            "C transaction_sha256",
            ExecutionKeys {
                transaction_sha256: Some(APPROVED_TX),
                ..Default::default()
            },
        ),
    ] {
        let audit = core.audit_execution(&sig, keys, Some(&log)).await;
        assert_ne!(audit.attribution, ExecutionAttribution::Chain, "{case}");
        assert_eq!(audit.recorded_approved, Some(true), "{case}: precondition");
        not_approved_and_executed(&audit.reconciliation, case);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// D: two transactions share one content_hash, one approved and one blocked.
/// Whichever is newest, a content_hash join without bytes never yields an
/// exact approved attribution.
#[tokio::test]
async fn a_shared_content_hash_never_yields_an_approved_execution() {
    let core = core_at(&cluster(Bytes::Null));
    let sig = unrelated_signature();
    let keys = ExecutionKeys {
        content_hash: Some("2222222222222222"),
        ..Default::default()
    };
    // Approved newest.
    let (log, dir) = trail(&[
        record("gr-r1-blocked", "2222222222222222", Some("b2"), false),
        record("gr-r1-approved", "2222222222222222", Some("a2"), true),
    ]);
    let audit = core.audit_execution(&sig, keys.clone(), Some(&log)).await;
    not_approved_and_executed(&audit.reconciliation, "D approved newest");
    let _ = std::fs::remove_dir_all(&dir);
    // Blocked newest: the alarm, never an approval.
    let (log, dir) = trail(&[
        record("gr-r1-approved2", "2222222222222222", Some("a2"), true),
        record("gr-r1-blocked2", "2222222222222222", Some("b2"), false),
    ]);
    let audit = core.audit_execution(&sig, keys, Some(&log)).await;
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::BlockedButExecuted
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// E: a blocked record, no bytes, a sighting — still the alarm.
#[tokio::test]
async fn a_blocked_record_still_alarms_without_bytes() {
    let (log, dir) = trail(&[record("gr-r1-no", "3333333333333333", Some("b3"), false)]);
    let core = core_at(&cluster(Bytes::Null));
    let audit = core
        .audit_execution(
            &unrelated_signature(),
            ExecutionKeys {
                audit_trail_id: Some("gr-r1-no"),
                ..Default::default()
            },
            Some(&log),
        )
        .await;
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::BlockedButExecuted
    );
    assert!(audit.reconciliation.is_discrepancy());
    let _ = std::fs::remove_dir_all(&dir);
}

/// F: the chain's own bytes, bound to the signature, digesting to the
/// approved record — the positive conclusion is still reachable.
#[tokio::test]
async fn the_chains_own_bytes_still_reconcile_an_approved_execution() {
    let (tx, sig) = signed_transfer();
    let digest = bound_artifact_sha256(&tx, &sig).expect("bound");
    let (log, dir) = trail(&[record(
        "gr-r1-real",
        "4444444444444444",
        Some(&digest),
        true,
    )]);
    let core = core_at(&cluster(Bytes::Signed(tx)));
    let audit = core
        .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
        .await;
    assert_eq!(audit.attribution, ExecutionAttribution::Chain);
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::ApprovedAndExecuted
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// H: getTransaction errors — no bytes, so no approved execution either.
#[tokio::test]
async fn a_failed_bytes_fetch_is_not_an_approved_execution() {
    let (log, dir) = trail(&[record(
        "gr-r1-err",
        "5555555555555555",
        Some(APPROVED_TX),
        true,
    )]);
    let core = core_at(&cluster(Bytes::Error));
    let audit = core
        .audit_execution(
            &unrelated_signature(),
            ExecutionKeys {
                audit_trail_id: Some("gr-r1-err"),
                ..Default::default()
            },
            Some(&log),
        )
        .await;
    assert!(audit.chain_bytes_unavailable.is_some());
    not_approved_and_executed(&audit.reconciliation, "H getTransaction error");
    let _ = std::fs::remove_dir_all(&dir);
}
