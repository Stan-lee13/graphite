//! A4-01 (2026-09-29 audit): a blocked transaction the witness saw executed
//! alarms even when the primary RPC is unavailable.
//!
//! `docs/CURRENT.md` ("L8 inclusion evidence") and SECURITY.md (Round 12)
//! state that a blocked transaction sighted by either endpoint alarms, and
//! `audit_execution` fetches the bytes from the witness when the primary
//! cannot see the signature, so the alarm can name it. The Round 12 test
//! `round12_rpc_equivocation::either_endpoint_seeing_a_blocked_transaction_alarms`
//! covers a primary that answers `UnknownSignature`. When the primary was
//! unavailable (an HTTP 5xx, or a malformed status that
//! `get_signature_status` rightly refuses), the reconciliation's
//! `(ExecutionVerification::Unavailable(_), _)` arm matched before the
//! witness sighting was consulted, and a blocked transaction the witness
//! placed in a finalized block reconciled as `Unavailable`: no discrepancy
//! and no page. A primary that was down, or made to answer malformed,
//! suppressed the one alarm L8 exists for.
//!
//! The fix adds a first arm: a primary that is unavailable, a record that is
//! not approved, a witness that saw the signature, and chain bytes that were
//! not rejected give `BlockedButExecuted`.
//!
//! The test runs both ways for the primary to be unavailable against a witness
//! holding the transaction finalized, and pins `BlockedButExecuted` for each.
//! Every RPC here is a loopback mock.
#![cfg(feature = "rpc")]

use graphite_core::durable::{audit_path, AuditLog, AuditRecord, LifecycleEvent};
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::tx_artifact::{artifact_sha256_of_signed, message_bytes};
use graphite_core::verification::{
    ExecutionKeys, ExecutionReconciliation, ExecutionVerification, GraphiteCore,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

const SYSTEM: &str = "11111111111111111111111111111111";

fn payer() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32])
}

/// The corpus transfer under the test's fee payer, signed for real so the
/// chain's bytes bind to the signature (same construction as round12).
fn signed_transfer() -> Vec<u8> {
    use ed25519_dalek::Signer;
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/artifacts/sak_bridge_corpus.json"))
            .expect("corpus must parse");
    let entry = raw["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "legacy_single_transfer")
        .unwrap()
        .clone();
    let first_key = entry["static_keys"][0].as_str().unwrap();
    let old = bs58::decode(first_key).into_vec().unwrap();
    let mut frame: Vec<u8> = entry["raw"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect();
    let pos = frame
        .windows(32)
        .position(|w| w == old.as_slice())
        .expect("fee payer in frame");
    frame[pos..pos + 32].copy_from_slice(&payer().verifying_key().to_bytes());
    let sig = payer().sign(message_bytes(&frame).unwrap());
    frame[1..65].copy_from_slice(&sig.to_bytes());
    frame
}

type Answer = Arc<dyn Fn(&str) -> (u16, String) + Send + Sync>;

/// Loopback JSON-RPC mock: `answer(method) -> (http status, body)`.
fn cluster(answer: Answer) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let answer = Arc::clone(&answer);
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let method = req
                    .split("\r\n\r\n")
                    .nth(1)
                    .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                    .and_then(|v| v["method"].as_str().map(str::to_string))
                    .unwrap_or_default();
                let (status, body) = answer(&method);
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
            });
        }
    });
    format!("http://{addr}")
}

fn status_body(slot: u64, commitment: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":2}},"value":[{{"slot":{slot},"confirmations":null,"confirmationStatus":"{commitment}","err":null,"status":{{"Ok":null}}}}]}}}}"#
    )
}

fn tx_body(signed: &[u8], slot: u64) -> String {
    use base64::Engine;
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"slot":{slot},"transaction":["{}","base64"],"meta":{{"err":null}}}}}}"#,
        base64::engine::general_purpose::STANDARD.encode(signed)
    )
}

fn client(endpoint: &str) -> SolanaRpcClient {
    SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    })
}

fn temp_log(tag: &str) -> (AuditLog, std::path::PathBuf) {
    let d = std::env::temp_dir().join(format!(
        "graphite-a4-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    (AuditLog::open(audit_path(&d)).unwrap(), d)
}

fn record_blocked(log: &AuditLog, signed: &[u8]) -> AuditRecord {
    let r = AuditRecord {
        event_type: LifecycleEvent::Verification,
        timestamp: graphite_core::durable::now_utc_rfc3339(),
        audit_trail_id: "gr-a4-blocked".to_string(),
        content_hash: "48c65c638aceb5de".to_string(),
        transaction_sha256: Some(artifact_sha256_of_signed(signed).unwrap()),
        program_id: SYSTEM.to_string(),
        instruction_name: "Transfer".to_string(),
        protocol_name: "System Program".to_string(),
        manifest_version: Some("1.0.0".to_string()),
        approved: false,
        decision: None,
        executable: None,
        confidence: 0.3,
        risk_status: "Blocked".to_string(),
        policy_verdict: "Rejected".to_string(),
        l3_status: "inconclusive".to_string(),
        l8_status: "inconclusive".to_string(),
        wallet_profile: None,
    };
    assert!(log.append(&r));
    r
}

#[tokio::test]
async fn a_witness_sighting_of_a_blocked_transaction_alarms_even_when_the_primary_is_down() {
    let signed = signed_transfer();
    let sig = bs58::encode(&signed[1..65]).into_string();
    let (log, dir) = temp_log("witness-primary-down");
    let rec = record_blocked(&log, &signed);

    // The witness: an honest cluster that has the transaction FINALIZED.
    let witness_signed = signed.clone();
    let witness = cluster(Arc::new(move |method| match method {
        "getSignatureStatuses" => (200, status_body(777, "finalized")),
        "getTransaction" => (200, tx_body(&witness_signed, 777)),
        _ => (200, r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string()),
    }));

    // Two ways for the primary to be Unavailable.
    let down: Answer = Arc::new(|_| (503, r#"{"error":"overloaded"}"#.to_string()));
    let malformed: Answer = Arc::new(|_| {
        (
            200,
            r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":2},"value":[{"slot":777,"confirmationStatus":"finalized","status":{}}]}}"#
                .to_string(),
        )
    });
    let primaries: Vec<(&str, Answer)> = vec![
        ("primary answers HTTP 503", down),
        (
            "primary answers a malformed status (neither Ok nor Err)",
            malformed,
        ),
    ];

    let mut failures = Vec::new();
    for (label, answer) in primaries {
        let primary = cluster(answer);
        let mut core = GraphiteCore::new();
        core.attach_rpc_client(client(&primary));
        core.attach_inclusion_witness(client(&witness)).unwrap();
        // The bridge always supplies the exact keys; supplying them here too
        // shows that nothing the caller can add rescues the alarm.
        let audit = core
            .audit_execution(
                &sig,
                ExecutionKeys {
                    audit_trail_id: Some(&rec.audit_trail_id),
                    transaction_sha256: rec.transaction_sha256.as_deref(),
                    content_hash: Some(&rec.content_hash),
                },
                Some(&log),
            )
            .await;
        // Preconditions: the primary really was Unavailable, and the witness
        // really did see the signature.
        assert!(
            matches!(audit.chain_status, ExecutionVerification::Unavailable(_)),
            "{label}: precondition — primary should be Unavailable, got {:?}",
            audit.chain_status
        );
        let w = audit.inclusion_witness.as_ref().expect("witness consulted");
        assert_eq!(w.seen, Some(true), "{label}: witness must have seen it");
        assert_eq!(
            audit.recorded_approved,
            Some(false),
            "{label}: blocked on record"
        );

        if audit.reconciliation != ExecutionReconciliation::BlockedButExecuted {
            failures.push(format!(
                "{label}: a BLOCKED transaction the witness places in a finalized block reconciled as {:?} \
                 (discrepancy = {}), not BlockedButExecuted",
                audit.reconciliation,
                audit.reconciliation.is_discrepancy()
            ));
        }
    }
    let _ = std::fs::remove_dir_all(dir);
    assert!(
        failures.is_empty(),
        "either endpoint's sighting of a blocked transaction must alarm:\n{}",
        failures.join("\n")
    );
}

// ---------------------------------------------------------------------------
// External review (2026-10-16): the primary REPORTS the signature but cannot
// produce its bytes (getTransaction null or failing), or produces bytes that
// are not the signature's. The bytes were fetched from the primary alone, so
// with no caller key there was nothing to join the blocked record by, and a
// blocked transaction the witness had seen reconciled as "nothing to
// reconcile" — or, with substituted bytes, as Unavailable whatever the keys.

fn record_with(log: &AuditLog, signed: &[u8], id: &str, approved: bool) -> AuditRecord {
    let mut r = record_blocked_unappended(signed);
    r.audit_trail_id = id.to_string();
    r.approved = approved;
    if approved {
        r.risk_status = "Clear".to_string();
        r.policy_verdict = "Approved".to_string();
    }
    assert!(log.append(&r));
    r
}

fn record_blocked_unappended(signed: &[u8]) -> AuditRecord {
    AuditRecord {
        event_type: LifecycleEvent::Verification,
        timestamp: graphite_core::durable::now_utc_rfc3339(),
        audit_trail_id: "gr-r25".to_string(),
        content_hash: "48c65c638aceb5de".to_string(),
        transaction_sha256: Some(artifact_sha256_of_signed(signed).unwrap()),
        program_id: SYSTEM.to_string(),
        instruction_name: "Transfer".to_string(),
        protocol_name: "System Program".to_string(),
        manifest_version: Some("1.0.0".to_string()),
        approved: false,
        decision: None,
        executable: None,
        confidence: 0.3,
        risk_status: "Blocked".to_string(),
        policy_verdict: "Rejected".to_string(),
        l3_status: "inconclusive".to_string(),
        l8_status: "inconclusive".to_string(),
        wallet_profile: None,
    }
}

/// The same transfer with a different blockhash, signed: a real transaction,
/// but not the one the audited signature belongs to.
fn another_signed_transfer() -> Vec<u8> {
    use ed25519_dalek::Signer;
    let mut frame = signed_transfer();
    let msg_len = message_bytes(&frame).unwrap().len();
    let msg_start = frame.len() - msg_len;
    // The blockhash sits after the header and the keys; flipping the last
    // message byte changes the instruction data instead, which is just as
    // much another transaction.
    let last = frame.len() - 1;
    frame[last] ^= 0x01;
    let sig = payer().sign(&frame[msg_start..]);
    frame[1..65].copy_from_slice(&sig.to_bytes());
    frame
}

/// A primary that reports the signature confirmed and answers getTransaction
/// with `tx` (an HTTP status and body).
fn confirmed_primary(tx: (u16, String)) -> String {
    cluster(Arc::new(move |method| match method {
        "getSignatureStatuses" => (200, status_body(777, "finalized")),
        "getTransaction" => tx.clone(),
        _ => (200, r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string()),
    }))
}

fn honest_witness(signed: &[u8]) -> String {
    let signed = signed.to_vec();
    cluster(Arc::new(move |method| match method {
        "getSignatureStatuses" => (200, status_body(777, "finalized")),
        "getTransaction" => (200, tx_body(&signed, 777)),
        _ => (200, r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string()),
    }))
}

const NO_KEYS: ExecutionKeys<'static> = ExecutionKeys {
    audit_trail_id: None,
    transaction_sha256: None,
    content_hash: None,
};

#[tokio::test]
async fn a_primary_without_the_bytes_does_not_hide_a_blocked_transaction_the_witness_saw() {
    let signed = signed_transfer();
    let sig = bs58::encode(&signed[1..65]).into_string();
    let null = (200, r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string());
    let failing = (500, r#"{"error":"getTransaction unavailable"}"#.to_string());
    for (label, tx) in [
        ("getTransaction returns null", null),
        ("getTransaction fails", failing),
    ] {
        let (log, dir) = temp_log("r25-null-bytes");
        record_with(&log, &signed, "gr-r25-blocked", false);
        let mut core = GraphiteCore::new();
        core.attach_rpc_client(client(&confirmed_primary(tx)));
        core.attach_inclusion_witness(client(&honest_witness(&signed)))
            .unwrap();
        let audit = core.audit_execution(&sig, NO_KEYS, Some(&log)).await;
        assert!(
            matches!(audit.chain_status, ExecutionVerification::Confirmed { .. }),
            "{label}: precondition — the primary reports the signature"
        );
        assert_eq!(
            audit.chain_transaction_sha256.as_deref(),
            Some(artifact_sha256_of_signed(&signed).unwrap().as_str()),
            "{label}: the witness's bound bytes give the digest"
        );
        assert_eq!(
            audit.reconciliation,
            ExecutionReconciliation::BlockedButExecuted,
            "{label}: {:?}",
            audit.chain_bytes_unavailable
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[tokio::test]
async fn substituted_bytes_from_the_primary_do_not_silence_the_witness() {
    let signed = signed_transfer();
    let sig = bs58::encode(&signed[1..65]).into_string();
    let other = another_signed_transfer();
    assert_ne!(
        other[1..65],
        signed[1..65],
        "precondition: another signature"
    );
    let substituted = (200, tx_body(&other, 777));

    // A blocked record: the witness's bound bytes find it, and it alarms.
    let (log, dir) = temp_log("r25-substituted-blocked");
    record_with(&log, &signed, "gr-r25-sub-blocked", false);
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(client(&confirmed_primary(substituted.clone())));
    core.attach_inclusion_witness(client(&honest_witness(&signed)))
        .unwrap();
    let audit = core.audit_execution(&sig, NO_KEYS, Some(&log)).await;
    assert!(
        audit.chain_bytes_rejected.is_some(),
        "the substitution is recorded"
    );
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::BlockedButExecuted
    );
    let _ = std::fs::remove_dir_all(dir);

    // An approved record: sources that disagree about the bytes conclude nothing.
    let (log, dir) = temp_log("r25-substituted-approved");
    record_with(&log, &signed, "gr-r25-sub-approved", true);
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(client(&confirmed_primary(substituted)));
    core.attach_inclusion_witness(client(&honest_witness(&signed)))
        .unwrap();
    let audit = core.audit_execution(&sig, NO_KEYS, Some(&log)).await;
    assert!(
        matches!(
            audit.reconciliation,
            ExecutionReconciliation::Unavailable { .. }
        ),
        "{:?}",
        audit.reconciliation
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn an_approved_transaction_is_reconciled_from_the_witnesss_bound_bytes() {
    let signed = signed_transfer();
    let sig = bs58::encode(&signed[1..65]).into_string();
    let (log, dir) = temp_log("r25-approved-witness-bytes");
    record_with(&log, &signed, "gr-r25-approved", true);
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(client(&confirmed_primary((
        200,
        r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
    ))));
    core.attach_inclusion_witness(client(&honest_witness(&signed)))
        .unwrap();
    let audit = core.audit_execution(&sig, NO_KEYS, Some(&log)).await;
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::ApprovedAndExecuted
    );
    assert!(
        audit.chain_bytes_unavailable.is_none(),
        "the miss is superseded"
    );
    let _ = std::fs::remove_dir_all(dir);
}
