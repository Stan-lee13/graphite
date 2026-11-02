//! Audit W23 (A010, D-45): a signed verdict that was not executable is not
//! an approval that executed.
//!
//! Since Round 30 only `decision == executable_approved` permits signing.
//! L8 decided on `approved` alone: an `analysis_only` record (not simulated,
//! or the request's amount not bound to the bytes) whose transaction landed
//! reconciled as `ApprovedAndExecuted`, "the expected case", with no
//! discrepancy. It is now `NotExecutableButExecuted`, a discrepancy unless
//! the signer put the residuals it accepted on its signing event (the agent
//! guard's operator-accepted path), which is then attributable, not silent.
#![cfg(feature = "rpc")]

use graphite_core::durable::{
    audit_path, AuditLog, AuditRecord, LifecycleEvent, LifecycleEventRecord,
};
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::tx_artifact::bound_artifact_sha256;
use graphite_core::verification::{
    ExecutionAttribution, ExecutionKeys, ExecutionReconciliation, GraphiteCore,
};
use std::io::{Read, Write};
use std::net::TcpListener;

#[derive(Clone)]
enum Bytes {
    Signed(Vec<u8>),
    /// The bytes, and the `blockTime` the response states (audit A082).
    SignedAt(Vec<u8>, i64),
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
                        Bytes::Signed(b) => format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"slot":12345,"transaction":["{}","base64"],"meta":{{"err":null}}}}}}"#,
                            base64::engine::general_purpose::STANDARD.encode(b)
                        ),
                        Bytes::SignedAt(b, t) => format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"slot":12345,"blockTime":{t},"transaction":["{}","base64"],"meta":{{"err":null}}}}}}"#,
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
        decision: None,
        executable: None,
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
        "graphite-w23-{}-{}",
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

fn with_decision(
    mut r: AuditRecord,
    decision: Option<&str>,
    executable: Option<bool>,
) -> AuditRecord {
    r.decision = decision.map(str::to_string);
    r.executable = executable;
    r
}

fn signing(id: &str, accepted: &[&str]) -> LifecycleEventRecord {
    LifecycleEventRecord {
        event_type: LifecycleEvent::Signing,
        timestamp: graphite_core::durable::now_utc_rfc3339(),
        content_hash: "5555555555555555".to_string(),
        verdict_on_record: None,
        verdict_on_record_key: None,
        transaction_sha256: None,
        audit_trail_id: Some(id.to_string()),
        transaction_signature: None,
        reported_by: Some("guard".to_string()),
        detail: None,
        observed_by_graphite: false,
        sequence_anomalies: Vec::new(),
        accepted_unobserved: accepted.iter().map(|s| s.to_string()).collect(),
    }
}

async fn reconcile(r: AuditRecord, events: &[LifecycleEventRecord]) -> ExecutionReconciliation {
    let (tx, sig) = signed_transfer();
    let digest = bound_artifact_sha256(&tx, &sig).expect("bound");
    let mut r = r;
    r.transaction_sha256 = Some(digest);
    let (log, dir) = trail(&[r]);
    for e in events {
        assert!(log.append_lifecycle(e));
    }
    let core = core_at(&cluster(Bytes::Signed(tx)));
    let audit = core
        .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
        .await;
    assert_eq!(audit.attribution, ExecutionAttribution::Chain);
    let _ = std::fs::remove_dir_all(&dir);
    audit.reconciliation
}

#[tokio::test]
async fn an_analysis_only_verdict_that_executed_is_a_discrepancy() {
    for (decision, executable) in [
        (Some("analysis_only"), Some(false)),
        (Some("inconclusive"), Some(false)),
        // A decision that disagrees with `executable` is not executable.
        (Some("analysis_only"), Some(true)),
        (Some("executable_approved"), Some(false)),
        (None, Some(false)),
    ] {
        let r = with_decision(
            record("gr-w23-a", "5555555555555555", None, true),
            decision,
            executable,
        );
        let got = reconcile(r, &[]).await;
        assert!(
            matches!(&got, ExecutionReconciliation::NotExecutableButExecuted { accepted_unobserved, .. } if accepted_unobserved.is_empty()),
            "{decision:?}/{executable:?}: {got:?}"
        );
        assert!(got.is_discrepancy(), "{decision:?}/{executable:?}");
    }
}

#[tokio::test]
async fn a_signer_that_named_the_residuals_it_accepted_is_attributed_not_paged() {
    let r = with_decision(
        record("gr-w23-b", "5555555555555555", None, true),
        Some("analysis_only"),
        Some(false),
    );
    let got = reconcile(r.clone(), &[signing("gr-w23-b", &["not_simulated"])]).await;
    match &got {
        ExecutionReconciliation::NotExecutableButExecuted {
            decision,
            accepted_unobserved,
        } => {
            assert_eq!(decision, "analysis_only");
            assert_eq!(accepted_unobserved, &vec!["not_simulated".to_string()]);
        }
        other => panic!("{other:?}"),
    }
    assert!(!got.is_discrepancy());
    // Another verification's signing event accepts nothing for this one.
    let got = reconcile(r, &[signing("gr-w23-other", &["not_simulated"])]).await;
    assert!(got.is_discrepancy(), "{got:?}");
}

#[tokio::test]
async fn an_executable_approval_and_a_pre_round_30_row_still_reconcile_as_before() {
    for (decision, executable) in [(Some("executable_approved"), Some(true)), (None, None)] {
        let r = with_decision(
            record("gr-w23-c", "5555555555555555", None, true),
            decision,
            executable,
        );
        let got = reconcile(r, &[]).await;
        assert!(
            matches!(got, ExecutionReconciliation::ApprovedAndExecuted),
            "{decision:?}: {got:?}"
        );
    }
}

/// Audit A082: with the chain's bytes, L8 attributed an execution to the
/// LAST verification recorded under their digest. Anyone with verify access
/// could take a landed transaction executed under an executable approval,
/// zero its signature slots and re-verify it (a wrong amount, a stricter
/// profile): the refusal was then the latest record, and every later L8
/// call reported `BlockedButExecuted`, "the gate was bypassed". The verdict
/// that governed an execution is the latest one recorded by the time it
/// executed (`blockTime`); later verdicts are counted in `recorded_verdicts`
/// and decide nothing. The same rule keeps a refusal that was bypassed an
/// alarm when an approval of the same bytes is obtained afterwards.
#[tokio::test]
async fn a_verdict_recorded_after_the_execution_does_not_reattribute_it() {
    use graphite_core::durable::rfc3339_utc;
    let (tx, sig) = signed_transfer();
    let digest = bound_artifact_sha256(&tx, &sig).expect("bound");
    let block_time: i64 = 1_790_000_000;
    let at = |offset: i64, r: AuditRecord| AuditRecord {
        timestamp: rfc3339_utc((block_time + offset) as u64, 0),
        transaction_sha256: Some(digest.clone()),
        ..r
    };
    let approved = || {
        with_decision(
            record("gr-a082-approved", "5555555555555555", None, true),
            Some("executable_approved"),
            Some(true),
        )
    };
    let refused = || {
        with_decision(
            record("gr-a082-refused", "5555555555555555", None, false),
            Some("blocked"),
            Some(false),
        )
    };
    let run = |records: Vec<AuditRecord>| {
        let tx = tx.clone();
        let sig = sig.clone();
        async move {
            let (log, dir) = trail(&records);
            let core = core_at(&cluster(Bytes::SignedAt(tx, block_time)));
            let audit = core
                .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
                .await;
            let _ = std::fs::remove_dir_all(&dir);
            audit
        }
    };

    // Approved before it executed; refused by someone re-verifying it two
    // minutes later.
    let audit = run(vec![at(-5, approved()), at(120, refused())]).await;
    assert_eq!(audit.attribution, ExecutionAttribution::Chain);
    assert!(
        matches!(
            audit.reconciliation,
            ExecutionReconciliation::ApprovedAndExecuted
        ),
        "a later re-verification paged the operator: {:?}",
        audit.reconciliation
    );
    assert!(!audit.reconciliation.is_discrepancy());
    let counts = audit.recorded_verdicts.expect("counted");
    assert_eq!((counts.approved, counts.refused), (1, 1));

    // Refused before it executed (the gate was bypassed), approved after:
    // still the alarm.
    let audit = run(vec![at(-5, refused()), at(120, approved())]).await;
    assert!(
        matches!(
            audit.reconciliation,
            ExecutionReconciliation::BlockedButExecuted
        ),
        "an approval obtained after the execution laundered a bypass: {:?}",
        audit.reconciliation
    );

    // Nothing recorded by the time it executed: no verdict governed it.
    let audit = run(vec![at(120, refused())]).await;
    assert!(
        matches!(
            audit.reconciliation,
            ExecutionReconciliation::NoVerificationOnRecord
        ),
        "{:?}",
        audit.reconciliation
    );
}
