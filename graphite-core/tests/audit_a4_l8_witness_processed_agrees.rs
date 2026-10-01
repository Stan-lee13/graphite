//! A4-08 (2026-09-29 audit): a witness that holds the signature only at
//! `processed` does not count as agreeing.
//!
//! Round 12 says `processed` is one node's view and not inclusion
//! (`rpc_client::InclusionCommitment`), and `docs/CURRENT.md` says that with
//! `GRAPHITE_RPC_WITNESS_URL` two independent endpoints must agree before an
//! approval is reported executed. `compare_witness` compared slot and outcome
//! only, and `audit_execution` checked `is_cluster_backed()` on the primary's
//! commitment only, so a witness at `processed` agreed and the approval was
//! reported `ApprovedAndExecuted` on one cluster-backed view plus one
//! single-node view.
//!
//! The fix: a witness agrees only at a cluster-backed commitment. A sighting
//! at `processed` still counts as a sighting, so for a blocked transaction it
//! still alarms at any commitment.
//!
//! The test serves an approved transaction finalized on the primary and
//! processed on the witness, and pins that the reconciliation is not
//! `ApprovedAndExecuted`.
#![cfg(feature = "rpc")]

use graphite_core::durable::{audit_path, AuditLog, AuditRecord, LifecycleEvent};
use graphite_core::rpc_client::{InclusionCommitment, RpcConfig, SolanaRpcClient};
use graphite_core::tx_artifact::{artifact_sha256_of_signed, message_bytes};
use graphite_core::verification::{ExecutionKeys, ExecutionReconciliation, GraphiteCore};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

fn payer() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32])
}

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
    let old = bs58::decode(entry["static_keys"][0].as_str().unwrap())
        .into_vec()
        .unwrap();
    let mut frame: Vec<u8> = entry["raw"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect();
    let pos = frame.windows(32).position(|w| w == old.as_slice()).unwrap();
    frame[pos..pos + 32].copy_from_slice(&payer().verifying_key().to_bytes());
    let sig = payer().sign(message_bytes(&frame).unwrap());
    frame[1..65].copy_from_slice(&sig.to_bytes());
    frame
}

fn cluster(answer: Arc<dyn Fn(&str) -> String + Send + Sync>) -> String {
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
                let body = answer(&method);
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

fn honest(
    signed: Vec<u8>,
    slot: u64,
    commitment: &'static str,
) -> Arc<dyn Fn(&str) -> String + Send + Sync> {
    Arc::new(move |method| {
        use base64::Engine;
        match method {
            "getSignatureStatuses" => format!(
                r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":2}},"value":[{{"slot":{slot},"confirmations":null,"confirmationStatus":"{commitment}","err":null,"status":{{"Ok":null}}}}]}}}}"#
            ),
            "getTransaction" => format!(
                r#"{{"jsonrpc":"2.0","id":1,"result":{{"slot":{slot},"transaction":["{}","base64"],"meta":{{"err":null}}}}}}"#,
                base64::engine::general_purpose::STANDARD.encode(&signed)
            ),
            _ => r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
        }
    })
}

fn client(endpoint: &str) -> SolanaRpcClient {
    SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    })
}

#[tokio::test]
async fn a_witness_at_processed_is_not_a_second_source_of_inclusion() {
    let signed = signed_transfer();
    let sig = bs58::encode(&signed[1..65]).into_string();
    let dir = std::env::temp_dir().join(format!(
        "graphite-a4-wproc-{}-{}",
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
        audit_trail_id: "gr-a4-approved".to_string(),
        content_hash: "48c65c638aceb5de".to_string(),
        transaction_sha256: Some(artifact_sha256_of_signed(&signed).unwrap()),
        program_id: "11111111111111111111111111111111".to_string(),
        instruction_name: "Transfer".to_string(),
        protocol_name: "System Program".to_string(),
        manifest_version: Some("1.0.0".to_string()),
        approved: true,
        confidence: 0.9,
        risk_status: "Clear".to_string(),
        policy_verdict: "Approved".to_string(),
        l3_status: "inconclusive".to_string(),
        l8_status: "inconclusive".to_string(),
        wallet_profile: None,
    }));

    let primary = cluster(honest(signed.clone(), 4242, "finalized"));
    let witness = cluster(honest(signed.clone(), 4242, "processed"));
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(client(&primary));
    core.attach_inclusion_witness(client(&witness)).unwrap();
    let audit = core
        .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
        .await;
    let _ = std::fs::remove_dir_all(&dir);

    let w = audit.inclusion_witness.as_ref().expect("witness consulted");
    assert_eq!(
        w.commitment,
        Some(InclusionCommitment::Processed),
        "precondition"
    );
    assert_ne!(
        audit.reconciliation,
        ExecutionReconciliation::ApprovedAndExecuted,
        "the witness holds the signature only at `processed` (one node's view, 'not inclusion'), \
         yet it was counted as the second, agreeing source (witness: {:?})",
        w
    );
}
