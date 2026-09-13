//! Requires the `rpc` feature: attribution is a question the chain answers.
#![cfg(feature = "rpc")]

//! Round 10: exact execution attribution.
//!
//! `content_hash` is one instruction's projection — program, discriminator,
//! accounts, data, CPI targets. Every transaction carrying that instruction
//! shares it: the same transfer beside a malicious sibling, under a different
//! fee payer, signer set or blockhash, is a different transaction with the
//! same `content_hash`. Until Round 10 it was the only key L8 and the
//! lifecycle rows joined on, so `last_verification_for(content_hash)`
//! answered for whichever such transaction was verified LAST — and the
//! approval of A could be returned for the execution of B.
//!
//! The chain settles it. The bytes behind a signature, with their signature
//! slots zeroed, are exactly the artifact Graphite was shown, and their
//! SHA-256 is `scope.transaction_sha256` of the verification of those bytes.
//! L8 now fetches them (`getTransaction`, base64), digests them, and joins on
//! that; the caller's keys are cross-checked against it and stand in only
//! when the chain's bytes cannot be fetched — most exact first, never falling
//! back to a coarser one.
//!
//! A is the corpus's own transfer (approved). B is the same transfer on the
//! same keys with an undeclared 100 SOL sibling to a fourth key (blocked at
//! L2). Their `content_hash` is identical; their digests are not.

use graphite_core::durable::{audit_path, AuditLog, VerificationKey};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::tx_artifact::{artifact_sha256_of_signed, unsigned_artifact};
use graphite_core::verification::{
    ExecutionAttribution, ExecutionKeys, ExecutionReconciliation, GraphiteCore, LayerStatus,
    ProposedIntent, VerificationInput, VerificationResult, VerificationScope,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

const SYSTEM: &str = "11111111111111111111111111111111";
const SIG: &str = "5sigAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn corpus_entry(name: &str) -> serde_json::Value {
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/artifacts/sak_bridge_corpus.json"))
            .expect("corpus must parse");
    raw["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|e| e["name"] == name)
        .unwrap_or_else(|| panic!("corpus entry {name}"))
        .clone()
}

fn bytes(v: &serde_json::Value) -> Vec<u8> {
    v.as_array()
        .expect("byte array")
        .iter()
        .map(|n| n.as_u64().expect("byte") as u8)
        .collect()
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect()
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

fn transfer_data(lamports: u64) -> Vec<u8> {
    let mut d = vec![2, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d
}

/// A: the corpus's `legacy_single_transfer`, unsigned, as web3.js serialized it.
fn tx_a() -> Vec<u8> {
    bytes(&corpus_entry("legacy_single_transfer")["raw"])
}

/// B: the same transfer on the same keys, then an undeclared 100 SOL transfer
/// from the payer to a fourth key. Encoded field by field.
fn tx_b() -> Vec<u8> {
    let keys = strings(&corpus_entry("legacy_single_transfer")["static_keys"]);
    let attacker = [0xA7u8; 32];
    let mut out = Vec::new();
    compact_u16(1, &mut out);
    out.extend_from_slice(&[0u8; 64]);
    out.extend_from_slice(&[1, 0, 1]);
    compact_u16(4, &mut out);
    out.extend_from_slice(&bs58::decode(&keys[0]).into_vec().unwrap());
    out.extend_from_slice(&bs58::decode(&keys[1]).into_vec().unwrap());
    out.extend_from_slice(&attacker);
    out.extend_from_slice(&bs58::decode(SYSTEM).into_vec().unwrap());
    out.extend_from_slice(&[9u8; 32]);
    compact_u16(2, &mut out);
    for (to, lamports) in [(1u8, 2_000_000u64), (2, 100_000_000_000)] {
        out.push(3);
        compact_u16(2, &mut out);
        out.extend_from_slice(&[0, to]);
        let d = transfer_data(lamports);
        compact_u16(d.len(), &mut out);
        out.extend_from_slice(&d);
    }
    out
}

/// What the chain holds: the same frame with a real-looking signature in the
/// slot the artifact left empty.
fn signed(unsigned: &[u8]) -> Vec<u8> {
    let mut s = unsigned.to_vec();
    for (i, b) in s[1..65].iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    s
}

fn account(lamports: u64) -> String {
    format!(
        r#"{{"lamports":{lamports},"owner":"{SYSTEM}","executable":false,"rentEpoch":0,"data":["","base64"]}}"#
    )
}

/// The chain's account of signature `SIG`: `None` = the cluster has no
/// transaction bytes for it (an RPC without `getTransaction`, or pruned).
type ChainBytes = Arc<Mutex<Option<Vec<u8>>>>;

/// A mock cluster: approves any simulation, confirms `SIG`, and serves
/// whatever bytes `chain` holds for `getTransaction`.
fn cluster(chain: ChainBytes) -> String {
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").unwrap());
    let addr = listener.local_addr().unwrap();
    let server = Arc::clone(&listener);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = server.accept() {
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let body_json: serde_json::Value = req
                .split("\r\n\r\n")
                .nth(1)
                .and_then(|b| serde_json::from_str(b).ok())
                .unwrap_or(serde_json::Value::Null);
            let method = body_json["method"].as_str().unwrap_or("?").to_string();
            let body = match method.as_str() {
                "getMultipleAccounts" => {
                    let count = body_json["params"][0].as_array().map(|a| a.len()).unwrap_or(0);
                    let vals: Vec<String> = (0..count)
                        .map(|i| account(if i == 0 { 1_000_000_000 } else { 1_000_000 }))
                        .collect();
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":[{}]}}}}"#,
                        vals.join(",")
                    )
                }
                "simulateTransaction" => {
                    let count = body_json["params"][1]["accounts"]["addresses"]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let post: Vec<String> = (0..count)
                        .map(|i| account(if i == 0 { 998_995_000 } else { 2_000_000 }))
                        .collect();
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
                            "err":null,"logs":[],"unitsConsumed":150,"fee":5000,
                            "preBalances":[1000000000,1000000,1],"postBalances":[998995000,2000000,1],
                            "innerInstructions":[],"loadedAddresses":{{"writable":[],"readonly":[]}},
                            "accounts":[{}],"returnData":null}}}}}}"#,
                        post.join(",")
                    )
                }
                "getSignatureStatuses" => {
                    r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":2},"value":[{"slot":12345,"confirmations":0,"err":null,"status":{"Ok":null}}]}}"#.to_string()
                }
                "getTransaction" => match chain.lock().unwrap().clone() {
                    Some(b) => {
                        use base64::Engine;
                        format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"slot":12345,"transaction":["{}","base64"],"meta":{{"err":null}}}}}}"#,
                            base64::engine::general_purpose::STANDARD.encode(b)
                        )
                    }
                    None => r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
                },
                _ => r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
            };
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });
    std::mem::forget(listener);
    format!("http://{addr}")
}

fn core_at(endpoint: &str) -> GraphiteCore {
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    }));
    core
}

/// The one description both A and B are verified under: the corpus transfer,
/// no siblings declared.
fn describe(artifact: Vec<u8>) -> VerificationInput {
    let keys = strings(&corpus_entry("legacy_single_transfer")["static_keys"]);
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send 0.002 SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![keys[0].clone(), keys[1].clone()],
        instruction_data: Some(transfer_data(2_000_000)),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 5,
            battle_tested_tx_count: 50_000,
            simulation_match_count: 100,
        },
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: Some(artifact),
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

fn digest(r: &VerificationResult) -> String {
    match &r.scope {
        VerificationScope::ArtifactBound {
            transaction_sha256, ..
        } => transaction_sha256.clone(),
        VerificationScope::Descriptive { .. } => panic!("artifact-bound expected"),
    }
}

fn temp_log(tag: &str) -> (AuditLog, std::path::PathBuf) {
    let d = std::env::temp_dir().join(format!(
        "graphite-r10-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|x| x.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap();
    (AuditLog::open(audit_path(&d)).unwrap(), d)
}

/// Verify, and write the row `/verify` would write.
async fn verify_and_record(
    core: &GraphiteCore,
    log: &AuditLog,
    artifact: Vec<u8>,
) -> VerificationResult {
    let r = core
        .verify_async(&describe(artifact))
        .await
        .expect("verification must run");
    assert!(log.append(&graphite_core::durable::AuditRecord {
        event_type: graphite_core::durable::LifecycleEvent::Verification,
        timestamp: graphite_core::durable::now_utc_rfc3339(),
        audit_trail_id: r.audit_trail_id.clone(),
        content_hash: r.content_hash.clone(),
        transaction_sha256: Some(digest(&r)),
        program_id: SYSTEM.to_string(),
        instruction_name: r.instruction_name.clone(),
        protocol_name: r.protocol_name.clone(),
        manifest_version: r.manifest_version.clone(),
        approved: r.approved,
        confidence: r.confidence,
        risk_status: r.risk_verdict.status.clone(),
        policy_verdict: r.policy_verdict.clone(),
        l3_status: "inconclusive".to_string(),
        l8_status: "inconclusive".to_string(),
    }));
    r
}

/// Warm the baseline, then verify B (blocked, undeclared sibling) and A
/// (approved) in that order, so A is the NEWEST record under their shared
/// `content_hash`. Returns (log, dir, A, B).
async fn a_then_b(
    core: &GraphiteCore,
) -> (
    AuditLog,
    std::path::PathBuf,
    VerificationResult,
    VerificationResult,
) {
    for _ in 0..3 {
        let _ = core.verify_async(&describe(tx_a())).await;
    }
    let (log, dir) = temp_log("ab");
    let b = verify_and_record(core, &log, tx_b()).await;
    let a = verify_and_record(core, &log, tx_a()).await;
    (log, dir, a, b)
}

// ─── The shared key ──────────────────────────────────────────────────────────

/// A and B share a `content_hash` and nothing else that identifies a
/// transaction. So does A with the corpus's same transfer under another
/// blockhash.
#[tokio::test]
async fn the_same_instruction_in_different_transactions_shares_a_content_hash_but_not_a_digest() {
    let chain: ChainBytes = Arc::new(Mutex::new(None));
    let core = core_at(&cluster(chain));
    let (_log, dir, a, b) = a_then_b(&core).await;
    assert!(a.approved, "{}", a.summary);
    assert!(!b.approved, "{}", b.summary);
    let l2 = b
        .layers
        .iter()
        .find(|l| l.layer == "L2_InstructionVerification")
        .unwrap();
    assert_eq!(l2.status, LayerStatus::Failed, "{}", l2.reason);
    assert!(l2.reason.contains("does not describe"), "{}", l2.reason);
    assert_eq!(
        a.content_hash, b.content_hash,
        "the instruction projection is identical"
    );
    assert_ne!(digest(&a), digest(&b), "the transactions are not");
    assert_ne!(a.audit_trail_id, b.audit_trail_id);

    let other = core
        .verify_async(&describe(bytes(
            &corpus_entry("legacy_other_blockhash")["raw"],
        )))
        .await
        .unwrap();
    assert_eq!(
        other.content_hash, a.content_hash,
        "a different blockhash: same content_hash"
    );
    assert_ne!(
        digest(&other),
        digest(&a),
        "different bytes, different digest"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Zeroing the signature slots of a signed frame yields the artifact the
/// bridge sent, so the chain's bytes digest to `scope.transaction_sha256`.
#[test]
fn a_signed_transaction_digests_to_the_artifact_it_was_signed_from() {
    for unsigned in [tx_a(), tx_b()] {
        let s = signed(&unsigned);
        assert_ne!(s, unsigned, "the signature slot was filled");
        assert_eq!(unsigned_artifact(&s).unwrap(), unsigned);
        use sha2::{Digest, Sha256};
        assert_eq!(
            artifact_sha256_of_signed(&s).unwrap(),
            hex::encode(Sha256::digest(&unsigned))
        );
        // Unsigned in, unsigned out.
        assert_eq!(unsigned_artifact(&unsigned).unwrap(), unsigned);
    }
    // A frame the packet bound refuses is refused here too.
    let big = vec![1u8; 1233];
    assert!(unsigned_artifact(&big).is_err());
    // A signature array past the input is refused, not partially zeroed.
    assert!(unsigned_artifact(&[2u8, 0, 0, 0]).is_err());
}

// ─── The attribution ────────────────────────────────────────────────────────

/// THE case. B (blocked) is what executed; A (approved, same content_hash)
/// is the newest record. With the chain's bytes, L8 joins on B's digest and
/// reports the bypass. The caller's `content_hash` agrees with both and is
/// not what decided.
#[tokio::test]
async fn an_executed_blocked_transaction_is_attributed_by_the_chain_not_by_its_content_hash() {
    let chain: ChainBytes = Arc::new(Mutex::new(None));
    let core = core_at(&cluster(Arc::clone(&chain)));
    let (log, dir, a, b) = a_then_b(&core).await;
    *chain.lock().unwrap() = Some(signed(&tx_b()));

    let audit = core
        .audit_execution(
            SIG,
            ExecutionKeys {
                content_hash: Some(&a.content_hash),
                ..Default::default()
            },
            Some(&log),
        )
        .await;
    assert_eq!(audit.attribution, ExecutionAttribution::Chain);
    assert_eq!(
        audit.chain_transaction_sha256.as_deref(),
        Some(digest(&b).as_str())
    );
    assert_eq!(
        audit.recorded_audit_trail_id.as_deref(),
        Some(b.audit_trail_id.as_str())
    );
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::BlockedButExecuted
    );
    assert!(audit.reconciliation.is_discrepancy());
    assert!(
        audit.caller_keys_disagree.is_empty(),
        "{:?}",
        audit.caller_keys_disagree
    );

    // And A's own execution is A's approval, by the same route.
    *chain.lock().unwrap() = Some(signed(&tx_a()));
    let audit = core
        .audit_execution(SIG, ExecutionKeys::default(), Some(&log))
        .await;
    assert_eq!(audit.attribution, ExecutionAttribution::Chain);
    assert_eq!(
        audit.recorded_audit_trail_id.as_deref(),
        Some(a.audit_trail_id.as_str())
    );
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::ApprovedAndExecuted
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A caller that names the wrong verification is told so, and the answer is
/// still the chain's.
#[tokio::test]
async fn caller_keys_that_name_a_different_verification_are_reported_not_believed() {
    let chain: ChainBytes = Arc::new(Mutex::new(None));
    let core = core_at(&cluster(Arc::clone(&chain)));
    let (log, dir, a, b) = a_then_b(&core).await;
    *chain.lock().unwrap() = Some(signed(&tx_b()));
    let a_digest = digest(&a);
    let audit = core
        .audit_execution(
            SIG,
            ExecutionKeys {
                content_hash: Some(&a.content_hash),
                transaction_sha256: Some(&a_digest),
                audit_trail_id: Some(&a.audit_trail_id),
            },
            Some(&log),
        )
        .await;
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::BlockedButExecuted
    );
    assert_eq!(
        audit.recorded_audit_trail_id.as_deref(),
        Some(b.audit_trail_id.as_str())
    );
    assert_eq!(
        audit.caller_keys_disagree.len(),
        2,
        "{:?}",
        audit.caller_keys_disagree
    );
    assert!(audit
        .caller_keys_disagree
        .iter()
        .any(|d| d.starts_with("audit_trail_id")));
    assert!(audit
        .caller_keys_disagree
        .iter()
        .any(|d| d.starts_with("transaction_sha256")));
    std::fs::remove_dir_all(&dir).ok();
}

/// Bytes that were never verified — the corpus transfer under a blockhash
/// nobody submitted to Graphite — are an execution Graphite never saw, even
/// though a verification with the same `content_hash` was approved.
#[tokio::test]
async fn an_execution_of_unverified_bytes_is_not_attributed_to_a_sibling_verification() {
    let chain: ChainBytes = Arc::new(Mutex::new(None));
    let core = core_at(&cluster(Arc::clone(&chain)));
    let (log, dir, a, _b) = a_then_b(&core).await;
    *chain.lock().unwrap() = Some(signed(&bytes(
        &corpus_entry("legacy_other_blockhash")["raw"],
    )));
    let audit = core
        .audit_execution(
            SIG,
            ExecutionKeys {
                content_hash: Some(&a.content_hash),
                ..Default::default()
            },
            Some(&log),
        )
        .await;
    assert_eq!(audit.attribution, ExecutionAttribution::Chain);
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::NoVerificationOnRecord
    );
    assert!(audit.recorded_audit_trail_id.is_none());
    std::fs::remove_dir_all(&dir).ok();
}

/// Without the chain's bytes, the caller's most exact key decides — and the
/// `content_hash`-only case is exactly the pre-Round-10 answer, now labelled
/// as such: A's approval, for B's execution.
#[tokio::test]
async fn without_chain_bytes_the_most_exact_caller_key_decides_and_content_hash_alone_is_ambiguous()
{
    let chain: ChainBytes = Arc::new(Mutex::new(None));
    let core = core_at(&cluster(Arc::clone(&chain)));
    let (log, dir, a, b) = a_then_b(&core).await;
    // The cluster has no bytes for SIG.
    assert!(chain.lock().unwrap().is_none());

    // content_hash only: the newest record under it is A. This is the
    // ambiguity, and the attribution says so.
    let audit = core
        .audit_execution(
            SIG,
            ExecutionKeys {
                content_hash: Some(&b.content_hash),
                ..Default::default()
            },
            Some(&log),
        )
        .await;
    assert_eq!(audit.attribution, ExecutionAttribution::ContentHash);
    assert_eq!(
        audit.recorded_audit_trail_id.as_deref(),
        Some(a.audit_trail_id.as_str())
    );
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::ApprovedAndExecuted
    );

    // transaction_sha256 of B: B's block.
    let b_digest = digest(&b);
    let audit = core
        .audit_execution(
            SIG,
            ExecutionKeys {
                content_hash: Some(&b.content_hash),
                transaction_sha256: Some(&b_digest),
                ..Default::default()
            },
            Some(&log),
        )
        .await;
    assert_eq!(audit.attribution, ExecutionAttribution::TransactionSha256);
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::BlockedButExecuted
    );

    // audit_trail_id of B: the same, by the most exact key.
    let audit = core
        .audit_execution(
            SIG,
            ExecutionKeys {
                content_hash: Some(&b.content_hash),
                audit_trail_id: Some(&b.audit_trail_id),
                ..Default::default()
            },
            Some(&log),
        )
        .await;
    assert_eq!(audit.attribution, ExecutionAttribution::AuditTrailId);
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::BlockedButExecuted
    );

    // A spoofed id is not rescued by the real content_hash beside it.
    let audit = core
        .audit_execution(
            SIG,
            ExecutionKeys {
                content_hash: Some(&b.content_hash),
                audit_trail_id: Some("gr-does-not-exist"),
                ..Default::default()
            },
            Some(&log),
        )
        .await;
    assert_eq!(audit.attribution, ExecutionAttribution::AuditTrailId);
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::NoVerificationOnRecord
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ─── The trail under the three keys ─────────────────────────────────────────

/// Every key survives rotation and reopen, and each returns the exact record
/// it names; concurrent verifications of one transaction stay distinct by id.
#[tokio::test]
async fn every_key_is_exact_across_rotation_and_concurrency() {
    let chain: ChainBytes = Arc::new(Mutex::new(None));
    let core = Arc::new(core_at(&cluster(chain)));
    for _ in 0..3 {
        let _ = core.verify_async(&describe(tx_a())).await;
    }
    let d = std::env::temp_dir().join(format!("graphite-r10-rot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    // Rotate every ~2 KB so the records land across several archives.
    let log = AuditLog::open_with_rotation(audit_path(&d), 2_000, 0).unwrap();
    let b = verify_and_record(&core, &log, tx_b()).await;
    // Ten concurrent verifications of A: same content_hash and digest, ten ids.
    let mut ids = Vec::new();
    let mut handles = Vec::new();
    for _ in 0..10 {
        let core2 = Arc::clone(&core);
        handles.push(tokio::spawn(async move {
            core2.verify_async(&describe(tx_a())).await.unwrap()
        }));
    }
    let mut a_digest = None;
    for h in handles {
        let r = h.await.unwrap();
        a_digest = Some(digest(&r));
        assert!(log.append(&graphite_core::durable::AuditRecord {
            event_type: graphite_core::durable::LifecycleEvent::Verification,
            timestamp: graphite_core::durable::now_utc_rfc3339(),
            audit_trail_id: r.audit_trail_id.clone(),
            content_hash: r.content_hash.clone(),
            transaction_sha256: Some(digest(&r)),
            program_id: SYSTEM.to_string(),
            instruction_name: r.instruction_name.clone(),
            protocol_name: r.protocol_name.clone(),
            manifest_version: r.manifest_version.clone(),
            approved: r.approved,
            confidence: r.confidence,
            risk_status: r.risk_verdict.status.clone(),
            policy_verdict: r.policy_verdict.clone(),
            l3_status: "inconclusive".to_string(),
            l8_status: "inconclusive".to_string(),
        }));
        ids.push(r.audit_trail_id.clone());
    }
    assert!(
        log.health().rotations_ok >= 1,
        "rotation must have happened"
    );
    let a_digest = a_digest.unwrap();
    let check = |log: &AuditLog| {
        // By id: exactly that record, all ten distinct.
        for id in &ids {
            let r = log
                .find_verification(VerificationKey::AuditTrailId(id))
                .unwrap();
            assert_eq!(&r.audit_trail_id, id);
        }
        let r = log
            .find_verification(VerificationKey::AuditTrailId(&b.audit_trail_id))
            .unwrap();
        assert!(!r.approved);
        // By digest: B's is B's, A's is one of the ten (the newest).
        let r = log
            .find_verification(VerificationKey::TransactionSha256(&digest(&b)))
            .unwrap();
        assert_eq!(r.audit_trail_id, b.audit_trail_id);
        let r = log
            .find_verification(VerificationKey::TransactionSha256(&a_digest))
            .unwrap();
        assert_eq!(r.audit_trail_id, *ids.last().unwrap());
        // By content_hash: the newest of the eleven, which is an A.
        let r = log
            .find_verification(VerificationKey::ContentHash(&b.content_hash))
            .unwrap();
        assert_eq!(r.audit_trail_id, *ids.last().unwrap());
        assert!(r.approved);
    };
    check(&log);
    drop(log);
    check(&AuditLog::open_with_rotation(audit_path(&d), 2_000, 0).unwrap());
    std::fs::remove_dir_all(&d).ok();
}
