//! Requires the `rpc` feature: every question here is about what a simulation
//! is allowed to teach the gate, and what the gate says about bytes that were
//! signed before they were shown.
#![cfg(feature = "rpc")]

//! Round 17: the regression tests Round 16 named.
//!
//! Each test below fails on the code Round 16 audited (`e95857d`) and passes
//! after the remediation it names. The mock cluster is controllable per test:
//! the simulation's `err`, its compute units, and what the chain holds for a
//! signature.
//!
//! - F-16-01: an artifact whose signature slots are filled is refused at
//!   `/verify`; a cited `audit_trail_id` for other bytes is reported as such.
//! - F-16-03 / F-15-02: refused requests and errored simulations do not
//!   train the baseline; an errored simulation is named by its own residual
//!   and never reads "clean".
//! - F-16-02: ten identical samples do not refuse the eleventh at +1 CU, and
//!   the shadow accumulator records what a flagged baseline refused.
//! - F-15-01: the same approved bytes are one observation, not two, and a
//!   refused request stays refused however often it is repeated.
//! - F-16-05: a CPI target the simulator observed is judged like a declared
//!   one, so leaving `cpi_targets` empty no longer switches Check 1 off.
//! - F-16-11: L8 reports every verdict recorded for the chain digest.

use graphite_core::durable::{audit_path, AuditLog};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::simulation_integrity::{ComputeBaseline, MIN_SAMPLES};
use graphite_core::tx_artifact::message_bytes;
use graphite_core::verification::{
    ExecutionKeys, ExecutionReconciliation, GraphiteCore, LayerStatus, ProposedIntent,
    UnobservedCode, VerificationError, VerificationInput, VerificationResult, VerificationScope,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

const SYSTEM: &str = "11111111111111111111111111111111";

fn payer() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x17u8; 32])
}

fn payer_b58() -> String {
    bs58::encode(payer().verifying_key().to_bytes()).into_string()
}

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

/// The corpus transfer with this test's fee payer in place of the corpus's.
fn with_payer(raw: Vec<u8>) -> Vec<u8> {
    let keys = strings(&corpus_entry("legacy_single_transfer")["static_keys"]);
    let old = bs58::decode(&keys[0]).into_vec().unwrap();
    let new = payer().verifying_key().to_bytes();
    let pos = raw
        .windows(32)
        .position(|w| w == old.as_slice())
        .expect("the corpus fee payer is in the frame");
    let mut out = raw;
    out[pos..pos + 32].copy_from_slice(&new);
    out
}

fn tx_a() -> Vec<u8> {
    with_payer(bytes(&corpus_entry("legacy_single_transfer")["raw"]))
}

fn tx_other_blockhash() -> Vec<u8> {
    with_payer(bytes(&corpus_entry("legacy_other_blockhash")["raw"]))
}

/// The same transfer for another amount: a DIFFERENT transaction, and one
/// the simulator executes differently (Round 19: a transaction that differs
/// only in its blockhash is the same simulation, and one observation).
fn with_amount(raw: &[u8], lamports: u64) -> Vec<u8> {
    let old = transfer_data(2_000_000);
    let pos = raw
        .windows(old.len())
        .position(|w| w == old.as_slice())
        .expect("the corpus transfer carries 2,000,000 lamports");
    let mut out = raw.to_vec();
    out[pos..pos + old.len()].copy_from_slice(&transfer_data(lamports));
    out
}

/// `describe` for `with_amount(tx_a(), lamports)`: the description matches
/// the bytes, so L2 locates the instruction.
fn describe_amount(lamports: u64) -> VerificationInput {
    let mut input = describe(with_amount(&tx_a(), lamports));
    input.instruction_data = Some(transfer_data(lamports));
    input
}

/// Earn the Gaming floor the way a deployment does: distinct approved
/// transactions of this program, each an observation.
async fn earn_baseline(core: &GraphiteCore) {
    for i in 1..=3u64 {
        let _ = core.verify_async(&describe_amount(2_000_000 + i)).await;
    }
}

fn transfer_data(lamports: u64) -> Vec<u8> {
    let mut d = vec![2, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d
}

/// The frame with the fee payer's real signature in the slot the artifact
/// left empty — what the chain holds, and what a caller who signed first
/// would send.
fn signed(unsigned: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let sig = payer().sign(message_bytes(unsigned).unwrap());
    let mut s = unsigned.to_vec();
    s[1..65].copy_from_slice(&sig.to_bytes());
    s
}

fn sig_of(signed: &[u8]) -> String {
    bs58::encode(&signed[1..65]).into_string()
}

fn account(lamports: u64) -> String {
    format!(
        r#"{{"lamports":{lamports},"owner":"{SYSTEM}","executable":false,"rentEpoch":0,"data":["","base64"]}}"#
    )
}

/// What the mock cluster says, per test.
#[derive(Clone)]
struct Knobs {
    /// `err` in the simulation response (`None` = `null`).
    sim_err: Option<String>,
    units: u64,
    /// Inner instructions: the program index each CPI called.
    inner_program_indexes: Vec<u8>,
    /// Bytes served by `getTransaction`, per signature.
    chain: Vec<(String, Vec<u8>)>,
}

impl Default for Knobs {
    fn default() -> Self {
        Self {
            sim_err: None,
            units: 150,
            inner_program_indexes: vec![],
            chain: vec![],
        }
    }
}

type Shared = Arc<Mutex<Knobs>>;

fn cluster(knobs: Shared) -> String {
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
            let k = knobs.lock().unwrap().clone();
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
                    let err = match &k.sim_err {
                        Some(e) => format!("\"{e}\""),
                        None => "null".to_string(),
                    };
                    let inner: Vec<String> = k
                        .inner_program_indexes
                        .iter()
                        .map(|i| format!(r#"{{"programIdIndex":{i},"accounts":[0,1],"data":""}}"#))
                        .collect();
                    let inner_groups = if inner.is_empty() {
                        "[]".to_string()
                    } else {
                        format!(r#"[{{"index":0,"instructions":[{}]}}]"#, inner.join(","))
                    };
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
                            "err":{err},"logs":[],"unitsConsumed":{},"fee":5000,
                            "preBalances":[1000000000,1000000,1],"postBalances":[998995000,2000000,1],
                            "innerInstructions":{inner_groups},"loadedAddresses":{{"writable":[],"readonly":[]}},
                            "accounts":[{}],"returnData":null}}}}}}"#,
                        k.units,
                        post.join(",")
                    )
                }
                "getSignatureStatuses" => {
                    r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":2},"value":[{"slot":12345,"confirmations":null,"confirmationStatus":"finalized","err":null,"status":{"Ok":null}}]}}"#.to_string()
                }
                "getTransaction" => {
                    let sig = body_json["params"][0].as_str().unwrap_or("").to_string();
                    match k.chain.iter().find(|(s, _)| *s == sig) {
                        Some((_, b)) => {
                            use base64::Engine;
                            format!(
                                r#"{{"jsonrpc":"2.0","id":1,"result":{{"slot":12345,"transaction":["{}","base64"],"meta":{{"err":null}}}}}}"#,
                                base64::engine::general_purpose::STANDARD.encode(b)
                            )
                        }
                        None => r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
                    }
                }
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
        account_addresses: vec![payer_b58(), keys[1].clone()],
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

fn layer<'a>(
    r: &'a VerificationResult,
    prefix: &str,
) -> &'a graphite_core::verification::PipelineLayerResult {
    r.layers
        .iter()
        .find(|l| l.layer.starts_with(prefix))
        .unwrap_or_else(|| panic!("{prefix} must be reported"))
}

fn codes(r: &VerificationResult) -> Vec<UnobservedCode> {
    match &r.scope {
        VerificationScope::ArtifactBound {
            unobserved_codes, ..
        }
        | VerificationScope::Descriptive {
            unobserved_codes, ..
        } => unobserved_codes.clone(),
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

fn samples(core: &GraphiteCore, program: &str) -> u64 {
    core.simulation_baseline(program)
        .map(|b| b.sample_count)
        .unwrap_or(0)
}

fn temp_log(tag: &str) -> (AuditLog, std::path::PathBuf) {
    let d = std::env::temp_dir().join(format!(
        "graphite-r17-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|x| x.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap();
    (AuditLog::open(audit_path(&d)).unwrap(), d)
}

fn record(log: &AuditLog, r: &VerificationResult) {
    assert!(log.append(&graphite_core::durable::AuditRecord {
        event_type: graphite_core::durable::LifecycleEvent::Verification,
        timestamp: graphite_core::durable::now_utc_rfc3339(),
        audit_trail_id: r.audit_trail_id.clone(),
        content_hash: r.content_hash.clone(),
        transaction_sha256: Some(digest(r)),
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
}

// ─── F-16-01: signed before it was shown ────────────────────────────────────

/// The Core verifies before signing. An artifact whose slot already holds a
/// signature was signed first; it is refused as malformed input, never
/// approved, never given a digest L8 could not reproduce.
#[tokio::test]
async fn a_presigned_artifact_is_refused_at_verify() {
    let core = core_at(&cluster(Arc::default()));
    let result = core.verify_async(&describe(signed(&tx_a()))).await;
    match result {
        Err(VerificationError::InvalidInput(msg)) => {
            assert!(msg.contains("non-zero signature slot"), "{msg}");
        }
        other => panic!("a pre-signed artifact must be refused as invalid input, got {other:?}"),
    }
    // Any non-zero slot, not only a valid signature.
    let mut garbage = tx_a();
    garbage[1] = 0xff;
    assert!(
        matches!(
            core.verify_async(&describe(garbage)).await,
            Err(VerificationError::InvalidInput(_))
        ),
        "a garbage slot is a filled slot"
    );
    // The control: the same bytes with empty slots verify and bind.
    let ok = core.verify_async(&describe(tx_a())).await.unwrap();
    assert!(matches!(ok.scope, VerificationScope::ArtifactBound { .. }));
}

/// L8, when the chain's bytes digest to nothing on record but the caller
/// cites an exact verification of OTHER bytes: the answer names that, and a
/// cited refusal is a discrepancy. Until Round 17 this was
/// `NoVerificationOnRecord, discrepancy: false` — the stronger evidence path
/// gave the weaker alarm.
#[tokio::test]
async fn a_cited_verdict_about_other_bytes_is_reported_and_a_cited_refusal_alarms() {
    let knobs: Shared = Arc::default();
    let core = core_at(&cluster(Arc::clone(&knobs)));
    earn_baseline(&core).await;
    let (log, dir) = temp_log("otherbytes");

    // A refused verification of transaction A (Treasury demands a tier this
    // program has not earned).
    let mut refused_input = describe(tx_a());
    refused_input.wallet_profile = WalletProfile::Treasury;
    let refused = core.verify_async(&refused_input).await.unwrap();
    assert!(!refused.approved, "{}", refused.summary);
    record(&log, &refused);

    // What actually executed under the signature: a DIFFERENT transaction
    // (same transfer, another blockhash), never verified.
    let executed = signed(&tx_other_blockhash());
    let sig = sig_of(&executed);
    knobs.lock().unwrap().chain = vec![(sig.clone(), executed.clone())];

    let audit = core
        .audit_execution(
            &sig,
            ExecutionKeys {
                content_hash: Some(&refused.content_hash),
                transaction_sha256: Some(&digest(&refused)),
                audit_trail_id: Some(&refused.audit_trail_id),
            },
            Some(&log),
        )
        .await;
    match &audit.reconciliation {
        ExecutionReconciliation::RecordedForDifferentBytes {
            recorded_approved,
            recorded_transaction_sha256,
            chain_transaction_sha256,
        } => {
            assert!(!recorded_approved);
            assert_eq!(
                recorded_transaction_sha256.as_deref(),
                Some(digest(&refused).as_str())
            );
            assert_ne!(chain_transaction_sha256, &digest(&refused));
        }
        other => panic!("expected RecordedForDifferentBytes, got {other:?}"),
    }
    assert!(
        audit.reconciliation.is_discrepancy(),
        "a cited refusal beside an execution is the alarm"
    );

    // The same shape with a cited APPROVAL is reported, not alarmed: the
    // caller's own account of it is an approval of something else.
    let approved = core.verify_async(&describe(tx_a())).await.unwrap();
    assert!(approved.approved, "{}", approved.summary);
    record(&log, &approved);
    let audit = core
        .audit_execution(
            &sig,
            ExecutionKeys {
                content_hash: None,
                transaction_sha256: None,
                audit_trail_id: Some(&approved.audit_trail_id),
            },
            Some(&log),
        )
        .await;
    assert!(matches!(
        audit.reconciliation,
        ExecutionReconciliation::RecordedForDifferentBytes {
            recorded_approved: true,
            ..
        }
    ));
    assert!(!audit.reconciliation.is_discrepancy());
    std::fs::remove_dir_all(&dir).ok();
}

// ─── F-16-03 / F-15-02 / F-15-01: what becomes evidence ─────────────────────

/// A request refused at L2 — a declared sibling that matches nothing — used
/// to train the baseline exactly as an honest one did.
#[tokio::test]
async fn an_l2_refused_request_does_not_grow_the_baseline() {
    let core = core_at(&cluster(Arc::default()));
    let mut input = describe(tx_a());
    input.transaction_instructions =
        vec![graphite_core::tx_pattern_analysis::TransactionInstruction {
            program_id: SYSTEM.to_string(),
            instruction_discriminator: "02000000".to_string(),
            account_addresses: vec![payer_b58(), payer_b58()],
            cpi_targets: vec![],
        }];
    for _ in 0..3 {
        let r = core.verify_async(&input).await.unwrap();
        assert_eq!(layer(&r, "L2").status, LayerStatus::Failed);
        assert!(!r.approved);
    }
    assert_eq!(
        samples(&core, SYSTEM),
        0,
        "a refused request is not an observation"
    );
}

/// A simulation that errored is not evidence: it does not enter the baseline,
/// L3 never calls it clean, and the verdict carries `simulation_failed`
/// rather than folding the failure into `no_state_diff`.
#[tokio::test]
async fn an_errored_simulation_is_not_evidence_and_is_named() {
    let knobs: Shared = Arc::default();
    knobs.lock().unwrap().sim_err = Some("BlockhashNotFound".to_string());
    let core = core_at(&cluster(Arc::clone(&knobs)));
    let r = core.verify_async(&describe(tx_a())).await.unwrap();
    assert_eq!(
        samples(&core, SYSTEM),
        0,
        "an errored simulation trained the baseline"
    );
    let l3 = layer(&r, "L3");
    assert_ne!(l3.status, LayerStatus::Passed, "{}", l3.reason);
    assert!(
        !l3.reason.contains("clean"),
        "a failed simulation must never read clean: {}",
        l3.reason
    );
    assert!(l3.reason.contains("FAILED"), "{}", l3.reason);
    let c = codes(&r);
    assert!(c.contains(&UnobservedCode::SimulationFailed), "{c:?}");
    assert!(!c.contains(&UnobservedCode::NoStateDiff), "{c:?}");
    assert!(!c.contains(&UnobservedCode::NotSimulated), "{c:?}");
    // The bridge's default policy refuses this code by construction (it is
    // not inherent). Nothing here says the transaction is approved-and-clean.
}

/// Ten identical approvals are one observation. The same request repeated
/// cannot raise its own confidence past a floor it did not clear.
#[tokio::test]
async fn the_same_request_is_not_approved_on_the_second_call() {
    let core = core_at(&cluster(Arc::default()));
    // TradingBot's 0.80 bar is out of reach for this program; every call
    // is refused and none of them may change that.
    let mut input = describe(tx_a());
    input.wallet_profile = WalletProfile::TradingBot;
    let first = core.verify_async(&input).await.unwrap();
    assert!(!first.approved, "{}", first.summary);
    let mut last = first.clone();
    for _ in 0..5 {
        last = core.verify_async(&input).await.unwrap();
        assert!(!last.approved, "repetition approved it: {}", last.summary);
    }
    // The sound transaction is one observation however often it is asked
    // about; six calls cannot be six samples.
    assert!(
        samples(&core, SYSTEM) <= 1,
        "repetition trained the baseline: {}",
        samples(&core, SYSTEM)
    );
    // And Gaming — which the FIRST call of a fresh program cannot clear
    // (0.44 < 0.55) — is not cleared by repeating that call either.
    let fresh = core_at(&cluster(Arc::default()));
    let mut input = describe(tx_a());
    input.wallet_profile = WalletProfile::Gaming;
    let first = fresh.verify_async(&input).await.unwrap();
    assert!(!first.approved, "{}", first.summary);
    for _ in 0..5 {
        let again = fresh.verify_async(&input).await.unwrap();
        assert!(
            !again.approved,
            "the identical request became approved by repetition: {}",
            again.summary
        );
    }
    let _ = last;
}

#[tokio::test]
async fn identical_approved_bytes_are_one_observation() {
    let core = core_at(&cluster(Arc::default()));
    earn_baseline(&core).await;
    let before = samples(&core, SYSTEM);
    assert_eq!(
        before, 3,
        "three distinct approved transactions are three samples"
    );
    for _ in 0..4 {
        let r = core.verify_async(&describe(tx_a())).await.unwrap();
        assert!(r.approved, "{}", r.summary);
    }
    assert_eq!(
        samples(&core, SYSTEM),
        before + 1,
        "four calls about one transaction are one sample"
    );
    // Round 19 (F-19-01): the same transfer under another blockhash is the
    // same simulation — the simulator replaces the blockhash — and is NOT one
    // more. Round 17 asserted it was.
    let r = core
        .verify_async(&describe(tx_other_blockhash()))
        .await
        .unwrap();
    assert!(r.approved, "{}", r.summary);
    assert_eq!(samples(&core, SYSTEM), before + 1);
    // A genuinely different transaction (another amount) is one more.
    let r = core
        .verify_async(&describe_amount(2_000_100))
        .await
        .unwrap();
    assert!(r.approved, "{}", r.summary);
    assert_eq!(samples(&core, SYSTEM), before + 2);
}

// ─── F-16-02: the frozen baseline ───────────────────────────────────────────

/// Ten identical samples used to make every other value a ">1000σ"
/// divergence. A one-value history is a band, not a point: +1 CU passes, a
/// doubling still flags, and what a flag refused is kept in the shadow.
#[tokio::test]
async fn ten_identical_samples_do_not_refuse_the_eleventh_at_plus_one_cu() {
    let knobs: Shared = Arc::default();
    let core = core_at(&cluster(Arc::clone(&knobs)));
    let mut baseline = ComputeBaseline::default();
    for _ in 0..MIN_SAMPLES {
        graphite_core::simulation_integrity::update_baseline(&mut baseline, 450, 2, 0);
    }
    assert_eq!(baseline.std_compute_units, 0.0);
    core.seed_simulation_baseline(SYSTEM, baseline).unwrap();

    knobs.lock().unwrap().units = 451;
    let r = core.verify_async(&describe(tx_a())).await.unwrap();
    assert_ne!(
        layer(&r, "L3").status,
        LayerStatus::Failed,
        "{}",
        layer(&r, "L3").reason
    );
    assert!(
        r.approved,
        "an honest transaction one unit off a uniform history was refused: {}",
        r.summary
    );

    knobs.lock().unwrap().units = 600;
    // A different transaction (Round 19: another blockhash would be the same
    // observation as the call above).
    let r = core
        .verify_async(&describe_amount(2_000_050))
        .await
        .unwrap();
    assert_ne!(
        layer(&r, "L3").status,
        LayerStatus::Failed,
        "a third more is within the band: {}",
        layer(&r, "L3").reason
    );

    knobs.lock().unwrap().units = 1200;
    let r = core.verify_async(&describe(tx_a())).await.unwrap();
    assert_eq!(
        layer(&r, "L3").status,
        LayerStatus::Failed,
        "a real divergence still flags"
    );
    assert!(!r.approved);
    // The refused-but-clean execution is on the shadow, keyed like the
    // trusted one, so a frozen baseline is visible and promotable.
    let shadow = core.shadow_baseline(SYSTEM).expect("shadow recorded");
    assert_eq!(shadow.sample_count, 1);
    assert_eq!(
        samples(&core, SYSTEM),
        MIN_SAMPLES + 2,
        "flagged observations never enter the trusted baseline"
    );
    // Promotion needs MIN_SAMPLES shadow observations.
    assert!(core.promote_shadow_baseline(SYSTEM).is_err());
    assert!(core.frozen_baselines().is_empty());
}

// ─── F-16-05: measured CPI targets ──────────────────────────────────────────

/// The simulator observed a CPI into a program the caller did not declare.
/// On a program with no manifest that is Check 1's fail-closed arm — which a
/// caller used to switch off by declaring nothing.
#[tokio::test]
async fn an_observed_cpi_target_the_caller_omitted_is_judged_like_a_declared_one() {
    let knobs: Shared = Arc::default();
    // Inner instruction calls the account at index 1 of the message — the
    // corpus destination, which no manifest lists as a universal program.
    let core = core_at(&cluster(Arc::clone(&knobs)));
    earn_baseline(&core).await;
    knobs.lock().unwrap().inner_program_indexes = vec![1];
    let honest = describe(tx_a());
    let r = core.verify_async(&honest).await.unwrap();
    // A System transfer that CPIs into an arbitrary account is not a System
    // transfer. The observed target is named and judged.
    let findings: Vec<String> = r
        .risk_verdict
        .findings
        .iter()
        .map(|f| f.pattern.clone())
        .collect();
    let warned = r
        .layers
        .iter()
        .any(|l| l.reason.contains("observed CPI target"));
    assert!(
        warned || !r.approved,
        "an observed, undeclared CPI target left no trace: findings {findings:?}, approved {}",
        r.approved
    );

    // Control: no inner instructions, nothing to judge, approved.
    knobs.lock().unwrap().inner_program_indexes = vec![];
    let r = core.verify_async(&describe(tx_a())).await.unwrap();
    assert!(r.approved, "{}", r.summary);
}

// ─── F-16-11: every verdict on record ───────────────────────────────────────

#[tokio::test]
async fn l8_reports_every_verdict_recorded_for_the_chain_digest() {
    let knobs: Shared = Arc::default();
    let core = core_at(&cluster(Arc::clone(&knobs)));
    earn_baseline(&core).await;
    let (log, dir) = temp_log("verdicts");
    // The same bytes refused (Treasury) and then approved (Gaming).
    let mut strict = describe(tx_a());
    strict.wallet_profile = WalletProfile::Treasury;
    let refused = core.verify_async(&strict).await.unwrap();
    assert!(!refused.approved);
    record(&log, &refused);
    let approved = core.verify_async(&describe(tx_a())).await.unwrap();
    assert!(approved.approved, "{}", approved.summary);
    record(&log, &approved);

    let executed = signed(&tx_a());
    let sig = sig_of(&executed);
    knobs.lock().unwrap().chain = vec![(sig.clone(), executed)];
    let audit = core
        .audit_execution(
            &sig,
            ExecutionKeys {
                content_hash: None,
                transaction_sha256: None,
                audit_trail_id: None,
            },
            Some(&log),
        )
        .await;
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::ApprovedAndExecuted
    );
    let v = audit.recorded_verdicts.expect("counts reported");
    assert_eq!(
        (v.approved, v.refused),
        (1, 1),
        "the refusal must be visible beside the approval"
    );
    std::fs::remove_dir_all(&dir).ok();
}
