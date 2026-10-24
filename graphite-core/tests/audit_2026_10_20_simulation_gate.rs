//! Audit 2026-10-20 — what a simulation must yield before the Core approves,
//! what may teach the baseline, and what L8 may alarm on.
//!
//! - H1: with an RPC client attached and a transaction supplied, a
//!   simulation that ran and errored is `SimulationFailed` (L3 Failed) and
//!   one that could not be obtained — an RPC error, a malformed or incomplete
//!   response, no post-state — is `VerificationIncomplete`. Both refuse.
//! - M1: a request refused ONLY by the policy threshold trains the baseline
//!   only under the operator's bootstrap policy
//!   (`ObservationPolicy::OperatorBootstrap`; Round 30, G-02).
//! - F5: a caller citing a refused `audit_trail_id` beside a signature whose
//!   chain bytes are something else is not a discrepancy.
//! - F10: the inclusion witness is never the primary, whichever is attached
//!   first.
#![cfg(feature = "rpc")]

use graphite_core::confidence_engine::TrustTier;
use graphite_core::durable::{audit_path, AuditLog};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::tx_artifact::message_bytes;
use graphite_core::verification::{
    ExecutionDecision, ExecutionKeys, ExecutionReconciliation, GraphiteCore, LayerStatus,
    ProposedIntent, VerificationInput, VerificationResult, VerificationScope,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

const SYSTEM: &str = "11111111111111111111111111111111";

fn payer() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x2au8; 32])
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

fn transfer_data(lamports: u64) -> Vec<u8> {
    let mut d = vec![2, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d
}

/// The corpus transfer, with this test's fee payer and `lamports`.
fn tx(lamports: u64) -> Vec<u8> {
    let keys = strings(&corpus_entry("legacy_single_transfer")["static_keys"]);
    let mut raw = bytes(&corpus_entry("legacy_single_transfer")["raw"]);
    let old = bs58::decode(&keys[0]).into_vec().unwrap();
    let pos = raw
        .windows(32)
        .position(|w| w == old.as_slice())
        .expect("the corpus fee payer is in the frame");
    raw[pos..pos + 32].copy_from_slice(&payer().verifying_key().to_bytes());
    let old = transfer_data(2_000_000);
    let pos = raw
        .windows(old.len())
        .position(|w| w == old.as_slice())
        .expect("the corpus transfer carries 2,000,000 lamports");
    raw[pos..pos + old.len()].copy_from_slice(&transfer_data(lamports));
    raw
}

fn tx_other_blockhash() -> Vec<u8> {
    let keys = strings(&corpus_entry("legacy_single_transfer")["static_keys"]);
    let mut raw = bytes(&corpus_entry("legacy_other_blockhash")["raw"]);
    let old = bs58::decode(&keys[0]).into_vec().unwrap();
    let pos = raw.windows(32).position(|w| w == old.as_slice()).unwrap();
    raw[pos..pos + 32].copy_from_slice(&payer().verifying_key().to_bytes());
    raw
}

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

/// How the mock cluster answers `simulateTransaction`, per test.
#[derive(Clone, Default)]
enum Simulation {
    /// A complete, clean simulation with post-state.
    #[default]
    Clean,
    /// The simulator executed the bytes and reports this error.
    Errored(String),
    /// A JSON-RPC error instead of a result (an outage, a rate limit).
    RpcError,
    /// A result with no compute units, no balance arrays and no inner
    /// instructions — nothing in it is a measurement.
    Incomplete,
    /// A clean, complete simulation that returns no post-state.
    NoPostState,
}

#[derive(Clone, Default)]
struct Knobs {
    simulation: Simulation,
    /// Bytes served by `getTransaction`, per signature.
    chain: Vec<(String, Vec<u8>)>,
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
                    let complete = |err: &str, accounts: &str| {
                        format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
                                "err":{err},"logs":[],"unitsConsumed":150,"fee":5000,
                                "preBalances":[1000000000,1000000,1],"postBalances":[998995000,2000000,1],
                                "innerInstructions":[],"loadedAddresses":{{"writable":[],"readonly":[]}},
                                {accounts}"returnData":null}}}}}}"#
                        )
                    };
                    match &k.simulation {
                        Simulation::Clean => complete("null", &format!(r#""accounts":[{}],"#, post.join(","))),
                        Simulation::Errored(e) => complete(&format!(r#"{{"InstructionError":[0,"{e}"]}}"#), r#""accounts":null,"#),
                        Simulation::NoPostState => complete("null", ""),
                        Simulation::RpcError => r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"node is behind"}}"#.to_string(),
                        Simulation::Incomplete => r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"err":null,"logs":[],"accounts":null,"returnData":null}}}"#.to_string(),
                    }
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

fn client(endpoint: &str) -> SolanaRpcClient {
    SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    })
}

fn core_at(endpoint: &str) -> GraphiteCore {
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(client(endpoint));
    core
}

/// A described transfer of `lamports` under `profile`.
fn describe(lamports: u64, profile: WalletProfile) -> VerificationInput {
    let keys = strings(&corpus_entry("legacy_single_transfer")["static_keys"]);
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send SOL".to_string(),
            confidence_of_parse: 0.95,
            // Round 36 (F-003): what the request states, which the bytes carry.
            extracted_parameters: Some(graphite_core::verification::ExtractedParameters {
                amount: Some(format!(
                    "{}.{:09}",
                    lamports / 1_000_000_000,
                    lamports % 1_000_000_000
                )),
                destination: Some(keys[1].clone()),
                input_token: Some("SOL".to_string()),
                ..Default::default()
            }),
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![payer_b58(), keys[1].clone()],
        instruction_data: Some(transfer_data(lamports)),
        cpi_targets: vec![],
        wallet_profile: profile,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: Some(tx(lamports)),
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

/// The lowest bar a fresh core's described transfer (0.44, OfficialManifest)
/// clears: a refusal under it is a gate, never the score.
fn official_floor() -> WalletProfile {
    WalletProfile::Custom {
        min_confidence: 0.40,
        min_trust_tier: TrustTier::OfficialManifest,
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

fn finding<'a>(r: &'a VerificationResult, pattern: &str) -> Option<&'a str> {
    r.risk_verdict
        .findings
        .iter()
        .find(|f| f.pattern == pattern)
        .map(|f| f.reason.as_str())
}

fn samples(core: &GraphiteCore) -> u64 {
    core.simulation_baseline(SYSTEM)
        .map(|b| b.sample_count)
        .unwrap_or(0)
}

async fn verify_with(simulation: Simulation) -> VerificationResult {
    let knobs: Shared = Arc::new(Mutex::new(Knobs {
        simulation,
        ..Default::default()
    }));
    let core = core_at(&cluster(knobs));
    core.verify_async(&describe(2_000_000, official_floor()))
        .await
        .unwrap()
}

// ─── H1 ─────────────────────────────────────────────────────────────────────

/// The control: a clean, complete simulation of a sound transfer approves.
#[tokio::test]
async fn a_clean_simulation_approves() {
    let r = verify_with(Simulation::Clean).await;
    assert!(r.approved, "{} {:?}", r.summary, r.risk_verdict.findings);
    assert!(matches!(
        r.scope,
        VerificationScope::ArtifactBound {
            simulated: true,
            ..
        }
    ));
    assert_eq!(
        layer(&r, "L4").status,
        LayerStatus::Passed,
        "{}",
        layer(&r, "L4").reason
    );
    // Round 30 (G-01): the one shape that permits signing.
    assert_eq!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{}",
        r.summary
    );
    assert!(r.executable && r.is_executable());
}

/// The simulator executed the bytes and said they would not land. That was
/// L3 text and a residual; the verdict was `approved: true`.
#[tokio::test]
async fn an_errored_simulation_is_refused() {
    let r = verify_with(Simulation::Errored("Custom(6004)".to_string())).await;
    assert!(!r.approved, "{}", r.summary);
    assert_eq!(r.policy_verdict, "Rejected");
    assert_eq!(r.risk_verdict.status, "Blocked");
    let why = finding(&r, "SimulationFailed").expect("a SimulationFailed finding");
    assert!(
        why.contains("Custom(6004)") && why.contains("would not land"),
        "{why}"
    );
    let l3 = layer(&r, "L3");
    assert_eq!(l3.status, LayerStatus::Failed, "{}", l3.reason);
    assert!(l3.reason.contains("FAILED"), "{}", l3.reason);
    // Round 30 (G-01): a simulation that failed is a finding, not missing
    // evidence: blocked, not inconclusive.
    assert_eq!(r.decision, ExecutionDecision::Blocked);
    assert!(!r.executable);
}

/// An RPC that answers with an error — an outage, a node behind, a rate
/// limit — used to leave the verdict approvable on static analysis alone.
#[tokio::test]
async fn an_unobtainable_simulation_is_refused_as_incomplete() {
    let r = verify_with(Simulation::RpcError).await;
    assert!(!r.approved, "{}", r.summary);
    let why = finding(&r, "VerificationIncomplete").expect("a VerificationIncomplete finding");
    assert!(why.contains("verification incomplete"), "{why}");
    assert!(why.contains("no complete simulation was obtained"), "{why}");
    let l3 = layer(&r, "L3");
    assert_eq!(l3.status, LayerStatus::Inconclusive, "{}", l3.reason);
    assert!(l3.reason.contains("INCOMPLETE"), "{}", l3.reason);
    // Round 30 (G-01): evidence that could not be obtained.
    assert_eq!(
        r.decision,
        ExecutionDecision::Inconclusive,
        "{:?}",
        r.risk_verdict.findings
    );
    assert!(!r.executable);
}

/// A response with no compute units, balance arrays or inner instructions
/// is not a measurement, and the observed-CPI checks cannot run on it.
#[tokio::test]
async fn an_incomplete_simulation_response_is_refused() {
    let r = verify_with(Simulation::Incomplete).await;
    assert!(!r.approved, "{}", r.summary);
    assert!(
        finding(&r, "VerificationIncomplete").is_some(),
        "{:?}",
        r.risk_verdict.findings
    );
    assert_eq!(r.decision, ExecutionDecision::Inconclusive);
    assert!(!r.executable);
}

/// A simulation that ran clean but brought back no post-state leaves L4
/// without a diff — the check that compares what the bytes DO. It cannot be
/// skipped on an approval.
#[tokio::test]
async fn a_simulation_without_a_diff_is_refused() {
    let r = verify_with(Simulation::NoPostState).await;
    assert!(!r.approved, "{}", r.summary);
    let why = finding(&r, "VerificationIncomplete").expect("a VerificationIncomplete finding");
    assert!(why.contains("no pre/post state diff was built"), "{why}");
    assert_eq!(r.decision, ExecutionDecision::Inconclusive);
    assert!(!r.executable);
}

// ─── M1 ─────────────────────────────────────────────────────────────────────

/// Three distinct transfers refused by the threshold took a fresh program
/// from 0.44 to 0.64 — past Gaming — for everyone. Off by default now, and
/// since Round 30 (G-02) not by naming a permissive profile either: a
/// verdict approved under the request's own `Custom { 0.40 }` profile is no
/// more evidence than one refused under Gaming.
#[tokio::test]
async fn policy_refusals_teach_nothing_unless_the_operator_opts_in() {
    use graphite_core::verification::ObservationPolicy;
    let endpoint = cluster(Arc::default());
    let core = core_at(&endpoint);
    assert_eq!(
        core.observation_policy(),
        ObservationPolicy::BuiltinFloor,
        "the built-in floor by default"
    );
    for i in 1..=3u64 {
        let r = core
            .verify_async(&describe(2_000_000 + i, WalletProfile::Gaming))
            .await
            .unwrap();
        assert!(
            !r.approved,
            "a fresh program is below Gaming: {}",
            r.summary
        );
    }
    assert_eq!(samples(&core), 0, "a policy refusal trained the baseline");
    let fourth = core
        .verify_async(&describe(2_000_010, WalletProfile::Gaming))
        .await
        .unwrap();
    assert!(!fourth.approved, "pumped past Gaming: {}", fourth.summary);
    assert!(
        (fourth.confidence - 0.44).abs() < 1e-9,
        "{}",
        fourth.confidence
    );

    // Round 30 (G-02): APPROVED under the request's own permissive profile,
    // and still no evidence — the request chose the bar it cleared.
    for i in 1..=3u64 {
        let approved = core
            .verify_async(&describe(2_000_020 + i, official_floor()))
            .await
            .unwrap();
        assert!(approved.approved, "{}", approved.summary);
    }
    assert_eq!(
        samples(&core),
        0,
        "a verdict approved below the built-in floor trained the baseline"
    );
    let after_self_approval = core
        .verify_async(&describe(2_000_030, WalletProfile::Gaming))
        .await
        .unwrap();
    assert!(
        !after_self_approval.approved,
        "{}",
        after_self_approval.summary
    );

    // The operator's bootstrap policy — library and CLI only — restores it.
    let mut opted = core_at(&endpoint);
    opted.set_observation_policy(ObservationPolicy::OperatorBootstrap);
    for i in 1..=3u64 {
        let _ = opted
            .verify_async(&describe(3_000_000 + i, WalletProfile::Gaming))
            .await
            .unwrap();
    }
    assert_eq!(samples(&opted), 3);
    let after = opted
        .verify_async(&describe(3_000_010, WalletProfile::Gaming))
        .await
        .unwrap();
    assert!(after.approved, "{}", after.summary);
    assert!(
        (after.confidence - 0.64).abs() < 1e-9,
        "{}",
        after.confidence
    );
}

// ─── F5 ─────────────────────────────────────────────────────────────────────

fn temp_log(tag: &str) -> (AuditLog, std::path::PathBuf) {
    let d = std::env::temp_dir().join(format!(
        "graphite-a20-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|x| x.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap();
    (AuditLog::open(audit_path(&d)).unwrap(), d)
}

fn digest(r: &VerificationResult) -> String {
    match &r.scope {
        VerificationScope::ArtifactBound {
            transaction_sha256, ..
        } => transaction_sha256.clone(),
        VerificationScope::Descriptive { .. } => panic!("artifact-bound expected"),
    }
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
        decision: None,
        executable: None,
        confidence: r.confidence,
        risk_status: r.risk_verdict.status.clone(),
        policy_verdict: r.policy_verdict.clone(),
        l3_status: "inconclusive".to_string(),
        l8_status: "inconclusive".to_string(),
        wallet_profile: None,
    }));
}

/// Anyone with a verify key could page the operator: cite any refused
/// `audit_trail_id` beside any landed signature whose bytes are something
/// else, and L8 answered `RecordedForDifferentBytes { recorded_approved:
/// false }` — a discrepancy. The chain's answer stands now; the caller's
/// contradicted citation is reported, not alarmed.
#[tokio::test]
async fn a_cited_refusal_of_other_bytes_is_not_an_alarm() {
    let knobs: Shared = Arc::default();
    let core = core_at(&cluster(Arc::clone(&knobs)));
    let (log, dir) = temp_log("f5");
    let refused = core
        .verify_async(&describe(2_000_000, WalletProfile::Treasury))
        .await
        .unwrap();
    assert!(!refused.approved);
    record(&log, &refused);

    // What executed under the signature: other bytes, never verified.
    let executed = signed(&tx_other_blockhash());
    let sig = sig_of(&executed);
    knobs.lock().unwrap().chain = vec![(sig.clone(), executed)];
    let audit = core
        .audit_execution(
            &sig,
            ExecutionKeys {
                content_hash: None,
                transaction_sha256: None,
                audit_trail_id: Some(&refused.audit_trail_id),
            },
            Some(&log),
        )
        .await;
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::NoVerificationOnRecord,
        "{audit:?}"
    );
    assert!(!audit.reconciliation.is_discrepancy());
    assert!(
        audit
            .caller_keys_disagree
            .iter()
            .any(|d| d.contains(&refused.audit_trail_id) && d.contains("refused")),
        "the contradicted citation must be reported: {:?}",
        audit.caller_keys_disagree
    );

    // The alarm stays where the evidence is the chain's: the refused bytes
    // themselves executing.
    let executed = signed(&tx(2_000_000));
    let sig = sig_of(&executed);
    knobs.lock().unwrap().chain = vec![(sig.clone(), executed)];
    let audit = core
        .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
        .await;
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::BlockedButExecuted
    );
    assert!(audit.reconciliation.is_discrepancy());
    std::fs::remove_dir_all(&dir).ok();
}

// ─── F10 ────────────────────────────────────────────────────────────────────

/// The "a witness is not the primary" rule was checked only when the witness
/// was attached second.
#[test]
fn the_witness_is_never_the_primary_whichever_is_attached_first() {
    // Witness first, then the same endpoint as the primary.
    let mut core = GraphiteCore::new();
    core.attach_inclusion_witness(client("http://127.0.0.1:9/"))
        .expect("no primary yet");
    assert!(core.has_inclusion_witness());
    assert!(
        core.try_attach_rpc_client(client("HTTP://127.0.0.1:9"))
            .is_err(),
        "the refusing form refuses"
    );
    core.attach_rpc_client(client("http://127.0.0.1:9"));
    assert!(
        !core.has_inclusion_witness(),
        "a witness that is the primary must not stay attached"
    );

    // A different endpoint is kept.
    let mut core = GraphiteCore::new();
    core.attach_inclusion_witness(client("http://127.0.0.1:9/"))
        .unwrap();
    core.attach_rpc_client(client("http://127.0.0.1:10/"));
    assert!(core.has_inclusion_witness());

    // Primary first is refused, as before.
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(client("http://127.0.0.1:9/"));
    assert!(core
        .attach_inclusion_witness(client("http://127.0.0.1:9"))
        .is_err());
}
