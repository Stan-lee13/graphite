//! Round 30 — who may teach the evidence every caller is judged by, what
//! evidence is about, and what happens to it when the code changes.
//!
//! - G-02: no verify request can raise a program's baseline, confidence or
//!   tier below the built-in floor — not by threshold refusals (M1), and not
//!   by approving itself under a permissive profile it named. Sequentially
//!   or concurrently. `GRAPHITE_LEARN_FROM_POLICY_REFUSALS` is retired.
//! - Every refusal class trains neither the trusted nor the shadow
//!   accumulator, under either observation policy.
//! - G-03: baselines are kept per transaction shape, judged by the shape
//!   once it is mature, and migrated without minting shape evidence.
//! - G-04: an upgrade withdraws the program's evidence; a deployment newer
//!   than the evidence at the first sighting withdraws it too; a simulation
//!   of replaced code is not recorded; loader-v4 programs say they are not
//!   tracked.
#![cfg(feature = "rpc")]

use graphite_core::confidence_engine::TrustTier;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::{
    shape_key, BehaviorEvidence, ObservedDeployment, SemanticGraphStore,
};
use graphite_core::simulation_integrity::{ComputeBaseline, ComputeUsage, MIN_SAMPLES};
use graphite_core::tx_artifact::message_bytes;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ObservationPolicy, ProposedIntent, VerificationInput,
    VerificationResult,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

const SYSTEM: &str = "11111111111111111111111111111111";
const UPGRADEABLE_LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const LOADER_V4: &str = "LoaderV411111111111111111111111111111111111";
const NATIVE_LOADER: &str = "NativeLoader1111111111111111111111111111111";

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

#[allow(dead_code)]
fn signed(unsigned: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let sig = payer().sign(message_bytes(unsigned).unwrap());
    let mut s = unsigned.to_vec();
    s[1..65].copy_from_slice(&sig.to_bytes());
    s
}

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn account(lamports: u64, owner: &str, data: &[u8]) -> String {
    format!(
        r#"{{"lamports":{lamports},"owner":"{owner}","executable":false,"rentEpoch":0,"data":["{}","base64"]}}"#,
        b64(data)
    )
}

/// How the mock cluster answers a simulation.
#[derive(Clone)]
enum Simulation {
    Clean,
    Errored,
    RpcError,
    Incomplete,
    NoPostState,
}

/// What the mock cluster says about the System program's code.
#[derive(Clone)]
enum Deployment {
    /// What a real cluster says: owned by the native loader.
    Native,
    /// Owned by the upgradeable loader, deployed at this slot.
    Upgradeable(u64),
    /// Owned by loader-v4.
    LoaderV4,
    /// The read fails.
    Unreadable,
}

#[derive(Clone)]
struct Knobs {
    simulation: Simulation,
    units: u64,
    sim_slot: u64,
    deployment: Deployment,
}

impl Default for Knobs {
    fn default() -> Self {
        Knobs {
            simulation: Simulation::Clean,
            units: 150,
            sim_slot: 1_000,
            deployment: Deployment::Native,
        }
    }
}

type Shared = Arc<Mutex<Knobs>>;

const PROGRAMDATA: [u8; 32] = [0x77; 32];

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
            let slice = body_json["params"][1]["dataSlice"]["length"].as_u64();
            let body = match method.as_str() {
                // The program-account read of a deployment check.
                "getMultipleAccounts" if slice == Some(36) => {
                    let addrs = body_json["params"][0]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    if matches!(k.deployment, Deployment::Unreadable) {
                        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"node is behind"}}"#.to_string()
                    } else {
                        let vals: Vec<String> = addrs
                            .iter()
                            .map(|a| {
                                if a.as_str() != Some(SYSTEM) {
                                    return "null".to_string();
                                }
                                match k.deployment {
                                    Deployment::Upgradeable(_) => {
                                        let mut d = 2u32.to_le_bytes().to_vec();
                                        d.extend_from_slice(&PROGRAMDATA);
                                        account(1, UPGRADEABLE_LOADER, &d)
                                    }
                                    Deployment::LoaderV4 => account(1, LOADER_V4, &[0u8; 36]),
                                    _ => account(1, NATIVE_LOADER, &[0u8; 36]),
                                }
                            })
                            .collect();
                        format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":{}}},"value":[{}]}}}}"#,
                            k.sim_slot,
                            vals.join(",")
                        )
                    }
                }
                // The ProgramData header read.
                "getMultipleAccounts" if slice == Some(45) => {
                    let slot = match k.deployment {
                        Deployment::Upgradeable(s) => s,
                        _ => 0,
                    };
                    let mut d = 3u32.to_le_bytes().to_vec();
                    d.extend_from_slice(&slot.to_le_bytes());
                    d.push(0);
                    d.extend_from_slice(&[0u8; 32]);
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":{}}},"value":[{}]}}}}"#,
                        k.sim_slot,
                        account(1, UPGRADEABLE_LOADER, &d)
                    )
                }
                "getMultipleAccounts" => {
                    let count = body_json["params"][0]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let vals: Vec<String> = (0..count)
                        .map(|i| {
                            account(if i == 0 { 1_000_000_000 } else { 1_000_000 }, SYSTEM, &[])
                        })
                        .collect();
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":{}}},"value":[{}]}}}}"#,
                        k.sim_slot,
                        vals.join(",")
                    )
                }
                "simulateTransaction" => {
                    let count = body_json["params"][1]["accounts"]["addresses"]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let post: Vec<String> = (0..count)
                        .map(|i| account(if i == 0 { 998_995_000 } else { 2_000_000 }, SYSTEM, &[]))
                        .collect();
                    let complete = |err: &str, accounts: &str| {
                        format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":{}}},"value":{{
                                "err":{err},"logs":[],"unitsConsumed":{},"fee":5000,
                                "preBalances":[1000000000,1000000,1],"postBalances":[998995000,2000000,1],
                                "innerInstructions":[],"loadedAddresses":{{"writable":[],"readonly":[]}},
                                {accounts}"returnData":null}}}}}}"#,
                            k.sim_slot, k.units
                        )
                    };
                    match &k.simulation {
                        Simulation::Clean => complete("null", &format!(r#""accounts":[{}],"#, post.join(","))),
                        Simulation::Errored => complete(r#"{"InstructionError":[0,"Custom(6004)"]}"#, r#""accounts":null,"#),
                        Simulation::NoPostState => complete("null", ""),
                        Simulation::RpcError => r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"node is behind"}}"#.to_string(),
                        Simulation::Incomplete => r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"err":null,"logs":[],"accounts":null,"returnData":null}}}"#.to_string(),
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

/// A described transfer of `lamports` under `profile`.
fn describe(lamports: u64, profile: WalletProfile) -> VerificationInput {
    let keys = strings(&corpus_entry("legacy_single_transfer")["static_keys"]);
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
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

/// The weakest bar a caller could name if nothing clamped it.
fn permissive() -> WalletProfile {
    WalletProfile::Custom {
        min_confidence: 0.0,
        min_trust_tier: TrustTier::Unknown,
    }
}

fn official_floor() -> WalletProfile {
    WalletProfile::Custom {
        min_confidence: 0.40,
        min_trust_tier: TrustTier::OfficialManifest,
    }
}

fn samples(core: &GraphiteCore) -> u64 {
    core.simulation_baseline(SYSTEM)
        .map(|b| b.sample_count)
        .unwrap_or(0)
}

fn shadow(core: &GraphiteCore) -> u64 {
    core.shadow_baseline(SYSTEM)
        .map(|b| b.sample_count)
        .unwrap_or(0)
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

fn warned(r: &VerificationResult, needle: &str) -> bool {
    r.summary.contains(needle)
        || r.layers.iter().any(|l| l.reason.contains(needle))
        || r.risk_verdict
            .findings
            .iter()
            .any(|f| f.reason.contains(needle))
}

/// Operator-asserted evidence a reviewed program would carry: two reviewer
/// attestations and a signed manifest.
fn seed_reviewed(core: &mut GraphiteCore) {
    core.seed_behavior(graphite_core::semantic_graph_store::Behavior {
        program_id: SYSTEM.to_string(),
        version: "1.0.0".to_string(),
        expected_state_changes: vec![],
        allowed_cpis: vec![],
        trust_tier: TrustTier::Unknown,
        evidence: BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 2,
            battle_tested_tx_count: 0,
            simulation_match_count: 0,
        },
        quarantined: false,
        quarantine_reason: None,
    })
    .unwrap();
}

// ─── G-02 ───────────────────────────────────────────────────────────────────

/// A verify-key holder sends forty distinct, sound, clean-looking transfers
/// under every profile it can name — the weakest possible, the agent guard's
/// 0.40, Gaming, Treasury — and the program it targets is exactly where it
/// started for the next caller: no sample, no confidence, no tier, no
/// approval under Gaming.
#[tokio::test]
async fn a_verify_key_holder_cannot_raise_a_programs_evidence() {
    let core = core_at(&cluster(Arc::default()));
    let before = core
        .verify_async(&describe(1_000, WalletProfile::Gaming))
        .await
        .unwrap();
    assert!(!before.approved, "{}", before.summary);
    let profiles = [
        permissive(),
        official_floor(),
        WalletProfile::Gaming,
        WalletProfile::Treasury,
    ];
    let mut self_approved = 0;
    for i in 0..40u64 {
        let r = core
            .verify_async(&describe(2_000_000 + i, profiles[(i % 4) as usize]))
            .await
            .unwrap();
        if r.approved {
            self_approved += 1;
        }
    }
    assert_eq!(
        self_approved, 20,
        "the attack must be approving its own requests for this test to mean anything"
    );
    assert_eq!(
        samples(&core),
        0,
        "a request below the floor trained the baseline"
    );
    assert_eq!(shadow(&core), 0);
    let after = core
        .verify_async(&describe(3_000_000, WalletProfile::Gaming))
        .await
        .unwrap();
    assert!(!after.approved, "{}", after.summary);
    assert_eq!(after.confidence, before.confidence);
    assert_eq!(after.trust_tier, before.trust_tier);
}

/// The same attack, concurrently: thirty-two self-approving requests in
/// flight at once teach nothing either.
#[tokio::test]
async fn concurrent_self_approvals_teach_nothing() {
    let core = Arc::new(core_at(&cluster(Arc::default())));
    let mut tasks = Vec::new();
    for i in 0..32u64 {
        let core = Arc::clone(&core);
        tasks.push(tokio::spawn(async move {
            core.verify_async(&describe(4_000_000 + i, permissive()))
                .await
                .unwrap()
                .approved
        }));
    }
    let mut approved = 0;
    for t in tasks {
        if t.await.unwrap() {
            approved += 1;
        }
    }
    assert_eq!(approved, 32);
    assert_eq!(samples(&core), 0);
    assert_eq!(shadow(&core), 0);
}

/// The control, so the floor is a floor and not "nothing ever trains": a
/// program the operator has vouched for clears Gaming on its own, and its
/// approved verdicts are evidence — whichever profile asked, the strictest
/// included (a Treasury refusal of a verdict that clears the floor is the
/// same observation).
#[tokio::test]
async fn a_verdict_clearing_the_built_in_floor_is_evidence() {
    let mut core = core_at(&cluster(Arc::default()));
    seed_reviewed(&mut core);
    let r = core
        .verify_async(&describe(5_000_001, WalletProfile::Gaming))
        .await
        .unwrap();
    assert!(r.approved, "{} {}", r.confidence, r.summary);
    assert!(r.confidence >= 0.55, "{}", r.confidence);
    assert_eq!(samples(&core), 1);
    let strict = core
        .verify_async(&describe(5_000_002, WalletProfile::Treasury))
        .await
        .unwrap();
    assert!(!strict.approved, "{}", strict.summary);
    assert_eq!(
        samples(&core),
        2,
        "a stricter caller's refusal is still an observation"
    );
    // And the same bytes again are not a third.
    let _ = core
        .verify_async(&describe(5_000_002, WalletProfile::Gaming))
        .await
        .unwrap();
    assert_eq!(samples(&core), 2);
}

/// The operator-only bootstrap is a library/CLI choice the server cannot
/// make, and setting the retired variable stops the server starting.
#[test]
fn the_learning_opt_in_is_retired() {
    use graphite_core::operator_boundary::OperatorPolicy;
    assert_eq!(
        GraphiteCore::new().observation_policy(),
        ObservationPolicy::BuiltinFloor
    );
    let e = OperatorPolicy::from_lookup(|k| {
        (k == "GRAPHITE_LEARN_FROM_POLICY_REFUSALS").then(|| "1".to_string())
    })
    .unwrap_err();
    assert!(e.contains("removed in Round 30"), "{e}");
    assert!(OperatorPolicy::from_lookup(|_| None).is_ok());
}

// ─── Every refusal class trains nothing ─────────────────────────────────────

/// Each row is a request refused for a different reason. Under BOTH
/// observation policies — the default floor and the operator's bootstrap —
/// none of them may add a sample to the trusted baseline or the shadow. The
/// program carries operator evidence, so the default floor itself is no
/// reason for silence: only the refusal is.
#[tokio::test]
async fn no_refusal_class_trains_any_accumulator() {
    enum Row {
        Sim(Simulation),
        /// A declared sibling that matches nothing (L2).
        UnmatchedSibling,
        /// The described instruction is not the one in the bytes.
        Unlocated,
        /// The intent contradicts the instruction (L5).
        WrongIntent,
        /// An undeclared, unknown CPI target the Risk Engine refuses.
        RiskBlock,
    }
    let rows: Vec<(&str, Row)> = vec![
        ("errored simulation", Row::Sim(Simulation::Errored)),
        ("unobtainable simulation", Row::Sim(Simulation::RpcError)),
        ("incomplete simulation", Row::Sim(Simulation::Incomplete)),
        (
            "simulation without post-state",
            Row::Sim(Simulation::NoPostState),
        ),
        ("unmatched sibling", Row::UnmatchedSibling),
        ("unlocated instruction", Row::Unlocated),
        ("contradicting intent", Row::WrongIntent),
        ("risk block", Row::RiskBlock),
    ];
    for policy in [
        ObservationPolicy::BuiltinFloor,
        ObservationPolicy::OperatorBootstrap,
    ] {
        for (name, row) in &rows {
            let knobs: Shared = Arc::default();
            let mut core = core_at(&cluster(Arc::clone(&knobs)));
            core.set_observation_policy(policy);
            seed_reviewed(&mut core);
            let mut input = describe(6_000_000, WalletProfile::Gaming);
            match row {
                Row::Sim(s) => knobs.lock().unwrap().simulation = s.clone(),
                Row::UnmatchedSibling => {
                    input.transaction_instructions =
                        vec![graphite_core::tx_pattern_analysis::TransactionInstruction {
                            program_id: SYSTEM.to_string(),
                            instruction_discriminator: "02000000".to_string(),
                            account_addresses: vec![payer_b58(), payer_b58()],
                            cpi_targets: vec![],
                        }]
                }
                Row::Unlocated => input.instruction_data = Some(transfer_data(6_000_001)),
                Row::WrongIntent => input.proposed_intent.intent_type = "swap".to_string(),
                Row::RiskBlock => {
                    input.cpi_targets =
                        vec!["Evi1111111111111111111111111111111111111111".to_string()]
                }
            }
            let r = core.verify_async(&input).await.unwrap();
            assert!(!r.approved, "{policy:?} / {name}: approved: {}", r.summary);
            assert_eq!(
                samples(&core),
                0,
                "{policy:?} / {name} trained the baseline"
            );
            assert_eq!(shadow(&core), 0, "{policy:?} / {name} trained the shadow");
            assert!(
                core.shape_baselines(SYSTEM).is_empty(),
                "{policy:?} / {name} trained a shape"
            );
        }
    }
    // The control: the same core and request, unrefused, trains under both.
    for policy in [
        ObservationPolicy::BuiltinFloor,
        ObservationPolicy::OperatorBootstrap,
    ] {
        let mut core = core_at(&cluster(Arc::default()));
        core.set_observation_policy(policy);
        seed_reviewed(&mut core);
        let r = core
            .verify_async(&describe(6_000_000, WalletProfile::Gaming))
            .await
            .unwrap();
        assert!(r.approved, "{policy:?}: {}", r.summary);
        assert_eq!(samples(&core), 1, "{policy:?}");
        assert_eq!(core.shape_baselines(SYSTEM).len(), 1, "{policy:?}");
    }
}

// ─── G-03: per-shape baselines ──────────────────────────────────────────────

/// Two shapes of one program learn apart; L3 judges by the shape once it is
/// mature and by the program until then; observations are counted once.
#[test]
fn shapes_learn_apart_and_judge_once_mature() {
    let alone = shape_key(SYSTEM, "transfer", [SYSTEM]);
    let beside = shape_key(
        SYSTEM,
        "transfer",
        [SYSTEM, "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"],
    );
    let budgeted = shape_key(
        SYSTEM,
        "transfer",
        [SYSTEM, "ComputeBudget111111111111111111111111111111"],
    );
    assert_ne!(alone, beside, "a sibling program is another shape");
    assert_eq!(alone, budgeted, "a priority fee does not split a shape");
    assert!(alone.starts_with(&format!("{SYSTEM}/transfer/")));

    let mut store = SemanticGraphStore::new();
    let usage = |cu| ComputeUsage {
        compute_units: cu,
        account_writes: 2,
        cpi_hops: 0,
    };
    for i in 0..MIN_SAMPLES {
        store.record_observation(
            SYSTEM,
            Some(&alone),
            &usage(150),
            Some(&format!("a{i}")),
            Some(10),
        );
    }
    for i in 0..3 {
        store.record_observation(
            SYSTEM,
            Some(&beside),
            &usage(30_000),
            Some(&format!("b{i}")),
            Some(5),
        );
    }
    // The same identity again is nothing, in the shape too.
    store.record_observation(SYSTEM, Some(&beside), &usage(30_000), Some("b0"), Some(1));
    assert_eq!(
        store.shape_baseline(&alone).unwrap().sample_count,
        MIN_SAMPLES
    );
    assert_eq!(store.shape_baseline(&beside).unwrap().sample_count, 3);
    assert_eq!(
        store.get_simulation_baseline(SYSTEM).unwrap().sample_count,
        MIN_SAMPLES + 3
    );
    assert_eq!(store.evidence_since_slot(SYSTEM), Some(5));
    let (b, by_shape) = store.baseline_for(SYSTEM, Some(&alone)).unwrap();
    assert!(by_shape);
    assert_eq!(b.mean_compute_units, 150.0);
    let (_, by_shape) = store.baseline_for(SYSTEM, Some(&beside)).unwrap();
    assert!(!by_shape, "an immature shape falls back to the program");
    // A shape named for another program is not this program's.
    store.record_observation(
        SYSTEM,
        Some("Other/transfer/00"),
        &usage(1),
        Some("c"),
        None,
    );
    assert!(store.shape_baseline("Other/transfer/00").is_none());
}

/// A snapshot written before Round 30 has no shapes, and any it claims to
/// have are dropped; its mature baselines are anchored where they stand.
#[test]
fn a_pre_round_30_snapshot_migrates_without_minting_shapes() {
    let mut legacy = ComputeBaseline::default();
    for _ in 0..50 {
        graphite_core::simulation_integrity::update_baseline(&mut legacy, 150, 2, 0);
    }
    legacy.anchor = None;
    let json = serde_json::json!({
        "behaviors": [],
        "baselines": { SYSTEM: legacy },
        "shape_baselines": { format!("{SYSTEM}/transfer/0011223344556677"): legacy },
    })
    .to_string();
    let store = SemanticGraphStore::from_json(&json).unwrap();
    assert!(store.shape_baselines_of(SYSTEM).is_empty());
    let b = store.get_simulation_baseline(SYSTEM).unwrap();
    assert_eq!(b.sample_count, 50);
    assert!(b.anchor.is_some(), "anchored on load");
    // Written back, it carries the schema, and its shapes survive a reload.
    let mut store = store;
    let shape = shape_key(SYSTEM, "transfer", [SYSTEM]);
    store.record_observation(
        SYSTEM,
        Some(&shape),
        &ComputeUsage {
            compute_units: 150,
            account_writes: 2,
            cpi_hops: 0,
        },
        Some("k"),
        None,
    );
    let again = SemanticGraphStore::from_json(&store.to_json().unwrap()).unwrap();
    assert_eq!(again.shape_baselines_of(SYSTEM).len(), 1);
}

/// The pipeline keys its observations by shape and says which baseline
/// judged it.
#[tokio::test]
async fn the_pipeline_judges_by_the_shape_once_mature() {
    let mut core = core_at(&cluster(Arc::default()));
    seed_reviewed(&mut core);
    for i in 0..MIN_SAMPLES {
        let r = core
            .verify_async(&describe(7_000_000 + i, WalletProfile::Gaming))
            .await
            .unwrap();
        assert!(r.approved, "{}", r.summary);
    }
    let shapes = core.shape_baselines(SYSTEM);
    assert_eq!(shapes.len(), 1, "{shapes:?}");
    assert_eq!(shapes[0].1.sample_count, MIN_SAMPLES);
    let r = core
        .verify_async(&describe(7_100_000, WalletProfile::Gaming))
        .await
        .unwrap();
    let l3 = layer(&r, "L3");
    assert_eq!(l3.status, LayerStatus::Passed, "{}", l3.reason);
    assert!(
        l3.reason.contains("this transaction shape's baseline"),
        "{}",
        l3.reason
    );
}

/// Round 34 (S-3): a shape's baseline is bootstrapped from observations the
/// program's band let through. Ten of them at that band's upper edge give the
/// shape a band centred on the edge, and once the shape is mature it alone
/// judged: a transaction twice as far from the program's centre as the
/// program allows passed L3. The program's band still anchors the shape's.
#[tokio::test]
async fn a_shape_bootstrapped_at_the_program_edge_escapes_the_program_anchor() {
    let knobs: Shared = Arc::default();
    let mut core = core_at(&cluster(Arc::clone(&knobs)));
    seed_reviewed(&mut core);
    // The program's reviewed band: centred on 100,000 CU, spread floored at
    // 25% (25,000), so at the 2σ threshold it admits up to 150,000.
    let mut program = ComputeBaseline::default();
    for _ in 0..50 {
        graphite_core::simulation_integrity::update_baseline(&mut program, 100_000, 2, 0);
    }
    core.seed_simulation_baseline(SYSTEM, program).unwrap();
    // Ten distinct transfers at 148,000 CU: inside the program's band.
    knobs.lock().unwrap().units = 148_000;
    for i in 0..MIN_SAMPLES {
        let r = core
            .verify_async(&describe(9_000_000 + i, WalletProfile::Gaming))
            .await
            .unwrap();
        let l3 = layer(&r, "L3");
        assert_eq!(l3.status, LayerStatus::Passed, "bootstrap {i}: {}", l3.reason);
    }
    let shapes = core.shape_baselines(SYSTEM);
    assert_eq!(shapes.len(), 1, "{shapes:?}");
    assert_eq!(shapes[0].1.sample_count, MIN_SAMPLES, "the shape is mature");
    // Control: the edge itself still passes, judged by both.
    let r = core
        .verify_async(&describe(9_100_000, WalletProfile::Gaming))
        .await
        .unwrap();
    assert_eq!(layer(&r, "L3").status, LayerStatus::Passed, "{}", layer(&r, "L3").reason);
    // 200,000 CU: 4σ from the program's centre, 1.4σ from the shape's.
    knobs.lock().unwrap().units = 200_000;
    let r = core
        .verify_async(&describe(9_200_000, WalletProfile::Gaming))
        .await
        .unwrap();
    let l3 = layer(&r, "L3");
    assert_ne!(
        l3.status,
        LayerStatus::Passed,
        "a value outside the program's band passed on the shape's alone: {}",
        l3.reason
    );
    assert!(
        l3.reason.contains("FLAGGED") && l3.reason.contains("the program's baseline"),
        "{}",
        l3.reason
    );
}

// ─── G-04: upgrades ─────────────────────────────────────────────────────────

/// A reviewed, trained program is redeployed. Its evidence — the baselines,
/// the shapes, the operator's attestations — described the old code and is
/// withdrawn: the next verdict is back at a fresh program's confidence and
/// Gaming refuses it. The retired figures are kept.
#[tokio::test]
async fn an_upgrade_withdraws_the_programs_evidence() {
    let knobs: Shared = Arc::new(Mutex::new(Knobs {
        deployment: Deployment::Upgradeable(500),
        ..Default::default()
    }));
    let mut core = core_at(&cluster(Arc::clone(&knobs)));
    seed_reviewed(&mut core);
    let first = core
        .verify_async(&describe(8_000_001, WalletProfile::Gaming))
        .await
        .unwrap();
    assert!(first.approved, "{}", first.summary);
    assert!(
        warned(&first, "ProgramDeploymentEnrolled"),
        "seeded evidence cannot be dated against the first deployment: {}",
        first.summary
    );
    let _ = core
        .verify_async(&describe(8_000_002, WalletProfile::Gaming))
        .await
        .unwrap();
    assert_eq!(samples(&core), 2);
    assert!(core.retired_evidence().is_empty());

    knobs.lock().unwrap().deployment = Deployment::Upgradeable(2_000);
    let upgraded = core
        .verify_async(&describe(8_000_003, WalletProfile::Gaming))
        .await
        .unwrap();
    assert_eq!(upgraded.program_upgrades.len(), 1);
    assert!(
        warned(&upgraded, "its evidence was withdrawn"),
        "{}",
        upgraded.summary
    );
    let retired = core.retired_evidence();
    assert_eq!(retired.len(), 1);
    assert_eq!(retired[0].baseline_samples, 2);
    assert_eq!(retired[0].shape_baselines, 1);
    assert_eq!(
        retired[0].previous_deployment,
        Some(ObservedDeployment {
            deploy_slot: 500,
            upgrade_authority: None
        })
    );
    assert_eq!(
        retired[0]
            .evidence
            .as_ref()
            .map(|e| e.community_verified_count),
        Some(2)
    );
    let behavior = core.program_behavior(SYSTEM).unwrap();
    assert_eq!(behavior.evidence.community_verified_count, 0);
    assert!(
        behavior.evidence.has_signed_manifest,
        "the manifest's signature stays"
    );

    let next = core
        .verify_async(&describe(8_000_004, WalletProfile::Gaming))
        .await
        .unwrap();
    assert!(!next.approved, "{}", next.summary);
    assert!((next.confidence - 0.44).abs() < 1e-9, "{}", next.confidence);
    assert_eq!(samples(&core), 0, "nothing below the floor re-trains it");
}

/// The hostile upgrade before the first sighting: evidence was gathered
/// while the deployment could not be read, and the code on chain now was
/// deployed after it. A first-sighting baseline would have blessed it; the
/// evidence is withdrawn instead. Deployed BEFORE the evidence began, it
/// stands.
#[tokio::test]
async fn a_deployment_newer_than_the_evidence_at_first_sighting_withdraws_it() {
    for (deployed_at, withdrawn) in [(2_000u64, true), (10u64, false)] {
        let knobs: Shared = Arc::new(Mutex::new(Knobs {
            deployment: Deployment::Unreadable,
            sim_slot: 1_000,
            ..Default::default()
        }));
        let mut core = core_at(&cluster(Arc::clone(&knobs)));
        core.set_observation_policy(ObservationPolicy::OperatorBootstrap);
        for i in 0..3u64 {
            let _ = core
                .verify_async(&describe(9_000_000 + i, official_floor()))
                .await
                .unwrap();
        }
        assert_eq!(samples(&core), 3);
        assert_eq!(core.evidence_since_slot(SYSTEM), Some(1_000));

        {
            let mut k = knobs.lock().unwrap();
            k.deployment = Deployment::Upgradeable(deployed_at);
            k.sim_slot = 3_000;
        }
        let r = core
            .verify_async(&describe(9_100_000, official_floor()))
            .await
            .unwrap();
        assert_eq!(
            warned(&r, "ProgramEvidenceWithdrawn"),
            withdrawn,
            "deployed at {deployed_at}: {}",
            r.summary
        );
        assert_eq!(core.retired_evidence().len(), usize::from(withdrawn));
        // This verdict's own observation is of the code that runs now.
        assert_eq!(
            samples(&core),
            if withdrawn { 1 } else { 4 },
            "{deployed_at}"
        );
    }
}

/// The code changed between the simulation and the deployment read: the
/// figures describe replaced code and are not recorded.
#[tokio::test]
async fn a_simulation_of_replaced_code_is_not_recorded() {
    for (sim_slot, recorded) in [(900u64, false), (1_100u64, true)] {
        let knobs: Shared = Arc::new(Mutex::new(Knobs {
            deployment: Deployment::Upgradeable(1_000),
            sim_slot,
            ..Default::default()
        }));
        let mut core = core_at(&cluster(knobs));
        core.set_observation_policy(ObservationPolicy::OperatorBootstrap);
        let _ = core
            .verify_async(&describe(9_500_000, official_floor()))
            .await
            .unwrap();
        assert_eq!(
            samples(&core),
            u64::from(recorded),
            "simulated at {sim_slot}"
        );
    }
}

/// A program whose code is final (a builtin) says nothing; a loader-v4
/// program — redeployable, and not read — says it is not tracked.
#[tokio::test]
async fn untracked_deployments_say_so() {
    for (deployment, note) in [(Deployment::Native, false), (Deployment::LoaderV4, true)] {
        let knobs: Shared = Arc::new(Mutex::new(Knobs {
            deployment,
            ..Default::default()
        }));
        let core = core_at(&cluster(knobs));
        let r = core
            .verify_async(&describe(9_700_000, official_floor()))
            .await
            .unwrap();
        assert_eq!(warned(&r, "ProgramUpgradeUntracked"), note, "{}", r.summary);
        assert!(core.retired_evidence().is_empty());
    }
}
