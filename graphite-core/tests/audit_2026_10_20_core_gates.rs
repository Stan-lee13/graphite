//! Audit 2026-10-20 — the Core pipeline's gates that need no RPC.
//!
//! - M2: the verdict's trust tier is the lowest of every top-level program
//!   the transaction invokes, not the primary's alone.
//! - F4: a `proposed_intent` carrying a field it does not have is refused.
//! - F9: `with_data_dir` refuses a corrupt snapshot instead of starting fresh.
//! - F11: a simulation-plugin Block refuses the verdict (L3 Failed is a gate).
//! - F14: L2's unknown-instruction soft pass is Inconclusive, and L5's
//!   high-risk list reads the CANONICAL intent ("trade", "Swap" = "swap").
//! - H1 (the no-RPC half): without an RPC client the verdict is unchanged —
//!   L3 Inconclusive and `not_simulated`.
#![cfg(any(feature = "rpc", feature = "server", feature = "cli"))]

use graphite_core::confidence_engine::TrustTier;
use graphite_core::plugin_orchestrator::{
    LayerId, PluginContext, PluginKind, PluginManifest, PluginVerdict, ReviewStatus,
    SimulationPlugin,
};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::{Behavior, BehaviorEvidence};
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, UnobservedCode, VerificationInput,
    VerificationResult, VerificationScope,
};
use std::sync::Arc;

const SYSTEM: &str = "11111111111111111111111111111111";
const FROM: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const TO: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
/// A program no manifest describes and the graph has never seen.
const UNMANIFESTED: &str = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const COMPUTE_BUDGET: &str = "ComputeBudget111111111111111111111111111111";

/// The lowest bar that still demands a manifest-backed tier: on a fresh core
/// a described System transfer (0.44, OfficialManifest) clears it, so a
/// refusal below is the gate under test, not the score.
fn official_floor() -> WalletProfile {
    WalletProfile::Custom {
        min_confidence: 0.40,
        min_trust_tier: TrustTier::OfficialManifest,
    }
}

fn transfer_data(lamports: u64) -> Vec<u8> {
    let mut d = vec![2, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d
}

fn transfer(intent: &str) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: intent.to_string(),
            raw_natural_language: "send 0.002 SOL".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![FROM.to_string(), TO.to_string()],
        instruction_data: Some(transfer_data(2_000_000)),
        cpi_targets: vec![],
        wallet_profile: official_floor(),
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: None,
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

// ─── M2: the tier of every top-level program ────────────────────────────────

/// An unmanifested program beside an honest transfer used to cost a warning
/// and nothing else: the tier, its ceiling and the policy's tier floor read
/// the primary alone. The verdict's tier is now the lowest of them.
#[test]
fn an_unmanifested_sibling_sets_the_verdicts_tier() {
    let core = GraphiteCore::new();

    // Control: the transfer alone is OfficialManifest and clears the floor.
    let alone = core.verify(&transfer("transfer")).unwrap();
    assert!(alone.approved, "{}", alone.summary);
    assert_eq!(alone.trust_tier, "OfficialManifest");

    let mut with_sibling = transfer("transfer");
    with_sibling.transaction_instructions = vec![TransactionInstruction {
        program_id: UNMANIFESTED.to_string(),
        instruction_discriminator: "01".to_string(),
        account_addresses: vec![FROM.to_string()],
        cpi_targets: vec![],
    }];
    let r = core.verify(&with_sibling).unwrap();
    assert_eq!(
        r.risk_verdict.status, "Clear",
        "the sibling must not be refused by a risk finding, or this test proves nothing: {:?}",
        r.risk_verdict.findings
    );
    assert_eq!(r.trust_tier, "Unknown", "{}", r.summary);
    assert!(
        !r.approved,
        "an Unknown-tier sibling must not be approvable: {}",
        r.summary
    );
    assert_eq!(layer(&r, "L6").status, LayerStatus::Failed);
    assert!(
        r.summary.contains(UNMANIFESTED) && r.summary.contains("lowest of every program"),
        "the verdict must name the program that lowered its tier: {}",
        r.summary
    );
    // The ceiling follows the tier.
    assert!(r.confidence <= 0.55, "{}", r.confidence);
}

/// The tier is the minimum, so an EARNED tier on the primary is held to its
/// siblings' too: a BattleTested primary beside an OfficialManifest program
/// is an OfficialManifest verdict.
#[test]
fn an_earned_primary_tier_is_held_to_its_siblings() {
    let mut core = GraphiteCore::new();
    core.seed_behavior(Behavior {
        program_id: SYSTEM.to_string(),
        version: "1.0.0".to_string(),
        expected_state_changes: vec![],
        allowed_cpis: vec![],
        trust_tier: TrustTier::BattleTested,
        evidence: BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 5,
            battle_tested_tx_count: 50_000,
            simulation_match_count: 100,
        },
        quarantined: false,
        quarantine_reason: None,
    })
    .unwrap();
    let alone = core.verify(&transfer("transfer")).unwrap();
    assert_eq!(alone.trust_tier, "BattleTested", "{}", alone.summary);

    let mut with_budget = transfer("transfer");
    with_budget.transaction_instructions = vec![TransactionInstruction {
        program_id: COMPUTE_BUDGET.to_string(),
        // SetComputeUnitLimit(200_000).
        instruction_discriminator: "02400d0300".to_string(),
        account_addresses: vec![],
        cpi_targets: vec![],
    }];
    let r = core.verify(&with_budget).unwrap();
    assert_eq!(r.trust_tier, "OfficialManifest", "{}", r.summary);
    assert!(r.confidence <= 0.75 + 1e-9, "{}", r.confidence);
}

// ─── F4: a request outside its schema ───────────────────────────────────────

/// A misspelled field inside `proposed_intent` was dropped: a typo'd
/// `extractedParameters` silently switched off the FakeSwap output check.
#[test]
fn an_intent_with_an_unknown_field_is_refused() {
    let good = serde_json::to_value(transfer("swap")).unwrap();
    serde_json::from_value::<VerificationInput>(good.clone()).expect("the schema parses");
    let mut typo = good;
    typo["proposed_intent"]["extractedParameters"] = serde_json::json!({"output_token": "USDC"});
    let err = serde_json::from_value::<VerificationInput>(typo).unwrap_err();
    assert!(err.to_string().contains("extractedParameters"), "{err}");
}

// ─── F9: a corrupt snapshot is not a fresh start ────────────────────────────

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "graphite-a20-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|x| x.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// `with_data_dir` logged a corrupt snapshot and started FRESH — every
/// quarantine in it lifted, and the next snapshot overwriting the evidence —
/// while its doc called that fail-closed. It refuses now, like
/// `open_data_dir`.
#[test]
fn a_corrupt_snapshot_is_refused_not_replaced() {
    let dir = temp_dir("corrupt");
    std::fs::write(dir.join("semantic_graph.json"), "{ not json").unwrap();
    let err = GraphiteCore::try_with_data_dir(dir.clone()).unwrap_err();
    assert!(err.contains("corrupt"), "{err}");
    let panicked = std::panic::catch_unwind(|| GraphiteCore::with_data_dir(dir.clone()));
    assert!(
        panicked.is_err(),
        "with_data_dir must not start fresh over a corrupt snapshot"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("semantic_graph.json")).unwrap(),
        "{ not json",
        "the evidence is left where it was"
    );
    // Control: no snapshot yet is a fresh store, not an error.
    let empty = temp_dir("empty");
    assert!(GraphiteCore::try_with_data_dir(empty.clone()).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&empty);
}

// ─── F11: a simulation plugin's Block is a gate ─────────────────────────────

struct BlockingSim {
    m: PluginManifest,
}

impl SimulationPlugin for BlockingSim {
    fn manifest(&self) -> &PluginManifest {
        &self.m
    }
    fn observe_simulation(&self, _ctx: &PluginContext) -> PluginVerdict {
        PluginVerdict::Block {
            pattern: "TestSimBlock".to_string(),
            reason: "the simulation plugin refuses".to_string(),
        }
    }
}

/// A simulation-plugin Block failed the L3 report and left the verdict
/// `approved: true`.
#[test]
fn a_simulation_plugin_block_refuses_the_verdict() {
    let mut core = GraphiteCore::new();
    let control = core.verify(&transfer("transfer")).unwrap();
    assert!(control.approved, "{}", control.summary);

    core.register_plugin(PluginKind::Simulation(Arc::new(BlockingSim {
        m: PluginManifest {
            name: "test-blocking-sim".to_string(),
            version: "1.0.0".to_string(),
            author: "test".to_string(),
            layer: LayerId::L3SimulationVerification,
            review_status: ReviewStatus::Approved,
            description: String::new(),
        },
    })));
    let r = core.verify(&transfer("transfer")).unwrap();
    let l3 = layer(&r, "L3");
    assert_eq!(l3.status, LayerStatus::Failed, "{}", l3.reason);
    assert!(l3.reason.contains("TestSimBlock"), "{}", l3.reason);
    assert!(!r.approved, "an L3 plugin Block must refuse: {}", r.summary);
    assert_eq!(r.policy_verdict, "Rejected");
}

// ─── F14: L2 and L5 on an undescribed instruction ───────────────────────────

fn undescribed(intent: &str) -> VerificationInput {
    let mut input = transfer(intent);
    // System has no instruction 0x7f: the manifest does not describe it.
    input.instruction_discriminator = "7f000000".to_string();
    input.instruction_data = Some(vec![0x7f, 0, 0, 0]);
    // The most permissive profile there is, so only the layers decide.
    input.wallet_profile = WalletProfile::Custom {
        min_confidence: 0.0,
        min_trust_tier: TrustTier::Unknown,
    };
    input
}

/// L2 reported "Passed" for an instruction the manifest does not describe;
/// a check that confirmed nothing is Inconclusive.
#[test]
fn an_undescribed_instruction_is_not_a_passed_l2() {
    let r = GraphiteCore::new()
        .verify(&undescribed("transfer"))
        .unwrap();
    assert_eq!(r.instruction_name, "unknown_instruction");
    let l2 = layer(&r, "L2");
    assert_eq!(l2.status, LayerStatus::Inconclusive, "{}", l2.reason);
    assert!(!l2.passed);
    assert_eq!(r.trust_tier, "Unknown");
}

/// L5's high-risk list compared the RAW intent, so "trade", "exchange" and
/// "Swap" — the same declaration as "swap" to every other check — were
/// low-risk here, and Custom{0, Unknown} approved them on an undescribed
/// instruction.
#[test]
fn every_spelling_of_a_high_risk_intent_is_high_risk() {
    let core = GraphiteCore::new();
    for intent in [
        "swap", "trade", "exchange", "Swap", " SWAP ", "delegate", "stake",
    ] {
        let r = core.verify(&undescribed(intent)).unwrap();
        let l5 = layer(&r, "L5");
        assert_eq!(l5.status, LayerStatus::Failed, "{intent}: {}", l5.reason);
        assert!(!r.approved, "{intent}: {}", r.summary);
    }
    // Control: a low-risk intent stays the P12 soft pass.
    let r = core.verify(&undescribed("send")).unwrap();
    assert_eq!(layer(&r, "L5").status, LayerStatus::Inconclusive);
}

// ─── H1, without an RPC client ──────────────────────────────────────────────

/// With no RPC client attached nothing about H1 changes: an artifact-bound
/// verdict is L3 Inconclusive with `not_simulated`, and approvable — the
/// limitation is the operator's to accept, and it is named.
#[test]
fn without_an_rpc_client_an_artifact_verdict_is_unchanged() {
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/artifacts/sak_bridge_corpus.json")).unwrap();
    let entry = raw["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "legacy_single_transfer")
        .unwrap()
        .clone();
    let bytes: Vec<u8> = entry["raw"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect();
    let keys: Vec<String> = entry["static_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    let mut input = transfer("transfer");
    input.account_addresses = vec![keys[0].clone(), keys[1].clone()];
    input.signed_transaction = Some(bytes);
    let r = GraphiteCore::new().verify(&input).unwrap();
    assert!(r.approved, "{} {:?}", r.summary, r.risk_verdict.findings);
    assert_eq!(layer(&r, "L3").status, LayerStatus::Inconclusive);
    match &r.scope {
        VerificationScope::ArtifactBound {
            unobserved_codes,
            simulated,
            ..
        } => {
            assert!(!simulated);
            assert!(unobserved_codes.contains(&UnobservedCode::NotSimulated));
        }
        other => panic!("artifact-bound expected: {other:?}"),
    }
    assert!(!r
        .risk_verdict
        .findings
        .iter()
        .any(|f| f.pattern == "VerificationIncomplete" || f.pattern == "SimulationFailed"));
}
