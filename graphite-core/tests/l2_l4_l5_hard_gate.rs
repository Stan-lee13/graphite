//! P0 regression suite (2026-09-05 audit finding, fixed 2026-09-05):
//! "The certification document claims L2/L4/L5 failures are hard gates, but
//! current approval logic appears to rely on confidence penalties instead."
//!
//! GRAPHITE_FINAL_CERTIFICATION_REPORT.md's "CRITICAL #6" originally required
//! `approved` to hard-require `l2_result.passed && l4_result.passed &&
//! l5_result.passed`. A later tri-state refactor (GAP-2026-08-06-3) correctly
//! introduced `LayerStatus::{Passed, Failed, Inconclusive}` so that an
//! Inconclusive layer (insufficient evidence — e.g. an unknown protocol)
//! never wrongly penalizes, but in doing so replaced the hard gate with a
//! confidence PENALTY (0.2 for L2, 0.15 for L4, 0.3 for L5) for a genuinely
//! Failed layer too. That is exploitable: a BattleTested-tier transaction can
//! reach confidence 1.0, and a single L2 Failed (a confirmed instruction-data
//! / discriminator mismatch — the caller's own input self-contradicting) only
//! costs 0.2, landing at exactly 0.80 — which clears TradingBot's 0.80
//! threshold.
//!
//! Resolution (see verification.rs's `structural_layer_failed`): a GENUINE
//! Failed (never Inconclusive) L2, L4, or L5 result is now a hard gate,
//! exactly like a Risk Engine block or a policy-plugin veto — restoring the
//! certification report's original intent, correctly scoped so P12's
//! Inconclusive soft-pass semantics are preserved. These tests prove the gate
//! fires regardless of trust tier or wallet-profile permissiveness, prove it
//! does NOT fire for Inconclusive layers, and prove the confidence penalty
//! (kept for explainability) is not what's doing the rejecting.

use graphite_core::plugin_orchestrator::{
    LayerId, PluginContext, PluginKind, PluginManifest, PluginVerdict, ReviewStatus, VerifierPlugin,
};
use graphite_core::semantic_graph_store::{Behavior, BehaviorEvidence, TrustTier};
use graphite_core::simulation_integrity::ComputeBaseline;
use graphite_core::verification::{GraphiteCore, LayerStatus, ProposedIntent, VerificationInput};
use graphite_core::WalletProfile;

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const SIGNER: &str = "7vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const RECIPIENT: &str = "6bSsP4p6wXqFJdD2TkYgNcVmLzHfWq7pRyA8tCzE5nBj";
const UNKNOWN_PROGRAM: &str = "GdP9U5aYx7f2kQzVwNmT8jRcL4hB6eX3sDnWqA1uMoH";

fn system_transfer(profile: WalletProfile) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Send 0.5 SOL to Alice".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: SYSTEM_PROGRAM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![SIGNER.to_string(), RECIPIENT.to_string()],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: profile,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
    }
}

/// Evidence that earns BattleTested tier (1000+ tx AND signed/community) —
/// same convention as tests/policy_profiles.rs's `battle_tested_evidence`.
/// With this seeded, a plain System transfer reaches confidence ~1.00.
fn battle_tested_evidence() -> BehaviorEvidence {
    BehaviorEvidence {
        has_signed_manifest: true,
        community_verified_count: 2,
        battle_tested_tx_count: 1000,
        simulation_match_count: 100,
    }
}

/// Seed an EARNED (never request-body) BattleTested-tier record for
/// SYSTEM_PROGRAM, exactly like tests/policy_profiles.rs's `seed_system`.
fn seed_battle_tested(core: &mut GraphiteCore) {
    core.seed_simulation_baseline(
        SYSTEM_PROGRAM,
        ComputeBaseline {
            mean_compute_units: 150.0,
            std_compute_units: 1.0,
            sample_count: 50,
            mean_account_writes: 2.0,
            std_account_writes: 0.5,
            mean_cpi_hops: 0.0,
            std_cpi_hops: 0.1,
            ..Default::default()
        },
    )
    .expect("baseline seed");
    core.seed_behavior(Behavior {
        program_id: SYSTEM_PROGRAM.to_string(),
        version: "1.0.0".to_string(),
        expected_state_changes: vec!["debits accounts.from by amount".to_string()],
        allowed_cpis: vec![],
        trust_tier: TrustTier::Unknown, // recomputed by append (P7)
        evidence: battle_tested_evidence(),
        quarantined: false,
        quarantine_reason: None,
    })
    .expect("behavior seed");
}

// ── L2: a genuine discriminator/instruction_data mismatch ──────────────────

#[test]
fn l2_failed_blocks_approval_at_battle_tested_tier_and_tradingbot_threshold() {
    let mut core = GraphiteCore::new();
    seed_battle_tested(&mut core);
    let mut input = system_transfer(WalletProfile::TradingBot);
    // instruction_discriminator is "02000000" (System Transfer) but
    // instruction_data starts with different bytes — a self-contradictory
    // input (the exact HIGH #1 "Discriminator Check Bypass" class).
    input.instruction_data = Some(vec![0xff, 0x00, 0x00, 0x00, 1, 0, 0, 0, 0, 0, 0, 0]);

    let result = core.verify(&input).unwrap();

    let l2 = result
        .layers
        .iter()
        .find(|l| l.layer == "L2_InstructionVerification")
        .unwrap();
    assert_eq!(
        l2.status,
        LayerStatus::Failed,
        "expected a genuine L2 Failed (data/discriminator mismatch), got {:?}: {}",
        l2.status,
        l2.reason
    );
    assert!(
        !result.approved,
        "a confirmed L2 discriminator/data mismatch must block regardless of trust tier or \
         profile — got approved=true at confidence={} (this is exactly the certification \
         report's CRITICAL #6, un-fixed)",
        result.confidence
    );
    // Prove this is the HARD GATE, not merely insufficient confidence: the
    // penalty-adjusted confidence is still at or above TradingBot's 0.80 —
    // under the old penalty-only model this would have been approved.
    assert!(
        result.confidence >= 0.79,
        "expected the penalty-adjusted confidence to still clear TradingBot's threshold \
         (proving the block is the hard gate, not a confidence deficiency), got {}",
        result.confidence
    );
    assert_eq!(result.policy_verdict, "Rejected");
}

#[test]
fn l2_failed_blocks_approval_even_on_the_most_permissive_gaming_profile() {
    let mut core = GraphiteCore::new();
    seed_battle_tested(&mut core);
    let mut input = system_transfer(WalletProfile::Gaming);
    input.instruction_data = Some(vec![0xff, 0x00, 0x00, 0x00]);

    let result = core.verify(&input).unwrap();

    assert!(
        !result.approved,
        "L2 Failed must block even on Gaming (0.55 / HeuristicInferred), got approved=true"
    );
}

/// Control: the SAME high-evidence setup, but with instruction_data that
/// correctly matches the discriminator — must approve normally. Proves the
/// gate above is specifically about the mismatch, not a general regression.
#[test]
fn l2_passed_with_matching_instruction_data_still_approves() {
    let mut core = GraphiteCore::new();
    seed_battle_tested(&mut core);
    let mut input = system_transfer(WalletProfile::TradingBot);
    input.instruction_data = Some(vec![0x02, 0x00, 0x00, 0x00, 1, 0, 0, 0, 0, 0, 0, 0]);

    let result = core.verify(&input).unwrap();

    let l2 = result
        .layers
        .iter()
        .find(|l| l.layer == "L2_InstructionVerification")
        .unwrap();
    assert_ne!(
        l2.status,
        LayerStatus::Failed,
        "L2 must pass: {}",
        l2.reason
    );
    assert!(
        result.approved,
        "matching instruction_data at battle-tested tier must approve: {}",
        result.summary
    );
}

// ── L4: a plugin-forced state-verification failure ──────────────────────────

struct BlockingVerifier {
    manifest: PluginManifest,
}
impl VerifierPlugin for BlockingVerifier {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
    fn verify(&self, _ctx: &PluginContext) -> PluginVerdict {
        PluginVerdict::Block {
            pattern: "TestStateVeto".into(),
            reason: "state-verification test veto".into(),
        }
    }
}

#[test]
fn l4_failed_blocks_approval_at_high_confidence() {
    let mut core = GraphiteCore::new();
    seed_battle_tested(&mut core);
    core.register_plugin(PluginKind::Verifier(std::sync::Arc::new(
        BlockingVerifier {
            manifest: PluginManifest {
                name: "l4-test-veto".to_string(),
                version: "1.0.0".to_string(),
                author: "test".to_string(),
                layer: LayerId::L4StateVerification,
                review_status: ReviewStatus::Approved,
                description: String::new(),
            },
        },
    )));

    let result = core
        .verify(&system_transfer(WalletProfile::TradingBot))
        .unwrap();

    let l4 = result
        .layers
        .iter()
        .find(|l| l.layer == "L4_StateVerification")
        .unwrap();
    assert_eq!(l4.status, LayerStatus::Failed);
    assert!(
        !result.approved,
        "a genuine L4 Failed must block regardless of confidence, got approved=true at {}",
        result.confidence
    );
    assert!(
        result.confidence >= 0.79,
        "expected penalty-adjusted confidence to still clear the threshold (proving hard \
         gate, not confidence deficiency), got {}",
        result.confidence
    );
}

// ── L5: a genuine intent/instruction semantic mismatch ──────────────────────

#[test]
fn l5_failed_intent_mismatch_blocks_approval_at_high_confidence() {
    let mut core = GraphiteCore::new();
    seed_battle_tested(&mut core);
    let mut input = system_transfer(WalletProfile::TradingBot);
    // Declared intent "stake" on a plain System Transfer instruction — a
    // genuine semantic mismatch (not one of the L5 special-cased high-risk
    // intents for the unknown-instruction path; this is a KNOWN instruction
    // going through the general intent-vs-instruction keyword comparison).
    input.proposed_intent.intent_type = "stake".to_string();

    let result = core.verify(&input).unwrap();

    let l5 = result
        .layers
        .iter()
        .find(|l| l.layer == "L5_SemanticVerification")
        .unwrap();
    assert_eq!(
        l5.status,
        LayerStatus::Failed,
        "expected a genuine L5 intent mismatch, got {:?}: {}",
        l5.status,
        l5.reason
    );
    assert!(
        !result.approved,
        "a confirmed intent/instruction mismatch must block regardless of trust tier, got \
         approved=true at confidence={}",
        result.confidence
    );
}

// ── Inconclusive layers must NOT trigger the new gate (P12 preserved) ──────

#[test]
fn inconclusive_l2_l4_l5_on_unknown_protocol_does_not_trigger_the_structural_gate() {
    let core = GraphiteCore::new();
    let mut input = system_transfer(WalletProfile::Gaming);
    input.program_id = UNKNOWN_PROGRAM.to_string();

    let result = core.verify(&input).unwrap();

    for name in [
        "L2_InstructionVerification",
        "L4_StateVerification",
        "L5_SemanticVerification",
    ] {
        let layer = result.layers.iter().find(|l| l.layer == name).unwrap();
        assert_ne!(
            layer.status,
            LayerStatus::Failed,
            "{name} must be Inconclusive (insufficient evidence), never Failed, for an \
             unknown protocol: {}",
            layer.reason
        );
    }
    // The transaction may still be rejected for OTHER reasons (Unknown trust
    // tier is below Gaming's HeuristicInferred minimum) — that is correct
    // and unrelated. What matters here is that the NEW structural gate is
    // not what's rejecting it.
    assert!(
        !result.summary.contains("structural verification failed")
            && !result
                .layers
                .iter()
                .any(|l| l.reason.contains("structural verification failed")),
        "the structural gate must not be attributed as the rejection reason for an \
         Inconclusive-only result: {}",
        result.summary
    );
}

// ── Determinism ───────────────────────────────────────────────────────────

#[test]
fn structural_gate_verdict_is_deterministic() {
    let mut core = GraphiteCore::new();
    seed_battle_tested(&mut core);
    let mut input = system_transfer(WalletProfile::TradingBot);
    input.instruction_data = Some(vec![0xff, 0x00, 0x00, 0x00]);

    let a = core.verify(&input).unwrap();
    let b = core.verify(&input).unwrap();

    assert_eq!(a.approved, b.approved);
    assert_eq!(a.policy_verdict, b.policy_verdict);
    assert_eq!(a.content_hash, b.content_hash);
}
