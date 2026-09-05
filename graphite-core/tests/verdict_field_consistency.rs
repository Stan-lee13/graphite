//! CRITICAL regression suite (2026-09-05 SDK integration audit):
//! "`policy_verdict` can read \"Approved\" while `approved` is false."
//!
//! `schemas/verification-result-v1.json` states that `approved` is the ONLY
//! field a consumer may gate execution on. That is the right rule — but it
//! was only a schema description string, enforced nowhere, while the result
//! payload could actually CONTRADICT itself:
//!
//!   - `policy_verdict` was derived from the policy engine's verdict, which
//!     is computed from the risk verdict captured BEFORE the L3
//!     simulation-integrity check runs.
//!   - When simulation flags compute divergence (the SimulationSpoofing case
//!     this layer exists to catch), the code mutates the FINAL `risk_summary`
//!     to "Blocked" — correctly forcing `approved = false` — but never
//!     resynced `policy_verdict`.
//!
//! So a flagged transaction came back as `approved: false` alongside
//! `policy_verdict: "Approved"`. A developer who gated on the field literally
//! named "policy verdict" — the more human-readable one, and the one the
//! stale `examples/sample-verification-result.json` showcased — would sign a
//! transaction Graphite's own simulation layer had flagged as spoofed.
//!
//! These tests assert the INVARIANT rather than the specific code path, so
//! they keep holding as new late-stage risk mutations are added:
//! `policy_verdict == "Approved"` if and only if `approved == true`.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::{BehaviorEvidence, TrustTier};
use graphite_core::simulation_integrity::ComputeBaseline;
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const FROM: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const TO: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

/// A plain System-Program transfer that a permissive profile would otherwise
/// approve — so any rejection observed is attributable to what the test
/// deliberately introduces, not to baseline strictness.
fn transfer_input(compute_units: u64) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: SYSTEM_PROGRAM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![FROM.to_string(), TO.to_string()],
        instruction_data: None,
        cpi_targets: vec![],
        // Most permissive built-in profile: isolates the invariant under test
        // from confidence-threshold effects.
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 5,
            battle_tested_tx_count: 50_000,
            simulation_match_count: 100,
        },
        compute_units,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
    }
}

/// A tight baseline: any wildly different compute figure is a large z-score.
fn tight_baseline() -> ComputeBaseline {
    ComputeBaseline {
        mean_compute_units: 450.0,
        std_compute_units: 5.0,
        sample_count: 500,
        mean_account_writes: 2.0,
        std_account_writes: 0.5,
        mean_cpi_hops: 0.0,
        std_cpi_hops: 0.5,
        ..Default::default()
    }
}

/// THE regression: a simulation-flagged transaction must never advertise
/// `policy_verdict: "Approved"`.
#[test]
fn simulation_flagged_transaction_never_reports_policy_approved() {
    let core = GraphiteCore::new();
    core.seed_simulation_baseline(SYSTEM_PROGRAM, tight_baseline())
        .expect("baseline seeds");

    // Compute usage far outside the seeded baseline -> divergence flagged.
    let result = core.verify(&transfer_input(999_999)).unwrap();

    assert!(
        !result.approved,
        "a simulation-flagged transaction must not be approved"
    );
    assert_eq!(
        result.risk_verdict.status, "Blocked",
        "simulation divergence must block: {:?}",
        result.risk_verdict.findings
    );
    assert_ne!(
        result.policy_verdict, "Approved",
        "policy_verdict said \"Approved\" on a BLOCKED transaction — a developer \
         gating on this field would sign a flagged transaction. findings={:?}",
        result.risk_verdict.findings
    );
}

/// The general invariant, stated directly: the two fields can never disagree.
/// Exercised across a spread of inputs so a future late-stage mutation of
/// `risk_summary` that forgets to resync `policy_verdict` fails here.
#[test]
fn approved_and_policy_verdict_never_disagree() {
    let core = GraphiteCore::new();
    core.seed_simulation_baseline(SYSTEM_PROGRAM, tight_baseline())
        .expect("baseline seeds");

    // In-baseline, wildly-out-of-baseline, zero, and boundary-ish values.
    for cu in [450u64, 455, 0, 1_000, 100_000, 999_999] {
        let result = core.verify(&transfer_input(cu)).unwrap();
        assert_eq!(
            result.policy_verdict == "Approved",
            result.approved,
            "policy_verdict/approved disagreement at compute_units={cu}: \
             approved={}, policy_verdict={:?}, risk={:?}",
            result.approved,
            result.policy_verdict,
            result.risk_verdict.status
        );
    }
}

/// The same invariant must hold across every wallet profile — the profiles
/// change the confidence bar, and the rejection reason with it, but never
/// whether the two fields agree.
#[test]
fn invariant_holds_across_wallet_profiles() {
    let core = GraphiteCore::new();
    core.seed_simulation_baseline(SYSTEM_PROGRAM, tight_baseline())
        .expect("baseline seeds");

    for profile in [
        WalletProfile::Gaming,
        WalletProfile::TradingBot,
        WalletProfile::Treasury,
        WalletProfile::Enterprise,
        WalletProfile::Custom {
            min_confidence: 0.0,
            min_trust_tier: TrustTier::Unknown,
        },
    ] {
        for cu in [450u64, 999_999] {
            let mut input = transfer_input(cu);
            input.wallet_profile = profile;
            let result = core.verify(&input).unwrap();
            assert_eq!(
                result.policy_verdict == "Approved",
                result.approved,
                "disagreement for profile {:?} at compute_units={cu}: \
                 approved={}, policy_verdict={:?}",
                profile,
                result.approved,
                result.policy_verdict
            );
        }
    }
}

/// A control: a clean transaction that IS approved must still say "Approved",
/// so the fix isn't just hardcoding "Rejected" everywhere and destroying the
/// field's meaning (P3 — explainability is not optional).
#[test]
fn clean_approved_transaction_still_reports_policy_approved() {
    let core = GraphiteCore::new();
    core.seed_simulation_baseline(SYSTEM_PROGRAM, tight_baseline())
        .expect("baseline seeds");

    // Usage matching the baseline, most permissive profile.
    let mut input = transfer_input(450);
    input.wallet_profile = WalletProfile::Custom {
        min_confidence: 0.0,
        min_trust_tier: TrustTier::Unknown,
    };
    let result = core.verify(&input).unwrap();

    assert!(
        result.approved,
        "a clean in-baseline transfer on a zero-threshold profile must approve: {} | {:?}",
        result.summary, result.risk_verdict
    );
    assert_eq!(
        result.policy_verdict, "Approved",
        "an approved transaction must still report policy_verdict Approved"
    );
}

/// Determinism (P2): the pair of fields is stable across runs.
#[test]
fn verdict_fields_are_deterministic() {
    let core = GraphiteCore::new();
    core.seed_simulation_baseline(SYSTEM_PROGRAM, tight_baseline())
        .expect("baseline seeds");
    let a = core.verify(&transfer_input(999_999)).unwrap();
    let b = core.verify(&transfer_input(999_999)).unwrap();
    assert_eq!(a.approved, b.approved);
    assert_eq!(a.policy_verdict, b.policy_verdict);
    assert_eq!(a.content_hash, b.content_hash);
}
