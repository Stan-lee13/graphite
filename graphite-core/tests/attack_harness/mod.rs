//! Shared harness for the four hand-written attack suites (`novel_attacks`,
//! `adversarial_handcrafted`, `real_world_attacks`, `extreme_adversarial`).
//!
//! Round 29 (audit 2026-10-20, MED-6). The suites used to turn ANY error out of
//! `verify()` into a "blocked" result — the pattern Round 25 removed from
//! `regression_corpus.rs` — and mostly asserted only `!approved` or
//! `confidence <= 0.55` under default evidence, where nothing is approvable at
//! all (the mainnet conformance run approves 0 of its real transactions with
//! no earned evidence). Such a case passes with its detector deleted. Here:
//!
//! - an `Err` from `verify()` fails the case, unless the case says it expects
//!   input validation to refuse the input (`expect_input_refused`);
//! - a block is asserted by its CAUSE (`assert_blocked_by`): the Risk Engine
//!   pattern, the failed layer, or the confidence ceiling of an unknown
//!   protocol, so removing the detector that blocks a case fails it;
//! - `seeded_core` gives the positive controls an engine that HAS earned
//!   evidence for a program, so a benign transaction through the same harness
//!   is approved — proving the cases are blocked by what they assert, not by
//!   an engine that approves nothing.
#![allow(dead_code)]

use graphite_core::semantic_graph_store::{Behavior, BehaviorEvidence, TrustTier};
use graphite_core::simulation_integrity::ComputeBaseline;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, VerificationError, VerificationInput, VerificationResult,
};

/// `verify()` on a fresh engine. An error is a test failure, not a block.
pub fn verify(input: &VerificationInput) -> VerificationResult {
    verify_with(&GraphiteCore::new(), input)
}

pub fn verify_with(core: &GraphiteCore, input: &VerificationInput) -> VerificationResult {
    match core.verify(input) {
        Ok(r) => r,
        Err(e) => panic!(
            "verify() returned an error, not a verdict: {e}. An error is not a block; \
             a case that expects input validation to refuse its input must use \
             `expect_input_refused`"
        ),
    }
}

/// The case expects `verify()` to refuse its input outright (an
/// input-validation error), and names the error.
pub fn expect_input_refused(input: &VerificationInput, contains: &str) -> VerificationError {
    match GraphiteCore::new().verify(input) {
        Ok(r) => panic!(
            "expected input validation to refuse this input ({contains:?}), got a verdict: \
             approved={} {}",
            r.approved, r.summary
        ),
        Err(e) => {
            // A refusal of the INPUT: a malformed field (`InvalidInput`), an
            // address that is not a public key or an account list the
            // instruction cannot have (`AccountResolution`), or a
            // transaction that cannot be built from it (`TransactionBuild`).
            // An internal failure of a later stage is not input validation.
            assert!(
                matches!(
                    e,
                    VerificationError::InvalidInput(_)
                        | VerificationError::AccountResolution(_)
                        | VerificationError::TransactionBuild(_)
                ),
                "expected an input-validation error, got {e:?}"
            );
            assert!(
                e.to_string().contains(contains),
                "the refusal must name {contains:?}: {e}"
            );
            e
        }
    }
}

/// What blocked a verdict, as stable tokens:
///
/// - `risk:<Pattern>`   every Risk Engine finding;
/// - `layer:<Layer>`    every pipeline layer whose status is `Failed`;
/// - `unknown_protocol` the program has no manifest (the P6 ceiling applies);
/// - `evidence_ceiling` no detector fired and no structural layer failed: the
///   policy layer refused it because the evidence on record does not lift
///   its confidence or tier over the profile's bar.
pub fn block_reasons(r: &VerificationResult) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for f in &r.risk_verdict.findings {
        out.push(format!("risk:{}", f.pattern));
    }
    for l in &r.layers {
        if l.status == LayerStatus::Failed {
            out.push(format!("layer:{}", l.layer));
        }
    }
    if r.unknown_protocol {
        out.push("unknown_protocol".to_string());
    }
    // Nothing but the policy layer refused it: no detector fired, and the
    // verdict is a block only because the confidence or tier the evidence
    // allows did not clear the profile. Named so a case that relies on it
    // says so.
    let only_policy = r.risk_verdict.findings.is_empty()
        && r.layers
            .iter()
            .all(|l| l.status != LayerStatus::Failed || l.layer == "L6_PolicyVerification")
        && r.layers
            .iter()
            .any(|l| l.layer == "L6_PolicyVerification" && l.status == LayerStatus::Failed);
    if only_policy {
        out.push("evidence_ceiling".to_string());
    }
    out.sort();
    out.dedup();
    out
}

/// The verdict is a block, and every one of `expected` is among its causes.
pub fn assert_blocked_by(r: &VerificationResult, expected: &[&str]) {
    assert!(
        !r.approved,
        "expected a block by {expected:?}, got an approval: {}",
        r.summary
    );
    let have = block_reasons(r);
    for e in expected {
        assert!(
            have.iter().any(|h| h == e),
            "expected the block to be caused by {e:?}; its causes are {have:?} \
             (confidence {}, policy {:?}, summary {})",
            r.confidence,
            r.policy_verdict,
            r.summary
        );
    }
    if expected.contains(&"unknown_protocol") {
        // The unknown-protocol ceiling (P6) is what the token stands for.
        assert!(
            r.confidence <= 0.55,
            "an unknown protocol must stay under the 0.55 ceiling, got {}",
            r.confidence
        );
    }
}

/// Evidence that earns BattleTested in the Semantic Graph (1,000+
/// transactions, signed manifest, community verification) — the convention
/// of `tests/policy_profiles.rs`.
pub fn earned_evidence() -> BehaviorEvidence {
    BehaviorEvidence {
        has_signed_manifest: true,
        community_verified_count: 2,
        battle_tested_tx_count: 1000,
        simulation_match_count: 100,
    }
}

/// An engine that has EARNED evidence for `program_id` (operator-seeded graph
/// behaviour and simulation baseline — never request input).
pub fn seeded_core(program_id: &str, expected_state_changes: &[&str]) -> GraphiteCore {
    try_seeded_core(program_id, expected_state_changes).expect("seed earned evidence")
}

pub fn try_seeded_core(
    program_id: &str,
    expected_state_changes: &[&str],
) -> Result<GraphiteCore, VerificationError> {
    let mut core = GraphiteCore::new();
    core.seed_simulation_baseline(
        program_id,
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
    )?;
    core.seed_behavior(Behavior {
        program_id: program_id.to_string(),
        version: "1.0.0".to_string(),
        expected_state_changes: expected_state_changes
            .iter()
            .map(|s| s.to_string())
            .collect(),
        allowed_cpis: vec![],
        trust_tier: TrustTier::Unknown, // recomputed by append (P7)
        evidence: earned_evidence(),
        quarantined: false,
        quarantine_reason: None,
    })?;
    Ok(core)
}

/// A positive control: the benign input is APPROVED by an engine with earned
/// evidence for its program. If this fails, the suite's blocks prove nothing.
pub fn assert_approved(r: &VerificationResult) {
    assert!(
        r.approved,
        "positive control: a benign transaction with earned evidence must be approved; \
         causes {:?}, confidence {}, policy {:?}: {}",
        block_reasons(r),
        r.confidence,
        r.policy_verdict,
        r.summary
    );
}

/// The input under an engine with earned evidence for its program, shaped to
/// that engine's baseline (the `discover` convention).
pub fn verify_seeded(input: &VerificationInput) -> VerificationResult {
    let mut seeded_input = input.clone();
    seeded_input.compute_units = 150;
    seeded_input.account_writes = 2;
    seeded_input.cpi_hops = 0;
    let core = seeded_core(&input.program_id, &["debits accounts.from by amount"]);
    verify_with(&core, &seeded_input)
}

/// R30: a case blocked by `evidence_ceiling` alone says so in a comment —
/// "with earned evidence the same input is APPROVED". This makes the comment
/// a test: no detector refuses the shape, and when one starts to, this fails
/// and the case should assert that detector instead. It pins a LIMITATION of
/// the request-time Core (a recipient it cannot know is a drainer, a stale
/// account it cannot see); the agent guard's recipient grounding is what
/// refuses most of them before signing.
pub fn assert_approved_with_earned_evidence(input: &VerificationInput) {
    let r = verify_seeded(input);
    assert!(
        r.approved,
        "documented as blocked only for want of evidence, but with earned evidence it is \
         refused by {:?} — assert that cause instead: {}",
        block_reasons(&r),
        r.summary
    );
}

/// Discovery aid for maintainers: with `GRAPHITE_ATTACK_DISCOVER=1`, print
/// each case's causes (`cargo test --test <suite> -- --nocapture`).
/// Also prints what the same input gets from an engine with earned evidence
/// for its program (`SEEDED`), which tells a detector's block from a block
/// that only the absence of evidence produced.
pub fn discover(input: &VerificationInput, r: &VerificationResult) {
    if std::env::var_os("GRAPHITE_ATTACK_DISCOVER").is_some() {
        let mut seeded_input = input.clone();
        seeded_input.compute_units = 150;
        seeded_input.account_writes = 2;
        seeded_input.cpi_hops = 0;
        let seeded = try_seeded_core(&input.program_id, &["debits accounts.from by amount"])
            .and_then(|core| core.verify(&seeded_input))
            .map(|s| format!("approved={} {:?}", s.approved, block_reasons(&s)))
            .unwrap_or_else(|e| format!("error {e}"));
        eprintln!(
            "DISCOVER\t{}\t{:?}\tconf={}\tSEEDED {}",
            std::thread::current().name().unwrap_or("?"),
            block_reasons(r),
            r.confidence,
            seeded
        );
    }
}
