//! The layer reports must describe the decision that was actually made.
//!
//! A verification result is two things at once: a verdict, and the permanent
//! record of why (P3, P9). The verdict is what protects a wallet; the record is
//! what an auditor reconciles months later, and what an operator reads when
//! calibrating a profile. A record that disagrees with its own verdict is not a
//! cosmetic defect — it is the audit trail asserting something untrue.
//!
//! This suite exists because exactly that happened. The L6 reason string built
//! its `min_conf` from a hardcoded copy of the profile thresholds rather than
//! from `WalletProfile::thresholds()`. C53 lowered Gaming from 0.60 to 0.55 in
//! the policy engine and the copy was never updated, so every Gaming
//! verification recorded `min_conf: 0.60` while the gate enforced 0.55. A
//! transaction approved at 0.57 was filed alongside a note saying the minimum
//! was 0.60. Found live against the running container, where the L6 report and
//! `graphite profiles` — the same binary — disagreed about the same number.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::{Behavior, BehaviorEvidence, TrustTier};
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

const SYSTEM: &str = "11111111111111111111111111111111";
const ALICE: &str = "7vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const BOB: &str = "6bSsP4p6wXqFJdD2TkYgNcVmLzHfWq7pRyA8tCzE5nBj";

fn input(profile: WalletProfile) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Send 0.001 SOL".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![ALICE.to_string(), BOB.to_string()],
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
        real_account_metas: vec![],
        state_diff: None,
    }
}

fn l6_reason(result: &graphite_core::verification::VerificationResult) -> String {
    result
        .layers
        .iter()
        .find(|l| l.layer == "L6_PolicyVerification")
        .expect("L6 must always be reported")
        .reason
        .clone()
}

/// Parse `min_conf: 0.55` back out of the reason the operator actually reads.
fn reported_min_conf(reason: &str) -> f64 {
    let tail = reason
        .split("min_conf: ")
        .nth(1)
        .unwrap_or_else(|| panic!("L6 reason has no min_conf: {reason}"));
    let num: String = tail
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    num.parse()
        .unwrap_or_else(|_| panic!("unparseable min_conf in: {reason}"))
}

fn reported_min_tier(reason: &str) -> String {
    let tail = reason
        .split("min_tier: ")
        .nth(1)
        .unwrap_or_else(|| panic!("L6 reason has no min_tier: {reason}"));
    tail.chars().take_while(|c| c.is_alphanumeric()).collect()
}

#[test]
fn the_l6_report_states_the_threshold_the_policy_engine_actually_enforces() {
    let core = GraphiteCore::new();
    for profile in [
        WalletProfile::Treasury,
        WalletProfile::TradingBot,
        WalletProfile::Gaming,
        WalletProfile::Enterprise,
        WalletProfile::Custom {
            min_confidence: 0.42,
            min_trust_tier: TrustTier::OfficialManifest,
        },
    ] {
        let (enforced_conf, enforced_tier) = profile.thresholds();
        let result = core.verify(&input(profile)).expect("verify");
        let reason = l6_reason(&result);

        assert!(
            (reported_min_conf(&reason) - enforced_conf).abs() < 1e-9,
            "{profile:?}: the audit trail says min_conf {} but the policy engine \
             enforces {enforced_conf} — the record contradicts the decision.\nreason: {reason}",
            reported_min_conf(&reason)
        );
        assert_eq!(
            reported_min_tier(&reason),
            format!("{enforced_tier:?}"),
            "{profile:?}: reported min_tier disagrees with the enforced one.\nreason: {reason}"
        );
    }
}

/// The specific regression: Gaming is 0.55, and a report claiming 0.60 is the
/// exact defect this file was written for.
#[test]
fn gaming_is_reported_as_the_055_it_enforces_not_the_060_it_used_to() {
    let core = GraphiteCore::new();
    let reason = l6_reason(&core.verify(&input(WalletProfile::Gaming)).unwrap());
    assert!(
        !reason.contains("min_conf: 0.60"),
        "the stale pre-C53 Gaming threshold is back in the layer report: {reason}"
    );
    assert!(reason.contains("min_conf: 0.55"), "{reason}");
}

/// The consequence that made it worth fixing: an approval inside the window the
/// stale number excluded. At 0.55–0.60 Gaming approves, and the record must not
/// say the minimum was higher than the score that passed it.
#[test]
fn an_approval_inside_the_stale_windows_gap_is_recorded_consistently() {
    let mut core = GraphiteCore::new();
    // Earn enough evidence to land above 0.55 but below 0.60 is not directly
    // dialable, so assert the weaker, sufficient property: whenever L6 approves,
    // the confidence it approved is at least the threshold it reported.
    core.seed_behavior(Behavior {
        program_id: SYSTEM.to_string(),
        version: "1.0.0".to_string(),
        expected_state_changes: vec!["debits accounts.from by amount".to_string()],
        allowed_cpis: vec![],
        trust_tier: TrustTier::Unknown,
        evidence: BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 2,
            battle_tested_tx_count: 1000,
            simulation_match_count: 100,
        },
        quarantined: false,
        quarantine_reason: None,
    })
    .expect("seed");

    for profile in [
        WalletProfile::Gaming,
        WalletProfile::TradingBot,
        WalletProfile::Treasury,
        WalletProfile::Enterprise,
    ] {
        let result = core.verify(&input(profile)).expect("verify");
        let reason = l6_reason(&result);
        let reported = reported_min_conf(&reason);
        if result.approved {
            assert!(
                result.confidence + 1e-9 >= reported,
                "{profile:?}: APPROVED at confidence {} while the record says the \
                 minimum was {reported} — the audit trail cannot explain its own \
                 approval.\nreason: {reason}",
                result.confidence
            );
        }
    }
}
