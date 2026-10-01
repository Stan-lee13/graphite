//! A3-10 (2026-09-29 audit): L1 does not report `Passed` for an account whose
//! identity check failed.
//!
//! `verify_async` built L1 as `LayerStatus::Passed` unconditionally, with a
//! reason from `account_resolution_reason` that counted slots by the kind of
//! check they have (PDA, constant, unverified) and said "matched against fixed
//! addresses" without reading `pda_mismatch` or `expected_address_mismatch`.
//! A substituted fixed-address account was reported as matched by L1 while L7
//! blocked it as `AccountIdentityMismatch`. The verdict was right; the layer
//! report was not (P3).
//!
//! The fix: `account_resolution_reason` returns a status with its text. Any
//! PDA, expected-address or privilege mismatch makes L1 Failed, and the
//! wording separates slots that were re-derived or equal to a fixed address
//! from slots accepted by position only.
//!
//! The test sends a Stake `Deactivate` whose clock-sysvar slot holds another
//! address and pins that L1 is neither Passed nor worded as matched.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{GraphiteCore, LayerStatus, ProposedIntent, VerificationInput};

const STAKE: &str = "Stake11111111111111111111111111111111111111";
const STAKE_ACCOUNT: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const NOT_THE_CLOCK: &str = "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx";
const AUTHORITY: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";

#[test]
fn l1_does_not_certify_an_identity_that_failed() {
    // Stake Deactivate (u32 5): [stake(w), clock_sysvar (pinned), authority(s)].
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "stake".to_string(),
            raw_natural_language: String::new(),
            confidence_of_parse: 1.0,
            extracted_parameters: None,
        },
        program_id: STAKE.to_string(),
        protocol_version: String::new(),
        instruction_discriminator: "05000000".to_string(),
        account_addresses: vec![
            STAKE_ACCOUNT.to_string(),
            NOT_THE_CLOCK.to_string(),
            AUTHORITY.to_string(),
        ],
        instruction_data: Some(vec![5, 0, 0, 0]),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Treasury,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        real_account_metas: vec![],
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        state_diff: None,
    };
    let r = GraphiteCore::new().verify(&input).unwrap();
    assert!(
        r.resolved_accounts
            .iter()
            .any(|a| a.expected_address_mismatch),
        "sanity: slot 1 is not the clock sysvar"
    );
    let l1 = r
        .layers
        .iter()
        .find(|l| l.layer == "L1_AccountResolution")
        .unwrap();
    assert!(
        l1.status != LayerStatus::Passed && !l1.reason.contains("matched against fixed addresses"),
        "L1 says {:?}: {}",
        l1.status,
        l1.reason
    );
}
