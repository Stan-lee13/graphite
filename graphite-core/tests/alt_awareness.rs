//! P1 regression suite (2026-09-05 audit finding): "no real ALT/v0
//! transaction awareness in the verification path."
//!
//! Graphite has no independent way to detect that a transaction is a
//! versioned (v0) message or that it resolves accounts through Address
//! Lookup Tables — it only ever sees the flat `account_addresses` list a
//! caller supplies. Full bincode `VersionedTransaction` parsing and
//! RPC-based ALT resolution is a substantially larger undertaking (this
//! crate deliberately avoids depending on `solana-sdk` — see
//! solana_types.rs's own doc comment — so a correct wire-format parser
//! would need to be hand-rolled, and a rushed one carries real correctness
//! risk) and is tracked as a follow-up, not attempted here.
//!
//! What IS implemented: `VerificationInput.uses_versioned_transaction` /
//! `.lookup_table_count` let a caller who DOES know this (the SDK/bridge
//! constructing the input from a real transaction object) disclose it, so
//! the existing blind spot is visible rather than silent. This must NEVER
//! reduce confidence or block — ALT usage is normal for legitimate complex
//! swaps/routes (P12) — these tests prove exactly that boundary.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const SIGNER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const RECIPIENT: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

fn base_input() -> VerificationInput {
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
        wallet_profile: WalletProfile::Gaming, // most permissive profile
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

#[test]
fn default_is_false_and_no_warning_for_a_legacy_transaction() {
    let core = GraphiteCore::new();
    let input = base_input();
    let result = core.verify(&input).unwrap();
    assert!(
        !result.summary.contains("address lookup table"),
        "a legacy (non-versioned) transaction must not mention ALTs: {}",
        result.summary
    );
}

#[test]
fn versioned_transaction_flag_surfaces_a_visible_warning() {
    let core = GraphiteCore::new();
    let mut input = base_input();
    input.uses_versioned_transaction = true;
    input.lookup_table_count = 2;

    let result = core.verify(&input).unwrap();
    assert!(
        result.summary.contains("address lookup table"),
        "the ALT warning must be visible in the summary: {}",
        result.summary
    );
    assert!(
        result.summary.contains('2'),
        "the lookup table count should be surfaced: {}",
        result.summary
    );
}

#[test]
fn alt_usage_never_reduces_confidence_or_blocks_approval() {
    let core = GraphiteCore::new();
    let plain = base_input();
    let mut versioned = base_input();
    versioned.uses_versioned_transaction = true;
    versioned.lookup_table_count = 5;

    let r_plain = core.verify(&plain).unwrap();
    let r_versioned = core.verify(&versioned).unwrap();

    assert_eq!(
        r_plain.confidence, r_versioned.confidence,
        "declaring ALT usage must not change the confidence score (P12: disclosure, not penalty)"
    );
    assert_eq!(
        r_plain.approved, r_versioned.approved,
        "declaring ALT usage must not change the approval outcome"
    );
    assert_eq!(r_plain.risk_verdict.status, r_versioned.risk_verdict.status);
}

#[test]
fn lookup_table_count_zero_still_warns_when_flag_is_set() {
    // A caller might know it's a v0 transaction without tracking the exact
    // ALT count — the warning must still fire (count is purely informational).
    let core = GraphiteCore::new();
    let mut input = base_input();
    input.uses_versioned_transaction = true;
    input.lookup_table_count = 0;

    let result = core.verify(&input).unwrap();
    assert!(
        result.summary.contains("address lookup table"),
        "the warning must fire even without a known count: {}",
        result.summary
    );
}

#[test]
fn alt_disclosure_is_deterministic() {
    let core = GraphiteCore::new();
    let mut input = base_input();
    input.uses_versioned_transaction = true;
    input.lookup_table_count = 3;

    let a = core.verify(&input).unwrap();
    let b = core.verify(&input).unwrap();
    assert_eq!(a.summary, b.summary);
    assert_eq!(a.content_hash, b.content_hash);
}
