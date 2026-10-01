//! A3-09 (2026-09-29 audit, filed with A1-03): a non-ASCII program id on a
//! declared sibling or a declared CPI trace node is refused, not a panic.
//!
//! `verify_async` bounded and base58-checked the primary program id and the
//! account addresses, but not the `program_id` of `transaction_instructions`
//! entries or `cpi_trace` nodes. Two sites sliced those strings at byte 8:
//! Check 1b in `risk_engine.rs` (a sibling whose declared `cpi_targets` name a
//! token program) and `impersonates` in `tx_pattern_analysis.rs`. A
//! three-byte UTF-8 character across byte 8 panicked. Over HTTP,
//! `CatchPanicLayer` turned it into a bare 500 with no verdict and no audit
//! row; through the library `verify()`, the caller's thread unwound.
//! Fail-closed, but a P3/P9 robustness gap.
//!
//! The fix: `validate_identifiers` refuses, before the pipeline runs, any
//! identifier that is non-ASCII, contains a control character or is over 44
//! characters, sibling and trace program ids included. Display slices go
//! through the char-safe `risk_engine::short_id`, and `impersonates` compares
//! prefixes with `str::get` rather than a byte slice.
//!
//! The tests pin that `verify` returns rather than panics for each of the two
//! positions, and that the sibling case is not approved.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::tx_pattern_analysis::{CpiTraceNode, TransactionInstruction};
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};
use std::panic::{catch_unwind, AssertUnwindSafe};

const SYSTEM: &str = "11111111111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// Seven ASCII bytes then U+20AC (3 bytes): byte 8 is inside the euro sign.
const BAD_ID: &str = "abcdefg\u{20ac}xyz";

fn transfer() -> VerificationInput {
    let mut data = vec![2u8, 0, 0, 0];
    data.extend_from_slice(&1_000u64.to_le_bytes());
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: String::new(),
            confidence_of_parse: 1.0,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: String::new(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7".to_string(),
        ],
        instruction_data: Some(data),
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
    }
}

#[test]
fn a_non_ascii_sibling_program_id_is_refused_not_a_panic() {
    let core = GraphiteCore::new();
    let mut input = transfer();
    input.transaction_instructions = vec![TransactionInstruction {
        program_id: BAD_ID.to_string(),
        instruction_discriminator: "01".to_string(),
        account_addresses: vec![],
        cpi_targets: vec![TOKEN.to_string()],
    }];
    let outcome = catch_unwind(AssertUnwindSafe(|| core.verify(&input)));
    assert!(outcome.is_ok(), "verify panicked on a sibling program id");
    if let Ok(Ok(r)) = outcome {
        assert!(!r.approved);
    }
}

#[test]
fn a_non_ascii_trace_program_id_is_refused_not_a_panic() {
    let core = GraphiteCore::new();
    let mut input = transfer();
    input.cpi_trace = Some(CpiTraceNode {
        program_id: SYSTEM.to_string(),
        instruction_discriminator: "02000000".to_string(),
        depth: 0,
        account_addresses: vec![],
        children: vec![CpiTraceNode {
            program_id: BAD_ID.to_string(),
            instruction_discriminator: String::new(),
            depth: 1,
            account_addresses: vec![],
            children: vec![],
        }],
    });
    let outcome = catch_unwind(AssertUnwindSafe(|| core.verify(&input)));
    assert!(outcome.is_ok(), "verify panicked on a CPI-trace program id");
}
