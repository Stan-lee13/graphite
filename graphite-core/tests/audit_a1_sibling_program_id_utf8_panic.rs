//! A1-03 (2026-09-29 audit, filed with A3-09): a non-ASCII `program_id` on a
//! declared sibling is refused; it no longer panics the Risk Engine.
//!
//! The primary `program_id` was length-capped and base58-checked before the
//! Risk Engine ran, but a declared sibling's
//! (`transaction_instructions[i].program_id`) and a caller CPI trace node's
//! were not checked at all. They reached `risk_engine::assess` through
//! `assess_secondary_instructions`, where Check 1b formatted its reason with
//! `&input.program_id[..8.min(len)]`, a byte slice of a caller string. A
//! sibling program id of four `€` (three bytes each) put byte 8 inside a
//! character and the slice panicked, in descriptive and artifact-bound mode
//! alike. In-process callers crashed; over HTTP `CatchPanicLayer` answered a
//! bare 500 that never reached the handler's audit append, so the P9 "every
//! outcome is audited" guarantee did not hold. Nothing was approved.
//!
//! The fix is at the source, in two parts. `validate_identifiers` refuses,
//! before the pipeline runs, any identifier that is non-ASCII, contains a
//! control character or is longer than 44 characters (discriminators 128), and
//! bounds the accounts (256) and CPI targets (32) per sibling and the size of
//! the CPI trace. Every display slice goes through the char-safe
//! `risk_engine::short_id`. `audit_a3_non_ascii_program_id_panics.rs` covers
//! the trace position.
//!
//! The test pins a refusal or an unapproved verdict, never a panic; the control
//! shows an equally bogus ASCII id is judged and not approved.
#![cfg(any(feature = "rpc", feature = "cli"))]

use graphite_core::manifest::load_seed_manifests;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

fn input(sibling_program: &str) -> VerificationInput {
    let mut data = vec![2u8, 0, 0, 0];
    data.extend_from_slice(&1u64.to_le_bytes());
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send 1 lamport".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: "11111111111111111111111111111111".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![
            bs58::encode([1u8; 32]).into_string(),
            bs58::encode([2u8; 32]).into_string(),
        ],
        instruction_data: Some(data),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![TransactionInstruction {
            program_id: sibling_program.to_string(),
            instruction_discriminator: "00".to_string(),
            account_addresses: vec![bs58::encode([3u8; 32]).into_string()],
            // A token-program CPI from an untrusted root: Check 1b's arm.
            cpi_targets: vec![TOKEN.to_string()],
        }],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

/// Control: an ASCII (but equally bogus) sibling program id does not panic
/// and is not approved.
#[test]
fn control_an_ascii_sibling_program_id_is_judged() {
    let core = GraphiteCore::with_registry(load_seed_manifests());
    let r = core.verify(&input("NotAProgram")).expect("verified");
    assert!(!r.approved);
}

/// A1-03: the verification returns (a refusal or an unapproved verdict)
/// instead of panicking.
#[test]
fn a_non_ascii_sibling_program_id_is_refused_not_a_panic() {
    let core = GraphiteCore::with_registry(load_seed_manifests());
    let i = input("\u{20ac}\u{20ac}\u{20ac}\u{20ac}");
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| core.verify(&i)));
    match outcome {
        Err(_) => panic!(
            "verify panicked on a caller-supplied sibling program id (byte-sliced at a non-char boundary)"
        ),
        // Either a 400-class refusal or a blocked verdict is acceptable.
        Ok(Ok(r)) => assert!(!r.approved),
        Ok(Err(_)) => {}
    }
}
