//! A3-04 (2026-09-29 audit, with A5-06): an instruction its program's manifest
//! does not describe is not scored like one it does describe.
//!
//! SECURITY.md says unknown instructions on known protocols are refused. In
//! the pipeline, `build_signals` gave ManifestMatch 1.0 because the program
//! has a manifest, and IntentAlignment 1.0 whenever L5 was not Failed. L5 is
//! Inconclusive for an undescribed instruction under any low-risk intent, so
//! alignment was granted in full; L2 passed ("P12 soft pass"); and the Risk
//! Engine saw `UNDESCRIBED_INSTRUCTION_EFFECTS`, a non-empty change list, so
//! the drainer heuristic could not fire below six accounts. A Token-2022
//! `TransferHookInstruction::Update` (`0x24 0x01`), which points every future
//! transfer of the mint at a hook program the caller chooses and which the
//! Token-2022 manifest does not describe, was approved on Gaming.
//!
//! The fix has two parts. An undescribed instruction on a manifested program
//! takes the `Unknown` trust tier, so the P6 ceiling applies and no built-in
//! profile's tier floor admits it: refused by policy with the reason (P12),
//! not blocked as a risk finding. And IntentAlignment credits only a Passed L5
//! (1.0); Failed gives 0.3 and anything else 0, so caller or AI intent text no
//! longer earns alignment for a check that did not run (A5-06).
//!
//! The control pins that the request really is an unknown instruction on a
//! known protocol. The tests pin that it scores below a described transfer and
//! is not approved, and that an Inconclusive L5 earns no alignment credit.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::simulation_integrity::ComputeBaseline;
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};
use graphite_core::Pubkey;

const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const VICTIM: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const SOURCE: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const DEST: &str = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7";
const MINT: &str = "3npQNsA9S1K9xJ9gTYn1BZu2xw2sBvZK9QG4pLkXVcBz";
const ATTACKER_HOOK: &str = "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx";

fn request(label: &str, data: Vec<u8>, accounts: &[&str]) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: String::new(),
            confidence_of_parse: 1.0,
            extracted_parameters: None,
        },
        program_id: TOKEN_2022.to_string(),
        protocol_version: String::new(),
        instruction_discriminator: label.to_string(),
        account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
        instruction_data: Some(data),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
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

fn hook_update() -> VerificationInput {
    let mut data = vec![0x24, 0x01];
    data.extend_from_slice(Pubkey::from_base58(ATTACKER_HOOK).unwrap().as_bytes());
    request("2401", data, &[MINT, VICTIM])
}

fn known_transfer() -> VerificationInput {
    let mut data = vec![0x03];
    data.extend_from_slice(&1_000u64.to_le_bytes());
    request("03", data, &[SOURCE, DEST, VICTIM])
}

fn core() -> GraphiteCore {
    let core = GraphiteCore::new();
    core.seed_simulation_baseline(
        TOKEN_2022,
        ComputeBaseline {
            mean_compute_units: 4_000.0,
            std_compute_units: 300.0,
            sample_count: 3,
            ..Default::default()
        },
    )
    .unwrap();
    core
}

#[test]
fn control_the_request_really_is_an_unknown_instruction_on_a_known_protocol() {
    let r = core().verify(&hook_update()).unwrap();
    assert!(r.manifest_found);
    assert_eq!(r.instruction_name, "unknown_instruction");
    assert!(r.summary.contains("confidence reduced"), "{}", r.summary);
}

#[test]
fn attack_an_unknown_instruction_scores_below_a_known_one() {
    let c = core();
    let unknown = c.verify(&hook_update()).unwrap();
    let known = c.verify(&known_transfer()).unwrap();
    assert!(
        unknown.confidence < known.confidence,
        "the warning says 'confidence reduced' but an undescribed instruction scored {:.4} and a \
         described Transfer {:.4}; breakdown {:?}",
        unknown.confidence,
        known.confidence,
        unknown
            .breakdown
            .iter()
            .map(|b| (b.kind.clone(), b.raw_value))
            .collect::<Vec<_>>()
    );
}

#[test]
fn attack_an_unknown_instruction_on_a_known_protocol_is_not_approved() {
    let r = core().verify(&hook_update()).unwrap();
    assert!(
        !r.approved,
        "SECURITY.md: unknown instructions on known protocols return BLOCKED (confidence 0.0); got \
         approved={} confidence={:.4} risk={:?}",
        r.approved,
        r.confidence,
        r.risk_verdict
    );
}

#[test]
fn a_semantic_check_that_did_not_run_earns_no_alignment_credit() {
    // A5-06: L5 is Inconclusive for an undescribed instruction — it compared
    // nothing — so the IntentAlignment signal must be 0, not the full 1.0 a
    // passed comparison earns.
    let r = core().verify(&hook_update()).unwrap();
    let l5 = r
        .layers
        .iter()
        .find(|l| l.layer == "L5_SemanticVerification")
        .unwrap();
    assert_eq!(
        l5.status,
        graphite_core::verification::LayerStatus::Inconclusive,
        "precondition"
    );
    let alignment = r
        .breakdown
        .iter()
        .find(|b| b.kind == "IntentAlignment")
        .map(|b| b.raw_value)
        .expect("IntentAlignment in the breakdown");
    assert_eq!(
        alignment, 0.0,
        "an uncompared intent was credited {alignment}"
    );
}
