//! A transaction whose every instruction is described must be verifiable.
//!
//! L2 fails an artifact carrying an instruction the request did not describe,
//! and that is right: a verdict about one instruction says nothing about the
//! ones beside it, and they execute in the same transaction.
//!
//! The question this file asks is what happens when the caller DOES describe
//! them. `transaction_instructions` exists for exactly that, and every entry in
//! it is risk-assessed as a secondary instruction — declaring a sibling buys
//! scrutiny, not silence. If L2 fails anyway, then supplying the artifact makes
//! a transaction unverifiable no matter how honestly it is described, and
//! almost every real Solana transaction is multi-instruction: a ComputeBudget
//! limit and price sit in front of most of them.
//!
//! That would matter beyond convenience. A control that punishes the more
//! honest input pushes integrators toward the weaker one — send no artifact,
//! get a Descriptive verdict, keep the approval — and a control people route
//! around is not a control.
//!
//! The artifact is the real devnet transaction already in the fixtures: a
//! System transfer with a System assign beside it.

use graphite_core::manifest::load_seed_manifests;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationResult,
};

const SYSTEM: &str = "11111111111111111111111111111111";

fn fixture() -> serde_json::Value {
    let raw = include_str!("../fixtures/artifacts/devnet_transactions.json");
    serde_json::from_str(raw).expect("committed artifact fixtures must parse")
}

fn blob(v: &serde_json::Value) -> Vec<u8> {
    v.as_array()
        .expect("blob is a byte array")
        .iter()
        .map(|n| n.as_u64().expect("byte") as u8)
        .collect()
}

fn described_accounts() -> Vec<String> {
    fixture()["described"]["accounts"]
        .as_array()
        .expect("accounts")
        .iter()
        .map(|a| a.as_str().expect("address").to_string())
        .collect()
}

fn verify(artifact: &str, siblings: Vec<TransactionInstruction>) -> VerificationResult {
    let core = GraphiteCore::with_registry(load_seed_manifests());
    let f = fixture();
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send 0.002 SOL".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: described_accounts(),
        instruction_data: Some(blob(&f["described"]["data"])),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: Default::default(),
        compute_units: 450,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: Some(blob(&f[artifact]["blob"])),
        transaction_instructions: siblings,
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    };
    core.verify(&input).expect("verification must complete")
}

fn l2(r: &VerificationResult) -> (LayerStatus, String) {
    r.layers
        .iter()
        .find(|l| l.layer == "L2_InstructionVerification")
        .map(|l| (l.status, l.reason.clone()))
        .expect("L2 must always be reported")
}

/// The sibling in the fixture, as a caller would declare it.
///
/// System `assign` (discriminator 01000000) reassigning the fee payer's account
/// to a new owner. Reading the artifact for its own account list would defeat
/// the point of the test: a declaration is what the caller sends.
fn the_sibling() -> TransactionInstruction {
    TransactionInstruction {
        program_id: SYSTEM.to_string(),
        instruction_discriminator: "01000000".to_string(),
        account_addresses: vec![described_accounts()[0].clone()],
        cpi_targets: vec![],
    }
}

/// Undeclared, the sibling fails L2. This is the behaviour that already
/// shipped, pinned here so the change below cannot quietly relax it.
#[test]
fn an_undeclared_sibling_still_fails() {
    let r = verify("transfer_plus_sibling_assign", vec![]);
    let (status, reason) = l2(&r);
    println!("undeclared: {status:?} — {reason}");
    assert_eq!(status, LayerStatus::Failed);
    assert!(reason.contains("does not describe 1 of them"));
}

/// Declared, the same transaction must verify.
#[test]
fn a_declared_sibling_lets_the_transaction_be_verified() {
    let r = verify("transfer_plus_sibling_assign", vec![the_sibling()]);
    let (status, reason) = l2(&r);
    println!("declared: {status:?} — {reason}");
    assert_eq!(
        status,
        LayerStatus::Passed,
        "every instruction in these bytes was described, and describing them is what the caller is asked to do: {reason}"
    );
}

/// Declaring the WRONG sibling must not satisfy the check.
///
/// Otherwise "describe your siblings" degrades into "send an entry of the right
/// length", which is the padding attack in a new place.
#[test]
fn declaring_a_different_instruction_than_the_one_present_still_fails() {
    let mut wrong = the_sibling();
    // Same program, a different instruction: System `allocate`.
    wrong.instruction_discriminator = "08000000".to_string();
    let r = verify("transfer_plus_sibling_assign", vec![wrong]);
    let (status, reason) = l2(&r);
    println!("wrong sibling: {status:?} — {reason}");
    assert_eq!(status, LayerStatus::Failed, "{reason}");
}

/// Over-declaring must fail even when every real instruction IS described.
///
/// A declaration matching nothing describes a transaction other than this one.
/// It also pads the set of accounts the lookup-table disclosure treats as
/// named, which is how a padded declaration list would quietly stop a real
/// resolved account from being reported.
#[test]
fn declaring_an_instruction_the_transaction_does_not_contain_fails() {
    let absent = TransactionInstruction {
        program_id: "ComputeBudget111111111111111111111111111111".to_string(),
        instruction_discriminator: "02".to_string(),
        account_addresses: vec![],
        cpi_targets: vec![],
    };
    let r = verify("transfer_plus_sibling_assign", vec![the_sibling(), absent]);
    let (status, reason) = l2(&r);
    println!("over-declared: {status:?} — {reason}");
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(
        reason.contains("match nothing in these bytes"),
        "the report must name the direction of the disagreement: {reason}"
    );
}

/// One declaration cannot cover two identical siblings.
///
/// Otherwise a transaction carrying the same instruction twice would be
/// described once and executed twice, and the count would look right.
#[test]
fn one_declaration_does_not_cover_two_identical_siblings() {
    // The fixture has one sibling, so this is the same shape from the other
    // side: two declarations for one sibling leaves a declaration unmatched.
    let r = verify(
        "transfer_plus_sibling_assign",
        vec![the_sibling(), the_sibling()],
    );
    let (status, reason) = l2(&r);
    println!("double-declared: {status:?} — {reason}");
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(reason.contains("match nothing in these bytes"), "{reason}");
}

/// A declaration that names the program but not the instruction describes
/// nothing.
///
/// An empty discriminator would otherwise be a wildcard: "there is another
/// System instruction in here somewhere" is not a description of it.
#[test]
fn a_declaration_with_no_discriminator_describes_nothing() {
    let mut vague = the_sibling();
    vague.instruction_discriminator = String::new();
    let r = verify("transfer_plus_sibling_assign", vec![vague]);
    let (status, reason) = l2(&r);
    println!("no discriminator: {status:?} — {reason}");
    assert_eq!(status, LayerStatus::Failed, "{reason}");
}

/// Declaring a sibling that is not in the transaction at all must not help
/// either.
#[test]
fn declaring_a_sibling_the_transaction_does_not_contain_still_fails() {
    let absent = TransactionInstruction {
        program_id: "ComputeBudget111111111111111111111111111111".to_string(),
        instruction_discriminator: "02".to_string(),
        account_addresses: vec![],
        cpi_targets: vec![],
    };
    let r = verify("transfer_plus_sibling_assign", vec![absent]);
    let (status, reason) = l2(&r);
    println!("absent sibling: {status:?} — {reason}");
    assert_eq!(status, LayerStatus::Failed, "{reason}");
}

/// Control: a single-instruction artifact with no siblings declared still
/// passes, so nothing here depends on declarations being present.
#[test]
fn a_single_instruction_artifact_is_unaffected() {
    let r = verify("benign_transfer", vec![]);
    let (status, reason) = l2(&r);
    println!("single: {status:?} — {reason}");
    assert_eq!(status, LayerStatus::Passed, "{reason}");
}
