//! The described accounts must be the matched instruction's accounts, in order.
//!
//! L2 established that the transaction contains an instruction under the
//! described program carrying the described data, and that nothing else sits
//! beside it undescribed. Both are necessary. Neither says the instruction's
//! ACCOUNTS are the accounts the rest of the verdict is about — and every layer
//! downstream reasons over the described list: the risk engine's counterparty
//! checks, the state-diff comparison, the manifest's slot roles.
//!
//! Two instructions with identical program and identical data can act on
//! entirely different accounts. On Solana that is not an edge case, it is what
//! "the same transfer to a different destination" looks like at the byte level:
//! System transfer encodes the amount in the data and the parties in the
//! account list, so a description that gets the accounts wrong while getting
//! the data right describes a payment to somebody else.
//!
//! Positional, because Solana passes accounts to a program by position. The
//! same two addresses in the other order is a transfer in the other direction.
//!
//! Every artifact here is the real serialized devnet transaction already
//! committed in `fixtures/artifacts/devnet_transactions.json`. Nothing about
//! the bytes changes between these tests; only the request's account list does,
//! which is exactly the variable under test.

use graphite_core::manifest::load_seed_manifests;
use graphite_core::policy_engine::WalletProfile;
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

fn verify_with(accounts: Vec<String>) -> VerificationResult {
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
        account_addresses: accounts,
        instruction_data: Some(blob(&f["described"]["data"])),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: Default::default(),
        compute_units: 450,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: Some(blob(&f["benign_transfer"]["blob"])),
        transaction_instructions: vec![],
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

/// The control: the real account list passes.
///
/// Without this the failures below would be consistent with L2 rejecting every
/// request that supplies an artifact.
#[test]
fn the_instructions_own_accounts_pass() {
    let r = verify_with(described_accounts());
    let (status, reason) = l2(&r);
    println!("control: {status:?} — {reason}");
    assert_eq!(
        status,
        LayerStatus::Passed,
        "the accounts this instruction actually takes must verify: {reason}"
    );
}

/// The same two accounts, the other way round.
///
/// This is a transfer in the opposite direction described as a transfer in this
/// one. The set is identical, the count is identical, the program and every
/// byte of instruction data are identical. Only the positions moved, and the
/// positions are what tell the runtime who pays.
#[test]
fn reversing_the_account_order_is_a_different_instruction() {
    let mut reversed = described_accounts();
    reversed.reverse();
    let r = verify_with(reversed);
    let (status, reason) = l2(&r);
    println!("reversed: {status:?} — {reason}");
    assert_eq!(
        status,
        LayerStatus::Failed,
        "same accounts in the other order is the opposite transfer: {reason}"
    );
    assert!(
        reason.contains("account 0 of the instruction is"),
        "the report must name the position that disagrees: {reason}"
    );
    assert!(!r.approved);
}

/// An account the transaction does not contain at all.
///
/// The account-universe check compares how many accounts the artifact
/// references against how many the request names, so a request that swaps one
/// real address for one absent address keeps every count intact.
#[test]
fn substituting_an_account_the_transaction_does_not_contain_fails() {
    let mut swapped = described_accounts();
    // A valid pubkey that is not in this transaction.
    swapped[1] = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7".to_string();
    let r = verify_with(swapped);
    let (status, reason) = l2(&r);
    println!("substituted: {status:?} — {reason}");
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(!r.approved);
}

/// Describing fewer accounts than the instruction takes.
///
/// The dropped account still executes. A verdict that reasoned over the
/// remaining ones would be describing a different instruction and would say
/// nothing about the one that runs.
#[test]
fn describing_fewer_accounts_than_the_instruction_takes_fails() {
    let mut short = described_accounts();
    short.pop();
    let r = verify_with(short);
    let (status, reason) = l2(&r);
    println!("short: {status:?} — {reason}");
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(
        reason.contains("account(s) and this request describes"),
        "the report must name both lengths: {reason}"
    );
}

/// Padding the described list with an address the transaction never mentions.
///
/// This is the attack the account-universe count could not see: adding an
/// address restores a count that dropping one broke. It is caught here because
/// the instruction's own list is compared, not counted.
#[test]
fn padding_the_described_list_fails() {
    let mut padded = described_accounts();
    padded.push("9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7".to_string());
    let r = verify_with(padded);
    let (status, reason) = l2(&r);
    println!("padded: {status:?} — {reason}");
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(!r.approved);
}
