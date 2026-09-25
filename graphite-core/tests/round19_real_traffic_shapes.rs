//! Round 19 (F-19-28): two shapes real mainnet traffic takes that L2 refused.
//!
//! Running the conformance probe over 19,458 real mainnet transactions left
//! two small classes of L2 refusals on transactions the chain had executed:
//!
//! - 71 "described instruction not located": the transaction carried TWO
//!   instructions with the same program and the same data — two same-amount
//!   transfers, to different destinations. `correspond` required exactly one
//!   program-and-data match and ignored the described accounts, which is
//!   exactly what tells the two apart. The refusal also said the instruction
//!   was absent, which was false.
//! - 41 "sibling coverage incomplete": a sibling whose data is EMPTY — the
//!   legacy associated-token-account `create` — could not be declared at all,
//!   because an empty discriminator matched nothing.
//!
//! Both fixes narrow a false refusal without widening what a description can
//! match: the located instruction still passes the full positional account
//! comparison, two fully identical instructions are still refused (now with an
//! honest reason), and an empty discriminator still describes nothing when the
//! instruction carries data (`described_siblings.rs`).

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationResult,
};

const SYSTEM: [u8; 32] = [0u8; 32];
const ATA: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

fn key(b: u8) -> [u8; 32] {
    [b; 32]
}

fn b58(k: &[u8; 32]) -> String {
    bs58::encode(k).into_string()
}

fn transfer_data(lamports: u64) -> Vec<u8> {
    let mut d = vec![2u8, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d
}

/// A legacy frame: one signer (key 0), `readonly_unsigned` trailing read-only
/// keys, one empty signature slot, instructions as (program index, account
/// indexes, data). Every count here is below 128, so compact-u16 is one byte.
fn legacy(keys: &[[u8; 32]], readonly_unsigned: u8, ixs: &[(u8, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![1u8];
    out.extend_from_slice(&[0u8; 64]);
    out.extend_from_slice(&[1, 0, readonly_unsigned]);
    out.push(keys.len() as u8);
    for k in keys {
        out.extend_from_slice(k);
    }
    out.extend_from_slice(&[5u8; 32]);
    out.push(ixs.len() as u8);
    for (program, accounts, data) in ixs {
        out.push(*program);
        out.push(accounts.len() as u8);
        out.extend_from_slice(accounts);
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    }
    out
}

fn describe(
    frame: Vec<u8>,
    program: String,
    data: Vec<u8>,
    accounts: Vec<String>,
    siblings: Vec<TransactionInstruction>,
) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send SOL".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: program,
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: hex::encode(&data[..data.len().min(4)]),
        account_addresses: accounts,
        instruction_data: Some(data),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: Some(frame),
        transaction_instructions: siblings,
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

fn l2(r: &VerificationResult) -> (LayerStatus, String) {
    let l = r
        .layers
        .iter()
        .find(|l| l.layer.starts_with("L2"))
        .expect("L2");
    (l.status, l.reason.clone())
}

fn sibling(program: String, data: &[u8], accounts: Vec<String>) -> TransactionInstruction {
    TransactionInstruction {
        program_id: program,
        instruction_discriminator: hex::encode(&data[..data.len().min(8)]),
        account_addresses: accounts,
        cpi_targets: vec![],
    }
}

/// Two transfers of the same amount to two different destinations: the
/// described accounts single out the second, and L2 locates it.
#[test]
fn same_amount_transfers_to_different_destinations_are_told_apart_by_their_accounts() {
    let (payer, a, b) = (key(1), key(2), key(3));
    let keys = [payer, a, b, SYSTEM];
    let data = transfer_data(5_000_000);
    let frame = legacy(
        &keys,
        1,
        &[(3, vec![0, 1], data.clone()), (3, vec![0, 2], data.clone())],
    );
    let r = GraphiteCore::new()
        .verify(&describe(
            frame,
            b58(&SYSTEM),
            data.clone(),
            vec![b58(&payer), b58(&b)],
            vec![sibling(b58(&SYSTEM), &data, vec![b58(&payer), b58(&a)])],
        ))
        .expect("verified");
    let (status, reason) = l2(&r);
    assert_ne!(status, LayerStatus::Failed, "{reason}");
}

/// Control: two instructions identical in program, data AND accounts are
/// indistinguishable. Still refused — and the reason says so, instead of
/// claiming the instruction is not there.
#[test]
fn two_fully_identical_instructions_are_still_refused_and_the_reason_is_honest() {
    let (payer, a) = (key(1), key(2));
    let keys = [payer, a, SYSTEM];
    let data = transfer_data(5_000_000);
    let frame = legacy(
        &keys,
        1,
        &[(2, vec![0, 1], data.clone()), (2, vec![0, 1], data.clone())],
    );
    let r = GraphiteCore::new()
        .verify(&describe(
            frame,
            b58(&SYSTEM),
            data.clone(),
            vec![b58(&payer), b58(&a)],
            vec![sibling(b58(&SYSTEM), &data, vec![b58(&payer), b58(&a)])],
        ))
        .expect("verified");
    let (status, reason) = l2(&r);
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(reason.contains("do not single out one of them"), "{reason}");
    assert!(!r.approved);
}

/// Control: accounts that match neither copy locate nothing.
#[test]
fn accounts_that_match_neither_copy_locate_nothing() {
    let (payer, a, b, stranger) = (key(1), key(2), key(3), key(9));
    let keys = [payer, a, b, SYSTEM];
    let data = transfer_data(5_000_000);
    let frame = legacy(
        &keys,
        1,
        &[(3, vec![0, 1], data.clone()), (3, vec![0, 2], data.clone())],
    );
    let r = GraphiteCore::new()
        .verify(&describe(
            frame,
            b58(&SYSTEM),
            data,
            vec![b58(&payer), b58(&stranger)],
            vec![],
        ))
        .expect("verified");
    let (status, reason) = l2(&r);
    assert_eq!(status, LayerStatus::Failed, "{reason}");
}

/// A sibling that carries no data — the legacy associated-token-account
/// `create` — is described exactly by its program, an empty discriminator and
/// its accounts.
#[test]
fn an_empty_data_sibling_is_declared_by_its_program_and_accounts() {
    let (payer, dest, owner) = (key(1), key(2), key(4));
    let ata = bs58::decode(ATA).into_vec().unwrap();
    let mut ata_key = [0u8; 32];
    ata_key.copy_from_slice(&ata);
    let keys = [payer, dest, owner, SYSTEM, ata_key];
    let data = transfer_data(1_000);
    let frame = legacy(
        &keys,
        3,
        &[(4, vec![0, 2], vec![]), (3, vec![0, 1], data.clone())],
    );
    let declared = |accounts: Vec<String>| TransactionInstruction {
        program_id: ATA.to_string(),
        instruction_discriminator: String::new(),
        account_addresses: accounts,
        cpi_targets: vec![],
    };
    let honest = GraphiteCore::new()
        .verify(&describe(
            frame.clone(),
            b58(&SYSTEM),
            data.clone(),
            vec![b58(&payer), b58(&dest)],
            vec![declared(vec![b58(&payer), b58(&owner)])],
        ))
        .expect("verified");
    let (status, reason) = l2(&honest);
    assert_ne!(status, LayerStatus::Failed, "{reason}");

    // The same empty declaration naming other accounts describes nothing.
    let wrong = GraphiteCore::new()
        .verify(&describe(
            frame,
            b58(&SYSTEM),
            data,
            vec![b58(&payer), b58(&dest)],
            vec![declared(vec![b58(&payer), b58(&dest)])],
        ))
        .expect("verified");
    let (status, reason) = l2(&wrong);
    assert_eq!(status, LayerStatus::Failed, "{reason}");
}
