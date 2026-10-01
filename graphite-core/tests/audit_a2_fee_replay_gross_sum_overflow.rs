//! A2-10 (2026-09-29 audit): the Token-2022 fee-replay disclosure cannot
//! overflow.
//!
//! `replay_findings` in `state_diff.rs` summed each destination's transfer
//! grosses into a `u64`. Three exactly-replaying transfers between two
//! accounts (A to B, B to A, A to B), every balance inside `u64`, sum to 2^64
//! at B: a panic with overflow checks on (as under the test profile) and a
//! wrapped figure in a finding's text in release.
//!
//! The fix sums grosses in `u128` and the withheld fees with saturating
//! arithmetic. The test pins that `check_state_diff` returns a report for that
//! replay instead of panicking.

use graphite_core::account_resolution::{AccountIdentity, ResolvedAccount};
use graphite_core::state_diff::{
    check_state_diff, AccountDelta, AccountSnapshot, DiffProvenance, ExecutedTokenInstruction,
    StateDiff, StateDiffCheck, TransferFeeConfigView, TransferFeeSchedule, SPL_TOKEN_2022_PROGRAM,
};

const SIGNER: &str = "7vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const A: &str = "AAcct111111111111111111111111111111111111111";
const B: &str = "BAcct111111111111111111111111111111111111111";
const X: u64 = 1u64 << 63;

/// A Token-2022 token account carrying TransferFeeAmount (withheld 0).
fn fee_account(mint: [u8; 32], amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(&mint);
    d[32..64].copy_from_slice(&[1u8; 32]);
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    d.push(2); // AccountType::Account
    d.extend_from_slice(&2u16.to_le_bytes()); // ExtensionType::TransferFeeAmount
    d.extend_from_slice(&8u16.to_le_bytes());
    d.extend_from_slice(&0u64.to_le_bytes()); // withheld_amount
    d
}

fn transfer(from: &str, to: &str, mint: &str) -> ExecutedTokenInstruction {
    let mut data = vec![12u8]; // TransferChecked
    data.extend_from_slice(&X.to_le_bytes());
    data.push(0);
    ExecutedTokenInstruction {
        position: "instruction #0".to_string(),
        accounts: vec![
            from.to_string(),
            mint.to_string(),
            to.to_string(),
            SIGNER.to_string(),
        ],
        data,
    }
}

fn resolved(address: &str, signer: bool) -> ResolvedAccount {
    ResolvedAccount {
        address: address.to_string(),
        role: "account".to_string(),
        name: "account".to_string(),
        is_pda: false,
        is_signer: signer,
        is_writable: true,
        pda_seeds: vec![],
        identity: AccountIdentity::Unverified,
        expected_address_mismatch: false,
        pda_mismatch: false,
        privilege_mismatch: false,
    }
}

#[test]
fn a_gross_above_u64_into_one_account_does_not_panic_the_diff_check() {
    let mint_bytes = [0x55u8; 32];
    let mint = bs58::encode(mint_bytes).into_string();
    let snap = |k: &str, amount: u64| {
        AccountSnapshot::from_raw(
            k,
            2_157_600,
            SPL_TOKEN_2022_PROGRAM,
            &fee_account(mint_bytes, amount),
        )
    };
    let schedule = TransferFeeSchedule {
        epoch: 0,
        maximum_fee: 0,
        basis_points: 0,
    };
    let mut fee_mints = std::collections::BTreeMap::new();
    fee_mints.insert(
        mint.clone(),
        TransferFeeConfigView {
            config_authority: None,
            withdraw_withheld_authority: None,
            withheld_amount: 0,
            older: schedule,
            newer: schedule,
        },
    );
    let diff = StateDiff {
        deltas: vec![
            AccountDelta {
                pubkey: A.to_string(),
                before: Some(snap(A, X)),
                after: Some(snap(A, 0)),
            },
            AccountDelta {
                pubkey: B.to_string(),
                before: Some(snap(B, 0)),
                after: Some(snap(B, X)),
            },
        ],
        provenance: DiffProvenance::RpcSimulated,
        fee_lamports: 5_000,
        covers_all_writable: false,
        artifact_balance_writes: None,
        artifact_account_universe: None,
        artifact_accounts_undescribed: Some(vec![]),
        transfer_fee_mints: fee_mints,
        // A -> B, B -> A, A -> B: every balance stays inside u64, the replay
        // reproduces the post-state exactly, and B's grosses sum to 2^64.
        token2022_executed: Some(vec![
            transfer(A, B, &mint),
            transfer(B, A, &mint),
            transfer(A, B, &mint),
        ]),
        fee_epoch: None,
        token2022_mints: Default::default(),
        transaction_accounts: None,
        transaction_privileges: None,
    };
    let accts = vec![
        resolved(SIGNER, true),
        resolved(A, false),
        resolved(B, false),
    ];
    let prose = vec!["transfers tokens from accounts.source to accounts.destination".to_string()];
    // Must return a report, not panic.
    let report = check_state_diff(&StateDiffCheck {
        diff: &diff,
        resolved_accounts: &accts,
        privileges_grounded: true,
        expected_state_changes: &prose,
        fee_payer: Some(SIGNER),
    });
    let _ = report.blocked;
}
