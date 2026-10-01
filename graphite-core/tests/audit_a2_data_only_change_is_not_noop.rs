//! A2-05 (2026-09-29 audit): an account whose data changed is not a no-op.
//!
//! `AccountSnapshot` kept the data length and the decoded SPL token and mint
//! views only, so two snapshots of the same non-token account with different
//! bytes compared equal. L4 neither counted nor judged the change, and the
//! deferred-write rule excused a written "read-only" account as "observed
//! unchanged". A stake account's withdrawer changing hands left no trace.
//!
//! The fix gives `AccountSnapshot` a `data_sha256`, the `executable` flag and
//! the native authorities at their fixed offsets (the Stake staker, withdrawer
//! and lockup custodian, and the ProgramData upgrade authority). L4 raises
//! `ExecutableChanged`, `UndeclaredNativeAuthorityChange` and
//! `AccountReallocated`, and a declared-read-only account whose data hash
//! changed is no longer "observed unchanged".
//!
//! The tests pin that a stake account whose withdrawer changed is not
//! `is_noop()`, and that `check_state_diff` counts it as a changed account.

use graphite_core::account_resolution::{AccountIdentity, ResolvedAccount};
use graphite_core::state_diff::{
    check_state_diff, AccountDelta, AccountSnapshot, DiffProvenance, StateDiff, StateDiffCheck,
};

const STAKE_PROGRAM: &str = "Stake11111111111111111111111111111111111111";
const STAKE_ACCOUNT: &str = "StakeAcct1111111111111111111111111111111111";
const SIGNER: &str = "7vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";

/// A 200-byte StakeStateV2::Stake image; `withdrawer` sits at bytes 44..76
/// (Meta: rent_exempt_reserve u64 @4, staker @12, withdrawer @44).
fn stake_state(withdrawer: [u8; 32]) -> Vec<u8> {
    let mut d = vec![0u8; 200];
    d[0..4].copy_from_slice(&2u32.to_le_bytes()); // StakeStateV2::Stake
    d[4..12].copy_from_slice(&2_282_880u64.to_le_bytes());
    d[12..44].copy_from_slice(&[1u8; 32]); // staker = the user
    d[44..76].copy_from_slice(&withdrawer);
    d
}

fn withdrawer_change() -> AccountDelta {
    AccountDelta {
        pubkey: STAKE_ACCOUNT.to_string(),
        before: Some(AccountSnapshot::from_raw(
            STAKE_ACCOUNT,
            10_000_000_000,
            STAKE_PROGRAM,
            &stake_state([1u8; 32]),
        )),
        after: Some(AccountSnapshot::from_raw(
            STAKE_ACCOUNT,
            10_000_000_000,
            STAKE_PROGRAM,
            &stake_state([0xAAu8; 32]), // attacker is now the withdrawer
        )),
    }
}

#[test]
fn a_rewritten_account_is_not_a_noop() {
    assert!(
        !withdrawer_change().is_noop(),
        "the stake account's withdrawer changed hands; the delta must not read as a no-op"
    );
}

#[test]
fn l4_counts_a_data_only_change() {
    let diff = StateDiff {
        deltas: vec![withdrawer_change()],
        provenance: DiffProvenance::RpcSimulated,
        fee_lamports: 5_000,
        covers_all_writable: false,
        artifact_balance_writes: None,
        artifact_account_universe: None,
        artifact_accounts_undescribed: Some(vec![]),
        transfer_fee_mints: Default::default(),
        token2022_executed: None,
        fee_epoch: None,
        token2022_mints: Default::default(),
        transaction_accounts: None,
        transaction_privileges: None,
    };
    let accts = vec![
        ResolvedAccount {
            address: SIGNER.to_string(),
            role: "authority".to_string(),
            name: "authority".to_string(),
            is_pda: false,
            is_signer: true,
            is_writable: true,
            pda_seeds: vec![],
            identity: AccountIdentity::Unverified,
            expected_address_mismatch: false,
            pda_mismatch: false,
            privilege_mismatch: false,
        },
        ResolvedAccount {
            address: STAKE_ACCOUNT.to_string(),
            role: "stake".to_string(),
            name: "stake".to_string(),
            is_pda: false,
            is_signer: false,
            is_writable: true,
            pda_seeds: vec![],
            identity: AccountIdentity::Unverified,
            expected_address_mismatch: false,
            pda_mismatch: false,
            privilege_mismatch: false,
        },
    ];
    let prose = vec!["delegates the stake to a validator vote account".to_string()];
    let report = check_state_diff(&StateDiffCheck {
        diff: &diff,
        resolved_accounts: &accts,
        privileges_grounded: true,
        expected_state_changes: &prose,
        fee_payer: Some(SIGNER),
    });
    assert!(
        !report.empty && report.changed_accounts == 1,
        "a withdrawer change on a stake account is a change L4 must see (empty={}, changed={})",
        report.empty,
        report.changed_accounts
    );
}
