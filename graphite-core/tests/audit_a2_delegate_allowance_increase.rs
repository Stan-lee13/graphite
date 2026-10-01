//! A2-02 (2026-09-29 audit): raising the allowance of a delegate that already
//! held one is a new standing permission.
//!
//! L4 compared only the delegate key, so an existing delegate whose allowance
//! went from a small amount to `u64::MAX` produced no finding at all.
//!
//! The fix makes a delegation the pair (delegate, `delegated_amount`).
//! `AccountDelta::delegate_granted` reports a new delegate or the same
//! delegate allowed to move more, and L4 raises `UndeclaredDelegateGrant`
//! unless the declaration names it. A lowered allowance takes power away and
//! is not a grant.
//!
//! The test pins that the raised allowance blocks with a delegate finding;
//! the control pins that spending an allowance down stays clean.

use graphite_core::account_resolution::{AccountIdentity, ResolvedAccount};
use graphite_core::state_diff::{
    check_state_diff, AccountDelta, AccountSnapshot, DiffProvenance, StateDiff, StateDiffCheck,
    SPL_TOKEN_PROGRAM,
};

const SOURCE: &str = "So1rceTokens1111111111111111111111111111111";
const SIGNER: &str = "7vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";

fn account(address: &str, signer: bool, writable: bool) -> ResolvedAccount {
    ResolvedAccount {
        address: address.to_string(),
        role: "account".to_string(),
        name: "account".to_string(),
        is_pda: false,
        is_signer: signer,
        is_writable: writable,
        pda_seeds: vec![],
        identity: AccountIdentity::Unverified,
        expected_address_mismatch: false,
        pda_mismatch: false,
        privilege_mismatch: false,
    }
}

fn token_account(delegate: [u8; 32], delegated_amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(&[7u8; 32]); // mint
    d[32..64].copy_from_slice(&[1u8; 32]); // owner
    d[64..72].copy_from_slice(&1_000u64.to_le_bytes());
    d[72..76].copy_from_slice(&1u32.to_le_bytes()); // COption::Some
    d[76..108].copy_from_slice(&delegate);
    d[108] = 1; // initialized
    d[121..129].copy_from_slice(&delegated_amount.to_le_bytes());
    d
}

fn diff(before_allowance: u64, after_allowance: u64) -> StateDiff {
    let snap = |allowance| {
        AccountSnapshot::from_raw(
            SOURCE,
            2_039_280,
            SPL_TOKEN_PROGRAM,
            &token_account([0xDDu8; 32], allowance),
        )
    };
    StateDiff {
        deltas: vec![AccountDelta {
            pubkey: SOURCE.to_string(),
            before: Some(snap(before_allowance)),
            after: Some(snap(after_allowance)),
        }],
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
    }
}

fn check(d: &StateDiff) -> (bool, Vec<String>) {
    let accts = vec![account(SIGNER, true, true), account(SOURCE, false, true)];
    let prose = vec!["transfers funds between the protocol and the involved accounts".to_string()];
    let report = check_state_diff(&StateDiffCheck {
        diff: d,
        resolved_accounts: &accts,
        privileges_grounded: true,
        expected_state_changes: &prose,
        fee_payer: Some(SIGNER),
    });
    (
        report.blocked,
        report.criticals().map(|f| f.code.clone()).collect(),
    )
}

#[test]
fn raising_an_existing_delegates_allowance_is_an_undeclared_delegate_grant() {
    let (blocked, criticals) = check(&diff(1, u64::MAX));
    assert!(
        blocked && criticals.iter().any(|c| c.contains("Delegate")),
        "allowance to the same delegate went 1 -> u64::MAX under a manifest that declares no \
         delegation; L4 reported nothing. criticals: {criticals:?}"
    );
}

#[test]
fn a_shrinking_allowance_is_not_a_grant_control() {
    // Spending down an allowance (what an honest delegated transfer does) must stay clean.
    let (blocked, criticals) = check(&diff(1_000, 900));
    assert!(!blocked, "{criticals:?}");
}
