//! Findings of the coverage-guided fuzzer (`fuzz/`, Round 30), each kept as a
//! deterministic test so it cannot come back between fuzz runs.
//!
//! R30-WSE-1 (`fuzz_targets/state_diff.rs`, first 90-second run): the state
//! diff excused an owner change of the FEE PAYER when the manifest declared
//! any creation ("initialize account", "create", "open"…). The excuse exists
//! for `allocate` + `assign` on a fresh account, which the diff cannot tell
//! apart from `SystemProgram::Assign`; but the fee payer is never a fresh
//! account — it held lamports and paid the fee — so a transaction under an
//! instruction that "initializes" something could hand the signer's own
//! wallet to another program with no Critical finding.

use graphite_core::account_resolution::ResolvedAccount;
use graphite_core::state_diff::{
    check_state_diff, AccountDelta, AccountSnapshot, StateDiff, StateDiffCheck, SPL_TOKEN_PROGRAM,
    SYSTEM_PROGRAM,
};

const WALLET: &str = "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T";
const FRESH: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
const ATTACKER_PROGRAM: &str = SPL_TOKEN_PROGRAM;

fn writable(address: &str, signer: bool) -> ResolvedAccount {
    serde_json::from_value(serde_json::json!({
        "address": address,
        "role": "account",
        "is_pda": false,
        "is_signer": signer,
        "is_writable": true,
        "pda_seeds": [],
    }))
    .expect("a ResolvedAccount from its required fields")
}

/// A funded, zero-data System account handed to another program.
fn assigned(pubkey: &str) -> AccountDelta {
    AccountDelta {
        pubkey: pubkey.to_string(),
        before: Some(AccountSnapshot::from_raw(
            pubkey,
            5_000_000_000,
            SYSTEM_PROGRAM,
            &[],
        )),
        after: Some(AccountSnapshot::from_raw(
            pubkey,
            4_999_995_000,
            ATTACKER_PROGRAM,
            &[],
        )),
    }
}

fn owner_reassignment_is_critical(pubkey: &str, fee_payer: &str) -> bool {
    let diff = StateDiff {
        deltas: vec![assigned(pubkey)],
        fee_lamports: 5_000,
        ..Default::default()
    };
    let accounts = [writable(pubkey, true)];
    let declared = ["initialize account".to_string()];
    let report = check_state_diff(&StateDiffCheck {
        diff: &diff,
        resolved_accounts: &accounts,
        privileges_grounded: true,
        expected_state_changes: &declared,
        fee_payer: Some(fee_payer),
    });
    let critical = report
        .criticals()
        .any(|f| f.code == "UndeclaredOwnerReassignment");
    critical
}

#[test]
fn a_creation_declaration_never_excuses_reassigning_the_fee_payer() {
    assert!(
        owner_reassignment_is_critical(WALLET, WALLET),
        "the fee payer's wallet was handed to another program under an `initialize` declaration with no Critical finding"
    );
}

/// Benign control: the allocation excuse still stands for an account that is
/// not the fee payer — `allocate` + `assign` of a pre-funded account under an
/// instruction that declares the creation.
#[test]
fn a_declared_allocation_of_another_account_is_still_excused() {
    assert!(!owner_reassignment_is_critical(FRESH, WALLET));
}
