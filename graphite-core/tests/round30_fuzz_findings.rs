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
        "name": "account",
        "is_pda": false,
        "is_signer": signer,
        "is_writable": true,
        "pda_seeds": [],
    }))
    .expect("a ResolvedAccount from its required fields")
}

/// A zero-data System account holding `before` lamports, handed to another
/// program (and, when it held any, paying the fee).
fn assigned(pubkey: &str, before: u64) -> AccountDelta {
    AccountDelta {
        pubkey: pubkey.to_string(),
        before: Some(AccountSnapshot::from_raw(
            pubkey,
            before,
            SYSTEM_PROGRAM,
            &[],
        )),
        after: Some(AccountSnapshot::from_raw(
            pubkey,
            before.saturating_sub(5_000),
            ATTACKER_PROGRAM,
            &[],
        )),
    }
}

fn owner_reassignment_is_critical(pubkey: &str, fee_payer: &str) -> bool {
    owner_reassignment_is_critical_under(pubkey, fee_payer, "initialize account", 5_000_000_000)
}

fn owner_reassignment_is_critical_under(
    pubkey: &str,
    fee_payer: &str,
    line: &str,
    before: u64,
) -> bool {
    let diff = StateDiff {
        deltas: vec![assigned(pubkey, before)],
        fee_lamports: 5_000,
        ..Default::default()
    };
    let accounts = [writable(pubkey, true)];
    let declared = [line.to_string()];
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
///
/// Re-pinned in Round 38 (R37-6). `FRESH` signs and held 5 SOL before the
/// transaction: it is a signer's wallet, and handing a signer's wallet to a
/// program under a creation line that names no account ("initialize
/// account") is the takeover the fee-payer rule above refuses. Since Round 38
/// a line excuses an effect on an account a signer holds only when it names
/// that account, so the excuse stands under a line that does, and for an
/// account the transaction itself funded (it held nothing before).
#[test]
fn a_declared_allocation_of_another_account_is_still_excused() {
    assert!(owner_reassignment_is_critical(FRESH, WALLET));
    assert!(!owner_reassignment_is_critical_under(
        FRESH,
        WALLET,
        "initializes accounts.account",
        5_000_000_000
    ));
    assert!(!owner_reassignment_is_critical_under(
        FRESH,
        WALLET,
        "initialize account",
        0
    ));
}
