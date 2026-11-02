//! Audit W22 (A001, D-39): a grant's route is the granted instruction alone.
//!
//! `grant_keeps_value` took every instruction of the granted program as "the
//! route", and every account any of them named was excused from the
//! value-gain check. A same-program sibling (a second instruction of the
//! same pool program, naming an attacker's pool) could move the claimed or
//! withdrawn tokens into an account it named, and the gain went unchecked.
//! Only the located instruction is the route now; every other instruction,
//! whatever its program, is judged as a sibling.

use graphite_core::intent_binding::{
    grant_keeps_value, withdrawal_keeps_value, Binding, Ix, WithdrawalContext,
};
use graphite_core::state_diff::{AccountDelta, AccountSnapshot, StateDiff, TokenAccountView};

const POOL_PROGRAM: &str = "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const OWNER: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const OWNER_ATA: &str = "7UX2i7SucgLMQcfZ75s3VXmZZY4YRUyJN9X1RgfMoDUi";
const RESERVE: &str = "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1";
const ATTACKER_RESERVE: &str = "3NZ9JMVBmGAqocybic2c7LQCJScmgsAZ6vQqTDzcqmJh";

fn token_delta(pubkey: &str, owner: &str, before: u64, after: u64) -> AccountDelta {
    let snap = |amount| AccountSnapshot {
        pubkey: pubkey.to_string(),
        lamports: 2_039_280,
        owner: TOKEN.to_string(),
        token: Some(TokenAccountView {
            mint: MINT.to_string(),
            owner: owner.to_string(),
            amount,
            ..Default::default()
        }),
        ..Default::default()
    };
    AccountDelta {
        pubkey: pubkey.to_string(),
        before: Some(snap(before)),
        after: Some(snap(after)),
    }
}

fn pool_ix(reserve: &str, tag: u8) -> Ix {
    Ix {
        program_id: POOL_PROGRAM.to_string(),
        accounts: vec![
            OWNER.to_string(),
            OWNER_ATA.to_string(),
            reserve.to_string(),
        ],
        data: vec![tag; 8],
    }
}

/// The claim pays 500 into the owner's account; a second instruction of the
/// same program (a "swap" into a pool the attacker owns) takes 400 of it on.
fn skimmed() -> (Vec<Ix>, StateDiff) {
    let ixs = vec![pool_ix(RESERVE, 1), pool_ix(ATTACKER_RESERVE, 2)];
    let diff = StateDiff {
        deltas: vec![
            token_delta(RESERVE, "pool-authority", 10_000, 9_500),
            token_delta(OWNER_ATA, OWNER, 0, 100),
            token_delta(ATTACKER_RESERVE, "attacker-authority", 0, 400),
        ],
        ..Default::default()
    };
    (ixs, diff)
}

fn ctx<'a>(ixs: &'a [Ix], signers: &'a [String], located: Option<usize>) -> WithdrawalContext<'a> {
    WithdrawalContext {
        instructions: Ok(ixs),
        signers,
        program_id: POOL_PROGRAM,
        owner: Some(OWNER),
        located,
    }
}

#[test]
fn a_same_program_sibling_cannot_take_what_a_grant_paid() {
    let (ixs, diff) = skimmed();
    let signers = [OWNER.to_string()];
    let r = grant_keeps_value("claim_fee", &[], Some(&diff), &ctx(&ixs, &signers, Some(0)));
    assert!(
        matches!(&r, Err(Binding::Mismatch { reason, .. }) if reason.contains(ATTACKER_RESERVE)),
        "{r:?}"
    );
}

#[test]
fn a_same_program_sibling_cannot_take_what_a_withdrawal_paid() {
    let (ixs, diff) = skimmed();
    let signers = [OWNER.to_string()];
    let r = withdrawal_keeps_value("withdraw", &[], Some(&diff), &ctx(&ixs, &signers, Some(0)));
    assert!(
        matches!(&r, Err(Binding::Mismatch { pattern: "WithdrawalUnderbounded", reason }) if reason.contains(ATTACKER_RESERVE)),
        "{r:?}"
    );
}

#[test]
fn the_granted_instruction_alone_still_keeps_value() {
    let ixs = vec![pool_ix(RESERVE, 1)];
    let diff = StateDiff {
        deltas: vec![
            token_delta(RESERVE, "pool-authority", 10_000, 9_500),
            token_delta(OWNER_ATA, OWNER, 0, 500),
        ],
        ..Default::default()
    };
    let signers = [OWNER.to_string()];
    let r = grant_keeps_value("claim_fee", &[], Some(&diff), &ctx(&ixs, &signers, Some(0)));
    assert!(r.is_ok(), "{r:?}");
}

#[test]
fn the_route_is_the_located_instruction_not_the_first_of_its_program() {
    // Located at 1: the sibling at 0 names the attacker's reserve, and its
    // gain is not excused by the granted instruction sharing its program.
    let ixs = vec![pool_ix(ATTACKER_RESERVE, 2), pool_ix(RESERVE, 1)];
    let (_, diff) = skimmed();
    let signers = [OWNER.to_string()];
    let r = grant_keeps_value("claim_fee", &[], Some(&diff), &ctx(&ixs, &signers, Some(1)));
    assert!(matches!(r, Err(Binding::Mismatch { .. })), "{r:?}");
}

#[test]
fn an_unlocated_grant_is_unbound_not_approved() {
    let (ixs, diff) = skimmed();
    let signers = [OWNER.to_string()];
    for located in [None, Some(2), Some(usize::MAX)] {
        let r = grant_keeps_value("claim_fee", &[], Some(&diff), &ctx(&ixs, &signers, located));
        assert!(matches!(r, Err(Binding::Unbound(_))), "{located:?}: {r:?}");
    }
    // An instruction of another program at the located index is not the
    // grant's route either.
    let mut other = ixs.clone();
    other[0].program_id = TOKEN.to_string();
    let r = grant_keeps_value(
        "claim_fee",
        &[],
        Some(&diff),
        &ctx(&other, &signers, Some(0)),
    );
    assert!(matches!(r, Err(Binding::Unbound(_))), "{r:?}");
}

#[test]
fn nothing_to_locate_in_an_empty_transaction_is_not_a_reason_to_refuse() {
    // `Ok(&[])`: there are no instructions, so nothing rides beside it and no
    // route is needed (the unit tests of `bind_withdrawal` build this).
    let diff = StateDiff::default();
    let signers = [OWNER.to_string()];
    let r = grant_keeps_value("claim_fee", &[], Some(&diff), &ctx(&[], &signers, None));
    assert!(r.is_ok(), "{r:?}");
}
