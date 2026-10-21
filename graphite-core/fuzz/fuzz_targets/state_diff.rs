//! The state-diff checker over arbitrary account snapshots, and the
//! declared-effects prose grammar.
//!
//! Snapshots are built the way Graphite builds them from RPC bytes
//! (`AccountSnapshot::from_raw`), so every decoder runs on fuzzed data inside
//! a real check. Invariants beyond "never panics":
//!
//! - a report is `blocked` exactly when it carries a Critical finding;
//! - an account whose OWNER changed is Critical unless the declaration
//!   excuses it: reassigning ownership is how an account is handed to
//!   another program, and moves no value a balance check would see. Only a
//!   declared authority change, or a declared creation of a pre-funded
//!   zero-data System account that is not the fee payer (`allocate` +
//!   `assign`), excuses one.
#![no_main]

use arbitrary::Arbitrary;
use graphite_core::account_resolution::ResolvedAccount;
use graphite_core::state_diff::{
    check_state_diff, AccountDelta, AccountSnapshot, DeclaredEffects, StateDiff, StateDiffCheck,
    SPL_TOKEN_2022_PROGRAM, SPL_TOKEN_PROGRAM,
};
use libfuzzer_sys::fuzz_target;

const OWNERS: [&str; 4] = [
    SPL_TOKEN_PROGRAM,
    SPL_TOKEN_2022_PROGRAM,
    "11111111111111111111111111111111",
    "Attacker1111111111111111111111111111111111",
];
const KEYS: [&str; 4] = [
    "AcctA111111111111111111111111111111111111111",
    "AcctB111111111111111111111111111111111111111",
    "AcctC111111111111111111111111111111111111111",
    "AcctD111111111111111111111111111111111111111",
];
/// Phrases shipped manifests use in `expected_state_changes`, plus the
/// fuzzer's own text.
const PHRASES: [&str; 8] = [
    "debit source token account",
    "credit destination token account",
    "close account",
    "transfer lamports from source to destination",
    "set delegate",
    "mint tokens to destination",
    "burn tokens from source",
    "initialize account",
];

#[derive(Arbitrary, Debug)]
struct Side {
    lamports: u64,
    owner: u8,
    data: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct Delta {
    key: u8,
    before: Option<Side>,
    after: Option<Side>,
}

#[derive(Arbitrary, Debug)]
struct Input {
    deltas: Vec<Delta>,
    fee_lamports: u64,
    covers_all_writable: bool,
    grounded: bool,
    writable_mask: u8,
    signer_mask: u8,
    phrases: Vec<u8>,
    free_text: Vec<String>,
}

fn snapshot(key: &str, side: &Side) -> AccountSnapshot {
    let owner = OWNERS[side.owner as usize % OWNERS.len()];
    AccountSnapshot::from_raw(key, side.lamports, owner, &side.data)
}

fn resolved(index: usize, key: &str, writable: bool, signer: bool) -> ResolvedAccount {
    serde_json::from_value(serde_json::json!({
        "address": key,
        "role": format!("account{index}"),
        "is_pda": false,
        "is_signer": signer,
        "is_writable": writable,
        "pda_seeds": [],
    }))
    .expect("harness: a ResolvedAccount from its required fields")
}

fuzz_target!(|input: Input| {

    let mut deltas = Vec::new();
    for d in input.deltas.iter().take(8) {
        let key = KEYS[d.key as usize % KEYS.len()];
        deltas.push(AccountDelta {
            pubkey: key.to_string(),
            before: d.before.as_ref().map(|s| snapshot(key, s)),
            after: d.after.as_ref().map(|s| snapshot(key, s)),
        });
    }
    let diff = StateDiff {
        deltas,
        fee_lamports: input.fee_lamports,
        covers_all_writable: input.covers_all_writable,
        ..Default::default()
    };
    let accounts: Vec<ResolvedAccount> = KEYS
        .iter()
        .enumerate()
        .map(|(i, k)| {
            resolved(
                i,
                k,
                input.writable_mask & (1 << i) != 0,
                input.signer_mask & (1 << i) != 0,
            )
        })
        .collect();
    let mut declared: Vec<String> = input
        .phrases
        .iter()
        .take(6)
        .map(|p| PHRASES[*p as usize % PHRASES.len()].to_string())
        .collect();
    declared.extend(input.free_text.iter().take(4).cloned());

    // The prose grammar on its own.
    let effects = DeclaredEffects::parse(&declared);
    let _ = effects.is_silent();
    let _ = effects.is_interpretable();

    let check = |expected: &[String]| {
        check_state_diff(&StateDiffCheck {
            diff: &diff,
            resolved_accounts: &accounts,
            privileges_grounded: input.grounded,
            expected_state_changes: expected,
            fee_payer: Some(KEYS[0]),
        })
    };
    let report = check(&declared);
    assert_eq!(
        report.blocked,
        report.criticals().next().is_some(),
        "`blocked` must mean exactly: a Critical finding is present"
    );

    // Which owner changes a declaration can excuse: a declared authority
    // change excuses any, a declared creation excuses the allocation of a
    // pre-funded zero-data System account that is NOT the fee payer (the fee
    // payer existed and paid the fee, so it is never being built). Every
    // other owner change is the takeover reading, and is Critical.
    let describe = || -> Vec<String> {
        diff.deltas
            .iter()
            .map(|d| {
                let side = |s: &Option<AccountSnapshot>| {
                    s.as_ref()
                        .map(|s| format!("{}:{}:{}b", s.owner, s.lamports, s.data_len))
                        .unwrap_or_else(|| "absent".to_string())
                };
                format!("{} {} -> {}", d.pubkey, side(&d.before), side(&d.after))
            })
            .collect()
    };
    let critical_owner = |r: &graphite_core::state_diff::StateDiffReport, key: &str| {
        r.criticals()
            .any(|f| f.code == "UndeclaredOwnerReassignment" && f.account.as_deref() == Some(key))
    };
    for d in &diff.deltas {
        let Some((from, _)) = d.owner_change() else {
            continue;
        };
        // An empty declaration excuses nothing.
        assert!(
            critical_owner(&check(&[]), &d.pubkey),
            "an undeclared owner change produced no Critical finding:\n{:#?}",
            describe()
        );
        if effects.covers("authority", &[]) {
            continue;
        }
        let allocation = from == "11111111111111111111111111111111"
            && d.before.as_ref().is_some_and(|s| s.data_len == 0)
            && d.pubkey != KEYS[0];
        if allocation && effects.covers("create", &[]) {
            continue;
        }
        assert!(
            critical_owner(&report, &d.pubkey),
            "an owner change the declaration does not excuse produced no Critical finding: {declared:?}\n{:#?}",
            describe()
        );
    }
});
