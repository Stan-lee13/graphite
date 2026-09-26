//! Round 20: Token-2022 `TransferFee`, modelled.
//!
//! Until this round every transaction touching a fee-bearing Token-2022 mint
//! was refused at L4 with `Token2022ExtensionNotModelled`, because the amount
//! that arrives is not the amount that was sent and Graphite could not say
//! what it was. These tests pin the model that replaces the blanket refusal:
//!
//! - the fee arithmetic is Token-2022's own (`TransferFee::calculate_fee`,
//!   checked against the upstream test vectors);
//! - the account and mint extensions are read exactly or not at all;
//! - an honest fee-bearing transfer is modelled, its fee stated, and no
//!   longer blocked — including into an account created in the same
//!   transaction;
//! - every movement the model cannot account for exactly still blocks, with
//!   the reason: a missing schedule, a withheld amount that is not the
//!   schedule's fee, tokens arriving untaxed, value that is not conserved, a
//!   withdrawal of withheld fees, an unreadable or duplicated entry, and any
//!   other semantics-altering extension beside the fee;
//! - a fee larger than what arrives, and an undeclared change to the fee
//!   terms, are findings of their own;
//! - a scheduled fee increase is disclosed with what would then arrive;
//! - through the pipeline over a loopback mock RPC, the mint's schedule is
//!   fetched by Graphite itself (the mint is read-only in a TransferChecked
//!   and so never in the diff), and a mint that cannot be fetched leaves the
//!   fee unmodelled.

use graphite_core::account_resolution::{AccountIdentity, ResolvedAccount};
use graphite_core::state_diff::{
    check_state_diff, decode_transfer_fee_config, decode_transfer_fee_withheld, AccountDelta,
    AccountSnapshot, DiffProvenance, StateDiff, StateDiffCheck, StateDiffReport,
    TransferFeeSchedule, MAX_FEE_BASIS_POINTS,
};

const T22: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

fn b58(k: &[u8; 32]) -> String {
    bs58::encode(k).into_string()
}

const MINT: [u8; 32] = [21u8; 32];
const SRC_OWNER: [u8; 32] = [11u8; 32];
const DST_OWNER: [u8; 32] = [12u8; 32];
const SOURCE: [u8; 32] = [31u8; 32];
const DEST: [u8; 32] = [32u8; 32];
const WITHDRAW_AUTHORITY: [u8; 32] = [41u8; 32];
const CONFIG_AUTHORITY: [u8; 32] = [42u8; 32];

// ─── Byte builders: the real layouts, so the real decoders run ─────────────

fn tlv(entries: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (t, v) in entries {
        out.extend_from_slice(&t.to_le_bytes());
        out.extend_from_slice(&(v.len() as u16).to_le_bytes());
        out.extend_from_slice(v);
    }
    out
}

fn fee_amount(withheld: u64) -> (u16, Vec<u8>) {
    (2, withheld.to_le_bytes().to_vec())
}

/// A Token-2022 token account: the 165-byte base, the Account type byte, TLV.
fn t22_account(owner: [u8; 32], amount: u64, entries: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(&MINT);
    d[32..64].copy_from_slice(&owner);
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    d.push(2);
    d.extend(tlv(entries));
    d
}

#[derive(Clone, Copy)]
struct Terms {
    config_authority: Option<[u8; 32]>,
    withdraw_authority: Option<[u8; 32]>,
    withheld: u64,
    older: (u64, u64, u16),
    newer: (u64, u64, u16),
}

fn flat(bps: u16, max: u64) -> Terms {
    Terms {
        config_authority: Some(CONFIG_AUTHORITY),
        withdraw_authority: Some(WITHDRAW_AUTHORITY),
        withheld: 0,
        older: (0, max, bps),
        newer: (0, max, bps),
    }
}

fn config_bytes(t: Terms) -> Vec<u8> {
    let mut v = Vec::with_capacity(108);
    v.extend_from_slice(&t.config_authority.unwrap_or([0u8; 32]));
    v.extend_from_slice(&t.withdraw_authority.unwrap_or([0u8; 32]));
    v.extend_from_slice(&t.withheld.to_le_bytes());
    for (epoch, max, bps) in [t.older, t.newer] {
        v.extend_from_slice(&epoch.to_le_bytes());
        v.extend_from_slice(&max.to_le_bytes());
        v.extend_from_slice(&bps.to_le_bytes());
    }
    assert_eq!(v.len(), 108);
    v
}

/// A Token-2022 mint: the 82-byte base padded to 165, the Mint type byte, TLV.
fn t22_mint(supply: u64, terms: Terms) -> Vec<u8> {
    let mut d = vec![0u8; 82];
    d[36..44].copy_from_slice(&supply.to_le_bytes());
    d[44] = 6;
    d[45] = 1;
    d.resize(165, 0);
    d.push(1);
    d.extend(tlv(&[(1, config_bytes(terms))]));
    d
}

fn snap(key: &[u8; 32], data: &[u8]) -> AccountSnapshot {
    AccountSnapshot::from_raw(&b58(key), 2_039_280, T22, data)
}

fn delta(key: &[u8; 32], before: Option<Vec<u8>>, after: Option<Vec<u8>>) -> AccountDelta {
    AccountDelta {
        pubkey: b58(key),
        before: before.map(|d| snap(key, &d)),
        after: after.map(|d| snap(key, &d)),
    }
}

fn resolved(address: &[u8; 32]) -> ResolvedAccount {
    ResolvedAccount {
        address: b58(address),
        role: "account".to_string(),
        is_pda: false,
        is_signer: false,
        is_writable: true,
        pda_seeds: vec![],
        identity: AccountIdentity::Unverified,
        expected_address_mismatch: false,
        pda_mismatch: false,
        privilege_mismatch: false,
    }
}

fn diff(deltas: Vec<AccountDelta>, mint_terms: Option<Terms>) -> StateDiff {
    let mut d = StateDiff {
        deltas,
        provenance: DiffProvenance::RpcSimulated,
        ..Default::default()
    };
    if let Some(t) = mint_terms {
        let config = decode_transfer_fee_config(&t22_mint(1_000_000_000, t)).expect("config");
        d.transfer_fee_mints.insert(b58(&MINT), config);
    }
    d
}

fn transfer_checked_prose() -> Vec<String> {
    vec![
        "debits accounts.source token balance by data.amount".to_string(),
        "credits accounts.destination token balance by data.amount".to_string(),
    ]
}

fn check_with(diff: &StateDiff, declared: &[String]) -> StateDiffReport {
    let accounts: Vec<ResolvedAccount> = diff
        .deltas
        .iter()
        .map(|d| {
            let bytes: [u8; 32] = bs58::decode(&d.pubkey)
                .into_vec()
                .unwrap()
                .try_into()
                .unwrap();
            resolved(&bytes)
        })
        .collect();
    check_state_diff(&StateDiffCheck {
        diff,
        resolved_accounts: &accounts,
        privileges_grounded: true,
        expected_state_changes: declared,
        fee_payer: None,
    })
}

fn check(diff: &StateDiff) -> StateDiffReport {
    check_with(diff, &transfer_checked_prose())
}

fn codes(r: &StateDiffReport) -> Vec<String> {
    r.findings.iter().map(|f| f.code.clone()).collect()
}

fn detail(r: &StateDiffReport, code: &str) -> String {
    r.findings
        .iter()
        .filter(|f| f.code == code)
        .map(|f| f.detail.clone())
        .collect::<Vec<_>>()
        .join(" || ")
}

/// A transfer of `gross` from SOURCE to DEST, `fee` withheld at DEST.
fn transfer(gross: u64, fee: u64) -> Vec<AccountDelta> {
    vec![
        delta(
            &SOURCE,
            Some(t22_account(SRC_OWNER, 10_000_000, &[fee_amount(0)])),
            Some(t22_account(SRC_OWNER, 10_000_000 - gross, &[fee_amount(0)])),
        ),
        delta(
            &DEST,
            Some(t22_account(DST_OWNER, 0, &[fee_amount(0)])),
            Some(t22_account(DST_OWNER, gross - fee, &[fee_amount(fee)])),
        ),
    ]
}

// ─── The arithmetic is Token-2022's ─────────────────────────────────────────

fn schedule(bps: u16, max: u64) -> TransferFeeSchedule {
    TransferFeeSchedule {
        epoch: 0,
        maximum_fee: max,
        basis_points: bps,
    }
}

/// The vectors of `calculate_fee_max`, `calculate_fee_min` and
/// `calculate_fee_zero` in spl-token-2022's
/// `interface/src/extension/transfer_fee/mod.rs`.
#[test]
fn the_fee_is_token_2022s_fee() {
    let one = u64::from(MAX_FEE_BASIS_POINTS);
    let s = schedule(1, 5_000);
    assert_eq!(s.fee(u64::MAX), Some(5_000));
    assert_eq!(s.fee(5_000 * one), Some(5_000));
    assert_eq!(s.fee(5_000 * one + 1), Some(5_000));
    assert_eq!(s.fee(5_000 * one - 1), Some(5_000));
    assert_eq!(s.fee(1), Some(1), "rounded up, never down");
    assert_eq!(s.fee(2), Some(1));
    assert_eq!(s.fee(one), Some(1));
    assert_eq!(s.fee(one + 1), Some(2));
    assert_eq!(s.fee(0), Some(0));
    let zero_rate = schedule(0, u64::MAX);
    for a in [0, 1, one, u64::MAX] {
        assert_eq!(zero_rate.fee(a), Some(0));
    }
    let zero_cap = schedule(MAX_FEE_BASIS_POINTS, 0);
    for a in [0, 1, one, u64::MAX] {
        assert_eq!(zero_cap.fee(a), Some(0));
    }
    // A rate the program refuses to set is not a schedule.
    assert_eq!(schedule(MAX_FEE_BASIS_POINTS + 1, u64::MAX).fee(100), None);
    // The everyday case: 1%, capped at 5,000.
    assert_eq!(schedule(100, 5_000).fee(1_000_000), Some(5_000));
    assert_eq!(schedule(100, 50_000).fee(1_000_000), Some(10_000));
}

// ─── The extensions are read exactly or not at all ──────────────────────────

#[test]
fn the_extensions_are_read_exactly_or_not_at_all() {
    assert_eq!(
        decode_transfer_fee_withheld(&t22_account(DST_OWNER, 1, &[fee_amount(77)])),
        Some(77)
    );
    // Wrong length.
    assert_eq!(
        decode_transfer_fee_withheld(&t22_account(DST_OWNER, 1, &[(2, vec![0u8; 7])])),
        None
    );
    // Twice: which one to believe is not a question the decoder answers.
    assert_eq!(
        decode_transfer_fee_withheld(&t22_account(DST_OWNER, 1, &[fee_amount(1), fee_amount(2)])),
        None
    );
    // A classic 165-byte account carries none.
    assert_eq!(decode_transfer_fee_withheld(&[0u8; 165]), None);

    let terms = Terms {
        config_authority: None,
        withdraw_authority: Some(WITHDRAW_AUTHORITY),
        withheld: 9,
        older: (3, 700, 25),
        newer: (5, 900, 50),
    };
    let c = decode_transfer_fee_config(&t22_mint(1, terms)).expect("config");
    assert_eq!(c.config_authority, None, "an all-zero authority is none");
    assert_eq!(
        c.withdraw_withheld_authority,
        Some(b58(&WITHDRAW_AUTHORITY))
    );
    assert_eq!(c.withheld_amount, 9);
    assert_eq!(
        (c.older.epoch, c.older.maximum_fee, c.older.basis_points),
        (3, 700, 25)
    );
    assert_eq!(
        (c.newer.epoch, c.newer.maximum_fee, c.newer.basis_points),
        (5, 900, 50)
    );
    // A schedule the program could never have written.
    let impossible = Terms {
        older: (0, 1, MAX_FEE_BASIS_POINTS + 1),
        ..terms
    };
    assert_eq!(decode_transfer_fee_config(&t22_mint(1, impossible)), None);
    // The account decoder does not read a mint, nor the mint decoder an account.
    assert_eq!(decode_transfer_fee_withheld(&t22_mint(1, terms)), None);
    assert_eq!(
        decode_transfer_fee_config(&t22_account(DST_OWNER, 1, &[fee_amount(1)])),
        None
    );
}

// ─── The model accepts what Token-2022 does ────────────────────────────────

/// 1,000,000 sent under 1% capped at 5,000: 5,000 withheld, 995,000 arrive.
/// Modelled, stated, not blocked.
#[test]
fn an_honest_fee_bearing_transfer_is_modelled_and_stated() {
    let r = check(&diff(transfer(1_000_000, 5_000), Some(flat(100, 5_000))));
    let c = codes(&r);
    assert!(
        !c.contains(&"Token2022ExtensionNotModelled".to_string()),
        "{:?}",
        r.findings
    );
    assert!(!r.blocked, "{:?}", r.findings);
    let stated = detail(&r, "Token2022TransferFeeCharged");
    assert!(stated.contains("1000000 was transferred"), "{stated}");
    assert!(stated.contains("fee of 5000"), "{stated}");
    assert!(stated.contains("995000 arrived"), "{stated}");
    assert!(stated.contains(&b58(&WITHDRAW_AUTHORITY)), "{stated}");
}

/// The destination did not exist before the transaction — an associated
/// token account created in the same transaction, the everyday shape of a
/// first transfer to someone.
#[test]
fn a_transfer_into_an_account_created_in_the_same_transaction_is_modelled() {
    let mut deltas = transfer(1_000_000, 5_000);
    deltas[1].before = None;
    let r = check(&diff(deltas, Some(flat(100, 5_000))));
    assert!(!r.blocked, "{:?}", r.findings);
    assert!(codes(&r).contains(&"Token2022TransferFeeCharged".to_string()));
}

/// A zero-rate schedule is a fee extension that charges nothing: the
/// tokens arrive whole, and that is what Token-2022 does.
#[test]
fn a_zero_rate_mint_is_modelled_with_nothing_withheld() {
    let r = check(&diff(transfer(1_000_000, 0), Some(flat(0, 0))));
    assert!(!r.blocked, "{:?}", r.findings);
}

/// Exactly the harvest: withheld fees leave the account and arrive in the
/// mint's pool, nothing else moves.
#[test]
fn a_harvest_into_the_mint_is_modelled() {
    let before = Terms {
        withheld: 0,
        ..flat(100, 5_000)
    };
    let after = Terms {
        withheld: 5_000,
        ..flat(100, 5_000)
    };
    let deltas = vec![
        delta(
            &DEST,
            Some(t22_account(DST_OWNER, 995_000, &[fee_amount(5_000)])),
            Some(t22_account(DST_OWNER, 995_000, &[fee_amount(0)])),
        ),
        delta(
            &MINT,
            Some(t22_mint(1_000_000_000, before)),
            Some(t22_mint(1_000_000_000, after)),
        ),
    ];
    let r = check_with(
        &diff(deltas, None),
        &["transfers withheld fees from the source accounts to accounts.mint".to_string()],
    );
    assert!(!r.blocked, "{:?}", r.findings);
    assert!(codes(&r).contains(&"Token2022WithheldFeesHarvested".to_string()));
}

// ─── The model refuses what it cannot account for exactly ──────────────────

fn assert_unmodelled(r: &StateDiffReport, why: &str) {
    let d = detail(r, "Token2022ExtensionNotModelled");
    assert!(r.blocked, "{:?}", r.findings);
    assert!(d.contains("TransferFeeAmount"), "{d}");
    assert!(d.contains(why), "expected the reason to say {why:?}: {d}");
}

#[test]
fn without_the_mints_schedule_the_fee_is_not_modelled() {
    let r = check(&diff(transfer(1_000_000, 5_000), None));
    assert_unmodelled(&r, "was not available");
}

/// The withheld amount is not the schedule's fee on what arrived: not what
/// one Token-2022 transfer produces.
#[test]
fn a_withheld_amount_that_is_not_the_schedules_fee_is_not_modelled() {
    let r = check(&diff(transfer(1_000_000, 4_000), Some(flat(100, 5_000))));
    assert_unmodelled(&r, "is not the fee Token-2022 charges");
}

/// Tokens arrived whole under a schedule that charges on that amount.
#[test]
fn tokens_arriving_untaxed_under_a_charging_schedule_are_not_modelled() {
    let r = check(&diff(transfer(1_000_000, 0), Some(flat(100, 5_000))));
    assert_unmodelled(&r, "with no fee withheld");
}

/// Value of the mint disappears between the two accounts: 1,000,000 left,
/// 990,000 arrived and 5,000 was withheld.
#[test]
fn value_that_is_not_conserved_is_not_modelled() {
    let mut deltas = transfer(1_000_000, 5_000);
    deltas[1].after = Some(snap(
        &DEST,
        &t22_account(DST_OWNER, 990_000, &[fee_amount(5_000)]),
    ));
    let r = check(&diff(deltas, Some(flat(100, 5_000))));
    assert_unmodelled(&r, "cannot be established");
}

/// Withheld fees moved out of an account into someone's balance: a
/// withdrawal of withheld fees, which the model does not cover.
#[test]
fn a_withdrawal_of_withheld_fees_is_not_modelled() {
    let deltas = vec![
        delta(
            &DEST,
            Some(t22_account(DST_OWNER, 995_000, &[fee_amount(5_000)])),
            Some(t22_account(DST_OWNER, 995_000, &[fee_amount(0)])),
        ),
        delta(
            &SOURCE,
            Some(t22_account(SRC_OWNER, 0, &[fee_amount(0)])),
            Some(t22_account(SRC_OWNER, 5_000, &[fee_amount(0)])),
        ),
    ];
    let r = check(&diff(deltas, Some(flat(100, 5_000))));
    assert_unmodelled(&r, "withdrawal of withheld fees");
}

#[test]
fn an_unreadable_withheld_amount_is_not_modelled() {
    let mut deltas = transfer(1_000_000, 5_000);
    deltas[1].after = Some(snap(
        &DEST,
        &t22_account(DST_OWNER, 995_000, &[(2, vec![0u8; 7])]),
    ));
    let r = check(&diff(deltas, Some(flat(100, 5_000))));
    assert_unmodelled(&r, "could not be read exactly");
}

/// The fee is modelled; a TransferHook beside it is not — and still blocks,
/// named on its own.
#[test]
fn another_semantics_altering_extension_beside_the_fee_still_blocks() {
    let mut deltas = transfer(1_000_000, 5_000);
    deltas[1].after = Some(snap(
        &DEST,
        &t22_account(DST_OWNER, 995_000, &[fee_amount(5_000), (15, vec![0u8; 1])]),
    ));
    let r = check(&diff(deltas, Some(flat(100, 5_000))));
    let d = detail(&r, "Token2022ExtensionNotModelled");
    assert!(r.blocked);
    assert!(d.contains("TransferHookAccount"), "{d}");
    assert!(
        !d.contains("TransferFeeAmount"),
        "the fee WAS modelled here: {d}"
    );
}

// ─── What the model states and judges ───────────────────────────────────────

/// 60%: more is withheld than arrives. The transfer mostly pays the mint's
/// withdraw authority.
#[test]
fn a_fee_larger_than_what_arrives_blocks() {
    let r = check(&diff(
        transfer(1_000_000, 600_000),
        Some(flat(6_000, u64::MAX)),
    ));
    assert!(r.blocked);
    let d = detail(&r, "Token2022TransferFeeMajority");
    assert!(d.contains("600000") && d.contains("400000"), "{d}");
    assert!(!codes(&r).contains(&"Token2022ExtensionNotModelled".to_string()));
}

/// Exactly half is not more than half.
#[test]
fn a_fee_of_exactly_half_is_stated_not_blocked() {
    let r = check(&diff(
        transfer(1_000_000, 500_000),
        Some(flat(5_000, u64::MAX)),
    ));
    assert!(!r.blocked, "{:?}", r.findings);
}

/// The older schedule applied and a higher one starts at epoch 900: the
/// verdict says what arrives if the transaction lands then.
#[test]
fn a_scheduled_fee_increase_is_disclosed() {
    let terms = Terms {
        older: (0, u64::MAX, 100),
        newer: (900, u64::MAX, 300),
        ..flat(100, u64::MAX)
    };
    let r = check(&diff(transfer(1_000_000, 10_000), Some(terms)));
    assert!(!r.blocked, "{:?}", r.findings);
    let d = detail(&r, "Token2022TransferFeeRising");
    assert!(d.contains("epoch 900"), "{d}");
    assert!(
        d.contains("30000") && d.contains("970000 arrives instead of 990000"),
        "{d}"
    );
}

/// The newer schedule is already the one in force: nothing is pending.
#[test]
fn a_fee_under_the_newer_schedule_is_modelled_with_nothing_pending() {
    let terms = Terms {
        older: (0, u64::MAX, 100),
        newer: (900, u64::MAX, 300),
        ..flat(100, u64::MAX)
    };
    let r = check(&diff(transfer(1_000_000, 30_000), Some(terms)));
    assert!(!r.blocked, "{:?}", r.findings);
    assert!(!codes(&r).contains(&"Token2022TransferFeeRising".to_string()));
    assert!(detail(&r, "Token2022TransferFeeCharged").contains("300 bps"));
}

/// The mint's fee terms changed in this transaction and the manifest
/// declared no authority change.
#[test]
fn an_undeclared_change_to_the_fee_terms_blocks() {
    let before = flat(100, 5_000);
    let after = Terms {
        newer: (902, u64::MAX, MAX_FEE_BASIS_POINTS),
        ..before
    };
    let deltas = vec![delta(
        &MINT,
        Some(t22_mint(1_000_000_000, before)),
        Some(t22_mint(1_000_000_000, after)),
    )];
    let r = check(&diff(deltas.clone(), None));
    assert!(r.blocked);
    assert!(detail(&r, "Token2022TransferFeeConfigChanged").contains("10000 bps"));
    // Declared (SetTransferFee's own description): stated, not an undeclared change.
    let declared = check_with(
        &diff(deltas, None),
        &["changes the transfer fee authority and schedule of accounts.mint".to_string()],
    );
    assert!(!codes(&declared).contains(&"Token2022TransferFeeConfigChanged".to_string()));
}

// ─── The fee-extension instructions move value ─────────────────────────────

/// TransferCheckedWithFee and the withheld withdrawals are fund movements for
/// the impersonation and unspendable-destination checks; the other 0x1a
/// instructions are not.
#[test]
fn the_fee_extension_transfers_are_fund_movements() {
    use graphite_core::risk_engine::is_fund_movement;
    for d in ["1a01", "1a02", "1a03"] {
        assert!(is_fund_movement(T22, d), "{d}");
    }
    for d in ["1a00", "1a04", "1a05"] {
        assert!(!is_fund_movement(T22, d), "{d}");
    }
    // Classic SPL Token has no 0x1a instruction family.
    assert!(!is_fund_movement(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "1a01"
    ));
}

// ─── Through the pipeline, over a loopback mock RPC ────────────────────────

#[cfg(feature = "rpc")]
mod pipeline {
    use super::*;
    use base64::Engine;
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
    use graphite_core::semantic_graph_store::BehaviorEvidence;
    use graphite_core::verification::{
        GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationResult,
    };
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    const AUTHORITY: [u8; 32] = [51u8; 32];
    const SYSTEM: &str = "11111111111111111111111111111111";

    type Account = (u64, String, Vec<u8>);

    #[derive(Default)]
    struct Cluster {
        pre: HashMap<String, Account>,
        post: HashMap<String, Account>,
        /// Every address a `getMultipleAccounts` asked for.
        reads: Vec<String>,
        /// Answer the mint's read with null, as if it could not be fetched.
        hide_mint: bool,
    }

    fn account_json(a: Option<&Account>) -> String {
        match a {
            None => "null".to_string(),
            Some((lamports, owner, data)) => format!(
                r#"{{"lamports":{lamports},"owner":"{owner}","executable":false,"rentEpoch":0,"data":["{}","base64"]}}"#,
                base64::engine::general_purpose::STANDARD.encode(data)
            ),
        }
    }

    fn strings(v: &serde_json::Value) -> Vec<String> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn serve(state: Arc<Mutex<Cluster>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                let mut buf = vec![0u8; 1 << 16];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body: serde_json::Value = req
                    .split("\r\n\r\n")
                    .nth(1)
                    .and_then(|b| serde_json::from_str(b).ok())
                    .unwrap_or(serde_json::Value::Null);
                let mut s = state.lock().unwrap();
                let result = match body["method"].as_str().unwrap_or("") {
                    "getMultipleAccounts" => {
                        let keys = strings(&body["params"][0]);
                        s.reads.extend(keys.iter().cloned());
                        let mint = b58(&MINT);
                        let vals: Vec<String> = keys
                            .iter()
                            .map(|k| {
                                if s.hide_mint && *k == mint {
                                    "null".to_string()
                                } else {
                                    account_json(s.pre.get(k))
                                }
                            })
                            .collect();
                        format!(
                            r#"{{"context":{{"slot":10}},"value":[{}]}}"#,
                            vals.join(",")
                        )
                    }
                    "simulateTransaction" => {
                        let keys = strings(&body["params"][1]["accounts"]["addresses"]);
                        let post: Vec<String> =
                            keys.iter().map(|k| account_json(s.post.get(k))).collect();
                        format!(
                            r#"{{"context":{{"slot":11}},"value":{{"err":null,"logs":[],"unitsConsumed":6000,"fee":5000,
                            "preBalances":[1000000000,2039280,2039280,1461600,1],
                            "postBalances":[999995000,2039280,2039280,1461600,1],
                            "innerInstructions":[],"loadedAddresses":{{"writable":[],"readonly":[]}},
                            "accounts":[{}],"returnData":null}}}}"#,
                            post.join(",")
                        )
                    }
                    _ => "null".to_string(),
                };
                let out = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    out.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(out.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    fn cluster(gross: u64, fee: u64, terms: Terms) -> Cluster {
        let mut c = Cluster::default();
        let t22 = T22.to_string();
        c.pre
            .insert(b58(&AUTHORITY), (1_000_000_000, SYSTEM.to_string(), vec![]));
        c.post
            .insert(b58(&AUTHORITY), (999_995_000, SYSTEM.to_string(), vec![]));
        c.pre.insert(
            b58(&SOURCE),
            (
                2_039_280,
                t22.clone(),
                t22_account(SRC_OWNER, 10_000_000, &[fee_amount(0)]),
            ),
        );
        c.post.insert(
            b58(&SOURCE),
            (
                2_039_280,
                t22.clone(),
                t22_account(SRC_OWNER, 10_000_000 - gross, &[fee_amount(0)]),
            ),
        );
        c.pre.insert(
            b58(&DEST),
            (
                2_039_280,
                t22.clone(),
                t22_account(DST_OWNER, 0, &[fee_amount(0)]),
            ),
        );
        c.post.insert(
            b58(&DEST),
            (
                2_039_280,
                t22.clone(),
                t22_account(DST_OWNER, gross - fee, &[fee_amount(fee)]),
            ),
        );
        c.pre
            .insert(b58(&MINT), (1_461_600, t22, t22_mint(1_000_000_000, terms)));
        c
    }

    /// A legacy TransferChecked on Token-2022: keys [authority (payer), source,
    /// destination, mint, program], one empty signature slot.
    fn transfer_checked(gross: u64) -> (Vec<u8>, Vec<u8>) {
        let program: [u8; 32] = bs58::decode(T22).into_vec().unwrap().try_into().unwrap();
        let keys = [AUTHORITY, SOURCE, DEST, MINT, program];
        let mut data = vec![12u8];
        data.extend_from_slice(&gross.to_le_bytes());
        data.push(6);
        let mut out = vec![1u8];
        out.extend_from_slice(&[0u8; 64]);
        out.extend_from_slice(&[1, 0, 2]);
        out.push(keys.len() as u8);
        for k in &keys {
            out.extend_from_slice(k);
        }
        out.extend_from_slice(&[5u8; 32]);
        out.push(1);
        out.push(4);
        out.push(4);
        out.extend_from_slice(&[1, 3, 2, 0]);
        out.push(data.len() as u8);
        out.extend_from_slice(&data);
        (out, data)
    }

    async fn verify(c: Cluster, gross: u64) -> (VerificationResult, Arc<Mutex<Cluster>>) {
        let state = Arc::new(Mutex::new(c));
        let endpoint = serve(Arc::clone(&state));
        let mut core = GraphiteCore::new();
        core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
            endpoint,
            timeout: std::time::Duration::from_secs(5),
            max_retries: 0,
            ..Default::default()
        }));
        let (frame, data) = transfer_checked(gross);
        let input = VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "transfer".to_string(),
                raw_natural_language: "send tokens".to_string(),
                confidence_of_parse: 0.9,
                extracted_parameters: None,
            },
            program_id: T22.to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: "0c".to_string(),
            account_addresses: vec![b58(&SOURCE), b58(&MINT), b58(&DEST), b58(&AUTHORITY)],
            instruction_data: Some(data),
            cpi_targets: vec![],
            wallet_profile: WalletProfile::Gaming,
            behavior_evidence: BehaviorEvidence::default(),
            compute_units: 0,
            account_writes: 0,
            cpi_hops: 0,
            signed_transaction: Some(frame),
            transaction_instructions: vec![],
            cpi_trace: None,
            uses_versioned_transaction: false,
            lookup_table_count: 0,
            real_account_metas: vec![],
            state_diff: None,
        };
        let r = core.verify_async(&input).await.expect("verified");
        (r, state)
    }

    fn l4(r: &VerificationResult) -> (LayerStatus, String) {
        let l = r
            .layers
            .iter()
            .find(|l| l.layer.starts_with("L4"))
            .expect("L4");
        (l.status, l.reason.clone())
    }

    /// Graphite reads the mint itself — it is read-only in a TransferChecked,
    /// so it is not among the diffed accounts — models the fee, and L4 states
    /// it rather than refusing the transaction.
    #[tokio::test]
    async fn graphite_fetches_the_mints_schedule_and_models_the_fee() {
        let (r, state) = verify(cluster(1_000_000, 5_000, flat(100, 5_000)), 1_000_000).await;
        let (status, reason) = l4(&r);
        assert!(
            state.lock().unwrap().reads.contains(&b58(&MINT)),
            "the mint's schedule was never read"
        );
        assert_ne!(status, LayerStatus::Failed, "{reason}");
        assert!(
            !reason.contains("Token2022ExtensionNotModelled"),
            "{reason}"
        );
        assert!(reason.contains("995000 arrived"), "{reason}");
        // The authority is the fee payer, writable because it pays the fee:
        // not an identity mismatch (Round 20).
        assert!(
            !r.risk_verdict
                .findings
                .iter()
                .any(|f| f.pattern == "AccountIdentityMismatch"),
            "{:?}",
            r.risk_verdict
        );
    }

    /// The same transaction when the mint cannot be read: the fee is not
    /// modelled, and L4 refuses it as it always did — saying why.
    #[tokio::test]
    async fn a_mint_that_cannot_be_read_leaves_the_fee_unmodelled() {
        let mut c = cluster(1_000_000, 5_000, flat(100, 5_000));
        c.hide_mint = true;
        let (r, _) = verify(c, 1_000_000).await;
        let (status, reason) = l4(&r);
        assert_eq!(status, LayerStatus::Failed, "{reason}");
        assert!(reason.contains("was not available"), "{reason}");
        assert!(!r.approved);
    }

    /// An RPC reporting a withheld amount that is not the schedule's fee —
    /// a post-state Token-2022 would not produce — is refused.
    #[tokio::test]
    async fn an_rpc_reporting_a_fee_the_schedule_does_not_charge_is_refused() {
        let (r, _) = verify(cluster(1_000_000, 1, flat(100, 5_000)), 1_000_000).await;
        let (status, reason) = l4(&r);
        assert_eq!(status, LayerStatus::Failed, "{reason}");
        assert!(
            reason.contains("is not the fee Token-2022 charges"),
            "{reason}"
        );
        assert!(!r.approved);
    }
}
