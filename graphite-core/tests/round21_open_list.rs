//! Round 21: the open list, closed where it could be.
//!
//! Round 20 left the Token-2022 transfer-fee model with four refusals it
//! named rather than resolved — a withdrawal of withheld fees, several
//! fee-bearing transfers into one account, an account that both sent and
//! received, and a pending schedule it disclosed without judging — and the
//! pipeline with two weaknesses of its own word: L4's structural fallback
//! said `Passed` without having observed any state, and the synchronous
//! `verify` built a multi-thread runtime on every call.
//!
//! These tests pin what replaced them:
//!
//! - the fee model replays the Token-2022 instructions the simulator
//!   executed and requires the replay to end exactly at the observed state,
//!   which models withdrawals, several transfers into one account and
//!   accounts that send and receive — and blocks, with the reason, whatever
//!   the replay does not reproduce or does not know;
//! - with the epoch read, only that epoch's schedule is accepted, and a
//!   pending schedule is judged against the transaction's lifetime;
//! - through the pipeline over a loopback mock RPC, Graphite builds the
//!   executed list from the transaction and `innerInstructions`, and reads
//!   the epoch itself;
//! - L4 without a diff is Inconclusive, not Passed;
//! - the synchronous `verify` refuses inside a runtime instead of panicking
//!   and serves concurrent callers from one runtime.

use graphite_core::account_resolution::{AccountIdentity, ResolvedAccount};
use graphite_core::state_diff::{
    check_state_diff, decode_transfer_fee_config, AccountDelta, AccountSnapshot, DiffProvenance,
    ExecutedTokenInstruction, FeeEpochContext, StateDiff, StateDiffCheck, StateDiffReport,
};

const T22: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

fn b58(k: &[u8; 32]) -> String {
    bs58::encode(k).into_string()
}

const MINT: [u8; 32] = [21u8; 32];
const SRC_OWNER: [u8; 32] = [11u8; 32];
const DST_OWNER: [u8; 32] = [12u8; 32];
const THIRD_OWNER: [u8; 32] = [13u8; 32];
const SOURCE: [u8; 32] = [31u8; 32];
const DEST: [u8; 32] = [32u8; 32];
const THIRD: [u8; 32] = [33u8; 32];
const UNSEEN: [u8; 32] = [34u8; 32];
const WITHDRAW_AUTHORITY: [u8; 32] = [41u8; 32];
const CONFIG_AUTHORITY: [u8; 32] = [42u8; 32];
const OWNER_SIGNER: [u8; 32] = [51u8; 32];

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

fn t22_account(owner: [u8; 32], amount: u64, withheld: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(&MINT);
    d[32..64].copy_from_slice(&owner);
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    d.push(2);
    d.extend(tlv(&[fee_amount(withheld)]));
    d
}

#[derive(Clone, Copy)]
struct Terms {
    withheld: u64,
    /// (epoch, maximum fee, basis points)
    older: (u64, u64, u16),
    newer: (u64, u64, u16),
}

fn flat(bps: u16, max: u64) -> Terms {
    Terms {
        withheld: 0,
        older: (0, max, bps),
        newer: (0, max, bps),
    }
}

fn config_bytes(t: Terms) -> Vec<u8> {
    let mut v = Vec::with_capacity(108);
    v.extend_from_slice(&CONFIG_AUTHORITY);
    v.extend_from_slice(&WITHDRAW_AUTHORITY);
    v.extend_from_slice(&t.withheld.to_le_bytes());
    for (epoch, max, bps) in [t.older, t.newer] {
        v.extend_from_slice(&epoch.to_le_bytes());
        v.extend_from_slice(&max.to_le_bytes());
        v.extend_from_slice(&bps.to_le_bytes());
    }
    v
}

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

fn account(key: &[u8; 32], owner: [u8; 32], before: (u64, u64), after: (u64, u64)) -> AccountDelta {
    AccountDelta {
        pubkey: b58(key),
        before: Some(snap(key, &t22_account(owner, before.0, before.1))),
        after: Some(snap(key, &t22_account(owner, after.0, after.1))),
    }
}

fn mint_delta(before: Terms, after: Terms) -> AccountDelta {
    AccountDelta {
        pubkey: b58(&MINT),
        before: Some(snap(&MINT, &t22_mint(1_000_000_000, before))),
        after: Some(snap(&MINT, &t22_mint(1_000_000_000, after))),
    }
}

fn resolved(address: &str) -> ResolvedAccount {
    ResolvedAccount {
        address: address.to_string(),
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

/// A Graphite-built diff: the fetched schedule (unless the mint is in the
/// diff), the executed instructions and the epoch, as the pipeline sets them.
fn diff(
    deltas: Vec<AccountDelta>,
    fetched: Option<Terms>,
    executed: Option<Vec<ExecutedTokenInstruction>>,
    epoch: Option<FeeEpochContext>,
) -> StateDiff {
    let mut d = StateDiff {
        deltas,
        provenance: DiffProvenance::RpcSimulated,
        ..Default::default()
    };
    if let Some(t) = fetched {
        d.transfer_fee_mints.insert(
            b58(&MINT),
            decode_transfer_fee_config(&t22_mint(1_000_000_000, t)).expect("config"),
        );
    }
    d.token2022_executed = executed;
    d.fee_epoch = epoch;
    d
}

fn check_with(diff: &StateDiff, declared: &[String]) -> StateDiffReport {
    let accounts: Vec<ResolvedAccount> = diff.deltas.iter().map(|d| resolved(&d.pubkey)).collect();
    check_state_diff(&StateDiffCheck {
        diff,
        resolved_accounts: &accounts,
        privileges_grounded: true,
        expected_state_changes: declared,
        fee_payer: None,
    })
}

fn check(diff: &StateDiff) -> StateDiffReport {
    check_with(
        diff,
        &[
            "debits accounts.source token balance by data.amount".to_string(),
            "credits accounts.destination token balance by data.amount".to_string(),
        ],
    )
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

fn assert_modelled(r: &StateDiffReport) {
    assert!(
        !codes(r).contains(&"Token2022ExtensionNotModelled".to_string()),
        "{:?}",
        r.findings
    );
    assert!(!r.blocked, "{:?}", r.findings);
}

fn assert_unmodelled(r: &StateDiffReport, why: &str) {
    let d = detail(r, "Token2022ExtensionNotModelled");
    assert!(r.blocked, "{:?}", r.findings);
    assert!(d.contains(why), "expected the reason to say {why:?}: {d}");
}

// ─── Executed-instruction builders ──────────────────────────────────────────

fn ix(position: &str, accounts: &[[u8; 32]], data: Vec<u8>) -> ExecutedTokenInstruction {
    ExecutedTokenInstruction {
        position: position.to_string(),
        accounts: accounts.iter().map(b58).collect(),
        data,
    }
}

fn transfer_checked(
    at: &str,
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
) -> ExecutedTokenInstruction {
    let mut data = vec![12u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(6);
    ix(at, &[from, MINT, to, OWNER_SIGNER], data)
}

fn transfer_checked_with_fee(
    at: &str,
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
    fee: u64,
) -> ExecutedTokenInstruction {
    let mut data = vec![26u8, 1];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(6);
    data.extend_from_slice(&fee.to_le_bytes());
    ix(at, &[from, MINT, to, OWNER_SIGNER], data)
}

// ─── Several transfers, and accounts that send and receive ─────────────────

/// 400,000 and 600,000 into one account at 1% capped at 5,000: fees of 4,000
/// and 5,000. Round 20 saw 1,000,000 gross with 9,000 withheld — not the fee
/// on ONE transfer of 1,000,000 — and refused. With what ran, it is exact.
#[test]
fn several_transfers_into_one_account_are_replayed_and_stated() {
    let deltas = || {
        vec![
            account(&SOURCE, SRC_OWNER, (10_000_000, 0), (9_000_000, 0)),
            account(&DEST, DST_OWNER, (0, 0), (991_000, 9_000)),
        ]
    };
    let executed = vec![
        transfer_checked("instruction #0", SOURCE, DEST, 400_000),
        transfer_checked("instruction #1", SOURCE, DEST, 600_000),
    ];
    let r = check(&diff(
        deltas(),
        Some(flat(100, 5_000)),
        Some(executed),
        None,
    ));
    assert_modelled(&r);
    let d = detail(&r, "Token2022TransferFeeCharged");
    assert!(d.contains("2 transfers totalling 1000000"), "{d}");
    assert!(
        d.contains("fee of 9000") && d.contains("991000 arrived"),
        "{d}"
    );

    // Without the executed list the Round 20 rule stands, and says why.
    let r = check(&diff(deltas(), Some(flat(100, 5_000)), None, None));
    assert_unmodelled(&r, "executed instructions were not available");
}

/// SOURCE → DEST 1,000,000, then DEST → THIRD 300,000, in one transaction.
/// DEST both received and sent; Round 20 could not separate the two.
#[test]
fn an_account_that_sends_and_receives_is_replayed() {
    let deltas = vec![
        account(&SOURCE, SRC_OWNER, (10_000_000, 0), (9_000_000, 0)),
        account(&DEST, DST_OWNER, (0, 0), (695_000, 5_000)),
        account(&THIRD, THIRD_OWNER, (0, 0), (297_000, 3_000)),
    ];
    let executed = vec![
        transfer_checked("instruction #0", SOURCE, DEST, 1_000_000),
        transfer_checked("instruction #1", DEST, THIRD, 300_000),
    ];
    let r = check(&diff(
        deltas.clone(),
        Some(flat(100, 5_000)),
        Some(executed),
        None,
    ));
    assert_modelled(&r);
    let d = detail(&r, "Token2022TransferFeeCharged");
    assert!(
        d.contains("995000 arrived") && d.contains("297000 arrived"),
        "{d}"
    );

    // Without the executed list the fee cap makes DEST's change (695,000
    // arriving, 5,000 withheld) look like one 700,000 transfer. Round 20
    // stated it as one; it now says it is arithmetic, not attribution.
    let r = check(&diff(deltas, Some(flat(100, 5_000)), None, None));
    let d = detail(&r, "Token2022TransferFeeCharged");
    assert!(d.contains("not a per-transfer attribution"), "{d}");
    assert!(!d.contains("was transferred into"), "{d}");
}

/// The order matters and is the executed order: the same two transfers the
/// other way round would have DEST send before it has anything.
#[test]
fn the_replay_follows_execution_order() {
    let deltas = vec![
        account(&SOURCE, SRC_OWNER, (10_000_000, 0), (9_000_000, 0)),
        account(&DEST, DST_OWNER, (0, 0), (695_000, 5_000)),
        account(&THIRD, THIRD_OWNER, (0, 0), (297_000, 3_000)),
    ];
    let executed = vec![
        transfer_checked("instruction #0", DEST, THIRD, 300_000),
        transfer_checked("instruction #1", SOURCE, DEST, 1_000_000),
    ];
    let r = check(&diff(deltas, Some(flat(100, 5_000)), Some(executed), None));
    assert_unmodelled(&r, "outside what a u64 balance holds");
}

// ─── Withdrawals of withheld fees ───────────────────────────────────────────

/// `WithdrawWithheldTokensFromMint`: the mint's whole pool, 7,000, into DEST.
#[test]
fn a_withdrawal_from_the_mint_is_replayed_and_disclosed() {
    let before = Terms {
        withheld: 7_000,
        ..flat(100, 5_000)
    };
    let deltas = vec![
        account(&DEST, DST_OWNER, (1_000, 0), (8_000, 0)),
        mint_delta(before, flat(100, 5_000)),
    ];
    let executed = vec![ix(
        "instruction #0",
        &[MINT, DEST, WITHDRAW_AUTHORITY],
        vec![26, 2],
    )];
    let declared =
        ["withdraws withheld fees from accounts.mint to accounts.destination".to_string()];
    let r = check_with(&diff(deltas.clone(), None, Some(executed), None), &declared);
    assert_modelled(&r);
    let d = detail(&r, "Token2022WithheldFeesWithdrawn");
    assert!(
        d.contains("withdrew 7000 from the mint's withheld pool"),
        "{d}"
    );
    assert!(d.contains(&b58(&WITHDRAW_AUTHORITY)), "{d}");

    // Without the executed list it is the Round 20 refusal.
    let r = check_with(&diff(deltas, None, None, None), &declared);
    assert_unmodelled(&r, "withdrawals of withheld fees are not modelled");
}

/// `WithdrawWithheldTokensFromAccounts` from SOURCE and THIRD into DEST. The
/// mint is read-only here, so its schedule is the fetched one.
#[test]
fn a_withdrawal_from_accounts_is_replayed_and_disclosed() {
    let deltas = vec![
        account(&SOURCE, SRC_OWNER, (500, 3_000), (500, 0)),
        account(&THIRD, THIRD_OWNER, (0, 2_000), (0, 0)),
        account(&DEST, DST_OWNER, (0, 0), (5_000, 0)),
    ];
    let executed = vec![ix(
        "a CPI under instruction #1",
        &[MINT, DEST, WITHDRAW_AUTHORITY, SOURCE, THIRD],
        vec![26, 3, 2],
    )];
    let declared =
        ["withdraws withheld fees from the source accounts to accounts.destination".to_string()];
    let r = check_with(
        &diff(deltas.clone(), Some(flat(100, 5_000)), Some(executed), None),
        &declared,
    );
    assert_modelled(&r);
    let d = detail(&r, "Token2022WithheldFeesWithdrawn");
    assert!(
        d.contains("a CPI under instruction #1 withdrew 5000"),
        "{d}"
    );

    let r = check_with(&diff(deltas, Some(flat(100, 5_000)), None, None), &declared);
    assert_unmodelled(&r, "withdrawal of withheld fees");
}

/// The withheld fees moved, but what ran was a transfer: the replay cannot
/// end where the simulator did.
#[test]
fn a_withdrawal_the_executed_instructions_do_not_explain_blocks() {
    let deltas = vec![
        account(&SOURCE, SRC_OWNER, (500, 3_000), (500, 0)),
        account(&DEST, DST_OWNER, (0, 0), (3_000, 0)),
    ];
    let executed = vec![transfer_checked("instruction #0", SOURCE, DEST, 0)];
    let r = check(&diff(deltas, Some(flat(100, 5_000)), Some(executed), None));
    assert_unmodelled(&r, "does not reproduce the observed state");
}

/// A withdrawal that names one of its own sources as the destination.
#[test]
fn a_withdrawal_into_its_own_source_is_not_modelled() {
    let deltas = vec![account(&SOURCE, SRC_OWNER, (0, 3_000), (3_000, 0))];
    let executed = vec![ix(
        "instruction #0",
        &[MINT, SOURCE, WITHDRAW_AUTHORITY, SOURCE],
        vec![26, 3, 1],
    )];
    let r = check(&diff(deltas, Some(flat(100, 5_000)), Some(executed), None));
    assert_unmodelled(&r, "into one of the accounts it drains");
}

// ─── What the replay refuses ────────────────────────────────────────────────

/// The instructions say 1,000,000 was sent; the simulator says DEST ended
/// with more than that.
#[test]
fn a_diff_the_replay_does_not_reproduce_blocks() {
    let deltas = vec![
        account(&SOURCE, SRC_OWNER, (10_000_000, 0), (8_995_000, 0)),
        account(&DEST, DST_OWNER, (0, 0), (1_000_000, 5_000)),
    ];
    let executed = vec![transfer_checked("instruction #0", SOURCE, DEST, 1_000_000)];
    let r = check(&diff(deltas, Some(flat(100, 5_000)), Some(executed), None));
    assert_unmodelled(&r, "the replay ends");
}

/// A Token-2022 instruction the replay does not know — a confidential
/// transfer (27) — on an account of the mint.
#[test]
fn an_instruction_the_replay_does_not_know_blocks() {
    let deltas = vec![
        account(&SOURCE, SRC_OWNER, (10_000_000, 0), (9_000_000, 0)),
        account(&DEST, DST_OWNER, (0, 0), (995_000, 5_000)),
    ];
    let executed = vec![
        transfer_checked("instruction #0", SOURCE, DEST, 1_000_000),
        ix("instruction #1", &[DEST, MINT], vec![27, 7]),
    ];
    let r = check(&diff(deltas, Some(flat(100, 5_000)), Some(executed), None));
    assert_unmodelled(&r, "instruction 27");
}

/// A transfer into an account the diff never observed: where the fee went
/// cannot be followed.
#[test]
fn a_transfer_through_an_unobserved_account_blocks() {
    let deltas = vec![
        account(&SOURCE, SRC_OWNER, (10_000_000, 0), (9_000_000, 0)),
        account(&DEST, DST_OWNER, (0, 0), (995_000, 5_000)),
    ];
    let executed = vec![
        transfer_checked("instruction #0", SOURCE, DEST, 1_000_000),
        transfer_checked("instruction #1", DEST, UNSEEN, 0),
    ];
    let r = check(&diff(deltas, Some(flat(100, 5_000)), Some(executed), None));
    assert_unmodelled(&r, "which the diff did not observe");
}

/// `TransferCheckedWithFee` states the fee; one that states the wrong one is
/// not a transfer Token-2022 executes.
#[test]
fn a_stated_fee_that_is_not_the_schedules_blocks() {
    let deltas = || {
        vec![
            account(&SOURCE, SRC_OWNER, (10_000_000, 0), (9_000_000, 0)),
            account(&DEST, DST_OWNER, (0, 0), (995_000, 5_000)),
        ]
    };
    let honest = vec![transfer_checked_with_fee(
        "instruction #0",
        SOURCE,
        DEST,
        1_000_000,
        5_000,
    )];
    assert_modelled(&check(&diff(
        deltas(),
        Some(flat(100, 5_000)),
        Some(honest),
        None,
    )));
    let lying = vec![transfer_checked_with_fee(
        "instruction #0",
        SOURCE,
        DEST,
        1_000_000,
        4_999,
    )];
    let r = check(&diff(deltas(), Some(flat(100, 5_000)), Some(lying), None));
    assert_unmodelled(&r, "states a fee of 4999");
}

/// Several transfers can still be mostly fee: each transfer is judged.
#[test]
fn a_majority_fee_on_one_of_several_transfers_blocks() {
    let terms = flat(6_000, u64::MAX);
    let deltas = vec![
        account(&SOURCE, SRC_OWNER, (10_000_000, 0), (9_989_000, 0)),
        account(&DEST, DST_OWNER, (0, 0), (4_400, 6_600)),
    ];
    let executed = vec![
        transfer_checked("instruction #0", SOURCE, DEST, 10_000),
        transfer_checked("instruction #1", SOURCE, DEST, 1_000),
    ];
    let r = check(&diff(deltas, Some(terms), Some(executed), None));
    assert!(r.blocked);
    assert!(codes(&r).contains(&"Token2022TransferFeeMajority".to_string()));
    assert!(
        !codes(&r).contains(&"Token2022ExtensionNotModelled".to_string()),
        "{:?}",
        r.findings
    );
}

// ─── The epoch ──────────────────────────────────────────────────────────────

fn rising() -> Terms {
    Terms {
        withheld: 0,
        older: (0, u64::MAX, 50),
        newer: (10, u64::MAX, 100),
    }
}

/// `nonce`: whether the transaction advances a durable nonce.
fn epoch(simulated: u64, nonce: bool) -> Option<FeeEpochContext> {
    Some(FeeEpochContext {
        simulated_epoch: simulated,
        durable_nonce: nonce,
    })
}

fn one_transfer(fee: u64) -> Vec<AccountDelta> {
    vec![
        account(&SOURCE, SRC_OWNER, (10_000_000, 0), (9_000_000, 0)),
        account(&DEST, DST_OWNER, (0, 0), (1_000_000 - fee, fee)),
    ]
}

/// In epoch 5 the older schedule (50 bps: 5,000) applies. A withheld amount
/// matching the newer one (100 bps: 10,000) was accepted while the epoch was
/// unknown; with the epoch read it is not what Token-2022 charged.
#[test]
fn with_the_epoch_read_only_that_epochs_schedule_is_accepted() {
    let executed = || {
        Some(vec![transfer_checked(
            "instruction #0",
            SOURCE,
            DEST,
            1_000_000,
        )])
    };
    assert_modelled(&check(&diff(
        one_transfer(10_000),
        Some(rising()),
        None,
        None,
    )));
    let r = check(&diff(
        one_transfer(10_000),
        Some(rising()),
        None,
        epoch(5, false),
    ));
    assert_unmodelled(&r, "is not the fee Token-2022 charges");
    let r = check(&diff(
        one_transfer(10_000),
        Some(rising()),
        executed(),
        epoch(5, false),
    ));
    assert_unmodelled(&r, "does not reproduce the observed state");
    assert_modelled(&check(&diff(
        one_transfer(5_000),
        Some(rising()),
        executed(),
        epoch(5, false),
    )));
    // From epoch 10 the newer schedule is the one.
    assert_modelled(&check(&diff(
        one_transfer(10_000),
        Some(rising()),
        executed(),
        epoch(10, false),
    )));
}

/// A pending increase is disclosed whenever the transaction can pay it — and
/// since Round 22 that is always: the landing epoch is not observable and no
/// number of slots bounds a blockhash's 150 blocks. The reason names why.
#[test]
fn a_pending_increase_is_disclosed_with_why_it_can_be_paid() {
    let executed = || {
        Some(vec![transfer_checked(
            "instruction #0",
            SOURCE,
            DEST,
            1_000_000,
        )])
    };
    // Epoch unknown: disclosed, as in Round 20.
    let r = check(&diff(one_transfer(5_000), Some(rising()), executed(), None));
    assert!(detail(&r, "Token2022TransferFeeRising").contains("was not read"));
    // Simulated in epoch 5, the increase is at 10. Round 21 stayed silent on
    // an assumed landing margin; nothing observed bounds it.
    for simulated in [5, 9] {
        let r = check(&diff(
            one_transfer(5_000),
            Some(rising()),
            executed(),
            epoch(simulated, false),
        ));
        assert_modelled(&r);
        let d = detail(&r, "Token2022TransferFeeRising");
        assert!(d.contains("nothing bounds the epoch it lands in"), "{d}");
        assert!(
            d.contains(&format!("simulated in epoch {simulated}")),
            "{d}"
        );
        assert!(d.contains("990000 arrives instead of 995000"), "{d}");
    }
    // A durable nonce does not expire.
    let r = check(&diff(
        one_transfer(5_000),
        Some(rising()),
        executed(),
        epoch(5, true),
    ));
    assert!(detail(&r, "Token2022TransferFeeRising").contains("durable nonce"));
}

/// A pending schedule that would take more than half of a transfer blocks,
/// for a blockhash transaction as for a durable nonce (Round 22).
#[test]
fn a_pending_majority_fee_blocks() {
    let terms = Terms {
        withheld: 0,
        older: (0, u64::MAX, 50),
        newer: (10, u64::MAX, 6_000),
    };
    let executed = || {
        Some(vec![transfer_checked(
            "instruction #0",
            SOURCE,
            DEST,
            1_000_000,
        )])
    };
    for (nonce, why) in [(false, "nothing bounds the epoch"), (true, "durable nonce")] {
        let r = check(&diff(
            one_transfer(5_000),
            Some(terms),
            executed(),
            epoch(5, nonce),
        ));
        assert!(r.blocked, "{:?}", r.findings);
        let d = detail(&r, "Token2022TransferFeeMajority");
        assert!(d.contains("pending schedule") && d.contains(why), "{d}");
    }
}

// ─── getEpochInfo, read strictly ────────────────────────────────────────────

#[cfg(feature = "rpc")]
#[test]
fn an_epoch_answer_is_read_strictly_and_placed_exactly() {
    use graphite_core::rpc_client::EpochInfo;
    let v = serde_json::json!({
        "absoluteSlot": 432_000u64 * 700 + 100,
        "blockHeight": 1,
        "epoch": 700,
        "slotIndex": 100,
        "slotsInEpoch": 432_000,
        "transactionCount": 1
    });
    let info = EpochInfo::from_value(&v).expect("valid");
    let start = 432_000u64 * 700;
    assert_eq!(info.epoch_of(start), Some(700));
    assert_eq!(info.epoch_of(start + 431_999), Some(700));
    assert_eq!(info.epoch_of(start + 432_000), Some(701));
    assert_eq!(info.epoch_of(start - 1), Some(699));
    assert_eq!(info.epoch_of(start - 432_001), None);

    for bad in [
        serde_json::json!({"absoluteSlot": 5, "epoch": 1, "slotIndex": 6, "slotsInEpoch": 10}),
        serde_json::json!({"absoluteSlot": 50, "epoch": 1, "slotIndex": 10, "slotsInEpoch": 10}),
        serde_json::json!({"absoluteSlot": 50, "epoch": 1, "slotIndex": 0, "slotsInEpoch": 0}),
        serde_json::json!({"absoluteSlot": 50, "epoch": 1, "slotIndex": 0}),
        serde_json::json!(null),
    ] {
        assert!(EpochInfo::from_value(&bad).is_err(), "{bad}");
    }
}

/// A request cannot tell the model what ran, or in which epoch: both fields
/// are skipped on the wire.
#[test]
fn a_request_cannot_supply_the_executed_list_or_the_epoch() {
    let d = diff(
        one_transfer(5_000),
        Some(flat(50, u64::MAX)),
        Some(vec![transfer_checked(
            "instruction #0",
            SOURCE,
            DEST,
            1_000_000,
        )]),
        epoch(5, false),
    );
    let wire = serde_json::to_value(&d).unwrap();
    assert!(wire.get("token2022_executed").is_none(), "{wire}");
    assert!(wire.get("fee_epoch").is_none(), "{wire}");
    let mut injected = wire.clone();
    injected["token2022_executed"] =
        serde_json::json!([{"position": "x", "accounts": [], "data": []}]);
    injected["fee_epoch"] = serde_json::json!({"simulated_epoch": 1, "durable_nonce": false});
    let back: StateDiff = serde_json::from_value(injected).unwrap();
    assert!(back.token2022_executed.is_none() && back.fee_epoch.is_none());
    assert_eq!(back.deltas.len(), d.deltas.len());
}

// ─── The diff covers the transaction, not one instruction ──────────────────

/// Round 21: L4 compared a transaction-wide diff against the PRIMARY
/// instruction's accounts, so every change another instruction of the same
/// transaction made to its own accounts was `DiffAccountNotInInstruction` —
/// 10 of 40 live mainnet transactions (2026-09-27) failed L4 on it. A diff
/// Graphite built carries the transaction's own account list; a change
/// outside it is still the diff failing to correspond.
#[test]
fn a_change_another_instruction_makes_is_not_a_diff_that_fails_to_correspond() {
    let deltas = || {
        vec![
            account(&SOURCE, SRC_OWNER, (10_000_000, 0), (9_000_000, 0)),
            account(&DEST, DST_OWNER, (0, 0), (1_000_000, 0)),
            // A sibling instruction's account: the primary never names it.
            account(&THIRD, THIRD_OWNER, (5, 0), (6, 0)),
        ]
    };
    let primary_accounts = vec![resolved(&b58(&SOURCE)), resolved(&b58(&DEST))];
    let declared = [
        "debits accounts.source token balance by data.amount".to_string(),
        "credits accounts.destination token balance by data.amount".to_string(),
    ];
    let run = |tx: Option<Vec<String>>| {
        let mut d = diff(deltas(), None, None, None);
        d.transaction_accounts = tx;
        check_state_diff(&StateDiffCheck {
            diff: &d,
            resolved_accounts: &primary_accounts,
            privileges_grounded: true,
            expected_state_changes: &declared,
            fee_payer: None,
        })
    };
    let in_tx = run(Some(vec![b58(&SOURCE), b58(&DEST), b58(&THIRD)]));
    assert!(
        !codes(&in_tx).contains(&"DiffAccountNotInInstruction".to_string()),
        "{:?}",
        in_tx.findings
    );
    assert!(
        !codes(&in_tx).contains(&"WriteToReadonlyAccount".to_string()),
        "{:?}",
        in_tx.findings
    );
    // Outside the transaction, or no list at all (a caller's diff): the
    // correspondence check stands.
    for tx in [Some(vec![b58(&SOURCE), b58(&DEST)]), None] {
        let r = run(tx);
        assert!(
            codes(&r).contains(&"DiffAccountNotInInstruction".to_string()),
            "{:?}",
            r.findings
        );
    }
    // And a request cannot supply the list.
    let wire = serde_json::to_value(diff(deltas(), None, None, None)).unwrap();
    let mut injected = wire.clone();
    injected["transaction_accounts"] = serde_json::json!([b58(&THIRD)]);
    let back: StateDiff = serde_json::from_value(injected).unwrap();
    assert!(back.transaction_accounts.is_none());
}

// ─── Through the pipeline, over a loopback mock RPC ─────────────────────────

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

    const SYSTEM: &str = "11111111111111111111111111111111";

    type Account = (u64, String, Vec<u8>);

    #[derive(Default)]
    struct Cluster {
        pre: HashMap<String, Account>,
        post: HashMap<String, Account>,
        /// The `innerInstructions` value to answer with, verbatim JSON.
        inner: String,
        /// The `getEpochInfo` result, verbatim JSON (`null` = unsupported).
        epoch_info: String,
        /// Methods asked for, in order.
        methods: Vec<String>,
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
                let method = body["method"].as_str().unwrap_or("").to_string();
                s.methods.push(method.clone());
                let result = match method.as_str() {
                    "getMultipleAccounts" => {
                        let keys = strings(&body["params"][0]);
                        let vals: Vec<String> =
                            keys.iter().map(|k| account_json(s.pre.get(k))).collect();
                        format!(
                            r#"{{"context":{{"slot":1000}},"value":[{}]}}"#,
                            vals.join(",")
                        )
                    }
                    "simulateTransaction" => {
                        let keys = strings(&body["params"][1]["accounts"]["addresses"]);
                        let post: Vec<String> =
                            keys.iter().map(|k| account_json(s.post.get(k))).collect();
                        format!(
                            r#"{{"context":{{"slot":1000}},"value":{{"err":null,"logs":[],"unitsConsumed":9000,"fee":5000,
                            "preBalances":[1000000000,2039280,2039280,1461600,1],
                            "postBalances":[999995000,2039280,2039280,1461600,1],
                            "innerInstructions":{},"loadedAddresses":{{"writable":[],"readonly":[]}},
                            "accounts":[{}],"returnData":null}}}}"#,
                            s.inner,
                            post.join(",")
                        )
                    }
                    "getEpochInfo" => s.epoch_info.clone(),
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
        let mut c = Cluster {
            inner: "[]".to_string(),
            epoch_info: "null".to_string(),
            ..Default::default()
        };
        let t22 = T22.to_string();
        c.pre.insert(
            b58(&OWNER_SIGNER),
            (1_000_000_000, SYSTEM.to_string(), vec![]),
        );
        c.post.insert(
            b58(&OWNER_SIGNER),
            (999_995_000, SYSTEM.to_string(), vec![]),
        );
        c.pre.insert(
            b58(&SOURCE),
            (
                2_039_280,
                t22.clone(),
                t22_account(SRC_OWNER, 10_000_000, 0),
            ),
        );
        c.post.insert(
            b58(&SOURCE),
            (
                2_039_280,
                t22.clone(),
                t22_account(SRC_OWNER, 10_000_000 - gross, 0),
            ),
        );
        c.pre.insert(
            b58(&DEST),
            (2_039_280, t22.clone(), t22_account(DST_OWNER, 0, 0)),
        );
        c.post.insert(
            b58(&DEST),
            (
                2_039_280,
                t22.clone(),
                t22_account(DST_OWNER, gross - fee, fee),
            ),
        );
        c.pre
            .insert(b58(&MINT), (1_461_600, t22, t22_mint(1_000_000_000, terms)));
        c
    }

    /// A legacy TransferChecked on Token-2022: keys [owner (payer), source,
    /// destination, mint, program], one empty signature slot.
    fn frame(gross: u64) -> (Vec<u8>, Vec<u8>) {
        let program: [u8; 32] = bs58::decode(T22).into_vec().unwrap().try_into().unwrap();
        let keys = [OWNER_SIGNER, SOURCE, DEST, MINT, program];
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
        let (frame, data) = frame(gross);
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
            account_addresses: vec![b58(&SOURCE), b58(&MINT), b58(&DEST), b58(&OWNER_SIGNER)],
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

    /// Slot 1000 in an epoch of 432,000 slots that started at slot 0: epoch 0,
    /// with 431,000 slots to go.
    fn epoch_zero() -> String {
        r#"{"absoluteSlot":1000,"blockHeight":900,"epoch":0,"slotIndex":1000,"slotsInEpoch":432000,"transactionCount":null}"#.to_string()
    }

    /// Graphite asks for the epoch itself: the transfer is judged under the
    /// epoch-0 schedule it paid, and the pending epoch-5 schedule is disclosed
    /// with the reason nothing bounds its reach (Round 22).
    #[tokio::test]
    async fn graphite_reads_the_epoch_and_judges_the_pending_schedule() {
        let terms = Terms {
            withheld: 0,
            older: (0, u64::MAX, 50),
            newer: (5, u64::MAX, 100),
        };
        let mut c = cluster(1_000_000, 5_000, terms);
        c.epoch_info = epoch_zero();
        let (r, state) = verify(c, 1_000_000).await;
        let (status, reason) = l4(&r);
        assert!(
            state
                .lock()
                .unwrap()
                .methods
                .iter()
                .any(|m| m == "getEpochInfo"),
            "the epoch was never read"
        );
        assert_ne!(status, LayerStatus::Failed, "{reason}");
        assert!(reason.contains("995000 arrived"), "{reason}");
        assert!(reason.contains("Token2022TransferFeeRising"), "{reason}");
        assert!(reason.contains("simulated in epoch 0"), "{reason}");

        // The same transaction against an RPC that cannot say the epoch: the
        // Round 20 disclosure, with the reason.
        let (r, _) = verify(cluster(1_000_000, 5_000, terms), 1_000_000).await;
        let (_, reason) = l4(&r);
        assert!(reason.contains("Token2022TransferFeeRising"), "{reason}");
        assert!(reason.contains("was not read"), "{reason}");
    }

    /// The executed list is Graphite's: the transaction's own TransferChecked
    /// replayed. An RPC that reports a different fee is refused by the
    /// replay, in its words.
    #[tokio::test]
    async fn the_replay_runs_on_what_graphite_parsed() {
        let (r, _) = verify(cluster(1_000_000, 4_000, flat(100, 5_000)), 1_000_000).await;
        let (status, reason) = l4(&r);
        assert_eq!(status, LayerStatus::Failed, "{reason}");
        assert!(
            reason.contains("does not reproduce the observed state"),
            "{reason}"
        );
        assert!(!r.approved);
    }

    /// An inner instruction that cannot be placed makes the executed list
    /// unknown — not shorter — and the Round 20 rule decides.
    #[tokio::test]
    async fn an_unplaceable_inner_instruction_falls_back_to_the_round_20_rule() {
        let mut c = cluster(1_000_000, 5_000, flat(100, 5_000));
        c.inner = r#"[{"index":7,"instructions":[{"programIdIndex":4,"accounts":[1,3,2,0],"data":"3","stackHeight":2}]}]"#.to_string();
        let (r, _) = verify(c, 1_000_000).await;
        let (_, reason) = l4(&r);
        assert!(!reason.contains("does not reproduce"), "{reason}");
        assert!(reason.contains("995000 arrived"), "{reason}");
    }
}

// ─── L4 without a diff ──────────────────────────────────────────────────────

mod l4_without_a_diff {
    use super::system_transfer_input as transfer;
    use graphite_core::manifest::load_seed_manifests;
    use graphite_core::verification::{GraphiteCore, LayerStatus};

    /// No RPC, no artifact: nothing was observed, and L4 no longer says it
    /// passed. It says what it checked.
    #[test]
    fn a_structural_check_without_a_diff_is_inconclusive_not_passed() {
        let core = GraphiteCore::with_registry(load_seed_manifests());
        let r = core.verify(&transfer()).expect("verified");
        let l4 = r
            .layers
            .iter()
            .find(|l| l.layer.starts_with("L4"))
            .expect("L4");
        assert_eq!(l4.status, LayerStatus::Inconclusive, "{}", l4.reason);
        assert!(l4.reason.contains("State not observed"), "{}", l4.reason);
        assert!(!r.approved);
    }
}

// ─── The synchronous verify ─────────────────────────────────────────────────

mod sync_verify {
    use super::system_transfer_input as input;
    use graphite_core::manifest::load_seed_manifests;
    use graphite_core::verification::{GraphiteCore, VerificationError};
    use std::sync::Arc;

    /// Blocking a runtime worker on another runtime is a Tokio panic; the
    /// synchronous API refuses instead and names the one to use.
    #[tokio::test]
    async fn inside_a_runtime_it_refuses_instead_of_panicking() {
        let core = GraphiteCore::with_registry(load_seed_manifests());
        match core.verify(&input()) {
            Err(VerificationError::InvalidInput(msg)) => {
                assert!(msg.contains("verify_async"), "{msg}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        // The async API is the one that works here.
        assert!(core.verify_async(&input()).await.is_ok());
    }

    /// Many threads, one runtime: every caller is served.
    #[test]
    fn concurrent_callers_share_one_runtime() {
        let core = Arc::new(GraphiteCore::with_registry(load_seed_manifests()));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let core = Arc::clone(&core);
                std::thread::spawn(move || {
                    for _ in 0..5 {
                        core.verify(&input()).expect("verified");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("no caller panicked");
        }
    }
}

/// A System transfer described without an artifact.
fn system_transfer_input() -> graphite_core::verification::VerificationInput {
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::semantic_graph_store::BehaviorEvidence;
    use graphite_core::verification::{ProposedIntent, VerificationInput};
    let mut data = vec![2u8, 0, 0, 0];
    data.extend_from_slice(&1_000u64.to_le_bytes());
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send 1000 lamports".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: "11111111111111111111111111111111".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![
            bs58::encode([7u8; 32]).into_string(),
            bs58::encode([8u8; 32]).into_string(),
        ],
        instruction_data: Some(data),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

// ─── A writable flag is not a write ─────────────────────────────────────────

/// Round 21: a declared-read-only account the transaction marks writable is
/// judged by what happened to it. Solana grants privileges per message, so
/// the flag alone says nothing about this instruction: another instruction's
/// declared write explains it, and otherwise Graphite's own simulation must
/// show the account unchanged. Not observed, or changed, it blocks as before;
/// a declared signer that does not sign always blocks.
#[cfg(feature = "rpc")]
mod a_writable_flag_is_not_a_write {
    use base64::Engine;
    use graphite_core::manifest::load_seed_manifests;
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
    use graphite_core::semantic_graph_store::BehaviorEvidence;
    use graphite_core::tx_pattern_analysis::TransactionInstruction;
    use graphite_core::verification::{
        GraphiteCore, ProposedIntent, VerificationInput, VerificationResult,
    };
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const SYSTEM: &str = "11111111111111111111111111111111";
    const AUTHORITY: [u8; 32] = [61u8; 32];
    const SOURCE: [u8; 32] = [62u8; 32];
    const DEST: [u8; 32] = [63u8; 32];
    const MINT: [u8; 32] = [64u8; 32];
    const DEST_OWNER: [u8; 32] = [65u8; 32];

    fn b58(k: &[u8; 32]) -> String {
        bs58::encode(k).into_string()
    }
    fn key(s: &str) -> [u8; 32] {
        bs58::decode(s).into_vec().unwrap().try_into().unwrap()
    }

    fn token_account(owner: [u8; 32], amount: u64) -> Vec<u8> {
        let mut d = vec![0u8; 165];
        d[0..32].copy_from_slice(&MINT);
        d[32..64].copy_from_slice(&owner);
        d[64..72].copy_from_slice(&amount.to_le_bytes());
        d[108] = 1;
        d
    }
    fn mint(supply: u64) -> Vec<u8> {
        let mut d = vec![0u8; 82];
        d[0..4].copy_from_slice(&1u32.to_le_bytes());
        d[4..36].copy_from_slice(&AUTHORITY);
        d[36..44].copy_from_slice(&supply.to_le_bytes());
        d[44] = 6;
        d[45] = 1;
        d
    }

    /// A legacy message: `keys` under `header`, then `(program, accounts,
    /// data)` instructions, one empty signature slot per signer.
    fn frame(keys: &[[u8; 32]], header: [u8; 3], ixs: &[(u8, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![header[0]];
        for _ in 0..header[0] {
            out.extend_from_slice(&[0u8; 64]);
        }
        out.extend_from_slice(&header);
        out.push(keys.len() as u8);
        for k in keys {
            out.extend_from_slice(k);
        }
        out.extend_from_slice(&[9u8; 32]);
        out.push(ixs.len() as u8);
        for (p, accs, data) in ixs {
            out.push(*p);
            out.push(accs.len() as u8);
            out.extend_from_slice(accs);
            out.push(data.len() as u8);
            out.extend_from_slice(data);
        }
        out
    }

    fn transfer_checked_data(amount: u64) -> Vec<u8> {
        let mut d = vec![12u8];
        d.extend_from_slice(&amount.to_le_bytes());
        d.push(6);
        d
    }

    type Account = (u64, String, Vec<u8>);

    struct Cluster {
        pre: HashMap<String, Account>,
        post: HashMap<String, Account>,
        /// Lamports added to an account in the pre-state READ only, as if
        /// another transaction credited it after the simulation's slot.
        read_skew: HashMap<String, u64>,
    }

    fn account_json(a: Option<&Account>) -> String {
        match a {
            None => "null".to_string(),
            Some((l, o, d)) => format!(
                r#"{{"lamports":{l},"owner":"{o}","executable":false,"rentEpoch":0,"data":["{}","base64"]}}"#,
                base64::engine::general_purpose::STANDARD.encode(d)
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

    /// `keys` is the transaction's account list, in order: the simulator's
    /// balance arrays are reported over it, consistent with the cluster —
    /// what a real RPC reports, one slot for both halves.
    fn serve(c: Cluster, keys: Vec<String>) -> String {
        let state = Arc::new(Mutex::new(c));
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
                let s = state.lock().unwrap();
                let result = match body["method"].as_str().unwrap_or("") {
                    "getMultipleAccounts" => {
                        let keys = strings(&body["params"][0]);
                        let v: Vec<String> = keys
                            .iter()
                            .map(|k| {
                                let mut a = s.pre.get(k).cloned();
                                if let (Some(acct), Some(extra)) = (a.as_mut(), s.read_skew.get(k))
                                {
                                    acct.0 += extra;
                                }
                                account_json(a.as_ref())
                            })
                            .collect();
                        format!(r#"{{"context":{{"slot":51}},"value":[{}]}}"#, v.join(","))
                    }
                    "simulateTransaction" => {
                        let asked = strings(&body["params"][1]["accounts"]["addresses"]);
                        let v: Vec<String> =
                            asked.iter().map(|k| account_json(s.post.get(k))).collect();
                        let lamports = |side: &HashMap<String, Account>, k: &String| {
                            side.get(k).map_or(1, |a| a.0).to_string()
                        };
                        let pre = keys
                            .iter()
                            .map(|k| lamports(&s.pre, k))
                            .collect::<Vec<_>>()
                            .join(",");
                        let post: Vec<String> = keys.iter().map(|k| lamports(&s.post, k)).collect();
                        format!(
                            r#"{{"context":{{"slot":50}},"value":{{"err":null,"logs":[],"unitsConsumed":7000,"fee":5000,"preBalances":[{pre}],"postBalances":[{}],"innerInstructions":[],"loadedAddresses":{{"writable":[],"readonly":[]}},"accounts":[{}],"returnData":null}}}}"#,
                            post.join(","),
                            v.join(",")
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

    fn input(frame: Vec<u8>, data: Vec<u8>) -> VerificationInput {
        VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "transfer".to_string(),
                raw_natural_language: "send tokens".to_string(),
                confidence_of_parse: 0.9,
                extracted_parameters: None,
            },
            program_id: TOKEN.to_string(),
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
        }
    }

    /// TransferChecked with the MINT — declared read-only — marked writable:
    /// keys [authority (payer), source, destination, mint, program], only the
    /// program read-only.
    fn mint_marked_writable() -> (Vec<u8>, Vec<u8>) {
        let data = transfer_checked_data(1_000);
        let keys = [AUTHORITY, SOURCE, DEST, MINT, key(TOKEN)];
        (
            frame(&keys, [1, 0, 1], &[(4, vec![1, 3, 2, 0], data.clone())]),
            data,
        )
    }

    fn cluster(mint_supply_after: u64) -> Cluster {
        let t = TOKEN.to_string();
        let mut pre = HashMap::new();
        let mut post = HashMap::new();
        pre.insert(b58(&AUTHORITY), (1_000_000_000, SYSTEM.to_string(), vec![]));
        post.insert(b58(&AUTHORITY), (999_995_000, SYSTEM.to_string(), vec![]));
        pre.insert(
            b58(&SOURCE),
            (2_039_280, t.clone(), token_account(AUTHORITY, 10_000)),
        );
        post.insert(
            b58(&SOURCE),
            (2_039_280, t.clone(), token_account(AUTHORITY, 9_000)),
        );
        pre.insert(
            b58(&DEST),
            (2_039_280, t.clone(), token_account(DEST_OWNER, 0)),
        );
        post.insert(
            b58(&DEST),
            (2_039_280, t.clone(), token_account(DEST_OWNER, 1_000)),
        );
        pre.insert(b58(&MINT), (1_461_600, t.clone(), mint(1_000_000)));
        post.insert(b58(&MINT), (1_461_600, t, mint(mint_supply_after)));
        Cluster {
            pre,
            post,
            read_skew: HashMap::new(),
        }
    }

    fn core() -> GraphiteCore {
        GraphiteCore::with_registry(load_seed_manifests())
    }

    async fn verify_input_with_rpc(c: Cluster, i: VerificationInput) -> VerificationResult {
        let keys =
            graphite_core::tx_artifact::parse_transaction(i.signed_transaction.as_ref().unwrap())
                .expect("the test frame parses")
                .static_keys;
        let mut core = core();
        core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
            endpoint: serve(c, keys),
            timeout: std::time::Duration::from_secs(5),
            max_retries: 0,
            ..Default::default()
        }));
        core.verify_async(&i).await.expect("verified")
    }

    async fn verify_with_rpc(
        c: Cluster,
        frame: Vec<u8>,
        data: Vec<u8>,
        _n: usize,
    ) -> VerificationResult {
        let keys = graphite_core::tx_artifact::parse_transaction(&frame)
            .expect("the test frame parses")
            .static_keys;
        let mut core = core();
        core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
            endpoint: serve(c, keys),
            timeout: std::time::Duration::from_secs(5),
            max_retries: 0,
            ..Default::default()
        }));
        core.verify_async(&input(frame, data))
            .await
            .expect("verified")
    }

    fn reasons(r: &VerificationResult) -> String {
        r.risk_verdict
            .findings
            .iter()
            .map(|f| format!("{}: {} ; ", f.pattern, f.reason))
            .collect()
    }

    fn privilege_blocked(r: &VerificationResult) -> bool {
        r.risk_verdict.status == "Blocked" && reasons(r).contains("kind=privilege")
    }

    /// Without an RPC nothing observed the mint: the flag blocks, as it did.
    #[tokio::test]
    async fn unobserved_it_still_blocks() {
        let (frame, data) = mint_marked_writable();
        let r = core().verify_async(&input(frame, data)).await.unwrap();
        assert!(privilege_blocked(&r), "{}", reasons(&r));
        assert!(
            reasons(&r).contains("no pre/post diff observed it"),
            "{}",
            reasons(&r)
        );
        assert!(!r.approved);
    }

    /// Observed unchanged: the flag granted a write nothing made.
    #[tokio::test]
    async fn observed_unchanged_it_is_not_an_escalation() {
        let (frame, data) = mint_marked_writable();
        let r = verify_with_rpc(cluster(1_000_000), frame, data, 5).await;
        assert!(!reasons(&r).contains("kind=privilege"), "{}", reasons(&r));
        let mint = r
            .resolved_accounts
            .iter()
            .find(|a| a.address == b58(&MINT))
            .expect("mint resolved");
        assert!(!mint.privilege_mismatch);
    }

    /// Observed CHANGED: the write happened, and it blocks.
    #[tokio::test]
    async fn observed_changed_it_blocks() {
        let (frame, data) = mint_marked_writable();
        let r = verify_with_rpc(cluster(2_000_000), frame, data, 5).await;
        assert!(privilege_blocked(&r), "{}", reasons(&r));
        assert!(
            reasons(&r).contains("the simulation shows it changed"),
            "{}",
            reasons(&r)
        );
        assert!(!r.approved);
        let mint = r
            .resolved_accounts
            .iter()
            .find(|a| a.address == b58(&MINT))
            .expect("mint resolved");
        assert!(
            mint.privilege_mismatch,
            "the flag is restored when the block stands"
        );
    }

    /// Round 21: the pre-state read lands a slot after the simulation, and
    /// another transaction credited the destination in between. Lamports come
    /// from the simulator's own preBalances, so the skew is not a
    /// conservation failure.
    #[tokio::test]
    async fn a_pre_state_read_a_slot_late_does_not_break_conservation() {
        let data = transfer_checked_data(1_000);
        let keys = [AUTHORITY, SOURCE, DEST, MINT, key(TOKEN)];
        let frame = frame(&keys, [1, 0, 2], &[(4, vec![1, 3, 2, 0], data.clone())]);
        let mut c = cluster(1_000_000);
        c.read_skew.insert(b58(&DEST), 7_777);
        let r = verify_with_rpc(c, frame, data, 5).await;
        let l4 = r
            .layers
            .iter()
            .find(|l| l.layer.starts_with("L4"))
            .expect("L4");
        assert!(!l4.reason.contains("LamportsNotConserved"), "{}", l4.reason);
        assert!(l4.reason.contains("preBalances"), "{}", l4.reason);
    }

    /// Round 21: an account the transaction marks read-only is not diffed —
    /// the runtime forbids writing it, so a "change" there is the pre-state
    /// read and the simulation landing at different slots. Here a declared
    /// sibling names the read-only mint, whose supply other transactions
    /// moved between the two reads.
    #[tokio::test]
    async fn a_read_only_account_is_not_diffed_for_skew_to_show_on() {
        let data = transfer_checked_data(1_000);
        let keys = [AUTHORITY, SOURCE, DEST, MINT, key(TOKEN)];
        let frame = frame(
            &keys,
            [1, 0, 2],
            &[
                (4, vec![1, 3, 2, 0], data.clone()),
                (4, vec![1, 3, 2, 0], data.clone()),
            ],
        );
        let mut c = cluster(1_000_000);
        // Two transfers of 1,000; the mint's supply moved by someone else.
        let t = TOKEN.to_string();
        c.post.insert(
            b58(&SOURCE),
            (2_039_280, t.clone(), token_account(AUTHORITY, 8_000)),
        );
        c.post.insert(
            b58(&DEST),
            (2_039_280, t.clone(), token_account(DEST_OWNER, 2_000)),
        );
        c.post.insert(b58(&MINT), (1_461_600, t, mint(1_000_777)));
        let mut i = input(frame, data.clone());
        i.transaction_instructions = vec![TransactionInstruction {
            program_id: TOKEN.to_string(),
            instruction_discriminator: "0c".to_string(),
            account_addresses: vec![b58(&SOURCE), b58(&MINT), b58(&DEST), b58(&AUTHORITY)],
            cpi_targets: vec![],
        }];
        let r = verify_input_with_rpc(c, i).await;
        let l4 = r
            .layers
            .iter()
            .find(|l| l.layer.starts_with("L4"))
            .expect("L4");
        assert!(!l4.reason.contains(&b58(&MINT)), "{}", l4.reason);
        assert!(
            !l4.reason.contains("WriteToReadonlyAccount"),
            "{}",
            l4.reason
        );
    }

    /// A sibling that declares the write explains the flag with no RPC at
    /// all: an SPL Token MintTo on the same mint, in the same transaction.
    #[tokio::test]
    async fn another_instructions_declared_write_explains_it() {
        let data = transfer_checked_data(1_000);
        let mut mint_to = vec![7u8];
        mint_to.extend_from_slice(&5u64.to_le_bytes());
        let keys = [AUTHORITY, SOURCE, DEST, MINT, key(TOKEN)];
        let frame = frame(
            &keys,
            [1, 0, 1],
            &[
                (4, vec![1, 3, 2, 0], data.clone()),
                (4, vec![3, 2, 0], mint_to),
            ],
        );
        let r = core().verify_async(&input(frame, data)).await.unwrap();
        assert!(
            !reasons(&r).contains("kind=privilege"),
            "a declared sibling write is not an escalation: {}",
            reasons(&r)
        );
    }

    /// The signer direction is unchanged: a declared signer that does not
    /// sign blocks whatever the diff says — here the authority is writable,
    /// unsigned, and observed UNCHANGED, which would pass the write rule.
    #[tokio::test]
    async fn a_declared_signer_that_does_not_sign_still_blocks() {
        let data = transfer_checked_data(1_000);
        let payer = [66u8; 32];
        // Payer signs; the authority is writable and does not sign.
        let keys = [payer, SOURCE, DEST, AUTHORITY, MINT, key(TOKEN)];
        let frame = frame(&keys, [1, 0, 2], &[(5, vec![1, 4, 2, 3], data.clone())]);
        let mut c = cluster(1_000_000);
        c.pre
            .insert(b58(&payer), (1_000_000_000, SYSTEM.to_string(), vec![]));
        c.post
            .insert(b58(&payer), (999_995_000, SYSTEM.to_string(), vec![]));
        c.post
            .insert(b58(&AUTHORITY), (1_000_000_000, SYSTEM.to_string(), vec![]));
        let r = verify_with_rpc(c, frame, data, 6).await;
        assert!(privilege_blocked(&r), "{}", reasons(&r));
    }
}

// ─── Token-2022 extensions judged by what the transaction does ─────────────

/// Round 21: a transfer hook that names no program, confidential-transfer
/// state nobody touched, and an issuer's standing powers used by nobody
/// change nothing about a transaction. They were refused on sight; they are
/// now stated, and the ones that DO something still block.
mod extensions_judged_by_what_happened {
    use super::*;

    const HOOK_PROGRAM: [u8; 32] = [71u8; 32];
    const DELEGATE: [u8; 32] = [72u8; 32];

    /// A plain Token-2022 account (no fee) of MINT carrying `entries`.
    fn account_with(owner: [u8; 32], amount: u64, entries: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut d = vec![0u8; 165];
        d[0..32].copy_from_slice(&MINT);
        d[32..64].copy_from_slice(&owner);
        d[64..72].copy_from_slice(&amount.to_le_bytes());
        d[108] = 1;
        d.push(2);
        d.extend(tlv(entries));
        d
    }

    fn mint_with(entries: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut d = vec![0u8; 82];
        d[36..44].copy_from_slice(&1_000_000u64.to_le_bytes());
        d[44] = 6;
        d[45] = 1;
        d.resize(165, 0);
        d.push(1);
        d.extend(tlv(entries));
        d
    }

    fn hook(program: Option<[u8; 32]>) -> (u16, Vec<u8>) {
        let mut v = vec![0u8; 32];
        v.extend_from_slice(&program.unwrap_or([0u8; 32]));
        (14, v)
    }

    fn with_mint(
        deltas: Vec<AccountDelta>,
        mint: Option<Vec<u8>>,
        executed: Option<Vec<ExecutedTokenInstruction>>,
    ) -> StateDiff {
        let mut d = StateDiff {
            deltas,
            provenance: DiffProvenance::RpcSimulated,
            ..Default::default()
        };
        if let Some(m) = mint {
            d.token2022_mints.insert(b58(&MINT), snap(&MINT, &m));
        }
        d.token2022_executed = executed;
        d
    }

    fn transfer_with(
        entries_src: &[(u16, Vec<u8>)],
        entries_dst: &[(u16, Vec<u8>)],
    ) -> Vec<AccountDelta> {
        vec![
            AccountDelta {
                pubkey: b58(&SOURCE),
                before: Some(snap(&SOURCE, &account_with(SRC_OWNER, 10_000, entries_src))),
                after: Some(snap(&SOURCE, &account_with(SRC_OWNER, 9_000, entries_src))),
            },
            AccountDelta {
                pubkey: b58(&DEST),
                before: Some(snap(&DEST, &account_with(DST_OWNER, 0, entries_dst))),
                after: Some(snap(&DEST, &account_with(DST_OWNER, 1_000, entries_dst))),
            },
        ]
    }

    fn hook_accounts() -> Vec<AccountDelta> {
        transfer_with(&[(15, vec![0])], &[(15, vec![0])])
    }

    #[test]
    fn a_transfer_hook_that_names_no_program_is_inert() {
        let r = check(&with_mint(
            hook_accounts(),
            Some(mint_with(&[hook(None)])),
            None,
        ));
        assert_modelled(&r);
        assert!(detail(&r, "Token2022ExtensionInert").contains("names no program"));
    }

    #[test]
    fn a_transfer_hook_that_runs_a_program_still_blocks_and_says_which() {
        let r = check(&with_mint(
            hook_accounts(),
            Some(mint_with(&[hook(Some(HOOK_PROGRAM))])),
            None,
        ));
        assert_unmodelled(&r, &b58(&HOOK_PROGRAM));
    }

    #[test]
    fn a_hook_whose_mint_was_not_read_still_blocks() {
        let r = check(&with_mint(hook_accounts(), None, None));
        assert_unmodelled(&r, "was not read");
    }

    fn confidential(bytes: u8) -> (u16, Vec<u8>) {
        (5, vec![bytes; 12])
    }

    #[test]
    fn confidential_state_nobody_touched_is_inert() {
        let deltas = || transfer_with(&[confidential(1)], &[]);
        let executed = Some(vec![transfer_checked(
            "instruction #0",
            SOURCE,
            DEST,
            1_000,
        )]);
        let r = check(&with_mint(deltas(), None, executed));
        assert_modelled(&r);
        assert!(detail(&r, "Token2022ExtensionInert").contains("byte-for-byte unchanged"));

        // Without the executed instructions nothing shows no confidential
        // instruction ran.
        let r = check(&with_mint(deltas(), None, None));
        assert_unmodelled(&r, "executed instructions were not available");

        // A confidential instruction on the account.
        let executed = Some(vec![
            transfer_checked("instruction #0", SOURCE, DEST, 1_000),
            ix("instruction #1", &[SOURCE, MINT], vec![27, 5]),
        ]);
        let r = check(&with_mint(deltas(), None, executed));
        assert_unmodelled(&r, "confidential-transfer instruction on it");
    }

    #[test]
    fn confidential_state_that_changed_blocks() {
        let mut deltas = transfer_with(&[confidential(1)], &[]);
        deltas[0].after = Some(snap(
            &SOURCE,
            &account_with(SRC_OWNER, 9_000, &[confidential(2)]),
        ));
        let executed = Some(vec![transfer_checked(
            "instruction #0",
            SOURCE,
            DEST,
            1_000,
        )]);
        let r = check(&with_mint(deltas, None, executed));
        assert_unmodelled(&r, "changed");
    }

    #[test]
    fn a_permanent_delegate_moving_someone_elses_tokens_is_critical() {
        let mint = mint_with(&[(12, DELEGATE.to_vec())]);
        let by = |authority: [u8; 32]| {
            let mut data = vec![12u8];
            data.extend_from_slice(&1_000u64.to_le_bytes());
            data.push(6);
            Some(vec![ix(
                "instruction #0",
                &[SOURCE, MINT, DEST, authority],
                data,
            )])
        };
        let r = check(&with_mint(
            transfer_with(&[], &[]),
            Some(mint.clone()),
            by(DELEGATE),
        ));
        assert!(r.blocked);
        let d = detail(&r, "Token2022PermanentDelegateExercised");
        assert!(
            d.contains(&b58(&DELEGATE)) && d.contains(&b58(&SRC_OWNER)),
            "{d}"
        );

        // The holder's own transfer, under the same mint: nothing exercised.
        let r = check(&with_mint(
            transfer_with(&[], &[]),
            Some(mint),
            by(SRC_OWNER),
        ));
        assert!(!codes(&r).contains(&"Token2022PermanentDelegateExercised".to_string()));
    }

    #[test]
    fn extension_values_are_read_exactly_or_not_at_all() {
        use graphite_core::state_diff::decode_token2022_powers;
        let p = decode_token2022_powers(&mint_with(&[
            hook(Some(HOOK_PROGRAM)),
            (12, DELEGATE.to_vec()),
        ]))
        .unwrap();
        assert_eq!(p.transfer_hook_program, Some(Some(b58(&HOOK_PROGRAM))));
        assert_eq!(p.permanent_delegate, Some(Some(b58(&DELEGATE))));
        assert_eq!(p.close_authority, None);
        // A hook entry of the wrong length, or twice.
        assert!(decode_token2022_powers(&mint_with(&[(14, vec![0u8; 63])])).is_none());
        assert!(decode_token2022_powers(&mint_with(&[hook(None), hook(None)])).is_none());
        assert!(decode_token2022_powers(&mint_with(&[(12, vec![0u8; 31])])).is_none());
    }
}

// ─── The compute budget, read from the bytes ───────────────────────────────

mod compute_budget {
    use graphite_core::tx_artifact::{compute_budget_request, parse_transaction};

    const CB: &str = "ComputeBudget111111111111111111111111111111";

    fn legacy(budget: &[Vec<u8>]) -> Vec<u8> {
        let cb: [u8; 32] = bs58::decode(CB).into_vec().unwrap().try_into().unwrap();
        let keys = [[1u8; 32], [2u8; 32], [0u8; 32], cb];
        let mut out = vec![1u8];
        out.extend_from_slice(&[0u8; 64]);
        out.extend_from_slice(&[1, 0, 2]);
        out.push(keys.len() as u8);
        for k in &keys {
            out.extend_from_slice(k);
        }
        out.extend_from_slice(&[9u8; 32]);
        out.push((budget.len() + 1) as u8);
        for data in budget {
            out.extend_from_slice(&[3, 0, data.len() as u8]);
            out.extend_from_slice(data);
        }
        let mut transfer = vec![2u8, 0, 0, 0];
        transfer.extend_from_slice(&1u64.to_le_bytes());
        out.extend_from_slice(&[2, 2, 0, 1, transfer.len() as u8]);
        out.extend_from_slice(&transfer);
        out
    }

    fn limit(n: u32) -> Vec<u8> {
        let mut d = vec![2u8];
        d.extend_from_slice(&n.to_le_bytes());
        d
    }
    fn price(n: u64) -> Vec<u8> {
        let mut d = vec![3u8];
        d.extend_from_slice(&n.to_le_bytes());
        d
    }
    fn heap(n: u32) -> Vec<u8> {
        let mut d = vec![1u8];
        d.extend_from_slice(&n.to_le_bytes());
        d
    }

    fn budget(frame: &[u8]) -> graphite_core::tx_artifact::ComputeBudgetRequest {
        compute_budget_request(&parse_transaction(frame).expect("parses"))
    }

    #[test]
    fn the_priority_fee_is_price_times_limit_rounded_up() {
        let b = budget(&legacy(&[limit(200_000), price(1_000_000)]));
        assert_eq!(b.source, "compute_budget_instructions");
        assert_eq!(b.compute_unit_limit, Some(200_000));
        assert_eq!(b.priority_fee_lamports, 200_000);
        let b = budget(&legacy(&[limit(3), price(1)]));
        assert_eq!(b.priority_fee_lamports, 1, "rounded up, never down");
        // A limit above the runtime's ceiling is capped, as the runtime caps it.
        let b = budget(&legacy(&[limit(5_000_000), price(1_000_000)]));
        assert_eq!(b.effective_compute_unit_limit, 1_400_000);
        assert_eq!(b.priority_fee_lamports, 1_400_000);
        // No limit: the default's upper bound, 200,000 per other instruction.
        let b = budget(&legacy(&[price(1_000_000)]));
        assert_eq!(b.effective_compute_unit_limit, 200_000);
        assert_eq!(b.priority_fee_lamports, 200_000);
        assert!(b.problems.is_empty());
    }

    #[test]
    fn what_the_runtime_refuses_is_named() {
        let b = budget(&legacy(&[limit(1), limit(2)]));
        assert!(
            b.problems.iter().any(|p| p.contains("duplicate")),
            "{:?}",
            b.problems
        );
        let b = budget(&legacy(&[heap(1000)]));
        assert!(
            b.problems.iter().any(|p| p.contains("heap")),
            "{:?}",
            b.problems
        );
        let b = budget(&legacy(&[vec![2u8, 1, 2]]));
        assert!(
            b.problems.iter().any(|p| p.contains("wrong length")),
            "{:?}",
            b.problems
        );
        let b = budget(&legacy(&[vec![9u8]]));
        assert!(
            b.problems.iter().any(|p| p.contains("cannot decode")),
            "{:?}",
            b.problems
        );
    }

    /// A priority fee above what a Solana fee can plausibly reach is refused
    /// before anything is simulated, and the verdict's scope carries the
    /// budget either way.
    #[cfg(any(feature = "rpc", feature = "cli"))]
    #[test]
    fn an_implausible_priority_fee_blocks_and_every_scope_states_the_budget() {
        use graphite_core::manifest::load_seed_manifests;
        use graphite_core::policy_engine::WalletProfile;
        use graphite_core::semantic_graph_store::BehaviorEvidence;
        use graphite_core::verification::{
            GraphiteCore, ProposedIntent, VerificationInput, VerificationScope,
        };
        let core = GraphiteCore::with_registry(load_seed_manifests());
        let run = |frame: Vec<u8>| {
            let mut data = vec![2u8, 0, 0, 0];
            data.extend_from_slice(&1u64.to_le_bytes());
            core.verify(&VerificationInput {
                proposed_intent: ProposedIntent {
                    intent_type: "transfer".to_string(),
                    raw_natural_language: "send 1 lamport".to_string(),
                    confidence_of_parse: 0.9,
                    extracted_parameters: None,
                },
                program_id: "11111111111111111111111111111111".to_string(),
                protocol_version: "1.0.0".to_string(),
                instruction_discriminator: "02000000".to_string(),
                account_addresses: vec![
                    bs58::encode([1u8; 32]).into_string(),
                    bs58::encode([2u8; 32]).into_string(),
                ],
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
            })
            .expect("verified")
        };
        // 1,400,000 compute units at 1,000,000,000 micro-lamports each:
        // 1.4e6 × 1e9 / 1e6 = 1.4e9 lamports, 1.4 SOL.
        let r = run(legacy(&[limit(1_400_000), price(1_000_000_000)]));
        assert_eq!(r.risk_verdict.status, "Blocked");
        assert!(r
            .risk_verdict
            .findings
            .iter()
            .any(|f| f.pattern == "ExcessivePriorityFee" && f.reason.contains("1400000000")));
        assert!(!r.approved);
        match &r.scope {
            VerificationScope::ArtifactBound { compute_budget, .. } => {
                assert_eq!(
                    compute_budget.as_ref().unwrap().priority_fee_lamports,
                    1_400_000_000
                )
            }
            other => panic!("{other:?}"),
        }
        // An ordinary fee is stated, not refused.
        let r = run(legacy(&[limit(200_000), price(10_000)]));
        assert!(!r
            .risk_verdict
            .findings
            .iter()
            .any(|f| f.pattern == "ExcessivePriorityFee"));
        match &r.scope {
            VerificationScope::ArtifactBound { compute_budget, .. } => {
                assert_eq!(
                    compute_budget.as_ref().unwrap().priority_fee_lamports,
                    2_000
                )
            }
            other => panic!("{other:?}"),
        }
    }
}

// ─── Structural checks read the bytes ──────────────────────────────────────

/// Round 21: two structural checks that refused executed mainnet traffic for
/// what an instruction's shape COULD mean, now read what its bytes say.
///
/// - A token CloseAccount whose destination is its own authority returns the
///   account's lamports to the wallet closing it — how every swap unwraps
///   SOL. Check 2 refused every CloseAccount (1,367 rows of the 2026-09-23
///   sample name one). A drain needs a destination that is not the
///   authority, and that still blocks.
/// - The drainer heuristic counted every account past the manifest's list;
///   with privileges from the bytes it counts the WRITABLE ones, since a
///   read-only account cannot lose anything.
#[cfg(any(feature = "rpc", feature = "cli"))]
mod structural_checks_read_the_bytes {
    use graphite_core::manifest::load_seed_manifests;
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::semantic_graph_store::BehaviorEvidence;
    use graphite_core::tx_pattern_analysis::TransactionInstruction;
    use graphite_core::verification::{
        GraphiteCore, ProposedIntent, VerificationInput, VerificationResult,
    };

    const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const WALLET: [u8; 32] = [81u8; 32];
    const WSOL_ACCOUNT: [u8; 32] = [82u8; 32];
    const ATTACKER: [u8; 32] = [83u8; 32];
    const SOURCE: [u8; 32] = [84u8; 32];
    const DEST: [u8; 32] = [85u8; 32];
    const MINT: [u8; 32] = [86u8; 32];

    fn b58(k: &[u8; 32]) -> String {
        bs58::encode(k).into_string()
    }
    fn token() -> [u8; 32] {
        bs58::decode(TOKEN).into_vec().unwrap().try_into().unwrap()
    }

    fn frame(keys: &[[u8; 32]], header: [u8; 3], ixs: &[(u8, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![header[0]];
        for _ in 0..header[0] {
            out.extend_from_slice(&[0u8; 64]);
        }
        out.extend_from_slice(&header);
        out.push(keys.len() as u8);
        for k in keys {
            out.extend_from_slice(k);
        }
        out.extend_from_slice(&[9u8; 32]);
        out.push(ixs.len() as u8);
        for (p, accs, data) in ixs {
            out.push(*p);
            out.push(accs.len() as u8);
            out.extend_from_slice(accs);
            out.push(data.len() as u8);
            out.extend_from_slice(data);
        }
        out
    }

    fn input(
        frame: Vec<u8>,
        disc: &str,
        data: Vec<u8>,
        accounts: Vec<String>,
        siblings: Vec<TransactionInstruction>,
    ) -> VerificationInput {
        VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "close".to_string(),
                raw_natural_language: "close my wrapped SOL account".to_string(),
                confidence_of_parse: 0.9,
                extracted_parameters: None,
            },
            program_id: TOKEN.to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: disc.to_string(),
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

    fn verify(i: VerificationInput) -> VerificationResult {
        GraphiteCore::with_registry(load_seed_manifests())
            .verify(&i)
            .expect("verified")
    }

    /// Blocked for the close by either check that judges one: Check 2's
    /// risky-instruction table, or Check 10's high-risk class with no intent
    /// (a sibling never carries an intent).
    fn close_blocked(r: &VerificationResult) -> bool {
        r.risk_verdict.findings.iter().any(|f| {
            f.reason.contains("CloseAccount") || f.reason.contains("high-risk class 'close'")
        })
    }

    /// keys [wallet (payer, signer), wsol account, attacker, token program]
    fn close(destination: u8) -> VerificationResult {
        let keys = [WALLET, WSOL_ACCOUNT, ATTACKER, token()];
        let accounts = [1u8, destination, 0];
        let f = frame(&keys, [1, 0, 1], &[(3, accounts.to_vec(), vec![9])]);
        let addrs = accounts.iter().map(|i| b58(&keys[*i as usize])).collect();
        verify(input(f, "09", vec![9], addrs, vec![]))
    }

    #[test]
    fn a_close_that_refunds_its_own_authority_is_not_a_drain() {
        let r = close(0);
        assert!(!close_blocked(&r), "{:?}", r.risk_verdict);
    }

    #[test]
    fn a_close_that_pays_someone_else_still_blocks() {
        let r = close(2);
        assert!(close_blocked(&r), "{:?}", r.risk_verdict);
        assert!(!r.approved);
    }

    fn transfer_data(amount: u64) -> Vec<u8> {
        let mut d = vec![12u8];
        d.extend_from_slice(&amount.to_le_bytes());
        d.push(9);
        d
    }

    /// A TransferChecked with a CloseAccount beside it, declared as a
    /// sibling: keys [wallet, source, dest, wsol, attacker, mint, program].
    fn transfer_then_closes(close_destinations: &[u8]) -> VerificationResult {
        let keys = [WALLET, SOURCE, DEST, WSOL_ACCOUNT, ATTACKER, MINT, token()];
        let data = transfer_data(1);
        let mut ixs = vec![(6u8, vec![1u8, 5, 2, 0], data.clone())];
        let mut siblings = Vec::new();
        for d in close_destinations {
            ixs.push((6u8, vec![3u8, *d, 0], vec![9]));
            siblings.push(TransactionInstruction {
                program_id: TOKEN.to_string(),
                instruction_discriminator: "09".to_string(),
                account_addresses: vec![b58(&WSOL_ACCOUNT), b58(&keys[*d as usize]), b58(&WALLET)],
                cpi_targets: vec![],
            });
        }
        let f = frame(&keys, [1, 0, 2], &ixs);
        verify(input(
            f,
            "0c",
            data,
            vec![b58(&SOURCE), b58(&MINT), b58(&DEST), b58(&WALLET)],
            siblings,
        ))
    }

    #[test]
    fn a_self_refunding_sibling_close_is_not_a_drain() {
        let r = transfer_then_closes(&[0]);
        assert!(!close_blocked(&r), "{:?}", r.risk_verdict);
    }

    #[test]
    fn one_draining_close_keeps_every_sibling_close_blocked() {
        let r = transfer_then_closes(&[4]);
        assert!(close_blocked(&r), "{:?}", r.risk_verdict);
        // A refunding close beside a draining one: the declaration of either
        // could be matched to either, so neither is exempt.
        let r = transfer_then_closes(&[0, 4]);
        assert!(close_blocked(&r), "{:?}", r.risk_verdict);
    }

    /// The exemption is the pipeline's word from the bytes, not the
    /// request's: a sibling DECLARED as refunding over a draining close in
    /// the bytes is still refused.
    #[test]
    fn a_declaration_cannot_claim_a_refund_the_bytes_do_not_show() {
        let keys = [WALLET, SOURCE, DEST, WSOL_ACCOUNT, ATTACKER, MINT, token()];
        let data = transfer_data(1);
        let f = frame(
            &keys,
            [1, 0, 2],
            &[
                (6, vec![1, 5, 2, 0], data.clone()),
                (6, vec![3, 4, 0], vec![9]),
            ],
        );
        let r = verify(input(
            f,
            "0c",
            data,
            vec![b58(&SOURCE), b58(&MINT), b58(&DEST), b58(&WALLET)],
            vec![TransactionInstruction {
                program_id: TOKEN.to_string(),
                instruction_discriminator: "09".to_string(),
                account_addresses: vec![b58(&WSOL_ACCOUNT), b58(&WALLET), b58(&WALLET)],
                cpi_targets: vec![],
            }],
        ));
        assert!(!r.approved);
        assert!(r.risk_verdict.status == "Blocked", "{:?}", r.risk_verdict);
    }

    /// TransferChecked (4 declared accounts) with `extra` more accounts
    /// appended, `writable` of them writable.
    fn transfer_with_extras(extra: u8, writable: u8) -> VerificationResult {
        let mut keys = vec![WALLET, SOURCE, DEST];
        let mut writable_extras = Vec::new();
        for i in 0..writable {
            writable_extras.push([100 + i; 32]);
        }
        keys.extend(writable_extras.iter().copied());
        let mut readonly = vec![MINT, token()];
        for i in 0..(extra - writable) {
            readonly.push([140 + i; 32]);
        }
        let first_readonly = keys.len() as u8;
        keys.extend(readonly.iter().copied());
        let program = first_readonly + 1;
        let mut accounts = vec![1u8, first_readonly, 2, 0];
        for i in 0..writable {
            accounts.push(3 + i);
        }
        for i in 0..(extra - writable) {
            accounts.push(first_readonly + 2 + i);
        }
        let data = transfer_data(1);
        let header = [1u8, 0, (keys.len() as u8) - first_readonly];
        let f = frame(&keys, header, &[(program, accounts.clone(), data.clone())]);
        let addrs = accounts.iter().map(|i| b58(&keys[*i as usize])).collect();
        verify(input(f, "0c", data, addrs, vec![]))
    }

    /// Either account-count heuristic: Check 3's ratio or Check 3b's
    /// STMT count.
    fn drainer(r: &VerificationResult) -> bool {
        r.risk_verdict
            .findings
            .iter()
            .any(|f| f.reason.contains("drainer pattern") || f.reason.contains("STMT drainer"))
    }

    #[test]
    fn read_only_remaining_accounts_are_not_account_proliferation() {
        let r = transfer_with_extras(8, 0);
        assert!(!drainer(&r), "{:?}", r.risk_verdict);
    }

    #[test]
    fn writable_remaining_accounts_still_are() {
        let r = transfer_with_extras(8, 3);
        assert!(drainer(&r), "{:?}", r.risk_verdict);
    }
}

// ─── Manifests that describe the programs as they run ──────────────────────

/// Round 21: manifest account lists grounded in the programs' own on-chain
/// IDLs AND in 16,414 executed mainnet instructions. Each pin below is a
/// list that refused real, successful transactions before this round.
mod manifests_match_the_programs {
    use graphite_core::account_resolution::{resolve_accounts, AccountResolutionInput};
    use graphite_core::manifest::load_seed_manifests;

    fn accounts(program: &str, disc: &str) -> Vec<(String, bool, bool)> {
        let r = load_seed_manifests();
        r.find_instruction(program, disc)
            .unwrap_or_else(|| panic!("{program} {disc}"))
            .accounts
            .iter()
            .map(|a| (a.name.clone(), a.is_signer, a.is_writable))
            .collect()
    }

    /// Pump.fun `sell` was three accounts with the seller first, as a
    /// signer; the program's IDL has fourteen with `global` first. Every
    /// executed sell was refused as "declared signer does not sign" (24 of
    /// 24 in the sample; 58 across buy/sell/v2).
    #[test]
    fn pump_fun_buy_and_sell_are_the_programs_layouts() {
        let pump = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
        let sell = accounts(pump, "33e685a4017f83ad");
        assert_eq!(sell.len(), 14);
        assert_eq!(sell[0], ("global".to_string(), false, false));
        assert_eq!(sell[6], ("user".to_string(), true, true));
        let buy = accounts(pump, "66063d1201daebea");
        assert_eq!(buy.len(), 16);
        assert_eq!(buy[6], ("user".to_string(), true, true));
    }

    /// Jupiter's v2 routes pinned `destination_token_program` to Token-2022
    /// alone and two token-account slots to program ids; the IDL has the
    /// token-program slots as interfaces over both token programs.
    #[test]
    fn jupiter_v2_routes_are_the_programs_layouts() {
        let r = load_seed_manifests();
        let jup = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
        let route = r.find_instruction(jup, "bb64facc31c4af14").unwrap();
        assert_eq!(route.accounts[5].name, "source_token_program");
        assert_eq!(route.accounts[6].name, "destination_token_program");
        for slot in [5, 6] {
            assert_eq!(route.accounts[slot].expected_address.len(), 2);
        }
        let shared = r.find_instruction(jup, "d19853937cfed8e9").unwrap();
        assert_eq!(shared.accounts.len(), 12);
        assert!(shared.accounts[3].expected_address.is_empty());
        assert!(shared.accounts[4].expected_address.is_empty());
    }

    /// The nonce account of AdvanceNonceAccount is writable, not a signer:
    /// 371 of 371 executed advances in the sample had it unsigned.
    #[test]
    fn a_nonce_account_is_not_a_signer() {
        let nonce = accounts("11111111111111111111111111111111", "04000000");
        assert_eq!(nonce[0], ("nonce".to_string(), false, true));
        assert!(nonce[2].1, "the authority signs");
    }

    /// Raydium AMM v4 swaps take 18 accounts or 17 (without
    /// `amm_target_orders`); with one layout, every account after the gap
    /// was judged against the wrong slot. A 17-account swap now resolves
    /// against the 17-account layout.
    #[test]
    fn a_17_account_raydium_swap_resolves_against_its_own_layout() {
        let registry = load_seed_manifests();
        let keys: Vec<String> = (0..17u8)
            .map(|i| bs58::encode([i + 1; 32]).into_string())
            .collect();
        let mut keys = keys;
        keys[0] = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string();
        let r = resolve_accounts(
            &AccountResolutionInput {
                program_id: "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8".to_string(),
                instruction_discriminator: "09".to_string(),
                account_addresses: keys.clone(),
                instruction_data: Some(vec![9u8; 17]),
                real_account_metas: vec![],
                fee_payer: None,
            },
            &registry,
        )
        .expect("resolves");
        assert_eq!(r.account_count_shortfall, None);
        assert_eq!(r.resolved_accounts[4].role, "writable");
        let ix = registry
            .find_instruction("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", "09")
            .unwrap();
        let layout = ix.layout_for(17);
        assert_eq!(layout[4].name, "pool_coin_token_account");
        assert_eq!(layout[16].name, "user_owner");
        assert_eq!(ix.layout_for(18)[4].name, "amm_target_orders");
        // A count matching no layout is judged against the primary one.
        assert_eq!(ix.layout_for(20).len(), 18);
    }

    /// Two layouts of one length would make the choice arbitrary: refused
    /// at load.
    #[test]
    fn two_layouts_of_one_length_are_refused() {
        let json = r#"{
            "graphite_manifest_version": "1.0",
            "protocol": {"name": "t", "program_id": "Stake11111111111111111111111111111111111111"},
            "version": {"label": "1", "effective_from_slot": 0, "previous_version_ref": null},
            "instructions": [{
                "name": "x", "discriminator": "01",
                "accounts": [{"name": "a", "role": "readonly", "is_writable": false, "is_signer": false, "pda_seeds": []}],
                "account_layouts": [[{"name": "b", "role": "readonly", "is_writable": false, "is_signer": false, "pda_seeds": []}]],
                "expected_state_changes": [], "allowed_cpis": [], "risk_rules": []
            }],
            "trust_tier": "HeuristicInferred"
        }"#;
        let mut r = graphite_core::manifest::ManifestRegistry::new();
        let err = r.load_from_json(json).expect_err("same-length layouts");
        assert!(format!("{err}").contains("same length"), "{err}");
    }
}
