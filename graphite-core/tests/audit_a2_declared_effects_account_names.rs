//! A2-01 (2026-09-29 audit): account names in a manifest are not declared
//! effects.
//!
//! `DeclaredEffects::parse` substring-matched every `expected_state_changes`
//! string, including the generated line
//! `modifies writable accounts: pool, owner, lpmint, ...`. An account named
//! `owner` or `authority` switched off the owner, delegate, close-authority,
//! SPL-authority, mint-authority and freeze-authority detectors for every
//! account in the transaction; one named `lpmint` switched off
//! `UndeclaredMint`, and one named `payer` read as a debit. Across the shipped
//! manifests that was 417 instructions for authority, 232 for mint and 133 for
//! debit.
//!
//! The fix rebuilds the parse as scoped declarations. Effect words match on
//! word boundaries; the `modifies writable accounts:` list is an enumeration
//! of names and declares nothing; an effect stated about `accounts.<name>`
//! applies to that account only (`DeclaredEffects::covers`), and
//! `check_state_diff` maps each delta's pubkey to its account names. A change
//! on an account the declaration does not name stays Critical.
//!
//! The tests pin each face: a writable account named `owner`, `lpmint` or
//! `payer` declares nothing, and an owner change declared for one account
//! (InitializeAccount3's) does not excuse a takeover of another. The
//! `*_control` test shows the same diff is blocked without the name list, so
//! the fixture is not vacuous.

use graphite_core::account_resolution::{AccountIdentity, ResolvedAccount};
use graphite_core::state_diff::{
    check_state_diff, AccountDelta, AccountSnapshot, DiffProvenance, StateDiff, StateDiffCheck,
    SPL_TOKEN_PROGRAM,
};

const SOURCE: &str = "So1rceTokens1111111111111111111111111111111";
const OWNER_SIGNER: &str = "Wner11111111111111111111111111111111111111111";
const POOL: &str = "Poo11111111111111111111111111111111111111111";
const LP_MINT: &str = "LpMint11111111111111111111111111111111111111";
const NEW_ACCOUNT: &str = "NewAcct111111111111111111111111111111111111";

fn account(address: &str, role: &str, signer: bool, writable: bool) -> ResolvedAccount {
    ResolvedAccount {
        address: address.to_string(),
        role: role.to_string(),
        name: role.to_string(),
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

fn token_account(owner: [u8; 32], amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(&[7u8; 32]); // mint
    d[32..64].copy_from_slice(&owner); // SPL authority
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1; // initialized
    d
}

fn mint_account(supply: u64) -> Vec<u8> {
    let mut d = vec![0u8; 82];
    d[0..4].copy_from_slice(&1u32.to_le_bytes());
    d[4..36].copy_from_slice(&[5u8; 32]); // mint authority
    d[36..44].copy_from_slice(&supply.to_le_bytes());
    d[44] = 6;
    d[45] = 1;
    d
}

fn diff(deltas: Vec<AccountDelta>) -> StateDiff {
    StateDiff {
        deltas,
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

/// The source token account is debited (declared) AND handed to an attacker
/// (never declared): SPL authority [1;32] -> [0xAA;32].
fn takeover_diff() -> StateDiff {
    let before = AccountSnapshot::from_raw(
        SOURCE,
        2_039_280,
        SPL_TOKEN_PROGRAM,
        &token_account([1u8; 32], 1_000),
    );
    let after = AccountSnapshot::from_raw(
        SOURCE,
        2_039_280,
        SPL_TOKEN_PROGRAM,
        &token_account([0xAAu8; 32], 900),
    );
    diff(vec![AccountDelta {
        pubkey: SOURCE.to_string(),
        before: Some(before),
        after: Some(after),
    }])
}

fn accounts() -> Vec<ResolvedAccount> {
    vec![
        account(POOL, "pool", false, true),
        account(OWNER_SIGNER, "owner", true, true),
        account(SOURCE, "sourcetokens", false, true),
        account(LP_MINT, "lpmint", false, true),
        // The account an InitializeAccount3 would name `accounts.account`: a
        // different account from SOURCE.
        account(NEW_ACCOUNT, "account", false, true),
    ]
}

fn codes(expected: &[String], d: &StateDiff) -> (bool, Vec<String>) {
    let accts = accounts();
    let report = check_state_diff(&StateDiffCheck {
        diff: d,
        resolved_accounts: &accts,
        privileges_grounded: true,
        expected_state_changes: expected,
        fee_payer: Some(OWNER_SIGNER),
    });
    (
        report.blocked,
        report.criticals().map(|f| f.code.clone()).collect(),
    )
}

/// Prose shape of the shipped manifest `amm-eo7wjk::lock`.
fn lock_prose() -> Vec<String> {
    vec![
        "modifies writable accounts: pool, lockescrow, owner, sourcetokens, escrowvault"
            .to_string(),
        "transfers funds between the protocol and the involved accounts".to_string(),
    ]
}

#[test]
fn a_writable_account_named_owner_does_not_declare_an_authority_change() {
    let (blocked, criticals) = codes(&lock_prose(), &takeover_diff());
    assert!(
        blocked
            && criticals
                .iter()
                .any(|c| c == "UndeclaredTokenAuthorityChange"),
        "the token account changed hands under a manifest that declares only a fund transfer; \
         an account NAMED `owner` must not excuse it. criticals: {criticals:?}"
    );
}

#[test]
fn a_writable_account_named_owner_does_not_declare_an_authority_change_control() {
    // Same diff, same verb line, no name list: blocked.
    let prose = vec!["transfers funds between the protocol and the involved accounts".to_string()];
    let (blocked, criticals) = codes(&prose, &takeover_diff());
    assert!(blocked, "{criticals:?}");
    assert!(criticals
        .iter()
        .any(|c| c == "UndeclaredTokenAuthorityChange"));
}

fn mint_inflation_diff() -> StateDiff {
    let before =
        AccountSnapshot::from_raw(LP_MINT, 1_461_600, SPL_TOKEN_PROGRAM, &mint_account(1_000));
    let after = AccountSnapshot::from_raw(
        LP_MINT,
        1_461_600,
        SPL_TOKEN_PROGRAM,
        &mint_account(1_000_000_000),
    );
    diff(vec![AccountDelta {
        pubkey: LP_MINT.to_string(),
        before: Some(before),
        after: Some(after),
    }])
}

#[test]
fn a_writable_account_named_lpmint_does_not_declare_a_mint() {
    let prose = vec![
        "modifies writable accounts: pool, lpmint, owner".to_string(),
        "transfers funds between the protocol and the involved accounts".to_string(),
    ];
    let (blocked, criticals) = codes(&prose, &mint_inflation_diff());
    assert!(
        blocked && criticals.iter().any(|c| c == "UndeclaredMint"),
        "supply rose 1,000,000x under a manifest that declares a transfer; an account NAMED \
         `lpmint` must not declare minting. criticals: {criticals:?}"
    );
}

/// Second face: SPL Token InitializeAccount3's prose legitimately declares
/// setting the NEW account's owner. It must not excuse a change of authority
/// on a different, pre-existing account in the same transaction.
#[test]
fn a_declared_owner_on_one_account_does_not_excuse_a_takeover_of_another() {
    let prose = vec![
        "initializes accounts.account token balance to 0".to_string(),
        "sets accounts.account owner to the owner in the instruction data".to_string(),
    ];
    let (blocked, criticals) = codes(&prose, &takeover_diff());
    assert!(
        blocked
            && criticals
                .iter()
                .any(|c| c == "UndeclaredTokenAuthorityChange"),
        "InitializeAccount3 declares the owner of accounts.account, not of every account in the \
         transaction. criticals: {criticals:?}"
    );
}

/// Debit flag from a name: an admin/config instruction whose writable
/// accounts include one NAMED `payer` (bridge-cards::update_admin shape)
/// declares no debit, so a token debit under it must block.
#[test]
fn a_writable_account_named_payer_does_not_declare_a_debit() {
    let prose = vec![
        "modifies writable accounts: payer, state".to_string(),
        "updates protocol configuration or authority".to_string(),
    ];
    let before = AccountSnapshot::from_raw(
        SOURCE,
        2_039_280,
        SPL_TOKEN_PROGRAM,
        &token_account([1u8; 32], 1_000),
    );
    let after = AccountSnapshot::from_raw(
        SOURCE,
        2_039_280,
        SPL_TOKEN_PROGRAM,
        &token_account([1u8; 32], 0),
    );
    let d = diff(vec![AccountDelta {
        pubkey: SOURCE.to_string(),
        before: Some(before),
        after: Some(after),
    }]);
    let (blocked, criticals) = codes(&prose, &d);
    assert!(
        blocked && criticals.iter().any(|c| c == "UndeclaredTokenDebit"),
        "a config update drained 1,000 tokens; an account NAMED `payer` must not declare a debit. \
         criticals: {criticals:?}"
    );
}
