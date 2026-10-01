//! A2-03 (2026-09-29 audit): a Token-2022 transfer under a mint Graphite never
//! read is not certified free of a permanent delegate.
//!
//! A permanent delegate lives on the mint and leaves no mark on the token
//! account. `transfer_fee_mints_to_fetch` fetched only the mints of accounts
//! carrying an account-side extension, so a plain 165-byte Token-2022
//! account's mint was never read, and a `TransferChecked` out of it signed by
//! the mint's permanent delegate came out of L4 clean.
//!
//! The fix has two parts. The pipeline fetches the mint of every Token-2022
//! token account in the diff. And a transfer whose mint could not be read,
//! under an authority not shown to be the source's owner or its ordinary
//! delegate, is `Token2022MintUnread`, which is Critical.
//!
//! The test builds that diff with `token2022_mints` empty, as for a mint that
//! was not read, and pins that L4 blocks.

use graphite_core::account_resolution::{AccountIdentity, ResolvedAccount};
use graphite_core::state_diff::{
    check_state_diff, AccountDelta, AccountSnapshot, DiffProvenance, ExecutedTokenInstruction,
    StateDiff, StateDiffCheck, SPL_TOKEN_2022_PROGRAM,
};

const SIGNER: &str = "7vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const SOURCE: &str = "So1rceTokens1111111111111111111111111111111";
const DEST: &str = "6bSsP4p6wXqFJdD2TkYgNcVmLzHfWq7pRyA8tCzE5nBj";

fn b58(bytes: [u8; 32]) -> String {
    bs58::encode(bytes).into_string()
}

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

/// A Token-2022 token account with NO extensions: exactly 165 bytes.
fn t22_account(mint: [u8; 32], owner: [u8; 32], amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(&mint);
    d[32..64].copy_from_slice(&owner);
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    d
}

#[test]
fn a_token2022_transfer_under_an_unread_mint_is_not_certified() {
    let mint = [0x44u8; 32];
    let permanent_delegate = [0x99u8; 32];
    let user = [0x01u8; 32];
    let snap = |k: &str, owner: [u8; 32], amount: u64| {
        AccountSnapshot::from_raw(
            k,
            2_074_080,
            SPL_TOKEN_2022_PROGRAM,
            &t22_account(mint, owner, amount),
        )
    };
    let mut data = vec![12u8]; // TransferChecked
    data.extend_from_slice(&1_000u64.to_le_bytes());
    data.push(6);
    let diff = StateDiff {
        deltas: vec![
            AccountDelta {
                pubkey: SOURCE.to_string(),
                before: Some(snap(SOURCE, user, 1_000)),
                after: Some(snap(SOURCE, user, 0)),
            },
            AccountDelta {
                pubkey: DEST.to_string(),
                before: Some(snap(DEST, permanent_delegate, 0)),
                after: Some(snap(DEST, permanent_delegate, 1_000)),
            },
        ],
        provenance: DiffProvenance::RpcSimulated,
        fee_lamports: 5_000,
        covers_all_writable: false,
        artifact_balance_writes: None,
        artifact_account_universe: None,
        artifact_accounts_undescribed: Some(vec![]),
        transfer_fee_mints: Default::default(),
        token2022_executed: Some(vec![ExecutedTokenInstruction {
            position: "a CPI under instruction #0".to_string(),
            accounts: vec![
                SOURCE.to_string(),
                b58(mint),
                DEST.to_string(),
                b58(permanent_delegate), // authority = the mint's permanent delegate
            ],
            data,
        }]),
        fee_epoch: None,
        // No entry for the mint: it was not read.
        token2022_mints: Default::default(),
        transaction_accounts: None,
        transaction_privileges: None,
    };
    let accts = vec![
        account(SIGNER, true, true),
        account(SOURCE, false, true),
        account(DEST, false, true),
    ];
    let prose = vec![
        "debits accounts.source token balance by data.amount".to_string(),
        "credits accounts.destination token balance by data.amount".to_string(),
    ];
    let report = check_state_diff(&StateDiffCheck {
        diff: &diff,
        resolved_accounts: &accts,
        privileges_grounded: true,
        expected_state_changes: &prose,
        fee_payer: Some(SIGNER),
    });
    let criticals: Vec<String> = report.criticals().map(|f| f.code.clone()).collect();
    assert!(
        report.blocked,
        "an executed Token-2022 transfer whose mint was never read was certified; the authority \
         may be the mint's permanent delegate. criticals: {criticals:?}"
    );
}
