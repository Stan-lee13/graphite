//! R30 (former MEDIUM 11, re-tested): Token-2022 authority-bearing extensions
//! that are malformed, duplicated or unknown, on EITHER side of the diff.
//! Round 29 made both sides scanned; these are the shapes its tests did not
//! cover — a duplicate entry (which no exact reading can resolve), an
//! undecodable authority on the PRE-state only, and an unknown extension that
//! the transaction stripped.

use graphite_core::account_resolution::{AccountIdentity, ResolvedAccount};
use graphite_core::state_diff::{
    check_state_diff, AccountDelta, AccountSnapshot, DiffProvenance, DiffSeverity, StateDiff,
    StateDiffCheck, StateDiffReport,
};

const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const MINT: &str = "Mint111111111111111111111111111111111111111";
const PERMANENT_DELEGATE: u16 = 12;
const METADATA_POINTER: u16 = 18;

fn resolved(address: &str, name: &str) -> ResolvedAccount {
    ResolvedAccount {
        address: address.to_string(),
        role: "account".to_string(),
        name: name.to_string(),
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

/// A Token-2022 mint: an initialized 82-byte base padded to 165, the Mint
/// account type, then the TLV entries given. `supply` varies the base so a
/// side's data can change without touching its extensions.
fn t22_mint(supply: u64, extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[36..44].copy_from_slice(&supply.to_le_bytes());
    d[44] = 6;
    d[45] = 1;
    d.push(1);
    for (ty, value) in extensions {
        d.extend_from_slice(&ty.to_le_bytes());
        d.extend_from_slice(&(value.len() as u16).to_le_bytes());
        d.extend_from_slice(value);
    }
    d
}

fn report(before: &[u8], after: &[u8], executed_known: bool) -> StateDiffReport {
    let diff = StateDiff {
        deltas: vec![AccountDelta {
            pubkey: MINT.to_string(),
            before: Some(AccountSnapshot::from_raw(MINT, 5_000_000, TOKEN_2022, before)),
            after: Some(AccountSnapshot::from_raw(MINT, 5_000_000, TOKEN_2022, after)),
        }],
        provenance: DiffProvenance::RpcSimulated,
        token2022_executed: executed_known.then(Vec::new),
        ..Default::default()
    };
    let declared = vec!["debit source, credit dest".to_string()];
    check_state_diff(&StateDiffCheck {
        diff: &diff,
        resolved_accounts: &[resolved(MINT, "mint")],
        privileges_grounded: true,
        expected_state_changes: &declared,
        fee_payer: None,
    })
}

fn critical(r: &StateDiffReport, code: &str) -> bool {
    r.findings
        .iter()
        .any(|f| f.code == code && f.severity == DiffSeverity::Critical)
}

/// Control: one permanent delegate, unchanged, with the executed instructions
/// known to have exercised nothing — inert, reported, not blocked.
#[test]
fn control_a_single_unchanged_permanent_delegate_is_inert() {
    let m = t22_mint(1_000, &[(PERMANENT_DELEGATE, vec![9u8; 32])]);
    let r = report(&m, &m, true);
    assert!(!r.blocked, "{:?}", r.findings);
}

/// The same delegate written twice: which one the program would read is not
/// something Graphite can establish, so it is never inert.
#[test]
fn a_duplicated_permanent_delegate_is_never_inert() {
    let m = t22_mint(
        1_000,
        &[
            (PERMANENT_DELEGATE, vec![9u8; 32]),
            (PERMANENT_DELEGATE, vec![7u8; 32]),
        ],
    );
    let r = report(&m, &m, true);
    assert!(r.blocked, "{:?}", r.findings);
    assert!(critical(&r, "Token2022ExtensionNotModelled"), "{:?}", r.findings);
}

/// Duplicated, and the mint's data changed: the authorities cannot be compared.
#[test]
fn a_duplicated_authority_on_a_changed_mint_is_unreadable() {
    let ext = [
        (PERMANENT_DELEGATE, vec![9u8; 32]),
        (PERMANENT_DELEGATE, vec![7u8; 32]),
    ];
    let r = report(&t22_mint(1_000, &ext), &t22_mint(2_000, &ext), true);
    assert!(critical(&r, "Token2022AuthoritiesUnreadable"), "{:?}", r.findings);
}

/// An authority-bearing extension that does not decode BEFORE the
/// transaction, and does after: the comparison has one side, which is none.
#[test]
fn an_authority_undecodable_only_before_is_a_finding() {
    let before = t22_mint(1_000, &[(METADATA_POINTER, vec![66u8; 31])]);
    let after = t22_mint(1_000, &[(METADATA_POINTER, vec![3u8; 64])]);
    let r = report(&before, &after, true);
    let f = r
        .findings
        .iter()
        .find(|f| f.code == "Token2022AuthoritiesUnreadable")
        .unwrap_or_else(|| panic!("{:?}", r.findings));
    assert_eq!(f.severity, DiffSeverity::Critical);
    assert!(f.detail.contains("before"), "{}", f.detail);
}

/// An extension this build does not know, present only on the pre-state: the
/// transaction stripped something Graphite cannot name.
#[test]
fn an_unknown_extension_the_transaction_removed_is_judged() {
    let before = t22_mint(1_000, &[(250, vec![1u8; 8])]);
    let after = t22_mint(1_000, &[]);
    let r = report(&before, &after, true);
    assert!(critical(&r, "Token2022ExtensionNotModelled"), "{:?}", r.findings);
}
