//! Token-2022 is an extension system, and Graphite decodes a base layout.
//!
//! The base 165-byte account layout is shared by Token and Token-2022: mint,
//! owner, amount, delegate, state, close authority. Graphite reads it well. An
//! extension can change what a transfer DOES without changing any of those
//! fields — a fee takes a cut, a hook runs arbitrary code, a permanent delegate
//! moves the balance, a non-transferable flag forbids the transfer outright.
//!
//! "The balances moved as described" is then a statement about arithmetic, not
//! about behaviour, and presenting it as a verified transfer would be exactly
//! the bytes-understood-is-not-behaviour-understood conflation this codebase
//! exists to refuse.
//!
//! So extensions are DETECTED, NAMED and CLASSIFIED here — never modelled.
//! Nothing in this file claims to know what a transfer hook will do. It claims
//! one is attached, which is a fact, and that Graphite cannot say what it does,
//! which is also a fact.
//!
//! Classification, from `ExtensionImpact`:
//!
//! | Class                     | Treatment |
//! |---------------------------|-----------|
//! | `AltersTransferSemantics` | BLOCKS — the effects cannot be presented as verified |
//! | `Unknown`                 | BLOCKS — an extension nobody here has heard of is not evidence of safety |
//! | `AltersAuthority`         | BLOCKS, same reasoning: a permanent delegate can move the balance later |
//! | `Informational`           | Reported, does not block |

use graphite_core::state_diff::{
    detect_token2022_extensions, AccountSnapshot, DetectedExtension, ExtensionImpact, ExtensionScan,
};

#[allow(dead_code)]
fn _scan_type_is_exported(_: ExtensionScan) {}

const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const MINT: &str = "So11111111111111111111111111111111111111112";
const OWNER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";

/// A base token account: initialized, 165 bytes, with the given amount.
fn base_account(amount: u64) -> Vec<u8> {
    let mut data = vec![0u8; 165];
    data[0..32].copy_from_slice(&bs58::decode(MINT).into_vec().unwrap());
    data[32..64].copy_from_slice(&bs58::decode(OWNER).into_vec().unwrap());
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    data[108] = 1; // initialized
    data
}

/// A Token-2022 account carrying the given extensions as TLV.
fn with_extensions(amount: u64, extensions: &[(u16, usize)]) -> Vec<u8> {
    let mut data = base_account(amount);
    data.push(2); // account type: Account
    for &(discriminant, len) in extensions {
        data.extend_from_slice(&discriminant.to_le_bytes());
        data.extend_from_slice(&(len as u16).to_le_bytes());
        data.extend(std::iter::repeat_n(0u8, len));
    }
    data
}

fn names(found: &[DetectedExtension]) -> Vec<String> {
    found.iter().map(|e| e.name.clone()).collect()
}

/// A plain account has no extensions, and that is reported as "none found"
/// rather than as an error.
#[test]
fn a_base_account_carries_no_extensions() {
    assert!(detect_token2022_extensions(&base_account(1000)).is_clean());
    // Even with the type byte and nothing after it.
    let mut typed = base_account(1000);
    typed.push(2);
    assert!(detect_token2022_extensions(&typed).is_clean());
}

/// The extensions that can redirect or block value are recognised by name.
#[test]
fn semantics_altering_extensions_are_named_and_classified() {
    for (discriminant, expected) in [
        (1u16, "TransferFeeConfig"),
        (2, "TransferFeeAmount"),
        (4, "ConfidentialTransferMint"),
        (5, "ConfidentialTransferAccount"),
        (6, "DefaultAccountState"),
        (9, "NonTransferable"),
        (13, "NonTransferableAccount"),
        (14, "TransferHook"),
        (15, "TransferHookAccount"),
    ] {
        let found = detect_token2022_extensions(&with_extensions(1000, &[(discriminant, 8)])).found;
        assert_eq!(found.len(), 1, "discriminant {discriminant}");
        assert_eq!(found[0].name, expected);
        assert_eq!(
            found[0].impact,
            ExtensionImpact::AltersTransferSemantics,
            "{expected} can change what a transfer does and must be classified as such"
        );
    }
}

/// Authority-altering extensions are their own class.
#[test]
fn authority_altering_extensions_are_classified_separately() {
    for (discriminant, expected) in [(3u16, "MintCloseAuthority"), (12, "PermanentDelegate")] {
        let found =
            detect_token2022_extensions(&with_extensions(1000, &[(discriminant, 32)])).found;
        assert_eq!(found[0].name, expected);
        assert_eq!(found[0].impact, ExtensionImpact::AltersAuthority);
    }
}

/// Extensions that do not redirect value are reported without being treated as
/// if they did.
///
/// `ImmutableOwner` in particular is on essentially every Token-2022 associated
/// token account. Classifying it as dangerous would block ordinary traffic and
/// teach operators to ignore the finding.
#[test]
fn informational_extensions_are_reported_without_alarm() {
    for (discriminant, expected) in [
        (7u16, "ImmutableOwner"),
        (8, "MemoTransfer"),
        (10, "InterestBearingConfig"),
        (11, "CpiGuard"),
        (18, "MetadataPointer"),
        (19, "TokenMetadata"),
    ] {
        let found = detect_token2022_extensions(&with_extensions(1000, &[(discriminant, 4)])).found;
        assert_eq!(found[0].name, expected);
        assert_eq!(found[0].impact, ExtensionImpact::Informational);
    }
}

/// An unrecognised discriminant is reported by number, not skipped.
///
/// The set grows. A build that silently ignored what it did not recognise would
/// get quieter as Token-2022 got richer, which is the wrong direction.
#[test]
fn an_unrecognised_extension_is_reported_rather_than_ignored() {
    let found = detect_token2022_extensions(&with_extensions(1000, &[(4242, 16)])).found;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].discriminant, 4242);
    assert!(
        found[0].name.contains("4242") && found[0].name.contains("not named by this build"),
        "the report must say which number it saw and that it does not know it: {}",
        found[0].name
    );
    assert_eq!(found[0].impact, ExtensionImpact::Unknown);
}

/// Several extensions on one account are all found, in order.
#[test]
fn multiple_extensions_are_all_detected() {
    let found = detect_token2022_extensions(&with_extensions(
        1000,
        &[(7, 0), (2, 8), (14, 32), (19, 12)],
    ))
    .found;
    assert_eq!(
        names(&found),
        vec![
            "ImmutableOwner",
            "TransferFeeAmount",
            "TransferHook",
            "TokenMetadata"
        ]
    );
}

/// A malformed TLV stops the walk, keeps what was read, and SAYS it stopped.
#[test]
fn a_length_running_past_the_buffer_stops_the_walk_and_says_so() {
    let mut data = with_extensions(1000, &[(7, 0)]);
    // A second entry claiming 60000 bytes that are not there.
    data.extend_from_slice(&14u16.to_le_bytes());
    data.extend_from_slice(&60000u16.to_le_bytes());
    let scan = detect_token2022_extensions(&data);
    assert_eq!(
        names(&scan.found),
        vec!["ImmutableOwner"],
        "the readable entry is kept and the malformed one is not guessed at"
    );
    assert!(!scan.is_clean());
    let why = scan
        .malformed
        .expect("the walk stopped early and must say so");
    assert!(
        why.contains("type 14") && why.contains("60000"),
        "the reason must name what was unreadable: {why}"
    );
}

/// R7-01: a malformed FIRST entry must not look like "no extensions".
///
/// This is the fail-open the scan type exists to close. Before it, the walk
/// stopped at the corrupt length, returned an empty list, and the state-diff
/// check read an empty list as an account with nothing attached — so a
/// transfer hook behind a bad length byte produced no finding at all.
#[test]
fn a_malformed_first_entry_is_distinguishable_from_no_extensions() {
    let mut data = base_account(1000);
    data.push(2);
    data.extend_from_slice(&14u16.to_le_bytes()); // TransferHook...
    data.extend_from_slice(&60000u16.to_le_bytes()); // ...behind a corrupt length

    let corrupt = detect_token2022_extensions(&data);
    let mut plain = base_account(1000);
    plain.push(2);
    let none = detect_token2022_extensions(&plain);

    assert!(none.is_clean());
    assert!(!corrupt.is_clean(), "unreadable is not the same as empty");
    assert!(corrupt.found.is_empty(), "nothing was read cleanly");
    assert!(corrupt.malformed.is_some());
    assert_ne!(corrupt, none);
}

/// Trailing bytes too short to be a header are reported, not ignored.
#[test]
fn trailing_bytes_shorter_than_a_header_are_reported() {
    let mut data = with_extensions(1000, &[(7, 0)]);
    data.extend_from_slice(&[0x0e, 0x00, 0x20]); // three of the four header bytes
    let scan = detect_token2022_extensions(&data);
    assert_eq!(names(&scan.found), vec!["ImmutableOwner"]);
    assert!(
        scan.malformed.as_deref().unwrap_or("").contains("trailing"),
        "{:?}",
        scan.malformed
    );
}

/// A type byte that is neither Account nor Mint on data long enough to carry a
/// TLV region is reported as unreadable, not read as nothing.
#[test]
fn an_unknown_account_type_byte_is_reported() {
    let mut data = base_account(1000);
    data.push(9); // not Account (2), not Mint (1)
    data.extend_from_slice(&[0x0e, 0x00, 0x00, 0x00]);
    let scan = detect_token2022_extensions(&data);
    assert!(scan.found.is_empty());
    assert!(
        scan.malformed
            .as_deref()
            .unwrap_or("")
            .contains("type byte 9"),
        "{:?}",
        scan.malformed
    );
}

/// Duplicate extensions are both reported. Whether the program permits them is
/// its business; Graphite reports what is there.
#[test]
fn duplicate_extensions_are_all_reported() {
    let scan = detect_token2022_extensions(&with_extensions(1000, &[(14, 32), (14, 32)]));
    assert_eq!(names(&scan.found), vec!["TransferHook", "TransferHook"]);
    assert!(scan.malformed.is_none());
}

/// Every discriminant the build names, checked against the spl-token-2022
/// `ExtensionType` order, so a renumbering upstream fails here rather than
/// mislabelling a hook as metadata.
#[test]
fn every_named_discriminant_has_the_expected_classification() {
    use ExtensionImpact::*;
    let table: &[(u16, &str, ExtensionImpact)] = &[
        (1, "TransferFeeConfig", AltersTransferSemantics),
        (2, "TransferFeeAmount", AltersTransferSemantics),
        (3, "MintCloseAuthority", AltersAuthority),
        (4, "ConfidentialTransferMint", AltersTransferSemantics),
        (5, "ConfidentialTransferAccount", AltersTransferSemantics),
        (6, "DefaultAccountState", AltersTransferSemantics),
        (7, "ImmutableOwner", Informational),
        (8, "MemoTransfer", Informational),
        (9, "NonTransferable", AltersTransferSemantics),
        (10, "InterestBearingConfig", Informational),
        (11, "CpiGuard", Informational),
        (12, "PermanentDelegate", AltersAuthority),
        (13, "NonTransferableAccount", AltersTransferSemantics),
        (14, "TransferHook", AltersTransferSemantics),
        (15, "TransferHookAccount", AltersTransferSemantics),
        (16, "ConfidentialTransferFeeConfig", AltersTransferSemantics),
        (17, "ConfidentialTransferFeeAmount", AltersTransferSemantics),
        (18, "MetadataPointer", Informational),
        (19, "TokenMetadata", Informational),
        (20, "GroupPointer", Informational),
        (21, "TokenGroup", Informational),
        (22, "GroupMemberPointer", Informational),
        (23, "TokenGroupMember", Informational),
    ];
    for &(d, name, impact) in table {
        let scan = detect_token2022_extensions(&with_extensions(1, &[(d, 4)]));
        assert_eq!(scan.found.len(), 1, "discriminant {d}");
        assert_eq!(scan.found[0].name, name, "discriminant {d}");
        assert_eq!(scan.found[0].impact, impact, "discriminant {d}");
    }
    // And the one past the table is Unknown, which blocks.
    let scan = detect_token2022_extensions(&with_extensions(1, &[(24, 4)]));
    assert_eq!(scan.found[0].impact, Unknown);
}

/// Classic SPL Token has no extension region, and none is invented for it.
///
/// The bytes after a 165-byte classic account are not TLV, and reading them as
/// TLV would manufacture findings against the most common token program there
/// is.
#[test]
fn classic_spl_token_accounts_are_never_scanned_for_extensions() {
    let mut data = base_account(1000);
    data.push(2);
    data.extend_from_slice(&14u16.to_le_bytes()); // would read as TransferHook
    data.extend_from_slice(&0u16.to_le_bytes());

    let classic = AccountSnapshot::from_raw("acct", 1_000_000, SPL_TOKEN, &data);
    assert!(
        classic.extensions.is_clean(),
        "a classic SPL Token account has no TLV region to read"
    );

    let t22 = AccountSnapshot::from_raw("acct", 1_000_000, TOKEN_2022, &data);
    assert_eq!(names(&t22.extensions.found), vec!["TransferHook"]);
}

/// A snapshot of a Token-2022 account carries its extensions.
#[test]
fn snapshots_carry_the_extensions_they_found() {
    let snap = AccountSnapshot::from_raw(
        "acct",
        1_000_000,
        TOKEN_2022,
        &with_extensions(5_000, &[(2, 8), (14, 32)]),
    );
    assert!(snap.token.is_some(), "the base layout still decodes");
    assert_eq!(snap.token.as_ref().unwrap().amount, 5_000);
    assert_eq!(
        names(&snap.extensions.found),
        vec!["TransferFeeAmount", "TransferHook"]
    );
}

/// The base decode is unaffected by the extension region.
///
/// Anti-vacuity in the other direction: if detecting extensions had broken the
/// base decode, every token check downstream would silently stop working while
/// these tests passed.
#[test]
fn the_base_layout_still_decodes_beneath_the_extensions() {
    let plain = AccountSnapshot::from_raw("a", 1, TOKEN_2022, &base_account(777));
    let extended = AccountSnapshot::from_raw(
        "a",
        1,
        TOKEN_2022,
        &with_extensions(777, &[(7, 0), (14, 32)]),
    );
    assert_eq!(
        plain.token.as_ref().map(|t| t.amount),
        extended.token.as_ref().map(|t| t.amount)
    );
    assert_eq!(
        plain.token.as_ref().map(|t| t.owner.clone()),
        extended.token.as_ref().map(|t| t.owner.clone())
    );
    assert!(plain.extensions.is_clean());
    assert_eq!(extended.extensions.found.len(), 2);
}
