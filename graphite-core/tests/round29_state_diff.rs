//! Round 29 (audit 2026-10-20): the state-diff findings F1–F8.
//!
//! Each test states the shape the audit found, and fails on the code as it
//! stood before the fix.

use graphite_core::account_resolution::{AccountIdentity, ResolvedAccount};
use graphite_core::state_diff::{
    check_state_diff, decode_mint, decode_token2022_powers, decode_token_account,
    detect_token2022_extensions, AccountDelta, AccountSnapshot, DiffProvenance, DiffSeverity,
    StateDiff, StateDiffCheck, StateDiffReport,
};

const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const SYSTEM: &str = "11111111111111111111111111111111";
const VOTE: &str = "Vote111111111111111111111111111111111111111";

const ACCOUNT: &str = "Acct111111111111111111111111111111111111111";
const MINT: &str = "Mint111111111111111111111111111111111111111";
const ATTACKER: &str = "Attacker1111111111111111111111111111111111";

/// The signer's wallet: a real base58 key, so it can be a token owner too.
fn signer_key() -> [u8; 32] {
    [42u8; 32]
}
fn signer() -> String {
    bs58::encode(signer_key()).into_string()
}

fn resolved(address: &str, name: &str, is_signer: bool) -> ResolvedAccount {
    ResolvedAccount {
        address: address.to_string(),
        role: "account".to_string(),
        name: name.to_string(),
        is_pda: false,
        is_signer,
        is_writable: true,
        pda_seeds: vec![],
        identity: AccountIdentity::Unverified,
        expected_address_mismatch: false,
        pda_mismatch: false,
        privilege_mismatch: false,
    }
}

fn delta(
    pubkey: &str,
    before: Option<AccountSnapshot>,
    after: Option<AccountSnapshot>,
) -> AccountDelta {
    AccountDelta {
        pubkey: pubkey.to_string(),
        before,
        after,
    }
}

fn snap(pubkey: &str, lamports: u64, owner: &str, data: &[u8]) -> Option<AccountSnapshot> {
    Some(AccountSnapshot::from_raw(pubkey, lamports, owner, data))
}

fn report_with(
    deltas: Vec<AccountDelta>,
    accounts: &[ResolvedAccount],
    declared: &[&str],
    fee: u64,
    fee_payer: Option<&str>,
) -> StateDiffReport {
    let diff = StateDiff {
        deltas,
        provenance: DiffProvenance::RpcSimulated,
        fee_lamports: fee,
        ..Default::default()
    };
    let declared: Vec<String> = declared.iter().map(|s| s.to_string()).collect();
    check_state_diff(&StateDiffCheck {
        diff: &diff,
        resolved_accounts: accounts,
        privileges_grounded: true,
        expected_state_changes: &declared,
        fee_payer,
    })
}

fn report(
    deltas: Vec<AccountDelta>,
    accounts: &[ResolvedAccount],
    declared: &[&str],
) -> StateDiffReport {
    report_with(deltas, accounts, declared, 0, None)
}

fn codes(r: &StateDiffReport) -> Vec<&str> {
    r.findings.iter().map(|f| f.code.as_str()).collect()
}

fn severity_of(r: &StateDiffReport, code: &str) -> Option<DiffSeverity> {
    r.findings
        .iter()
        .find(|f| f.code == code)
        .map(|f| f.severity)
}

/// A 165-byte initialized token account of `mint` held by `owner`.
fn token_account(mint: [u8; 32], owner: [u8; 32], amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(&mint);
    d[32..64].copy_from_slice(&owner);
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    d
}

/// A Token-2022 mint: an initialized 82-byte base padded to 165, the Mint
/// account type, then the TLV entries given.
fn t22_mint(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut d = vec![0u8; 165];
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

/// A Token-2022 token account with the TLV entries given.
fn t22_account(
    mint: [u8; 32],
    owner: [u8; 32],
    amount: u64,
    extensions: &[(u16, Vec<u8>)],
) -> Vec<u8> {
    let mut d = token_account(mint, owner, amount);
    d.push(2);
    for (ty, value) in extensions {
        d.extend_from_slice(&ty.to_le_bytes());
        d.extend_from_slice(&(value.len() as u16).to_le_bytes());
        d.extend_from_slice(value);
    }
    d
}

// ── F1 / M11: the TLV tail Token-2022 itself leaves ─────────────────────────

/// `adjust_len_for_multisig`: a mint whose extensions total 189 bytes would be
/// 355 bytes long, the Multisig length, and is padded to 357 with two zeros.
/// It was a Critical "region unreadable".
#[test]
fn a_mint_padded_past_the_multisig_length_reads_cleanly() {
    let mut data = t22_mint(&[(18, vec![3u8; 64]), (19, vec![4u8; 117])]);
    assert_eq!(data.len(), 355, "166 bytes of base and type, 189 of TLV");
    data.extend_from_slice(&[0, 0]);
    assert_eq!(data.len(), 357);

    let scan = detect_token2022_extensions(&data);
    assert!(scan.malformed.is_none(), "{:?}", scan.malformed);
    let found: Vec<u16> = scan.found.iter().map(|e| e.discriminant).collect();
    assert_eq!(found, vec![18, 19]);
    assert!(decode_mint(&data).is_some());
    let powers = decode_token2022_powers(&data).expect("the authorities read exactly");
    assert_eq!(powers.extension_authorities.len(), 2);

    // And through the layer: an untouched padded mint whose lamports moved
    // carries no "unreadable" finding.
    let r = report(
        vec![delta(
            MINT,
            snap(MINT, 5_000_000, TOKEN_2022, &data),
            snap(MINT, 6_000_000, TOKEN_2022, &data),
        )],
        &[resolved(MINT, "mint", false)],
        &["debit source, credit dest"],
    );
    assert!(
        !codes(&r).contains(&"Token2022ExtensionRegionUnreadable"),
        "{:?}",
        r.findings
    );
}

/// What ends the region cleanly and what does not, tail by tail. Upstream's
/// walk ends at a zero type and at a tail too short for a type; it refuses a
/// non-zero type with no room for its length.
#[test]
fn short_tails_end_the_region_only_when_they_are_padding() {
    let base = t22_mint(&[(18, vec![3u8; 64])]);
    let scan_with = |tail: &[u8]| {
        let mut d = base.clone();
        d.extend_from_slice(tail);
        detect_token2022_extensions(&d)
    };
    for tail in [&[0u8][..], &[0, 0], &[0, 0, 0], &[0, 0, 9]] {
        let scan = scan_with(tail);
        assert!(
            scan.malformed.is_none(),
            "tail {tail:?}: {:?}",
            scan.malformed
        );
        assert_eq!(scan.found.len(), 1, "tail {tail:?}");
    }
    for tail in [&[5u8][..], &[14, 0], &[14, 0, 32]] {
        let scan = scan_with(tail);
        assert!(
            scan.malformed.as_deref().unwrap_or("").contains("trailing"),
            "tail {tail:?}: {:?}",
            scan.malformed
        );
    }
}

// ── F2: a debit that ends in closure ────────────────────────────────────────

/// Draining a token account and closing it in the same transaction had no
/// token delta (the closed side has no token view), so it was no debit at all.
#[test]
fn a_token_balance_taken_out_by_a_closure_is_a_debit() {
    let wallet = signer();
    let before = token_account([7u8; 32], signer_key(), 1_000_000);
    let deltas = vec![
        delta(ACCOUNT, snap(ACCOUNT, 2_039_280, TOKEN, &before), None),
        delta(
            &wallet,
            snap(&wallet, 1_000_000_000, SYSTEM, &[]),
            snap(&wallet, 1_002_039_280, SYSTEM, &[]),
        ),
    ];
    let accounts = [
        resolved(ACCOUNT, "account", false),
        resolved(&wallet, "destination", true),
    ];
    let r = report(deltas, &accounts, &["closes accounts.account"]);
    assert_eq!(
        severity_of(&r, "UndeclaredTokenDebit"),
        Some(DiffSeverity::Critical),
        "{:?}",
        r.findings
    );
    assert!(
        !codes(&r).contains(&"UndeclaredAccountClosure"),
        "{:?}",
        r.findings
    );
}

/// An empty account closed is not a debit.
#[test]
fn closing_an_empty_token_account_is_no_debit() {
    let before = token_account([7u8; 32], signer_key(), 0);
    let r = report(
        vec![delta(
            ACCOUNT,
            snap(ACCOUNT, 2_039_280, TOKEN, &before),
            None,
        )],
        &[resolved(ACCOUNT, "account", false)],
        &["closes accounts.account"],
    );
    assert!(
        !codes(&r).contains(&"UndeclaredTokenDebit"),
        "{:?}",
        r.findings
    );
}

// ── F3: extensions on either side ───────────────────────────────────────────

/// The post-state was scanned when there was one. An account that ENTERED
/// the transaction carrying a transfer-hook flag and left it emptied and
/// handed back to the System program was judged on its empty post-state.
#[test]
fn an_extension_present_only_before_the_transaction_is_judged() {
    let before = t22_account([7u8; 32], [9u8; 32], 0, &[(15, vec![0u8])]);
    let r = report(
        vec![delta(
            ACCOUNT,
            snap(ACCOUNT, 2_039_280, TOKEN_2022, &before),
            snap(ACCOUNT, 0, SYSTEM, &[]),
        )],
        &[resolved(ACCOUNT, "account", false)],
        &["closes accounts.account"],
    );
    let f = r
        .findings
        .iter()
        .find(|f| f.code == "Token2022ExtensionNotModelled")
        .unwrap_or_else(|| panic!("{:?}", r.findings));
    assert!(f.detail.contains("TransferHookAccount"), "{}", f.detail);
}

/// An unreadable PRE-state region is unreadable too.
#[test]
fn an_unreadable_pre_state_region_is_reported() {
    let mut before = t22_account([7u8; 32], [9u8; 32], 0, &[]);
    before.extend_from_slice(&[14, 0, 200, 0, 1, 2]); // declares 200 bytes, has 2
    let after = t22_account([7u8; 32], [9u8; 32], 0, &[]);
    let r = report(
        vec![delta(
            ACCOUNT,
            snap(ACCOUNT, 2_039_280, TOKEN_2022, &before),
            snap(ACCOUNT, 2_039_280, TOKEN_2022, &after),
        )],
        &[resolved(ACCOUNT, "account", false)],
        &["debit source, credit dest"],
    );
    assert_eq!(
        severity_of(&r, "Token2022ExtensionRegionUnreadable"),
        Some(DiffSeverity::Critical),
        "{:?}",
        r.findings
    );
}

// ── F4: fee terms, scoped ───────────────────────────────────────────────────

fn transfer_fee_config(newer_bps: u16) -> Vec<u8> {
    let mut v = vec![1u8; 32]; // config authority
    v.extend_from_slice(&[2u8; 32]); // withdraw-withheld authority
    v.extend_from_slice(&0u64.to_le_bytes()); // withheld
    for (epoch, bps) in [(0u64, 10u16), (500u64, newer_bps)] {
        v.extend_from_slice(&epoch.to_le_bytes());
        v.extend_from_slice(&1_000u64.to_le_bytes());
        v.extend_from_slice(&bps.to_le_bytes());
    }
    assert_eq!(v.len(), 108);
    v
}

/// An authority change declared about ONE account excused rewriting the fee
/// terms of every mint in the transaction.
#[test]
fn a_fee_terms_change_is_not_excused_by_an_authority_declared_elsewhere() {
    let before = t22_mint(&[(1, transfer_fee_config(10))]);
    let after = t22_mint(&[(1, transfer_fee_config(5_000))]);
    let deltas = vec![delta(
        MINT,
        snap(MINT, 5_000_000, TOKEN_2022, &before),
        snap(MINT, 5_000_000, TOKEN_2022, &after),
    )];
    let accounts = [
        resolved(MINT, "mint", false),
        resolved(ACCOUNT, "account", false),
    ];

    let elsewhere = report(deltas.clone(), &accounts, &["sets accounts.account owner"]);
    assert_eq!(
        severity_of(&elsewhere, "Token2022TransferFeeConfigChanged"),
        Some(DiffSeverity::Critical),
        "{:?}",
        elsewhere.findings
    );
    let here = report(
        deltas,
        &accounts,
        &["sets accounts.mint transfer fee authority"],
    );
    assert!(
        !codes(&here).contains(&"Token2022TransferFeeConfigChanged"),
        "{:?}",
        here.findings
    );
}

// ── F5: powers that do not decode ───────────────────────────────────────────

/// A MetadataPointer value one byte short of its authority does not decode,
/// and the authority comparison needs both sides — so it was skipped, and an
/// informational extension never blocks on its own.
#[test]
fn an_authority_bearing_extension_that_does_not_decode_is_a_finding() {
    let before = t22_mint(&[(18, vec![3u8; 64])]);
    let after = t22_mint(&[(18, vec![66u8; 31])]);
    assert!(decode_token2022_powers(&before).is_some());
    assert!(decode_token2022_powers(&after).is_none());
    let r = report(
        vec![delta(
            MINT,
            snap(MINT, 5_000_000, TOKEN_2022, &before),
            snap(MINT, 5_000_000, TOKEN_2022, &after),
        )],
        &[resolved(MINT, "mint", false)],
        &["debit source, credit dest"],
    );
    assert_eq!(
        severity_of(&r, "Token2022AuthoritiesUnreadable"),
        Some(DiffSeverity::Critical),
        "{:?}",
        r.findings
    );
}

// ── F6: vote state V4 ───────────────────────────────────────────────────────

fn vote_v4(withdrawer: u8, collector: u8) -> Vec<u8> {
    let mut d = 3u32.to_le_bytes().to_vec();
    d.extend_from_slice(&[1u8; 32]); // node
    d.extend_from_slice(&[withdrawer; 32]);
    d.extend_from_slice(&[collector; 32]); // inflation rewards collector
    d.extend_from_slice(&[collector; 32]); // block revenue collector
    d.extend_from_slice(&[0u8; 200]);
    d
}

#[test]
fn a_v4_vote_accounts_withdrawer_and_collectors_are_watched() {
    let accounts = [resolved(ACCOUNT, "vote", false)];
    let declared = ["debit source, credit dest"];
    let changed = |b: &[u8], a: &[u8]| {
        report(
            vec![delta(
                ACCOUNT,
                snap(ACCOUNT, 27_074_400, VOTE, b),
                snap(ACCOUNT, 27_074_400, VOTE, a),
            )],
            &accounts,
            &declared,
        )
    };
    for (before, after) in [
        (vote_v4(5, 7), vote_v4(6, 7)),
        (vote_v4(5, 7), vote_v4(5, 8)),
    ] {
        let r = changed(&before, &after);
        assert_eq!(
            severity_of(&r, "UndeclaredNativeAuthorityChange"),
            Some(DiffSeverity::Critical),
            "{:?}",
            r.findings
        );
    }
    let mut unvoted = vote_v4(5, 7);
    let n = unvoted.len();
    unvoted[n - 1] = 9; // a vote lands; no authority moves
    assert!(changed(&vote_v4(5, 7), &unvoted).findings.is_empty());
}

/// A version this build does not decode is not a vote account without
/// authorities: a change to its bytes is a finding.
#[test]
fn an_undecodable_vote_state_that_changed_is_a_finding() {
    let mut before = 9u32.to_le_bytes().to_vec();
    before.extend_from_slice(&[1u8; 300]);
    let mut after = before.clone();
    after[100] = 2;
    let r = report(
        vec![delta(
            ACCOUNT,
            snap(ACCOUNT, 27_074_400, VOTE, &before),
            snap(ACCOUNT, 27_074_400, VOTE, &after),
        )],
        &[resolved(ACCOUNT, "vote", false)],
        &["debit source, credit dest"],
    );
    assert_eq!(
        severity_of(&r, "UndeclaredNativeAuthorityChange"),
        Some(DiffSeverity::Critical),
        "{:?}",
        r.findings
    );
}

// ── F7: a signer's lamports under a manifest that declares no debit ─────────

/// Five SOL left the signer's wallet under an instruction that declares a
/// freeze and nothing else. It was a Warning; a token debit of the same
/// shape was already Critical.
#[test]
fn a_signers_undeclared_lamport_loss_is_critical() {
    let wallet = signer();
    let deltas = vec![
        delta(
            &wallet,
            snap(&wallet, 10_000_005_000, SYSTEM, &[]),
            snap(&wallet, 5_000_000_000, SYSTEM, &[]),
        ),
        delta(ATTACKER, None, snap(ATTACKER, 5_000_000_000, SYSTEM, &[])),
    ];
    let accounts = [
        resolved(&wallet, "authority", true),
        resolved(ATTACKER, "account", false),
    ];
    let r = report_with(
        deltas,
        &accounts,
        &["freezes accounts.account"],
        5_000,
        Some(&wallet),
    );
    let f = r
        .findings
        .iter()
        .find(|f| f.code == "UndeclaredSignerLamportDebit")
        .unwrap_or_else(|| panic!("{:?}", r.findings));
    assert_eq!(f.severity, DiffSeverity::Critical);
    assert!(f.detail.contains("5000000000"), "{}", f.detail);
    assert!(r.blocked);
}

/// The same loss under a manifest that declares a closure: the old warning
/// was switched off by any declared closure or creation.
#[test]
fn a_declared_closure_does_not_excuse_a_signers_loss() {
    let wallet = signer();
    let deltas = vec![
        delta(
            &wallet,
            snap(&wallet, 10_000_000_000, SYSTEM, &[]),
            snap(&wallet, 5_000_000_000, SYSTEM, &[]),
        ),
        delta(ATTACKER, None, snap(ATTACKER, 5_000_000_000, SYSTEM, &[])),
    ];
    let accounts = [
        resolved(&wallet, "authority", true),
        resolved(ATTACKER, "account", false),
    ];
    let r = report(deltas, &accounts, &["closes accounts.account"]);
    assert_eq!(
        severity_of(&r, "UndeclaredSignerLamportDebit"),
        Some(DiffSeverity::Critical),
        "{:?}",
        r.findings
    );
}

/// What a signer pays to OWN a new account — its rent-exempt minimum — and
/// the fee are not a loss; lamports put into it beyond that are.
#[test]
fn rent_for_a_created_account_and_the_fee_are_not_a_loss() {
    let wallet = signer();
    // Held by someone else: lamports in a token account the signer holds are
    // still the signer's (the next test), so this one must not be.
    let new_account = token_account([7u8; 32], [9u8; 32], 0);
    let run = |funding: u64| {
        let deltas = vec![
            delta(
                &wallet,
                snap(&wallet, 1_000_000_000, SYSTEM, &[]),
                snap(&wallet, 1_000_000_000 - 5_000 - funding, SYSTEM, &[]),
            ),
            delta(ACCOUNT, None, snap(ACCOUNT, funding, TOKEN, &new_account)),
        ];
        let accounts = [
            resolved(&wallet, "payer", true),
            resolved(ACCOUNT, "account", false),
        ];
        report_with(
            deltas,
            &accounts,
            &["initializes accounts.account"],
            5_000,
            Some(&wallet),
        )
    };
    let exact = run(2_039_280);
    assert!(
        !codes(&exact).contains(&"UndeclaredSignerLamportDebit"),
        "{:?}",
        exact.findings
    );
    let over = run(3_000_000);
    let f = over
        .findings
        .iter()
        .find(|f| f.code == "UndeclaredSignerLamportDebit")
        .unwrap_or_else(|| panic!("{:?}", over.findings));
    assert!(f.detail.contains("960720"), "{}", f.detail);
}

/// Wrapping SOL moves a signer's lamports into a token account the signer
/// holds: the value changed form, it did not leave.
#[test]
fn lamports_into_a_signers_own_token_account_are_not_a_loss() {
    let wallet = signer();
    let wsol_before = token_account([7u8; 32], signer_key(), 0);
    let wsol_after = token_account([7u8; 32], signer_key(), 1_000_000_000);
    let deltas = vec![
        delta(
            &wallet,
            snap(&wallet, 5_000_000_000, SYSTEM, &[]),
            snap(&wallet, 4_000_000_000, SYSTEM, &[]),
        ),
        delta(
            ACCOUNT,
            snap(ACCOUNT, 2_039_280, TOKEN, &wsol_before),
            snap(ACCOUNT, 1_002_039_280, TOKEN, &wsol_after),
        ),
    ];
    let accounts = [
        resolved(&wallet, "owner", true),
        resolved(ACCOUNT, "account", false),
    ];
    let r = report(deltas, &accounts, &["credits accounts.account"]);
    assert!(
        !codes(&r).contains(&"UndeclaredSignerLamportDebit"),
        "{:?}",
        r.findings
    );
}

/// A silent manifest, or prose Graphite cannot interpret, no longer excuses a
/// signer's loss unless the manifest's security class for the instruction is
/// one that moves value (R30: this test pinned the warning for both; the loss
/// now blocks, and the warning stands only under such a class —
/// `tests/r30_declared_effects.rs`).
#[test]
fn a_signers_loss_under_silent_or_uninterpretable_prose_blocks_unless_its_class_moves_value() {
    let wallet = signer();
    let deltas = || {
        vec![
            delta(
                &wallet,
                snap(&wallet, 10_000_000_000, SYSTEM, &[]),
                snap(&wallet, 5_000_000_000, SYSTEM, &[]),
            ),
            delta(ATTACKER, None, snap(ATTACKER, 5_000_000_000, SYSTEM, &[])),
        ]
    };
    let accounts = [
        resolved(&wallet, "authority", true),
        resolved(ATTACKER, "account", false),
    ];
    let silent = report(deltas(), &accounts, &[]);
    assert!(silent.blocked, "{:?}", silent.findings);
    let prose = report(deltas(), &accounts, &["frobnicate the widget"]);
    assert!(prose.blocked, "{:?}", prose.findings);
    assert_eq!(
        severity_of(&prose, "UndeclaredSignerLamportDebit"),
        Some(DiffSeverity::Critical)
    );
    let transfer_class = graphite_core::state_diff::security_class_line("transfer");
    let prose = report(
        deltas(),
        &accounts,
        &["frobnicate the widget", transfer_class.as_str()],
    );
    assert!(!prose.blocked, "{:?}", prose.findings);
    assert_eq!(
        severity_of(&prose, "UninterpretableDeclarationWithSignerLamportDebit"),
        Some(DiffSeverity::Warning)
    );
}

// ── F8: COption tags and the Multisig length ────────────────────────────────

#[test]
fn a_coption_tag_other_than_zero_or_one_does_not_decode() {
    let mut data = token_account([7u8; 32], [9u8; 32], 5);
    data[72..76].copy_from_slice(&2u32.to_le_bytes());
    data[76..108].copy_from_slice(&[66u8; 32]);
    assert!(
        decode_token_account(&data).is_none(),
        "tag 2 used to read as a delegate of [66; 32]"
    );
    let snapshot = AccountSnapshot::from_raw(ACCOUNT, 2_039_280, TOKEN, &data);
    assert!(snapshot.token.is_none());
    assert!(snapshot.extensions.malformed.is_some());

    let good = token_account([7u8; 32], [9u8; 32], 5);
    let r = report(
        vec![delta(
            ACCOUNT,
            snap(ACCOUNT, 2_039_280, TOKEN, &good),
            Some(snapshot),
        )],
        &[resolved(ACCOUNT, "account", false)],
        &["debit source, credit dest"],
    );
    assert_eq!(
        severity_of(&r, "TokenLayoutUndecodable"),
        Some(DiffSeverity::Critical),
        "{:?}",
        r.findings
    );

    let mut mint = vec![0u8; 82];
    mint[0..4].copy_from_slice(&7u32.to_le_bytes());
    mint[45] = 1;
    assert!(decode_mint(&mint).is_none(), "a mint authority tag of 7");
    mint[0..4].copy_from_slice(&0u32.to_le_bytes());
    assert!(decode_mint(&mint).is_some());
    mint[45] = 2;
    assert!(decode_mint(&mint).is_none(), "is_initialized is a bool");
}

/// A 355-byte account owned by a token program is a Multisig, whatever byte
/// 165 holds: it was decoded as a token account (or a mint) when that byte
/// was 2 (or 1), its signer keys read as mint, owner and balance.
#[test]
fn a_multisig_never_decodes_as_an_account_or_a_mint() {
    let mut multisig = vec![0u8; 355];
    multisig[0] = 2; // m
    multisig[1] = 3; // n
    multisig[2] = 1; // initialized
    for b in multisig.iter_mut().skip(3) {
        *b = 1;
    }
    multisig[165] = 2;
    assert!(decode_token_account(&multisig).is_none());
    multisig[165] = 1;
    assert!(decode_mint(&multisig).is_none());
    let s = AccountSnapshot::from_raw(ACCOUNT, 3_000_000, TOKEN, &multisig);
    assert!(s.token.is_none() && s.mint.is_none());
    assert!(
        s.extensions.malformed.is_none(),
        "a Multisig is not an unreadable account"
    );
}

/// Audit 2026-10-20 (F4): a caller-supplied diff with a field the Core does
/// not know is refused, not read with the field silently dropped.
#[test]
fn a_supplied_diff_with_an_unknown_field_is_refused() {
    let ok = serde_json::json!({"deltas": [{"pubkey": "x"}]});
    assert!(serde_json::from_value::<graphite_core::state_diff::StateDiff>(ok).is_ok());
    for bad in [
        serde_json::json!({"deltas": [], "covers_all_writeable": true}),
        serde_json::json!({"deltas": [{"pubkey": "x", "befor": null}]}),
        serde_json::json!({"deltas": [{"pubkey": "x", "after": {"pubkey": "x", "lamports": 1, "owner": "o", "data_len": 0, "tokn": null}}]}),
    ] {
        assert!(
            serde_json::from_value::<graphite_core::state_diff::StateDiff>(bad.clone()).is_err(),
            "{bad}"
        );
    }
}
