//! R30 (§4.5): how a manifest's `expected_state_changes` prose is judged
//! against an observed diff, for the declarations that are not plainly
//! interpretable.
//!
//! - A MIXED declaration — a line Graphite reads beside a line it cannot —
//!   was flagged as a possible bypass (an unparsed material effect passing
//!   because the declaration counts as interpretable). It is not: an
//!   interpretable declaration is judged strictly, and a line that maps to no
//!   effect excuses nothing, not even about an account it names. Pinned here.
//! - A SILENT declaration (an empty list) and an UNINTERPRETABLE one (prose,
//!   none of it mapped to an effect) used to let a SIGNER lose value with at
//!   most a warning: "a manifest that promises nothing cannot be
//!   contradicted". A declaration that says nothing Graphite can read cannot
//!   excuse the signer's loss either; that loss is Critical now. Value moving
//!   between other accounts under such a declaration keeps its old treatment.

use graphite_core::account_resolution::{AccountIdentity, ResolvedAccount};
use graphite_core::state_diff::{
    check_state_diff, AccountDelta, AccountSnapshot, DeclaredEffects, DiffProvenance, DiffSeverity,
    StateDiff, StateDiffCheck, StateDiffReport,
};

const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SYSTEM: &str = "11111111111111111111111111111111";
const SOURCE: &str = "Src1111111111111111111111111111111111111111";
const DEST: &str = "Dest111111111111111111111111111111111111111";
const VAULT: &str = "Vau1t11111111111111111111111111111111111111";
const POOL: &str = "Poo11111111111111111111111111111111111111111";
const ATTACKER: &str = "Attacker1111111111111111111111111111111111";

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

fn snap(pubkey: &str, lamports: u64, owner: &str, data: &[u8]) -> Option<AccountSnapshot> {
    Some(AccountSnapshot::from_raw(pubkey, lamports, owner, data))
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

/// A 165-byte initialized token account of `mint` held by `owner`.
fn token_account(mint: [u8; 32], owner: [u8; 32], amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(&mint);
    d[32..64].copy_from_slice(&owner);
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    d
}

fn report(
    deltas: Vec<AccountDelta>,
    accounts: &[ResolvedAccount],
    declared: &[&str],
) -> StateDiffReport {
    let diff = StateDiff {
        deltas,
        provenance: DiffProvenance::RpcSimulated,
        fee_lamports: 5_000,
        ..Default::default()
    };
    let declared: Vec<String> = declared.iter().map(|s| s.to_string()).collect();
    let wallet = signer();
    check_state_diff(&StateDiffCheck {
        diff: &diff,
        resolved_accounts: accounts,
        privileges_grounded: true,
        expected_state_changes: &declared,
        fee_payer: Some(&wallet),
    })
}

fn severity_of(r: &StateDiffReport, code: &str) -> Option<DiffSeverity> {
    r.findings
        .iter()
        .find(|f| f.code == code)
        .map(|f| f.severity)
}

/// The signer's token account `VAULT` loses 1,000,000 of its 1,000,000.
fn signer_token_drain() -> Vec<AccountDelta> {
    vec![
        delta(
            VAULT,
            snap(VAULT, 2_039_280, TOKEN, &token_account([7; 32], signer_key(), 1_000_000)),
            snap(VAULT, 2_039_280, TOKEN, &token_account([7; 32], signer_key(), 0)),
        ),
        delta(
            ATTACKER,
            snap(ATTACKER, 2_039_280, TOKEN, &token_account([7; 32], [9; 32], 0)),
            snap(ATTACKER, 2_039_280, TOKEN, &token_account([7; 32], [9; 32], 1_000_000)),
        ),
    ]
}

/// The signer's wallet loses 5 SOL beyond the fee, to the attacker.
fn signer_lamport_drain() -> Vec<AccountDelta> {
    let wallet = signer();
    vec![
        delta(
            &wallet,
            snap(&wallet, 10_000_005_000, SYSTEM, &[]),
            snap(&wallet, 5_000_000_000, SYSTEM, &[]),
        ),
        delta(ATTACKER, None, snap(ATTACKER, 5_000_000_000, SYSTEM, &[])),
    ]
}

/// A pool's token vault pays out to another pool account: value moving
/// between accounts that are not a signer's.
fn pool_payout() -> Vec<AccountDelta> {
    vec![
        delta(
            POOL,
            snap(POOL, 2_039_280, TOKEN, &token_account([7; 32], [5; 32], 1_000_000)),
            snap(POOL, 2_039_280, TOKEN, &token_account([7; 32], [5; 32], 0)),
        ),
        delta(
            DEST,
            snap(DEST, 2_039_280, TOKEN, &token_account([7; 32], [6; 32], 0)),
            snap(DEST, 2_039_280, TOKEN, &token_account([7; 32], [6; 32], 1_000_000)),
        ),
    ]
}

fn accounts() -> Vec<ResolvedAccount> {
    vec![
        resolved(&signer(), "authority", true),
        resolved(SOURCE, "source", false),
        resolved(DEST, "destination", false),
        resolved(VAULT, "vault", false),
        resolved(POOL, "pool", false),
        resolved(ATTACKER, "other", false),
    ]
}

// ── Mixed declarations: strict, and an unread line excuses nothing ─────────

const MIXED: &[&str] = &[
    "transfers tokens from accounts.source to accounts.destination",
    "liquidates accounts.vault against the oracle price",
];

#[test]
fn a_mixed_declaration_is_interpretable_and_its_unread_line_declares_nothing() {
    let lines: Vec<String> = MIXED.iter().map(|s| s.to_string()).collect();
    let e = DeclaredEffects::parse(&lines);
    assert!(e.is_interpretable());
    assert!(
        DeclaredEffects::parse(&lines[1..]).unrecognised,
        "the second line alone maps to no effect"
    );
    assert!(e.covers("debit", &["source"]));
    assert!(
        !e.covers("debit", &["vault"]),
        "the unread line names the vault but declares nothing about it"
    );
    assert!(!e.covers("debit", &[]));
}

/// The account the unread line names is the signer's, and it is drained: the
/// readable line's debit is scoped to `source`, so this is Critical.
#[test]
fn a_mixed_declaration_does_not_excuse_draining_the_account_its_unread_line_names() {
    let r = report(signer_token_drain(), &accounts(), MIXED);
    assert_eq!(
        severity_of(&r, "UndeclaredTokenDebit"),
        Some(DiffSeverity::Critical),
        "{:?}",
        r.findings
    );
    assert!(r.blocked);
}

/// A mixed declaration with no debit anywhere: a signer token debit is
/// Critical exactly as under a fully interpretable one.
#[test]
fn a_mixed_declaration_without_a_debit_blocks_any_token_debit() {
    let r = report(
        signer_token_drain(),
        &accounts(),
        &["closes accounts.source", "rebalances accounts.vault"],
    );
    assert_eq!(
        severity_of(&r, "UndeclaredTokenDebit"),
        Some(DiffSeverity::Critical),
        "{:?}",
        r.findings
    );
}

// ── Silent and uninterpretable declarations: the signer's loss blocks ──────

#[test]
fn a_signers_token_loss_under_a_silent_declaration_is_critical() {
    let r = report(signer_token_drain(), &accounts(), &[]);
    assert_eq!(
        severity_of(&r, "UndeclaredTokenDebit"),
        Some(DiffSeverity::Critical),
        "{:?}",
        r.findings
    );
    assert!(r.blocked);
}

#[test]
fn a_signers_token_loss_under_uninterpretable_prose_is_critical() {
    let r = report(signer_token_drain(), &accounts(), &["frobnicates the widget"]);
    assert_eq!(
        severity_of(&r, "UndeclaredTokenDebit"),
        Some(DiffSeverity::Critical),
        "{:?}",
        r.findings
    );
    assert!(r.blocked);
}

#[test]
fn a_signers_lamport_loss_under_a_silent_declaration_is_critical() {
    let r = report(signer_lamport_drain(), &accounts(), &[]);
    assert_eq!(
        severity_of(&r, "UndeclaredSignerLamportDebit"),
        Some(DiffSeverity::Critical),
        "{:?}",
        r.findings
    );
    assert!(r.blocked);
}

#[test]
fn a_signers_lamport_loss_under_uninterpretable_prose_is_critical() {
    let r = report(signer_lamport_drain(), &accounts(), &["frobnicates the widget"]);
    assert_eq!(
        severity_of(&r, "UndeclaredSignerLamportDebit"),
        Some(DiffSeverity::Critical),
        "{:?}",
        r.findings
    );
    assert!(r.blocked);
}

/// The pipeline states the manifest's security class beside the prose. A
/// class whose instructions move value keeps the old warning for unreadable
/// prose (a swap described as "Orca Whirlpools instruction"); one that states
/// the instruction moves nothing (`inert`, `authority`) does not.
#[test]
fn the_security_class_decides_an_unreadable_declarations_signer_loss() {
    use graphite_core::state_diff::security_class_line;
    for (class, blocks) in [
        ("transfer", false),
        ("withdraw", false),
        ("close", false),
        ("", false),
        ("inert", true),
        ("authority", true),
    ] {
        let line = security_class_line(class);
        let declared = ["Orca Whirlpools instruction", line.as_str()];
        for (what, deltas, code) in [
            ("token", signer_token_drain(), "UndeclaredTokenDebit"),
            ("lamports", signer_lamport_drain(), "UndeclaredSignerLamportDebit"),
        ] {
            let r = report(deltas, &accounts(), &declared);
            assert_eq!(r.blocked, blocks, "{class:?} {what}: {:?}", r.findings);
            if blocks {
                assert_eq!(severity_of(&r, code), Some(DiffSeverity::Critical), "{class:?}");
            }
        }
    }
}

/// The class line is the pipeline's: it states nothing about effects, so a
/// declaration made only of it is silent, and two different classes state
/// none.
#[test]
fn the_class_line_is_not_prose() {
    use graphite_core::state_diff::security_class_line;
    let only = DeclaredEffects::parse(&[security_class_line("transfer")]);
    assert!(only.is_silent());
    assert_eq!(only.security_class.as_deref(), Some("transfer"));
    assert!(only.class_moves_value());
    let two = DeclaredEffects::parse(&[
        security_class_line("transfer"),
        security_class_line("inert"),
    ]);
    assert_eq!(two.security_class, None);
    assert!(!two.class_moves_value());
    let none = DeclaredEffects::parse(&["frobnicates the widget".to_string()]);
    assert!(!none.class_moves_value(), "no class stated: no allowance");
}

/// A manifest cannot write the pipeline's line itself.
#[test]
fn a_manifest_may_not_declare_a_graphite_line() {
    let mut m = graphite_core::manifest::load_seed_manifests()
        .get("11111111111111111111111111111111")
        .unwrap()
        .clone();
    m.instructions[0]
        .expected_state_changes
        .push(graphite_core::state_diff::security_class_line("transfer"));
    let err = graphite_core::manifest::validate_manifest(&m).unwrap_err();
    assert!(err.to_string().contains("graphite:"), "{err}");
}

/// Control: value moving between accounts no signer owns, under prose
/// Graphite cannot read, keeps the old warning — the rule is about the
/// signer's value, not about every movement a declaration does not explain.
#[test]
fn a_payout_between_other_accounts_under_uninterpretable_prose_still_only_warns() {
    let r = report(pool_payout(), &accounts(), &["frobnicates the widget"]);
    assert_eq!(
        severity_of(&r, "UninterpretableDeclarationWithTokenDebit"),
        Some(DiffSeverity::Warning),
        "{:?}",
        r.findings
    );
    assert!(!r.blocked, "{:?}", r.findings);
}

/// Control: a silent declaration with no signer loss has nothing to judge.
#[test]
fn a_silent_declaration_with_no_signer_loss_has_no_value_finding() {
    let r = report(pool_payout(), &accounts(), &[]);
    assert!(!r.blocked, "{:?}", r.findings);
}

/// Control: the fee alone is not a loss.
#[test]
fn the_fee_alone_is_not_a_signers_loss_under_a_silent_declaration() {
    let wallet = signer();
    let r = report(
        vec![delta(
            &wallet,
            snap(&wallet, 1_000_005_000, SYSTEM, &[]),
            snap(&wallet, 1_000_000_000, SYSTEM, &[]),
        )],
        &accounts(),
        &[],
    );
    assert!(!r.blocked, "{:?}", r.findings);
}
