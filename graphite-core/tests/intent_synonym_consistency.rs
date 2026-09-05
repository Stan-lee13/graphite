//! Intent-vocabulary consistency (2026-09-05 red-team follow-up).
//!
//! The intent vocabulary has documented synonym groups — `swap|trade|exchange`,
//! `close|close_account`, `create|create_account`, `transfer|send`,
//! `stake|delegate`, `approve|revoke`. `program_supports_intent` honours those
//! groups. Several individual risk checks did not: they compared
//! `proposed_intent_type` against a single literal.
//!
//! That inconsistency fails in BOTH directions, which is why it is worth
//! fixing as a class rather than patching one site:
//!
//!   - UNDER-blocking (security): `detect_fake_swap` only fired on the literal
//!     `"swap"`, so declaring `"exchange"` on a trusted DEX skipped the check
//!     built specifically to catch a swap that produces no output — while
//!     `program_supports_intent` simultaneously accepted `"exchange"` as a
//!     valid swap intent, so the intent-mismatch check did not fire either.
//!     One word, and a FakeSwap drain passes.
//!
//!   - OVER-blocking (correctness): the account-creation check uses the
//!     literal in the opposite direction (`intent != "create"` ⇒ flag the
//!     creation), so a caller honestly declaring `"create_account"` — a
//!     synonym the vocabulary explicitly supports — had a legitimate account
//!     creation flagged as a malicious change.
//!
//! A verification gate that can be evaded by a synonym is broken; one that
//! blocks legitimate traffic over a synonym is also broken. Both come from the
//! same root cause: the vocabulary was defined in one place and re-implemented
//! ad hoc in others. Every comparison now routes through `canonical_intent`.
//!
//! NOTE on a hypothesis this investigation DISPROVED: the equivalent
//! `close`/`close_account` case is NOT a false positive. CloseAccount sits in
//! the unconditional known-risky-discriminator table because it genuinely
//! drains all lamports, so it blocks under any intent — including the honest
//! one. That is deliberate, and is pinned below so the synonym work here is
//! never mistaken for a licence to relax it.

use graphite_core::risk_engine::{assess, RiskAssessmentInput, RiskVerdict};

const JUPITER: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SYSTEM: &str = "11111111111111111111111111111111";
const A: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const B: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

fn base(program_id: &str, disc: &str, intent: &str) -> RiskAssessmentInput {
    RiskAssessmentInput {
        program_id: program_id.to_string(),
        accounts: vec![A.to_string(), B.to_string()],
        cpi_targets: vec![],
        expected_state_changes: vec![],
        allowed_cpis: vec![],
        instruction_discriminator: disc.to_string(),
        expected_account_count: Some(2),
        variable_accounts: false,
        proposed_intent_type: intent.to_string(),
        extracted_output_token: None,
        manifest_risk_class: String::new(),
    }
}

fn is_blocked(v: &RiskVerdict) -> bool {
    matches!(v, RiskVerdict::Blocked { .. })
}

// ── UNDER-blocking: the FakeSwap evasion ───────────────────────────────────

/// A swap on a trusted DEX whose declared state changes contain no credit or
/// output — funds leave and nothing comes back. This is the FakeSwap shape.
fn fake_swap_with_intent(intent: &str) -> RiskAssessmentInput {
    let mut i = base(JUPITER, "e517cb97", intent);
    // Debit declared, no corresponding credit/output anywhere.
    i.expected_state_changes =
        vec!["debits accounts.source token balance by data.amount".to_string()];
    i
}

#[test]
fn fake_swap_is_caught_under_the_literal_swap_intent() {
    let verdict = assess(&fake_swap_with_intent("swap")).unwrap();
    assert!(
        is_blocked(&verdict),
        "the baseline FakeSwap case must block: {verdict:?}"
    );
}

/// THE evasion: every synonym the vocabulary treats as a swap must be held to
/// the same standard. Declaring "exchange" instead of "swap" must not turn a
/// FakeSwap into an approval.
#[test]
fn fake_swap_cannot_be_evaded_by_using_a_swap_synonym() {
    for intent in ["trade", "exchange"] {
        let verdict = assess(&fake_swap_with_intent(intent)).unwrap();
        assert!(
            is_blocked(&verdict),
            "declaring intent {intent:?} evaded FakeSwap detection — a one-word relabel \
             defeats the check built to catch exactly this: {verdict:?}"
        );
    }
}

/// A genuine swap that DOES declare its output must keep passing under every
/// synonym — the fix must not turn "hold synonyms to the same standard" into
/// "block all swaps".
#[test]
fn genuine_swaps_still_pass_under_every_synonym() {
    for intent in ["swap", "trade", "exchange"] {
        let mut i = base(JUPITER, "e517cb97", intent);
        i.expected_state_changes = vec![
            "debits accounts.source token balance by data.amount".to_string(),
            "credits accounts.destination token balance with output amount".to_string(),
        ];
        let verdict = assess(&i).unwrap();
        assert!(
            !is_blocked(&verdict),
            "a genuine swap declaring its output must not be blocked under intent {intent:?}: {verdict:?}"
        );
    }
}

// ── OVER-blocking: the legitimate-synonym false positive ───────────────────

/// CloseAccount sits in the unconditional known-risky-discriminator table (it
/// genuinely drains all lamports from the closed account), so it blocks
/// regardless of declared intent — including an honest `close`. That is
/// deliberate, not a synonym bug.
///
/// Recorded because the investigation initially expected the opposite: the
/// first version of this test asserted an honest `close` should pass. The code
/// was right and the expectation was wrong. Pinning the real behaviour here
/// stops the synonym work below from being mistaken for a licence to relax it.
#[test]
fn close_account_blocks_unconditionally_regardless_of_intent_synonym() {
    for intent in ["close", "close_account", "transfer"] {
        let verdict = assess(&base(SPL_TOKEN, "09", intent)).unwrap();
        assert!(
            is_blocked(&verdict),
            "CloseAccount drains lamports and must block under any intent, incl. {intent:?}: {verdict:?}"
        );
    }
}

/// Same for account creation: `create_account` is a documented synonym of
/// `create`.
#[test]
fn declaring_create_account_is_not_treated_as_a_malicious_create() {
    for intent in ["create", "create_account"] {
        let verdict = assess(&base(SYSTEM, "00000000", intent)).unwrap();
        assert!(
            !is_blocked(&verdict),
            "an honestly-declared account creation under intent {intent:?} must not be \
             flagged: {verdict:?}"
        );
    }
}

/// The over-blocking fix must not become under-blocking: account creation
/// declared as something unrelated is the real attack Check 6b exists for.
#[test]
fn create_account_under_an_unrelated_intent_still_blocks() {
    let verdict = assess(&base(SYSTEM, "00000000", "swap")).unwrap();
    assert!(
        is_blocked(&verdict),
        "a CreateAccount declared as a swap must still be caught: {verdict:?}"
    );
}
