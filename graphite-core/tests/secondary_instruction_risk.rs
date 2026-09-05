//! P0-3 regression suite (2026-09-05 audit finding, fixed 2026-09-05):
//! "Secondary instructions are largely not passed through the Risk Engine."
//!
//! Before this fix, `risk_engine::assess()` was called exactly once per
//! verification — against the PRIMARY instruction only. Everything else in
//! the transaction (CPI-flattened callees, top-level sibling instructions)
//! was invisible to the 23 structural risk checks, and reachable only via
//! `tx_pattern_analysis`'s narrow, correlation-based multi-instruction rules
//! (which require a SPECIFIC paired instruction, e.g. an Approve immediately
//! followed by a Transfer of the SAME account). A standalone secondary
//! instruction with no such pairing — a bare SetAuthority, a manifest-tagged
//! high-risk instruction with no declared justification — passed through
//! completely unscrutinized.
//!
//! These tests exercise `GraphiteCore::assess_secondary_instructions` (via
//! the public `verify()` entry point only — no internals are called
//! directly) and prove, independently of `tx_pattern_analysis`'s pairing
//! rules, that every instruction in a transaction now gets meaningful risk
//! scrutiny: a standalone risky secondary is blocked, a benign one is not,
//! multiple risky secondaries aggregate into one coherent block, ordering
//! and duplication cannot evade detection, an unmanifested secondary program
//! fails safely (visible warning, not a silent bypass and not a false
//! block), and the whole assessment is deterministic.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::semantic_graph_store::TrustTier;
use graphite_core::tx_pattern_analysis::{CpiTraceNode, TransactionInstruction};
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
// Unmanifested program ID (not in any seed manifest) — reused from
// tests/policy_profiles.rs and tests/plugin_framework.rs's UNKNOWN_PROGRAM
// convention.
const UNKNOWN_PROGRAM: &str = "GdP9U5aYx7f2kQzVwNmT8jRcL4hB6eX3sDnWqA1uMoH";

const A: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const B: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const C: &str = "9RGFwSryu7FvDaqHWFLrnvQHge7hc5chawhcSH7m8FVU";
const D: &str = "DuFgLf6zzf2N9v3iT4NrkdTPDSD2xK52CCnx6Ag2ckTP";
const E: &str = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const F: &str = "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1";

/// A benign primary instruction (plain SPL Token transfer, declared intent
/// "transfer") — deliberately unrelated to whatever secondary instructions a
/// test attaches, so any block observed is attributable to the SECONDARY
/// instruction, not the primary. Low confidence bar (Custom 0.40 / tier
/// OfficialManifest) isolates the Risk Engine's hard gate from confidence/
/// policy-threshold effects, matching the convention in
/// tests/phase2_tx_patterns.rs.
fn benign_primary() -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Transfer tokens".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: TOKEN_PROGRAM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "03".to_string(),
        account_addresses: vec![A.to_string(), B.to_string(), C.to_string()],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Custom {
            min_confidence: 0.40,
            min_trust_tier: TrustTier::OfficialManifest,
        },
        behavior_evidence: BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 5,
            battle_tested_tx_count: 50000,
            simulation_match_count: 100,
        },
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
    }
}

fn ix(program: &str, disc: &str, accounts: &[&str]) -> TransactionInstruction {
    TransactionInstruction {
        program_id: program.to_string(),
        instruction_discriminator: disc.to_string(),
        account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
        cpi_targets: vec![],
    }
}

/// A standalone SetAuthority (06) on account D, with NO paired Transfer of D
/// anywhere in the transaction — deliberately does NOT match
/// `tx_pattern_analysis`'s authority-hijack-then-transfer pairing rule, so a
/// block here can only come from the per-instruction Risk Engine pass this
/// fix adds.
fn standalone_setauthority(target: &str) -> TransactionInstruction {
    ix(TOKEN_PROGRAM, "06", &[target, B])
}

// ── 1. Dangerous secondary instruction → blocked ───────────────────────────

#[test]
fn standalone_secondary_setauthority_is_blocked() {
    let core = GraphiteCore::new();
    let mut input = benign_primary();
    input.transaction_instructions = vec![standalone_setauthority(D)];

    let result = core.verify(&input).unwrap();

    assert!(
        !result.approved,
        "a standalone secondary SetAuthority with no paired Transfer must block, got approved=true, findings={:?}",
        result.risk_verdict.findings
    );
    assert_eq!(result.risk_verdict.status, "Blocked");
    // Must NOT be the multi-instruction pairing rule (there is no paired
    // Transfer of D) — proves the per-instruction Risk Engine pass, not
    // tx_pattern_analysis, caught this.
    assert!(
        !result
            .risk_verdict
            .findings
            .iter()
            .any(|f| f.pattern == "MultiInstructionDrain"),
        "this must NOT be attributed to the AAT/hijack pairing rule (no paired Transfer exists): {:?}",
        result.risk_verdict.findings
    );
    assert!(
        result
            .risk_verdict
            .findings
            .iter()
            .any(|f| f.pattern == "AuthorityHijack"),
        "expected an AuthorityHijack finding from the per-instruction risk pass, got: {:?}",
        result.risk_verdict.findings
    );
    assert!(
        result
            .risk_verdict
            .findings
            .iter()
            .any(|f| f.reason.contains("secondary instruction")),
        "a finding must name which instruction triggered the block: {:?}",
        result.risk_verdict.findings
    );
}

/// Same standalone-SetAuthority scenario but hidden inside the CPI trace of
/// the primary instruction (depth 1) instead of a top-level sibling — proves
/// coverage extends to CPI-flattened instructions, not just
/// `transaction_instructions`.
#[test]
fn standalone_setauthority_hidden_in_cpi_trace_is_blocked() {
    let core = GraphiteCore::new();
    let mut input = benign_primary();
    input.cpi_trace = Some(CpiTraceNode {
        program_id: TOKEN_PROGRAM.to_string(),
        instruction_discriminator: String::new(),
        depth: 0,
        account_addresses: vec![],
        children: vec![CpiTraceNode {
            program_id: TOKEN_PROGRAM.to_string(),
            instruction_discriminator: "06".to_string(),
            depth: 1,
            account_addresses: vec![D.to_string(), B.to_string()],
            children: vec![],
        }],
    });

    let result = core.verify(&input).unwrap();
    assert!(
        !result.approved,
        "a standalone SetAuthority nested in the CPI trace must block, findings={:?}",
        result.risk_verdict.findings
    );
    assert!(result
        .risk_verdict
        .findings
        .iter()
        .any(|f| f.pattern == "AuthorityHijack"));
}

// ── 2. Benign secondary instruction → no false rejection ───────────────────

#[test]
fn benign_secondary_instruction_does_not_cause_false_rejection() {
    let core = GraphiteCore::new();
    let mut input = benign_primary();
    // A second, ordinary transfer to a different destination — nothing here
    // matches any risk pattern.
    input.transaction_instructions = vec![ix(TOKEN_PROGRAM, "03", &[A, D, C])];

    let result = core.verify(&input).unwrap();

    assert!(
        result.approved,
        "a benign secondary transfer must not cause a false rejection: {} | findings={:?}",
        result.summary, result.risk_verdict.findings
    );
    assert_eq!(result.risk_verdict.status, "Clear");
}

// ── 3. Multiple risky secondaries aggregate correctly ───────────────────────

#[test]
fn multiple_risky_secondary_instructions_aggregate_into_one_blocked_verdict() {
    let core = GraphiteCore::new();
    let mut input = benign_primary();
    input.transaction_instructions = vec![
        standalone_setauthority(D),          // secondary #1: AuthorityHijack
        ix(TOKEN_PROGRAM, "04", &[E, F, E]), // secondary #2: Approve → PermissionEscalation
    ];

    let result = core.verify(&input).unwrap();

    assert!(!result.approved);
    assert_eq!(result.risk_verdict.status, "Blocked");
    let combined_reason = result
        .risk_verdict
        .findings
        .iter()
        .map(|f| f.reason.as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        combined_reason.contains("secondary instruction #1")
            && combined_reason.contains("secondary instruction #2"),
        "both risky secondary instructions must be named in the aggregated reason, got: {:?}",
        result.risk_verdict.findings
    );
}

// ── 4. Ordering cannot bypass detection ─────────────────────────────────────

#[test]
fn ordering_of_risky_secondary_instruction_does_not_affect_detection() {
    let core = GraphiteCore::new();

    let mut risky_first = benign_primary();
    risky_first.transaction_instructions = vec![
        standalone_setauthority(D),          // risky, position 1
        ix(TOKEN_PROGRAM, "03", &[A, D, C]), // benign, position 2
    ];
    let result_first = core.verify(&risky_first).unwrap();

    let mut risky_last = benign_primary();
    risky_last.transaction_instructions = vec![
        ix(TOKEN_PROGRAM, "03", &[A, D, C]), // benign, position 1
        standalone_setauthority(D),          // risky, position 2
    ];
    let result_last = core.verify(&risky_last).unwrap();

    assert!(
        !result_first.approved && !result_last.approved,
        "the risky secondary must block regardless of position: first={}, last={}",
        result_first.approved,
        result_last.approved
    );
    assert_eq!(result_first.risk_verdict.status, "Blocked");
    assert_eq!(result_last.risk_verdict.status, "Blocked");
}

// ── 5. Duplicate instructions cannot bypass detection ───────────────────────

#[test]
fn duplicate_risky_secondary_instructions_are_still_blocked() {
    let core = GraphiteCore::new();
    let mut input = benign_primary();
    input.transaction_instructions = vec![
        standalone_setauthority(D),
        standalone_setauthority(D),
        standalone_setauthority(D),
    ];

    let result = core.verify(&input).unwrap();

    assert!(
        !result.approved,
        "3 duplicate risky secondary instructions must not dilute detection into an approval"
    );
    assert_eq!(result.risk_verdict.status, "Blocked");
}

// ── 6. Unknown secondary instructions fail safely ───────────────────────────

#[test]
fn unknown_program_secondary_instruction_fails_safely() {
    let core = GraphiteCore::new();
    let mut input = benign_primary();
    // An unmanifested program as a secondary instruction, with an otherwise
    // unremarkable shape (few accounts, no known-risky discriminator match).
    input.transaction_instructions = vec![ix(UNKNOWN_PROGRAM, "ff", &[A, B])];

    let result = core.verify(&input).unwrap();

    // "Fails safely" here means: visible (not silently dropped), and NOT a
    // false Block on the mere fact of being unmanifested (P12 — unknown is
    // not itself proof of harm) — a genuinely dangerous unmanifested
    // secondary is still caught by the structural checks that don't require
    // a manifest (Check 2's unconditional discriminator table, Check 10a
    // impersonation); this fixture has neither, so it should approve, with
    // the gap disclosed.
    assert!(
        result.summary.contains("unmanifested program"),
        "an unmanifested secondary program must be surfaced, not silently ignored: {}",
        result.summary
    );
    assert!(
        result.approved,
        "an unmanifested secondary with no structural risk signal must not be falsely blocked: {}",
        result.summary
    );
}

/// A CPI-trace child with NO discriminator at all (the common case for trace
/// introspection — see `regression_corpus.rs`'s `trace_node` helper, which
/// never populates one) must NOT be routed into the empty-discriminator
/// fail-closed branch of Check 2 — that branch exists for the PRIMARY
/// instruction, where omitting a discriminator is the caller's choice, not a
/// CPI-trace observability limit. This is a direct regression test for the
/// false-positive this fix's first implementation caused (caught by
/// `regression_corpus_replays_perfect` during implementation).
#[test]
fn cpi_trace_child_with_no_discriminator_is_not_falsely_blocked() {
    let core = GraphiteCore::new();
    let mut input = benign_primary();
    input.cpi_trace = Some(CpiTraceNode {
        program_id: TOKEN_PROGRAM.to_string(),
        instruction_discriminator: String::new(),
        depth: 0,
        account_addresses: vec![],
        // A Token-program CPI child with an empty discriminator — exactly
        // the shape that regressed against Check 2's unconditional
        // "empty discriminator on a known-risky program" branch.
        children: vec![CpiTraceNode {
            program_id: TOKEN_PROGRAM.to_string(),
            instruction_discriminator: String::new(),
            depth: 1,
            account_addresses: vec![A.to_string(), B.to_string()],
            children: vec![],
        }],
    });

    let result = core.verify(&input).unwrap();

    assert!(
        result.approved,
        "a CPI-trace child with no discriminator must not be falsely blocked: {} | findings={:?}",
        result.summary, result.risk_verdict.findings
    );
    assert!(
        result.summary.contains("no discriminator available"),
        "the missing-discriminator limitation must still be surfaced: {}",
        result.summary
    );
}

// ── 7. Determinism ───────────────────────────────────────────────────────────

#[test]
fn secondary_instruction_risk_assessment_is_deterministic() {
    let core = GraphiteCore::new();
    let mut input = benign_primary();
    input.transaction_instructions = vec![
        standalone_setauthority(D),
        ix(TOKEN_PROGRAM, "03", &[A, D, C]),
        ix(TOKEN_PROGRAM, "04", &[E, F, E]),
        standalone_setauthority(D),
    ];

    let result_a = core.verify(&input).unwrap();
    let result_b = core.verify(&input).unwrap();

    assert_eq!(
        result_a.approved, result_b.approved,
        "same input must yield the same approval verdict across runs"
    );
    assert_eq!(result_a.risk_verdict, result_b.risk_verdict);
    assert_eq!(
        result_a.content_hash, result_b.content_hash,
        "content_hash must be reproducible (Constitution P2)"
    );
}
