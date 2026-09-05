//! Property-based invariants for the COMPOSITE, caller-controlled input
//! surfaces (Milestone 4 adversarial pass, 2026-09-05).
//!
//! `tests/proptest_engine.rs` fuzzes a single instruction. It always sends
//! `transaction_instructions: vec![]`, `cpi_trace: None`, `cpi_targets:
//! vec![]` and `real_account_metas: vec![]` — so the newest and structurally
//! richest inputs, every one of them attacker-supplied, were never fuzzed at
//! all. Those are exactly the surfaces the recent fixes touched:
//! secondary-instruction risk assessment, CPI-trace flattening,
//! multi-instruction drain analysis, and privilege grounding.
//!
//! This suite generates hostile MULTI-INSTRUCTION transactions and recursive
//! CPI trees and asserts the invariants that must hold for ANY of them. It is
//! deliberately about invariants rather than specific attacks: a handcrafted
//! corpus pins the attacks we already thought of, while these catch the shape
//! we did not.
//!
//! Invariants asserted:
//!   - `verify()` never panics on any structural shape (deep trees, wide
//!     fan-out, empty/duplicated/self-referential nodes, mismatched lengths)
//!   - `approved == true` implies risk Clear AND `policy_verdict == "Approved"`
//!     (the two fields cannot contradict — regression-guarded structurally)
//!   - an unknown protocol never exceeds the P6 confidence ceiling, no matter
//!     what composite structure is attached
//!   - determinism (P2) holds across composite inputs, including the ORDER of
//!     any internally-aggregated findings
//!   - a blocked verdict can never be diluted into approval by ADDING benign
//!     instructions around the malicious one

use graphite_core::tx_pattern_analysis::{CpiTraceNode, TransactionInstruction};
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};
use graphite_core::WalletProfile;
use proptest::prelude::*;

const SYS: &str = "11111111111111111111111111111111";
const SPL: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN22: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const JUPITER: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const UNKNOWN: &str = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";

const ACCOUNTS: &[&str] = &[
    "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
    "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
    "9RGFwSryu7FvDaqHWFLrnvQHge7hc5chawhcSH7m8FVU",
    "DuFgLf6zzf2N9v3iT4NrkdTPDSD2xK52CCnx6Ag2ckTP",
];

/// Programs a real transaction touches, plus an unmanifested one.
fn any_program() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(SYS.to_string()),
        Just(SPL.to_string()),
        Just(TOKEN22.to_string()),
        Just(JUPITER.to_string()),
        Just(UNKNOWN.to_string()),
    ]
}

/// Includes the dangerous discriminators (SetAuthority 06, Approve 04,
/// CloseAccount 09, Transfer 03/0c, System assign 01) so generated
/// transactions really do contain drain-shaped material, plus empty and
/// non-hex forms.
fn any_discriminator() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("03".to_string()),
        Just("0c".to_string()),
        Just("04".to_string()),
        Just("06".to_string()),
        Just("09".to_string()),
        Just("01".to_string()),
        Just("02000000".to_string()),
        Just(String::new()),
        Just("zz".to_string()),
        Just("0600000000000000".to_string()), // width-padded SetAuthority
    ]
}

fn any_accounts() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(
        prop::sample::select(ACCOUNTS).prop_map(|s| s.to_string()),
        0..5,
    )
}

fn any_instruction() -> impl Strategy<Value = TransactionInstruction> {
    (any_program(), any_discriminator(), any_accounts()).prop_map(
        |(program_id, instruction_discriminator, account_addresses)| TransactionInstruction {
            program_id,
            instruction_discriminator,
            account_addresses,
            cpi_targets: vec![],
        },
    )
}

/// A recursive CPI tree with bounded depth and fan-out. Bounded deliberately:
/// unbounded generation would test proptest's stack, not Graphite's. Extreme
/// depth is covered separately by the handcrafted 6000-deep payload test.
fn any_cpi_trace() -> impl Strategy<Value = CpiTraceNode> {
    let leaf = (any_program(), any_discriminator(), any_accounts()).prop_map(
        |(program_id, instruction_discriminator, account_addresses)| CpiTraceNode {
            program_id,
            instruction_discriminator,
            depth: 0,
            account_addresses,
            children: vec![],
        },
    );
    leaf.prop_recursive(4, 24, 3, |inner| {
        (
            any_program(),
            any_discriminator(),
            any_accounts(),
            prop::collection::vec(inner, 0..3),
        )
            .prop_map(
                |(program_id, instruction_discriminator, account_addresses, children)| {
                    CpiTraceNode {
                        program_id,
                        instruction_discriminator,
                        depth: 0,
                        account_addresses,
                        children,
                    }
                },
            )
    })
}

fn any_real_metas() -> impl Strategy<Value = Vec<graphite_core::account_resolution::RealAccountMeta>>
{
    prop::collection::vec(
        (any::<bool>(), any::<bool>()).prop_map(|(is_signer, is_writable)| {
            graphite_core::account_resolution::RealAccountMeta {
                is_signer,
                is_writable,
            }
        }),
        // Deliberately spans lengths that do NOT match the account list, to
        // exercise the "treated as not supplied" fail-safe path.
        0..6,
    )
}

fn any_profile() -> impl Strategy<Value = WalletProfile> {
    prop_oneof![
        Just(WalletProfile::Gaming),
        Just(WalletProfile::TradingBot),
        Just(WalletProfile::Treasury),
        Just(WalletProfile::Enterprise),
        // A zero-threshold Custom profile is included ON PURPOSE. It is what
        // the server-boundary clamp now refuses from an untrusted caller, but
        // the CORE must still be exercised with it: without a profile that can
        // actually approve, every generated case came back blocked and the
        // `if r.approved { ... }` invariants below never executed once — they
        // passed vacuously across 400 cases. The anti-vacuity test at the
        // bottom of this file pins that this stays true.
        Just(WalletProfile::Custom {
            min_confidence: 0.0,
            min_trust_tier: graphite_core::confidence_engine::TrustTier::Unknown,
        }),
    ]
}

fn composite_input() -> impl Strategy<Value = VerificationInput> {
    (
        any_program(),
        any_discriminator(),
        any_accounts(),
        prop::collection::vec(any_instruction(), 0..6),
        prop::option::of(any_cpi_trace()),
        any_real_metas(),
        any_profile(),
        prop::collection::vec(any_program(), 0..4),
    )
        .prop_map(
            |(
                program_id,
                instruction_discriminator,
                account_addresses,
                transaction_instructions,
                cpi_trace,
                real_account_metas,
                wallet_profile,
                cpi_targets,
            )| VerificationInput {
                proposed_intent: ProposedIntent {
                    intent_type: "transfer".to_string(),
                    raw_natural_language: "composite proptest input".to_string(),
                    confidence_of_parse: 0.9,
                    extracted_parameters: None,
                },
                program_id,
                protocol_version: "1.0.0".to_string(),
                instruction_discriminator,
                account_addresses,
                instruction_data: None,
                cpi_targets,
                wallet_profile,
                behavior_evidence: Default::default(),
                compute_units: 150,
                account_writes: 2,
                cpi_hops: 0,
                signed_transaction: None,
                transaction_instructions,
                cpi_trace,
                uses_versioned_transaction: false,
                lookup_table_count: 0,
                real_account_metas,
                state_diff: None,
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(384))]

    /// No composite shape may panic, and any Ok must satisfy the verdict
    /// invariants. A panic here is a remote DoS: every one of these fields is
    /// caller-supplied over HTTP.
    #[test]
    fn composite_inputs_never_panic_and_verdicts_are_consistent(input in composite_input()) {
        let core = GraphiteCore::new();
        match core.verify(&input) {
            Ok(r) => {
                prop_assert!(
                    (0.0..=1.0).contains(&r.confidence) && r.confidence.is_finite(),
                    "confidence out of range or non-finite: {}", r.confidence
                );

                // A hard risk gate can never be bypassed by an approval.
                if r.approved {
                    prop_assert_eq!(
                        &r.risk_verdict.status, "Clear",
                        "approved must imply risk Clear"
                    );
                }

                // The two verdict fields must never contradict — a developer
                // gating on policy_verdict must reach the same decision as one
                // gating on approved.
                prop_assert_eq!(
                    r.policy_verdict == "Approved", r.approved,
                    "policy_verdict/approved disagreement: approved={}, policy_verdict={}, risk={}",
                    r.approved, r.policy_verdict, r.risk_verdict.status
                );

                // P3: a confidence its own breakdown cannot explain is an
                // audit-trail lie.
                prop_assert!(!r.breakdown.is_empty(), "breakdown must never be empty");
            }
            Err(_) => { /* caller-fixable errors are fine; panics are not */ }
        }
    }

    /// P6: an unknown protocol never receives high confidence, regardless of
    /// what composite structure is attached to the request. Attaching many
    /// instructions or a deep CPI tree must not become an evidence source.
    #[test]
    fn unknown_protocol_ceiling_holds_under_composite_input(input in composite_input()) {
        let mut input = input;
        input.program_id = UNKNOWN.to_string();
        let core = GraphiteCore::new();
        if let Ok(r) = core.verify(&input) {
            prop_assert!(
                r.confidence <= 0.55 + 1e-9,
                "P6 ceiling breached for an unknown protocol: {} (tier {:?})",
                r.confidence, r.trust_tier
            );
        }
    }

    /// P2: composite inputs must verify deterministically. Aggregation over
    /// instructions and CPI nodes is the most likely place for hash-map
    /// iteration order to leak into an output string.
    #[test]
    fn composite_verification_is_deterministic(input in composite_input()) {
        let core = GraphiteCore::new();
        let a = core.verify(&input);
        let b = core.verify(&input);
        match (a, b) {
            (Ok(x), Ok(y)) => {
                prop_assert_eq!(x.approved, y.approved);
                prop_assert_eq!(&x.content_hash, &y.content_hash);
                prop_assert_eq!(&x.policy_verdict, &y.policy_verdict);
                prop_assert_eq!(&x.risk_verdict.status, &y.risk_verdict.status);
                // Finding ORDER must be stable too, not just the set.
                let xs: Vec<&str> = x.risk_verdict.findings.iter().map(|f| f.pattern.as_str()).collect();
                let ys: Vec<&str> = y.risk_verdict.findings.iter().map(|f| f.pattern.as_str()).collect();
                prop_assert_eq!(xs, ys, "risk finding order must be deterministic");
            }
            (Err(_), Err(_)) => {}
            _ => prop_assert!(false, "verify() disagreed with itself across runs"),
        }
    }

    /// Dilution resistance: once a transaction is blocked, ADDING benign
    /// instructions around the malicious one must never turn it into an
    /// approval. This is the "outvote the detector" attack — an attacker pads
    /// a drain with harmless-looking calls.
    #[test]
    fn adding_benign_instructions_can_never_unblock(
        input in composite_input(),
        padding in prop::collection::vec(
            (any_discriminator(), any_accounts()),
            1..4,
        ),
    ) {
        let core = GraphiteCore::new();
        let Ok(before) = core.verify(&input) else { return Ok(()); };
        if before.approved {
            return Ok(()); // only the blocked case is interesting here
        }

        // Pad with plain SPL transfers, the most ordinary instruction there is.
        let mut padded = input.clone();
        for (_disc, accounts) in padding {
            padded.transaction_instructions.push(TransactionInstruction {
                program_id: SPL.to_string(),
                instruction_discriminator: "03".to_string(),
                account_addresses: accounts,
                cpi_targets: vec![],
            });
        }

        if let Ok(after) = core.verify(&padded) {
            prop_assert!(
                !after.approved,
                "a BLOCKED transaction became APPROVED after adding benign padding — \
                 detection can be diluted. risk before={}, after={}",
                before.risk_verdict.status, after.risk_verdict.status
            );
        }
    }
}

/// Anti-vacuity guard. A property test that never reaches the state it
/// asserts about is worse than no test: it reports green forever while
/// checking nothing. This pins that the generator actually produces
/// approved AND blocked verdicts, risk findings, and multi-instruction
/// inputs — so the invariants above are genuinely exercised.
/// (Caught for real: the first version of this suite produced 0 approvals
/// across 400 cases, silently voiding every approved-side assertion.)
#[test]
fn vacuity_probe_generator_reaches_interesting_states() {
    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::deterministic();
    let core = GraphiteCore::new();
    let (mut approved, mut blocked, mut errored, mut with_findings, mut multi_ix) = (0, 0, 0, 0, 0);
    for _ in 0..400 {
        let tree = composite_input().new_tree(&mut runner).unwrap();
        let input = tree.current();
        if !input.transaction_instructions.is_empty() {
            multi_ix += 1;
        }
        match core.verify(&input) {
            Ok(r) => {
                if r.approved {
                    approved += 1;
                } else {
                    blocked += 1;
                }
                if !r.risk_verdict.findings.is_empty() {
                    with_findings += 1;
                }
            }
            Err(_) => errored += 1,
        }
    }
    eprintln!("VACUITY: approved={approved} blocked={blocked} errored={errored} with_findings={with_findings} multi_ix={multi_ix}");
    assert!(
        blocked > 0,
        "generator never produced a BLOCKED verdict — dilution test is vacuous"
    );
    assert!(
        approved > 0,
        "generator never produced an APPROVED verdict — every `if r.approved` invariant \n         above is passing vacuously"
    );
    assert!(
        with_findings > 0,
        "generator never produced a risk finding — detection paths untested"
    );
    assert!(
        multi_ix > 0,
        "generator never produced multi-instruction input"
    );
}
