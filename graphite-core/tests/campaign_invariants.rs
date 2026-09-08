//! MISSION 11 — the invariants behind the findings, not the findings again.
//!
//! Every defect this campaign found already has a regression test pinning that
//! exact case. That is necessary and it is also how a suite overfits: the next
//! attacker does not reuse the fee field, they find the next unbounded number.
//!
//! So each defect was reduced to the rule it broke, and each rule is checked
//! here at surfaces OTHER than the one it was discovered on. A rule that only
//! holds where it was found is a coincidence.
//!
//! The five rules, and where each came from:
//!
//! **I1 — An absent check reports its absence, in words no passing check uses.**
//! From L4 reporting "State verification passed" in identical wording whether it
//! had built a real diff or fallen back to a shape heuristic, and from L3 and L8
//! calling themselves unimplemented phases long after they were implemented.
//!
//! **I2 — A number that grants credit is bounded by something its supplier does
//! not control.** From `fee_lamports`, where the RPC chose both the balances and
//! the fee that reconciles them; from `unitsConsumed`, where one impossible
//! figure permanently disabled L3 for a program; from response bodies and error
//! strings, where the peer chose Graphite's memory and its audit trail.
//!
//! **I3 — Unreadable input is absent, never zero.** From balances reported as
//! floats deriving "no account changed", and from unreadable inner-instruction
//! groups being dropped so a deep CPI tree counted as shallow.
//!
//! **I4 — Nothing outside the deterministic core may add to a verdict; it may
//! only subtract.** From `PluginVerdict` having no approving variant, and from
//! the RPC's ceiling on how far it can move the score.
//!
//! **I5 — A finding is named for the check that produced it.** From every plugin
//! veto being recorded on the append-only trail as the `Drainer` pattern — a
//! specific accusation Graphite had not made.

use graphite_core::state_diff::{
    check_state_diff, AccountDelta, AccountSnapshot, DiffProvenance, StateDiff, StateDiffCheck,
    MAX_PLAUSIBLE_FEE_LAMPORTS,
};
use graphite_core::verification::{GraphiteCore, LayerStatus, ProposedIntent, VerificationInput};
use graphite_core::{BehaviorEvidence, WalletProfile};

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const FROM: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const TO: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

fn base(intent_confidence: f64) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send SOL".to_string(),
            confidence_of_parse: intent_confidence,
            extracted_parameters: None,
        },
        program_id: SYSTEM_PROGRAM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![FROM.to_string(), TO.to_string()],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 5,
            battle_tested_tx_count: 50_000,
            simulation_match_count: 100,
        },
        compute_units: 300,
        account_writes: 2,
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

// ════════════════════════════════════════════════════════════════════════════
// I1 — an absent check reports its absence.
// ════════════════════════════════════════════════════════════════════════════

/// Checked across every layer that can be unable to run, rather than only at
/// L4 where the problem was found.
///
/// The failure mode this guards is specific: a layer that could not do its work
/// reporting in the words of one that did. An operator reading "verification
/// passed" cannot tell those apart, and neither can an automated consumer.
#[test]
fn no_layer_that_could_not_run_reports_in_the_words_of_one_that_did() {
    // No RPC attached, so L3 has no simulation and L4 has no diff — the exact
    // configuration in which the pipeline is most tempted to sound complete.
    let result = GraphiteCore::new().verify(&base(0.95)).expect("verify ok");

    for layer in &result.layers {
        if matches!(layer.status, LayerStatus::Inconclusive) {
            let r = layer.reason.to_lowercase();
            // An inconclusive layer must not describe itself as having verified
            // anything. "not verified" and "cannot be verified" are fine; the
            // bare claim is not.
            let claims_success = (r.contains("verified") || r.contains("passed"))
                && !r.contains("not ")
                && !r.contains("no ")
                && !r.contains("cannot")
                && !r.contains("could not")
                && !r.contains("unable");
            assert!(
                !claims_success,
                "{} is Inconclusive but its reason reads as a completed check: {}",
                layer.layer, layer.reason
            );
        }
    }
}

/// The same rule from the other side: an inconclusive layer must say something.
///
/// A silent skip is the version of this bug that no wording check catches.
#[test]
fn an_inconclusive_layer_always_explains_itself() {
    let result = GraphiteCore::new().verify(&base(0.95)).expect("verify ok");
    for layer in &result.layers {
        if matches!(layer.status, LayerStatus::Inconclusive) {
            assert!(
                layer.reason.trim().len() > 20,
                "{} is Inconclusive with no usable explanation (P3): {:?}",
                layer.layer,
                layer.reason
            );
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// I2 — a number that grants credit is bounded.
// ════════════════════════════════════════════════════════════════════════════

/// Run the diff checks with nothing declared and no grounded privileges, so the
/// only thing that can produce a finding is the diff's own integrity.
fn check(diff: &StateDiff) -> graphite_core::state_diff::StateDiffReport {
    check_state_diff(&StateDiffCheck {
        diff,
        resolved_accounts: &[],
        privileges_grounded: false,
        expected_state_changes: &[],
        fee_payer: Some(FROM),
    })
}

fn delta(pubkey: &str, before: u64, after: u64) -> AccountDelta {
    AccountDelta {
        pubkey: pubkey.to_string(),
        before: Some(AccountSnapshot::from_raw(
            pubkey,
            before,
            SYSTEM_PROGRAM,
            &[],
        )),
        after: Some(AccountSnapshot::from_raw(
            pubkey,
            after,
            SYSTEM_PROGRAM,
            &[],
        )),
    }
}

/// The fee bound checked on the CALLER path, not the RPC path it was found on.
///
/// `state_diff` is a public input: a caller can hand Graphite a diff directly,
/// with no network involved, and assert whatever fee balances it. If the bound
/// lived in the RPC client it would not be a rule, only a patch on one route.
#[test]
fn an_implausible_fee_is_refused_wherever_the_diff_came_from() {
    let drained = 4_900_000_000u64;
    let diff = StateDiff {
        deltas: vec![delta(FROM, 5_000_000_000, 100_000_000)],
        provenance: DiffProvenance::CallerSupplied,
        // Exactly the shortfall, declared a fee.
        fee_lamports: drained,
        covers_all_writable: true,
        // No artifact was simulated in this fixture, so there is no
        // measured effect count to compare coverage against.
        artifact_balance_writes: None,
        artifact_account_universe: None,
    };
    let report = check(&diff);
    let codes: Vec<&str> = report.findings.iter().map(|f| f.code.as_str()).collect();
    assert!(
        codes.contains(&"ImplausibleFee"),
        "a caller-supplied diff balanced its own books with a {drained}-lamport 'fee' and \
         nothing objected: {codes:?}"
    );
    assert!(
        report.blocked,
        "the diff was not usable as evidence but the report did not say so"
    );
}

/// The bound has to be a real bound, not a formality: a fee at the ceiling is
/// accepted and one above it is not.
#[test]
fn the_fee_ceiling_is_where_it_says_it_is() {
    let at_ceiling = StateDiff {
        deltas: vec![delta(
            FROM,
            1_000_000_000,
            1_000_000_000 - MAX_PLAUSIBLE_FEE_LAMPORTS,
        )],
        provenance: DiffProvenance::RpcSimulated,
        fee_lamports: MAX_PLAUSIBLE_FEE_LAMPORTS,
        covers_all_writable: true,
        // No artifact was simulated in this fixture, so there is no
        // measured effect count to compare coverage against.
        artifact_balance_writes: None,
        artifact_account_universe: None,
    };
    let ok = check(&at_ceiling);
    assert!(
        !ok.findings.iter().any(|f| f.code == "ImplausibleFee"),
        "a fee exactly at the documented ceiling was rejected — the bound is off by one and \
         will reject legitimate traffic"
    );

    let over = StateDiff {
        deltas: vec![delta(
            FROM,
            1_000_000_000,
            1_000_000_000 - MAX_PLAUSIBLE_FEE_LAMPORTS - 1,
        )],
        provenance: DiffProvenance::RpcSimulated,
        fee_lamports: MAX_PLAUSIBLE_FEE_LAMPORTS + 1,
        covers_all_writable: true,
        // No artifact was simulated in this fixture, so there is no
        // measured effect count to compare coverage against.
        artifact_balance_writes: None,
        artifact_account_universe: None,
    };
    let bad = check(&over);
    assert!(
        bad.findings.iter().any(|f| f.code == "ImplausibleFee"),
        "one lamport over the ceiling was accepted — the bound does not bind"
    );
}

/// The AI's own confidence in its parse is accepted and never read.
///
/// It is the purest case of I4 expressed as a number: a value the advisory layer
/// chooses about its own reliability. If it moved the score, an AI layer that
/// was confidently wrong would be worth more than one that was honestly unsure,
/// which is exactly backwards. The schema already says it is "NOT a verification
/// confidence score"; this asserts that Graphite behaves that way.
#[test]
fn the_ai_layers_confidence_in_itself_does_not_move_the_verdict() {
    let core = GraphiteCore::new();
    let unsure = core.verify(&base(0.0)).expect("verify ok");
    let certain = core.verify(&base(1.0)).expect("verify ok");

    assert_eq!(
        unsure.approved, certain.approved,
        "the AI's self-reported parse confidence changed the verdict"
    );
    assert!(
        (unsure.confidence - certain.confidence).abs() < 1e-9,
        "the AI's self-reported parse confidence moved Graphite's confidence score: \
         {:.6} at 0.0 vs {:.6} at 1.0",
        unsure.confidence,
        certain.confidence
    );
}

// ════════════════════════════════════════════════════════════════════════════
// I3 — unreadable is absent, never zero.
// ════════════════════════════════════════════════════════════════════════════

/// Checked at the RPC parser, across every field the derivations read.
///
/// The shape of this bug is always the same: a parse that fails, a comparison
/// that then finds no difference, and a caller that reads "no difference" as a
/// measurement. Zero is a claim; absent is not.
#[cfg(feature = "rpc")]
#[test]
fn every_unparseable_simulation_field_is_none_rather_than_zero() {
    use graphite_core::rpc_client::simulation_result_from_value_for_test as parse;

    // Balances that are not integers.
    for bad in [
        r#"{"unitsConsumed":300,"preBalances":[1.5,2.5],"postBalances":[1.5,2.5]}"#,
        r#"{"unitsConsumed":300,"preBalances":["1","2"],"postBalances":["1","2"]}"#,
        r#"{"unitsConsumed":300,"preBalances":[-1,-2],"postBalances":[-1,-2]}"#,
    ] {
        let v: serde_json::Value = serde_json::from_str(bad).unwrap();
        let r = parse(&v).expect("parse must not error");
        assert_eq!(
            r.account_writes, None,
            "balances Graphite cannot read produced a write count instead of no answer: {bad}"
        );
    }

    // Inner instructions whose shape is unreadable: one bad group makes the
    // total unknown, never smaller.
    let v: serde_json::Value = serde_json::from_str(
        r#"{"unitsConsumed":300,"innerInstructions":[{"instructions":[{},{}]},{"instructions":"nope"}]}"#,
    )
    .unwrap();
    let r = parse(&v).expect("parse must not error");
    assert_eq!(
        r.cpi_hops, None,
        "an unreadable inner-instruction group was dropped, undercounting CPI hops to {:?} — \
         the direction that makes a deep call tree look shallow",
        r.cpi_hops
    );

    // And the readable case still works, so none of the above is achieved by
    // refusing everything.
    let v: serde_json::Value = serde_json::from_str(
        r#"{"unitsConsumed":300,"preBalances":[10,20],"postBalances":[9,21],
            "innerInstructions":[{"instructions":[{},{}]}]}"#,
    )
    .unwrap();
    let r = parse(&v).expect("parse must not error");
    assert_eq!(r.account_writes, Some(2));
    assert_eq!(r.cpi_hops, Some(2));
}

// ════════════════════════════════════════════════════════════════════════════
// I5 — a finding is named for the check that produced it.
// ════════════════════════════════════════════════════════════════════════════

/// Every risk pattern name is distinct and non-empty.
///
/// The `Drainer`-for-plugin-blocks defect was two variants sharing one name in
/// the report. This is the cheap general guard: if a new outcome is ever given
/// an existing pattern's name because the enum had no word for it, the names
/// collide here.
#[test]
fn every_risk_pattern_has_its_own_name() {
    use graphite_core::risk_engine::RiskPattern::*;
    let all = [
        Drainer,
        HiddenTransfer,
        AuthorityHijack,
        FakeSwap,
        UnexpectedCpi,
        PermissionEscalation,
        MaliciousAccountChange,
        CompositionalDrainPattern,
        Impersonation,
        MultiInstructionDrain,
        CpiTraceAnomaly,
        UnspendableDestination,
        PluginBlock,
    ];
    let mut names: Vec<&str> = all.iter().map(|p| p.name()).collect();
    let count = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        count,
        "two risk patterns report the same name, so a finding cannot be attributed to the \
         check that produced it: {names:?}"
    );
    assert!(
        names.iter().all(|n| !n.trim().is_empty()),
        "a risk pattern reports an empty name"
    );
}
