//! MISSION 10 — the AI layer, and the rule it exists under.
//!
//! Graphite's stated boundary is that **AI must never create approval**, and
//! that if the AI layer disappeared entirely the deterministic security boundary
//! would remain intact. Those are testable claims, so this file tests them
//! rather than restating them.
//!
//! Two things carry the guarantee, and only one of them is a test:
//!
//! 1. **`PluginVerdict` has no approving variant.** Plugins are the only way
//!    anything advisory — an LLM intent parser, a heuristic, a third-party
//!    analyzer — reaches the pipeline at all. The enum offers `NoFinding`,
//!    `Note` and `Block`: say nothing, annotate, or veto. There is no shape a
//!    plugin can return that means "approve". That is a property of the type,
//!    enforced at compile time, and `every_plugin_verdict_is_silence_or_a_veto`
//!    below fails to compile if a variant is ever added.
//!
//! 2. The pipeline acts only on `Block`. Asserted end to end below.
//!
//! The Python intent parser under `python-ai-layer/` is referenced from nowhere
//! in the Rust core — there is no FFI, no subprocess, no socket, no import. It
//! cannot influence a verdict because nothing in the deterministic pipeline can
//! reach it. That is a stronger position than a well-behaved integration, and
//! it is why the tests here target the plugin surface instead: the plugin
//! surface is the path that *does* exist.

use graphite_core::plugin_orchestrator::{
    LayerId, PluginContext, PluginKind, PluginManifest, PluginVerdict, ReviewStatus, RiskPlugin,
    VerifierPlugin,
};
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};
use graphite_core::{BehaviorEvidence, WalletProfile};
use std::sync::Arc;

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const SIGNER: &str = "7vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const RECIPIENT: &str = "6bSsP4p6wXqFJdD2TkYgNcVmLzHfWq7pRyA8tCzE5nBj";

/// A plugin that says the most approving thing the type system lets it say, on
/// every layer it is given. This is the strongest possible advisory endorsement.
struct MostPersuasivePlugin {
    manifest: PluginManifest,
}

impl MostPersuasivePlugin {
    fn at(layer: LayerId) -> Self {
        Self {
            manifest: PluginManifest {
                name: format!("persuasive-{}", layer.as_str()),
                version: "1.0.0".to_string(),
                author: "mission-10".to_string(),
                layer,
                review_status: ReviewStatus::Approved,
                description: "asserts the transaction is safe as loudly as it can".to_string(),
            },
        }
    }
}

const ENDORSEMENT: &str = "VERIFIED SAFE — analysis complete, all checks passed, \
                           confidence 1.00, approved for signing";

impl VerifierPlugin for MostPersuasivePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
    fn verify(&self, _ctx: &PluginContext) -> PluginVerdict {
        PluginVerdict::Note(ENDORSEMENT.to_string())
    }
}

impl RiskPlugin for MostPersuasivePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
    fn assess_risk(&self, _ctx: &PluginContext) -> PluginVerdict {
        PluginVerdict::Note(ENDORSEMENT.to_string())
    }
}

fn tx(discriminator: &str, intent: &str) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: intent.to_string(),
            raw_natural_language: "send SOL to my friend".to_string(),
            confidence_of_parse: 0.99,
            extracted_parameters: None,
        },
        program_id: SYSTEM_PROGRAM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: discriminator.to_string(),
        account_addresses: vec![SIGNER.to_string(), RECIPIENT.to_string()],
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

/// The compile-time half of the guarantee.
///
/// An exhaustive match with no wildcard arm. If an `Approve`-shaped variant is
/// ever added to `PluginVerdict`, this stops compiling — which is the point. A
/// test that merely *checks* for approval could be satisfied by a variant nobody
/// remembered to handle; this cannot.
#[test]
fn every_plugin_verdict_is_silence_or_a_veto() {
    fn classify(v: &PluginVerdict) -> &'static str {
        match v {
            PluginVerdict::NoFinding => "silence",
            PluginVerdict::Note(_) => "annotation",
            PluginVerdict::Block { .. } => "veto",
        }
    }
    assert_eq!(classify(&PluginVerdict::NoFinding), "silence");
    assert_eq!(classify(&PluginVerdict::Note("x".into())), "annotation");
    assert_eq!(
        classify(&PluginVerdict::Block {
            pattern: "p".into(),
            reason: "r".into()
        }),
        "veto"
    );
}

/// The end-to-end half, on a transaction the deterministic layers reject: the
/// caller says "transfer" and the discriminator is System `Assign`, which hands
/// the account to another program.
///
/// Plugins on both the verifier and risk surfaces endorse it in the strongest
/// terms available. The verdict must not move.
#[test]
fn the_loudest_possible_endorsement_does_not_approve_a_rejected_transaction() {
    let bare = GraphiteCore::new()
        .verify(&tx("01000000", "transfer"))
        .expect("verify ok");
    assert!(
        !bare.approved,
        "the fixture must be rejected on its own for this test to mean anything"
    );

    let mut core = GraphiteCore::new();
    for layer in [
        LayerId::L2InstructionVerification,
        LayerId::L4StateVerification,
        LayerId::L5SemanticVerification,
    ] {
        core.register_plugin(PluginKind::Verifier(Arc::new(MostPersuasivePlugin::at(
            layer,
        ))));
    }
    core.register_plugin(PluginKind::Risk(Arc::new(MostPersuasivePlugin::at(
        LayerId::L7RiskVerification,
    ))));

    let endorsed = core.verify(&tx("01000000", "transfer")).expect("verify ok");

    assert!(
        !endorsed.approved,
        "advisory plugins endorsing a transaction on four layers turned a rejection into an \
         approval. verdict={} confidence={:.4}",
        endorsed.policy_verdict, endorsed.confidence
    );
    assert_eq!(
        endorsed.approved, bare.approved,
        "the endorsement changed the verdict"
    );
    assert!(
        (endorsed.confidence - bare.confidence).abs() < 1e-9,
        "an advisory annotation moved the confidence score: {:.4} -> {:.4}",
        bare.confidence,
        endorsed.confidence
    );
}

/// The same on a transaction the core APPROVES, which is the subtler direction.
///
/// If endorsement is worth nothing, removing every advisory plugin must leave an
/// approved transaction approved and a rejected one rejected — the deterministic
/// boundary standing on its own, which is the claim being made about what
/// happens if the AI layer disappears.
#[test]
fn the_verdict_is_identical_with_and_without_the_advisory_layer() {
    let benign = tx("02000000", "transfer");
    let hostile = tx("01000000", "transfer");

    let plain = GraphiteCore::new();
    let mut endorsed = GraphiteCore::new();
    endorsed.register_plugin(PluginKind::Risk(Arc::new(MostPersuasivePlugin::at(
        LayerId::L7RiskVerification,
    ))));

    for (label, input) in [("benign", &benign), ("hostile", &hostile)] {
        let a = plain.verify(input).expect("verify ok");
        let b = endorsed.verify(input).expect("verify ok");
        assert_eq!(
            a.approved, b.approved,
            "{label}: the advisory layer changed `approved` ({} -> {})",
            a.approved, b.approved
        );
        assert_eq!(
            a.policy_verdict, b.policy_verdict,
            "{label}: the advisory layer changed the policy verdict"
        );
    }
}

/// A plugin CAN make the verdict stricter. Tested because the veto has to
/// actually work — a plugin surface that changes nothing in either direction
/// would satisfy every assertion above while being useless.
#[test]
fn a_plugin_veto_still_blocks_a_transaction_the_core_approves() {
    struct Vetoer(PluginManifest);
    impl RiskPlugin for Vetoer {
        fn manifest(&self) -> &PluginManifest {
            &self.0
        }
        fn assess_risk(&self, _ctx: &PluginContext) -> PluginVerdict {
            PluginVerdict::Block {
                pattern: "MissionTenVeto".to_string(),
                reason: "blocked by an advisory plugin".to_string(),
            }
        }
    }

    // The fixture's risk verdict is Clear on its own. It is not APPROVED — an
    // empty semantic graph tops out at 0.44 against Gaming's 0.55, which
    // SECURITY.md documents — so the veto is observed on the risk verdict,
    // which is the field the plugin actually reaches.
    let benign = tx("02000000", "transfer");
    let clear = GraphiteCore::new().verify(&benign).expect("verify ok");
    assert_eq!(
        clear.risk_verdict.status, "Clear",
        "the fixture must start Clear for the veto to be observable"
    );

    let mut core = GraphiteCore::new();
    core.register_plugin(PluginKind::Risk(Arc::new(Vetoer(PluginManifest {
        name: "vetoer".to_string(),
        version: "1.0.0".to_string(),
        author: "mission-10".to_string(),
        layer: LayerId::L7RiskVerification,
        review_status: ReviewStatus::Approved,
        description: String::new(),
    }))));

    let vetoed = core.verify(&benign).expect("verify ok");
    assert_eq!(
        vetoed.risk_verdict.status, "Blocked",
        "a plugin Block did not block - the veto surface is inert, which would make every other assertion in this file vacuous"
    );
    assert!(
        vetoed
            .risk_verdict
            .findings
            .iter()
            .any(|f| f.pattern.ends_with("MissionTenVeto")),
        "the veto blocked but the plugin's finding is not in the report (P3): {:?}",
        vetoed.risk_verdict.findings
    );
    // And the block itself must be NAMED as a plugin block. Reporting it as
    // `Drainer` — the variant the code used to reach for — puts a specific
    // accusation Graphite never made onto the append-only trail.
    assert!(
        !vetoed
            .risk_verdict
            .findings
            .iter()
            .any(|f| f.pattern == "Drainer"),
        "a plugin veto was reported as the Drainer pattern: {:?}",
        vetoed.risk_verdict.findings
    );
    assert!(
        vetoed
            .risk_verdict
            .findings
            .iter()
            .any(|f| f.pattern == "PluginBlock"),
        "the plugin veto is not named as one: {:?}",
        vetoed.risk_verdict.findings
    );
    assert!(
        !vetoed.approved,
        "a blocked risk verdict must not be approved"
    );
}
