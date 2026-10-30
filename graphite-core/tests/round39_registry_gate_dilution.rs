//! Round 39 (core-identity, R39-CORE-IDENTITY-1): the registry's P10 replay
//! gate could be diluted.
//!
//! `ManifestRegistryEngine::submit` replays the registry's OWN corpus for the
//! program together with the fixtures the submitter hands in, and promotes
//! when at least 99.5% of them pass (`decide_promotion`). The submitter's
//! fixtures are recorded under the candidate manifest, so they pass by
//! construction, and a fixture's identity covers its `source` string, so one
//! input can be pinned any number of times. 199 padding fixtures therefore
//! let one registry fixture fail. The one that fails can be a REFUSAL the
//! registry pinned when it accepted v1 — the case the gate exists for
//! ("a submission can add fixtures but never remove one", MR-1): a loosening
//! v2 approves what v1 refused, and it was accepted.
//!
//! The fix: a fixture pinned as refused that the candidate approves blocks the
//! promotion outright, whatever the pass rate, and the registry's own fixtures
//! are held to the pass rate on their own, so the submitter's fixtures cannot
//! dilute them. A correction that legitimately approves what was refused goes
//! through the operator's named escape hatch (`deprecate_regression_fixture`).
#![cfg(any(feature = "rpc", feature = "server", feature = "cli"))]

use ed25519_dalek::{Signer, SigningKey};
use graphite_core::manifest::{
    AccountRoleDef, InstructionDef, ManifestVersion, ProtocolInfo, ProtocolManifest,
};
use graphite_core::manifest_registry::{ManifestRegistryEngine, ManifestSubmission, RegistryError};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::regression_engine::{record_fixture, RegressionCorpus};
use graphite_core::semantic_graph_store::{BehaviorEvidence, SemanticGraphStore, TrustTier};
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

/// No shipped seed manifest, so a candidate for it takes effect.
const PROGRAM: &str = "GdP9U5aYx7f2kQzVwNmT8jRcL4hB6eX3sDnWqA1uMoH";
const ACCT_A: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const ACCT_B: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

fn key(seed: u8) -> (SigningKey, String) {
    let k = SigningKey::from_bytes(&[seed; 32]);
    let b58 = bs58::encode(k.verifying_key().to_bytes()).into_string();
    (k, b58)
}

fn manifest(label: &str, prev: Option<&str>, risk_class: &str) -> ProtocolManifest {
    let accounts = [("from", true), ("to", false)]
        .into_iter()
        .map(|(name, is_signer)| AccountRoleDef {
            name: name.to_string(),
            role: "writable".to_string(),
            is_writable: true,
            is_signer,
            pda_seeds: vec![],
            expected_address: vec![],
            optional: false,
        })
        .collect();
    ProtocolManifest {
        graphite_manifest_version: "1.0".to_string(),
        protocol: ProtocolInfo {
            name: "Guarded".to_string(),
            program_id: PROGRAM.to_string(),
            website: String::new(),
            github: String::new(),
            category: String::new(),
        },
        version: ManifestVersion {
            label: label.to_string(),
            effective_from_slot: 0,
            previous_version_ref: prev.map(str::to_string),
        },
        instructions: vec![InstructionDef {
            name: "TestOp".to_string(),
            discriminator: "01".to_string(),
            accounts,
            account_layouts: vec![],
            expected_state_changes: vec!["debits accounts.from".to_string()],
            allowed_cpis: vec![],
            risk_rules: vec![],
            variable_accounts: false,
            risk_class: risk_class.to_string(),
        }],
        trust_tier: String::new(),
    }
}

fn signed(m: ProtocolManifest, signer: &(SigningKey, String)) -> ManifestSubmission {
    let mut s = ManifestSubmission {
        manifest: m,
        signer_pubkey: Some(signer.1.clone()),
        signature_hex: None,
        attestations: vec![],
    };
    let message = s.signing_message();
    s.signature_hex = Some(hex::encode(signer.0.sign(&message).to_bytes()));
    s
}

/// The instruction v1 pins as refused (its class is `authority`).
fn pinned_input() -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "test".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: PROGRAM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "01".to_string(),
        account_addresses: vec![ACCT_A.to_string(), ACCT_B.to_string()],
        instruction_data: None,
        cpi_targets: vec![],
        // Round 40 (R39-CORE-IDENTITY-7): the profile was (0.40,
        // OfficialManifest). A first version is now replayed at
        // HeuristicInferred, where that floor refused every fixture whatever
        // its class (and its confidence is 0.36); at (0.30,
        // HeuristicInferred) the outcome depends on the instruction's class
        // at either tier, which is what these tests are about.
        wallet_profile: WalletProfile::Custom {
            min_confidence: 0.30,
            min_trust_tier: TrustTier::HeuristicInferred,
        },
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        real_account_metas: vec![],
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        state_diff: None,
    }
}

/// A corpus of `n` fixtures that each record what `submission`'s manifest
/// does with the pinned input — at `tier`, the tier the registry replays it
/// at (Round 40: `HeuristicInferred` for a first version, or an upgrade with
/// no earlier fixture left in force; `OfficialManifest` for a registered
/// reviewer's signed upgrade) — under `n` provenance strings: distinct
/// identities for one input.
fn recorded_under(
    core: &GraphiteCore,
    submission: &ManifestSubmission,
    n: usize,
    tag: &str,
) -> RegressionCorpus {
    // A first version ("v1.0" here, named by no previous_version_ref) is
    // replayed at HeuristicInferred since Round 40.
    let tier = if submission.manifest.version.previous_version_ref.is_none() {
        "HeuristicInferred"
    } else {
        "OfficialManifest"
    };
    recorded_at(core, submission, n, tag, tier)
}

fn recorded_at(
    core: &GraphiteCore,
    submission: &ManifestSubmission,
    n: usize,
    tag: &str,
    tier: &str,
) -> RegressionCorpus {
    let mut at_gate_tier = submission.manifest.clone();
    at_gate_tier.trust_tier = tier.to_string();
    let candidate = core.with_candidate_manifest(&at_gate_tier).unwrap();
    let outcome = candidate.verify(&pinned_input()).unwrap().approved;
    let mut corpus = RegressionCorpus::new();
    for i in 0..n {
        record_fixture(&mut corpus, &pinned_input(), outcome, &format!("{tag}-{i}"));
    }
    corpus
}

/// An engine that accepted v1, which pins the input as refused.
fn engine_with_v1(core: &GraphiteCore) -> (ManifestRegistryEngine, SemanticGraphStore) {
    let mut engine = ManifestRegistryEngine::new();
    let mut store = SemanticGraphStore::new();
    let (a, b) = (key(71), key(72));
    engine.register_reviewer(&a.1, 1000).unwrap();
    engine.register_reviewer(&b.1, 1000).unwrap();
    let v1 = signed(manifest("v1.0", None, "authority"), &a);
    let corpus = recorded_under(core, &v1, 1, "v1");
    assert!(
        !corpus.all()[0].expected_approved,
        "precondition: v1 refuses the instruction it pins"
    );
    engine
        .submit(&mut store, v1, Some((&corpus, core)))
        .expect("v1 accepted");
    (engine, store)
}

#[test]
fn padding_the_submitted_corpus_does_not_let_an_upgrade_approve_a_pinned_refusal() {
    let core = GraphiteCore::new();
    let (mut engine, mut store) = engine_with_v1(&core);
    let v2 = signed(manifest("v2.0", Some("v1.0"), "transfer"), &key(72));
    let padding = recorded_under(&core, &v2, 250, "v2");
    assert!(
        padding.all().iter().all(|f| f.expected_approved),
        "precondition: the loosened v2 approves what v1 refused"
    );
    let decision = engine.submit(&mut store, v2, Some((&padding, &core)));
    assert!(
        matches!(decision, Err(RegistryError::RegressionGateBlocked(_))),
        "a loosening v2 was accepted by padding the corpus with 250 self-consistent fixtures: {decision:?}"
    );
    assert_eq!(engine.manifests_in_force()[0].version.label, "v1.0");
}

/// Control: without padding the same v2 is blocked (MR-1, as before).
#[test]
fn the_same_upgrade_without_padding_is_blocked() {
    let core = GraphiteCore::new();
    let (mut engine, mut store) = engine_with_v1(&core);
    let v2 = signed(manifest("v2.0", Some("v1.0"), "transfer"), &key(72));
    let one = recorded_under(&core, &v2, 1, "v2");
    assert!(matches!(
        engine.submit(&mut store, v2, Some((&one, &core))),
        Err(RegistryError::RegressionGateBlocked(_))
    ));
}

/// Benign control: an upgrade that keeps the refusal (another label, the same
/// class, a reworded declaration) is still accepted, padded or not.
#[test]
fn an_upgrade_that_keeps_the_pinned_refusal_is_accepted() {
    let core = GraphiteCore::new();
    let (mut engine, mut store) = engine_with_v1(&core);
    let mut m = manifest("v2.0", Some("v1.0"), "authority");
    m.instructions[0].expected_state_changes = vec!["debits accounts.from by amount".to_string()];
    let v2 = signed(m, &key(72));
    let corpus = recorded_under(&core, &v2, 250, "v2");
    assert!(corpus.all().iter().all(|f| !f.expected_approved));
    engine
        .submit(&mut store, v2, Some((&corpus, &core)))
        .expect("an upgrade that keeps the refusal is accepted");
    assert_eq!(engine.manifests_in_force()[0].version.label, "v2.0");
}

/// The escape hatch: once the operator retires the pinned refusal by name, a
/// correction that approves the instruction is judged on what is left.
#[test]
fn a_retired_refusal_no_longer_holds_the_upgrade_back() {
    let core = GraphiteCore::new();
    let (mut engine, mut store) = engine_with_v1(&core);
    let pinned: Vec<String> = engine
        .regression_corpus()
        .fixtures_for(PROGRAM)
        .iter()
        .map(|f| f.content_hash.clone())
        .collect();
    for hash in &pinned {
        assert!(engine.deprecate_regression_fixture(hash));
    }
    let v2 = signed(manifest("v2.0", Some("v1.0"), "transfer"), &key(72));
    // Round 40: with every earlier fixture retired its replay validates
    // nothing independent, so it is capped and replayed at HeuristicInferred.
    let corpus = recorded_at(&core, &v2, 1, "v2", "HeuristicInferred");
    assert_eq!(
        engine
            .submit(&mut store, v2, Some((&corpus, &core)))
            .expect("accepted once the operator retired the refusal"),
        graphite_core::manifest_registry::RegistryDecision::Accepted {
            trust_tier: TrustTier::HeuristicInferred,
            version_label: "v2.0".to_string(),
        }
    );
}

/// The first arm on its own: a registry whose OWN corpus is large. v1 pins
/// 250 approvals of one instruction (`02`) and one refusal of another (`01`).
/// A v2 that approves `01` fails 1 of 251 registry fixtures — 99.6%, above
/// the bar for the registry's fixtures alone and for the whole replay — so
/// only the rule that a pinned refusal may never turn into an approval
/// blocks it.
#[test]
fn a_large_registry_corpus_does_not_tolerate_one_loosened_refusal() {
    let core = GraphiteCore::new();
    let mut engine = ManifestRegistryEngine::new();
    let mut store = SemanticGraphStore::new();
    let (a, b) = (key(75), key(76));
    engine.register_reviewer(&a.1, 1000).unwrap();
    engine.register_reviewer(&b.1, 1000).unwrap();
    let two_ops = |label: &str, prev: Option<&str>, class01: &str| {
        let mut m = manifest(label, prev, class01);
        let mut op2 = m.instructions[0].clone();
        op2.name = "OtherOp".to_string();
        op2.discriminator = "02".to_string();
        op2.risk_class = "transfer".to_string();
        m.instructions.push(op2);
        m
    };
    // Round 40: v1 (a first version) is replayed at HeuristicInferred, v2
    // (a signed upgrade) at OfficialManifest.
    let at_gate = |s: &ManifestSubmission| {
        let mut m = s.manifest.clone();
        m.trust_tier = if s.manifest.version.previous_version_ref.is_none() {
            "HeuristicInferred"
        } else {
            "OfficialManifest"
        }
        .to_string();
        core.with_candidate_manifest(&m).unwrap()
    };
    let mut other = pinned_input();
    other.instruction_discriminator = "02".to_string();

    let v1 = signed(two_ops("v1.0", None, "authority"), &a);
    let v1_core = at_gate(&v1);
    assert!(!v1_core.verify(&pinned_input()).unwrap().approved);
    assert!(v1_core.verify(&other).unwrap().approved);
    let mut corpus = RegressionCorpus::new();
    record_fixture(&mut corpus, &pinned_input(), false, "v1-refusal");
    for i in 0..250 {
        record_fixture(&mut corpus, &other, true, &format!("v1-approval-{i}"));
    }
    engine
        .submit(&mut store, v1, Some((&corpus, &core)))
        .expect("v1 accepted");
    assert_eq!(engine.regression_corpus().fixtures_for(PROGRAM).len(), 251);

    let v2 = signed(two_ops("v2.0", Some("v1.0"), "transfer"), &b);
    assert!(
        at_gate(&v2).verify(&pinned_input()).unwrap().approved,
        "precondition: v2 approves what v1 refused"
    );
    let decision = engine.submit(&mut store, v2, Some((&RegressionCorpus::new(), &core)));
    assert!(
        matches!(&decision, Err(RegistryError::RegressionGateBlocked(reason)) if reason.contains("pinned as refused")),
        "one loosened refusal among 251 pinned fixtures was tolerated: {decision:?}"
    );
}

/// The second arm: the registry's own fixtures meet the pass rate on their
/// own. v1 pins an APPROVAL; a v2 that refuses it was blocked without padding
/// (1 of 1 failed) and, before this round, accepted with 250 padding fixtures
/// (1 of 251). Either way a change of a pinned outcome now needs the operator
/// to retire the fixture — padding does not stand in for that.
#[test]
fn padding_does_not_dilute_the_registrys_own_fixtures() {
    let core = GraphiteCore::new();
    let mut engine = ManifestRegistryEngine::new();
    let mut store = SemanticGraphStore::new();
    let (a, b) = (key(73), key(74));
    engine.register_reviewer(&a.1, 1000).unwrap();
    engine.register_reviewer(&b.1, 1000).unwrap();
    let v1 = signed(manifest("v1.0", None, "transfer"), &a);
    let corpus = recorded_under(&core, &v1, 1, "v1");
    assert!(
        corpus.all()[0].expected_approved,
        "precondition: v1 approves"
    );
    engine
        .submit(&mut store, v1, Some((&corpus, &core)))
        .expect("v1 accepted");
    let v2 = signed(manifest("v2.0", Some("v1.0"), "authority"), &b);
    let padding = recorded_under(&core, &v2, 250, "v2");
    assert!(padding.all().iter().all(|f| !f.expected_approved));
    let decision = engine.submit(&mut store, v2, Some((&padding, &core)));
    assert!(
        matches!(&decision, Err(RegistryError::RegressionGateBlocked(reason)) if reason.contains("registry's own fixtures")),
        "{decision:?}"
    );
}
