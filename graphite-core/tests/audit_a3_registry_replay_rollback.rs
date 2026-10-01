//! A3-07 (2026-09-29 audit): an old registry submission cannot be replayed to
//! roll a manifest back.
//!
//! Signatures and attestations verify over `content_hash`, the SHA-256 of the
//! manifest JSON alone: no registry identity, no sequence, no binding to the
//! current head. `submit` did not compare a submission with what the log
//! already held, and a resubmission at the same computed tier is not a
//! promotion, so the P10 gate did not run. An old accepted manifest handed in
//! again with its old attestations was accepted, and as the newest record it
//! became the manifest in force, rolling back a later correction with no new
//! signature. Registry submission is CLI-only, so the party that can be fed a
//! replay is the operator processing submissions.
//!
//! The fix: `submit` refuses, with `VersionAlreadyAccepted`, a submission whose
//! version label or content hash the log already holds for the program.
//!
//! The test accepts v1, then a v2 that pins a slot, replays byte-identical v1
//! with its old attestation, and pins that the replay is refused or v2 stays in
//! force.

use ed25519_dalek::{Signer, SigningKey};
use graphite_core::manifest::{
    AccountRoleDef, InstructionDef, ManifestVersion, ProtocolInfo, ProtocolManifest,
};
use graphite_core::manifest_registry::{
    ManifestRegistryEngine, ManifestSubmission, ReviewerAttestation,
};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::regression_engine::{record_fixture, RegressionCorpus};
use graphite_core::semantic_graph_store::{BehaviorEvidence, SemanticGraphStore};
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

const PROGRAM: &str = "4rQz2f4Wc1y7DpQ8v6mW2nN5uM3sR9bHjC1kTv8XwYdL";
const USER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";

fn manifest(version: &str, expected: &[&str], prev: Option<&str>) -> ProtocolManifest {
    ProtocolManifest {
        graphite_manifest_version: "1.0".to_string(),
        protocol: ProtocolInfo {
            name: "A3 Replay".to_string(),
            program_id: PROGRAM.to_string(),
            website: String::new(),
            github: String::new(),
            category: String::new(),
        },
        version: ManifestVersion {
            label: version.to_string(),
            effective_from_slot: 0,
            previous_version_ref: prev.map(str::to_string),
        },
        instructions: vec![InstructionDef {
            name: "op".to_string(),
            discriminator: "01".to_string(),
            accounts: vec![AccountRoleDef {
                name: "user".to_string(),
                role: "signer".to_string(),
                is_writable: false,
                is_signer: true,
                pda_seeds: vec![],
                // v2 pins the slot; v1 did not.
                expected_address: expected.iter().map(|s| s.to_string()).collect(),
                optional: false,
            }],
            account_layouts: vec![],
            expected_state_changes: vec!["debits accounts.user".to_string()],
            allowed_cpis: vec![],
            risk_rules: vec![],
            variable_accounts: false,
            risk_class: String::new(),
        }],
        trust_tier: String::new(),
    }
}

fn attested(m: ProtocolManifest, reviewer: &SigningKey, reviewer_b58: &str) -> ManifestSubmission {
    let mut s = ManifestSubmission {
        manifest: m,
        signer_pubkey: None,
        signature_hex: None,
        attestations: vec![],
    };
    let h = s.content_hash();
    s.attestations.push(ReviewerAttestation {
        reviewer_pubkey: reviewer_b58.to_string(),
        signature_hex: hex::encode(reviewer.sign(h.as_bytes()).to_bytes()),
    });
    s
}

fn fixture_input() -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: String::new(),
            confidence_of_parse: 1.0,
            extracted_parameters: None,
        },
        program_id: PROGRAM.to_string(),
        protocol_version: String::new(),
        instruction_discriminator: "01".to_string(),
        account_addresses: vec![USER.to_string()],
        instruction_data: Some(vec![1]),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Treasury,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
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

#[test]
fn replaying_a_superseded_submission_does_not_roll_the_manifest_back() {
    let reviewer = SigningKey::from_bytes(&[9u8; 32]);
    let reviewer_b58 = bs58::encode(reviewer.verifying_key().to_bytes()).into_string();
    let mut engine = ManifestRegistryEngine::new();
    engine.register_reviewer(&reviewer_b58, 1_000).unwrap();
    let mut store = SemanticGraphStore::new();
    let gate_core = GraphiteCore::new();
    let mut corpus = RegressionCorpus::new();
    record_fixture(&mut corpus, &fixture_input(), false, "a3");

    let v1 = attested(manifest("1.0.0", &[], None), &reviewer, &reviewer_b58);
    let v1_replay = v1.clone(); // what anyone holding the old submission has
    engine
        .submit(&mut store, v1, Some((&corpus, &gate_core)))
        .expect("v1 accepted");
    let v2 = attested(
        manifest("2.0.0", &[USER], Some("1.0.0")),
        &reviewer,
        &reviewer_b58,
    );
    engine
        .submit(&mut store, v2, Some((&corpus, &gate_core)))
        .expect("v2 accepted");

    // The replay: byte-identical v1, old attestation, no new signature.
    let replay = engine.submit(&mut store, v1_replay, None);

    let in_force: Vec<String> = engine
        .accepted_manifests()
        .map(|m| m.version.label.clone())
        .collect();
    assert!(
        replay.is_err() || in_force == vec!["2.0.0".to_string()],
        "a replayed v1 submission was {:?} and the manifest in force is now {:?} — the v2 correction \
         (pinned slot) was rolled back without any new signature",
        replay,
        in_force
    );
}
