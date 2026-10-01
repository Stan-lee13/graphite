//! A3-06 (2026-09-29 audit): a community manifest's tier on the verdict path
//! is the one the registry computed, not the one its document declares.
//!
//! `ManifestRegistryEngine::submit` computes a submission's tier from its
//! evidence (P7), but the verification core merged the accepted manifest and
//! `verify_async` read the document's own `trust_tier` string, capped at
//! `OfficialManifest`. A submission that earned `HeuristicInferred` from one
//! reviewer attestation and wrote "OfficialManifest" into its own document was
//! verified at `OfficialManifest`: a confidence ceiling of 0.75 instead of
//! 0.55, and a TrustTierLevel signal of 0.70 instead of 0.30. P7: a tier is
//! computed from evidence, never asserted.
//!
//! The fix: `ManifestRegistryEngine::manifests_in_force` overrides each
//! manifest's tier with the registry's computed tier, and
//! `merge_community_manifests` merges only those.
//!
//! The test submits such a manifest with one independent attestation, checks
//! that the registry computed `HeuristicInferred`, merges it into a core, and
//! pins that the verdict's trust tier is `HeuristicInferred`.

use ed25519_dalek::{Signer, SigningKey};
use graphite_core::confidence_engine::TrustTier;
use graphite_core::manifest::{
    AccountRoleDef, InstructionDef, ManifestVersion, ProtocolInfo, ProtocolManifest,
};
use graphite_core::manifest_registry::{
    ManifestRegistryEngine, ManifestSubmission, RegistryDecision, ReviewerAttestation,
};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::regression_engine::{record_fixture, RegressionCorpus};
use graphite_core::semantic_graph_store::{BehaviorEvidence, SemanticGraphStore};
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

const PROGRAM: &str = "4rQz2f4Wc1y7DpQ8v6mW2nN5uM3sR9bHjC1kTv8XwYdL";
const USER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";

fn manifest(declared_tier: &str) -> ProtocolManifest {
    ProtocolManifest {
        graphite_manifest_version: "1.0".to_string(),
        protocol: ProtocolInfo {
            name: "A3 Community Protocol".to_string(),
            program_id: PROGRAM.to_string(),
            website: String::new(),
            github: String::new(),
            category: String::new(),
        },
        version: ManifestVersion {
            label: "1.0.0".to_string(),
            effective_from_slot: 0,
            previous_version_ref: None,
        },
        instructions: vec![InstructionDef {
            name: "ping".to_string(),
            discriminator: "01".to_string(),
            accounts: vec![AccountRoleDef {
                name: "user".to_string(),
                role: "signer".to_string(),
                is_writable: false,
                is_signer: true,
                pda_seeds: vec![],
                expected_address: vec![],
                optional: false,
            }],
            account_layouts: vec![],
            expected_state_changes: vec!["transfers nothing; records a ping".to_string()],
            allowed_cpis: vec![],
            risk_rules: vec![],
            variable_accounts: false,
            risk_class: String::new(),
        }],
        trust_tier: declared_tier.to_string(),
    }
}

fn input() -> VerificationInput {
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
fn attack_a_self_declared_tier_outranks_the_computed_one() {
    let reviewer = SigningKey::from_bytes(&[7u8; 32]);
    let reviewer_b58 = bs58::encode(reviewer.verifying_key().to_bytes()).into_string();
    let mut engine = ManifestRegistryEngine::new();
    engine.register_reviewer(&reviewer_b58, 1_000).unwrap();

    // One independent attestation, no submitter signature: evidence worth
    // HeuristicInferred (compute_trust_tier), whatever the document says.
    let mut submission = ManifestSubmission {
        manifest: manifest("OfficialManifest"),
        signer_pubkey: None,
        signature_hex: None,
        attestations: vec![],
    };
    let hash = submission.content_hash();
    submission.attestations.push(ReviewerAttestation {
        reviewer_pubkey: reviewer_b58.clone(),
        signature_hex: hex::encode(reviewer.sign(hash.as_bytes()).to_bytes()),
    });

    // P10: a first submission is a promotion; pin one fixture (refused under
    // Treasury on a fresh core, and still refused under the candidate).
    let mut corpus = RegressionCorpus::new();
    record_fixture(&mut corpus, &input(), false, "a3");
    let gate_core = GraphiteCore::new();
    let mut store = SemanticGraphStore::new();
    let decision = engine
        .submit(&mut store, submission, Some((&corpus, &gate_core)))
        .expect("accepted");
    assert_eq!(
        decision,
        RegistryDecision::Accepted {
            trust_tier: TrustTier::HeuristicInferred,
            version_label: "1.0.0".to_string()
        },
        "sanity: the registry computed HeuristicInferred from one attestation"
    );

    let mut core = GraphiteCore::new();
    assert_eq!(core.merge_community_manifests(&engine), 1);
    let r = core.verify(&input()).unwrap();
    assert!(r.manifest_found);
    assert_eq!(
        r.trust_tier,
        "HeuristicInferred",
        "the registry computed HeuristicInferred; the verdict path used the document's own \
         'OfficialManifest' (ceiling {:?})",
        r.breakdown
            .iter()
            .find(|b| b.kind == "TrustTierLevel")
            .map(|b| b.raw_value)
    );
}
