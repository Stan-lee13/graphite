//! R30 (§8, the Round 29 deliberate-break gap): every manifest-registry and
//! manifest-validation check was disabled in turn and the suite run. These
//! five were caught by NO test; each gets one here, with a control.
//!
//! - the registry's stricter rule on an empty discriminator;
//! - an attestation from a registered reviewer below the reputation bar;
//! - the corpus integrity check when a persisted registry is loaded;
//! - the program id being a public key;
//! - a seed byte range reading past the 32 bytes of an account key. This
//!   one is refused twice: the seed grammar (`validate_seed_templates`)
//!   refuses the range before the validator's own 32-byte check is reached,
//!   so disabling that check alone cannot fail any input — it is dead
//!   defence in depth. The test pins the refusal, from whichever check.

use ed25519_dalek::{Signer, SigningKey};
use graphite_core::manifest::{
    validate_manifest, AccountRoleDef, InstructionDef, ManifestVersion, ProtocolInfo,
    ProtocolManifest,
};
use graphite_core::manifest_registry::{
    ManifestRegistryEngine, ManifestSubmission, RegistryError, ReviewerAttestation,
    MIN_REVIEWER_REPUTATION,
};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::regression_engine::{record_fixture, RegressionCorpus};
use graphite_core::semantic_graph_store::{BehaviorEvidence, SemanticGraphStore};
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

const PROGRAM: &str = "4rQz2f4Wc1y7DpQ8v6mW2nN5uM3sR9bHjC1kTv8XwYdL";
const USER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";

fn account(name: &str, seeds: &[&str]) -> AccountRoleDef {
    AccountRoleDef {
        name: name.to_string(),
        role: "signer".to_string(),
        is_writable: false,
        is_signer: true,
        pda_seeds: seeds.iter().map(|s| s.to_string()).collect(),
        expected_address: vec![],
        optional: false,
    }
}

fn manifest(discriminator: &str, accounts: Vec<AccountRoleDef>) -> ProtocolManifest {
    ProtocolManifest {
        graphite_manifest_version: "1.0".to_string(),
        protocol: ProtocolInfo {
            name: "R30 Breaks".to_string(),
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
            name: "op".to_string(),
            discriminator: discriminator.to_string(),
            accounts,
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

fn reviewer(seed: u8) -> (SigningKey, String) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let b58 = bs58::encode(key.verifying_key().to_bytes()).into_string();
    (key, b58)
}

fn attested(m: ProtocolManifest, reviewers: &[&(SigningKey, String)]) -> ManifestSubmission {
    let mut s = ManifestSubmission {
        manifest: m,
        signer_pubkey: None,
        signature_hex: None,
        attestations: vec![],
    };
    let message = s.signing_message();
    for (key, b58) in reviewers {
        s.attestations.push(ReviewerAttestation {
            reviewer_pubkey: b58.clone(),
            signature_hex: hex::encode(key.sign(&message).to_bytes()),
        });
    }
    s
}

fn corpus() -> RegressionCorpus {
    let input = VerificationInput {
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
    };
    let mut c = RegressionCorpus::new();
    record_fixture(&mut c, &input, false, "r30");
    c
}

#[test]
fn the_registry_refuses_a_sole_empty_discriminator_the_loader_would_take() {
    let m = manifest("", vec![account("user", &[])]);
    assert!(
        validate_manifest(&m).is_ok(),
        "control: the runtime loader takes it"
    );
    let r = reviewer(9);
    let mut engine = ManifestRegistryEngine::new();
    engine.register_reviewer(&r.1, 1_000).unwrap();
    let core = GraphiteCore::new();
    let result = engine.submit(
        &mut SemanticGraphStore::new(),
        attested(m, &[&r]),
        Some((&corpus(), &core)),
    );
    assert!(
        matches!(result, Err(RegistryError::InvalidManifest(ref why)) if why.contains("stricter than the runtime loader")),
        "{result:?}"
    );
}

#[test]
fn an_attestation_below_the_reputation_bar_earns_nothing() {
    let low = reviewer(9);
    let ok = reviewer(10);
    let mut engine = ManifestRegistryEngine::new();
    engine
        .register_reviewer(&low.1, MIN_REVIEWER_REPUTATION - 1)
        .unwrap();
    engine
        .register_reviewer(&ok.1, MIN_REVIEWER_REPUTATION)
        .unwrap();
    let core = GraphiteCore::new();
    let c = corpus();
    let m = manifest("01", vec![account("user", &[])]);
    let result = engine.submit(
        &mut SemanticGraphStore::new(),
        attested(m.clone(), &[&low]),
        Some((&c, &core)),
    );
    assert!(
        matches!(result, Err(RegistryError::NoEvidence)),
        "{result:?}"
    );
    // Control: a reviewer at the bar counts.
    let result = engine.submit(
        &mut SemanticGraphStore::new(),
        attested(m, &[&ok]),
        Some((&c, &core)),
    );
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn a_persisted_registry_whose_corpus_was_edited_does_not_load() {
    let r = reviewer(9);
    let mut engine = ManifestRegistryEngine::new();
    engine.register_reviewer(&r.1, 1_000).unwrap();
    let core = GraphiteCore::new();
    engine
        .submit(
            &mut SemanticGraphStore::new(),
            attested(manifest("01", vec![account("user", &[])]), &[&r]),
            Some((&corpus(), &core)),
        )
        .expect("accepted");
    let saved = engine.to_json().unwrap();
    assert!(ManifestRegistryEngine::from_json(&saved).is_ok(), "control");

    let mut json: serde_json::Value = serde_json::from_str(&saved).unwrap();
    let fixture = &mut json["corpus"]["fixtures"][0];
    assert_eq!(fixture["expected_approved"], serde_json::Value::Bool(false));
    fixture["expected_approved"] = serde_json::Value::Bool(true);
    assert!(
        ManifestRegistryEngine::from_json(&json.to_string()).is_err(),
        "an edited outcome in the registry's own corpus must fail the load"
    );
}

#[test]
fn a_program_id_that_is_not_a_public_key_is_refused() {
    let mut m = manifest("01", vec![account("user", &[])]);
    assert!(validate_manifest(&m).is_ok(), "control");
    m.protocol.program_id = "not-a-public-key".to_string();
    let err = validate_manifest(&m).unwrap_err();
    assert!(err.to_string().contains("invalid program_id"), "{err}");
}

#[test]
fn a_seed_reading_past_a_keys_32_bytes_is_refused() {
    let ok = manifest(
        "01",
        vec![account("pda", &["{account_1:0:32}"]), account("user", &[])],
    );
    assert!(validate_manifest(&ok).is_ok(), "control: 0..32 fits");
    let past = manifest(
        "01",
        vec![account("pda", &["{account_1:0:33}"]), account("user", &[])],
    );
    let err = validate_manifest(&past).unwrap_err();
    assert!(err.to_string().contains("32 bytes"), "{err}");
}
