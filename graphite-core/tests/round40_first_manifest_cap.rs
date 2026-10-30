//! Round 40 (R39-CORE-IDENTITY-7, owner decision option 4): a program's FIRST
//! manifest accepted by the registry reaches the verdict at
//! `HeuristicInferred` at most.
//!
//! A first submission has no earlier behaviour to be replayed against: its
//! fixtures are recorded under the candidate and agree with it by
//! construction (`manifest_registry.rs`, "What the first-submission gate does
//! and does not prove"). Before Round 40 a registered reviewer's signature on
//! it earned `OfficialManifest`, and two more attestations
//! `CommunityVerified`, on the strength of a replay that validated nothing.
//! The cap is applied where the tier is computed
//! (`semantic_graph_store::compute_trust_tier_for`), from a flag on the
//! registry's evidence — in the manifest in force and in the graph record,
//! the two sources `program_trust_tier` takes the verdict's tier from — not
//! as a special case in the verdict. The first upgrade replayed against the
//! fixtures the first version pinned lifts it.
//!
//! The seeded built-in manifests are not registry submissions: they create
//! no registry record, carry no flag, and keep their tier.

use ed25519_dalek::{Signer, SigningKey};
use graphite_core::confidence_engine::TrustTier;
use graphite_core::manifest::{
    AccountRoleDef, InstructionDef, ManifestVersion, ProtocolInfo, ProtocolManifest,
};
use graphite_core::manifest_registry::{ManifestRegistryEngine, ManifestSubmission};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::regression_engine::{record_fixture, RegressionCorpus};
use graphite_core::semantic_graph_store::{BehaviorEvidence, SemanticGraphStore};
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

const PROGRAM: &str = "4rQz2f4Wc1y7DpQ8v6mW2nN5uM3sR9bHjC1kTv8XwYdL";
const SYSTEM: &str = "11111111111111111111111111111111";
const USER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const FRIEND: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

fn manifest(program: &str, label: &str, previous: Option<&str>) -> ProtocolManifest {
    ProtocolManifest {
        graphite_manifest_version: "1.0".to_string(),
        protocol: ProtocolInfo {
            name: "Round 40 Protocol".to_string(),
            program_id: program.to_string(),
            website: String::new(),
            github: String::new(),
            category: String::new(),
        },
        version: ManifestVersion {
            label: label.to_string(),
            effective_from_slot: 0,
            previous_version_ref: previous.map(str::to_string),
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
        // What the document claims is never what it earns (P7).
        trust_tier: "OfficialManifest".to_string(),
    }
}

fn signed(m: ProtocolManifest, key: &SigningKey) -> ManifestSubmission {
    let mut sub = ManifestSubmission {
        manifest: m,
        signer_pubkey: Some(bs58::encode(key.verifying_key().to_bytes()).into_string()),
        signature_hex: None,
        attestations: vec![],
    };
    let message = sub.signing_message();
    sub.signature_hex = Some(hex::encode(key.sign(&message).to_bytes()));
    sub
}

fn input(program: &str, discriminator: &str, accounts: &[&str]) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: String::new(),
            confidence_of_parse: 1.0,
            extracted_parameters: None,
        },
        program_id: program.to_string(),
        protocol_version: String::new(),
        instruction_discriminator: discriminator.to_string(),
        account_addresses: accounts.iter().map(|a| a.to_string()).collect(),
        instruction_data: None,
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

fn corpus_for(
    core: &GraphiteCore,
    sub: &ManifestSubmission,
    i: &VerificationInput,
) -> RegressionCorpus {
    let observed = core
        .with_candidate_manifest(&sub.manifest)
        .unwrap()
        .verify(i)
        .unwrap()
        .approved;
    let mut corpus = RegressionCorpus::new();
    record_fixture(&mut corpus, i, observed, "round40");
    corpus
}

/// The verdict's trust tier for `i` on a core carrying the registry's
/// manifests in force and, when given, the registry's graph record.
fn verdict_tier(
    engine: &ManifestRegistryEngine,
    store: Option<&SemanticGraphStore>,
    i: &VerificationInput,
) -> String {
    let mut core = GraphiteCore::new();
    core.merge_community_manifests(engine);
    if let Some(store) = store {
        if let Some(b) = store.get(&i.program_id) {
            core.seed_behavior(b.clone()).unwrap();
        }
    }
    core.verify(i).unwrap().trust_tier
}

#[test]
fn a_first_manifest_reaches_the_verdict_capped_and_its_validated_upgrade_does_not() {
    let reviewer = SigningKey::from_bytes(&[40u8; 32]);
    let mut engine = ManifestRegistryEngine::new();
    engine
        .register_reviewer(
            &bs58::encode(reviewer.verifying_key().to_bytes()).into_string(),
            1_000,
        )
        .unwrap();
    let gate = GraphiteCore::new();
    let mut store = SemanticGraphStore::new();
    let ping = input(PROGRAM, "01", &[USER]);

    // Attack: a signed first submission. Its replay is self-consistent by
    // construction; before Round 40 the verdict read OfficialManifest.
    let v1 = signed(manifest(PROGRAM, "1.0.0", None), &reviewer);
    let corpus = corpus_for(&gate, &v1, &ping);
    engine
        .submit(&mut store, v1, Some((&corpus, &gate)))
        .unwrap();
    assert_eq!(verdict_tier(&engine, None, &ping), "HeuristicInferred");
    // The graph record is capped too, so it cannot lift the verdict back
    // (the verdict takes the higher of the graph's tier and the manifest's).
    assert_eq!(
        store.get(PROGRAM).unwrap().trust_tier,
        TrustTier::HeuristicInferred
    );
    assert_eq!(
        verdict_tier(&engine, Some(&store), &ping),
        "HeuristicInferred"
    );

    // Benign: the upgrade, replayed against the fixture v1 pinned, earns
    // what its signature earns.
    let v2 = signed(manifest(PROGRAM, "1.1.0", Some("1.0.0")), &reviewer);
    let corpus = corpus_for(&gate, &v2, &ping);
    engine
        .submit(&mut store, v2, Some((&corpus, &gate)))
        .unwrap();
    assert_eq!(verdict_tier(&engine, None, &ping), "OfficialManifest");
    assert_eq!(
        verdict_tier(&engine, Some(&store), &ping),
        "OfficialManifest"
    );
}

/// The built-in seed manifests are loaded by `load_seed_manifests`, not
/// accepted by the registry: no record, no flag, the same tier. A community
/// first submission for a seed program does not install its manifest and
/// its capped graph record cannot drag the seed's tier down.
#[test]
fn the_seed_manifests_are_not_registry_submissions_and_keep_their_tier() {
    let transfer = input(SYSTEM, "02000000", &[USER, FRIEND]);
    let fresh = GraphiteCore::new();
    let seed_tier = fresh.verify(&transfer).unwrap().trust_tier;
    // The seed document's own tier, capped at OfficialManifest (P7).
    assert!(graphite_core::manifest::load_seed_manifests()
        .get(SYSTEM)
        .is_some());
    assert_eq!(seed_tier, "OfficialManifest");
    assert!(fresh.program_behavior(SYSTEM).is_none(), "no graph record");

    let reviewer = SigningKey::from_bytes(&[41u8; 32]);
    let mut engine = ManifestRegistryEngine::new();
    engine
        .register_reviewer(
            &bs58::encode(reviewer.verifying_key().to_bytes()).into_string(),
            1_000,
        )
        .unwrap();
    let mut store = SemanticGraphStore::new();
    let mut m = manifest(SYSTEM, "community-1", None);
    m.instructions[0].discriminator = "02000000".to_string();
    let sub = signed(m, &reviewer);
    let corpus = corpus_for(&fresh, &sub, &transfer);
    engine
        .submit(&mut store, sub, Some((&corpus, &fresh)))
        .unwrap();
    assert!(engine.records()[0].first_manifest_unvalidated);
    assert_eq!(
        store.get(SYSTEM).unwrap().trust_tier,
        TrustTier::HeuristicInferred
    );
    assert_eq!(verdict_tier(&engine, Some(&store), &transfer), seed_tier);
}
