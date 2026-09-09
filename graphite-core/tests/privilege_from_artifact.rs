//! Privileges must come from the artifact, not from whoever supplies it.
//!
//! `privilege_mismatch.rs` proves Graphite blocks a required signer that is not
//! signed and a read-only slot that is writable — but only when the caller
//! supplies `real_account_metas` saying so. Those metas are an ASSERTION by the
//! party proposing the transaction, and the party proposing the transaction is
//! exactly the party a privilege check exists to constrain.
//!
//! Solana does not carry a per-account privilege byte. Writability and
//! signer-ness are positional: three header counts plus the key order determine
//! them, and the message under `signed_transaction` is the fact of the matter.
//! With the artifact parsed, a caller's metas contradicting the header is not a
//! discrepancy to average out — one of the two is the transaction that will
//! execute, and it is never the metas.
//!
//! The artifacts here are wire-format legacy messages written by the same
//! encoder that round-tripped three real mainnet transactions byte for byte
//! (see `alt_real_v0.rs`). The keys are test keys: the property under test is a
//! header flag, and pointing a privilege-escalation fixture at real accounts
//! would mean naming somebody's wallet in an attack artifact.

use base64::Engine;
use graphite_core::account_resolution::RealAccountMeta;
use graphite_core::manifest::load_seed_manifests;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::verification::{
    GraphiteCore, ProposedIntent, VerificationInput, VerificationResult,
};

const TEST_PROGRAM: &str = "TestPrivMismatch111111111111111111111111111";

fn fixture() -> serde_json::Value {
    let raw = include_str!("../fixtures/artifacts/privilege_artifacts.json");
    serde_json::from_str(raw).expect("privilege artifacts must parse")
}

fn artifact(name: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(fixture()[name]["raw_base64"].as_str().expect("base64"))
        .expect("must decode")
}

fn acct(name: &str) -> String {
    fixture()["accounts"][name]
        .as_str()
        .expect("account")
        .to_string()
}

/// Four slots, because the read-only one has to sit among genuine writable
/// ones: a manifest whose only writable slot is the account under attack
/// cannot describe fund movement, so L4 would fail for its own reasons and
/// mask whatever the privilege check did.
fn manifest_json() -> String {
    format!(
        r#"{{
        "graphite_manifest_version": "1.0",
        "protocol": {{
            "name": "Test Privilege Grounding Protocol",
            "program_id": "{pid}",
            "website": "",
            "github": ""
        }},
        "version": {{ "label": "1.0" }},
        "trust_tier": "OfficialManifest",
        "instructions": [
            {{
                "name": "TestInstruction",
                "discriminator": "bbbbbbbbbbbbbbbb",
                "accounts": [
                    {{ "name": "authority", "role": "signer", "is_writable": false, "is_signer": true, "pda_seeds": [] }},
                    {{ "name": "readonly_slot", "role": "readonly", "is_writable": false, "is_signer": false, "pda_seeds": [] }},
                    {{ "name": "source", "role": "writable", "is_writable": true, "is_signer": false, "pda_seeds": [] }},
                    {{ "name": "destination", "role": "writable", "is_writable": true, "is_signer": false, "pda_seeds": [] }}
                ],
                "expected_state_changes": ["debits accounts.source by amount", "credits accounts.destination by amount"],
                "allowed_cpis": [],
                "risk_rules": []
            }}
        ]
    }}"#,
        pid = TEST_PROGRAM
    )
}

/// Metas that agree with the manifest in every slot. A caller sends these when
/// the transaction really is shaped this way — and also when it is not.
fn metas_matching_the_manifest() -> Vec<RealAccountMeta> {
    vec![
        RealAccountMeta {
            is_signer: true,
            is_writable: false,
        },
        RealAccountMeta {
            is_signer: false,
            is_writable: false,
        },
        RealAccountMeta {
            is_signer: false,
            is_writable: true,
        },
        RealAccountMeta {
            is_signer: false,
            is_writable: true,
        },
    ]
}

fn verify(artifact_name: &str, metas: Vec<RealAccountMeta>) -> VerificationResult {
    let mut registry = load_seed_manifests();
    registry
        .load_from_json(&manifest_json())
        .expect("test manifest must load");
    let core = GraphiteCore::with_registry(registry);

    let data = hex::decode(
        fixture()["instruction_data_hex"]
            .as_str()
            .expect("instruction data"),
    )
    .expect("hex");

    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "test".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: TEST_PROGRAM.to_string(),
        protocol_version: "1.0".to_string(),
        instruction_discriminator: "bbbbbbbbbbbbbbbb".to_string(),
        account_addresses: vec![
            acct("authority"),
            acct("readonly"),
            acct("source"),
            acct("destination"),
        ],
        instruction_data: Some(data),
        cpi_targets: vec![],
        // The most permissive profile on purpose: a privilege escalation that
        // only a strict profile catches is not caught, it is outvoted.
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: Default::default(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: Some(artifact(artifact_name)),
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: metas,
        state_diff: None,
    };
    core.verify(&input).expect("verification must complete")
}

/// Whether this verdict blocked specifically on a privilege, rather than on
/// anything else that can block.
///
/// Asserting on `approved` would be the wrong altitude here: with no RPC
/// configured L3 is Inconclusive and the confidence ceiling keeps every result
/// below the policy threshold, so `approved == false` is true of the honest
/// artifact too and would prove nothing about privileges.
fn blocked_on_privilege(r: &VerificationResult) -> bool {
    r.risk_verdict.status == "Blocked"
        && r.risk_verdict
            .findings
            .iter()
            .any(|f| f.reason.contains("kind=privilege"))
}

/// The L1 line, which is where the provenance of the privilege flags is stated.
fn l1(r: &VerificationResult) -> String {
    r.layers
        .iter()
        .find(|l| l.layer == "L1_AccountResolution")
        .map(|l| l.reason.clone())
        .expect("L1 must always be reported")
}

fn dump(label: &str, r: &VerificationResult) {
    println!("--- {label} ---");
    for l in &r.layers {
        println!("  {} {:?}: {}", l.layer, l.status, l.reason);
    }
    println!(
        "  approved={} confidence={:.4} status={} findings={:?}",
        r.approved,
        r.confidence,
        r.risk_verdict.status,
        r.risk_verdict
            .findings
            .iter()
            .map(|f| (f.pattern.clone(), f.reason.clone()))
            .collect::<Vec<_>>()
    );
}

/// The artifacts express the privileges the tests below assume.
///
/// Without this, a fixture that silently stopped carrying the privilege it was
/// built to carry would make every assertion here pass for no reason.
#[test]
fn the_fixtures_actually_carry_the_privileges_under_test() {
    use graphite_core::tx_artifact::parse_transaction;

    let honest = parse_transaction(&artifact("honest")).expect("must parse");
    assert!(honest.signers.contains(&acct("authority")));
    assert!(!honest.writable.contains(&acct("readonly")));
    assert!(honest.writable.contains(&acct("source")));
    assert!(honest.writable.contains(&acct("destination")));

    let escalated =
        parse_transaction(&artifact("readonly_slot_is_writable_in_artifact")).expect("must parse");
    assert!(
        escalated.writable.contains(&acct("readonly")),
        "the attack artifact must actually mark the read-only slot writable"
    );
    assert!(
        escalated.signers.contains(&acct("authority")),
        "only writability should differ from the control"
    );

    let unsigned = parse_transaction(&artifact("required_signer_is_unsigned_in_artifact"))
        .expect("must parse");
    assert!(
        !unsigned.signers.contains(&acct("authority")),
        "the unsigned-authority artifact must not sign the authority"
    );
}

/// The control: an artifact that agrees with the manifest raises nothing.
///
/// Anti-vacuity for everything below. If this blocked too, the blocks that
/// follow would prove only that this manifest blocks everything.
#[test]
fn an_artifact_that_agrees_with_the_manifest_raises_no_privilege_finding() {
    let r = verify("honest", metas_matching_the_manifest());
    dump("honest", &r);
    assert_eq!(
        r.risk_verdict.status, "Clear",
        "a transaction whose header matches the manifest must not be blocked"
    );
    assert!(!blocked_on_privilege(&r));
    assert!(
        l1(&r).contains("read from the transaction's own header"),
        "L1 must say the flags came from the artifact: {}",
        l1(&r)
    );
    assert!(
        !l1(&r).contains("CONTRADICT"),
        "the honest metas agree with the header"
    );
}

/// A read-only slot the message marks WRITABLE, with metas that say read-only.
///
/// The escalation is in the bytes about to be signed. The metas are the
/// supplier's account of those bytes, and they are wrong. Graphite holds both.
#[test]
fn a_writable_slot_declared_readonly_by_the_caller_must_not_approve() {
    let r = verify(
        "readonly_slot_is_writable_in_artifact",
        metas_matching_the_manifest(),
    );
    dump("readonly slot is writable in the artifact", &r);
    assert!(
        blocked_on_privilege(&r),
        "the message marks a manifest-read-only account writable; the caller's metas said otherwise and were believed"
    );
    assert!(
        l1(&r).contains("CONTRADICT"),
        "the caller's description of these bytes was wrong and that should be said: {}",
        l1(&r)
    );
    assert!(!r.approved);
}

/// The two artifacts must not produce the same verdict.
///
/// This is the defect in its plainest form: before the header was read, an
/// escalated transaction and an honest one differed by a single header byte and
/// Graphite returned byte-identical risk verdicts, identical layer reports and
/// the same confidence for both.
#[test]
fn the_escalated_artifact_is_distinguishable_from_the_honest_one() {
    let honest = verify("honest", metas_matching_the_manifest());
    let escalated = verify(
        "readonly_slot_is_writable_in_artifact",
        metas_matching_the_manifest(),
    );
    assert_ne!(
        honest.risk_verdict.status, escalated.risk_verdict.status,
        "one header count is the only difference between these two transactions and it is a privilege escalation"
    );
    assert_ne!(l1(&honest), l1(&escalated));
}

/// The same shape in the signer direction: the manifest requires the authority
/// to sign, the message does not sign it, the metas claim it did.
#[test]
fn a_required_signer_left_unsigned_by_the_artifact_must_not_approve() {
    let r = verify(
        "required_signer_is_unsigned_in_artifact",
        metas_matching_the_manifest(),
    );
    dump("required signer unsigned in the artifact", &r);
    assert!(
        blocked_on_privilege(&r),
        "the message does not sign an account the manifest requires signed; the caller's metas said it did"
    );
    assert!(!r.approved);
}

/// Supplying no metas must not be a way to skip a check the artifact can
/// answer on its own.
///
/// Before the artifact parsed, absent metas honestly meant "not checked". With
/// the message in hand that is no longer honest: the header is right there.
#[test]
fn omitting_the_metas_does_not_skip_a_check_the_artifact_can_answer() {
    let r = verify("readonly_slot_is_writable_in_artifact", vec![]);
    dump("escalation with no metas supplied", &r);
    assert!(
        blocked_on_privilege(&r),
        "with no metas supplied, the artifact's own header still shows the escalation"
    );
    assert!(
        !l1(&r).contains("CONTRADICT"),
        "nothing was supplied, so nothing contradicts: {}",
        l1(&r)
    );
}

/// With no artifact at all, the caller's metas are still used and the layer
/// says so rather than implying the header was consulted.
///
/// The fix must not quietly turn "the caller told us" into "we established it"
/// for requests that carry no bytes.
#[test]
fn without_an_artifact_the_layer_says_the_flags_came_from_the_caller() {
    let mut registry = load_seed_manifests();
    registry
        .load_from_json(&manifest_json())
        .expect("test manifest must load");
    let core = GraphiteCore::with_registry(registry);

    let mut metas = metas_matching_the_manifest();
    metas[1].is_writable = true; // the escalation, asserted rather than observed

    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "test".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: TEST_PROGRAM.to_string(),
        protocol_version: "1.0".to_string(),
        instruction_discriminator: "bbbbbbbbbbbbbbbb".to_string(),
        account_addresses: vec![
            acct("authority"),
            acct("readonly"),
            acct("source"),
            acct("destination"),
        ],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: Default::default(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: metas,
        state_diff: None,
    };
    let r = core.verify(&input).expect("verification must complete");
    dump("no artifact, caller-supplied metas", &r);
    assert!(
        l1(&r).contains("came from the caller"),
        "with no bytes to read, the layer must not imply the header was consulted: {}",
        l1(&r)
    );
    assert!(
        blocked_on_privilege(&r),
        "a caller-declared escalation is still an escalation"
    );
}
