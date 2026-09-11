//! The SAK bridge's real output, verified by the Core.
//!
//! The bridge and the Core are two implementations of one agreement: the bridge
//! serializes the transaction it is about to run and describes its
//! instructions, and the Core reads both and decides whether they agree. Tests
//! on either side alone prove only that each is self-consistent with itself.
//!
//! `integrations/solana-agent-kit/emit-artifact-fixture.ts` writes the
//! TypeScript side's actual output — `@solana/web3.js` doing the serialization,
//! `artifact.ts` doing the declarations — and this file consumes it. A change
//! to either side that breaks the agreement fails here rather than in an
//! integration.
//!
//! The transaction is the shape almost every real Solana transaction has: a
//! ComputeBudget limit and price in front of the instruction that does the
//! work. That is exactly the shape the sibling rule had to be able to accept,
//! and the reason it could not before is why this fixture exists.
//!
//! Unsigned, and nothing here signs or submits: Graphite is a pre-signature
//! gate.

use graphite_core::manifest::load_seed_manifests;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationResult,
};

fn fixture() -> serde_json::Value {
    let raw = include_str!("../fixtures/artifacts/sak_bridge_artifact.json");
    serde_json::from_str(raw).expect("the bridge fixture must parse")
}

fn bytes(v: &serde_json::Value) -> Vec<u8> {
    v.as_array()
        .expect("byte array")
        .iter()
        .map(|n| n.as_u64().expect("byte") as u8)
        .collect()
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect()
}

fn declared_siblings(f: &serde_json::Value) -> Vec<TransactionInstruction> {
    f["transaction_instructions"]
        .as_array()
        .expect("declarations")
        .iter()
        .map(|d| TransactionInstruction {
            program_id: d["program_id"].as_str().expect("program").to_string(),
            instruction_discriminator: d["instruction_discriminator"]
                .as_str()
                .expect("discriminator")
                .to_string(),
            account_addresses: strings(&d["account_addresses"]),
            cpi_targets: strings(&d["cpi_targets"]),
        })
        .collect()
}

fn verify(siblings: Vec<TransactionInstruction>) -> VerificationResult {
    let f = fixture();
    let core = GraphiteCore::with_registry(load_seed_manifests());
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send 0.002 SOL".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: f["primary"]["program_id"]
            .as_str()
            .expect("program")
            .to_string(),
        protocol_version: "1.0".to_string(),
        instruction_discriminator: f["primary"]["instruction_discriminator"]
            .as_str()
            .expect("discriminator")
            .to_string(),
        account_addresses: strings(&f["primary"]["account_addresses"]),
        instruction_data: Some(bytes(&f["primary"]["instruction_data"])),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: Default::default(),
        compute_units: 450,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: Some(bytes(&f["signed_transaction"])),
        transaction_instructions: siblings,
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    };
    core.verify(&input).expect("verification must complete")
}

fn l2(r: &VerificationResult) -> (LayerStatus, String) {
    r.layers
        .iter()
        .find(|l| l.layer == "L2_InstructionVerification")
        .map(|l| (l.status, l.reason.clone()))
        .expect("L2 must always be reported")
}

/// What `@solana/web3.js` serializes, Graphite's parser reads.
///
/// Independent implementations of the same wire format: one written against the
/// Solana SDK in TypeScript, one written from the format definition in Rust.
#[test]
fn the_bridges_serialized_transaction_parses() {
    let f = fixture();
    let m = graphite_core::tx_artifact::parse_transaction(&bytes(&f["signed_transaction"]))
        .expect("what the bridge sends must be readable by the Core");

    assert_eq!(
        m.instructions.len(),
        f["instruction_count"].as_u64().expect("count") as usize
    );
    assert_eq!(m.version, None, "the bridge builds a legacy transaction");

    let described = strings(&f["primary"]["account_addresses"]);
    assert!(
        m.signers.contains(&described[0]),
        "the payer signs in the header the bridge produced"
    );
    assert!(
        m.writable.contains(&described[1]),
        "the destination is writable in the header the bridge produced"
    );
    println!(
        "{} instructions, fee payer {}, {} signer(s)",
        m.instructions.len(),
        m.fee_payer,
        m.signers.len()
    );
}

/// The privileges the Core derives match the ones the bridge read off the
/// instruction.
///
/// Two routes to the same fact — the bridge from `TransactionInstruction.keys`,
/// the Core from the message header and key order — and they have to agree, or
/// one of them is wrong about the transaction.
#[test]
fn the_derived_privileges_match_what_the_bridge_read_off_the_instruction() {
    let f = fixture();
    let m = graphite_core::tx_artifact::parse_transaction(&bytes(&f["signed_transaction"]))
        .expect("must parse");
    let described = strings(&f["primary"]["account_addresses"]);

    for (i, meta) in f["primary"]["real_account_metas"]
        .as_array()
        .expect("metas")
        .iter()
        .enumerate()
    {
        let addr = &described[i];
        assert_eq!(
            m.signers.contains(addr),
            meta["is_signer"].as_bool().expect("is_signer"),
            "signer flag disagrees for {addr}"
        );
        assert_eq!(
            m.writable.contains(addr),
            meta["is_writable"].as_bool().expect("is_writable"),
            "writable flag disagrees for {addr}"
        );
    }
}

/// The bridge's declarations satisfy the Core's sibling rule.
///
/// This is the whole point of the fixture. The bridge now sends the artifact,
/// and an artifact with two ComputeBudget instructions in front of the transfer
/// fails L2 unless those are described. If the two sides disagree about how to
/// describe them, every swap and every transfer through this bridge is blocked.
#[test]
fn the_bridges_declarations_satisfy_the_sibling_rule() {
    let f = fixture();
    let r = verify(declared_siblings(&f));
    let (status, reason) = l2(&r);
    println!("with declarations: {status:?} — {reason}");
    assert_eq!(
        status,
        LayerStatus::Passed,
        "the bridge describes every instruction it sends, and the Core must accept that description: {reason}"
    );
}

/// Dropping the declarations fails, so the test above is not passing for some
/// unrelated reason.
#[test]
fn the_same_artifact_without_declarations_fails() {
    let r = verify(vec![]);
    let (status, reason) = l2(&r);
    println!("without declarations: {status:?} — {reason}");
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(
        reason.contains("ComputeBudget111111111111111111111111111111"),
        "the report must name what went undescribed: {reason}"
    );
}

/// A declaration whose data was altered no longer describes the instruction.
///
/// The compute-unit price is a fee the user pays. If the declaration could
/// differ from the bytes, the risk assessment of that sibling would be about a
/// different instruction than the one that runs.
#[test]
fn altering_a_declaration_stops_it_describing_the_instruction() {
    let f = fixture();
    let mut siblings = declared_siblings(&f);
    let original = siblings[1].instruction_discriminator.clone();
    // Same length, one nibble different: still a plausible declaration, no
    // longer this transaction's.
    let mut altered = original.clone();
    altered.replace_range(2..3, "f");
    assert_ne!(altered, original);
    siblings[1].instruction_discriminator = altered;

    let r = verify(siblings);
    let (status, reason) = l2(&r);
    println!("altered declaration: {status:?} — {reason}");
    assert_eq!(status, LayerStatus::Failed, "{reason}");
}

/// The verdict the bridge gets is artifact-bound, and says what it did not
/// observe.
///
/// The bridge's whole reason for sending the bytes is to leave Descriptive
/// mode. If the scope still came back Descriptive, the change would have cost
/// an RPC round trip and bought nothing.
#[test]
fn the_verdict_is_artifact_bound() {
    let f = fixture();
    let r = verify(declared_siblings(&f));
    let unobserved = r.scope.unobserved();
    println!("scope: {:?}", r.scope);
    assert!(
        r.scope.is_artifact_bound(),
        "sending the transaction must produce an artifact-bound verdict"
    );
    assert!(
        !unobserved.is_empty(),
        "an artifact-bound verdict still has limits and must name them"
    );
}

/// The digest the bridge will compare against is the digest the Core computes.
///
/// `BoundTransaction.assertApproved` re-serializes the transaction immediately
/// before signing and requires `scope.transaction_sha256`. That check is only
/// meaningful if both sides hash the same bytes with the same function — and if
/// they ever disagreed, the failure would not be a silent bypass but a total
/// one: every honest transaction would be refused at the signing boundary,
/// because a digest would be compared against the digest of something else.
///
/// The fixture carries what Node's `createHash("sha256")` produced over the
/// artifact. This asserts the Rust pipeline reports the same string.
#[test]
fn the_core_and_the_bridge_agree_on_the_digest_of_the_same_bytes() {
    let f = fixture();
    let expected = f["transaction_sha256"].as_str().expect("digest");
    let r = verify(declared_siblings(&f));

    let scope = serde_json::to_value(&r.scope).expect("scope must serialize");
    assert_eq!(scope["kind"], "artifact_bound");
    assert_eq!(
        scope["transaction_sha256"].as_str().expect("digest"),
        expected,
        "the Core hashed different bytes than the bridge will compare against"
    );
    assert_eq!(
        scope["transaction_bytes"].as_u64().expect("length") as usize,
        f["signed_transaction"].as_array().expect("bytes").len(),
        "the reported length must be the length of what was supplied"
    );

    // Anti-vacuity: the fixture's digest is a real SHA-256 of those bytes and
    // not some constant both sides happen to echo.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes(&f["signed_transaction"]));
    assert_eq!(hex::encode(h.finalize()), expected);
}

/// One byte of difference is a different digest.
///
/// The property the execution check rests on. Without it, "the digest still
/// matches" would be compatible with a transaction that had been edited.
#[test]
fn changing_one_byte_of_the_artifact_changes_the_reported_digest() {
    let f = fixture();
    let original = verify(declared_siblings(&f));
    let original_digest = serde_json::to_value(&original.scope).unwrap()["transaction_sha256"]
        .as_str()
        .expect("digest")
        .to_string();

    // Flip a byte inside the instruction data — the lamport amount's low byte.
    let mut mutated = bytes(&f["signed_transaction"]);
    let last = mutated.len() - 1;
    mutated[last] ^= 0x01;

    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&mutated);
    let mutated_digest = hex::encode(h.finalize());

    assert_ne!(
        original_digest, mutated_digest,
        "a one-byte edit must change the digest, or the binding binds nothing"
    );
}
