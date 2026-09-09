//! The central promise, made checkable.
//!
//! Graphite is not selling eight layers or a test count. The product promise is
//! one sentence:
//!
//! > The thing Graphite approved is the thing that gets signed and executed, and
//! > every security-relevant property of that thing was either independently
//! > verified or explicitly identified as unverified.
//!
//! Until 2026-09-08 a consumer had no way to tell which half of that sentence
//! applied to the verdict in their hands. A `/verify` response describing
//! caller-supplied metadata and one bound to a real signed blob were the same
//! shape, so an integration could gate on `approved` without ever learning that
//! Graphite had not been shown a transaction — which is precisely how the SAK
//! swap path came to execute an instruction that nothing had examined.
//!
//! Both modes are legitimate. What was missing was the label, and the list of
//! what the label leaves out. `VerificationScope` is that label; these tests are
//! the invariant.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{
    GraphiteCore, ProposedIntent, VerificationInput, VerificationScope,
};

const SYSTEM: &str = "11111111111111111111111111111111";
const FROM: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const TO: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

fn input(signed: Option<Vec<u8>>) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
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
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: signed,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

fn scope_of(input: &VerificationInput) -> VerificationScope {
    GraphiteCore::new().verify(input).expect("verify ok").scope
}

/// Every verdict says which of the two things it is. There is no third state
/// and no absent state.
#[test]
fn every_verdict_declares_what_it_is_bound_to() {
    for signed in [None, Some(vec![1u8, 2, 3, 4])] {
        let scope = scope_of(&input(signed.clone()));
        match &scope {
            VerificationScope::ArtifactBound {
                transaction_sha256,
                transaction_bytes,
                ..
            } => {
                assert_eq!(
                    transaction_sha256.len(),
                    64,
                    "a SHA-256 must be 64 hex chars"
                );
                assert!(*transaction_bytes > 0);
            }
            VerificationScope::Descriptive { unobserved } => {
                assert!(
                    !unobserved.is_empty(),
                    "descriptive with nothing unobserved is a contradiction"
                );
            }
        }
    }
}

/// The half of the promise that carries the weight: whatever the mode, the
/// verdict enumerates what it did NOT observe. An empty list is a very strong
/// claim and must never be produced by accident.
#[test]
fn no_verdict_ever_claims_to_have_observed_everything() {
    for signed in [None, Some(vec![9u8; 64])] {
        let scope = scope_of(&input(signed.clone()));
        assert!(
            !scope.unobserved().is_empty(),
            "a verdict claimed to have observed every security-relevant property of the \
             transaction. If that is ever true it must be argued for explicitly, not fall out \
             of an empty vector. scope={scope:?}"
        );
        for entry in scope.unobserved() {
            assert!(
                entry.len() > 30,
                "an unobserved entry must say what is missing, not name a category: {entry:?}"
            );
        }
    }
}

/// With no artifact, the verdict must say so first — before any consumer reads
/// `approved`. This is the case the SAK swap path was silently in.
#[test]
fn a_verdict_with_no_transaction_says_nothing_constrains_what_gets_signed() {
    let scope = scope_of(&input(None));
    assert!(
        !scope.is_artifact_bound(),
        "no blob was supplied and the verdict claimed to be artifact-bound"
    );
    let joined = scope.unobserved().join(" | ");
    assert!(
        joined.contains("nothing here constrains what is actually signed"),
        "the primary consequence of a descriptive verdict is not stated: {joined}"
    );
    assert!(
        joined.contains("other instructions"),
        "a descriptive verdict must warn that the approved instruction can be submitted \
         alongside unexamined ones — the attack L4 exists for, moved to the signing \
         boundary: {joined}"
    );
}

/// Supplying bytes binds the verdict to those bytes, by digest. This is a
/// stronger binding than `content_hash`, which covers a projection of one
/// instruction and cannot see the fee payer, the blockhash, the signer set, or
/// any other instruction in the transaction.
#[test]
fn supplying_a_transaction_binds_the_verdict_to_its_exact_bytes() {
    let a = scope_of(&input(Some(vec![1, 2, 3, 4])));
    let b = scope_of(&input(Some(vec![1, 2, 3, 5])));

    let (ha, hb) = match (&a, &b) {
        (
            VerificationScope::ArtifactBound {
                transaction_sha256: ha,
                ..
            },
            VerificationScope::ArtifactBound {
                transaction_sha256: hb,
                ..
            },
        ) => (ha, hb),
        _ => panic!("a supplied blob must produce an artifact-bound scope: {a:?} {b:?}"),
    };
    assert_ne!(
        ha, hb,
        "two different transactions produced the same binding — one byte changed and the \
         digest did not"
    );

    // And it is the digest of the bytes themselves, reproducible by the caller
    // without asking Graphite.
    use sha2::{Digest, Sha256};
    assert_eq!(
        *ha,
        hex::encode(Sha256::digest([1u8, 2, 3, 4])),
        "the binding must be a plain SHA-256 of the submitted bytes, so a caller can compute \
         it independently before signing"
    );
}

/// An artifact that was never executed must not read as one that was. Without
/// an RPC there is no simulator, so `simulated` is false and the reason is
/// stated rather than left for the reader to deduce from a missing layer.
#[test]
fn an_unsimulated_artifact_is_marked_unsimulated() {
    let scope = scope_of(&input(Some(vec![7u8; 32])));
    match scope {
        VerificationScope::ArtifactBound {
            simulated,
            unobserved,
            ..
        } => {
            assert!(
                !simulated,
                "no RPC is attached, so nothing executed these bytes, yet the verdict says it did"
            );
            assert!(
                unobserved
                    .iter()
                    .any(|u| u.contains("never executed by a simulator")),
                "an unsimulated artifact must say so: {unobserved:?}"
            );
        }
        other => panic!("expected artifact-bound, got {other:?}"),
    }
}

/// Even a simulated artifact leaves something unobserved, and Graphite must say
/// which: it reads a transaction's effects, never its wire format, so it does
/// not confirm that the described instruction is the primary instruction of
/// those bytes.
///
/// This is the honest limit of the current design and the most likely place for
/// a future reader to over-read the guarantee.
#[test]
fn even_a_bound_artifact_states_the_limit_of_the_binding() {
    let scope = scope_of(&input(Some(vec![3u8; 16])));
    let joined = scope.unobserved().join(" | ");
    assert!(
        joined.contains("could not be parsed as a legacy or v0 Solana message"),
        "when the artifact cannot be read the verdict must name that and say what it costs. \
         These fixtures are synthetic blobs, so this is the FALLBACK branch; a real \
         transaction takes the parsed branch - see tests/tx_artifact_real.rs: {joined}"
    );
}

/// Missing privilege metadata is a security-relevant absence and appears in
/// both modes, because privilege escalation inside the account list is
/// invisible without it.
#[test]
fn ungrounded_signer_and_writable_flags_are_reported_as_unobserved() {
    for signed in [None, Some(vec![4u8; 8])] {
        let joined = scope_of(&input(signed)).unobserved().join(" | ");
        assert!(
            joined.contains("real_account_metas"),
            "signer/writable flags were not supplied and the verdict did not say so: {joined}"
        );
    }
}

/// The scope must survive serialization: a consumer reads it over HTTP, not
/// from Rust.
#[test]
fn the_scope_survives_the_wire() {
    let result = GraphiteCore::new()
        .verify(&input(Some(vec![1, 2, 3])))
        .expect("verify ok");
    let json = serde_json::to_value(&result).expect("serializable");
    let scope = json.get("scope").expect("scope must be on the response");
    assert_eq!(
        scope.get("kind").and_then(|k| k.as_str()),
        Some("artifact_bound"),
        "the mode must be readable by a consumer without parsing prose: {scope}"
    );
    assert!(
        scope
            .get("unobserved")
            .and_then(|u| u.as_array())
            .is_some_and(|a| !a.is_empty()),
        "the unobserved list must cross the wire: {scope}"
    );
}

// ── The described instruction must be IN the artifact ────────────────────────
//
// Found 2026-09-09 attacking the artifact semantic boundary, on live devnet.
// Two real transactions, identical in every respect a checker was looking at:
// same payer, same recipient, same program, same discriminator, same account
// count, lamports conserved, account universe covered. Only the AMOUNT differed
// — 0.002 SOL described, 0.9 SOL in the bytes.
//
//     approved: true
//     scope:    artifact_bound
//     L4:       "no undeclared effects"
//
// Graphite held both facts and never compared them. `content_hash` covers the
// DESCRIPTION and was byte-identical across the two requests; `transaction_sha256`
// covers the ARTIFACT and differed. Nothing joined them.
//
// The containment needs no parser. A Solana message stores instruction data as
// raw, length-prefixed bytes, so an instruction that is in the transaction has
// its data in the transaction's bytes, verbatim and contiguous. Presence is a
// NECESSARY condition, and the attack above needed it to be false.

/// A "transaction" carrying `data` somewhere inside it, with plausible
/// surrounding bytes. The check is a substring search, so this is a faithful
/// stand-in for a serialized message without needing one.
fn artifact_containing(data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xABu8; 64];
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(&[0xCD; 64]);
    bytes
}

fn with_artifact(data: Vec<u8>, artifact: Vec<u8>) -> VerificationInput {
    let mut i = input(Some(artifact));
    i.instruction_data = Some(data);
    i
}

fn l2_of(input: &VerificationInput) -> (bool, String) {
    let r = GraphiteCore::new().verify(input).expect("verify ok");
    let l2 = r
        .layers
        .iter()
        .find(|l| l.layer.contains("L2"))
        .expect("L2 present");
    (
        matches!(l2.status, graphite_core::verification::LayerStatus::Passed),
        l2.reason.clone(),
    )
}

/// THE case: a System transfer's 12 data bytes, where the artifact carries a
/// different amount. Only four of the twelve bytes differ.
#[test]
fn an_artifact_that_does_not_contain_the_described_instruction_fails_l2() {
    // 0x02 = System Transfer, then a u64 LE amount.
    let mut described = vec![2u8, 0, 0, 0];
    described.extend_from_slice(&2_000_000u64.to_le_bytes());
    let mut executed = vec![2u8, 0, 0, 0];
    executed.extend_from_slice(&900_000_000u64.to_le_bytes());

    let (passed, reason) = l2_of(&with_artifact(described, artifact_containing(&executed)));
    assert!(
        !passed,
        "the artifact sends 450x the described amount and L2 passed: {reason}"
    );
    assert!(
        reason.contains("does not contain the instruction being verified"),
        "L2 failed for some other reason, so this test would not notice the check being \
         removed: {reason}"
    );
}

/// Anti-vacuity. If the check rejected every artifact, the test above would
/// pass while the layer was useless.
#[test]
fn an_artifact_that_does_contain_the_described_instruction_passes_l2() {
    let mut data = vec![2u8, 0, 0, 0];
    data.extend_from_slice(&2_000_000u64.to_le_bytes());
    let (passed, reason) = l2_of(&with_artifact(data.clone(), artifact_containing(&data)));
    assert!(
        passed,
        "an artifact that does contain the described instruction was rejected — the check is \
         over-blocking: {reason}"
    );
}

/// Every byte of the data matters, including the ones deep inside the amount.
/// A check that only compared the discriminator would pass all of these.
#[test]
fn a_single_differing_byte_anywhere_in_the_instruction_data_is_caught() {
    let mut described = vec![2u8, 0, 0, 0];
    described.extend_from_slice(&2_000_000u64.to_le_bytes());

    for flip in 0..described.len() {
        let mut executed = described.clone();
        executed[flip] ^= 0x01;
        let (passed, _) = l2_of(&with_artifact(
            described.clone(),
            artifact_containing(&executed),
        ));
        assert!(
            !passed,
            "flipping byte {flip} of the instruction data went undetected — the check is \
             comparing a prefix rather than the whole thing"
        );
    }
}

/// The check abstains rather than guessing when the data is too short to
/// identify anything. Eight bytes is the Anchor discriminator length; below
/// that a sequence can occur inside a pubkey or a blockhash by chance, and a
/// check satisfiable by coincidence is worse than one that says nothing.
#[test]
fn instruction_data_too_short_to_identify_anything_does_not_trigger_the_check() {
    let described = vec![2u8, 0, 0, 0]; // 4 bytes
    let executed = vec![9u8, 9, 9, 9];
    let (passed, reason) = l2_of(&with_artifact(described, artifact_containing(&executed)));
    assert!(
        passed,
        "a 4-byte discriminator is too short to be identifying; the check must abstain rather \
         than block on a coincidence-prone comparison: {reason}"
    );
}

/// With no artifact there is nothing to look inside, so the check must not fire
/// — a descriptive verdict is a legitimate mode, not a failure.
#[test]
fn a_descriptive_verification_is_unaffected_by_the_presence_check() {
    let mut data = vec![2u8, 0, 0, 0];
    data.extend_from_slice(&2_000_000u64.to_le_bytes());
    let mut i = input(None);
    i.instruction_data = Some(data);
    let (passed, reason) = l2_of(&i);
    assert!(
        passed,
        "no artifact was supplied and L2 blocked anyway: {reason}"
    );
}

/// The residual is disclosed, not just commented. Presence is necessary, not
/// sufficient: finding the bytes does not prove they belong to an instruction
/// with the described program and accounts.
#[test]
fn the_limit_of_the_presence_check_is_reported_to_the_caller() {
    let mut data = vec![2u8, 0, 0, 0];
    data.extend_from_slice(&2_000_000u64.to_le_bytes());
    let r = GraphiteCore::new()
        .verify(&with_artifact(data.clone(), artifact_containing(&data)))
        .expect("verify ok");
    let joined = r.scope.unobserved().join(" | ");
    assert!(
        joined.contains("fell back to checking that the described instruction"),
        "an unparseable artifact must state that the fallback proves the bytes are PRESENT, \
         not that they belong to the described instruction: {joined}"
    );
}
