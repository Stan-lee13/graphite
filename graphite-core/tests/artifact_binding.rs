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
        joined.contains("does not parse the transaction's wire format"),
        "an artifact-bound verdict must state that Graphite did not confirm the described \
         instruction is the one inside the bytes: {joined}"
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
