//! Round 12: Graphite is never looser than the runtime's own sanitizer.
//!
//! `tools/runtime-oracle` decodes byte strings with the agave crates exactly
//! as a validator's packet path does and compares the verdict with
//! `parse_transaction`. Its first run found 3,382 of 200,000 generated frames
//! — and 8 of the recorded corpus's own mutations — that Graphite parsed and
//! the runtime's `sanitize` refuses:
//!
//! - an instruction whose program index is 0 (the fee payer; "a program
//!   cannot be a payer");
//! - a LEGACY instruction naming an account index past the static keys
//!   (Graphite read it as a lookup-derived account, in a message that has no
//!   lookups, and L2 PASSED with "1 of its account(s) arrive through address
//!   lookup tables");
//! - a v0 instruction naming an index past the static keys plus every loaded
//!   address;
//! - a v0 lookup that loads nothing;
//! - a v0 account universe past 256, which a u8 index cannot address.
//!
//! None of these can execute, so none was a bypass. Each was an
//! `artifact_bound` verdict — a digest, a scope, a layer report — about a
//! frame that is not a transaction, and in the legacy case a layer report
//! explaining an impossible index as something it is not. These pin the
//! refusal, at the parser and through the pipeline, without the agave
//! crates; the oracle keeps proving the property against the crates
//! themselves.

// The pipeline test below needs tokio (a network-capable feature); without
// one, the helpers only it uses are unused.
#![cfg_attr(
    not(any(feature = "rpc", feature = "cli")),
    allow(unused_imports, dead_code)
)]

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::tx_artifact::{parse_transaction, ArtifactParseError};
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, UnobservedCode, VerificationInput, VerificationScope,
};

const SYSTEM: &str = "11111111111111111111111111111111";

fn corpus_entry(name: &str) -> serde_json::Value {
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/artifacts/sak_bridge_corpus.json"))
            .expect("corpus must parse");
    raw["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|e| e["name"] == name)
        .unwrap_or_else(|| panic!("corpus entry {name}"))
        .clone()
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

fn compact_u16(mut v: usize, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn transfer_data(lamports: u64) -> Vec<u8> {
    let mut d = vec![2, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d
}

/// The corpus transfer, whose layout is fixed: 65 bytes of signature, a
/// 3-byte header, key count at 68, three keys, the blockhash, then one
/// instruction at 198: program index, account count, indexes at 200–201.
fn transfer() -> Vec<u8> {
    bytes(&corpus_entry("legacy_single_transfer")["raw"])
}

/// A legacy frame built field by field: `keys` static keys, one instruction
/// under `program_index` naming `account_indexes`.
fn legacy(keys: usize, program_index: u8, account_indexes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    compact_u16(1, &mut out);
    out.extend_from_slice(&[0u8; 64]);
    out.extend_from_slice(&[1, 0, 1]);
    compact_u16(keys, &mut out);
    for i in 0..keys {
        out.extend_from_slice(&[i as u8 + 1; 32]);
    }
    out.extend_from_slice(&[9u8; 32]);
    compact_u16(1, &mut out);
    out.push(program_index);
    compact_u16(account_indexes.len(), &mut out);
    out.extend_from_slice(account_indexes);
    let d = transfer_data(1);
    compact_u16(d.len(), &mut out);
    out.extend_from_slice(&d);
    out
}

/// A v0 frame: `keys` static keys, one instruction naming `account_indexes`,
/// then `lookups` as (writable count, readonly count) pairs.
fn v0(keys: usize, account_indexes: &[u8], lookups: &[(usize, usize)]) -> Vec<u8> {
    let mut out = Vec::new();
    compact_u16(1, &mut out);
    out.extend_from_slice(&[0u8; 64]);
    out.push(0x80);
    out.extend_from_slice(&[1, 0, 1]);
    compact_u16(keys, &mut out);
    for i in 0..keys {
        out.extend_from_slice(&[i as u8 + 1; 32]);
    }
    out.extend_from_slice(&[9u8; 32]);
    compact_u16(1, &mut out);
    out.push((keys - 1) as u8);
    compact_u16(account_indexes.len(), &mut out);
    out.extend_from_slice(account_indexes);
    compact_u16(0, &mut out);
    compact_u16(lookups.len(), &mut out);
    for (t, (w, r)) in lookups.iter().enumerate() {
        out.extend_from_slice(&[0xA0 + t as u8; 32]);
        compact_u16(*w, &mut out);
        for i in 0..*w {
            out.push(i as u8);
        }
        compact_u16(*r, &mut out);
        for i in 0..*r {
            out.push((*w + i) as u8);
        }
    }
    out
}

#[test]
fn the_fee_payer_cannot_be_a_program() {
    let err = parse_transaction(&legacy(3, 0, &[0, 1])).expect_err("refused");
    assert!(
        matches!(err, ArtifactParseError::ProgramIsFeePayer { index: 0 }),
        "{err}"
    );
    // The same frame under a legal program index parses.
    parse_transaction(&legacy(3, 2, &[0, 1])).expect("legal");
}

#[test]
fn a_legacy_account_index_past_the_static_keys_is_refused() {
    // Three keys; index 3 does not exist and there are no lookups.
    let err = parse_transaction(&legacy(3, 2, &[0, 3])).expect_err("refused");
    assert!(
        matches!(
            err,
            ArtifactParseError::AccountIndexOutOfRange {
                index: 0,
                account_index: 3,
                keys: 3
            }
        ),
        "{err}"
    );
    let err = parse_transaction(&legacy(3, 2, &[0, 255])).expect_err("refused");
    assert!(
        matches!(
            err,
            ArtifactParseError::AccountIndexOutOfRange {
                account_index: 255,
                ..
            }
        ),
        "{err}"
    );
}

/// The corpus's own recorded mutation: flipping the second account index
/// byte of the transfer (offset 201) makes it 254. web3.js accepts the
/// frame; the runtime does not; Graphite now does not.
#[test]
fn the_corpus_flip_the_runtime_refuses_is_refused() {
    for at in [200usize, 201] {
        let mut raw = transfer();
        raw[at] ^= 0xff;
        let err = parse_transaction(&raw).expect_err("refused");
        assert!(
            matches!(err, ArtifactParseError::AccountIndexOutOfRange { .. }),
            "flip at {at}: {err}"
        );
    }
    parse_transaction(&transfer()).expect("the unflipped transfer parses");
}

#[test]
fn a_v0_account_index_past_the_loaded_universe_is_refused() {
    // Two static keys plus 3 loaded (2 writable, 1 readonly): indexes 0..=4.
    parse_transaction(&v0(2, &[0, 4], &[(2, 1)])).expect("index 4 is the last loaded key");
    let err = parse_transaction(&v0(2, &[0, 5], &[(2, 1)])).expect_err("refused");
    assert!(
        matches!(
            err,
            ArtifactParseError::AccountIndexOutOfRange {
                account_index: 5,
                keys: 5,
                ..
            }
        ),
        "{err}"
    );
}

#[test]
fn a_v0_lookup_that_loads_nothing_is_refused() {
    let err = parse_transaction(&v0(2, &[0, 1], &[(0, 0)])).expect_err("refused");
    assert!(
        matches!(err, ArtifactParseError::EmptyLookup { .. }),
        "{err}"
    );
    parse_transaction(&v0(2, &[0, 1], &[(0, 1)])).expect("one readonly address is enough");
}

#[test]
fn more_than_256_accounts_is_refused() {
    // Three static keys plus one table loading 200 writable and 60 readonly
    // = 263 keys, well within the packet size (one byte per loaded index).
    let frame = v0(3, &[0, 1], &[(200, 60)]);
    assert!(frame.len() <= 1232);
    let err = parse_transaction(&frame).expect_err("refused");
    assert!(
        matches!(err, ArtifactParseError::TooManyAccounts { total: 263 }),
        "{err}"
    );
    // 253 loaded on 3 static = 256 exactly is the largest legal universe.
    parse_transaction(&v0(3, &[0, 255], &[(200, 53)])).expect("256 keys is legal");
}

fn describe(artifact: Vec<u8>, program_id: &str) -> VerificationInput {
    let keys = strings(&corpus_entry("legacy_single_transfer")["static_keys"]);
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send 0.002 SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: program_id.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![keys[0].clone(), keys[1].clone()],
        instruction_data: Some(transfer_data(2_000_000)),
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
        signed_transaction: Some(artifact),
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

/// Through the pipeline: the frame the runtime refuses fails L2 with the
/// parse reason, is not approved, and — the point — is not explained as
/// anything else. Before Round 12 this exact frame passed L2 as "1 of its
/// account(s) arrive through address lookup tables".
// tokio is a dependency only of the network-capable features.
#[cfg(any(feature = "rpc", feature = "cli"))]
#[tokio::test]
async fn a_frame_the_runtime_refuses_fails_l2_with_the_reason() {
    let core = GraphiteCore::new();
    let mut raw = transfer();
    raw[200] ^= 0xff;
    let r = core
        .verify_async(&describe(raw, SYSTEM))
        .await
        .expect("verification must run");
    assert!(!r.approved);
    let l2 = r
        .layers
        .iter()
        .find(|l| l.layer.starts_with("L2"))
        .expect("L2 reports");
    assert_eq!(l2.status, LayerStatus::Failed, "{}", l2.reason);
    assert!(
        l2.reason.contains("could not be parsed") && l2.reason.contains("account index 255"),
        "{}",
        l2.reason
    );
    assert!(
        !l2.reason.contains("lookup table"),
        "an impossible index must not be explained as a lookup: {}",
        l2.reason
    );
    // The blocked verdict is bound to the bytes it refused, and says the
    // bytes were not read as a transaction.
    match &r.scope {
        VerificationScope::ArtifactBound {
            unobserved_codes, ..
        } => assert!(
            unobserved_codes.contains(&UnobservedCode::ArtifactUnparsed),
            "{unobserved_codes:?}"
        ),
        other => panic!("{other:?}"),
    }
}

/// A v1 message behind a legacy/v0 signature count is not a v1 transaction.
/// Graphite parses v1 since Round 19 (F-19-V1), but only as a v1 FRAME —
/// `0x81` first, signatures last (`tests/round19_v1_transactions.rs`). The
/// runtime's decoder refuses this shape ("invalid message version"), and
/// Graphite must refuse it by name, never read it as something else.
#[test]
fn a_version_1_message_is_refused_by_name() {
    let mut frame = v0(2, &[0, 1], &[(0, 1)]);
    // The version prefix sits right after the signature array.
    assert_eq!(frame[65], 0x80);
    frame[65] = 0x81;
    let err = parse_transaction(&frame).expect_err("refused");
    assert!(
        matches!(err, ArtifactParseError::UnsupportedVersion(1)),
        "{err}"
    );
    assert!(err.to_string().contains("v1"), "{err}");
}
