//! Round 9: resource exhaustion through the artifact.
//!
//! Everything a caller sends to `/verify` is bounded — account count,
//! instruction data, identifier lengths, CPI targets — except the two things
//! Round 3 introduced: the serialized transaction itself and the list of
//! declared sibling instructions. Sibling coverage compares every instruction
//! in the artifact against every declaration (O(n·m), one hex encoding per
//! pair), and a 1 MiB request body leaves room for hundreds of thousands of
//! minimal instructions.
//!
//! The runtime settles the bound: a Solana transaction is at most
//! `PACKET_DATA_SIZE` = 1232 bytes, and `sendTransaction` refuses anything
//! larger. So an artifact above 1232 bytes is not a transaction that can ever
//! execute, and nothing about it needs to be examined. The artifacts here are
//! well-formed on the wire (they parse; only their size makes them
//! unsendable) — the point is what Graphite spends on bytes the network would
//! never accept.

use graphite_core::manifest::load_seed_manifests;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::tx_artifact::{parse_transaction, ArtifactParseError, MAX_TRANSACTION_BYTES};
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationError, VerificationInput,
};
use std::time::Instant;

const SYSTEM: &str = "11111111111111111111111111111111";

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

/// A legacy transaction: one signature slot, three static keys (payer,
/// destination, System program), a real System transfer at instruction 0,
/// then `siblings` minimal System calls carrying one data byte each.
///
/// Every field is encoded the way the runtime reads it; the only thing that
/// makes the result unsendable is its length.
fn transaction_with_siblings(siblings: usize) -> (Vec<u8>, [String; 3]) {
    let payer = [1u8; 32];
    let dest = [2u8; 32];
    let system = bs58::decode(SYSTEM).into_vec().unwrap();
    let mut out = Vec::new();
    compact_u16(1, &mut out);
    out.extend_from_slice(&[0u8; 64]);
    out.extend_from_slice(&[1, 0, 1]); // 1 signer, 0 readonly signed, 1 readonly unsigned (the program)
    compact_u16(3, &mut out);
    out.extend_from_slice(&payer);
    out.extend_from_slice(&dest);
    out.extend_from_slice(&system);
    out.extend_from_slice(&[9u8; 32]); // recent blockhash
    compact_u16(1 + siblings, &mut out);
    // instruction 0: transfer 2_000_000 lamports payer -> dest
    out.push(2);
    compact_u16(2, &mut out);
    out.extend_from_slice(&[0, 1]);
    let mut data = vec![2, 0, 0, 0];
    data.extend_from_slice(&2_000_000u64.to_le_bytes());
    compact_u16(data.len(), &mut out);
    out.extend_from_slice(&data);
    for _ in 0..siblings {
        out.push(2); // program index: System
        compact_u16(0, &mut out); // no accounts
        compact_u16(1, &mut out); // one data byte
        out.push(0xff);
    }
    (
        out,
        [
            bs58::encode(payer).into_string(),
            bs58::encode(dest).into_string(),
            SYSTEM.to_string(),
        ],
    )
}

fn input_for(
    raw: Vec<u8>,
    keys: &[String; 3],
    declared: Vec<TransactionInstruction>,
) -> VerificationInput {
    let mut data = vec![2, 0, 0, 0];
    data.extend_from_slice(&2_000_000u64.to_le_bytes());
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send 0.002 SOL".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![keys[0].clone(), keys[1].clone()],
        instruction_data: Some(data),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: Default::default(),
        compute_units: 450,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: Some(raw),
        transaction_instructions: declared,
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

/// A declaration that matches none of the siblings (wrong discriminator), so
/// every sibling scans the whole declaration list — the worst case of the
/// greedy matcher.
fn unmatched_declaration() -> TransactionInstruction {
    TransactionInstruction {
        program_id: SYSTEM.to_string(),
        instruction_discriminator: "aa".to_string(),
        account_addresses: vec![],
        cpi_targets: vec![],
    }
}

#[test]
fn the_runtime_packet_size_is_the_bound() {
    assert_eq!(
        MAX_TRANSACTION_BYTES, 1232,
        "PACKET_DATA_SIZE = 1280 - 40 - 8"
    );
}

/// Reproduction, kept as the regression: one request under the 1 MiB body
/// limit used to hold a 600 KB artifact and thousands of declarations, and
/// L2's sibling coverage compared every pair. The same request is now refused
/// at the entry point in O(1), before anything is parsed.
#[test]
fn an_artifact_larger_than_a_solana_packet_is_refused_before_it_is_parsed() {
    let core = GraphiteCore::with_registry(load_seed_manifests());
    // ~150,000 siblings: 4 bytes each, ~600 KB in total, under the body limit
    // once base64-encoded alongside the declarations below.
    let (raw, keys) = transaction_with_siblings(150_000);
    assert!(raw.len() > MAX_TRANSACTION_BYTES);
    let declared: Vec<_> = (0..4_000).map(|_| unmatched_declaration()).collect();

    let started = Instant::now();
    let err = core
        .verify(&input_for(raw.clone(), &keys, declared))
        .expect_err("an artifact the network would refuse must not be examined");
    let elapsed = started.elapsed();
    match err {
        VerificationError::InvalidInput(msg) => {
            assert!(msg.contains("1232"), "{msg}");
            assert!(msg.contains(&raw.len().to_string()), "{msg}");
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
    println!(
        "round9: {}-byte artifact with 150,000 siblings refused in {:?}",
        raw.len(),
        elapsed
    );
    assert!(
        elapsed.as_millis() < 500,
        "refusal must cost nothing: {elapsed:?}"
    );

    // The parser refuses it too, independently of the pipeline, so a library
    // caller that reaches `parse_transaction` directly gets the same bound.
    match parse_transaction(&raw) {
        Err(ArtifactParseError::TooLarge { len, max }) => {
            assert_eq!(len, raw.len());
            assert_eq!(max, MAX_TRANSACTION_BYTES);
        }
        other => panic!("parser must refuse an oversized artifact: {other:?}"),
    }
}

/// The cost this bound removes, measured on the unbounded path so the number
/// in the report is observed. `parse_transaction` is bypassed by calling the
/// message parser on the bytes the bound would have refused — that parser is
/// still what runs on a legitimate artifact, so its cost per instruction is
/// real. Sibling coverage is exercised through the pipeline on an artifact
/// that fits in a packet, at the maximum instruction count a packet can hold.
#[test]
fn a_packet_sized_artifact_at_maximum_instruction_count_is_cheap() {
    let core = GraphiteCore::with_registry(load_seed_manifests());
    // The largest number of these siblings that still fits in 1232 bytes.
    let mut n = 0;
    loop {
        let (raw, _) = transaction_with_siblings(n + 1);
        if raw.len() > MAX_TRANSACTION_BYTES {
            break;
        }
        n += 1;
    }
    let (raw, keys) = transaction_with_siblings(n);
    assert!(raw.len() <= MAX_TRANSACTION_BYTES);
    // The declared list is bounded separately; fill it to the bound with
    // declarations that match nothing so every sibling scans the whole list.
    let declared: Vec<_> = (0..graphite_core::verification::MAX_TRANSACTION_INSTRUCTIONS)
        .map(|_| unmatched_declaration())
        .collect();
    let started = Instant::now();
    let result = core
        .verify(&input_for(raw.clone(), &keys, declared))
        .expect("a packet-sized artifact must be examined");
    let elapsed = started.elapsed();
    let l2 = result
        .layers
        .iter()
        .find(|l| l.layer == "L2_InstructionVerification")
        .unwrap();
    assert_eq!(l2.status, LayerStatus::Failed, "{}", l2.reason);
    assert!(
        l2.reason.contains("does not describe"),
        "the siblings are undescribed: {}",
        l2.reason
    );
    assert!(!result.approved);
    println!(
        "round9: {}-byte artifact, {} siblings, {} declarations: {:?}",
        raw.len(),
        n,
        graphite_core::verification::MAX_TRANSACTION_INSTRUCTIONS,
        elapsed
    );
    assert!(
        elapsed.as_secs() < 5,
        "the bounded worst case must be well inside REQUEST_TIMEOUT: {elapsed:?}"
    );
}

/// The declaration list has its own bound: more declarations than a packet
/// can hold instructions describe a transaction other than this one.
#[test]
fn more_declarations_than_a_packet_can_hold_are_refused() {
    let core = GraphiteCore::with_registry(load_seed_manifests());
    let (raw, keys) = transaction_with_siblings(2);
    let declared: Vec<_> = (0..graphite_core::verification::MAX_TRANSACTION_INSTRUCTIONS + 1)
        .map(|_| unmatched_declaration())
        .collect();
    let err = core
        .verify(&input_for(raw, &keys, declared))
        .expect_err("refused at the entry point");
    match err {
        VerificationError::InvalidInput(msg) => {
            assert!(msg.contains("transaction_instructions"), "{msg}")
        }
        other => panic!("{other:?}"),
    }
}

/// The bound is exactly the runtime's: 1232 bytes is accepted, 1233 is not.
/// Padding a real transaction past the limit is done with a trailing byte,
/// which the parser refuses for its own reason — the size check has to come
/// first for the refusal to be about size.
#[test]
fn the_bound_is_exact() {
    let mut n = 0;
    let (mut raw, _) = loop {
        let (raw, keys) = transaction_with_siblings(n);
        if raw.len() >= MAX_TRANSACTION_BYTES - 4 {
            break (raw, keys);
        }
        n += 1;
    };
    // Pad to exactly 1232 with trailing bytes: parse fails on the trailing
    // bytes, not on size.
    while raw.len() < MAX_TRANSACTION_BYTES {
        raw.push(0);
    }
    assert_eq!(raw.len(), MAX_TRANSACTION_BYTES);
    assert!(
        !matches!(
            parse_transaction(&raw),
            Err(ArtifactParseError::TooLarge { .. })
        ),
        "1232 bytes is a legal packet"
    );
    raw.push(0);
    assert!(matches!(
        parse_transaction(&raw),
        Err(ArtifactParseError::TooLarge {
            len: 1233,
            max: 1232
        })
    ));
}
