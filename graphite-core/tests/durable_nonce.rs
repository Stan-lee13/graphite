//! Durable-nonce transactions: a transaction with no clock.
//!
//! Every state-based conclusion Graphite reaches is true at verification
//! time. A normal transaction is bounded to roughly a minute after that by
//! its blockhash, which is what makes "verified, then signed, then sent" a
//! coherent sequence. A durable-nonce transaction replaces the blockhash with
//! a value that never expires: once signed it stays valid until its nonce
//! account advances, and can be submitted an hour or a month later, by
//! whoever holds the bytes, against state that no longer resembles what was
//! verified. The bridge's `lastValidBlockHeight` expiry does not apply to it.
//!
//! The runtime's rule is structural — instruction 0 is a System
//! `AdvanceNonceAccount` — and so is Graphite's. Both corpus entries here were
//! serialized by `@solana/web3.js` (`SystemProgram.nonceAdvance`), so the
//! shape is the SDK's, not this test's.
//!
//! Refused at L2 by default. With the operator opt-in, refused until the
//! nonce account is verified on-chain — see `durable_nonce_rpc.rs` for the
//! fetch-and-check half with a local mock serving the nonce account.

use graphite_core::manifest::load_seed_manifests;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::tx_artifact::{
    check_durable_nonce, decode_nonce_account, durable_nonce, parse_transaction, DurableNonce,
    NonceAccountState, ADVANCE_NONCE_ACCOUNT, NONCE_ACCOUNT_SIZE, SYSTEM_PROGRAM,
};
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationResult,
};

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

/// A nonce account's data as the runtime lays it out: `NonceVersions::Current`
/// (u32 = 1), `State::Initialized` (u32 = 1), authority, nonce, fee (u64).
pub fn nonce_account_data(authority: &str, nonce_value: &str) -> Vec<u8> {
    let mut d = Vec::with_capacity(NONCE_ACCOUNT_SIZE);
    d.extend_from_slice(&1u32.to_le_bytes());
    d.extend_from_slice(&1u32.to_le_bytes());
    d.extend_from_slice(&bs58::decode(authority).into_vec().expect("base58"));
    d.extend_from_slice(&bs58::decode(nonce_value).into_vec().expect("base58"));
    d.extend_from_slice(&5000u64.to_le_bytes());
    assert_eq!(d.len(), NONCE_ACCOUNT_SIZE);
    d
}

/// Instruction 0's accounts, as the corpus static keys lay them out for
/// `SystemProgram.nonceAdvance`: nonce account, RecentBlockhashes sysvar,
/// authority.
struct Shape {
    payer: String,
    nonce_account: String,
    destination: String,
    nonce_value: String,
    raw: Vec<u8>,
}

fn shape(name: &str) -> Shape {
    let e = corpus_entry(name);
    let keys = strings(&e["static_keys"]);
    let raw = bytes(&e["raw"]);
    let m = parse_transaction(&raw).expect("must parse");
    Shape {
        payer: keys[0].clone(),
        nonce_account: keys[1].clone(),
        destination: keys[2].clone(),
        nonce_value: m.recent_blockhash.clone(),
        raw,
    }
}

/// The transfer is described as the primary instruction and the nonce
/// advance as a declared sibling, so nothing about sibling coverage is what
/// fails: the ONLY thing that can fail L2 here is the nonce rule.
fn verify_with(core: &GraphiteCore, s: &Shape) -> VerificationResult {
    let mut data = vec![2, 0, 0, 0];
    data.extend_from_slice(&2_000_000u64.to_le_bytes());
    let nonce_sibling = TransactionInstruction {
        program_id: SYSTEM_PROGRAM.to_string(),
        instruction_discriminator: "04000000".to_string(),
        account_addresses: vec![
            s.nonce_account.clone(),
            "SysvarRecentB1ockHashes11111111111111111111".to_string(),
            s.payer.clone(),
        ],
        cpi_targets: vec![],
    };
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send 0.002 SOL".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: SYSTEM_PROGRAM.to_string(),
        protocol_version: "1.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![s.payer.clone(), s.destination.clone()],
        instruction_data: Some(data),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: Default::default(),
        compute_units: 450,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: Some(s.raw.clone()),
        transaction_instructions: vec![nonce_sibling],
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

// ─── Detection from the bytes ────────────────────────────────────────────────

#[test]
fn web3js_nonce_advance_in_position_zero_is_detected_from_the_bytes() {
    let s = shape("legacy_durable_nonce");
    let m = parse_transaction(&s.raw).unwrap();
    let n = durable_nonce(&m).expect("instruction 0 is SystemProgram.nonceAdvance");
    assert_eq!(n.nonce_account, s.nonce_account);
    assert_eq!(n.nonce_authority.as_deref(), Some(s.payer.as_str()));
    assert!(n.authority_is_signer, "the payer signs");
    assert_eq!(n.nonce_value, s.nonce_value);
    // The value in the blockhash slot is the corpus's NONCE_VALUE, not a
    // blockhash: it is the base58 of a seeded keypair's public key.
    assert_ne!(
        n.nonce_value, "11111111111111111111111111111111",
        "the slot carries the nonce, not the placeholder blockhash the other entries use"
    );
    // And the instruction's own bytes are what the runtime checks.
    assert_eq!(m.instructions[0].program_id, SYSTEM_PROGRAM);
    assert_eq!(&m.instructions[0].data[..4], &ADVANCE_NONCE_ACCOUNT);
    println!(
        "durable nonce: account {} authority {} value {}",
        n.nonce_account,
        n.nonce_authority.unwrap(),
        n.nonce_value
    );
}

/// The runtime honours a nonce advance ONLY in position 0. The same two
/// instructions the other way round are an ordinary transaction with an
/// ordinary blockhash, and treating it as nonce-based would refuse a
/// transaction the runtime treats normally.
#[test]
fn a_nonce_advance_anywhere_but_position_zero_is_not_a_nonce_transaction() {
    let s = shape("legacy_nonce_advance_not_first");
    let m = parse_transaction(&s.raw).unwrap();
    assert_eq!(m.instructions.len(), 2);
    assert_eq!(&m.instructions[1].data[..4], &ADVANCE_NONCE_ACCOUNT);
    assert!(
        durable_nonce(&m).is_none(),
        "position 1 does not make a durable-nonce transaction"
    );
}

/// Trailing bytes after the discriminator do not hide the advance: the
/// runtime's `limited_deserialize` ignores them, so a transaction it treats
/// as nonce-based must be treated as nonce-based here too.
#[test]
fn trailing_bytes_after_the_discriminator_do_not_hide_the_advance() {
    let s = shape("legacy_durable_nonce");
    let mut m = parse_transaction(&s.raw).unwrap();
    m.instructions[0].data.extend_from_slice(&[0xde, 0xad]);
    assert!(durable_nonce(&m).is_some());
    // And a different System instruction is not an advance.
    m.instructions[0].data = vec![2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(durable_nonce(&m).is_none());
    // Nor is a three-byte prefix of the discriminator.
    m.instructions[0].data = vec![4, 0, 0];
    assert!(durable_nonce(&m).is_none());
}

// ─── The nonce account's state ───────────────────────────────────────────────

#[test]
fn a_nonce_account_decodes_from_the_runtime_layout() {
    let s = shape("legacy_durable_nonce");
    let data = nonce_account_data(&s.payer, &s.nonce_value);
    let state = decode_nonce_account(SYSTEM_PROGRAM, &data).expect("initialized nonce account");
    assert_eq!(state.authority, s.payer);
    assert_eq!(state.nonce_value, s.nonce_value);

    // The legacy version tag (0) is also honoured by the runtime.
    let mut legacy = data.clone();
    legacy[0..4].copy_from_slice(&0u32.to_le_bytes());
    assert!(decode_nonce_account(SYSTEM_PROGRAM, &legacy).is_ok());

    // Everything the runtime refuses, refused here with a reason.
    let wrong_owner =
        decode_nonce_account("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", &data).unwrap_err();
    assert!(wrong_owner.contains("System program"), "{wrong_owner}");
    let short = decode_nonce_account(SYSTEM_PROGRAM, &data[..79]).unwrap_err();
    assert!(short.contains("79 bytes"), "{short}");
    let mut uninit = data.clone();
    uninit[4..8].copy_from_slice(&0u32.to_le_bytes());
    let uninit = decode_nonce_account(SYSTEM_PROGRAM, &uninit).unwrap_err();
    assert!(uninit.contains("Initialized"), "{uninit}");
    let mut future = data.clone();
    future[0..4].copy_from_slice(&7u32.to_le_bytes());
    let future = decode_nonce_account(SYSTEM_PROGRAM, &future).unwrap_err();
    assert!(future.contains("version 7"), "{future}");
}

#[test]
fn every_mismatch_between_message_and_nonce_account_is_named() {
    let s = shape("legacy_durable_nonce");
    let m = parse_transaction(&s.raw).unwrap();
    let declared = durable_nonce(&m).unwrap();
    let good = NonceAccountState {
        authority: s.payer.clone(),
        nonce_value: s.nonce_value.clone(),
    };
    assert!(check_durable_nonce(&declared, &good).is_ok());

    // The nonce has advanced (or the message was built against another
    // account): the value differs.
    let advanced = NonceAccountState {
        nonce_value: s.destination.clone(),
        ..good.clone()
    };
    let err = check_durable_nonce(&declared, &advanced).unwrap_err();
    assert!(err.contains("nonce has advanced"), "{err}");

    // The account's authority is not the signer the instruction names.
    let other_authority = NonceAccountState {
        authority: s.destination.clone(),
        ..good.clone()
    };
    let err = check_durable_nonce(&declared, &other_authority).unwrap_err();
    assert!(err.contains("authority is"), "{err}");

    // The instruction names an authority that does not sign.
    let unsigned = DurableNonce {
        authority_is_signer: false,
        ..declared.clone()
    };
    let err = check_durable_nonce(&unsigned, &good).unwrap_err();
    assert!(err.contains("not a required signer"), "{err}");

    // The instruction names no authority at all.
    let missing = DurableNonce {
        nonce_authority: None,
        ..declared
    };
    let err = check_durable_nonce(&missing, &good).unwrap_err();
    assert!(err.contains("no nonce authority"), "{err}");
}

// ─── Through the pipeline ────────────────────────────────────────────────────

/// Default posture: refused at L2, and the reason says exactly what the
/// transaction is and why that matters.
#[test]
fn a_durable_nonce_transaction_fails_l2_by_default() {
    let s = shape("legacy_durable_nonce");
    let core = GraphiteCore::with_registry(load_seed_manifests());
    let r = verify_with(&core, &s);
    let (status, reason) = l2(&r);
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(reason.contains("DURABLE-NONCE"), "{reason}");
    assert!(reason.contains(&s.nonce_account), "{reason}");
    assert!(reason.contains(&s.nonce_value), "{reason}");
    assert!(reason.contains("does not expire"), "{reason}");
    assert!(reason.contains("GRAPHITE_ALLOW_DURABLE_NONCE"), "{reason}");
    assert!(!r.approved, "L2 is a hard gate");
    println!("L2: {reason}");
}

/// The opt-in is "permitted once verified on-chain". With no RPC client there
/// is nothing to verify against, so the opt-in alone changes nothing about
/// the verdict — the reason changes to say why.
#[test]
fn the_operator_opt_in_without_rpc_still_refuses() {
    let s = shape("legacy_durable_nonce");
    let mut core = GraphiteCore::with_registry(load_seed_manifests());
    core.set_allow_durable_nonce(true);
    let r = verify_with(&core, &s);
    let (status, reason) = l2(&r);
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(
        reason.contains("Permitted by operator policy only once"),
        "{reason}"
    );
    assert!(reason.contains("no RPC client"), "{reason}");
    assert!(!r.approved);
}

/// The control: the same two instructions with the advance in position 1 are
/// an ordinary transaction, and L2 says nothing about nonces. Without this the
/// three tests above could pass on a rule that fires for any nonce advance
/// anywhere, which would refuse transactions the runtime treats normally.
#[test]
fn the_same_instructions_with_the_advance_second_are_not_refused_for_it() {
    let s = shape("legacy_nonce_advance_not_first");
    let core = GraphiteCore::with_registry(load_seed_manifests());
    let r = verify_with(&core, &s);
    let (_, reason) = l2(&r);
    assert!(
        !reason.contains("DURABLE-NONCE"),
        "an advance in position 1 must not trigger the nonce rule: {reason}"
    );
}
