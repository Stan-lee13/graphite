//! A1-01 (2026-09-29 audit): a draining token `CloseAccount` cannot hide
//! behind one trailing data byte.
//!
//! Round 21 exempts a token close from Check 2's `CloseAccount` pattern and
//! Check 10's `close` class when the transaction's own bytes show it pays the
//! closed account's lamports back to its authority, and only while every
//! close in the message does (`every_close_refunds_its_authority`).
//! `verification::self_refund_closes` counted a close only when its data was
//! exactly `[9]` (`ix.data.len() != 1` skipped the rest). SPL Token, p-token
//! and Token-2022 read the leading byte and ignore what follows, so `[9, 0]`
//! is a close to the runtime. A message with one honest self-refunding `[9]`
//! and one `[9, 0]` closing the victim's wSOL account to an attacker was read
//! as having a single, refunding close: the draining sibling inherited the
//! exemption and came out Clear.
//!
//! The fix counts every instruction `is_token_close` recognises by its leading
//! byte, as the runtime does; the length condition is gone. The draining close
//! keeps `every_close_refunds_its_authority` false and stays Blocked.
//!
//! The control pins that the canonical `[9]` draining sibling is Blocked (as
//! `round21_open_list::one_draining_close_keeps_every_sibling_close_blocked`
//! also does). The regression test pins the same verdict with a trailing byte,
//! on the artifact-bound path with every instruction described.
#![cfg(any(feature = "rpc", feature = "cli"))]

use graphite_core::manifest::load_seed_manifests;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationResult,
};

const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// The victim's wallet: fee payer, signer, authority of both token accounts.
const WALLET: [u8; 32] = [81u8; 32];
/// An empty token account the wallet closes back to itself (the cover).
const EMPTY: [u8; 32] = [87u8; 32];
/// The wallet's wrapped-SOL account — the thing drained.
const WSOL: [u8; 32] = [82u8; 32];
const ATTACKER: [u8; 32] = [83u8; 32];

fn b58(k: &[u8; 32]) -> String {
    bs58::encode(k).into_string()
}
fn token() -> [u8; 32] {
    bs58::decode(TOKEN).into_vec().unwrap().try_into().unwrap()
}

/// A legacy frame: `keys` under `header`, one empty signature slot per
/// signer, then `(program index, account indexes, data)` instructions.
fn frame(keys: &[[u8; 32]], header: [u8; 3], ixs: &[(u8, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![header[0]];
    for _ in 0..header[0] {
        out.extend_from_slice(&[0u8; 64]);
    }
    out.extend_from_slice(&header);
    out.push(keys.len() as u8);
    for k in keys {
        out.extend_from_slice(k);
    }
    out.extend_from_slice(&[9u8; 32]);
    out.push(ixs.len() as u8);
    for (p, accs, data) in ixs {
        out.push(*p);
        out.push(accs.len() as u8);
        out.extend_from_slice(accs);
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    }
    out
}

/// keys [wallet (payer), empty, wsol, attacker, token program];
/// instruction 0 closes EMPTY to the wallet (self-refund, data `[9]`),
/// instruction 1 closes WSOL to the attacker with `drain_data`.
fn verify_drain(drain_data: Vec<u8>) -> VerificationResult {
    let keys = [WALLET, EMPTY, WSOL, ATTACKER, token()];
    let f = frame(
        &keys,
        [1, 0, 1],
        &[(4, vec![1, 0, 0], vec![9]), (4, vec![2, 3, 0], drain_data)],
    );
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "close".to_string(),
            raw_natural_language: "close my empty token account".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: TOKEN.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "09".to_string(),
        account_addresses: vec![b58(&EMPTY), b58(&WALLET), b58(&WALLET)],
        instruction_data: Some(vec![9]),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: Some(f),
        // The draining close is DECLARED honestly — a declared sibling is
        // exactly what Check 2 exists to judge.
        transaction_instructions: vec![TransactionInstruction {
            program_id: TOKEN.to_string(),
            instruction_discriminator: "09".to_string(),
            account_addresses: vec![b58(&WSOL), b58(&ATTACKER), b58(&WALLET)],
            cpi_targets: vec![],
        }],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    };
    GraphiteCore::with_registry(load_seed_manifests())
        .verify(&input)
        .expect("verified")
}

fn l2_passed(r: &VerificationResult) -> bool {
    r.layers
        .iter()
        .find(|l| l.layer.starts_with("L2"))
        .is_some_and(|l| l.status != LayerStatus::Failed)
}

/// Blocked for the draining sibling close: Check 2's CloseAccount pattern,
/// or Check 10's `close` class with no intent.
fn draining_close_blocked(r: &VerificationResult) -> bool {
    r.risk_verdict.status == "Blocked"
        && r.risk_verdict.findings.iter().any(|f| {
            f.reason.contains("secondary instruction")
                && (f.reason.contains("CloseAccount")
                    || f.reason.contains("high-risk class 'close'"))
        })
}

/// Control: with canonical `[9]` data the draining sibling is Blocked.
#[test]
fn control_a_draining_sibling_close_is_blocked() {
    let r = verify_drain(vec![9]);
    assert!(
        l2_passed(&r),
        "L2 should locate and cover both: {:?}",
        r.layers
    );
    assert!(draining_close_blocked(&r), "{:?}", r.risk_verdict);
}

/// A1-01: one trailing byte the Token program ignores does not change the
/// verdict; the same draining close is still Blocked.
#[test]
fn a_draining_sibling_close_with_a_trailing_byte_is_still_blocked() {
    let r = verify_drain(vec![9, 0]);
    // The bytes are bound and every instruction described: this is the
    // artifact-bound path, not a parse failure.
    assert!(
        l2_passed(&r),
        "L2 should locate and cover both: {:?}",
        r.layers
    );
    assert!(
        draining_close_blocked(&r),
        "a CloseAccount paying the attacker was exempted as a self-refund because \
         `[9, 0]` was not counted as a close: {:?}",
        r.risk_verdict
    );
}
