//! A1-04 (2026-09-29 audit): a p-token `batch` instruction as a declared
//! sibling meets a risk check.
//!
//! Graphite keys the known-risky table and the manifest risk class on an
//! instruction's leading bytes (`09`, `06`, `04`). p-token's `batch`
//! (SIMD-0266, leading byte 255) carries several token instructions, each as
//! `(n_accounts u8, data_len u8, data)`, and dispatches each to the ordinary
//! processors, so `[255, 3, 1, 9]` over `[wsol, attacker, wallet]` is a
//! `CloseAccount` paying the attacker. Its leading byte `ff` matched no table
//! entry and no manifest entry, so Check 2 and Check 10 had nothing to act on
//! and the sibling was Clear. Reachability depends on `batch` being live on
//! the cluster's Token program; the finding was filed as P3 with that
//! unverified.
//!
//! The fix lists `ff` on SPL Token and Token-2022 in `RISKY_PATTERNS`
//! (`MaliciousAccountChange`). Graphite does not decode a batch into its inner
//! instructions, so it refuses one rather than judge it by `ff`.
//!
//! The test pins that a batch sibling wrapping a draining close, beside a
//! System transfer, is Blocked.
#![cfg(any(feature = "rpc", feature = "cli"))]

use graphite_core::manifest::load_seed_manifests;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const WALLET: [u8; 32] = [81u8; 32];
const RECIPIENT: [u8; 32] = [84u8; 32];
const WSOL: [u8; 32] = [82u8; 32];
const ATTACKER: [u8; 32] = [83u8; 32];

fn b58(k: &[u8; 32]) -> String {
    bs58::encode(k).into_string()
}
fn token() -> [u8; 32] {
    bs58::decode(TOKEN).into_vec().unwrap().try_into().unwrap()
}

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

#[test]
fn a_token_batch_sibling_wrapping_a_draining_close_is_blocked() {
    // keys [wallet (payer), recipient, wsol, attacker, system, token]
    let keys = [WALLET, RECIPIENT, WSOL, ATTACKER, [0u8; 32], token()];
    let mut transfer = vec![2u8, 0, 0, 0];
    transfer.extend_from_slice(&1_000u64.to_le_bytes());
    let batch = vec![255u8, 3, 1, 9];
    let f = frame(
        &keys,
        [1, 0, 2],
        &[
            (4, vec![0, 1], transfer.clone()),
            (5, vec![2, 3, 0], batch.clone()),
        ],
    );
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send 1000 lamports".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: "11111111111111111111111111111111".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![b58(&WALLET), b58(&RECIPIENT)],
        instruction_data: Some(transfer),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: Some(f),
        transaction_instructions: vec![TransactionInstruction {
            program_id: TOKEN.to_string(),
            instruction_discriminator: hex::encode(&batch),
            account_addresses: vec![b58(&WSOL), b58(&ATTACKER), b58(&WALLET)],
            cpi_targets: vec![],
        }],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    };
    let r = GraphiteCore::with_registry(load_seed_manifests())
        .verify(&input)
        .expect("verified");
    assert_eq!(
        r.risk_verdict.status, "Blocked",
        "a Token instruction Graphite cannot name (leading byte 0xff) was risk-Clear as a sibling: {:?}",
        r.risk_verdict
    );
}
