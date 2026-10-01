//! A1-05 (2026-09-29 audit, not a finding): a v0 `AdvanceNonceAccount` whose
//! nonce account arrives through a lookup table.
//!
//! agave (`require_static_nonce_account`) does not treat such a transaction
//! as nonce-based; it is judged by its blockhash. Graphite still declares it
//! nonce-based (`durable_nonce` names the position `<lookup-table index N>`),
//! which only ever refuses more: with the default policy L2 fails, and with
//! the opt-in the placeholder is not a fetchable address, so the on-chain
//! check fails too. The audit found this correct and fail-closed, but nothing
//! tested the branch.
//!
//! The test is kept as a pin of the fail-closed reading, so a later change
//! cannot turn the placeholder into a silent `None`.
use graphite_core::tx_artifact::{durable_nonce, parse_transaction};

fn b58(k: &[u8; 32]) -> String {
    bs58::encode(k).into_string()
}

/// v0: keys [payer, system]; lookup table T loads one WRITABLE address; the
/// only instruction is System AdvanceNonceAccount over
/// [loaded #2, payer, payer].
fn v0_nonce_via_lookup() -> Vec<u8> {
    let payer = [1u8; 32];
    let system = [0u8; 32];
    let table = [7u8; 32];
    let mut out = vec![1u8];
    out.extend_from_slice(&[0u8; 64]);
    out.push(0x80); // v0
    out.extend_from_slice(&[1, 0, 1]);
    out.push(2);
    out.extend_from_slice(&payer);
    out.extend_from_slice(&system);
    out.extend_from_slice(&[9u8; 32]); // "blockhash" (the nonce value)
    out.push(1); // one instruction
    out.push(1); // program: system
    out.push(3);
    out.extend_from_slice(&[2, 0, 0]);
    out.push(4);
    out.extend_from_slice(&[4, 0, 0, 0]);
    out.push(1); // one lookup
    out.extend_from_slice(&table);
    out.push(1);
    out.push(0); // writable index 0
    out.push(0); // no readonly
    out
}

#[test]
fn a_nonce_account_from_a_lookup_table_is_still_declared_nonce_based() {
    let m = parse_transaction(&v0_nonce_via_lookup()).expect("a valid v0 frame");
    assert_eq!(m.version, Some(0));
    let n = durable_nonce(&m).expect("instruction 0 is AdvanceNonceAccount: declared, not dropped");
    assert_eq!(n.nonce_account, "<lookup-table index 2>");
    assert_eq!(n.nonce_authority.as_deref(), Some(b58(&[1u8; 32]).as_str()));
    assert!(n.authority_is_signer);
    // The placeholder is in no writable set, so the opt-in check refuses it.
    assert!(!n.nonce_account_writable);
}
