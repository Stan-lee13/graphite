//! The parser, checked against REAL serialized devnet transactions.

use graphite_core::tx_artifact::{correspond, parse_transaction, ArtifactParseError};

/// Real serialized devnet transactions, committed with the repository.
///
/// The previous artifact tests used a hand-built blob — 64 filler bytes, the
/// described data, 64 more — which proved the substring search worked without
/// proving it meant anything. These are actual wire-format transactions with
/// signatures, a header, an account key table, a blockhash and compiled
/// instructions, built against devnet and simulated read-only. Nothing was
/// signed and nothing was submitted; the signature bytes are placeholders,
/// which is exactly the shape Graphite sees, since it verifies BEFORE signing.
fn artifacts() -> serde_json::Value {
    let raw = include_str!("../fixtures/artifacts/devnet_transactions.json");
    serde_json::from_str(raw).expect("committed artifact fixtures must parse")
}
fn blob(v: &serde_json::Value) -> Vec<u8> {
    v.as_array()
        .expect("blob is a byte array")
        .iter()
        .map(|n| n.as_u64().expect("byte") as u8)
        .collect()
}
const SYSTEM: &str = "11111111111111111111111111111111";

#[test]
fn parses_a_real_legacy_devnet_transfer() {
    let f = artifacts();
    let m = parse_transaction(&blob(&f["benign_transfer"]["blob"]))
        .expect("real devnet transfer must parse");
    println!(
        "version={:?} keys={} ixs={} feepayer={}",
        m.version,
        m.static_keys.len(),
        m.instructions.len(),
        m.fee_payer
    );
    assert_eq!(m.version, None, "this fixture is a legacy transaction");
    assert_eq!(m.instructions.len(), 1);
    assert_eq!(m.instructions[0].program_id, SYSTEM);
    assert_eq!(m.static_keys.len(), 3);
    assert!(m.signers.contains(&m.fee_payer));
    assert!(m.writable.contains(&m.fee_payer));
}

#[test]
fn finds_the_sibling_instruction_the_description_omitted() {
    let f = artifacts();
    let m =
        parse_transaction(&blob(&f["transfer_plus_sibling_assign"]["blob"])).expect("must parse");
    assert_eq!(
        m.instructions.len(),
        2,
        "the artifact really does carry two instructions"
    );
    let described: Vec<String> = f["described"]["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_string())
        .collect();
    let data: Vec<u8> = blob(&f["described"]["data"]);
    let c = correspond(&m, SYSTEM, Some(&data), &described);
    println!(
        "matched={:?} undescribed={:?}",
        c.matched_instruction, c.undescribed_instructions
    );
    assert_eq!(
        c.matched_instruction,
        Some(0),
        "the described transfer is instruction 0"
    );
    assert_eq!(
        c.undescribed_instructions.len(),
        1,
        "the sibling must be reported"
    );
}

#[test]
fn the_amount_substitution_has_no_matching_instruction() {
    let f = artifacts();
    let m = parse_transaction(&blob(&f["amount_substituted"]["blob"])).expect("must parse");
    let described: Vec<String> = f["amount_honest"]["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_string())
        .collect();
    let tiny_data: Vec<u8> = blob(&f["amount_honest"]["data"]);
    let c = correspond(&m, SYSTEM, Some(&tiny_data), &described);
    assert_eq!(
        c.matched_instruction, None,
        "no instruction carries the described 0.002 SOL data"
    );
    assert_eq!(
        c.undescribed_instructions.len(),
        1,
        "the 0.9 SOL instruction is undescribed"
    );
}

#[test]
fn an_honest_transfer_corresponds_exactly() {
    let f = artifacts();
    let m = parse_transaction(&blob(&f["amount_honest"]["blob"])).expect("must parse");
    let described: Vec<String> = f["amount_honest"]["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_string())
        .collect();
    let data: Vec<u8> = blob(&f["amount_honest"]["data"]);
    let c = correspond(&m, SYSTEM, Some(&data), &described);
    assert_eq!(c.matched_instruction, Some(0));
    assert!(
        c.undescribed_instructions.is_empty(),
        "nothing else is in this transaction"
    );
    assert!(
        c.described_but_absent.is_empty(),
        "every described account is in the artifact"
    );
    assert!(
        c.undescribed_accounts.is_empty(),
        "and nothing beyond them: {:?}",
        c.undescribed_accounts
    );
}

#[test]
fn malformed_artifacts_are_refused_rather_than_guessed_at() {
    assert!(matches!(
        parse_transaction(&[]),
        Err(ArtifactParseError::Empty)
    ));
    let f = artifacts();
    let good = blob(&f["amount_honest"]["blob"]);
    // Every truncation of a real transaction must error, never parse.
    for cut in [1usize, 5, 17, 40, 80, good.len() - 1] {
        assert!(
            parse_transaction(&good[..cut]).is_err(),
            "truncation at {cut} parsed"
        );
    }
    // Trailing bytes change the artifact and must not be ignored.
    let mut extra = good.clone();
    extra.push(0);
    assert!(matches!(
        parse_transaction(&extra),
        Err(ArtifactParseError::TrailingBytes { .. })
    ));
}

#[test]
fn every_byte_of_a_real_transaction_matters() {
    // A structural parser that ignored a field would let two different
    // transactions produce the same reading. Flip each byte and require that
    // the artifact either fails to parse or parses DIFFERENTLY.
    let f = artifacts();
    let good = blob(&f["amount_honest"]["blob"]);
    let base = parse_transaction(&good).expect("must parse");
    let mut ignored = Vec::new();
    for i in 0..good.len() {
        let mut m = good.clone();
        m[i] ^= 0x01;
        if let Ok(parsed) = parse_transaction(&m) {
            if parsed == base {
                ignored.push(i);
            }
        }
    }
    // Signature bytes are legitimately ignored: Graphite verifies BEFORE
    // signing, so an artifact arrives with placeholder signatures and their
    // contents cannot be part of the structure.
    let sig_region = 1 + 64 * base.signers.len();
    let unexpected: Vec<usize> = ignored.into_iter().filter(|i| *i >= sig_region).collect();
    assert!(
        unexpected.is_empty(),
        "these non-signature bytes changed without changing the parse, so the parser is \
         ignoring part of the transaction: {unexpected:?}"
    );
}
