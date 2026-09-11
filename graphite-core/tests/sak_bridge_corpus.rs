//! The cross-language corpus: ten shapes, every conclusion checked twice.
//!
//! `sak_bridge_artifact.rs` pins one transaction shape. One shape proves the
//! mechanism exists; it does not prove the TypeScript serializer and the Rust
//! parser agree about signer sets, empty data, shared accounts, unusual
//! orderings, or a v0 message backed by a real lookup table. A disagreement in
//! any of those would not be a bypass but an outage — every honest transaction
//! refused at the signing boundary, comparing a digest against the digest of
//! something else.
//!
//! Each corpus entry records what `@solana/web3.js` believes about its own
//! bytes. This file requires Graphite's parser to reach the same conclusions
//! from the bytes alone: the digest, the message slice, the required signers,
//! the static keys, the instruction count, the version, and for v0 the lookup
//! structure and — against the real table — the resolved addresses.
//!
//! CI regenerates the corpus and fails on drift, so the two implementations
//! cannot diverge quietly.

use graphite_core::tx_artifact::{parse_transaction, resolve_lookups};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

fn corpus() -> Vec<serde_json::Value> {
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/artifacts/sak_bridge_corpus.json"))
            .expect("corpus must parse");
    raw["entries"].as_array().expect("entries").clone()
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

/// The message half: everything after the compact-u16 signature array. The
/// Rust twin of the TypeScript `messageOf`, written independently so the two
/// agreeing is evidence rather than tautology.
fn message_of(raw: &[u8]) -> &[u8] {
    let mut offset = 0usize;
    let mut count = 0usize;
    for group in 0..3 {
        let byte = raw[offset];
        offset += 1;
        count |= ((byte & 0x7f) as usize) << (group * 7);
        if byte & 0x80 == 0 {
            break;
        }
    }
    &raw[offset + count * 64..]
}

#[test]
fn the_corpus_is_not_trivial() {
    let entries = corpus();
    assert!(
        entries.len() >= 10,
        "expected at least ten shapes, got {}",
        entries.len()
    );
    assert!(
        entries.iter().any(|e| e["version"] == 0),
        "a v0 entry is required"
    );
    assert!(
        entries.iter().any(|e| e["version"].is_null()),
        "a legacy entry is required"
    );
    assert!(
        entries
            .iter()
            .any(|e| strings(&e["required_signers"]).len() >= 2),
        "a multi-signer entry is required"
    );
}

/// Every entry: the Rust parser agrees with web3.js about its own bytes.
#[test]
fn rust_reaches_every_conclusion_the_typescript_side_recorded() {
    for e in corpus() {
        let name = e["name"].as_str().expect("name");
        let raw = bytes(&e["raw"]);
        let m = parse_transaction(&raw).unwrap_or_else(|err| panic!("{name}: must parse: {err}"));

        // Version.
        let want_version = e["version"].as_u64().map(|v| v as u8);
        assert_eq!(m.version, want_version, "{name}: version");

        // Digest over the exact bytes.
        let mut h = Sha256::new();
        h.update(&raw);
        assert_eq!(
            hex::encode(h.finalize()),
            e["transaction_sha256"].as_str().expect("digest"),
            "{name}: digest"
        );

        // The message slice, by two independent implementations.
        assert_eq!(
            message_of(&raw),
            &bytes(&e["message"])[..],
            "{name}: message slice"
        );

        // Required signers: the header's count over the static keys.
        let want_signers = strings(&e["required_signers"]);
        assert_eq!(m.signers, want_signers, "{name}: required signers");

        // Static keys, in order.
        assert_eq!(
            m.static_keys,
            strings(&e["static_keys"]),
            "{name}: static keys"
        );

        // Instruction count.
        assert_eq!(
            m.instructions.len(),
            e["instruction_count"].as_u64().expect("count") as usize,
            "{name}: instruction count"
        );

        // Lookups, for v0.
        if let Some(lookups) = e["lookups"].as_array() {
            assert_eq!(m.lookups.len(), lookups.len(), "{name}: lookup count");
            for (got, want) in m.lookups.iter().zip(lookups) {
                assert_eq!(got.table, want["table"].as_str().unwrap(), "{name}: table");
                let w: Vec<u8> = want["writable"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| n.as_u64().unwrap() as u8)
                    .collect();
                let r: Vec<u8> = want["readonly"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| n.as_u64().unwrap() as u8)
                    .collect();
                assert_eq!(got.writable_indexes, w, "{name}: writable indexes");
                assert_eq!(got.readonly_indexes, r, "{name}: readonly indexes");
            }
        } else {
            assert!(
                m.lookups.is_empty(),
                "{name}: a legacy entry has no lookups"
            );
        }
        println!(
            "{name}: agreed on version, digest, message, signers, keys, instructions, lookups"
        );
    }
}

/// The v0 entry resolves against the same real table web3.js compiled it with.
///
/// web3.js chose the indexes from the table's address list; Graphite decodes
/// the table from the same bytes and turns those indexes back into addresses.
/// The instruction's accounts, fully resolved, must be the accounts the
/// TypeScript side put in the instruction.
#[test]
fn the_v0_entry_resolves_against_the_real_table_it_was_compiled_with() {
    let alt: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/artifacts/mainnet_v0_alt.json"))
            .expect("alt fixture");
    let tables: HashMap<String, Vec<u8>> = alt["lookup_tables"]
        .as_object()
        .expect("tables")
        .iter()
        .map(|(addr, t)| {
            use base64::Engine;
            (
                addr.clone(),
                base64::engine::general_purpose::STANDARD
                    .decode(t["data_base64"].as_str().unwrap())
                    .unwrap(),
            )
        })
        .collect();

    let e = corpus()
        .into_iter()
        .find(|e| e["name"] == "v0_real_lookup_table")
        .expect("the v0 entry");
    let m = parse_transaction(&bytes(&e["raw"])).expect("must parse");
    let resolved = resolve_lookups(&m, &tables).expect("the real table must resolve");
    assert_eq!(resolved.writable.len(), 1);
    assert_eq!(resolved.readonly.len(), 1);

    // The memo instruction is instruction 1; its last two accounts arrive
    // through the table, one writable and one readonly, in that order.
    let ix = &m.instructions[1];
    let accounts =
        graphite_core::tx_artifact::resolve_instruction_accounts(&m, ix, Some(&resolved))
            .expect("every index must resolve");
    assert_eq!(accounts.len(), 3);
    assert_eq!(accounts[0], m.fee_payer, "the payer is static");
    assert_eq!(
        accounts[1], resolved.writable[0],
        "the writable one came through the table"
    );
    assert_eq!(
        accounts[2], resolved.readonly[0],
        "the readonly one came through the table"
    );
    assert!(
        !m.static_keys.contains(&accounts[1]) && !m.static_keys.contains(&accounts[2]),
        "neither table-sourced account is in the static keys — that is the point of the entry"
    );
    println!(
        "v0: payer {}, via table writable {}, readonly {}",
        accounts[0], accounts[1], accounts[2]
    );
}

/// The "different" variants are different transactions with different digests.
///
/// The corpus exists partly to show that changing only the blockhash, only the
/// destination, or only the instruction order changes the digest. If any pair
/// collided, the execution gate would accept one for the other.
#[test]
fn every_entry_has_a_distinct_digest() {
    let entries = corpus();
    let mut seen = HashMap::new();
    for e in &entries {
        let d = e["transaction_sha256"].as_str().unwrap().to_string();
        if let Some(prev) = seen.insert(d, e["name"].as_str().unwrap()) {
            panic!("{} and {} share a digest", prev, e["name"]);
        }
    }
    // And the explicitly-paired ones differ from the base.
    let base = entries
        .iter()
        .find(|e| e["name"] == "legacy_single_transfer")
        .unwrap();
    for variant in ["legacy_other_blockhash", "legacy_other_destination"] {
        let v = entries.iter().find(|e| e["name"] == variant).unwrap();
        assert_ne!(
            v["transaction_sha256"], base["transaction_sha256"],
            "{variant}"
        );
        // Same length, different bytes: the difference is content, not shape.
        assert_eq!(
            bytes(&v["raw"]).len(),
            bytes(&base["raw"]).len(),
            "{variant}"
        );
    }
}
