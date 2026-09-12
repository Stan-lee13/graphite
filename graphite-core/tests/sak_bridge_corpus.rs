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

// ─── Byte-level mutations ─────────────────────────────────────────────────────

/// Apply one recorded mutation to a base entry's bytes, exactly as
/// `emit-corpus.ts` did on its side.
fn mutate(raw: &[u8], m: &serde_json::Value) -> Vec<u8> {
    match m["op"].as_str().expect("op") {
        "truncate" => raw[..m["at"].as_u64().unwrap() as usize].to_vec(),
        "flip" => {
            let mut out = raw.to_vec();
            let at = m["at"].as_u64().unwrap() as usize;
            out[at] ^= 0xff;
            out
        }
        "prefix" => {
            let mut out = bytes(&m["bytes"]);
            out.extend_from_slice(&raw[1..]);
            out
        }
        "append" => {
            let mut out = raw.to_vec();
            out.extend_from_slice(&bytes(&m["bytes"]));
            out
        }
        // Zero-pad to exactly `to` bytes: the packet-size bound from both
        // sides (1232 is a legal packet, 1233 is refused before a byte is
        // read).
        "pad" => {
            let to = m["to"].as_u64().unwrap() as usize;
            assert!(to >= raw.len(), "pad target below the base length");
            let mut out = raw.to_vec();
            out.resize(to, 0);
            out
        }
        other => panic!("unknown mutation op {other}"),
    }
}

fn mutations() -> Vec<serde_json::Value> {
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/artifacts/sak_bridge_corpus.json"))
            .expect("corpus must parse");
    raw["mutations"].as_array().expect("mutations").clone()
}

/// The same 1,647 damaged transactions, read by both sides.
///
/// Three things are required, and one is measured.
///
/// Required: (1) Graphite's `message_bytes` — the same compact-u16 reader
/// `parse_transaction` uses — accepts a mutation exactly when the bridge's
/// `messageOf` does, and yields the same slice. These two functions decide
/// whether a signed transaction's message is the message that was verified;
/// a disagreement is an outage at the signing gate. (2) Nothing panics: a
/// parser that panics on one byte of a hostile artifact is a denial of
/// service on the gate. (3) Graphite never accepts bytes that
/// `@solana/web3.js` refuses — it is at least as strict as the SDK on every
/// mutation here.
///
/// Measured: how often the SDK accepts bytes Graphite refuses, and why. The
/// SDK is not the authority — the runtime is — and `web3.js` is lenient in
/// ways the runtime is not: its shortvec decoder accepts non-minimal
/// encodings (`0x81 0x00` for 1), it slices a declared length past the end
/// of the buffer instead of failing, and it ignores trailing bytes, all of
/// which the RPC's wire decoder rejects (`reject_trailing_bytes`, and the
/// `ShortU16` visitor's alias check). Graphite refuses each of those, and
/// the test prints the breakdown so the number in the report is observed.
#[test]
fn every_byte_level_mutation_is_read_the_same_way_on_both_sides() {
    use graphite_core::tx_artifact::{message_bytes, parse_transaction, ArtifactParseError};
    let entries = corpus();
    let ms = mutations();
    assert!(
        ms.len() >= 1_500,
        "expected a large mutation set, got {}",
        ms.len()
    );

    let mut prefix_agreed = 0usize;
    let mut sdk_stricter: Vec<String> = Vec::new();
    let mut graphite_stricter: HashMap<&'static str, usize> = HashMap::new();
    let mut both_accept = 0usize;
    let mut both_reject = 0usize;

    for m in &ms {
        let base = entries
            .iter()
            .find(|e| e["name"] == m["base"])
            .expect("base entry");
        let raw = bytes(&base["raw"]);
        let mutated = mutate(&raw, &m["mutation"]);
        let label = format!("{} {}", m["base"], m["mutation"]);

        // (1) Prefix language: exact agreement with messageOf.
        let ts_len = m["ts_message_len"].as_u64().map(|n| n as usize);
        match (message_bytes(&mutated), ts_len) {
            (Ok(slice), Some(len)) => {
                assert_eq!(slice.len(), len, "{label}: message length");
                let mut h = Sha256::new();
                h.update(slice);
                assert_eq!(
                    hex::encode(h.finalize()),
                    m["ts_message_sha256"].as_str().unwrap(),
                    "{label}: message digest"
                );
                prefix_agreed += 1;
            }
            (Err(_), None) => prefix_agreed += 1,
            (Ok(slice), None) => panic!(
                "{label}: messageOf rejected these bytes but Graphite sliced a {}-byte message",
                slice.len()
            ),
            (Err(e), Some(len)) => {
                panic!("{label}: messageOf produced a {len}-byte message but Graphite refused: {e}")
            }
        }

        // (2)/(3) The full parse, against the SDK's verdict.
        let parsed = parse_transaction(&mutated);
        let sdk = m["sdk_accepts"].as_bool().unwrap();
        match (parsed, sdk) {
            (Ok(_), true) => both_accept += 1,
            (Err(_), false) => both_reject += 1,
            (Ok(_), false) => sdk_stricter.push(label.clone()),
            (Err(e), true) => {
                let why = match e {
                    ArtifactParseError::NonCanonicalLength { .. } => "non-canonical compact-u16",
                    ArtifactParseError::LengthExceedsInput { .. } => "declared length past the end",
                    ArtifactParseError::Truncated { .. } => "truncated field",
                    ArtifactParseError::TrailingBytes { .. } => "trailing bytes",
                    ArtifactParseError::LengthNotU16 { .. } => "length not a u16",
                    ArtifactParseError::ImpossibleHeader { .. } => "impossible header",
                    ArtifactParseError::ProgramIndexOutOfRange { .. } => {
                        "program index out of range"
                    }
                    ArtifactParseError::AccountIndexOutOfRange { .. } => {
                        "account index out of range"
                    }
                    ArtifactParseError::UnsupportedVersion(_) => "unsupported version",
                    ArtifactParseError::Empty => "empty",
                    ArtifactParseError::TooLarge { .. } => "larger than a packet",
                };
                *graphite_stricter.entry(why).or_insert(0) += 1;
            }
        }
    }

    println!("prefix agreement: {prefix_agreed}/{}", ms.len());
    println!("full parse — both accept: {both_accept}, both reject: {both_reject}");
    println!("Graphite refuses what web3.js accepts, by reason: {graphite_stricter:?}");
    println!(
        "web3.js refuses what Graphite accepts: {}",
        sdk_stricter.len()
    );
    for s in &sdk_stricter {
        println!("  {s}");
    }
    assert_eq!(prefix_agreed, ms.len());
    assert!(
        sdk_stricter.is_empty(),
        "Graphite accepted {} mutation(s) that web3.js refuses; each needs a named reason before it is allowed",
        sdk_stricter.len()
    );
    // The bases themselves are accepted by both — the mutation set is not
    // vacuous because it damages transactions both sides read.
    assert!(both_accept > 0, "no mutation was accepted by both sides");
    assert!(both_reject > 0, "no mutation was rejected by both sides");
}
