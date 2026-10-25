//! Round 39 (campaign 14): the cross-language conformance corpus,
//! `examples/decisions/conformance.json`, read by the Core's own types and
//! rule — `serde_json` into `VerificationResult`, then `is_executable()` —
//! and held to the outcome the corpus names for Rust. The TypeScript SDK
//! (`sdk/typescript/src/conformance.test.ts`), the Go SDK
//! (`sdk/go/conformance_test.go`) and the agent guard
//! (`integrations/agent-guard/conformance.test.ts`) read the same file, so a
//! change to the rule, a residual code, the content-hash framing or the
//! digest in one language fails the others' tests until the corpus says what
//! every language now does.
//!
//! The Rust column is the Core's TYPE and RULE over a verdict someone else
//! wrote, not a client's trust boundary: the Core never reads a verdict back
//! from a server. Where a client is stricter (it refuses a shape the Core
//! never writes), the corpus says so in a `note`; the clients' own tests
//! assert that none of them is ever looser.

use graphite_core::tx_artifact::artifact_sha256_of_signed;
use graphite_core::verification::VerificationResult;
use serde_json::Value;
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../examples/decisions")
}

fn corpus() -> Value {
    let raw =
        std::fs::read_to_string(dir().join("conformance.json")).expect("the corpus is committed");
    let c: Value = serde_json::from_str(&raw).expect("the corpus is JSON");
    assert_eq!(c["version"], 1);
    c
}

/// The committed verdict a vector starts from, with its exact text
/// replacements applied (each must occur exactly once).
fn vector_text(v: &Value) -> String {
    let base = v["base"].as_str().expect("base");
    let mut text =
        std::fs::read_to_string(dir().join(format!("{base}.json"))).expect("base verdict");
    for pair in v["raw_replace"].as_array().into_iter().flatten() {
        let from = pair[0].as_str().unwrap();
        let to = pair[1].as_str().unwrap();
        assert_eq!(
            text.matches(from).count(),
            1,
            "{}: {from:?} must occur exactly once",
            v["name"]
        );
        text = text.replacen(from, to, 1);
    }
    text
}

fn apply_edits(v: &Value, doc: &mut Value) {
    for e in v["edits"].as_array().into_iter().flatten() {
        let path = e["path"].as_array().expect("path");
        let (last, parents) = path.split_last().expect("a non-empty path");
        let mut at = &mut *doc;
        for step in parents {
            at = match step {
                Value::String(k) => &mut at[k.as_str()],
                Value::Number(i) => &mut at[i.as_u64().unwrap() as usize],
                other => panic!("path step {other}"),
            };
        }
        match (e["op"].as_str().unwrap(), last) {
            ("set", Value::String(k)) => at[k.as_str()] = e["value"].clone(),
            ("set", Value::Number(i)) => at[i.as_u64().unwrap() as usize] = e["value"].clone(),
            ("delete", Value::String(k)) => {
                at.as_object_mut().unwrap().remove(k.as_str());
            }
            ("push", Value::String(k)) => at[k.as_str()]
                .as_array_mut()
                .unwrap()
                .push(e["value"].clone()),
            (op, step) => panic!("{}: edit {op} at {step}", v["name"]),
        }
    }
}

fn rust_outcome(v: &Value) -> &'static str {
    assert!(
        v.get("raw_replace").is_none() || v.get("edits").is_none(),
        "{}: a vector is either raw text or edits, not both",
        v["name"]
    );
    let text = vector_text(v);
    let parsed: Result<VerificationResult, _> = if v.get("edits").is_some() {
        let mut doc: Value =
            serde_json::from_str(&text).expect("an edited vector starts from valid JSON");
        apply_edits(v, &mut doc);
        serde_json::from_value(doc)
    } else {
        serde_json::from_str(&text)
    };
    match parsed {
        Err(_) => "unreadable",
        Ok(r) if r.is_executable() => "executable",
        Ok(_) => "not_executable",
    }
}

#[test]
fn every_verdict_vector_reads_by_the_cores_rule_as_the_corpus_says() {
    let c = corpus();
    let verdicts = c["verdicts"].as_array().expect("verdicts");
    assert!(verdicts.len() >= 90, "{} verdict vectors", verdicts.len());
    let mut wrong = Vec::new();
    for v in verdicts {
        let got = rust_outcome(v);
        if got != v["expect"]["rust"] {
            wrong.push(format!(
                "{}: expected {}, got {got}",
                v["name"], v["expect"]["rust"]
            ));
        }
        // No client is looser than the Core's rule.
        for lang in ["ts", "go"] {
            if v["expect"][lang] == "executable" {
                assert_eq!(
                    v["expect"]["rust"], "executable",
                    "{}: {lang} executable where the Core's rule is not",
                    v["name"]
                );
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn transaction_digests_are_the_cores() {
    for d in corpus()["transaction_digest"].as_array().expect("digests") {
        let bytes = hex::decode(d["hex"].as_str().unwrap()).unwrap();
        let got = artifact_sha256_of_signed(&bytes).unwrap_or_else(|_| "error".to_string());
        assert_eq!(got, d["expect"]["rust"].as_str().unwrap(), "{}", d["name"]);
        // Where the Core computes a digest, each SDK computes the same one or refuses.
        if got != "error" {
            for lang in ["ts", "go"] {
                let sdk = d["expect"][lang].as_str().unwrap();
                assert!(
                    sdk == got || sdk == "error",
                    "{}: {lang} differs from the Core",
                    d["name"]
                );
            }
        }
    }
}

/// The content hash comes out of a real verification of the described
/// instruction — the Core's `generate_audit_id` is private, and this is the
/// value every verdict carries.
#[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
#[test]
fn content_hashes_are_the_cores() {
    use graphite_core::verification::{GraphiteCore, VerificationInput};
    let core = GraphiteCore::new();
    let mut got = std::collections::HashMap::new();
    let vectors = corpus()["content_hash"]
        .as_array()
        .expect("content_hash")
        .clone();
    for c in &vectors {
        let data: Result<Option<Vec<u8>>, _> = serde_json::from_value(c["data"].clone());
        let hash = match data {
            Err(_) => "error".to_string(),
            Ok(data) => {
                let input: VerificationInput = serde_json::from_value(serde_json::json!({
                    "proposed_intent": {
                        "intent_type": "transfer",
                        "raw_natural_language": "conformance vector",
                        "confidence_of_parse": 0.5
                    },
                    "program_id": c["program_id"],
                    "protocol_version": "1.0.0",
                    "instruction_discriminator": c["discriminator"],
                    "account_addresses": c["accounts"],
                    "instruction_data": data,
                    "cpi_targets": c["cpi_targets"],
                    "behavior_evidence": {
                        "has_signed_manifest": false,
                        "community_verified_count": 0,
                        "battle_tested_tx_count": 0,
                        "simulation_match_count": 0
                    },
                    "compute_units": 0,
                    "account_writes": 0,
                    "cpi_hops": 0
                }))
                .expect("a vector the Core's input type reads");
                let result = core
                    .verify(&input)
                    .unwrap_or_else(|e| panic!("{}: {e}", c["name"]));
                assert_eq!(result.instruction_bind_key, result.content_hash);
                result.content_hash
            }
        };
        assert_eq!(hash, c["expect"].as_str().unwrap(), "{}", c["name"]);
        got.insert(c["name"].as_str().unwrap().to_string(), hash);
    }
    for c in &vectors {
        if let Some(other) = c["differs_from"].as_str() {
            assert_ne!(
                got[c["name"].as_str().unwrap()],
                got[other],
                "{} vs {other}",
                c["name"]
            );
        }
    }
}
