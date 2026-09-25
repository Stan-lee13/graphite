//! Requires the `rpc` feature: the pipeline tests here are about what a
//! simulation is allowed to count as evidence.
#![cfg(feature = "rpc")]

//! Round 19: what one observation is.
//!
//! Round 17 made "the same bytes re-verified are one observation" the rule for
//! the trusted simulation baseline, keyed on the artifact digest and
//! remembered for the last 256 observations. Three ways around it, each
//! reproduced against a running Core before it was fixed:
//!
//! - F-19-01: the digest covers the recent blockhash, which the simulator
//!   REPLACES (`replaceRecentBlockhash: true`). The same transfer re-asked
//!   with a fresh blockhash — which every agent retry fetches anyway — was a
//!   new observation each time: refused at 0.44 on the first ask, approved on
//!   the third (measured on `a1db51f`).
//! - F-19-02: a request with no artifact was simulated anyway — its
//!   `instruction_data` sent as though it were a transaction — and recorded
//!   with no key at all, so the identical request counted on every repeat
//!   (5 → 16 samples in twelve requests) and L3 certified "clean
//!   (RPC-verified)" bytes that were never a transaction.
//! - F-19-03 (reported by an external review): a key that had left the
//!   256-key window counted again — `sample_count` 257 → 258 on bytes already
//!   counted.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::{
    BehaviorEvidence, SemanticGraphStore, OBSERVATION_MEMORY,
};
use graphite_core::simulation_integrity::{ComputeUsage, ROBUST_WINDOW};
use graphite_core::tx_artifact::{message_bytes, parse_transaction, simulation_identity};
use graphite_core::verification::{GraphiteCore, LayerStatus, ProposedIntent, VerificationInput};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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

fn transfer() -> Vec<u8> {
    bytes(&corpus_entry("legacy_single_transfer")["raw"])
}

fn transfer_data(lamports: u64) -> Vec<u8> {
    let mut d = vec![2, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d
}

/// The same transaction under another recent blockhash.
fn with_blockhash(raw: &[u8], i: u8) -> Vec<u8> {
    let m = parse_transaction(raw).expect("frame parses");
    let bh = bs58::decode(&m.recent_blockhash).into_vec().unwrap();
    let msg = message_bytes(raw).expect("message");
    let msg_start = raw.len() - msg.len();
    let pos = msg
        .windows(32)
        .rposition(|w| w == bh.as_slice())
        .expect("blockhash is in the message");
    let mut out = raw.to_vec();
    out[msg_start + pos] ^= i.wrapping_add(1);
    out
}

/// The same transfer for another amount: a different transaction.
fn with_amount(raw: &[u8], lamports: u64) -> Vec<u8> {
    let old = transfer_data(2_000_000);
    let pos = raw
        .windows(old.len())
        .position(|w| w == old.as_slice())
        .expect("the corpus transfer carries 2,000,000 lamports");
    let mut out = raw.to_vec();
    out[pos..pos + old.len()].copy_from_slice(&transfer_data(lamports));
    out
}

fn describe(artifact: Option<Vec<u8>>, lamports: u64) -> VerificationInput {
    let keys = strings(&corpus_entry("legacy_single_transfer")["static_keys"]);
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![keys[0].clone(), keys[1].clone()],
        instruction_data: Some(transfer_data(lamports)),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: artifact,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

fn account(lamports: u64) -> String {
    format!(
        r#"{{"lamports":{lamports},"owner":"{SYSTEM}","executable":false,"rentEpoch":0,"data":["","base64"]}}"#
    )
}

/// A loopback cluster that answers every simulation cleanly and counts the
/// `simulateTransaction` calls it receives.
fn cluster(simulations: Arc<AtomicUsize>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let body_json: serde_json::Value = req
                .split("\r\n\r\n")
                .nth(1)
                .and_then(|b| serde_json::from_str(b).ok())
                .unwrap_or(serde_json::Value::Null);
            let body = match body_json["method"].as_str().unwrap_or("?") {
                "getMultipleAccounts" => {
                    let count = body_json["params"][0]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let vals: Vec<String> = (0..count)
                        .map(|i| account(if i == 0 { 1_000_000_000 } else { 1_000_000 }))
                        .collect();
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":[{}]}}}}"#,
                        vals.join(",")
                    )
                }
                "simulateTransaction" => {
                    simulations.fetch_add(1, Ordering::SeqCst);
                    let count = body_json["params"][1]["accounts"]["addresses"]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let post: Vec<String> = (0..count)
                        .map(|i| account(if i == 0 { 998_995_000 } else { 2_000_000 }))
                        .collect();
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
                            "err":null,"logs":[],"unitsConsumed":150,"fee":5000,
                            "preBalances":[1000000000,1000000,1],"postBalances":[998995000,2000000,1],
                            "innerInstructions":[],"loadedAddresses":{{"writable":[],"readonly":[]}},
                            "accounts":[{}],"returnData":null}}}}}}"#,
                        post.join(",")
                    )
                }
                _ => r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
            };
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://{addr}")
}

fn core_at(endpoint: &str) -> GraphiteCore {
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    }));
    core
}

fn samples(core: &GraphiteCore) -> u64 {
    core.simulation_baseline(SYSTEM)
        .map(|b| b.sample_count)
        .unwrap_or(0)
}

fn usage(cu: u64) -> ComputeUsage {
    ComputeUsage {
        compute_units: cu,
        account_writes: 2,
        cpi_hops: 0,
    }
}

// ─── the identity ───────────────────────────────────────────────────────────

/// What the simulator executes is the identity: signatures and the blockhash
/// (both replaced or ignored by a simulation) do not change it; anything the
/// transaction does does.
#[test]
fn the_simulation_identity_ignores_the_blockhash_and_nothing_else() {
    let a = transfer();
    let id = simulation_identity(&a).unwrap();
    for i in 0..5u8 {
        assert_eq!(
            simulation_identity(&with_blockhash(&a, i)).unwrap(),
            id,
            "another blockhash is the same simulation"
        );
    }
    let mut signed = a.clone();
    signed[1..65].copy_from_slice(&[7u8; 64]);
    assert_eq!(
        simulation_identity(&signed).unwrap(),
        id,
        "a signature is not executed"
    );
    assert_ne!(
        simulation_identity(&with_amount(&a, 3_000_000)).unwrap(),
        id,
        "another amount is another transaction"
    );
    assert!(
        simulation_identity(&[0x01, 0x02]).is_err(),
        "bytes that are not a transaction have no identity"
    );
}

// ─── F-19-03: the window ────────────────────────────────────────────────────

/// The reviewer's reproduction, inverted: after 256 other identities the
/// first one is still remembered.
#[test]
fn an_identity_counted_once_is_never_counted_again() {
    let mut store = SemanticGraphStore::new();
    store.record_simulation_keyed(SYSTEM, &usage(150), Some("first"));
    for i in 0..(ROBUST_WINDOW + 1) {
        store.record_simulation_keyed(SYSTEM, &usage(150), Some(&format!("other-{i}")));
    }
    let before = store.get_simulation_baseline(SYSTEM).unwrap().sample_count;
    assert_eq!(before, ROBUST_WINDOW as u64 + 2);
    store.record_simulation_keyed(SYSTEM, &usage(150), Some("first"));
    assert_eq!(
        store.get_simulation_baseline(SYSTEM).unwrap().sample_count,
        before,
        "an identity that left the robust window is still the same identity"
    );
    // And across a snapshot.
    let mut restored = SemanticGraphStore::from_json(&store.to_json().unwrap()).unwrap();
    restored.record_simulation_keyed(SYSTEM, &usage(150), Some("first"));
    restored.record_simulation_keyed(SYSTEM, &usage(150), Some("other-3"));
    assert_eq!(
        restored
            .get_simulation_baseline(SYSTEM)
            .unwrap()
            .sample_count,
        before,
        "the memory survives a restart"
    );
}

/// At the bound the trusted accumulator stops learning rather than
/// forgetting: a new identity goes to the shadow, and nothing already counted
/// can be counted again.
#[test]
fn a_full_memory_stops_learning_instead_of_forgetting() {
    let mut store = SemanticGraphStore::new();
    for i in 0..OBSERVATION_MEMORY {
        store.record_simulation_keyed(SYSTEM, &usage(150), Some(&format!("id-{i}")));
    }
    let (remembered, full) = store.observation_memory(SYSTEM);
    assert_eq!(remembered, OBSERVATION_MEMORY);
    assert!(full);
    let counted = store.get_simulation_baseline(SYSTEM).unwrap().sample_count;
    store.record_simulation_keyed(SYSTEM, &usage(150), Some("one-more"));
    store.record_simulation_keyed(SYSTEM, &usage(150), Some("id-0"));
    assert_eq!(
        store.get_simulation_baseline(SYSTEM).unwrap().sample_count,
        counted,
        "neither a new identity nor an old one moves a full baseline"
    );
    assert_eq!(
        store.shadow_baselines().get(SYSTEM).map(|b| b.sample_count),
        Some(1),
        "the new identity is kept where an operator can adopt it"
    );
}

/// A snapshot whose memory is not a whole number of fingerprints, or holds
/// more than the bound, does not load as an empty memory.
#[test]
fn a_malformed_memory_is_refused_at_load() {
    let mut store = SemanticGraphStore::new();
    store.record_simulation_keyed(SYSTEM, &usage(150), Some("a"));
    let json = store.to_json().unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    v["observed"][SYSTEM]["fingerprints"] = serde_json::json!("AAAA");
    assert!(SemanticGraphStore::from_json(&v.to_string()).is_err());
}

// ─── F-19-01 and F-19-02, through the pipeline ──────────────────────────────

/// The same transfer re-asked with a fresh blockhash is one observation, and
/// a refused request stays refused however many fresh blockhashes it is
/// asked with.
#[tokio::test]
async fn a_fresh_blockhash_is_not_a_new_observation() {
    let sims = Arc::new(AtomicUsize::new(0));
    let core = core_at(&cluster(sims.clone()));
    let mut approvals = 0;
    for i in 0..5u8 {
        let r = core
            .verify_async(&describe(Some(with_blockhash(&transfer(), i)), 2_000_000))
            .await
            .unwrap();
        approvals += usize::from(r.approved);
    }
    assert_eq!(sims.load(Ordering::SeqCst), 5, "each ask was simulated");
    assert_eq!(samples(&core), 1, "five blockhashes, one observation");
    assert_eq!(
        approvals, 0,
        "the refused transfer is not approved by asking again"
    );
}

/// Distinct transactions still earn — the bootstrap Round 17 kept is intact.
#[tokio::test]
async fn distinct_transactions_still_earn() {
    let core = core_at(&cluster(Arc::new(AtomicUsize::new(0))));
    for (i, lamports) in [2_000_000u64, 2_000_001, 2_000_002].into_iter().enumerate() {
        let r = core
            .verify_async(&describe(
                Some(with_amount(&transfer(), lamports)),
                lamports,
            ))
            .await
            .unwrap();
        assert_eq!(samples(&core), i as u64 + 1, "{:?}", r.layers);
    }
}

/// A request with no artifact has nothing to execute: it is not simulated,
/// nothing is recorded, and L3 says why.
#[tokio::test]
async fn a_descriptive_request_is_not_simulated_and_teaches_nothing() {
    let sims = Arc::new(AtomicUsize::new(0));
    let core = core_at(&cluster(sims.clone()));
    for _ in 0..12 {
        let r = core.verify_async(&describe(None, 2_000_000)).await.unwrap();
        let l3 = r
            .layers
            .iter()
            .find(|l| l.layer.starts_with("L3"))
            .expect("L3 reported");
        assert_ne!(l3.status, LayerStatus::Passed, "{}", l3.reason);
        assert!(
            l3.reason.contains("no transaction artifact"),
            "{}",
            l3.reason
        );
    }
    assert_eq!(
        sims.load(Ordering::SeqCst),
        0,
        "instruction bytes are never sent as a transaction"
    );
    assert_eq!(samples(&core), 0);
}
