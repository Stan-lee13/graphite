//! A2-07 (2026-09-29 audit): the shadow accumulator takes only what the
//! trusted accumulator would have taken but for the flag itself.
//!
//! The shadow accumulator is promotable to the trusted baseline, so it must
//! pass the same gate. It took every flagged request, including ones refused
//! at L2 or blocked by the Risk Engine. A request refused at L2 (here, a
//! declared sibling that matches nothing) is not an observation of the program
//! used honestly (F-16-03); ten of them filled the shadow and raised the
//! frozen-baseline alarm, and an operator who promoted that shadow would have
//! installed a baseline made of attacker samples.
//!
//! The fix records a shadow observation only when no structural layer failed
//! and the only risk findings are the divergence itself (`SimulationSpoofing`)
//! or warnings.
//!
//! The test sends refused, flagged requests through a loopback mock cluster
//! and pins that they neither train the shadow nor raise the frozen-baseline
//! alarm. Harness copied from `round17_remediations.rs`.
#![cfg(feature = "rpc")]
#![allow(dead_code)]

use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::simulation_integrity::{ComputeBaseline, MIN_SAMPLES};
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationResult,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

const SYSTEM: &str = "11111111111111111111111111111111";

fn payer() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x17u8; 32])
}

fn payer_b58() -> String {
    bs58::encode(payer().verifying_key().to_bytes()).into_string()
}

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

/// The corpus transfer with this test's fee payer in place of the corpus's.
fn with_payer(raw: Vec<u8>) -> Vec<u8> {
    let keys = strings(&corpus_entry("legacy_single_transfer")["static_keys"]);
    let old = bs58::decode(&keys[0]).into_vec().unwrap();
    let new = payer().verifying_key().to_bytes();
    let pos = raw
        .windows(32)
        .position(|w| w == old.as_slice())
        .expect("the corpus fee payer is in the frame");
    let mut out = raw;
    out[pos..pos + 32].copy_from_slice(&new);
    out
}

fn tx_a() -> Vec<u8> {
    with_payer(bytes(&corpus_entry("legacy_single_transfer")["raw"]))
}

fn tx_other_blockhash() -> Vec<u8> {
    with_payer(bytes(&corpus_entry("legacy_other_blockhash")["raw"]))
}

/// The same transfer for another amount: a DIFFERENT transaction, and one
/// the simulator executes differently (Round 19: a transaction that differs
/// only in its blockhash is the same simulation, and one observation).
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

/// `describe` for `with_amount(tx_a(), lamports)`: the description matches
/// the bytes, so L2 locates the instruction.
fn describe_amount(lamports: u64) -> VerificationInput {
    let mut input = describe(with_amount(&tx_a(), lamports));
    input.instruction_data = Some(transfer_data(lamports));
    input
}

/// Earn the Gaming floor the way a deployment does: distinct approved
/// transactions of this program, each an observation.
async fn earn_baseline(core: &GraphiteCore) {
    for i in 1..=3u64 {
        let _ = core.verify_async(&describe_amount(2_000_000 + i)).await;
    }
}

fn transfer_data(lamports: u64) -> Vec<u8> {
    let mut d = vec![2, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d
}

fn account(lamports: u64) -> String {
    format!(
        r#"{{"lamports":{lamports},"owner":"{SYSTEM}","executable":false,"rentEpoch":0,"data":["","base64"]}}"#
    )
}

/// What the mock cluster says, per test.
#[derive(Clone)]
struct Knobs {
    /// `err` in the simulation response (`None` = `null`).
    sim_err: Option<String>,
    units: u64,
    /// Inner instructions: the program index each CPI called.
    inner_program_indexes: Vec<u8>,
    /// Bytes served by `getTransaction`, per signature.
    chain: Vec<(String, Vec<u8>)>,
}

impl Default for Knobs {
    fn default() -> Self {
        Self {
            sim_err: None,
            units: 150,
            inner_program_indexes: vec![],
            chain: vec![],
        }
    }
}

type Shared = Arc<Mutex<Knobs>>;

fn cluster(knobs: Shared) -> String {
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").unwrap());
    let addr = listener.local_addr().unwrap();
    let server = Arc::clone(&listener);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = server.accept() {
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let body_json: serde_json::Value = req
                .split("\r\n\r\n")
                .nth(1)
                .and_then(|b| serde_json::from_str(b).ok())
                .unwrap_or(serde_json::Value::Null);
            let method = body_json["method"].as_str().unwrap_or("?").to_string();
            let k = knobs.lock().unwrap().clone();
            let body = match method.as_str() {
                "getMultipleAccounts" => {
                    let count = body_json["params"][0].as_array().map(|a| a.len()).unwrap_or(0);
                    let vals: Vec<String> = (0..count)
                        .map(|i| account(if i == 0 { 1_000_000_000 } else { 1_000_000 }))
                        .collect();
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":[{}]}}}}"#,
                        vals.join(",")
                    )
                }
                "simulateTransaction" => {
                    let count = body_json["params"][1]["accounts"]["addresses"]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let post: Vec<String> = (0..count)
                        .map(|i| account(if i == 0 { 998_995_000 } else { 2_000_000 }))
                        .collect();
                    let err = match &k.sim_err {
                        Some(e) => format!("\"{e}\""),
                        None => "null".to_string(),
                    };
                    let inner: Vec<String> = k
                        .inner_program_indexes
                        .iter()
                        .map(|i| format!(r#"{{"programIdIndex":{i},"accounts":[0,1],"data":""}}"#))
                        .collect();
                    let inner_groups = if inner.is_empty() {
                        "[]".to_string()
                    } else {
                        format!(r#"[{{"index":0,"instructions":[{}]}}]"#, inner.join(","))
                    };
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
                            "err":{err},"logs":[],"unitsConsumed":{},"fee":5000,
                            "preBalances":[1000000000,1000000,1],"postBalances":[998995000,2000000,1],
                            "innerInstructions":{inner_groups},"loadedAddresses":{{"writable":[],"readonly":[]}},
                            "accounts":[{}],"returnData":null}}}}}}"#,
                        k.units,
                        post.join(",")
                    )
                }
                "getSignatureStatuses" => {
                    r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":2},"value":[{"slot":12345,"confirmations":null,"confirmationStatus":"finalized","err":null,"status":{"Ok":null}}]}}"#.to_string()
                }
                "getTransaction" => {
                    let sig = body_json["params"][0].as_str().unwrap_or("").to_string();
                    match k.chain.iter().find(|(s, _)| *s == sig) {
                        Some((_, b)) => {
                            use base64::Engine;
                            format!(
                                r#"{{"jsonrpc":"2.0","id":1,"result":{{"slot":12345,"transaction":["{}","base64"],"meta":{{"err":null}}}}}}"#,
                                base64::engine::general_purpose::STANDARD.encode(b)
                            )
                        }
                        None => r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
                    }
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
    std::mem::forget(listener);
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

fn describe(artifact: Vec<u8>) -> VerificationInput {
    let keys = strings(&corpus_entry("legacy_single_transfer")["static_keys"]);
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send 0.002 SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![payer_b58(), keys[1].clone()],
        instruction_data: Some(transfer_data(2_000_000)),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 5,
            battle_tested_tx_count: 50_000,
            simulation_match_count: 100,
        },
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: Some(artifact),
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

fn layer<'a>(
    r: &'a VerificationResult,
    prefix: &str,
) -> &'a graphite_core::verification::PipelineLayerResult {
    r.layers
        .iter()
        .find(|l| l.layer.starts_with(prefix))
        .unwrap_or_else(|| panic!("{prefix} must be reported"))
}

#[tokio::test]
async fn refused_requests_do_not_fill_the_promotable_shadow() {
    let knobs: Shared = Arc::default();
    let core = core_at(&cluster(Arc::clone(&knobs)));
    let mut baseline = ComputeBaseline::default();
    for _ in 0..MIN_SAMPLES {
        graphite_core::simulation_integrity::update_baseline(&mut baseline, 450, 2, 0);
    }
    core.seed_simulation_baseline(SYSTEM, baseline).unwrap();

    // Every request below flags (5,000 CU against a 450 CU history) AND is
    // refused at L2 by a declared sibling that matches nothing.
    knobs.lock().unwrap().units = 5_000;
    for i in 0..MIN_SAMPLES {
        let mut input = describe_amount(2_000_100 + i);
        input.transaction_instructions =
            vec![graphite_core::tx_pattern_analysis::TransactionInstruction {
                program_id: SYSTEM.to_string(),
                instruction_discriminator: "02000000".to_string(),
                account_addresses: vec![payer_b58(), payer_b58()],
                cpi_targets: vec![],
            }];
        let r = core.verify_async(&input).await.unwrap();
        assert_eq!(
            layer(&r, "L2").status,
            LayerStatus::Failed,
            "{}",
            layer(&r, "L2").reason
        );
        assert!(!r.approved);
    }

    assert!(
        core.shadow_baseline(SYSTEM).is_none(),
        "L2-refused requests trained the promotable shadow: {:?}",
        core.shadow_baseline(SYSTEM).map(|b| b.sample_count)
    );
    assert!(
        core.frozen_baselines().is_empty(),
        "refused requests raised the frozen-baseline alarm: {:?}",
        core.frozen_baselines()
    );
}
