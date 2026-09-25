//! Requires the `rpc` feature: both tests are about what the simulator
//! reports and what the pipeline does with it.
#![cfg(feature = "rpc")]

//! Round 19: the pipeline judges what the simulator executed.
//!
//! - F-19-04: an instruction the manifest does not describe used to put only
//!   its FIRST account in L4's state diff (the fallback resolution marked
//!   every other account read-only, and the diff observes writable accounts).
//! - F-19-22: the CPI-trace rules (re-entry, sweep fan-out, impersonation)
//!   ran only on a trace the caller chose to send. The reference bridge never
//!   sends one. They now run on the tree the simulator reports in
//!   `innerInstructions`.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

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

fn transfer_data(lamports: u64) -> Vec<u8> {
    let mut d = vec![2, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d
}

/// What the mock records, and what it answers with.
#[derive(Default)]
struct Cluster {
    /// Addresses each `simulateTransaction` asked post-state for.
    requested_addresses: Vec<Vec<String>>,
    /// `innerInstructions` to report, as JSON.
    inner: String,
}

fn account(lamports: u64) -> String {
    format!(
        r#"{{"lamports":{lamports},"owner":"{SYSTEM}","executable":false,"rentEpoch":0,"data":["","base64"]}}"#
    )
}

fn cluster(state: Arc<Mutex<Cluster>>) -> String {
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
                    let vals: Vec<String> = (0..count).map(|_| account(1_000_000_000)).collect();
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":[{}]}}}}"#,
                        vals.join(",")
                    )
                }
                "simulateTransaction" => {
                    let addrs: Vec<String> = body_json["params"][1]["accounts"]["addresses"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|s| s.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    let mut s = state.lock().unwrap();
                    s.requested_addresses.push(addrs.clone());
                    let post: Vec<String> = addrs.iter().map(|_| account(1_000_000_000)).collect();
                    let inner = if s.inner.is_empty() {
                        "[]".to_string()
                    } else {
                        s.inner.clone()
                    };
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
                            "err":null,"logs":[],"unitsConsumed":900,"fee":0,
                            "preBalances":[1000000000,1000000000,1],"postBalances":[1000000000,1000000000,1],
                            "innerInstructions":{inner},"loadedAddresses":{{"writable":[],"readonly":[]}},
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

/// The corpus transfer with its instruction data replaced by `data` of the
/// same length, described exactly.
fn input_with_data(data: Vec<u8>) -> VerificationInput {
    let e = corpus_entry("legacy_single_transfer");
    let keys = strings(&e["static_keys"]);
    let old = transfer_data(2_000_000);
    assert_eq!(data.len(), old.len());
    let mut raw = bytes(&e["raw"]);
    let pos = raw
        .windows(old.len())
        .position(|w| w == old.as_slice())
        .expect("corpus transfer data");
    raw[pos..pos + old.len()].copy_from_slice(&data);
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send SOL".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: hex::encode(&data[..4]),
        account_addresses: vec![keys[0].clone(), keys[1].clone()],
        instruction_data: Some(data),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 900,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: Some(raw),
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

/// F-19-04: a System instruction the manifest does not describe (tag 99) on
/// the corpus transfer's two accounts. Both accounts are writable in the
/// message, and both are now observed.
#[tokio::test]
async fn an_undescribed_instruction_has_every_writable_account_diffed() {
    let state = Arc::new(Mutex::new(Cluster::default()));
    let core = core_at(&cluster(Arc::clone(&state)));
    let mut data = vec![99u8, 0, 0, 0];
    data.extend_from_slice(&[0u8; 8]);
    let r = core.verify_async(&input_with_data(data)).await.unwrap();
    assert_eq!(r.instruction_name, "unknown_instruction", "{:?}", r.layers);
    let keys = strings(&corpus_entry("legacy_single_transfer")["static_keys"]);
    let asked = state.lock().unwrap().requested_addresses.clone();
    let last = asked.last().expect("simulated with a state diff");
    assert!(
        last.contains(&keys[0]) && last.contains(&keys[1]),
        "the destination (account 1) must be in the diff; asked for {last:?}"
    );
}

/// F-19-22: the simulator reports the primary instruction fanning out to
/// the same program and instruction twelve times, over twelve distinct
/// account sets — a sweep. No trace was declared. It is refused.
#[tokio::test]
async fn a_sweep_the_simulator_executed_is_refused_without_a_declared_trace() {
    let state = Arc::new(Mutex::new(Cluster::default()));
    let sets: [&[u8]; 12] = [
        &[0],
        &[1],
        &[2],
        &[0, 1],
        &[1, 0],
        &[0, 2],
        &[2, 0],
        &[1, 2],
        &[2, 1],
        &[0, 1, 2],
        &[0, 2, 1],
        &[1, 0, 2],
    ];
    let calls: Vec<String> = sets
        .iter()
        .map(|accts| {
            format!(
                r#"{{"programIdIndex":2,"accounts":{},"data":"{}","stackHeight":2}}"#,
                serde_json::to_string(accts).unwrap(),
                bs58::encode([2u8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]).into_string()
            )
        })
        .collect();
    state.lock().unwrap().inner =
        format!(r#"[{{"index":0,"instructions":[{}]}}]"#, calls.join(","));
    let core = core_at(&cluster(Arc::clone(&state)));
    let r = core
        .verify_async(&input_with_data(transfer_data(2_000_000)))
        .await
        .unwrap();
    assert!(!r.approved);
    assert_eq!(r.risk_verdict.status, "Blocked", "{:?}", r.risk_verdict);
    assert!(
        r.risk_verdict
            .findings
            .iter()
            .any(|f| f.reason.starts_with("observed CPI trace:")
                && f.reason.contains("side by side")),
        "{:?}",
        r.risk_verdict.findings
    );

    // Control: the same response with no inner instructions is not a sweep.
    state.lock().unwrap().inner = String::new();
    let r = core
        .verify_async(&input_with_data(transfer_data(2_000_000)))
        .await
        .unwrap();
    assert!(
        !r.risk_verdict
            .findings
            .iter()
            .any(|f| f.reason.starts_with("observed CPI trace:")),
        "{:?}",
        r.risk_verdict.findings
    );
}
