//! Requires the `rpc` feature.
#![cfg(feature = "rpc")]

//! Round 9: the two halves of a state diff are two RPC calls.
//!
//! The simulation and the pre-state read can land on different slots, and
//! when they do, every change made by other transactions in between shows
//! up in the diff as this transaction's. That cannot manufacture an
//! approval — the diff still has to be explained by the manifest, and a
//! change that hides a real effect would have to be its exact inverse,
//! deposited by the attacker at their own expense — but a reader of the L4
//! detail must be able to tell a one-slot skew from a measurement of this
//! transaction alone. So the slots are captured and, when they differ, named.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationResult,
};
use std::io::{Read, Write};
use std::net::TcpListener;
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

fn account(lamports: u64) -> String {
    format!(
        r#"{{"lamports":{lamports},"owner":"{SYSTEM}","executable":false,"rentEpoch":0,"data":["","base64"]}}"#
    )
}

/// A cluster that answers every account read and every simulation with a
/// plausible, successful, three-account transfer: the payer pays, the second
/// account receives, the program is untouched. It reads the request so the
/// entry counts line up with whatever was asked.
fn cluster(pre_slot: u64, sim_slot: u64) -> String {
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
            let body = match method.as_str() {
                "getMultipleAccounts" => {
                    let count = body_json["params"][0]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let vals: Vec<String> = (0..count)
                        .map(|i| account(if i == 0 { 1_000_000_000 } else { 1_000_000 }))
                        .collect();
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":{pre_slot}}},"value":[{}]}}}}"#,
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
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":{sim_slot}}},"value":{{
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

/// Describes the corpus's own transfer: payer -> `8u8L…`, 2,000,000 lamports.
fn describe(artifact: Vec<u8>, data: Option<Vec<u8>>) -> VerificationInput {
    let honest = corpus_entry("legacy_single_transfer");
    let keys = strings(&honest["static_keys"]);
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
        account_addresses: vec![keys[0].clone(), keys[1].clone()],
        instruction_data: data,
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

fn transfer_data() -> Vec<u8> {
    let mut d = vec![2, 0, 0, 0];
    d.extend_from_slice(&2_000_000u64.to_le_bytes());
    d
}

fn l4(r: &VerificationResult) -> (LayerStatus, String) {
    r.layers
        .iter()
        .find(|l| l.layer == "L4_StateVerification")
        .map(|l| (l.status, l.reason.clone()))
        .expect("L4 must always be reported")
}

#[tokio::test]
async fn a_diff_read_across_two_slots_says_so() {
    let core = core_at(&cluster(1000, 1003));
    let honest = corpus_entry("legacy_single_transfer");
    let r = core
        .verify_async(&describe(bytes(&honest["raw"]), Some(transfer_data())))
        .await
        .expect("verification must run");
    let (status, reason) = l4(&r);
    assert_eq!(status, LayerStatus::Passed, "{reason}");
    assert!(
        reason.contains("pre-state was read at slot 1000 and the simulation ran at slot 1003"),
        "{reason}"
    );
    assert!(reason.contains("3 slot(s)"), "{reason}");
}

#[tokio::test]
async fn a_diff_read_at_one_slot_carries_no_skew_note() {
    let core = core_at(&cluster(77, 77));
    let honest = corpus_entry("legacy_single_transfer");
    let r = core
        .verify_async(&describe(bytes(&honest["raw"]), Some(transfer_data())))
        .await
        .expect("verification must run");
    let (status, reason) = l4(&r);
    assert_eq!(status, LayerStatus::Passed, "{reason}");
    assert!(!reason.contains("slot"), "{reason}");
}
