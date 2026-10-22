//! Round 30 (G-01): the four decisions as real verdicts, committed for the
//! SDKs' contract tests.
//!
//! `examples/decisions/<decision>.json` is a verdict the Core produced for
//! each `decision`: an executable approval (a clean simulation from a
//! loopback mock cluster), an analysis-only approval (no RPC), an
//! inconclusive refusal (the RPC answers with an error) and a blocked one
//! (the simulator reports the transaction fails). The TypeScript and Go
//! SDKs read these files and must recompute the same decision from each
//! verdict's fields that the Core wrote into it — the rule is implemented
//! three times, and this is what holds the three to one answer.
//!
//! This test regenerates the files under `GRAPHITE_REGENERATE_SAMPLES=1`;
//! otherwise it checks that each committed file still says what the Core
//! decides for the same scenario now, that the Rust rule recomputes the
//! committed decision, and that each file satisfies the published schema's
//! decision fields. `audit_trail_id` carries a per-process sequence, so the
//! files are compared on what the decision rests on, not byte for byte.
#![cfg(feature = "rpc")]

use graphite_core::confidence_engine::TrustTier;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{
    execution_decision, ExecutionDecision, GraphiteCore, ProposedIntent, VerificationInput,
    VerificationResult,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;

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

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect()
}

fn bytes(v: &serde_json::Value) -> Vec<u8> {
    v.as_array()
        .expect("byte array")
        .iter()
        .map(|n| n.as_u64().expect("byte") as u8)
        .collect()
}

fn account(lamports: u64) -> String {
    format!(
        r#"{{"lamports":{lamports},"owner":"{SYSTEM}","executable":false,"rentEpoch":0,"data":["","base64"]}}"#
    )
}

#[derive(Clone, Copy)]
enum Sim {
    Clean,
    Errored,
    RpcError,
}

/// A loopback cluster that answers `getMultipleAccounts` and
/// `simulateTransaction` the way `sim` says (the harness of
/// `audit_2026_10_20_simulation_gate.rs`, reduced to what this needs).
fn cluster(sim: Sim) -> String {
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
                    let count = body_json["params"][1]["accounts"]["addresses"]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let post: Vec<String> = (0..count)
                        .map(|i| account(if i == 0 { 997_995_000 } else { 3_000_000 }))
                        .collect();
                    let complete = |err: &str, accounts: &str| {
                        format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
                                "err":{err},"logs":[],"unitsConsumed":150,"fee":5000,
                                "preBalances":[1000000000,1000000,1],"postBalances":[997995000,3000000,1],
                                "innerInstructions":[],"loadedAddresses":{{"writable":[],"readonly":[]}},
                                {accounts}"returnData":null}}}}}}"#
                        )
                    };
                    match sim {
                        Sim::Clean => complete("null", &format!(r#""accounts":[{}],"#, post.join(","))),
                        Sim::Errored => complete(r#"{"InstructionError":[0,"Custom(1)"]}"#, r#""accounts":null,"#),
                        Sim::RpcError => r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"node is behind"}}"#.to_string(),
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
    format!("http://{addr}")
}

/// The corpus's legacy transfer of 2,000,000 lamports, described
/// faithfully, under the lowest bar a fresh core clears.
fn transfer() -> VerificationInput {
    let entry = corpus_entry("legacy_single_transfer");
    let keys = strings(&entry["static_keys"]);
    let mut data = vec![2, 0, 0, 0];
    data.extend_from_slice(&2_000_000u64.to_le_bytes());
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
        instruction_data: Some(data),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Custom {
            min_confidence: 0.40,
            min_trust_tier: TrustTier::OfficialManifest,
        },
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: Some(bytes(&entry["raw"])),
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

async fn produce(sim: Option<Sim>) -> VerificationResult {
    let mut core = GraphiteCore::new();
    if let Some(sim) = sim {
        core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
            endpoint: cluster(sim),
            timeout: std::time::Duration::from_secs(5),
            max_retries: 0,
            ..Default::default()
        }));
    }
    core.verify_async(&transfer()).await.expect("verify")
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("examples")
        .join("decisions")
}

/// What a fixture is compared on: what the decision rests on.
fn essentials(v: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "approved": v["approved"],
        "decision": v["decision"],
        "executable": v["executable"],
        "policy_verdict": v["policy_verdict"],
        "risk_status": v["risk_verdict"]["status"],
        "risk_patterns": v["risk_verdict"]["findings"].as_array().map(|f| f.iter().map(|x| x["pattern"].clone()).collect::<Vec<_>>()),
        "scope_kind": v["scope"]["kind"],
        "simulated": v["scope"]["simulated"],
        "unobserved_codes": v["scope"]["unobserved_codes"],
        "instruction_bind_key": v["instruction_bind_key"],
        "content_hash": v["content_hash"],
    })
}

#[tokio::test]
async fn each_decision_has_a_real_committed_verdict() {
    let cases = [
        (
            "executable_approved",
            Some(Sim::Clean),
            ExecutionDecision::ExecutableApproved,
        ),
        ("analysis_only", None, ExecutionDecision::AnalysisOnly),
        (
            "inconclusive",
            Some(Sim::RpcError),
            ExecutionDecision::Inconclusive,
        ),
        ("blocked", Some(Sim::Errored), ExecutionDecision::Blocked),
    ];
    let regenerate = std::env::var("GRAPHITE_REGENERATE_SAMPLES").as_deref() == Ok("1");
    for (name, sim, expected) in cases {
        let fresh = produce(sim).await;
        assert_eq!(fresh.decision, expected, "{name}: {}", fresh.summary);
        assert_eq!(execution_decision(&fresh), expected);
        let fresh_json = serde_json::to_value(&fresh).unwrap();
        let path = dir().join(format!("{name}.json"));
        if regenerate {
            std::fs::create_dir_all(dir()).unwrap();
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&fresh_json).unwrap() + "\n",
            )
            .unwrap();
            continue;
        }
        let committed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!(
                    "{}: {e} (regenerate with GRAPHITE_REGENERATE_SAMPLES=1)",
                    path.display()
                )
            }))
            .unwrap();
        assert_eq!(
            essentials(&committed),
            essentials(&fresh_json),
            "{name}: the committed verdict no longer says what the Core decides (regenerate with GRAPHITE_REGENERATE_SAMPLES=1 and review the diff)"
        );
        let parsed: VerificationResult = serde_json::from_value(committed).unwrap();
        assert_eq!(
            execution_decision(&parsed),
            expected,
            "{name}: the rule recomputes the committed decision"
        );
        assert_eq!(
            parsed.is_executable(),
            expected == ExecutionDecision::ExecutableApproved
        );
    }
}
