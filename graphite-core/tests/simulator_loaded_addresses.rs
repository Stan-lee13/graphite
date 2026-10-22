//! Requires the `rpc` feature: the simulation is served by a loopback mock.
#![cfg(feature = "rpc")]

//! The simulator's `loadedAddresses` are compared with the accounts Graphite
//! resolved from the lookup tables itself (Round 34, finding S-5).
//!
//! A v0 transaction reaches accounts through address lookup tables. Graphite
//! resolves them from the tables' own data, and uses that resolution for
//! privileges and identities; but every index past the static keys in the
//! simulation's balance arrays, inner instructions and callees was read
//! through the SIMULATOR's `loadedAddresses`, never compared with that
//! resolution. An RPC that reversed the writable list attributed each loaded
//! account's balance change to the other one. The response is now set aside
//! when the two differ, and the verdict is refused as an incomplete
//! simulation.

use base64::Engine as _;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::{BehaviorEvidence, TrustTier};
use graphite_core::tx_artifact::{ADDRESS_LOOKUP_TABLE_PROGRAM, LOOKUP_TABLE_META_SIZE};
use graphite_core::verification::{
    ExecutionDecision, GraphiteCore, ProposedIntent, VerificationInput, VerificationResult,
};
use std::io::{Read, Write};
use std::net::TcpListener;

const SYSTEM: &str = "11111111111111111111111111111111";
const FEE: u64 = 5_000;
const AMOUNT: u64 = 1_000_000_000;

fn key(seed: u8) -> String {
    let mut b = [seed; 32];
    b[0] = 0x40 | (seed & 0x3f);
    bs58::encode(b).into_string()
}

fn payer() -> String {
    key(1)
}
fn table() -> String {
    key(2)
}
/// The two writable accounts the table holds, at indexes 0 and 1.
fn w0() -> String {
    key(3)
}
fn w1() -> String {
    key(4)
}

fn compact_u16(mut v: usize, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn raw(k: &str) -> Vec<u8> {
    bs58::decode(k).into_vec().unwrap()
}

fn transfer_data() -> Vec<u8> {
    let mut d = 2u32.to_le_bytes().to_vec();
    d.extend_from_slice(&AMOUNT.to_le_bytes());
    d
}

/// A v0 frame: static keys [payer (signer, writable), System], one lookup
/// table loading two writable accounts (W0, W1), and a System transfer from
/// the payer to W0 (account index 2, the first loaded writable).
fn frame() -> Vec<u8> {
    let mut out = Vec::new();
    compact_u16(1, &mut out);
    out.extend_from_slice(&[0u8; 64]);
    out.push(0x80);
    out.extend_from_slice(&[1, 0, 1]);
    compact_u16(2, &mut out);
    out.extend_from_slice(&raw(&payer()));
    out.extend_from_slice(&raw(SYSTEM));
    out.extend_from_slice(&[9u8; 32]);
    compact_u16(1, &mut out);
    out.push(1);
    compact_u16(2, &mut out);
    out.extend_from_slice(&[0, 2]);
    let data = transfer_data();
    compact_u16(data.len(), &mut out);
    out.extend_from_slice(&data);
    compact_u16(1, &mut out);
    out.extend_from_slice(&raw(&table()));
    compact_u16(2, &mut out);
    out.extend_from_slice(&[0, 1]);
    compact_u16(0, &mut out);
    out
}

fn table_data() -> Vec<u8> {
    let mut data = vec![0u8; LOOKUP_TABLE_META_SIZE];
    data[0..4].copy_from_slice(&1u32.to_le_bytes());
    data[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
    data.extend_from_slice(&raw(&w0()));
    data.extend_from_slice(&raw(&w1()));
    data
}

fn account_json(lamports: u64, owner: &str, data: &[u8]) -> String {
    format!(
        r#"{{"lamports":{lamports},"owner":"{owner}","executable":false,"rentEpoch":0,"data":["{}","base64"]}}"#,
        base64::engine::general_purpose::STANDARD.encode(data)
    )
}

/// The account state the cluster holds, before or after.
fn state(k: &str, post: bool) -> String {
    let (pre_l, post_l) = if k == payer() {
        (10 * AMOUNT, 10 * AMOUNT - AMOUNT - FEE)
    } else if k == w0() {
        (AMOUNT, 2 * AMOUNT)
    } else if k == w1() {
        (3 * AMOUNT, 3 * AMOUNT)
    } else if k == table() {
        return account_json(5_000_000, ADDRESS_LOOKUP_TABLE_PROGRAM, &table_data());
    } else {
        return "null".to_string();
    };
    account_json(if post { post_l } else { pre_l }, SYSTEM, &[])
}

fn read_request(stream: &mut std::net::TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some(end) = text.find("\r\n\r\n") {
            let len = text[..end]
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                return String::from_utf8_lossy(&buf[end + 4..end + 4 + len]).to_string();
            }
        }
    }
    String::new()
}

/// A loopback RPC whose simulation reports `loaded_writable` as the
/// accounts it loaded through the table. The balance arrays are the
/// cluster's, in the order the runtime really loads the accounts:
/// [payer, System, W0, W1].
fn serve(loaded_writable: [String; 2]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let req: serde_json::Value =
                serde_json::from_str(&read_request(&mut stream)).unwrap_or_default();
            let result = match req["method"].as_str() {
                Some("getMultipleAccounts") => {
                    let keys = req["params"][0].as_array().cloned().unwrap_or_default();
                    let v: Vec<String> = keys
                        .iter()
                        .map(|k| state(k.as_str().unwrap_or(""), false))
                        .collect();
                    format!(r#"{{"context":{{"slot":1}},"value":[{}]}}"#, v.join(","))
                }
                Some("getAccountInfo") => format!(
                    r#"{{"context":{{"slot":1}},"value":{}}}"#,
                    state(req["params"][0].as_str().unwrap_or(""), false)
                ),
                Some("simulateTransaction") => {
                    let keys = req["params"][1]["accounts"]["addresses"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    let post: Vec<String> = keys
                        .iter()
                        .map(|k| state(k.as_str().unwrap_or(""), true))
                        .collect();
                    format!(
                        r#"{{"context":{{"slot":1}},"value":{{"err":null,"logs":[],"unitsConsumed":150,"fee":{FEE},"preBalances":[{},1,{},{}],"postBalances":[{},1,{},{}],"innerInstructions":[],"loadedAddresses":{{"writable":["{}","{}"],"readonly":[]}},"accounts":[{}],"returnData":null}}}}"#,
                        10 * AMOUNT,
                        AMOUNT,
                        3 * AMOUNT,
                        10 * AMOUNT - AMOUNT - FEE,
                        2 * AMOUNT,
                        3 * AMOUNT,
                        loaded_writable[0],
                        loaded_writable[1],
                        post.join(",")
                    )
                }
                _ => "null".to_string(),
            };
            let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
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

fn input() -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send 1 SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![payer(), w0()],
        instruction_data: Some(transfer_data()),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Custom {
            min_confidence: 0.40,
            min_trust_tier: TrustTier::OfficialManifest,
        },
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: Some(frame()),
        transaction_instructions: vec![],
        cpi_trace: None,
        real_account_metas: vec![],
        uses_versioned_transaction: true,
        lookup_table_count: 1,
        state_diff: None,
    }
}

async fn verify(loaded_writable: [String; 2]) -> VerificationResult {
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint: serve(loaded_writable),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    }));
    core.verify_async(&input()).await.expect("a verdict")
}

fn said(r: &VerificationResult) -> String {
    let layers = r
        .layers
        .iter()
        .map(|l| format!("{} {:?}: {}", l.layer, l.status, l.reason))
        .collect::<Vec<_>>()
        .join("\n");
    format!("{layers}\n{:?}\n{}", r.risk_verdict, r.summary)
}

#[tokio::test]
async fn a_simulator_that_reorders_the_loaded_addresses_is_not_believed() {
    let r = verify([w1(), w0()]).await;
    assert!(
        !r.approved && r.decision != ExecutionDecision::ExecutableApproved,
        "a simulation whose loadedAddresses contradict the tables was used ({:?}):\n{}",
        r.decision,
        said(&r)
    );
    let s = said(&r);
    assert!(
        s.contains("loadedAddresses") && s.contains("not the accounts Graphite resolved"),
        "the refusal does not say the simulator's loaded addresses contradict the tables:\n{s}"
    );
}

#[tokio::test]
async fn a_simulator_that_reports_the_tables_accounts_is_used() {
    let r = verify([w0(), w1()]).await;
    let s = said(&r);
    assert!(
        !s.contains("not the accounts Graphite resolved"),
        "the honest order was reported as a contradiction:\n{s}"
    );
    eprintln!("control decision: {:?}\n{s}", r.decision);
}
