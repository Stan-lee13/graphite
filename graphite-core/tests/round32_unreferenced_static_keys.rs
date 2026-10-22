//! Requires the `rpc` feature: the account universe is read from a simulation.
#![cfg(feature = "rpc")]

//! A static key no instruction references is not an undescribed effect.
//!
//! Found by the live mainnet workflow (Round 32, run 39817822320, row 6): an
//! ordinary System transfer, executed on chain, whose message carried one more
//! static key than its only instruction used. Graphite refused it as
//! `ArtifactAccountsNotDescribed` — "nothing here examined what it does to
//! them".
//!
//! Nothing can do anything to it. A program sees only the accounts its
//! instruction passes (and passes on by CPI from those), so a key that no
//! instruction references is untouched by every program in the transaction;
//! the runtime only loads (and, if writable, locks) it. Its balance moving
//! would still be caught: `ArtifactEffectsNotCovered` compares the
//! simulator's balance count against the diff.
//!
//! A key an instruction DOES reference but the request does not name stays a
//! Critical finding, whatever else refuses the transaction.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, PipelineLayerResult, ProposedIntent, VerificationInput,
    VerificationResult,
};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

const SYSTEM: &str = "11111111111111111111111111111111";
const SENDER: &str = "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx";
const RECIPIENT: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const AMOUNT: u64 = 2_000_000;
const FEE: u64 = 5_000;

fn extra() -> String {
    bs58::encode([0x5Au8; 32]).into_string()
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

fn transfer_data(lamports: u64) -> Vec<u8> {
    let mut d = vec![0x02u8, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d
}

/// A legacy frame with static keys [sender (signer, writable), recipient
/// (writable), extra (read-only), System (read-only)] and the given
/// instructions as (program index, account indexes, data).
fn frame(instructions: &[(u8, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let extra = extra();
    let keys = [SENDER, RECIPIENT, extra.as_str(), SYSTEM];
    let mut out = Vec::new();
    compact_u16(1, &mut out);
    out.extend_from_slice(&[0u8; 64]);
    // One signer, no read-only signer, two read-only non-signers.
    out.extend_from_slice(&[1, 0, 2]);
    compact_u16(keys.len(), &mut out);
    for k in keys {
        out.extend_from_slice(&bs58::decode(k).into_vec().expect("valid base58"));
    }
    out.extend_from_slice(&[9u8; 32]);
    compact_u16(instructions.len(), &mut out);
    for (program, accounts, data) in instructions {
        out.push(*program);
        compact_u16(accounts.len(), &mut out);
        out.extend_from_slice(accounts);
        compact_u16(data.len(), &mut out);
        out.extend_from_slice(data);
    }
    out
}

fn serve(routes: HashMap<String, String>) -> String {
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").unwrap());
    let addr = listener.local_addr().unwrap();
    let server = Arc::clone(&listener);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = server.accept() {
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).unwrap_or(0);
            let method = String::from_utf8_lossy(&buf[..n])
                .split("\"method\":\"")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .unwrap_or("?")
                .to_string();
            let body = routes
                .get(&method)
                .cloned()
                .unwrap_or_else(|| r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string());
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

fn account(lamports: u64) -> String {
    format!(
        r#"{{"lamports":{lamports},"owner":"{SYSTEM}","executable":false,"rentEpoch":0,"data":["","base64"]}}"#
    )
}

/// The cluster the live row saw: the sender pays the amount and the fee, the
/// recipient receives the amount, the extra key and System do not move.
fn cluster() -> String {
    let (s0, r0, x0) = (1_000_000_000u64, 1_000_000u64, 500_000u64);
    let (s1, r1) = (s0 - AMOUNT - FEE, r0 + AMOUNT);
    let sim = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
            "err":null,"logs":[],"unitsConsumed":150,"fee":{FEE},
            "preBalances":[{s0},{r0},{x0},1],"postBalances":[{s1},{r1},{x0},1],
            "innerInstructions":[],"loadedAddresses":{{"writable":[],"readonly":[]}},
            "accounts":[{},{}],"returnData":null}}}}}}"#,
        account(s1),
        account(r1),
    );
    let pre = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":[{},{}]}}}}"#,
        account(s0),
        account(r0)
    );
    let mut m = HashMap::new();
    m.insert("simulateTransaction".to_string(), sim);
    m.insert("getMultipleAccounts".to_string(), pre);
    serve(m)
}

fn input(artifact: Vec<u8>) -> VerificationInput {
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
        account_addresses: vec![SENDER.to_string(), RECIPIENT.to_string()],
        instruction_data: Some(transfer_data(AMOUNT)),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: Some(artifact),
        transaction_instructions: vec![],
        cpi_trace: None,
        real_account_metas: vec![],
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        state_diff: None,
    }
}

async fn verify(artifact: Vec<u8>) -> VerificationResult {
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint: cluster(),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    }));
    core.verify_async(&input(artifact))
        .await
        .expect("verification must reach a verdict")
}

fn l4(r: &VerificationResult) -> &PipelineLayerResult {
    r.layers
        .iter()
        .find(|l| l.layer.starts_with("L4"))
        .expect("L4 must be reported")
}

#[tokio::test]
async fn a_static_key_no_instruction_references_is_not_an_undescribed_effect() {
    let r = verify(frame(&[(3, vec![0, 1], transfer_data(AMOUNT))])).await;
    let l4 = l4(&r);
    assert!(
        !l4.reason.contains("ArtifactAccountsNotDescribed"),
        "a key no instruction references was reported as an account the transaction acts on: {}",
        l4.reason
    );
    assert_eq!(
        l4.status,
        LayerStatus::Passed,
        "an ordinary transfer with one inert static key failed L4: {}",
        l4.reason
    );
}

#[tokio::test]
async fn a_static_key_an_undescribed_instruction_references_is_still_critical() {
    // The same key, now passed to a second instruction the request does not
    // describe: a program sees it, so the request owes a description of it.
    let r = verify(frame(&[
        (3, vec![0, 1], transfer_data(AMOUNT)),
        (3, vec![0, 2], transfer_data(1)),
    ]))
    .await;
    assert!(!r.approved, "an undescribed instruction was approved");
    let l4 = l4(&r);
    assert!(
        l4.reason.contains("ArtifactAccountsNotDescribed") && l4.reason.contains(&extra()),
        "a key an instruction references, named nowhere in the request, is not reported: {:?} {}",
        l4.status,
        l4.reason
    );
}
