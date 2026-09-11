//! Requires the `rpc` feature.
#![cfg(feature = "rpc")]

//! A number under a name Solana does not define is not evidence.
//!
//! `accountWrites` and `cpiHops` are not fields any Solana RPC returns —
//! confirmed against devnet, where a `simulateTransaction` response carries
//! exactly {accounts, err, fee, innerInstructions, loadedAccountsDataSize,
//! loadedAddresses, logs, postBalances, postTokenBalances, preBalances,
//! preTokenBalances, replacementBlockhash, returnData, unitsConsumed}. Graphite
//! derives both from the canonical fields instead.
//!
//! It also read the invented names FIRST, and a provider that supplied them won
//! over the derivation. That has the provenance rule backwards: a value under a
//! name the protocol does not define is a value the provider chose, and this
//! layer exists to bound what a provider can assert. Both numbers feed the
//! simulation-integrity baseline, so a provider controlling them controls what
//! Graphite considers normal.
//!
//! Found by review 2026-09-11. The derivation is the evidence now; a provider
//! field is compared against it and reported, never adopted.
//!
//! Everything here is a loopback socket. No public endpoint is contacted.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::verification::{
    GraphiteCore, ProposedIntent, VerificationInput, VerificationResult,
};
use std::io::{Read, Write};
use std::net::TcpListener;

const SYSTEM: &str = "11111111111111111111111111111111";
const PAYER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const BOB: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

/// A simulation response whose canonical fields say ONE account moved, plus
/// whatever extra fields `extra` injects.
fn serve_simulation(extra: &str) -> String {
    // Two accounts, one balance change: the derivation must read 1.
    let sim = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
            "err":null,"logs":["Program {SYSTEM} consumed 150 of 200000 compute units"],
            "unitsConsumed":150,"fee":5000,
            "preBalances":[1000000000,1000000],"postBalances":[998995000,1000000],
            "innerInstructions":[],"loadedAddresses":{{"writable":[],"readonly":[]}},
            "accounts":[null,null],"returnData":null{extra}}}}}}}"#
    );
    let accounts = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":[
            {{"lamports":1000000000,"owner":"{SYSTEM}","data":["","base64"],"executable":false,"rentEpoch":0}},
            {{"lamports":1000000,"owner":"{SYSTEM}","data":["","base64"],"executable":false,"rentEpoch":0}}]}}}}"#
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).unwrap_or(0);
            let body = String::from_utf8_lossy(&buf[..n]).to_string();
            let payload = if body.contains("simulateTransaction") {
                sim.clone()
            } else {
                accounts.clone()
            };
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    payload.len(),
                    payload
                )
                .as_bytes(),
            );
        }
    });
    format!("http://{addr}")
}

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../fixtures/artifacts/devnet_transactions.json"
    ))
    .expect("fixtures must parse")
}

fn blob(v: &serde_json::Value) -> Vec<u8> {
    v.as_array()
        .expect("blob")
        .iter()
        .map(|n| n.as_u64().expect("byte") as u8)
        .collect()
}

async fn verify(endpoint: &str) -> VerificationResult {
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    }));
    let f = fixture();
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send 0.002 SOL".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![PAYER.to_string(), BOB.to_string()],
        instruction_data: Some(blob(&f["described"]["data"])),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: Default::default(),
        compute_units: 150,
        account_writes: 1,
        cpi_hops: 0,
        signed_transaction: Some(blob(&f["benign_transfer"]["blob"])),
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    };
    core.verify_async(&input)
        .await
        .expect("verification must complete")
}

fn warnings(r: &VerificationResult) -> String {
    r.risk_verdict
        .findings
        .iter()
        .map(|f| f.reason.clone())
        .chain(r.layers.iter().map(|l| l.reason.clone()))
        .collect::<Vec<_>>()
        .join(" | ")
}

/// A provider claiming a different number must not be believed.
///
/// The response's own balances show one account moved. The provider also says
/// `accountWrites: 9`, contradicting the data it sent in the same message.
#[test]
fn a_provider_supplied_account_write_count_does_not_override_the_derivation() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let endpoint = serve_simulation(r#","accountWrites":9,"cpiHops":7"#);
    let r = rt.block_on(verify(&endpoint));
    let text = warnings(&r);
    println!("{text}");

    assert!(
        text.contains("non-standard `accountWrites` of 9"),
        "a provider contradicting its own canonical fields must be reported: {text}"
    );
    assert!(
        text.contains("Graphite derived 1"),
        "the report must say what Graphite worked out instead: {text}"
    );
    assert!(
        text.contains("non-standard `cpiHops` of 7"),
        "both invented fields get the same treatment: {text}"
    );
}

/// The control: a response carrying only what Solana defines reports nothing.
///
/// Without this, the assertions above would be satisfied by a pipeline that
/// complains about every simulation it sees.
#[test]
fn a_standard_response_produces_no_anomaly() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let endpoint = serve_simulation("");
    let r = rt.block_on(verify(&endpoint));
    let text = warnings(&r);
    println!("{text}");
    assert!(
        !text.contains("non-standard"),
        "an ordinary Solana response must not be flagged: {text}"
    );
}

/// A provider whose invented number AGREES is not worth a warning either.
///
/// The rule is "derive, then report a disagreement" — not "report that a field
/// was present". An operator who sees a warning every time a provider is
/// harmlessly verbose stops reading them.
#[test]
fn a_provider_field_that_agrees_is_not_reported() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let endpoint = serve_simulation(r#","accountWrites":1,"cpiHops":0"#);
    let r = rt.block_on(verify(&endpoint));
    let text = warnings(&r);
    println!("{text}");
    assert!(
        !text.contains("non-standard `accountWrites`"),
        "an agreeing value is not an anomaly: {text}"
    );
}
