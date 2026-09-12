//! Requires the `rpc` feature: verifying a nonce means fetching the account.
#![cfg(feature = "rpc")]

//! The on-chain half of the durable-nonce rule.
//!
//! With the operator opt-in, a durable-nonce transaction passes L2 only when
//! the nonce account it names holds the nonce value the message carries,
//! under the authority the instruction names, and that authority signs.
//! Every mismatch is one the runtime refuses at load, so a verdict that
//! passed one would be a verdict about a transaction that cannot execute —
//! or, for a stale nonce, about one that already did.
//!
//! The mock is a local socket serving the nonce account and nothing else of
//! substance. No public endpoint is contacted, nothing is signed or sent.

use graphite_core::manifest::load_seed_manifests;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::tx_artifact::{parse_transaction, NONCE_ACCOUNT_SIZE, SYSTEM_PROGRAM};
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationResult,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

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

struct Shape {
    payer: String,
    nonce_account: String,
    destination: String,
    nonce_value: String,
    raw: Vec<u8>,
}

fn shape() -> Shape {
    let e = corpus_entry("legacy_durable_nonce");
    let keys = strings(&e["static_keys"]);
    let raw = bytes(&e["raw"]);
    let m = parse_transaction(&raw).expect("must parse");
    Shape {
        payer: keys[0].clone(),
        nonce_account: keys[1].clone(),
        destination: keys[2].clone(),
        nonce_value: m.recent_blockhash.clone(),
        raw,
    }
}

/// `NonceVersions::Current(State::Initialized { authority, durable_nonce, fee })`.
fn nonce_account_data(authority: &str, nonce_value: &str) -> Vec<u8> {
    let mut d = Vec::with_capacity(NONCE_ACCOUNT_SIZE);
    d.extend_from_slice(&1u32.to_le_bytes());
    d.extend_from_slice(&1u32.to_le_bytes());
    d.extend_from_slice(&bs58::decode(authority).into_vec().expect("base58"));
    d.extend_from_slice(&bs58::decode(nonce_value).into_vec().expect("base58"));
    d.extend_from_slice(&5000u64.to_le_bytes());
    d
}

/// What the mock returns for the nonce account.
enum Served {
    /// An initialized nonce account with this authority and value.
    Account { authority: String, value: String },
    /// `null` — the account does not exist.
    Missing,
}

/// Routes on the nonce account's address in the request body, so the state
/// fetch for the state diff (also `getMultipleAccounts`) gets an honest error
/// rather than the nonce account's bytes.
fn serve(nonce_account: &str, served: Served) -> String {
    let nonce_account = nonce_account.to_string();
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").unwrap());
    let addr = listener.local_addr().unwrap();
    let server = Arc::clone(&listener);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = server.accept() {
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).unwrap_or(0);
            let body = String::from_utf8_lossy(&buf[..n]).to_string();
            let payload = if body.contains("getMultipleAccounts") && body.contains(&nonce_account) {
                match &served {
                    Served::Account { authority, value } => {
                        use base64::Engine;
                        let data = base64::engine::general_purpose::STANDARD
                            .encode(nonce_account_data(authority, value));
                        format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":[
                                {{"lamports":1447680,"owner":"{SYSTEM_PROGRAM}",
                                  "data":["{data}","base64"],"executable":false,"rentEpoch":0}}]}}}}"#
                        )
                    }
                    Served::Missing => {
                        r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":[null]}}"#
                            .to_string()
                    }
                }
            } else {
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"not served by this test"}}"#
                    .to_string()
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                payload.len(),
                payload
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}")
}

async fn verify(endpoint: &str, s: &Shape, allow: bool) -> VerificationResult {
    let mut core = GraphiteCore::with_registry(load_seed_manifests());
    core.set_allow_durable_nonce(allow);
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    }));
    let mut data = vec![2, 0, 0, 0];
    data.extend_from_slice(&2_000_000u64.to_le_bytes());
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send 0.002 SOL".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: SYSTEM_PROGRAM.to_string(),
        protocol_version: "1.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![s.payer.clone(), s.destination.clone()],
        instruction_data: Some(data),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: Default::default(),
        compute_units: 450,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: Some(s.raw.clone()),
        transaction_instructions: vec![TransactionInstruction {
            program_id: SYSTEM_PROGRAM.to_string(),
            instruction_discriminator: "04000000".to_string(),
            account_addresses: vec![
                s.nonce_account.clone(),
                "SysvarRecentB1ockHashes11111111111111111111".to_string(),
                s.payer.clone(),
            ],
            cpi_targets: vec![],
        }],
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

fn l2(r: &VerificationResult) -> (LayerStatus, String) {
    r.layers
        .iter()
        .find(|l| l.layer == "L2_InstructionVerification")
        .map(|l| (l.status, l.reason.clone()))
        .expect("L2 must always be reported")
}

/// The one path that passes: opted in, and the account agrees with the
/// message on every count.
#[tokio::test]
async fn a_verified_nonce_passes_l2_when_the_operator_opted_in() {
    let s = shape();
    let endpoint = serve(
        &s.nonce_account,
        Served::Account {
            authority: s.payer.clone(),
            value: s.nonce_value.clone(),
        },
    );
    let r = verify(&endpoint, &s, true).await;
    let (status, reason) = l2(&r);
    assert_eq!(status, LayerStatus::Passed, "{reason}");
    assert!(reason.contains("DURABLE-NONCE"), "{reason}");
    assert!(
        reason.contains("the nonce account was fetched and holds this nonce value"),
        "{reason}"
    );
    println!("L2: {reason}");
}

/// Same account served, no opt-in: still refused. The fetch is not even
/// attempted — the default refuses before asking.
#[tokio::test]
async fn a_verified_nonce_is_still_refused_without_the_opt_in() {
    let s = shape();
    let endpoint = serve(
        &s.nonce_account,
        Served::Account {
            authority: s.payer.clone(),
            value: s.nonce_value.clone(),
        },
    );
    let r = verify(&endpoint, &s, false).await;
    let (status, reason) = l2(&r);
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(reason.contains("refused by default"), "{reason}");
    assert!(!r.approved);
}

/// The nonce account holds a different value: the nonce has advanced (this
/// transaction, or another by the same authority, already executed) or the
/// message was built against another account. Either way the runtime
/// refuses it, and a verdict must not describe it as executable.
#[tokio::test]
async fn a_stale_nonce_fails_l2() {
    let s = shape();
    let endpoint = serve(
        &s.nonce_account,
        Served::Account {
            authority: s.payer.clone(),
            // Any other 32 bytes: the destination's key, base58.
            value: s.destination.clone(),
        },
    );
    let r = verify(&endpoint, &s, true).await;
    let (status, reason) = l2(&r);
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(reason.contains("nonce has advanced"), "{reason}");
    assert!(!r.approved);
}

/// The account's authority is someone else: the instruction's named
/// authority signs, but is not the one the account honours.
#[tokio::test]
async fn a_nonce_under_a_different_authority_fails_l2() {
    let s = shape();
    let endpoint = serve(
        &s.nonce_account,
        Served::Account {
            authority: s.destination.clone(),
            value: s.nonce_value.clone(),
        },
    );
    let r = verify(&endpoint, &s, true).await;
    let (status, reason) = l2(&r);
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(reason.contains("authority is"), "{reason}");
    assert!(!r.approved);
}

/// No such account on-chain.
#[tokio::test]
async fn a_missing_nonce_account_fails_l2() {
    let s = shape();
    let endpoint = serve(&s.nonce_account, Served::Missing);
    let r = verify(&endpoint, &s, true).await;
    let (status, reason) = l2(&r);
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(reason.contains("does not exist on-chain"), "{reason}");
    assert!(!r.approved);
}

/// The RPC is unreachable: the opt-in is conditional on the check, so an
/// unanswerable check refuses.
#[tokio::test]
async fn an_unreachable_rpc_fails_l2_rather_than_skipping_the_check() {
    let s = shape();
    // A listener that is bound and immediately dropped: connection refused.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    let r = verify(&dead, &s, true).await;
    let (status, reason) = l2(&r);
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(
        reason.contains("could not be fetched"),
        "an RPC failure must be named, not skipped: {reason}"
    );
    assert!(!r.approved);
}
