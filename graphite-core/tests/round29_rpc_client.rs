//! Round 29 (audit 2026-10-20): the RPC client findings R1–R10.
//!
//! Every test runs against a loopback server that records what it was sent,
//! so the request shape is asserted as well as the parsing.
#![cfg(feature = "rpc")]

use graphite_core::rpc_client::{
    simulation_result_from_value_for_test, token_account_frozen_flag, validate_endpoint,
    AccountState, RpcConfig, RpcError, SolanaRpcClient,
};
use graphite_core::Pubkey;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::Duration;

/// Serve `responses` in order, one per connection, and hand back each
/// request body as JSON.
fn recording_server(
    responses: Vec<String>,
) -> (
    String,
    mpsc::Receiver<serde_json::Value>,
    std::thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        for body in responses {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut reader = BufReader::new(stream);
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap_or(0);
                }
                if line == "\r\n" {
                    break;
                }
            }
            let mut request = vec![0u8; length];
            let _ = reader.read_exact(&mut request);
            let _ = tx.send(serde_json::from_slice(&request).unwrap_or(serde_json::Value::Null));
            let mut stream = reader.into_inner();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), rx, handle)
}

fn client(endpoint: &str, commitment: &str) -> SolanaRpcClient {
    SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        commitment: commitment.to_string(),
        timeout: Duration::from_secs(5),
        max_retries: 0,
    })
}

const TX_RESULT: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"slot":7,"transaction":["AQID","base64"],"meta":{"err":null}}}"#;

// ── R1 / M9 ─────────────────────────────────────────────────────────────────

/// `getTransaction` sent no commitment, so the node answered at `finalized`
/// and a confirmed transaction "did not exist" for ~13 s.
#[tokio::test]
async fn get_transaction_asks_at_the_configured_commitment() {
    let (url, requests, handle) = recording_server(vec![
        TX_RESULT.to_string(),
        TX_RESULT.to_string(),
        TX_RESULT.to_string(),
    ]);
    let confirmed = client(&url, "confirmed");
    confirmed
        .get_chain_transaction("sig")
        .await
        .unwrap()
        .unwrap();
    let sent = requests.recv().unwrap();
    assert_eq!(sent["method"], "getTransaction");
    assert_eq!(sent["params"][1]["commitment"], "confirmed", "{sent}");
    assert_eq!(sent["params"][1]["encoding"], "base64");
    assert_eq!(sent["params"][1]["maxSupportedTransactionVersion"], 1);

    // `getTransaction` refuses `processed`; it is raised to `confirmed`.
    client(&url, "processed")
        .get_transaction_bytes("sig")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        requests.recv().unwrap()["params"][1]["commitment"],
        "confirmed"
    );

    client(&url, "finalized")
        .get_transaction("sig")
        .await
        .unwrap();
    let json = requests.recv().unwrap();
    assert_eq!(json["params"][1]["commitment"], "finalized");
    assert_eq!(json["params"][1]["encoding"], "json");
    handle.join().unwrap();
}

// ── R2 ──────────────────────────────────────────────────────────────────────

/// Unreadable `data` used to become an empty account, and an empty pre-state
/// equals an empty post-state.
#[tokio::test]
async fn unreadable_account_data_is_refused_not_read_as_empty() {
    let shapes = [
        r#"{"lamports":5,"owner":"11111111111111111111111111111111"}"#,
        r#"{"lamports":5,"owner":"11111111111111111111111111111111","data":{"x":1}}"#,
        r#"{"lamports":5,"owner":"11111111111111111111111111111111","data":7}"#,
        r#"{"lamports":5,"owner":"11111111111111111111111111111111","data":[7,"base64"]}"#,
        r#"{"lamports":5,"owner":"11111111111111111111111111111111","data":["AQID","base58"]}"#,
        r#"{"lamports":5,"owner":"11111111111111111111111111111111","data":"AQID"}"#,
        r#"{"lamports":5,"owner":"11111111111111111111111111111111","data":["!!","base64"]}"#,
    ];
    let responses: Vec<String> = shapes
        .iter()
        .map(|v| {
            format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{v}}}}}"#)
        })
        .collect();
    let (url, _requests, handle) = recording_server(responses);
    let c = client(&url, "confirmed");
    let key = Pubkey::from_base58("11111111111111111111111111111111").unwrap();
    for shape in shapes {
        let err = c.get_account(&key).await.unwrap_err();
        assert!(
            matches!(err, RpcError::InvalidResponse(_)),
            "{shape}: {err:?}"
        );
    }
    handle.join().unwrap();

    // The real empty shape still reads as empty.
    let (url, _r, handle) = recording_server(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"lamports":5,"owner":"11111111111111111111111111111111","data":["","base64"]}}}"#.to_string(),
    ]);
    let account = client(&url, "confirmed").get_account(&key).await.unwrap();
    assert!(account.data.is_empty());
    handle.join().unwrap();
}

// ── R3 ──────────────────────────────────────────────────────────────────────

/// A non-string entry was dropped, shifting every later address by one, so
/// an inner instruction's index named the neighbouring account.
#[test]
fn an_unreadable_loaded_address_makes_the_whole_set_unknown() {
    let base = |loaded: serde_json::Value| {
        serde_json::json!({
            "err": null, "logs": [], "unitsConsumed": 1000,
            "preBalances": [1, 2], "postBalances": [1, 2],
            "innerInstructions": [], "loadedAddresses": loaded
        })
    };
    let good = simulation_result_from_value_for_test(&base(serde_json::json!({
        "writable": ["A", "B"], "readonly": ["C"]
    })))
    .unwrap();
    assert_eq!(good.loaded_addresses.unwrap().len(), 3);
    for loaded in [
        serde_json::json!({"writable": ["A", 7, "B"], "readonly": ["C"]}),
        serde_json::json!({"writable": ["A"], "readonly": [null]}),
        serde_json::json!({"writable": ["A"]}),
        serde_json::json!({"writable": "A", "readonly": []}),
    ] {
        let sim = simulation_result_from_value_for_test(&base(loaded.clone())).unwrap();
        assert!(sim.loaded_addresses.is_none(), "{loaded}");
    }
}

// ── R4 ──────────────────────────────────────────────────────────────────────

/// A JSON-RPC error echoing the request URL carried the operator's key into
/// the L3 reason. Bounded was not redacted.
#[tokio::test]
async fn a_jsonrpc_error_echoing_credentials_is_scrubbed() {
    const KEY: &str = "3f9c2a7e1b5d4c8a9e0f6b2d7c1a5e8b";
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":-32401,"message":"invalid api key for https://mainnet.example-rpc.com/?api-key={KEY}; got api-key={KEY} token:{KEY} Bearer abcdef"}}}}"#
    );
    let (url, _r, handle) = recording_server(vec![body]);
    let err = client(&url, "confirmed").get_slot().await.unwrap_err();
    let text = err.to_string();
    assert!(matches!(err, RpcError::RequestFailed(_)), "{err:?}");
    assert!(!text.contains(KEY), "{text}");
    assert!(!text.contains("example-rpc.com"), "{text}");
    assert!(!text.contains("abcdef"), "{text}");
    assert!(text.contains("-32401"), "the diagnostic survives: {text}");
    assert!(text.contains("invalid api key"), "{text}");
    handle.join().unwrap();
}

// ── R5 ──────────────────────────────────────────────────────────────────────

#[test]
fn debug_output_never_prints_the_endpoint() {
    let endpoint = "https://solana-mainnet.example.com/v2/SeCrEtKeY0123456789?api-key=hunter2";
    let config = RpcConfig {
        endpoint: endpoint.to_string(),
        ..Default::default()
    };
    let client = SolanaRpcClient::new(config.clone());
    for printed in [
        format!("{config:?}"),
        format!("{client:?}"),
        format!("{client:#?}"),
    ] {
        for secret in ["SeCrEtKeY", "hunter2", "example.com", "/v2/"] {
            assert!(!printed.contains(secret), "{printed}");
        }
        assert!(printed.contains("redacted https endpoint"), "{printed}");
    }
    assert!(format!("{config:?}").contains("confirmed"));
}

// ── R6 ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_jsonrpc_envelope_is_read_as_one() {
    let (url, _r, handle) = recording_server(vec![
        // `"error": null` is absence, not an error named null.
        r#"{"jsonrpc":"2.0","id":1,"error":null,"result":42}"#.to_string(),
        // An answer to another request is not an answer to this one.
        r#"{"jsonrpc":"2.0","id":99,"result":42}"#.to_string(),
        r#"{"jsonrpc":"1.0","id":1,"result":42}"#.to_string(),
        r#"[{"jsonrpc":"2.0","id":1,"result":42}]"#.to_string(),
        // An error the peer could not attribute carries `id: null`.
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}"#
            .to_string(),
    ]);
    let c = client(&url, "confirmed");
    assert_eq!(c.get_slot().await.unwrap(), 42);
    for _ in 0..3 {
        let err = c.get_slot().await.unwrap_err();
        assert!(matches!(err, RpcError::InvalidResponse(_)), "{err:?}");
    }
    let err = c.get_slot().await.unwrap_err();
    assert!(
        matches!(err, RpcError::RequestFailed(ref m) if m.contains("Parse error")),
        "{err:?}"
    );
    handle.join().unwrap();
}

// ── R7 ──────────────────────────────────────────────────────────────────────

#[test]
fn loopback_is_read_from_the_parsed_host() {
    for endpoint in [
        "http://127.0.0.1:8899",
        "http://127.8.9.1:8899",
        "http://[::1]:8899",
        "http://[::ffff:127.0.0.1]:8899",
        "http://localhost:8899",
        "http://LOCALHOST.:8899",
        "  http://localhost:8899  ",
    ] {
        assert!(validate_endpoint(endpoint).unwrap().loopback, "{endpoint}");
    }
    for endpoint in [
        "http://10.0.0.1:8899",
        "http://[::ffff:10.0.0.1]:8899",
        "http://localhost.example.com:8899",
        "http://notlocalhost:8899",
    ] {
        assert!(!validate_endpoint(endpoint).unwrap().loopback, "{endpoint}");
    }
}

/// The string validated is the string posted to.
#[tokio::test]
async fn the_client_posts_to_the_endpoint_it_was_validated_as() {
    let (url, requests, handle) =
        recording_server(vec![r#"{"jsonrpc":"2.0","id":1,"result":5}"#.to_string()]);
    let padded = format!("  {url}\n");
    assert!(validate_endpoint(&padded).is_ok());
    let c = client(&padded, "confirmed");
    assert_eq!(c.endpoint(), url);
    assert_eq!(c.get_slot().await.unwrap(), 5);
    assert_eq!(requests.recv().unwrap()["method"], "getSlot");
    handle.join().unwrap();
}

// ── R8 ──────────────────────────────────────────────────────────────────────

fn account(owner: &str, data: Vec<u8>) -> AccountState {
    AccountState {
        pubkey: "x".to_string(),
        lamports: 2_039_280,
        owner: owner.to_string(),
        executable: false,
        rent_epoch: 0,
        data,
    }
}

fn token_bytes(state: u8) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(&[7u8; 32]);
    d[32..64].copy_from_slice(&[9u8; 32]);
    d[108] = state;
    d
}

#[test]
fn token_2022_accounts_answer_the_frozen_question() {
    const T22: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
    const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    // Every Token-2022 account read as frozen.
    assert!(!token_account_frozen_flag(&account(T22, token_bytes(1))));
    assert!(token_account_frozen_flag(&account(T22, token_bytes(2))));
    let mut extended = token_bytes(1);
    extended.push(2); // AccountType::Account
    extended.extend_from_slice(&[7, 0, 0, 0]); // ImmutableOwner
    assert!(!token_account_frozen_flag(&account(T22, extended.clone())));
    // Classic SPL Token is exactly 165 bytes.
    assert!(!token_account_frozen_flag(&account(TOKEN, token_bytes(1))));
    assert!(token_account_frozen_flag(&account(TOKEN, extended)));
    // A mint, a Multisig and an uninitialized account cannot answer.
    let mut mint = vec![0u8; 165];
    mint[45] = 1;
    mint.push(1); // AccountType::Mint
    assert!(token_account_frozen_flag(&account(T22, mint)));
    let mut multisig = vec![1u8; 355];
    multisig[108] = 1;
    multisig[165] = 2;
    assert!(token_account_frozen_flag(&account(TOKEN, multisig.clone())));
    assert!(token_account_frozen_flag(&account(T22, multisig)));
    assert!(token_account_frozen_flag(&account(T22, token_bytes(0))));
}

// ── R9 ──────────────────────────────────────────────────────────────────────

/// A node that answers inner instructions in parsed form gives no index.
/// Round 29 named that as the reason the callee set was unknown. Round 35:
/// Agave always answers so, and the parsed form is now read; what is still
/// named is a parsed instruction Graphite does not rebuild to its bytes (here
/// a `transfer` whose `info` is empty), whose callee is known and whose
/// instruction is not.
#[test]
fn parsed_inner_instructions_are_named_as_the_reason_the_cpi_set_is_unknown() {
    let mut sim = simulation_result_from_value_for_test(&serde_json::json!({
        "err": null, "logs": [], "unitsConsumed": 1000,
        "preBalances": [1, 2], "postBalances": [1, 2],
        "innerInstructions": [{"index": 0, "instructions": [
            {"program": "system", "programId": "11111111111111111111111111111111",
             "parsed": {"type": "transfer", "info": {}}, "stackHeight": 2}
        ]}]
    }))
    .unwrap();
    assert!(sim.inner_instructions.is_none());
    assert!(sim.inner_program_indexes.is_none());
    assert_eq!(sim.cpi_hops, Some(1), "the count needs no index");
    assert!(
        sim.provider_anomalies
            .iter()
            .any(|a| a.contains("does not rebuild") && a.contains("`transfer`")),
        "{:?}",
        sim.provider_anomalies
    );
    let keys = vec![
        "4cvyjjocbsVgYLsJGsy1UmVZHi4XYtagv38zezydqzSx".to_string(),
        "11111111111111111111111111111111".to_string(),
    ];
    sim.resolve_reported_inner(&keys);
    assert_eq!(
        sim.inner_program_indexes,
        Some(vec![1]),
        "the callee is known"
    );
    assert!(sim.inner_instructions.is_none(), "the instruction is not");

    let compiled = simulation_result_from_value_for_test(&serde_json::json!({
        "err": null, "logs": [], "unitsConsumed": 1000,
        "preBalances": [1, 2], "postBalances": [1, 2],
        "innerInstructions": [{"index": 0, "instructions": [
            {"programIdIndex": 1, "accounts": [0], "data": "3", "stackHeight": 2}
        ]}]
    }))
    .unwrap();
    assert!(compiled.inner_instructions.is_some());
    assert!(compiled.provider_anomalies.is_empty());
}

// ── R10 ─────────────────────────────────────────────────────────────────────

/// Two refusals carried runs of 18 spaces from a line continuation inside the
/// string literal.
#[tokio::test]
async fn refusals_carry_no_runs_of_spaces() {
    let (url, _r, handle) = recording_server(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"lamports":"5","owner":"11111111111111111111111111111111","data":["","base64"]}}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"lamports":5,"data":["","base64"]}}}"#.to_string(),
    ]);
    let c = client(&url, "confirmed");
    let key = Pubkey::from_base58("11111111111111111111111111111111").unwrap();
    for _ in 0..2 {
        let text = c.get_account(&key).await.unwrap_err().to_string();
        assert!(!text.contains("  "), "{text:?}");
    }
    handle.join().unwrap();
}
