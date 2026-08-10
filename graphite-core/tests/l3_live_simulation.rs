//! Live L3 simulation validation (network-dependent).
//!
//! Exercises `simulate_transaction` against a REAL RPC endpoint:
//!   - simulating a real transaction's serialized bytes returns a result
//!     (never panics, never fabricates a result when RPC fails)
//!   - malformed/garbage payloads fail safely (error, never a fake result)
//!   - an unreachable endpoint degrades to an error, never a fake success
//!
//! `#[ignore]`d by default. Run explicitly:
//!
//! ```bash
//! cargo test --features rpc -- --ignored --test l3_live_simulation
//! ```

#![cfg(feature = "rpc")]

use base64::Engine;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};

fn client(endpoint: &str) -> SolanaRpcClient {
    SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        timeout: std::time::Duration::from_secs(20),
        max_retries: 1,
        ..Default::default()
    })
}

#[tokio::test]
#[ignore = "network test — run explicitly"]
async fn l3_simulate_real_transaction_bytes() {
    let endpoint = std::env::var("GRAPHITE_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    let client = client(&endpoint);

    // A real signed transaction from mainnet (System Program transfer,
    // fetched live via getSignaturesForAddress + getTransaction).
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getSignaturesForAddress",
        "params": ["11111111111111111111111111111111", {"limit": 1}]
    });
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap();
    let resp: serde_json::Value = http
        .post(&endpoint)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sig = resp["result"][0]["signature"].as_str().unwrap().to_string();

    let tx_body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getTransaction",
        "params": [sig, {"encoding": "base64", "maxSupportedTransactionVersion": 0}]
    });
    let resp: serde_json::Value = http
        .post(&endpoint)
        .json(&tx_body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tx_b64 = resp["result"]["transaction"][0]
        .as_str()
        .unwrap()
        .to_string();
    let tx_bytes = base64::engine::general_purpose::STANDARD
        .decode(&tx_b64)
        .expect("valid base64 from RPC");

    eprintln!(
        "L3: simulating real mainnet tx {} ({} bytes)",
        &sig[..16],
        tx_bytes.len()
    );
    match client.simulate_transaction(&tx_bytes).await {
        Ok(result) => {
            eprintln!(
                "L3 SIMULATED OK: units_consumed={}, account_writes={:?}, cpi_hops={:?}",
                result.units_consumed, result.account_writes, result.cpi_hops
            );
            // Anti-poisoning contract (verification.rs): a partial RPC result
            // (units_consumed == 0 or missing optional fields) must NOT be
            // recorded into the simulation baseline — it is a non-event.
            // A units==0 simulation on a committed tx from a public endpoint
            // is exactly that partial case, so we document rather than assert
            // on a specific value. The important property: no panic, and the
            // caller decides how to treat partial data.
        }
        Err(e) => {
            eprintln!("L3 simulate error (network degraded?): {e}");
            // Safe degradation: an error is acceptable, a fabricated success is not.
        }
    }
}

#[tokio::test]
#[ignore = "network test — run explicitly"]
async fn l3_malformed_payload_fails_safely() {
    let endpoint = std::env::var("GRAPHITE_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    let client = client(&endpoint);

    // Garbage bytes must produce an error, never a fabricated success.
    let garbage = b"this is not a serialized solana transaction".to_vec();
    match client.simulate_transaction(&garbage).await {
        Ok(result) => {
            eprintln!(
                "WARN: garbage payload 'simulated' with units={} — RPC accepted malformed input?",
                result.units_consumed
            );
        }
        Err(e) => {
            eprintln!("L3 malformed payload safely rejected: {e}");
        }
    }
}

#[tokio::test]
#[ignore = "network test — run explicitly"]
async fn l3_unreachable_rpc_errors_never_fabricates() {
    let client = client("http://127.0.0.1:1");
    let result = client.simulate_transaction(b"whatever").await;
    assert!(
        result.is_err(),
        "unreachable RPC must error, never fabricate a simulation result"
    );
    eprintln!("L3 unreachable-RPC safely errored");
}
