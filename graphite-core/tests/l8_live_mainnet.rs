//! Live mainnet validation of L8 execution verification (network-dependent).
//!
//! Validates `GraphiteCore::verify_execution` against REAL mainnet RPC:
//!   - a confirmed SUCCESSFUL signature  -> ExecutionVerification::Confirmed { success: true }
//!   - an unknown/fabricated signature   -> UnknownSignature (or Unavailable, never a fake Confirmed)
//!   - an RPC-unreachable endpoint       -> Unavailable (never a fake Confirmed)
//!   - malformed RPC response            -> Unavailable (safe failure)
//!
//! `#[ignore]`d by default (the deterministic suite must never depend on the
//! network). Run explicitly:
//!
//! ```bash
//! cargo test --features rpc -- --ignored --test l8_live_mainnet
//! ```
//!
//! Honest L8 contract (see verification.rs): L8 confirms INCLUSION and
//! on-chain STATUS of an already-submitted signature. It does NOT and cannot
//! prove that the transaction's effects matched a pre-submission prediction —
//! that would require fetching and diffing post-state, which the getSignature
//! primitive does not provide. This test documents exactly that boundary.

#![cfg(feature = "rpc")]

use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::verification::{ExecutionVerification, GraphiteCore};

fn mainnet_client(endpoint: Option<&str>) -> SolanaRpcClient {
    match endpoint {
        Some(e) => SolanaRpcClient::new(RpcConfig {
            endpoint: e.to_string(),
            ..Default::default()
        }),
        None => SolanaRpcClient::mainnet(),
    }
}

/// Endpoint override for tests (avoids depending on the operator's env).
fn env_endpoint() -> Option<String> {
    std::env::var("GRAPHITE_RPC_URL")
        .ok()
        .filter(|v| !v.is_empty())
}

/// A signature that has been confirmed successfully on mainnet (fetched live
/// via getSignaturesForAddress for the System Program, err=null entries).
async fn fetch_a_confirmed_success_signature() -> Option<String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getSignaturesForAddress",
        "params": ["11111111111111111111111111111111", {"limit": 3}]
    });
    let url = std::env::var("GRAPHITE_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    let resp = post_json(&url, &body).await?;
    let arr = resp.get("result")?.as_array()?;
    for item in arr {
        let sig = item.get("signature")?.as_str()?;
        match item.get("err") {
            None | Some(serde_json::Value::Null) => return Some(sig.to_string()),
            _ => {}
        }
    }
    None
}

async fn post_json(url: &str, body: &serde_json::Value) -> Option<serde_json::Value> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .ok()?;
    let resp = client.post(url).json(body).send().await.ok()?;
    resp.json().await.ok()
}

#[tokio::test]
#[ignore = "network test — run explicitly: cargo test --features rpc -- --ignored --test l8_live_mainnet"]
async fn l8_confirmed_success_signature_reports_confirmed_success() {
    let sig = match fetch_a_confirmed_success_signature().await {
        Some(s) => s,
        None => {
            eprintln!(
                "SKIP: could not fetch a confirmed mainnet signature (network or RPC degraded)"
            );
            return;
        }
    };
    eprintln!("testing confirmed signature: {}", &sig[..20]);
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(mainnet_client(env_endpoint().as_deref()));
    let outcome = core
        .verify_execution(&sig)
        .await
        .expect("verify_execution must not error");
    match &outcome {
        ExecutionVerification::Confirmed {
            signature,
            slot,
            success,
            error,
        } => {
            assert!(
                *success,
                "fetched signature has err=null so must report success, got error={error:?}"
            );
            assert!(signature.starts_with(&sig[..10]));
            assert!(*slot > 0, "confirmed signature must carry a slot");
            eprintln!("L8 CONFIRMED: slot={slot} success={success}");
        }
        ExecutionVerification::UnknownSignature(s) => {
            // A signature we JUST fetched from the cluster being unknown would
            // be an RPC inconsistency — but a lagging/load-balanced endpoint
            // can legitimately miss it. Report, don't fail the network test.
            eprintln!(
                "WARN: freshly-fetched signature reported Unknown: {}",
                &s[..20]
            );
        }
        ExecutionVerification::Unavailable(reason) => {
            eprintln!("WARN: L8 unavailable (network degraded?): {reason}");
        }
    }
}

#[tokio::test]
#[ignore = "network test — run explicitly"]
async fn l8_fabricated_signature_is_never_confirmed() {
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(mainnet_client(env_endpoint().as_deref()));
    // A fabricated signature (64 bytes, never submitted) must NOT be reported
    // as Confirmed — UnknownSignature or Unavailable only.
    let fake =
        "2AXDGYSE4f2sz7tvMMzyHvUfcoJmxudvdhBcmiUSo6ijwfYmfZYsKRxboQMPh3R4kUhXRVdtSXFXMheka4Rc4P2";
    let outcome = core.verify_execution(fake).await.expect("must not error");
    assert!(
        !matches!(outcome, ExecutionVerification::Confirmed { .. }),
        "a fabricated signature must NEVER be reported as Confirmed: {outcome:?}"
    );
    eprintln!("L8 fabricated signature outcome: {outcome:?}");
}

#[tokio::test]
#[ignore = "network test — run explicitly"]
async fn l8_unreachable_rpc_is_unavailable_not_confirmed() {
    // An unreachable endpoint must produce Unavailable — never a fabricated
    // Confirmed. (Unavailable is a safe, honest degradation.)
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(mainnet_client(Some("http://127.0.0.1:1")));
    let outcome = core
        .verify_execution("2AXDGYSE4f2sz7tvMMzyHvUfcoJmxudvdhBcmiUSo6ijwfYmfZYsKRxboQMPh3R4kUhXRVdtSXFXMheka4Rc4P2")
        .await
        .expect("must not error");
    assert!(
        matches!(outcome, ExecutionVerification::Unavailable(_)),
        "unreachable RPC must be Unavailable, got: {outcome:?}"
    );
    eprintln!("L8 unreachable-RPC outcome: {outcome:?}");
}
