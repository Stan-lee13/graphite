//! CRITICAL regression suite (2026-09-05 production audit, fixed 2026-09-05):
//! "RPC provider URL (with embedded API key) leaks into the /verify HTTP
//! response body."
//!
//! `reqwest::Error`'s `Display` impl appends `" for url (<full url>)"` to
//! every error that carries a URL. Managed Solana RPC providers (Helius,
//! QuickNode, Alchemy, Shyft, …) embed the operator's API key directly in
//! that URL — as a query parameter (`?api-key=SECRET`) or a path segment.
//!
//! `RpcError` values flow into `VerificationResult`'s L3 layer `reason`
//! string, which is serialized straight into the `/verify` HTTP response
//! body. So before this fix, ONE ordinary transport hiccup — a timeout, a DNS
//! blip, a TLS error, a provider outage, a rate-limit disconnect — handed the
//! operator's paid RPC credentials to whoever happened to make that request.
//! No attacker-controlled infrastructure was required: an attacker only had
//! to send `/verify` traffic and wait for the provider to be flaky, or induce
//! flakiness by burning the operator's rate limit.
//!
//! These tests are deliberately adversarial: they assert on the SECRET's
//! absence rather than on the error message's exact wording, so they keep
//! catching the leak even if the surrounding message text is rewritten later,
//! and they cover every transport failure mode reachable from a bad endpoint
//! (connection refused, DNS failure, timeout, TLS failure) rather than just
//! the one that happened to be reported.

#![cfg(feature = "rpc")]

use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::solana_types::Pubkey;
use std::time::Duration;

/// The kind of value a real operator's `GRAPHITE_RPC_URL` carries. If any of
/// these substrings ever appears in an error surfaced to a caller, the
/// operator's paid credentials have been disclosed.
const SECRET_KEY: &str = "a1b2c3d4-SUPER-SECRET-RPC-KEY-e5f6";
const SECRET_HOST: &str = "operator-private-endpoint.example.invalid";

fn client_for(endpoint: &str) -> SolanaRpcClient {
    SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        commitment: "confirmed".to_string(),
        // Keep the test fast: one attempt, short timeout. The redaction must
        // hold on the FINAL surfaced error, which is what a caller sees.
        max_retries: 0,
        timeout: Duration::from_millis(600),
    })
}

fn any_pubkey() -> Pubkey {
    Pubkey::from_base58("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU")
        .expect("fixture pubkey must parse")
}

/// Assert an error string discloses neither the API key nor the private host.
/// Checked case-insensitively: a leak that differs only in case is still a
/// leak.
fn assert_no_secret_leak(context: &str, rendered: &str) {
    let haystack = rendered.to_lowercase();
    assert!(
        !haystack.contains(&SECRET_KEY.to_lowercase()),
        "{context}: RPC API KEY leaked into an error surfaced to the caller: {rendered}"
    );
    assert!(
        !haystack.contains(&SECRET_HOST.to_lowercase()),
        "{context}: private RPC host leaked into an error surfaced to the caller: {rendered}"
    );
    // The scheme+host prefix is the shape reqwest's Display appends; catching
    // it directly guards against a partial-URL leak that happens to omit the
    // key itself but still discloses the operator's private endpoint.
    assert!(
        !haystack.contains("for url ("),
        "{context}: reqwest's URL-bearing Display output reached the caller verbatim: {rendered}"
    );
}

/// Connection refused / DNS failure against a URL whose QUERY STRING carries
/// the key — the Helius/Shyft shape.
#[tokio::test]
async fn query_string_api_key_never_leaks_on_transport_failure() {
    let endpoint = format!("https://{SECRET_HOST}/?api-key={SECRET_KEY}");
    let client = client_for(&endpoint);

    let err = client
        .get_account(&any_pubkey())
        .await
        .expect_err("an unreachable endpoint must fail");

    assert_no_secret_leak("query-string key", &err.to_string());
    assert_no_secret_leak("query-string key (Debug)", &format!("{err:?}"));
}

/// Same, for a URL whose PATH SEGMENT carries the key — the QuickNode/Alchemy
/// shape. A redaction that only stripped query parameters would pass the test
/// above and still leak here.
#[tokio::test]
async fn path_segment_api_key_never_leaks_on_transport_failure() {
    let endpoint = format!("https://{SECRET_HOST}/v2/{SECRET_KEY}/");
    let client = client_for(&endpoint);

    let err = client
        .get_account(&any_pubkey())
        .await
        .expect_err("an unreachable endpoint must fail");

    assert_no_secret_leak("path-segment key", &err.to_string());
    assert_no_secret_leak("path-segment key (Debug)", &format!("{err:?}"));
}

/// Credentials embedded as HTTP basic auth in the userinfo component.
#[tokio::test]
async fn basic_auth_credentials_never_leak_on_transport_failure() {
    let endpoint = format!("https://user:{SECRET_KEY}@{SECRET_HOST}/");
    let client = client_for(&endpoint);

    let err = client
        .get_account(&any_pubkey())
        .await
        .expect_err("an unreachable endpoint must fail");

    assert_no_secret_leak("basic-auth credentials", &err.to_string());
    assert_no_secret_leak("basic-auth credentials (Debug)", &format!("{err:?}"));
}

/// A TIMEOUT is a distinct `reqwest::Error` variant from a connection
/// failure, and it also carries the URL. Point at a black-hole address
/// (TEST-NET-1, RFC 5737 — guaranteed non-routable, so the request hangs
/// until the client timeout fires) to exercise that path specifically.
#[tokio::test]
async fn timeout_error_never_leaks_the_endpoint() {
    let endpoint = format!("https://192.0.2.1/?api-key={SECRET_KEY}");
    let client = SolanaRpcClient::new(RpcConfig {
        endpoint,
        commitment: "confirmed".to_string(),
        max_retries: 0,
        timeout: Duration::from_millis(400),
    });

    let err = client
        .get_account(&any_pubkey())
        .await
        .expect_err("a black-holed endpoint must time out");

    assert_no_secret_leak("timeout", &err.to_string());
    assert_no_secret_leak("timeout (Debug)", &format!("{err:?}"));
    // 192.0.2.1 is not itself secret, but the same Display path that would
    // print it is the one that prints a real operator's host — assert the
    // URL-bearing suffix is gone rather than the literal address.
    assert!(
        !err.to_string().contains("192.0.2.1"),
        "the endpoint address reached the caller: {err}"
    );
}

/// Retries must not reintroduce the leak: the error a caller finally sees
/// after exhausting `max_retries` is the LAST error, and it goes through the
/// same construction path.
#[tokio::test]
async fn secret_never_leaks_after_retries_are_exhausted() {
    let endpoint = format!("https://{SECRET_HOST}/?api-key={SECRET_KEY}");
    let client = SolanaRpcClient::new(RpcConfig {
        endpoint,
        commitment: "confirmed".to_string(),
        max_retries: 2,
        timeout: Duration::from_millis(400),
    });

    let err = client
        .get_account(&any_pubkey())
        .await
        .expect_err("an unreachable endpoint must fail");

    assert_no_secret_leak("after retries", &err.to_string());
}

/// The error must still be USEFUL after redaction — an operator debugging a
/// misconfigured endpoint needs to know the failure category. A redaction
/// that returned a bare empty/constant string would pass every assertion
/// above while destroying operability (P3: explainability is not optional).
#[tokio::test]
async fn redacted_error_still_identifies_the_failure_category() {
    let endpoint = format!("https://{SECRET_HOST}/?api-key={SECRET_KEY}");
    let client = client_for(&endpoint);

    let err = client
        .get_account(&any_pubkey())
        .await
        .expect_err("an unreachable endpoint must fail");
    let rendered = err.to_string().to_lowercase();

    assert!(
        rendered.contains("connection failed")
            || rendered.contains("timeout")
            || rendered.contains("transport error")
            || rendered.contains("request error"),
        "the redacted error must still name the failure category, got: {err}"
    );
}
