//! Requires the `rpc` feature.
#![cfg(feature = "rpc")]

//! A slow RPC must cost Graphite its evidence, not its verdict.
//!
//! Found 2026-09-08 auditing the server as production infrastructure. The
//! timeout budget was inverted: `server.rs` gives every request a 10-second
//! `REQUEST_TIMEOUT` and attached an RPC client built from `RpcConfig::default()`
//! — 30 seconds per call, 3 retries, backoff. A verification makes up to three
//! calls, so the RPC side could run for minutes behind a ten-second deadline,
//! and the deadline always won.
//!
//! The damage is not slowness. The caller got a bare `408` with no verdict, no
//! layer report and no reason, from a system whose premise is fail-closed *with
//! an explanation*; nothing reached the append-only audit trail, because the
//! verification never finished; and an SDK reading `408` as "the server was
//! slow" retries, which is the worst available response to an overloaded RPC.
//! All of it triggered by the most ordinary production degradation there is.
//!
//! Bounding the total is what makes this hold — three calls each comfortably
//! under the deadline still exceed it together — so these tests measure elapsed
//! wall-clock against the budget rather than checking that a number was
//! configured.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, DEFAULT_RPC_BUDGET,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const FROM: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const TO: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

/// An RPC that accepts the connection and then does nothing.
///
/// This is what a rate-limiting or overloaded endpoint looks like from the
/// client side, and it is the case a per-call timeout handles individually and
/// a total budget has to handle collectively.
fn stalling_rpc(hold: Duration) -> String {
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").unwrap());
    let addr = listener.local_addr().unwrap();
    let server = Arc::clone(&listener);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = server.accept() {
            let mut buf = vec![0u8; 65536];
            let _ = stream.read(&mut buf);
            std::thread::sleep(hold);
            // If anyone is still listening by now, answer something valid so a
            // pass cannot be attributed to a malformed reply.
            let body = r#"{"jsonrpc":"2.0","id":1,"result":null}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
        }
    });
    std::mem::forget(listener);
    format!("http://{addr}")
}

fn core_against(endpoint: &str, budget: Duration) -> GraphiteCore {
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        // Deliberately LONGER than the budget, reproducing the shape of the
        // original defect: a per-call timeout that cannot save the request.
        timeout: Duration::from_secs(60),
        max_retries: 3,
        ..Default::default()
    }));
    core.set_rpc_budget(budget);
    core
}

fn tx() -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: SYSTEM_PROGRAM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![FROM.to_string(), TO.to_string()],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 5,
            battle_tested_tx_count: 50_000,
            simulation_match_count: 100,
        },
        compute_units: 300,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: Some(vec![1, 2, 3, 4]),
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

/// The load-bearing measurement: an RPC that never answers must not be able to
/// hold a verification past its budget.
///
/// The client here is configured with a 60-second per-call timeout and 3
/// retries — the original defect's shape — so if the total is not enforced, this
/// test hangs for minutes instead of failing.
#[tokio::test]
async fn a_stalled_rpc_cannot_hold_a_verification_past_its_budget() {
    let budget = Duration::from_secs(2);
    let endpoint = stalling_rpc(Duration::from_secs(120));
    let core = core_against(&endpoint, budget);

    let started = Instant::now();
    let result = core
        .verify_async(&tx())
        .await
        .expect("verification must still return a verdict");
    let elapsed = started.elapsed();

    assert!(
        elapsed < budget + Duration::from_secs(3),
        "an RPC that never answered held the verification for {elapsed:?} against a {budget:?} \
         budget — the per-call timeout is not bounding the total"
    );
    // And it is a real verdict, not an error: the caller gets layers and a
    // reason, which is the whole difference between this and a bare 408.
    assert_eq!(result.layers.len(), 8, "all eight layers must be reported");
}

/// Losing the RPC must cost evidence and nothing else. L3 and L4 report that
/// they could not run; neither claims a pass.
#[tokio::test]
async fn a_budget_exhaustion_is_reported_as_missing_evidence_not_as_a_pass() {
    let endpoint = stalling_rpc(Duration::from_secs(120));
    let core = core_against(&endpoint, Duration::from_secs(2));
    let result = core
        .verify_async(&tx())
        .await
        .expect("verification must return a verdict");

    let l3 = result
        .layers
        .iter()
        .find(|l| l.layer.contains("Simulation"))
        .expect("L3 present");
    assert!(
        !matches!(l3.status, LayerStatus::Passed),
        "an RPC that never answered produced a passing simulation-integrity result: {}",
        l3.reason
    );

    let l4 = result
        .layers
        .iter()
        .find(|l| l.layer.contains("State"))
        .expect("L4 present");
    assert!(
        l4.reason.contains("could not be built") || l4.reason.contains("structural consistency"),
        "L4 had no diff and did not say so: {}",
        l4.reason
    );
}

/// The budget is a TOTAL, not a per-call allowance.
///
/// This is the property a per-call timeout cannot give you: several calls that
/// each finish inside the deadline can still exceed it together. Each response
/// here arrives comfortably within any single-call limit, and the verification
/// still has to stop at the budget.
#[tokio::test]
async fn several_individually_prompt_calls_cannot_together_exceed_the_budget() {
    let budget = Duration::from_secs(2);
    // Each call takes ~1.2s: fine on its own, over budget by the third.
    let endpoint = stalling_rpc(Duration::from_millis(1200));
    let core = core_against(&endpoint, budget);

    let started = Instant::now();
    let _ = core.verify_async(&tx()).await.expect("verdict");
    let elapsed = started.elapsed();

    assert!(
        elapsed < budget + Duration::from_secs(3),
        "three calls at 1.2s each ran for {elapsed:?} against a {budget:?} total budget"
    );
}

/// The shipped default has to be a number that actually fits.
///
/// `server.rs` carries a compile-time assertion of the same relationship; this
/// states it once more where a reader looking for the guarantee will find it.
#[test]
fn the_default_budget_fits_inside_the_servers_request_timeout() {
    // server::REQUEST_TIMEOUT is 10s and private; the invariant is that the
    // budget leaves headroom for the rest of the pipeline and the response.
    assert!(
        DEFAULT_RPC_BUDGET <= Duration::from_secs(8),
        "the default RPC budget ({DEFAULT_RPC_BUDGET:?}) leaves no headroom inside a 10s request \
         timeout — the inner deadline must always expire before the outer one"
    );
    assert!(
        DEFAULT_RPC_BUDGET >= Duration::from_secs(3),
        "the default RPC budget ({DEFAULT_RPC_BUDGET:?}) is too tight for a simulate + \
         getMultipleAccounts round trip against a real cluster, and would turn ordinary \
         latency into permanent evidence loss"
    );
}
