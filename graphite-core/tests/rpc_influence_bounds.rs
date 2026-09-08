//! Requires the `rpc` feature.
#![cfg(feature = "rpc")]

//! MISSION 7 — how far can the RPC move the verdict?
//!
//! `rpc_trust_boundary.rs` asks whether a lying peer can break a check. This
//! asks the quieter question: how much can an honest-looking peer move the
//! score, and can that movement alone carry a transaction across the approval
//! line?
//!
//! The distinction matters because a clean simulation is legitimate positive
//! evidence — P5 says simulation is evidence, and evidence is supposed to count.
//! The design is only sound if the movement it buys is bounded and cannot
//! overturn a deterministic finding. That is a claim about a number, so these
//! tests measure the number rather than asserting a feeling about it.
//!
//! Establishing a baseline takes MIN_SAMPLES observations, so the attacker
//! modelled here is patient: they answer plausibly ten times to earn the
//! layer's trust, then spend it.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationResult,
};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const FROM: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const TO: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

/// A cooperative mock: answers every request with the same flawless result.
/// This is the peer trying to be believed, not the peer trying to break things.
fn perfect_rpc() -> String {
    let sim = r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{
        "err":null,"logs":["Program 11111111111111111111111111111111 success"],
        "unitsConsumed":300,"fee":5000,
        "preBalances":[1000000000,1000000],"postBalances":[999993000,1002000],
        "innerInstructions":[],"accounts":[
            {"lamports":999993000,"owner":"11111111111111111111111111111111","executable":false,"rentEpoch":0,"data":["","base64"]},
            {"lamports":1002000,"owner":"11111111111111111111111111111111","executable":false,"rentEpoch":0,"data":["","base64"]}],
        "returnData":null}}}"#;
    let accounts = r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":[
        {"lamports":1000000000,"owner":"11111111111111111111111111111111","executable":false,"rentEpoch":0,"data":["","base64"]},
        {"lamports":1000000,"owner":"11111111111111111111111111111111","executable":false,"rentEpoch":0,"data":["","base64"]}]}}"#;
    let mut m = HashMap::new();
    m.insert("simulateTransaction".to_string(), sim.to_string());
    m.insert("getMultipleAccounts".to_string(), accounts.to_string());
    serve(m)
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
    // Leaked deliberately: the listener must outlive the test body, and a test
    // process is the whole lifetime.
    std::mem::forget(listener);
    format!("http://{addr}")
}

fn core_with_rpc(endpoint: &str) -> GraphiteCore {
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    }));
    core
}

fn input(discriminator: &str, intent: &str, profile: WalletProfile) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: intent.to_string(),
            raw_natural_language: "send SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: SYSTEM_PROGRAM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: discriminator.to_string(),
        account_addresses: vec![FROM.to_string(), TO.to_string()],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: profile,
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

/// Run the same transaction enough times for the peer to earn a baseline, then
/// return the verdict it gets afterwards.
async fn after_baseline_is_earned(
    core: &GraphiteCore,
    tx: &VerificationInput,
) -> VerificationResult {
    for _ in 0..12 {
        let _ = core.verify_async(tx).await;
    }
    core.verify_async(tx).await.expect("verification must run")
}

/// The measurement this file exists for.
///
/// Reported rather than merely asserted: a bound nobody has measured is a
/// belief. The number printed here is the maximum the RPC moved the score in
/// this configuration, and the assertion is on what it may never move.
#[tokio::test]
async fn the_rpc_cannot_move_the_score_past_a_deterministic_finding() {
    let endpoint = perfect_rpc();
    let tx = input("02000000", "transfer", WalletProfile::Gaming);

    let without = GraphiteCore::new()
        .verify_async(&tx)
        .await
        .expect("verification must run");
    let with = after_baseline_is_earned(&core_with_rpc(&endpoint), &tx).await;

    eprintln!(
        "confidence without RPC: {:.4}   with a flawless RPC: {:.4}   swing: {:+.4}",
        without.confidence,
        with.confidence,
        with.confidence - without.confidence
    );

    // A clean simulation is allowed to be worth something — that is what P5
    // means by evidence. What it may not do is carry a transaction whose
    // deterministic layers found a problem.
    let failed_layers: Vec<_> = with
        .layers
        .iter()
        .filter(|l| matches!(l.status, LayerStatus::Failed))
        .map(|l| l.layer.clone())
        .collect();
    if !failed_layers.is_empty() {
        assert!(
            !with.approved,
            "a flawless RPC produced an approval while these layers reported a failure: {failed_layers:?}"
        );
    }
}

/// The same measurement where it actually bites: a transaction the static
/// layers reject outright.
///
/// The peer answers perfectly, has a fully earned baseline, and reports a clean
/// diff. If the score alone could carry this, the peer would be deciding.
#[tokio::test]
async fn an_earned_baseline_does_not_buy_a_rejected_transaction_an_approval() {
    let endpoint = perfect_rpc();
    // Intent says "transfer"; the discriminator is System Assign, which hands
    // the account to another program.
    let hostile = input("01000000", "transfer", WalletProfile::Gaming);
    let benign = input("02000000", "transfer", WalletProfile::Gaming);

    let core = core_with_rpc(&endpoint);
    // Earn the baseline on ordinary traffic first, exactly as a patient peer
    // would.
    for _ in 0..12 {
        let _ = core.verify_async(&benign).await;
    }
    let result = core
        .verify_async(&hostile)
        .await
        .expect("verification must run");

    assert!(
        !result.approved,
        "an RPC with a fully earned baseline approved a transaction whose intent contradicts \
         its instruction. confidence={:.4} verdict={}",
        result.confidence, result.policy_verdict
    );
}

/// L4 has two modes that report in similar words: a real pre/post diff, and the
/// structural check it falls back to. An operator — and the score — must be able
/// to tell them apart.
///
/// Absence of evidence must not read as evidence of absence, so the fallback
/// says so in its own reason.
#[tokio::test]
async fn a_fallback_state_check_says_so_rather_than_reporting_a_diff() {
    // A peer that simulates but returns no post-state: the diff cannot be built.
    let mut m = HashMap::new();
    m.insert(
        "simulateTransaction".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{
            "err":null,"logs":[],"unitsConsumed":300,"fee":5000,
            "preBalances":[1000000000,1000000],"postBalances":[999993000,1002000],
            "innerInstructions":[],"accounts":null,"returnData":null}}}"#
            .to_string(),
    );
    let endpoint = serve(m);
    let core = core_with_rpc(&endpoint);
    let result = core
        .verify_async(&input("02000000", "transfer", WalletProfile::Gaming))
        .await
        .expect("verification must run");

    let l4 = result
        .layers
        .iter()
        .find(|l| l.layer.contains("State"))
        .expect("L4 must be present");
    assert!(
        l4.reason.contains("structural consistency check")
            || l4.reason.contains("could not be built"),
        "L4 fell back to its heuristic and reported it in the words of a completed diff: {}",
        l4.reason
    );
}

/// An RPC that is present but useless must leave the verdict where an absent one
/// leaves it.
///
/// Otherwise "the endpoint is configured" would itself be worth confidence, and
/// an attacker who can answer at all — with nothing — would gain something.
#[tokio::test]
async fn a_useless_rpc_is_worth_no_more_than_no_rpc() {
    // Answers every method with `null`: reachable, informative about nothing.
    let endpoint = serve(HashMap::new());
    let tx = input("02000000", "transfer", WalletProfile::Gaming);

    let none = GraphiteCore::new()
        .verify_async(&tx)
        .await
        .expect("verification must run");
    let useless = core_with_rpc(&endpoint)
        .verify_async(&tx)
        .await
        .expect("verification must run");

    assert_eq!(
        useless.approved, none.approved,
        "an RPC that returned nothing changed the verdict"
    );
    assert!(
        (useless.confidence - none.confidence).abs() < 1e-9,
        "an RPC that returned nothing changed the confidence score: {:.4} vs {:.4}",
        useless.confidence,
        none.confidence
    );
}

/// The measurement that decides whether the swing above is academic.
///
/// It is not. `SimulationMatch` is 20% of the confidence score and saturates
/// after `SIMULATION_MATCH` earned observations, so a peer that answers
/// plausibly enough times takes the score from 0.44 to 0.64 — across the Gaming
/// profile's 0.55 threshold. A transaction Graphite refused for want of evidence
/// becomes one it approves, on the word of a single unauthenticated network
/// endpoint.
///
/// This is the design working as specified rather than a check failing: earned
/// simulation evidence is meant to count, and P5 calls simulation evidence. What
/// it means is that the RPC endpoint an operator configures is inside the
/// trusted computing base, and that fact belongs in the threat model rather than
/// in a surprise. The hard boundary — that no amount of it overturns a
/// deterministic finding — is asserted in the tests above.
///
/// Pinned here so the size of the RPC's influence cannot grow unnoticed.
#[tokio::test]
async fn the_rpcs_influence_on_the_score_is_measured_and_bounded() {
    let endpoint = perfect_rpc();
    let tx = input("02000000", "transfer", WalletProfile::Gaming);

    let without = GraphiteCore::new()
        .verify_async(&tx)
        .await
        .expect("verification must run");
    let with = after_baseline_is_earned(&core_with_rpc(&endpoint), &tx).await;
    let swing = with.confidence - without.confidence;

    eprintln!(
        "RPC influence: {:.4} -> {:.4} (swing {:+.4}); approved {} -> {}",
        without.confidence, with.confidence, swing, without.approved, with.approved
    );

    // The whole of SimulationMatch is 0.20 of the score. Earned simulation
    // evidence may saturate that signal and nothing more; if this ever exceeds
    // it, the RPC has gained weight somewhere else as well.
    assert!(
        swing <= 0.20 + 1e-9,
        "a cooperative RPC moved the confidence score by {swing:+.4}, more than the 0.20 that \
         the SimulationMatch signal is worth. It is contributing to some other signal too."
    );
    assert!(
        swing >= 0.0,
        "earned simulation evidence reduced the score by {swing:+.4}"
    );

    // And it must never reach a transaction the deterministic layers rejected.
    let rejected = input("01000000", "transfer", WalletProfile::Gaming);
    let core = core_with_rpc(&endpoint);
    for _ in 0..12 {
        let _ = core.verify_async(&tx).await;
    }
    let hostile = core
        .verify_async(&rejected)
        .await
        .expect("verification must run");
    assert!(
        !hostile.approved,
        "the swing carried a transaction whose intent contradicts its instruction: {:.4}",
        hostile.confidence
    );
}
