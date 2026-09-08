//! Requires the `rpc` feature: the signal comes from a simulation response.
#![cfg(feature = "rpc")]

//! MISSION 8 — Address Lookup Tables, measured instead of taken on trust.
//!
//! Graphite's ALT handling was a caller-declared boolean and a documented blind
//! spot: `uses_versioned_transaction` produced a warning that said "accounts
//! resolved via ALT are not independently verified by this pipeline", and the
//! source comment recorded that full `VersionedTransaction` parsing plus RPC ALT
//! resolution was a larger follow-up nobody wanted to rush.
//!
//! It turns out the answer was already arriving. `simulateTransaction` returns
//! `loadedAddresses` — precisely the accounts the runtime pulled in through a
//! lookup table. Graphite was reading that response for compute numbers and
//! post-state and discarding the field. No wire-format parser is required.
//!
//! Why it matters beyond tidiness: ALT-resolved accounts never appear in the
//! transaction's static keys, so they never appear in the `account_addresses`
//! that L1, L4, L5 and L7 all reason over. A transaction can therefore touch
//! accounts that every layer in this pipeline examined nothing about, and before
//! this the only hint was the caller volunteering a boolean that defaults to
//! false.
//!
//! Disclosed, never penalized. ALT usage is ordinary for legitimate complex
//! routes, and because the flag defaults to false, blocking on a contradiction
//! would reject every integration that simply never set it. The change is that
//! the disclosure is now a measurement rather than a restatement of the caller's
//! claim.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const FROM: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const TO: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
/// Two accounts that exist only inside a lookup table — the transaction's static
/// keys never name them, so nothing in `account_addresses` covers them.
const HIDDEN_WRITABLE: &str = "HidW1111111111111111111111111111111111111111";
const HIDDEN_READONLY: &str = "HidR1111111111111111111111111111111111111111";

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

/// A simulation response whose `loadedAddresses` is whatever the test needs.
fn rpc_reporting(loaded: &str) -> String {
    let account = |l: u64| {
        format!(
            r#"{{"lamports":{l},"owner":"{SYSTEM_PROGRAM}","executable":false,"rentEpoch":0,"data":["","base64"]}}"#
        )
    };
    let sim = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
            "err":null,"logs":[],"unitsConsumed":300,"fee":5000,
            "preBalances":[1000000000,1000000],"postBalances":[999993000,1002000],
            "innerInstructions":[],"loadedAddresses":{loaded},
            "accounts":[{},{}],"returnData":null}}}}}}"#,
        account(999_993_000),
        account(1_002_000)
    );
    let accounts = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":[{},{}]}}}}"#,
        account(1_000_000_000),
        account(1_000_000)
    );
    let mut m = HashMap::new();
    m.insert("simulateTransaction".to_string(), sim);
    m.insert("getMultipleAccounts".to_string(), accounts);
    serve(m)
}

fn core_at(endpoint: &str) -> GraphiteCore {
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    }));
    core
}

fn transfer(declares_v0: bool) -> VerificationInput {
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
        uses_versioned_transaction: declares_v0,
        lookup_table_count: if declares_v0 { 1 } else { 0 },
        real_account_metas: vec![],
        state_diff: None,
    }
}

/// THE case. The request says this is not a versioned transaction; the simulator
/// says two accounts came in through lookup tables. Graphite must report what it
/// measured, not what it was told.
#[tokio::test]
async fn a_caller_denying_alt_use_is_contradicted_by_the_simulator() {
    let endpoint = rpc_reporting(&format!(
        r#"{{"writable":["{HIDDEN_WRITABLE}"],"readonly":["{HIDDEN_READONLY}"]}}"#
    ));
    let result = core_at(&endpoint)
        .verify_async(&transfer(false))
        .await
        .expect("verification must run");

    assert!(
        result.summary.contains("uses_versioned_transaction=false"),
        "the simulator resolved accounts through lookup tables while the request declared \
         it was not a versioned transaction, and nothing said so: {}",
        result.summary
    );
}

/// The consequence that matters more than the flag: those accounts are not in
/// the list any layer looked at, so the report has to name them.
///
/// "Accounts resolved via ALT are not independently verified" was true and
/// useless — it told an operator a category was unverified without telling them
/// what was in it.
#[tokio::test]
async fn alt_resolved_accounts_missing_from_the_examined_list_are_named() {
    let endpoint = rpc_reporting(&format!(
        r#"{{"writable":["{HIDDEN_WRITABLE}"],"readonly":["{HIDDEN_READONLY}"]}}"#
    ));
    let result = core_at(&endpoint)
        .verify_async(&transfer(true))
        .await
        .expect("verification must run");

    assert!(
        result.summary.contains(HIDDEN_WRITABLE) && result.summary.contains(HIDDEN_READONLY),
        "the ALT-resolved accounts the pipeline never examined are not named in the report: {}",
        result.summary
    );
    assert!(
        result
            .summary
            .contains("2 ALT-resolved account(s) are absent"),
        "the count of unexamined accounts is missing: {}",
        result.summary
    );
}

/// Disclosure, not punishment. ALT usage is ordinary, `uses_versioned_transaction`
/// defaults to false, and a pipeline that blocked on this would reject every
/// integration that never set the field.
#[tokio::test]
async fn an_alt_observation_warns_and_does_not_block() {
    let endpoint = rpc_reporting(&format!(
        r#"{{"writable":["{HIDDEN_WRITABLE}"],"readonly":[]}}"#
    ));
    let with_alt = core_at(&endpoint)
        .verify_async(&transfer(false))
        .await
        .expect("verification must run");

    let endpoint_clean = rpc_reporting(r#"{"writable":[],"readonly":[]}"#);
    let without_alt = core_at(&endpoint_clean)
        .verify_async(&transfer(false))
        .await
        .expect("verification must run");

    assert_eq!(
        with_alt.approved, without_alt.approved,
        "an ALT observation changed the verdict; it is a disclosure, not a finding"
    );
    assert!(
        (with_alt.confidence - without_alt.confidence).abs() < 1e-9,
        "an ALT observation moved the confidence score: {:.4} vs {:.4}",
        with_alt.confidence,
        without_alt.confidence
    );
}

/// The positive half: when the simulator resolved nothing through a lookup
/// table, a declared v0 transaction gets told so.
///
/// An empty `loadedAddresses` does not prove the transaction was legacy — a v0
/// transaction referencing no table looks identical — so the wording claims only
/// what is true: nothing arrived through a table, so nothing went unexamined.
#[tokio::test]
async fn a_v0_transaction_with_no_loaded_addresses_is_reported_as_complete() {
    let endpoint = rpc_reporting(r#"{"writable":[],"readonly":[]}"#);
    let result = core_at(&endpoint)
        .verify_async(&transfer(true))
        .await
        .expect("verification must run");

    assert!(
        result
            .summary
            .contains("the account list examined here is complete"),
        "a v0 transaction that pulled in no ALT accounts should be told so rather than left \
         under a generic blind-spot warning: {}",
        result.summary
    );
}

/// No claim without evidence. With no RPC there is no `loadedAddresses`, so
/// Graphite must fall back to reporting the caller's declaration AS a
/// declaration — never asserting completeness it did not measure.
#[tokio::test]
async fn without_an_rpc_graphite_reports_the_declaration_and_claims_nothing() {
    let result = GraphiteCore::new()
        .verify_async(&transfer(true))
        .await
        .expect("verification must run");

    assert!(
        result
            .summary
            .contains("caller declares a versioned (v0) transaction"),
        "the declaration should be attributed to the caller: {}",
        result.summary
    );
    assert!(
        !result
            .summary
            .contains("the account list examined here is complete"),
        "Graphite claimed the account list was complete with no simulation to support it: {}",
        result.summary
    );
}
