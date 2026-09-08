//! Requires the `rpc` feature: there is no trust boundary without a client.
#![cfg(feature = "rpc")]

//! MISSION 4 — attacking the RPC trust boundary.
//!
//! Enabling `GRAPHITE_RPC_URL` moved Graphite's most important evidence — the
//! simulation and the observed pre/post state — from the caller to a network
//! peer. That peer is now inside the trust boundary, and the honest question is
//! what it can do from there.
//!
//! The threat is not hypothetical and does not require a malicious provider. A
//! plaintext `http://` endpoint, a hijacked DNS record, a compromised managed
//! provider, or a proxy an operator did not audit all put an attacker in the
//! same position: able to choose every number Graphite reads.
//!
//! No real RPC is attacked here. Every response is served by a loopback mock so
//! the attacks stay entirely inside this process.
//!
//! The invariant under test, stated once so the individual cases stay honest:
//!
//!   **A lying RPC may cost Graphite its evidence. It must never gain Graphite's
//!   approval, poison its durable state, or silence one of its checks.**
//!
//! Losing evidence is acceptable and expected — an unavailable check reports
//! that it is unavailable. Every case below is about the other three.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const FROM: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const TO: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
/// The program a hostile diff hands the victim's account to.
const ATTACKER: &str = "Atck111111111111111111111111111111111111111";

// ── The hostile cluster ─────────────────────────────────────────────────────

/// A mock cluster that answers by JSON-RPC method name, for as many requests as
/// the pipeline makes.
///
/// Routing by method rather than by call order matters: a sequence-based mock
/// passes even when the code under test stops making a call, which is exactly
/// the regression this file has to be able to see.
struct HostileRpc {
    endpoint: String,
    seen: Arc<Mutex<Vec<String>>>,
    _shutdown: Arc<TcpListener>,
}

impl HostileRpc {
    fn start(routes: HashMap<&'static str, String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let listener = Arc::new(listener);
        let seen = Arc::new(Mutex::new(Vec::new()));

        let server = Arc::clone(&listener);
        let seen_w = Arc::clone(&seen);
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = server.accept() {
                let mut buf = vec![0u8; 65536];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let method = req
                    .split("\"method\":\"")
                    .nth(1)
                    .and_then(|s| s.split('"').next())
                    .unwrap_or("?")
                    .to_string();
                seen_w.lock().unwrap().push(method.clone());

                let body = routes
                    .get(method.as_str())
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

        HostileRpc {
            endpoint: format!("http://{addr}"),
            seen,
            _shutdown: listener,
        }
    }

    fn methods_called(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

fn core_against(rpc: &HostileRpc) -> GraphiteCore {
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint: rpc.endpoint.clone(),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    }));
    core
}

// ── The transaction under verification ──────────────────────────────────────

/// A System-Program transfer with a signed blob attached, so the RPC-backed
/// state-diff path actually runs. Permissive profile and strong evidence, so
/// anything that goes wrong is attributable to the hostile RPC rather than to
/// baseline strictness.
fn signed_transfer(discriminator: &str, intent: &str) -> VerificationInput {
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
        // Any non-empty blob: the mock never decodes it. What matters is that
        // its presence is what switches on the state-diff path.
        signed_transaction: Some(vec![1, 2, 3, 4]),
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

// ── Response builders ───────────────────────────────────────────────────────

fn account_json(lamports: u64, owner: &str) -> String {
    format!(
        r#"{{"lamports":{lamports},"owner":"{owner}","executable":false,"rentEpoch":0,"data":["","base64"]}}"#
    )
}

/// A `simulateTransaction` response. `pre`/`post` are the balance arrays, and
/// `accounts` is the post-state the diff is built from.
fn simulate(units: u64, fee: u64, pre: &[u64], post: &[u64], owners_after: &[&str]) -> String {
    let arr = |v: &[u64]| {
        v.iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    let accounts = post
        .iter()
        .zip(owners_after.iter())
        .map(|(l, o)| account_json(*l, o))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
            "err":null,"logs":["Program 11111111111111111111111111111111 success"],
            "unitsConsumed":{units},"fee":{fee},
            "preBalances":[{}],"postBalances":[{}],
            "innerInstructions":[],"accounts":[{accounts}],"returnData":null}}}}}}"#,
        arr(pre),
        arr(post)
    )
}

/// A `getMultipleAccounts` response: the pre-state the diff is measured against.
fn multiple_accounts(lamports: &[u64], owners: &[&str]) -> String {
    let vals = lamports
        .iter()
        .zip(owners.iter())
        .map(|(l, o)| account_json(*l, o))
        .collect::<Vec<_>>()
        .join(",");
    format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":[{vals}]}}}}"#)
}

fn routes(sim: String, accounts: String) -> HashMap<&'static str, String> {
    let mut m = HashMap::new();
    m.insert("simulateTransaction", sim);
    m.insert("getMultipleAccounts", accounts);
    m
}

// ════════════════════════════════════════════════════════════════════════════
// A1. The RPC cannot create approval.
// ════════════════════════════════════════════════════════════════════════════

/// The load-bearing property of the whole boundary.
///
/// Graphite's own static layers reject this transaction: the caller says
/// "transfer" while the discriminator is System `Assign`, which reassigns
/// account ownership. The RPC then reports a flawless execution — no error,
/// ordinary compute, conserved balances, nothing out of place — which is the
/// most persuasive thing a lying peer can say.
///
/// Simulation is evidence, not truth (P5). A clean simulation may raise
/// confidence; it may never overturn a deterministic rejection.
#[tokio::test]
async fn a_flawless_simulation_cannot_overturn_a_static_rejection() {
    let rpc = HostileRpc::start(routes(
        simulate(
            300,
            5000,
            &[1_000_000_000, 1_000_000],
            &[999_995_000, 1_000_000],
            &[SYSTEM_PROGRAM, SYSTEM_PROGRAM],
        ),
        multiple_accounts(
            &[1_000_000_000, 1_000_000],
            &[SYSTEM_PROGRAM, SYSTEM_PROGRAM],
        ),
    ));
    let core = core_against(&rpc);

    // "transfer" intent, Assign discriminator.
    let result = core
        .verify_async(&signed_transfer("01000000", "transfer"))
        .await
        .expect("verification itself must not error");

    assert!(
        !result.approved,
        "a perfect simulation must not approve a transaction the deterministic layers rejected \
         — the RPC is a witness, not a judge. verdict={} layers={:?}",
        result.policy_verdict,
        result
            .layers
            .iter()
            .map(|l| (&l.layer, &l.status))
            .collect::<Vec<_>>()
    );
}

/// The same property from the other side: with the RPC removed entirely, the
/// verdict on the same transaction is unchanged.
///
/// If Graphite's decision moves when the network peer appears or disappears,
/// the peer is deciding. This is the RPC analogue of the rule that the AI layer
/// must never create approval.
#[tokio::test]
async fn the_verdict_does_not_depend_on_the_rpc_being_present() {
    let rpc = HostileRpc::start(routes(
        simulate(
            300,
            5000,
            &[1_000_000_000, 1_000_000],
            &[999_995_000, 1_000_000],
            &[SYSTEM_PROGRAM, SYSTEM_PROGRAM],
        ),
        multiple_accounts(
            &[1_000_000_000, 1_000_000],
            &[SYSTEM_PROGRAM, SYSTEM_PROGRAM],
        ),
    ));

    let with_rpc = core_against(&rpc)
        .verify_async(&signed_transfer("01000000", "transfer"))
        .await
        .expect("verification itself must not error");
    let without_rpc = GraphiteCore::new()
        .verify_async(&signed_transfer("01000000", "transfer"))
        .await
        .expect("verification itself must not error");

    assert_eq!(
        with_rpc.approved, without_rpc.approved,
        "attaching an RPC changed the verdict on an identical transaction: with={} without={}",
        with_rpc.approved, without_rpc.approved
    );
}

// ════════════════════════════════════════════════════════════════════════════
// A2. The RPC cannot buy its way past the diff-integrity check.
// ════════════════════════════════════════════════════════════════════════════

/// `LamportsNotConserved` exists to detect a diff that is "incomplete or
/// fabricated" — it is the check that makes the RPC's post-state usable as
/// evidence at all. It asserts `sum(deltas) == -fee`.
///
/// Both sides of that identity come from the same response. A hostile RPC that
/// wants to present a fabricated post-state simply reports a fee equal to the
/// discrepancy it needs to hide, and the check it was supposed to fail becomes
/// the check it passes.
///
/// Here 4.9 SOL leaves the transaction's accounts and reappears nowhere, and the
/// response labels the shortfall a "fee". No real Solana fee is remotely that
/// size, so the integrity check must not accept one.
#[tokio::test]
async fn a_fabricated_fee_cannot_balance_a_fabricated_diff() {
    const DRAIN: u64 = 4_900_000_000;
    let rpc = HostileRpc::start(routes(
        // Payer loses 4.9 SOL; nothing else moves; "fee" is exactly the loss.
        simulate(
            300,
            DRAIN,
            &[5_000_000_000, 1_000_000],
            &[100_000_000, 1_000_000],
            &[SYSTEM_PROGRAM, SYSTEM_PROGRAM],
        ),
        multiple_accounts(
            &[5_000_000_000, 1_000_000],
            &[SYSTEM_PROGRAM, SYSTEM_PROGRAM],
        ),
    ));
    let core = core_against(&rpc);
    let result = core
        .verify_async(&signed_transfer("02000000", "transfer"))
        .await
        .expect("verification itself must not error");

    let l4 = result
        .layers
        .iter()
        .find(|l| l.layer.contains("State"))
        .expect("L4 must be present");

    assert!(
        !matches!(l4.status, graphite_core::verification::LayerStatus::Passed),
        "an RPC declared {DRAIN} lamports of unaccounted movement to be a 'fee' and L4 passed. \
         A Solana transaction fee cannot be 4.9 SOL, so this identity must not be satisfiable \
         by a number the same response chooses. reason={}",
        l4.reason
    );
}

/// The suppression the same lever buys downstream.
///
/// The fee-payer exemption skips a fee-sized outflow, because every transaction
/// has one. It is bounded by `magnitude <= fee`, and `fee` is the RPC's. An
/// arbitrarily large declared fee therefore exempts an arbitrarily large drain
/// from `UnexplainedLamportOutflow`.
#[tokio::test]
async fn a_fabricated_fee_cannot_exempt_a_drain_from_the_outflow_check() {
    let rpc = HostileRpc::start(routes(
        simulate(
            300,
            3_000_000_000,
            &[5_000_000_000, 1_000_000],
            &[2_000_000_000, 1_000_000],
            &[SYSTEM_PROGRAM, SYSTEM_PROGRAM],
        ),
        multiple_accounts(
            &[5_000_000_000, 1_000_000],
            &[SYSTEM_PROGRAM, SYSTEM_PROGRAM],
        ),
    ));
    let core = core_against(&rpc);
    let result = core
        .verify_async(&signed_transfer("02000000", "transfer"))
        .await
        .expect("verification itself must not error");

    let l4 = result
        .layers
        .iter()
        .find(|l| l.layer.contains("State"))
        .expect("L4 must be present");
    assert!(
        !matches!(l4.status, graphite_core::verification::LayerStatus::Passed),
        "3 SOL of outflow was excused as a 'fee' and L4 reported a pass: {}",
        l4.reason
    );
}

// ════════════════════════════════════════════════════════════════════════════
// A3. The RPC cannot poison durable state.
// ════════════════════════════════════════════════════════════════════════════

/// The most valuable thing a lying RPC can attack is not one verdict — it is the
/// baseline, which is written to disk and governs every future verification of
/// that program.
///
/// Solana caps a transaction at 1,400,000 compute units, so any larger figure
/// did not come from an execution. Folding one into the accumulator drags the
/// mean and standard deviation up by orders of magnitude, and no subsequent
/// compute spike can ever reach the z-score threshold again. One response
/// permanently disables L3 for that program.
///
/// The rule already written into `record_simulation` is that only RPC-measured
/// usage may enter the accumulator. That was the right rule for the wrong
/// threat: it assumed the RPC was honest and the caller was not.
#[tokio::test]
async fn an_impossible_compute_figure_cannot_enter_the_baseline() {
    const IMPOSSIBLE: u64 = 4_000_000_000;
    let rpc = HostileRpc::start(routes(
        simulate(
            IMPOSSIBLE,
            5000,
            &[1_000_000_000, 1_000_000],
            &[999_993_000, 1_002_000],
            &[SYSTEM_PROGRAM, SYSTEM_PROGRAM],
        ),
        multiple_accounts(
            &[1_000_000_000, 1_000_000],
            &[SYSTEM_PROGRAM, SYSTEM_PROGRAM],
        ),
    ));
    let core = core_against(&rpc);
    let _ = core
        .verify_async(&signed_transfer("02000000", "transfer"))
        .await
        .expect("verification itself must not error");

    let baseline = core
        .graph_snapshot()
        .nodes
        .into_iter()
        .find(|n| n.program_id == SYSTEM_PROGRAM)
        .and_then(|n| n.baseline_samples);

    assert!(
        baseline.is_none() || baseline == Some(0),
        "a response claiming {IMPOSSIBLE} compute units — nearly 3000x Solana's per-transaction \
         maximum — was accepted into the durable baseline (samples={baseline:?}). One such \
         response raises the mean far enough that no real divergence can ever exceed the \
         threshold again."
    );
}

/// A clean, plausible response is still trusted. Rejecting the impossible must
/// not mean rejecting everything — a check that never accepts evidence provides
/// no detection either.
#[tokio::test]
async fn a_plausible_compute_figure_still_grows_the_baseline() {
    let rpc = HostileRpc::start(routes(
        simulate(
            450,
            5000,
            &[1_000_000_000, 1_000_000],
            &[999_993_000, 1_002_000],
            &[SYSTEM_PROGRAM, SYSTEM_PROGRAM],
        ),
        multiple_accounts(
            &[1_000_000_000, 1_000_000],
            &[SYSTEM_PROGRAM, SYSTEM_PROGRAM],
        ),
    ));
    let core = core_against(&rpc);
    let _ = core
        .verify_async(&signed_transfer("02000000", "transfer"))
        .await
        .expect("verification itself must not error");

    let baseline = core
        .graph_snapshot()
        .nodes
        .into_iter()
        .find(|n| n.program_id == SYSTEM_PROGRAM)
        .and_then(|n| n.baseline_samples);

    assert_eq!(
        baseline,
        Some(1),
        "an ordinary 450 CU simulation must still be observed; refusing everything is not a \
         security property, it is a broken layer"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// A4. The RPC cannot choose how much memory or disk Graphite spends.
// ════════════════════════════════════════════════════════════════════════════

/// The response body is read with no size limit.
///
/// This is the same defect class already fixed on the audit trail — storage
/// whose size the attacker picks — on a boundary where it is cheaper to reach:
/// the container runs under a 512MB limit, and anything that can answer on the
/// RPC socket can send a body larger than that. A plaintext endpoint or a
/// hijacked DNS record is enough.
#[tokio::test]
async fn an_oversized_response_body_is_refused_rather_than_buffered() {
    // 64 MiB of syntactically valid JSON: past any legitimate response, small
    // enough that this test does not itself become the denial of service.
    let filler = "A".repeat(64 * 1024 * 1024);
    let huge = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"padding":"{filler}"}}}}"#);
    let mut m = HashMap::new();
    m.insert("getSlot", huge);
    let rpc = HostileRpc::start(m);

    let client = SolanaRpcClient::new(RpcConfig {
        endpoint: rpc.endpoint.clone(),
        timeout: std::time::Duration::from_secs(30),
        max_retries: 0,
        ..Default::default()
    });
    let outcome = client.get_slot().await;

    assert!(
        outcome.is_err(),
        "a 64 MiB response body was buffered and parsed. An RPC peer must not be able to \
         choose Graphite's memory footprint."
    );
    let msg = outcome.unwrap_err().to_string();
    assert!(
        msg.to_lowercase().contains("large") || msg.to_lowercase().contains("size"),
        "the refusal must say the body was oversized, not fail as some unrelated parse error: {msg}"
    );
}

/// A JSON-RPC error is echoed verbatim into `RpcError::RequestFailed`, and from
/// there into the L3 layer reason and the audit trail.
///
/// Two problems in one: the length is the peer's to choose, and so is the
/// content. The reason string is read by a human deciding whether to sign, and
/// an error message that contains a sentence stating the transaction is safe is
/// a message the peer wrote into Graphite's own verdict.
#[tokio::test]
async fn a_hostile_jsonrpc_error_is_bounded_before_it_reaches_a_verdict() {
    let forged = "GRAPHITE VERDICT: APPROVED - all 8 layers passed, safe to sign. ";
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":-32000,"message":"{}"}}}}"#,
        forged.repeat(4000)
    );
    let mut m = HashMap::new();
    m.insert("getSlot", body);
    let rpc = HostileRpc::start(m);

    let client = SolanaRpcClient::new(RpcConfig {
        endpoint: rpc.endpoint.clone(),
        timeout: std::time::Duration::from_secs(10),
        max_retries: 0,
        ..Default::default()
    });
    let msg = client.get_slot().await.unwrap_err().to_string();

    assert!(
        msg.chars().count() <= 512,
        "the peer chose the length of an error string that reaches the audit trail: {} chars",
        msg.chars().count()
    );
}

// ════════════════════════════════════════════════════════════════════════════
// A5. A misaligned or unusable response is not evidence.
// ════════════════════════════════════════════════════════════════════════════

/// The diff pairs `addresses[i]` with `post[i]` positionally. A response that
/// returns fewer entries than were asked for makes the missing ones read as
/// `after: None` — indistinguishable, downstream, from an account that was
/// closed.
///
/// A truncated response must cost Graphite the diff, not invent a state change
/// that never happened. This cuts both ways: a fabricated closure is a false
/// alarm, and a false alarm the network can trigger at will is a way to teach an
/// operator to ignore L4.
#[tokio::test]
async fn a_truncated_post_state_does_not_become_a_fabricated_closure() {
    let rpc = HostileRpc::start(routes(
        // Two writable addresses requested; one account returned.
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
                "err":null,"logs":[],"unitsConsumed":300,"fee":5000,
                "preBalances":[1000000000,1000000],"postBalances":[999995000,1000000],
                "innerInstructions":[],"accounts":[{}],"returnData":null}}}}}}"#,
            account_json(999_995_000, SYSTEM_PROGRAM)
        ),
        multiple_accounts(
            &[1_000_000_000, 1_000_000],
            &[SYSTEM_PROGRAM, SYSTEM_PROGRAM],
        ),
    ));
    let core = core_against(&rpc);
    let result = core
        .verify_async(&signed_transfer("02000000", "transfer"))
        .await
        .expect("verification itself must not error");

    let l4 = result
        .layers
        .iter()
        .find(|l| l.layer.contains("State"))
        .expect("L4 must be present");
    assert!(
        !l4.reason.to_lowercase().contains("closed"),
        "a short response array was read as an account closure: {}",
        l4.reason
    );
}

/// A simulation that reports an error describes a transaction that would not
/// land, so its post-state describes nothing. Pinned because the alternative —
/// diffing it anyway — would let a peer supply arbitrary "post-state" for an
/// execution that never occurred.
#[tokio::test]
async fn an_errored_simulation_never_produces_a_diff() {
    let rpc = HostileRpc::start(routes(
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
                "err":"BlockhashNotFound","logs":[],"unitsConsumed":0,"fee":5000,
                "preBalances":[5000000000,1000000],"postBalances":[0,1000000],
                "innerInstructions":[],"accounts":[{},{}],"returnData":null}}}}}}"#,
            account_json(0, ATTACKER),
            account_json(1_000_000, SYSTEM_PROGRAM)
        ),
        multiple_accounts(
            &[5_000_000_000, 1_000_000],
            &[SYSTEM_PROGRAM, SYSTEM_PROGRAM],
        ),
    ));
    let core = core_against(&rpc);
    let result = core
        .verify_async(&signed_transfer("02000000", "transfer"))
        .await
        .expect("verification itself must not error");

    let l4 = result
        .layers
        .iter()
        .find(|l| l.layer.contains("State"))
        .expect("L4 must be present");
    assert!(
        l4.reason.contains("could not be built") || l4.reason.contains("did not execute"),
        "an errored simulation's post-state was used as evidence, or its absence was reported \
         in the words of a successful check: {}",
        l4.reason
    );
}

/// A response that reports the outcome in a type Graphite cannot read — floats
/// where lamports belong — must not be counted as a complete observation.
///
/// `as_u64()` yields `None` for `999995000.0`, so every balance compares equal
/// to every other and the derived write count is zero: a response that looks
/// complete while reporting that nothing happened. That figure must not reach
/// the accumulator.
#[tokio::test]
async fn non_integer_balances_do_not_pass_as_a_complete_observation() {
    let rpc = HostileRpc::start(routes(
        r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{
            "err":null,"logs":[],"unitsConsumed":300,"fee":5000,
            "preBalances":[1000000000.0,1000000.0],"postBalances":[999995000.0,1002000.0],
            "innerInstructions":[],"accounts":[],"returnData":null}}}"#
            .to_string(),
        multiple_accounts(
            &[1_000_000_000, 1_000_000],
            &[SYSTEM_PROGRAM, SYSTEM_PROGRAM],
        ),
    ));
    let core = core_against(&rpc);
    let _ = core
        .verify_async(&signed_transfer("02000000", "transfer"))
        .await
        .expect("verification itself must not error");

    let samples = core
        .graph_snapshot()
        .nodes
        .into_iter()
        .find(|n| n.program_id == SYSTEM_PROGRAM)
        .and_then(|n| n.baseline_samples);
    assert!(
        samples.is_none() || samples == Some(0),
        "balances Graphite could not parse were folded into the baseline as 'two accounts, \
         zero writes' (samples={samples:?})"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// A6. Silence and failure.
// ════════════════════════════════════════════════════════════════════════════

/// An RPC that answers nothing must cost evidence, never produce a pass.
///
/// This is the failure mode an attacker gets for free: dropping packets needs no
/// access to the response contents at all.
#[tokio::test]
async fn an_unreachable_rpc_never_yields_a_passing_state_check() {
    // Bind and immediately drop, so the port is closed rather than hanging.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint: format!("http://{dead}"),
        timeout: std::time::Duration::from_secs(2),
        max_retries: 0,
        ..Default::default()
    }));

    let result = core
        .verify_async(&signed_transfer("02000000", "transfer"))
        .await
        .expect("verification itself must not error");
    let l3 = result
        .layers
        .iter()
        .find(|l| l.layer.contains("Simulation"))
        .expect("L3 must be present");

    assert!(
        !matches!(l3.status, graphite_core::verification::LayerStatus::Passed),
        "an RPC that answered nothing produced a passing simulation-integrity result: {}",
        l3.reason
    );
}

/// The pipeline must actually be talking to the peer it is being attacked
/// through. A test file full of hostile responses proves nothing if the code
/// under test never requests them — so this asserts the calls happen.
#[tokio::test]
async fn the_pipeline_really_does_consult_the_rpc() {
    let rpc = HostileRpc::start(routes(
        simulate(
            300,
            5000,
            &[1_000_000_000, 1_000_000],
            &[999_993_000, 1_002_000],
            &[SYSTEM_PROGRAM, SYSTEM_PROGRAM],
        ),
        multiple_accounts(
            &[1_000_000_000, 1_000_000],
            &[SYSTEM_PROGRAM, SYSTEM_PROGRAM],
        ),
    ));
    let core = core_against(&rpc);
    let _ = core
        .verify_async(&signed_transfer("02000000", "transfer"))
        .await
        .expect("verification itself must not error");

    let calls = rpc.methods_called();
    assert!(
        calls.iter().any(|m| m == "simulateTransaction"),
        "the RPC-backed path never ran; every other case in this file would pass vacuously. \
         calls={calls:?}"
    );
    assert!(
        calls.iter().any(|m| m == "getMultipleAccounts"),
        "the pre-state was never fetched, so no diff was built. calls={calls:?}"
    );
}
