//! Requires the `rpc` feature: the coverage number comes from a simulation.
#![cfg(feature = "rpc")]

//! The description must cover what the artifact actually does.
//!
//! Found 2026-09-08 attacking the artifact boundary, against the shipped
//! container on live devnet. A request describing a 0.002 SOL transfer to Bob,
//! carrying a signed artifact that sends 0.9 SOL to Mallory, came back:
//!
//! ```text
//! approved: true
//! scope:    artifact_bound, simulated: true
//! L4:       "State diff verified against the manifest: no undeclared effects"
//! ```
//!
//! The attacker's entire contribution was declaring a second instruction that
//! did not exist.
//!
//! `covers_all_writable` — the flag gating the lamport-conservation check, which
//! is the only thing binding an artifact's effects to the described account set
//! — was computed as `transaction_instructions.len() <= 1`. That field is
//! caller-supplied and nothing verifies its contents. One fictional entry turned
//! the check off, and with it the finding that had caught the same mismatch a
//! moment earlier.
//!
//! The repair is not a stricter rule about the field. It is to stop asking the
//! caller. `simulateTransaction` returns `preBalances`/`postBalances` over the
//! transaction's whole account list, so Graphite can count how many accounts the
//! artifact moved value on without parsing it and without believing anything the
//! request said. Coverage is now that measurement compared against the diff.
//!
//! Note what this does NOT require: no wire-format parser, no new dependency,
//! and no knowledge of the addresses involved. The count alone is enough,
//! because a description that covers fewer changed accounts than the artifact
//! produced is describing a different transaction.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{GraphiteCore, LayerStatus, ProposedIntent, VerificationInput};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

const SYSTEM: &str = "11111111111111111111111111111111";
const PAYER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const BOB: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

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

fn account(lamports: u64) -> String {
    format!(
        r#"{{"lamports":{lamports},"owner":"{SYSTEM}","executable":false,"rentEpoch":0,"data":["","base64"]}}"#
    )
}

/// A cluster whose simulation reports the artifact moving value on
/// `changed_accounts` accounts, while the two DESCRIBED accounts show only the
/// payer changing.
///
/// `changed_accounts == 2` is the honest case (payer + Bob). `3` is the attack:
/// the artifact also paid someone the request never named.
fn cluster(changed_accounts: usize) -> String {
    // Balance arrays span the transaction's whole account list: the payer, the
    // recipients, and the System Program itself. An honest two-account transfer
    // is therefore three entries, and each extra account the artifact touches
    // is one more — which is exactly what the account-universe check reads.
    let total = changed_accounts + 1;
    let pre: Vec<String> = (0..total).map(|_| "1000000000".to_string()).collect();
    let post: Vec<String> = (0..total)
        .map(|i| {
            if i < changed_accounts {
                "999000000".to_string()
            } else {
                "1000000000".to_string()
            }
        })
        .collect();
    let sim = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
            "err":null,"logs":[],"unitsConsumed":150,"fee":5000,
            "preBalances":[{}],"postBalances":[{}],
            "innerInstructions":[],"loadedAddresses":{{"writable":[],"readonly":[]}},
            "accounts":[{},{}],"returnData":null}}}}}}"#,
        pre.join(","),
        post.join(","),
        // Post-state of the two DESCRIBED accounts.
        //
        // The payer always moves. Bob moves only in the honest case — when the
        // artifact's changed set IS the described set. In the attack the
        // artifact paid someone else, so Bob's balance is untouched and the
        // request covers one of the artifact's two movements.
        // Payer: -1,005,000 (a 1,000,000 transfer plus the 5,000 fee).
        account(998_995_000),
        // Bob receives it in the honest case, so the covered deltas sum to
        // exactly -fee and lamport conservation holds. In the attack Bob is
        // untouched — the artifact paid an account the request never named —
        // and coverage, not conservation, is what has to catch it.
        if changed_accounts >= 3 {
            account(1_000_000)
        } else {
            account(2_000_000)
        },
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

fn request(declared_instructions: usize) -> VerificationInput {
    use graphite_core::tx_pattern_analysis::TransactionInstruction;
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send a little SOL to Bob".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![PAYER.to_string(), BOB.to_string()],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 5,
            battle_tested_tx_count: 50_000,
            simulation_match_count: 100,
        },
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: Some(vec![1, 2, 3, 4]),
        // The lever. Contents are never verified; only the count used to matter.
        transaction_instructions: (0..declared_instructions)
            .map(|_| TransactionInstruction {
                program_id: "ComputeBudget111111111111111111111111111111".to_string(),
                instruction_discriminator: "02".to_string(),
                account_addresses: vec![],
                cpi_targets: vec![],
            })
            .collect(),
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

async fn l4(endpoint: &str, declared: usize) -> (bool, LayerStatus, String) {
    let r = core_at(endpoint)
        .verify_async(&request(declared))
        .await
        .expect("verification must run");
    let layer = r
        .layers
        .iter()
        .find(|l| l.layer.contains("State"))
        .expect("L4 present")
        .clone();
    (r.approved, layer.status, layer.reason)
}

/// THE attack. The artifact moved value on three accounts; the request named
/// two, of which one moved. Declaring extra instructions must not change that.
#[tokio::test]
async fn an_artifact_touching_accounts_the_request_never_named_is_refused() {
    let endpoint = cluster(3);
    for declared in [0usize, 1, 2, 5] {
        let (approved, status, reason) = l4(&endpoint, declared).await;
        assert!(
            !approved,
            "with {declared} declared instruction(s) the request was approved while the \
             artifact moved value on an account it never named. reason={reason}"
        );
        assert!(
            matches!(status, LayerStatus::Failed),
            "L4 must fail, not merely warn: {status:?} {reason}"
        );
        assert!(
            reason.contains("ArtifactEffectsNotCovered"),
            "blocked, but not for the reason that matters: {reason}"
        );
    }
}

/// The anti-vacuity guard. If the coverage check blocked everything, the test
/// above would pass while the layer was useless. An artifact whose effects the
/// request does cover must still be approved — including when the caller
/// declares extra instructions, since the measurement is what decides now.
#[tokio::test]
async fn an_artifact_the_request_fully_covers_still_passes_l4() {
    let endpoint = cluster(2);
    for declared in [0usize, 1, 2, 5] {
        let (_approved, status, reason) = l4(&endpoint, declared).await;
        // Asserted on the LAYER, not on `approved`. The coverage rule governs
        // L4; final approval also depends on the confidence threshold, and on
        // an empty semantic graph a known protocol tops out at 0.44 against
        // Gaming's 0.55 (documented in SECURITY.md). Asserting `approved` here
        // would make this test pass or fail for reasons unrelated to coverage.
        assert!(
            matches!(status, LayerStatus::Passed),
            "an artifact whose effects the request covers failed L4 with {declared} declared              instruction(s) - the coverage rule is over-blocking: {status:?} {reason}"
        );
        assert!(
            !reason.contains("ArtifactEffectsNotCovered"),
            "full coverage was reported as incomplete: {reason}"
        );
    }
}

/// The property that actually closes the hole, stated on its own: the verdict
/// must not depend on `transaction_instructions`, because nothing verifies it.
///
/// This is the invariant rather than the exploit. A future change that reads
/// that field for anything security-relevant fails here even if it invents a
/// completely different bypass.
#[tokio::test]
async fn a_caller_declared_instruction_count_cannot_change_the_verdict() {
    for changed in [2usize, 3] {
        let endpoint = cluster(changed);
        let baseline = l4(&endpoint, 1).await;
        for declared in [0usize, 2, 3, 7, 20] {
            let other = l4(&endpoint, declared).await;
            assert_eq!(
                baseline.0, other.0,
                "declaring {declared} instructions instead of 1 changed `approved` \
                 ({} -> {}) for an artifact that moved {changed} account(s). \
                 transaction_instructions is caller-supplied and unverified; no security \
                 decision may turn on it.",
                baseline.0, other.0
            );
            assert_eq!(
                format!("{:?}", baseline.1),
                format!("{:?}", other.1),
                "declaring {declared} instructions changed L4's status for an artifact that \
                 moved {changed} account(s)"
            );
        }
    }
}

/// Coverage is only claimed when it was measured. With no artifact there is no
/// simulation to count, so Graphite must not assert complete coverage on the
/// strength of the caller having described one instruction.
#[tokio::test]
async fn no_artifact_means_no_coverage_claim() {
    let endpoint = cluster(2);
    let mut input = request(0);
    input.signed_transaction = None;
    let r = core_at(&endpoint)
        .verify_async(&input)
        .await
        .expect("verification must run");
    assert!(
        !r.scope.is_artifact_bound(),
        "no artifact was supplied but the verdict claims artifact binding"
    );
    let l4 = r
        .layers
        .iter()
        .find(|l| l.layer.contains("State"))
        .expect("L4 present");
    assert!(
        !l4.reason.contains("ArtifactEffectsNotCovered"),
        "there is no artifact to compare coverage against; the check must not fire: {}",
        l4.reason
    );
}

// ── Silent state mutation: no lamports move at all ──────────────────────────
//
// Balance deltas are a FLOOR on what a transaction did. An owner reassignment,
// a delegate grant, a close-authority change and a token freeze all move zero
// lamports, so a coverage measure built on balance movement cannot see any of
// them.
//
// Measured on live devnet 2026-09-08: a benign transfer, and the same transfer
// carrying a second instruction that hands an account to an attacker program,
// BOTH report exactly two lamport-moved accounts. The hostile one references
// four accounts where the benign one references three.
//
// Before the account-universe check, L4 answered "State diff verified against
// the manifest: 2 account(s) changed, no undeclared effects" on the hostile
// artifact. The transaction was blocked, but by L3's compute divergence — the
// statistical signal documented in SECURITY.md as a false-positive source, not
// a control reasoning about ownership. An attacker whose baseline already
// includes two-instruction traffic loses nothing by that block.

/// A cluster where the artifact touches `extra` accounts beyond the two the
/// request describes, and NONE of them move lamports.
fn cluster_silent(extra: usize) -> String {
    // Two accounts move value in every case — the payer and Bob — exactly as in
    // the benign transfer. Only the size of the account universe changes.
    let total = 3 + extra;
    let pre: Vec<String> = (0..total).map(|_| "1000000000".to_string()).collect();
    let post: Vec<String> = (0..total)
        .map(|i| match i {
            0 => "998995000".to_string(),
            1 => "1001000000".to_string(),
            _ => "1000000000".to_string(),
        })
        .collect();
    let sim = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
            "err":null,"logs":[],"unitsConsumed":150,"fee":5000,
            "preBalances":[{}],"postBalances":[{}],
            "innerInstructions":[],"loadedAddresses":{{"writable":[],"readonly":[]}},
            "accounts":[{},{}],"returnData":null}}}}}}"#,
        pre.join(","),
        post.join(","),
        account(998_995_000),
        account(2_000_000),
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

/// The exploit: a secondary instruction mutating an account the request never
/// names, moving no lamports, so every balance-based measure reads clean.
#[tokio::test]
async fn an_artifact_touching_an_undescribed_account_is_refused_even_with_no_value_moved() {
    let endpoint = cluster_silent(1);
    // `declared == 0` only. Declaring instructions ADDS their programs and
    // accounts to the described universe, which is what the padding limitation
    // below is about — see
    // `padding_the_described_universe_defeats_the_count_and_that_is_a_known_limit`.
    for declared in [0usize] {
        let (approved, status, reason) = l4(&endpoint, declared).await;
        assert!(
            !approved,
            "an artifact referencing an account the request never named was approved with \
             {declared} declared instruction(s). No lamports moved, so nothing balance-based \
             could see it: {reason}"
        );
        assert!(
            matches!(status, LayerStatus::Failed),
            "L4 must fail: {status:?} {reason}"
        );
        assert!(
            reason.contains("ArtifactAccountsNotDescribed"),
            "blocked, but not by the check that reasons about the artifact's account universe — \
             a block from some other layer is incidental and an attacker can engineer around \
             it: {reason}"
        );
    }
}

/// Anti-vacuity: an artifact whose account universe the request does cover must
/// still pass, or the check above is satisfied by blocking everything.
#[tokio::test]
async fn an_artifact_whose_accounts_are_all_described_still_passes_l4() {
    let endpoint = cluster_silent(0);
    let (_approved, status, reason) = l4(&endpoint, 0).await;
    assert!(
        matches!(status, LayerStatus::Passed),
        "an artifact whose accounts the request fully describes failed L4 — the universe check \
         is over-blocking: {status:?} {reason}"
    );
    assert!(
        !reason.contains("ArtifactAccountsNotDescribed"),
        "full account coverage was reported as incomplete: {reason}"
    );
}

/// The check scales with how much is hidden, and never reports fewer
/// unaccounted accounts than there are.
#[tokio::test]
async fn the_number_of_unaccounted_accounts_is_reported_accurately() {
    for extra in [1usize, 3, 7] {
        let endpoint = cluster_silent(extra);
        let (_, _, reason) = l4(&endpoint, 0).await;
        assert!(
            reason.contains(&format!("references {} account(s)", 3 + extra)),
            "the artifact's account count is misreported for extra={extra}: {reason}"
        );
        assert!(
            reason.contains(&format!("The {extra} unaccounted")),
            "the number of unexamined accounts is misreported for extra={extra}: {reason}"
        );
    }
}

/// The same question asked of a READABLE transaction, where identity is
/// available and a count is not the best answer available.
///
/// The counts agree here on purpose: the simulation reports three accounts and
/// the request describes three (the payer, Bob, and the System Program itself).
/// A count-based check passes. The message's static key list contains a fourth
/// account the request names nowhere, and the check has to see it — otherwise
/// "the numbers match" is doing the work that "these are the same accounts"
/// should be doing.
#[tokio::test]
async fn a_readable_artifact_names_the_account_the_request_left_out() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../fixtures/artifacts/undescribed_account.json"
    ))
    .expect("fixture must parse");
    let bytes: Vec<u8> = f["blob"]
        .as_array()
        .expect("blob")
        .iter()
        .map(|n| n.as_u64().expect("byte") as u8)
        .collect();
    let undescribed = f["accounts"]["undescribed"].as_str().expect("address");

    // Two changed accounts => three balance entries => a count that agrees with
    // the three the request describes.
    let endpoint = cluster(2);
    let mut input = request(0);
    input.signed_transaction = Some(bytes);
    let r = core_at(&endpoint)
        .verify_async(&input)
        .await
        .expect("verification must run");
    let layer = r
        .layers
        .iter()
        .find(|l| l.layer.contains("State"))
        .expect("L4 present")
        .clone();
    println!("{:?} — {}", layer.status, layer.reason);

    assert!(
        matches!(layer.status, LayerStatus::Failed),
        "the transaction reaches an account the request never named and the counts agree,          so only identity can catch it: {:?} {}",
        layer.status,
        layer.reason
    );
    assert!(
        layer.reason.contains("ArtifactAccountsNotDescribed"),
        "blocked by something else, which an attacker can engineer around: {}",
        layer.reason
    );
    assert!(
        layer.reason.contains(undescribed),
        "the finding must NAME the account, not count it: {}",
        layer.reason
    );
    assert!(!r.approved);
}

/// A limitation of the check above, demonstrated rather than described.
///
/// The account-universe comparison is a COUNT. An attacker who needs to hide
/// one account simply names one more — any address, or an instruction carrying
/// one — and the two numbers agree again. Counting cannot distinguish "the four
/// accounts you described" from "four accounts, one of which is not the one in
/// the transaction", because nothing in a simulation response reveals the
/// artifact's account IDENTITIES. `preBalances` is a list of numbers in the
/// transaction's key order; the keys are in the wire format, which Graphite
/// does not parse.
///
/// So this test asserts the gap is still there. It exists so nobody later reads
/// `ArtifactAccountsNotDescribed` as a proof of correspondence when it is a
/// floor — and so that closing it (by parsing the artifact) has a failing test
/// waiting to confirm the closure.
///
/// What the check still buys: an attacker can no longer hide an account for
/// free. They have to make the request name an account the transaction does not
/// contain, which is a concrete, auditable lie recorded on the P9 trail rather
/// than an omission.
#[tokio::test]
async fn padding_the_described_universe_defeats_the_count_and_that_is_a_known_limit() {
    // Still true, and now ONLY for an artifact that cannot be parsed — which is
    // what this fixture's four filler bytes are. When the message can be read,
    // `a_readable_artifact_names_the_account_the_request_left_out` above shows
    // the identity check catching exactly this with the counts in agreement.
    let endpoint = cluster_silent(1);
    // One declared instruction contributes its program id to the described
    // universe, restoring the count the hidden account broke.
    let (_approved, status, reason) = l4(&endpoint, 1).await;
    assert!(
        matches!(status, LayerStatus::Passed),
        "padding no longer defeats the count. If the artifact's account identities are now          established — by parsing the transaction, most likely — then this limitation is          closed, `ArtifactAccountsNotDescribed` means more than it did, and both this test and          the `unobserved` entry claiming the gap should be rewritten: {status:?} {reason}"
    );
}
