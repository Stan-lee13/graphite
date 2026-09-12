//! Requires the `rpc` feature: the question is whether `approved` is reachable.
#![cfg(feature = "rpc")]

//! Round 9: an artifact-bound verdict whose L2 never looked at the artifact.
//!
//! `instruction_data` is optional on `/verify`. The artifact correspondence
//! check in L2 — "the described instruction is IN these bytes, positionally,
//! and every sibling is declared" — was keyed on it: with no data (or fewer
//! than 8 bytes of it) the check was skipped, while `scope` still reported
//! `artifact_bound` and its prose still said L2 had established the
//! correspondence. Every consumer that gates on `artifact_bound` — the SAK
//! bridge's `signSubmitAndConfirm`, the SDK's `isArtifactBound` — would have
//! treated that verdict as one about the bytes.
//!
//! The artifacts here were serialized by `@solana/web3.js` (the SAK bridge
//! corpus). The description names the corpus's payer and destination; the
//! artifact is the corpus's `legacy_other_destination` — the same transfer to
//! an account the request never mentions.
//!
//! What was reachable before the fix, and what is now: `approved` on that
//! request was blocked by L4's account-universe check (the destination the
//! artifact pays is not in the described set), so the verdict was not an
//! approval — but L2 reported `Passed` on bytes it had not compared, and the
//! scope claimed a binding L2 had not made. That contradiction is the finding.
//! The fix makes an artifact without identifying instruction data an L2
//! failure, and an unparseable artifact an L2 failure, so `artifact_bound`
//! means what its prose says in every verdict.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, UnobservedCode, VerificationInput,
    VerificationResult, VerificationScope,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

const SYSTEM: &str = "11111111111111111111111111111111";

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

fn account(lamports: u64) -> String {
    format!(
        r#"{{"lamports":{lamports},"owner":"{SYSTEM}","executable":false,"rentEpoch":0,"data":["","base64"]}}"#
    )
}

/// A cluster that answers every account read and every simulation with a
/// plausible, successful, three-account transfer: the payer pays, the second
/// account receives, the program is untouched. It reads the request so the
/// entry counts line up with whatever was asked.
fn cluster() -> String {
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").unwrap());
    let addr = listener.local_addr().unwrap();
    let server = Arc::clone(&listener);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = server.accept() {
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let body_json: serde_json::Value = req
                .split("\r\n\r\n")
                .nth(1)
                .and_then(|b| serde_json::from_str(b).ok())
                .unwrap_or(serde_json::Value::Null);
            let method = body_json["method"].as_str().unwrap_or("?").to_string();
            let body = match method.as_str() {
                "getMultipleAccounts" => {
                    let count = body_json["params"][0]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let vals: Vec<String> = (0..count)
                        .map(|i| account(if i == 0 { 1_000_000_000 } else { 1_000_000 }))
                        .collect();
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":[{}]}}}}"#,
                        vals.join(",")
                    )
                }
                "simulateTransaction" => {
                    let count = body_json["params"][1]["accounts"]["addresses"]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let post: Vec<String> = (0..count)
                        .map(|i| account(if i == 0 { 998_995_000 } else { 2_000_000 }))
                        .collect();
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
                            "err":null,"logs":[],"unitsConsumed":150,"fee":5000,
                            "preBalances":[1000000000,1000000,1],"postBalances":[998995000,2000000,1],
                            "innerInstructions":[],"loadedAddresses":{{"writable":[],"readonly":[]}},
                            "accounts":[{}],"returnData":null}}}}}}"#,
                        post.join(",")
                    )
                }
                _ => r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
            };
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

/// Describes the corpus's own transfer: payer -> `8u8L…`, 2,000,000 lamports.
fn describe(artifact: Vec<u8>, data: Option<Vec<u8>>) -> VerificationInput {
    let honest = corpus_entry("legacy_single_transfer");
    let keys = strings(&honest["static_keys"]);
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send 0.002 SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![keys[0].clone(), keys[1].clone()],
        instruction_data: data,
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
        signed_transaction: Some(artifact),
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

fn transfer_data() -> Vec<u8> {
    let mut d = vec![2, 0, 0, 0];
    d.extend_from_slice(&2_000_000u64.to_le_bytes());
    d
}

fn l2(r: &VerificationResult) -> (LayerStatus, String) {
    r.layers
        .iter()
        .find(|l| l.layer == "L2_InstructionVerification")
        .map(|l| (l.status, l.reason.clone()))
        .expect("L2 must always be reported")
}

fn codes(r: &VerificationResult) -> Vec<UnobservedCode> {
    match &r.scope {
        VerificationScope::ArtifactBound {
            unobserved_codes, ..
        } => unobserved_codes.clone(),
        VerificationScope::Descriptive {
            unobserved_codes, ..
        } => unobserved_codes.clone(),
    }
}

/// The honest request, with the data: the control. Everything about it lines
/// up, and it is approved through the mock cluster — which is what makes the
/// cases below meaningful.
#[tokio::test]
async fn the_honest_request_with_data_is_approved_and_bound() {
    let core = core_at(&cluster());
    let honest = corpus_entry("legacy_single_transfer");
    // The simulation-match signal grows with RPC-verified observations; a
    // fresh core sits just under the Gaming threshold on its first call, so
    // the baseline is earned first, exactly as a deployed core would.
    for _ in 0..3 {
        let _ = core
            .verify_async(&describe(bytes(&honest["raw"]), Some(transfer_data())))
            .await;
    }
    let r = core
        .verify_async(&describe(bytes(&honest["raw"]), Some(transfer_data())))
        .await
        .expect("verification must run");
    let (status, reason) = l2(&r);
    assert_eq!(status, LayerStatus::Passed, "{reason}");
    assert!(r.scope.is_artifact_bound());
    assert!(
        r.approved,
        "control: the honest request must be approvable: {}",
        r.summary
    );
    let c = codes(&r);
    assert!(
        c.iter().all(|c| c.inherent()),
        "an honest, simulated, diffed artifact carries only the inherent residuals: {c:?}"
    );
}

/// The same request with `instruction_data` omitted. L2 used to report
/// `Passed` — the artifact check was keyed on the data and simply did not
/// run — while the scope said `artifact_bound`. Now the missing data IS the
/// L2 failure: an instruction that cannot be identified in the bytes has not
/// been found in them.
#[tokio::test]
async fn an_artifact_without_identifying_data_fails_l2_instead_of_skipping_the_check() {
    let core = core_at(&cluster());
    let honest = corpus_entry("legacy_single_transfer");
    // Warm the baseline so that, were L2 to pass, the verdict WOULD be an
    // approval — the block below has to come from the hard gate.
    for _ in 0..3 {
        let _ = core
            .verify_async(&describe(bytes(&honest["raw"]), Some(transfer_data())))
            .await;
    }
    // No data: the instruction cannot be located. Four bytes (the
    // discriminator alone): a prefix is not the instruction, and nothing in
    // the message carries exactly those four bytes.
    for (data, expect) in [
        (None, "instruction_data was not"),
        (Some(vec![2u8, 0, 0, 0]), "no instruction matching"),
    ] {
        let r = core
            .verify_async(&describe(bytes(&honest["raw"]), data.clone()))
            .await
            .expect("verification must run");
        let (status, reason) = l2(&r);
        assert_eq!(
            status,
            LayerStatus::Failed,
            "data={data:?}: L2 must not pass on an artifact it did not compare: {reason}"
        );
        assert!(reason.contains(expect), "data={data:?}: {reason}");
        assert!(!r.approved, "{}", r.summary);
        assert!(
            codes(&r).contains(&UnobservedCode::InstructionNotLocated),
            "the scope says the instruction was not located: {:?}",
            codes(&r)
        );
    }
}

/// The attack the skipped check would have hidden: the description names the
/// corpus destination, the artifact pays a different one, and the request
/// omits the data. Before the fix: L2 Passed, scope artifact_bound. L4's
/// account-universe check still refused the approval — a second line that
/// held — but a verdict whose layers contradict its scope is not a verdict
/// anyone can rely on.
#[tokio::test]
async fn an_undescribed_destination_is_an_l2_failure_even_without_data() {
    let core = core_at(&cluster());
    let other = corpus_entry("legacy_other_destination");
    let r = core
        .verify_async(&describe(bytes(&other["raw"]), None))
        .await
        .expect("verification must run");
    let (status, _) = l2(&r);
    assert_eq!(status, LayerStatus::Failed);
    assert!(!r.approved);

    // And WITH the data, the positional check itself catches the swapped
    // destination: the described accounts are not the instruction's accounts.
    let r = core
        .verify_async(&describe(bytes(&other["raw"]), Some(transfer_data())))
        .await
        .expect("verification must run");
    let (status, reason) = l2(&r);
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(!r.approved);
}

/// Bytes that are not a Solana message at all. This used to fall back to
/// "do the described instruction's data bytes appear anywhere in the
/// artifact" and pass L2 when they did; it is now an L2 failure with the
/// parse error in the reason. The scope names both the failed parse and the
/// unlocated instruction.
#[tokio::test]
async fn an_unparseable_artifact_fails_l2() {
    let core = core_at(&cluster());
    // The described instruction's exact data, embedded in garbage: the old
    // substring fallback would have found it.
    let mut garbage = vec![0xde, 0xad, 0xbe, 0xef];
    garbage.extend_from_slice(&transfer_data());
    garbage.extend_from_slice(&[0xff; 16]);
    let r = core
        .verify_async(&describe(garbage, Some(transfer_data())))
        .await
        .expect("verification must run");
    let (status, reason) = l2(&r);
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(
        reason.contains("could not be parsed"),
        "the reason carries the parse failure: {reason}"
    );
    assert!(!r.approved);
    let c = codes(&r);
    assert!(c.contains(&UnobservedCode::ArtifactUnparsed), "{c:?}");
    assert!(
        c.contains(&UnobservedCode::AccountIdentityUnparsed),
        "{c:?}"
    );
    assert!(c.contains(&UnobservedCode::InstructionNotLocated), "{c:?}");
}

fn compact_u16(mut v: usize, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// A legacy transaction on the corpus's own keys — payer, destination,
/// System — carrying one transfer of `lamports`. Encoded field by field the
/// way the runtime reads it; `parse_transaction` accepts it.
fn transfer_of(lamports: u64) -> Vec<u8> {
    let honest = corpus_entry("legacy_single_transfer");
    let keys = strings(&honest["static_keys"]);
    let mut out = Vec::new();
    compact_u16(1, &mut out);
    out.extend_from_slice(&[0u8; 64]);
    out.extend_from_slice(&[1, 0, 1]);
    compact_u16(3, &mut out);
    for k in &keys {
        out.extend_from_slice(&bs58::decode(k).into_vec().unwrap());
    }
    out.extend_from_slice(&[9u8; 32]);
    compact_u16(1, &mut out);
    out.push(2);
    compact_u16(2, &mut out);
    out.extend_from_slice(&[0, 1]);
    let mut data = vec![2, 0, 0, 0];
    data.extend_from_slice(&lamports.to_le_bytes());
    compact_u16(data.len(), &mut out);
    out.extend_from_slice(&data);
    out
}

/// The headline reproduction. Before Round 9 this request came back
/// `approved: true, confidence 0.64, scope artifact_bound, L2 "Instruction
/// Transfer verified against manifest"` through the mock cluster: a
/// 100 SOL transfer, bound by SHA-256, under a description whose intent
/// said "send 0.002 SOL" and whose accounts matched — because with no
/// `instruction_data` nothing compared the amount, and L4 saw two described
/// accounts change, which is what a transfer does. The 2026-09-09 amount
/// finding, reopened by omitting one optional field.
#[tokio::test]
async fn a_hundred_sol_artifact_under_a_small_transfer_description_is_refused() {
    let core = core_at(&cluster());
    let honest = corpus_entry("legacy_single_transfer");
    for _ in 0..3 {
        let _ = core
            .verify_async(&describe(bytes(&honest["raw"]), Some(transfer_data())))
            .await;
    }
    let artifact = transfer_of(100_000_000_000);
    assert!(graphite_core::tx_artifact::parse_transaction(&artifact).is_ok());
    let r = core
        .verify_async(&describe(artifact, None))
        .await
        .expect("verification must run");
    let (status, reason) = l2(&r);
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(!r.approved, "{}", r.summary);
    assert!(
        r.scope.is_artifact_bound(),
        "the binding is reported, and reported as unlocated"
    );
    assert!(codes(&r).contains(&UnobservedCode::InstructionNotLocated));
    // With the data the description is held to, the amount is what fails:
    // the described 2,000,000-lamport data is in no instruction of a
    // 100 SOL transfer.
    let r = core
        .verify_async(&describe(
            transfer_of(100_000_000_000),
            Some(transfer_data()),
        ))
        .await
        .expect("verification must run");
    let (status, reason) = l2(&r);
    assert_eq!(status, LayerStatus::Failed, "{reason}");
    assert!(reason.contains("no instruction matching"), "{reason}");
    assert!(!r.approved);
}

/// The prose and the codes are one list: same length, same order, so a
/// consumer that gates on codes and prints prose never prints the wrong line.
#[tokio::test]
async fn unobserved_prose_and_codes_are_parallel() {
    let core = core_at(&cluster());
    let honest = corpus_entry("legacy_single_transfer");
    for (artifact, data) in [
        (Some(bytes(&honest["raw"])), Some(transfer_data())),
        (Some(bytes(&honest["raw"])), None),
        (Some(vec![1, 2, 3, 4]), Some(transfer_data())),
        (None, Some(transfer_data())),
    ] {
        let mut input = describe(artifact.clone().unwrap_or_default(), data);
        input.signed_transaction = artifact;
        let r = core
            .verify_async(&input)
            .await
            .expect("verification must run");
        let (prose, codes) = match &r.scope {
            VerificationScope::ArtifactBound {
                unobserved,
                unobserved_codes,
                ..
            }
            | VerificationScope::Descriptive {
                unobserved,
                unobserved_codes,
            } => (unobserved.clone(), unobserved_codes.clone()),
        };
        assert_eq!(prose.len(), codes.len(), "{prose:?} vs {codes:?}");
        assert!(!codes.is_empty(), "never empty (schema minItems 1)");
        // Every code serializes to the snake_case name the SDKs match on.
        for c in &codes {
            let s = serde_json::to_string(c).unwrap();
            assert!(
                s.starts_with('"')
                    && s.chars()
                        .all(|ch| ch.is_ascii_lowercase() || ch == '_' || ch == '"'),
                "{s}"
            );
        }
    }
}
