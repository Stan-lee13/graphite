//! Requires the `rpc` feature: every verification is served by a loopback mock.
#![cfg(feature = "rpc")]

//! Round 39 (core-identity), attack campaign 5: address lookup tables, end to
//! end through `verify_async`.
//!
//! One v0 System transfer from the payer to an account the transaction reaches
//! only through a lookup table, verified against a loopback RPC that serves
//! the table and a simulation. Each case changes one thing the table or the
//! simulator says and pins that the verdict is never `executable_approved`
//! and that the refusal names the cause; the honest case is the control and
//! must be `executable_approved`, so every refusal below is the case's, not an
//! engine that approves nothing.
//!
//! Graphite does not apply Agave's last-extended-slot rule itself
//! (`tx_artifact::NOT_DEACTIVATING`'s doc): an index into entries appended in
//! the slot a transaction lands in fails to load. The simulator applies it, so
//! such a transaction comes back as a failed simulation — pinned here as
//! `last_extended_slot_and_stale_simulations_are_refused`, which is also what a
//! simulator a slot behind the table read reports.

use base64::Engine as _;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::{BehaviorEvidence, TrustTier};
use graphite_core::tx_artifact::{ADDRESS_LOOKUP_TABLE_PROGRAM, LOOKUP_TABLE_META_SIZE};
use graphite_core::verification::{
    ExecutionDecision, GraphiteCore, ProposedIntent, VerificationInput, VerificationResult,
};
use std::io::{Read, Write};
use std::net::TcpListener;

const SYSTEM: &str = "11111111111111111111111111111111";
const FEE: u64 = 5_000;
const AMOUNT: u64 = 1_000_000_000;

fn key(seed: u8) -> String {
    let mut b = [seed; 32];
    b[0] = 0x40 | (seed & 0x3f);
    bs58::encode(b).into_string()
}
fn payer() -> String {
    key(1)
}
fn table() -> String {
    key(2)
}
/// The recipient, entry 0 of the table.
fn w0() -> String {
    key(3)
}
/// Entry 1 of the table, loaded writable beside the recipient.
fn w1() -> String {
    key(4)
}
fn stranger() -> String {
    key(9)
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

fn raw(k: &str) -> Vec<u8> {
    bs58::decode(k).into_vec().unwrap()
}

fn transfer_data() -> Vec<u8> {
    let mut d = 2u32.to_le_bytes().to_vec();
    d.extend_from_slice(&AMOUNT.to_le_bytes());
    d
}

/// A v0 frame: static keys [payer (signer, writable), System], the given
/// lookups (table, writable indexes, readonly indexes), and a System transfer
/// from the payer to account index 2 — the first loaded writable.
fn v0_frame(lookups: &[(String, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    compact_u16(1, &mut out);
    out.extend_from_slice(&[0u8; 64]);
    out.push(0x80);
    out.extend_from_slice(&[1, 0, 1]);
    compact_u16(2, &mut out);
    out.extend_from_slice(&raw(&payer()));
    out.extend_from_slice(&raw(SYSTEM));
    out.extend_from_slice(&[9u8; 32]);
    compact_u16(1, &mut out);
    out.push(1);
    compact_u16(2, &mut out);
    out.extend_from_slice(&[0, 2]);
    let data = transfer_data();
    compact_u16(data.len(), &mut out);
    out.extend_from_slice(&data);
    compact_u16(lookups.len(), &mut out);
    for (t, w, r) in lookups {
        out.extend_from_slice(&raw(t));
        compact_u16(w.len(), &mut out);
        out.extend_from_slice(w);
        compact_u16(r.len(), &mut out);
        out.extend_from_slice(r);
    }
    out
}

/// The honest frame: one table, entries 0 and 1 loaded writable.
fn honest_frame() -> Vec<u8> {
    v0_frame(&[(table(), vec![0, 1], vec![])])
}

/// A legacy frame naming the recipient statically: [payer, recipient, System].
fn legacy_frame() -> Vec<u8> {
    let mut out = Vec::new();
    compact_u16(1, &mut out);
    out.extend_from_slice(&[0u8; 64]);
    out.extend_from_slice(&[1, 0, 1]);
    compact_u16(3, &mut out);
    out.extend_from_slice(&raw(&payer()));
    out.extend_from_slice(&raw(&w0()));
    out.extend_from_slice(&raw(SYSTEM));
    out.extend_from_slice(&[9u8; 32]);
    compact_u16(1, &mut out);
    out.push(2);
    compact_u16(2, &mut out);
    out.extend_from_slice(&[0, 1]);
    let data = transfer_data();
    compact_u16(data.len(), &mut out);
    out.extend_from_slice(&data);
    out
}

fn table_data(deactivation_slot: u64, entries: &[String]) -> Vec<u8> {
    let mut data = vec![0u8; LOOKUP_TABLE_META_SIZE];
    data[0..4].copy_from_slice(&1u32.to_le_bytes());
    data[4..12].copy_from_slice(&deactivation_slot.to_le_bytes());
    for e in entries {
        data.extend_from_slice(&raw(e));
    }
    data
}

fn account_json(lamports: u64, owner: &str, data: &[u8]) -> String {
    format!(
        r#"{{"lamports":{lamports},"owner":"{owner}","executable":false,"rentEpoch":0,"data":["{}","base64"]}}"#,
        base64::engine::general_purpose::STANDARD.encode(data)
    )
}

/// What the loopback cluster serves for one case.
#[derive(Clone)]
struct Cluster {
    /// The table account as JSON (`null`: no such account).
    table_account: String,
    /// The `loadedAddresses` member of the simulation, verbatim (`None`:
    /// the member is absent).
    loaded_addresses: Option<String>,
    /// The simulation's `err`, verbatim.
    sim_err: String,
    /// The simulation's balance arrays: [payer, System, recipient, entry 1]
    /// for a v0 frame, [payer, recipient, System] for the legacy one.
    legacy: bool,
}

impl Cluster {
    fn honest() -> Self {
        Self {
            table_account: account_json(
                5_000_000,
                ADDRESS_LOOKUP_TABLE_PROGRAM,
                &table_data(u64::MAX, &[w0(), w1()]),
            ),
            loaded_addresses: Some(format!(
                r#"{{"writable":["{}","{}"],"readonly":[]}}"#,
                w0(),
                w1()
            )),
            sim_err: "null".to_string(),
            legacy: false,
        }
    }

    fn state(&self, k: &str, post: bool) -> String {
        let (pre_l, post_l) = if k == payer() {
            (10 * AMOUNT, 10 * AMOUNT - AMOUNT - FEE)
        } else if k == w0() {
            (AMOUNT, 2 * AMOUNT)
        } else if k == w1() {
            (3 * AMOUNT, 3 * AMOUNT)
        } else if k == table() {
            return self.table_account.clone();
        } else {
            return "null".to_string();
        };
        account_json(if post { post_l } else { pre_l }, SYSTEM, &[])
    }

    fn simulation(&self, addresses: &[serde_json::Value]) -> String {
        let post: Vec<String> = addresses
            .iter()
            .map(|k| self.state(k.as_str().unwrap_or(""), true))
            .collect();
        let (pre, postb) = if self.legacy {
            (
                format!("[{},{},1]", 10 * AMOUNT, AMOUNT),
                format!("[{},{},1]", 10 * AMOUNT - AMOUNT - FEE, 2 * AMOUNT),
            )
        } else {
            (
                format!("[{},1,{},{}]", 10 * AMOUNT, AMOUNT, 3 * AMOUNT),
                format!(
                    "[{},1,{},{}]",
                    10 * AMOUNT - AMOUNT - FEE,
                    2 * AMOUNT,
                    3 * AMOUNT
                ),
            )
        };
        let loaded = self
            .loaded_addresses
            .as_ref()
            .map(|l| format!(r#","loadedAddresses":{l}"#))
            .unwrap_or_default();
        format!(
            r#"{{"context":{{"slot":1}},"value":{{"err":{},"logs":[],"unitsConsumed":150,"fee":{FEE},"preBalances":{pre},"postBalances":{postb},"innerInstructions":[]{loaded},"accounts":[{}],"returnData":null}}}}"#,
            self.sim_err,
            post.join(",")
        )
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some(end) = text.find("\r\n\r\n") {
            let len = text[..end]
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                return String::from_utf8_lossy(&buf[end + 4..end + 4 + len]).to_string();
            }
        }
    }
    String::new()
}

fn serve(cluster: Cluster) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let req: serde_json::Value =
                serde_json::from_str(&read_request(&mut stream)).unwrap_or_default();
            let result = match req["method"].as_str() {
                Some("getMultipleAccounts") => {
                    let keys = req["params"][0].as_array().cloned().unwrap_or_default();
                    let v: Vec<String> = keys
                        .iter()
                        .map(|k| cluster.state(k.as_str().unwrap_or(""), false))
                        .collect();
                    format!(r#"{{"context":{{"slot":1}},"value":[{}]}}"#, v.join(","))
                }
                Some("getAccountInfo") => format!(
                    r#"{{"context":{{"slot":1}},"value":{}}}"#,
                    cluster.state(req["params"][0].as_str().unwrap_or(""), false)
                ),
                Some("simulateTransaction") => {
                    let keys = req["params"][1]["accounts"]["addresses"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    cluster.simulation(&keys)
                }
                _ => "null".to_string(),
            };
            let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://{addr}")
}

fn input(frame: Vec<u8>, versioned: bool) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send 1 SOL".to_string(),
            confidence_of_parse: 0.95,
            // Round 36 (F-003): what the request states, which the bytes carry.
            extracted_parameters: Some(graphite_core::verification::ExtractedParameters {
                amount: Some("1".to_string()),
                destination: Some(w0()),
                input_token: Some("SOL".to_string()),
                ..Default::default()
            }),
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![payer(), w0()],
        instruction_data: Some(transfer_data()),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Custom {
            min_confidence: 0.40,
            min_trust_tier: TrustTier::OfficialManifest,
        },
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: Some(frame),
        transaction_instructions: vec![],
        cpi_trace: None,
        real_account_metas: vec![],
        uses_versioned_transaction: versioned,
        lookup_table_count: if versioned { 1 } else { 0 },
        state_diff: None,
    }
}

async fn verify(cluster: Cluster, frame: Vec<u8>) -> VerificationResult {
    let legacy = cluster.legacy;
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint: serve(cluster),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    }));
    core.verify_async(&input(frame, !legacy))
        .await
        .expect("a verdict")
}

fn said(r: &VerificationResult) -> String {
    let layers = r
        .layers
        .iter()
        .map(|l| format!("{} {:?}: {}", l.layer, l.status, l.reason))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "{layers}\n{:?}\n{}\n{}",
        r.risk_verdict,
        r.summary,
        serde_json::to_string(&r.scope).unwrap_or_default()
    )
}

/// Not executable, and the refusal says `why`.
fn refused_for(r: &VerificationResult, case: &str, why: &str) {
    assert_ne!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{case}: executable_approved:\n{}",
        said(r)
    );
    assert!(!r.executable, "{case}");
    let s = said(r);
    assert!(
        s.contains(why),
        "{case}: the refusal does not say {why:?}:\n{s}"
    );
}

#[tokio::test]
async fn the_honest_lookup_is_executable() {
    let r = verify(Cluster::honest(), honest_frame()).await;
    assert_eq!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "the control must be approvable, or no refusal below means anything:\n{}",
        said(&r)
    );
}

#[tokio::test]
async fn a_table_under_another_owner_is_refused() {
    let mut c = Cluster::honest();
    c.table_account = account_json(5_000_000, SYSTEM, &table_data(u64::MAX, &[w0(), w1()]));
    let r = verify(c, honest_frame()).await;
    refused_for(&r, "wrong owner", "not the Address Lookup Table program");
}

#[tokio::test]
async fn a_deactivating_table_is_refused() {
    let mut c = Cluster::honest();
    c.table_account = account_json(
        5_000_000,
        ADDRESS_LOOKUP_TABLE_PROGRAM,
        &table_data(1_000, &[w0(), w1()]),
    );
    let r = verify(c, honest_frame()).await;
    refused_for(&r, "deactivating", "deactivating");
}

#[tokio::test]
async fn a_missing_table_is_refused() {
    let mut c = Cluster::honest();
    c.table_account = "null".to_string();
    let r = verify(c, honest_frame()).await;
    refused_for(&r, "missing table", "was not supplied");
}

#[tokio::test]
async fn an_index_past_the_table_is_refused() {
    let r = verify(
        Cluster::honest(),
        v0_frame(&[(table(), vec![0, 2], vec![])]),
    )
    .await;
    refused_for(&r, "index past the end", "asks for index 2");
}

#[tokio::test]
async fn one_table_looked_up_twice_for_one_entry_loads_it_twice_and_is_refused() {
    let frame = v0_frame(&[(table(), vec![0], vec![]), (table(), vec![0], vec![])]);
    let r = verify(Cluster::honest(), frame).await;
    refused_for(&r, "duplicate entry", "loads an account twice");
}

/// A table listed twice for different entries loads two distinct accounts;
/// the runtime accepts it and so does Graphite's resolution.
#[tokio::test]
async fn one_table_looked_up_twice_for_two_entries_resolves() {
    let frame = v0_frame(&[(table(), vec![0], vec![]), (table(), vec![1], vec![])]);
    let r = verify(Cluster::honest(), frame).await;
    let s = said(&r);
    assert!(
        !s.contains("could not be resolved") && !s.contains("not the accounts Graphite resolved"),
        "two lookups of one table for distinct entries were not resolved:\n{s}"
    );
    assert_eq!(r.decision, ExecutionDecision::ExecutableApproved, "{s}");
}

#[tokio::test]
async fn a_simulator_that_substitutes_a_loaded_address_is_not_believed() {
    let mut c = Cluster::honest();
    c.loaded_addresses = Some(format!(
        r#"{{"writable":["{}","{}"],"readonly":[]}}"#,
        stranger(),
        w1()
    ));
    let r = verify(c, honest_frame()).await;
    refused_for(&r, "substituted", "not the accounts Graphite resolved");
}

#[tokio::test]
async fn a_simulator_that_moves_a_loaded_address_to_readonly_is_not_believed() {
    let mut c = Cluster::honest();
    c.loaded_addresses = Some(format!(
        r#"{{"writable":["{}"],"readonly":["{}"]}}"#,
        w0(),
        w1()
    ));
    let r = verify(c, honest_frame()).await;
    refused_for(&r, "privilege moved", "not the accounts Graphite resolved");
}

/// A simulator that does not say which accounts it loaded. Every index past
/// the static keys in its report is then unplaceable, and Graphite's own
/// resolution was never confirmed by the execution (Round 34, S-5).
#[tokio::test]
async fn a_simulator_that_omits_or_nulls_its_loaded_addresses_is_not_believed() {
    for (case, loaded) in [
        ("absent", None),
        ("null", Some("null".to_string())),
        (
            "unreadable",
            Some(r#"{"writable":[1],"readonly":[]}"#.to_string()),
        ),
    ] {
        let mut c = Cluster::honest();
        c.loaded_addresses = loaded;
        let r = verify(c, honest_frame()).await;
        refused_for(&r, case, "loadedAddresses");
    }
}

/// The last-extended-slot rule, and a simulator a slot behind the table
/// read: the runtime fails the load (`InvalidAddressLookupTableIndex`), so
/// the simulation errs and nothing it reports is evidence.
#[tokio::test]
async fn last_extended_slot_and_stale_simulations_are_refused() {
    let mut c = Cluster::honest();
    c.sim_err = r#""InvalidAddressLookupTableIndex""#.to_string();
    c.loaded_addresses = Some(r#"{"writable":[],"readonly":[]}"#.to_string());
    let r = verify(c, honest_frame()).await;
    refused_for(&r, "last extended slot", "InvalidAddressLookupTableIndex");
}

#[tokio::test]
async fn loaded_addresses_for_a_legacy_message_are_a_contradiction() {
    let mut c = Cluster::honest();
    c.legacy = true;
    c.loaded_addresses = Some(format!(r#"{{"writable":["{}"],"readonly":[]}}"#, w1()));
    let r = verify(c, legacy_frame()).await;
    refused_for(&r, "legacy with loads", "for a message that uses none");
}
