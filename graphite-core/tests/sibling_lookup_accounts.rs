//! Requires the `rpc` feature.
#![cfg(feature = "rpc")]

//! A declared sibling's lookup-table positions were wildcards.
//!
//! The PRIMARY instruction's account comparison resolves address-lookup-table
//! positions before comparing (`resolve_instruction_accounts`), so a v0
//! transaction's ALT-sourced accounts are checked against what the request
//! says. A declared SIBLING's comparison did not: `declaration_describes`
//! compared against `ArtifactInstruction::accounts`, the UNRESOLVED
//! `Vec<Option<String>>`, and `compare_instruction_accounts` reads an
//! unresolved position as neither a match nor a mismatch.
//!
//! So every lookup position in a sibling accepted any address the caller
//! cared to write. That is worse than a weak comparison, because declared
//! accounts widen the set `ArtifactAccountsNotDescribed` treats as named: a
//! fabricated address at a lookup position could mask a real account from a
//! Critical finding, which is the padding `SiblingCoverage`'s own doc comment
//! says is closed.
//!
//! This file needs a live RPC to exercise it at all — the resolution only
//! happens when a client is attached and the tables come back — so it stands
//! up a loopback mock that serves one lookup table, exactly as
//! `rpc_influence_bounds.rs` does. Nothing here touches a network beyond
//! 127.0.0.1.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, UnobservedCode, VerificationInput,
    VerificationResult,
};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

const SYSTEM: &str = "11111111111111111111111111111111";
const ALT_PROGRAM: &str = "AddressLookupTab1e1111111111111111111111111";
const PAYER: &str = "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx";
const RECIPIENT: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";

fn addr(seed: u8) -> String {
    bs58::encode([seed; 32]).into_string()
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

fn transfer_data(lamports: u64) -> Vec<u8> {
    let mut d = vec![0x02u8, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d
}

/// A v0 frame with one lookup table loading one readonly address.
///
/// Static keys: payer(0, signer+writable), recipient(1), system(2, readonly).
/// The table's single loaded address becomes runtime index 3.
fn v0_frame_with_lookup(table: &str, instructions: &[(u8, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let keys = [PAYER, RECIPIENT, SYSTEM];
    let mut out = Vec::new();
    compact_u16(1, &mut out);
    out.extend_from_slice(&[0u8; 64]);
    out.push(0x80); // version 0
    out.extend_from_slice(&[1, 0, 1]);
    compact_u16(keys.len(), &mut out);
    for k in keys {
        out.extend_from_slice(&bs58::decode(k).into_vec().expect("valid base58"));
    }
    out.extend_from_slice(&[9u8; 32]); // blockhash
    compact_u16(instructions.len(), &mut out);
    for (program, accounts, data) in instructions {
        out.push(*program);
        compact_u16(accounts.len(), &mut out);
        out.extend_from_slice(accounts);
        compact_u16(data.len(), &mut out);
        out.extend_from_slice(data);
    }
    // One table, zero writable indexes, one readonly index (entry 0).
    compact_u16(1, &mut out);
    out.extend_from_slice(&bs58::decode(table).into_vec().expect("valid base58"));
    compact_u16(0, &mut out);
    compact_u16(1, &mut out);
    out.push(0);
    out
}

/// A lookup-table account holding exactly one address.
///
/// Layout: a 56-byte meta block whose `deactivation_slot` (bytes 4..12) must be
/// `u64::MAX` for the table to be considered live, then a packed address array.
fn lookup_table_account(entry: &str) -> String {
    let mut data = vec![0u8; 56];
    data[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
    data.extend_from_slice(&bs58::decode(entry).into_vec().expect("valid base58"));
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(&data)
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
    std::mem::forget(listener);
    format!("http://{addr}")
}

/// An RPC that serves the lookup table and nothing else of consequence.
fn rpc_serving(table_entry: &str) -> String {
    let accounts = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":[
            {{"lamports":1000000,"owner":"{ALT_PROGRAM}","executable":false,"rentEpoch":0,"data":["{}","base64"]}}]}}}}"#,
        lookup_table_account(table_entry)
    );
    let mut m = HashMap::new();
    m.insert("getMultipleAccounts".to_string(), accounts);
    serve(m)
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

/// The described sibling's fourth account is the ALT-resolved one. `declared`
/// is what the caller claims sits there.
fn input_with_sibling(table: &str, declared_alt_account: &str) -> VerificationInput {
    // Primary: System transfer on static keys 0,1.
    // Sibling: System transfer on static key 0 and the ALT-resolved index 3.
    let artifact = v0_frame_with_lookup(
        table,
        &[
            (2, vec![0, 1], transfer_data(2_000_000)),
            (2, vec![0, 3], transfer_data(1_000_000)),
        ],
    );
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send some SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![PAYER.to_string(), RECIPIENT.to_string()],
        instruction_data: Some(transfer_data(2_000_000)),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: Some(artifact),
        transaction_instructions: vec![TransactionInstruction {
            program_id: SYSTEM.to_string(),
            instruction_discriminator: hex::encode(transfer_data(1_000_000)),
            account_addresses: vec![PAYER.to_string(), declared_alt_account.to_string()],
            cpi_targets: vec![],
        }],
        cpi_trace: None,
        real_account_metas: vec![],
        uses_versioned_transaction: true,
        lookup_table_count: 1,
        state_diff: None,
    }
}

fn l2(r: &VerificationResult) -> &graphite_core::verification::PipelineLayerResult {
    r.layers
        .iter()
        .find(|l| l.layer.starts_with("L2"))
        .expect("L2 must be reported")
}

#[tokio::test]
async fn a_sibling_whose_lookup_account_matches_is_accepted() {
    // The control. The table loads REAL, and the declaration names it
    // correctly, so coverage is complete and L2 has no reason to fail. If this
    // ever starts failing, the test below is measuring a broken fixture rather
    // than the check it exists for.
    let real = addr(0xAA);
    let endpoint = rpc_serving(&real);
    let core = core_with_rpc(&endpoint);
    let r = core
        .verify_async(&input_with_sibling(&addr(0x7A), &real))
        .await
        .expect("verification must reach a verdict");
    assert_eq!(
        l2(&r).status,
        LayerStatus::Passed,
        "an honestly declared ALT-resolved sibling account was refused: {}",
        l2(&r).reason
    );
}

#[tokio::test]
async fn a_sibling_that_misnames_its_lookup_account_is_refused() {
    // The table loads `real`; the declaration claims `fabricated` sits there.
    // Before the fix the position was unresolved, `compare_instruction_accounts`
    // read it as neither match nor mismatch, and the declaration "described"
    // the instruction anyway — so the fabricated address entered the set that
    // `ArtifactAccountsNotDescribed` treats as named.
    let real = addr(0xAA);
    let fabricated = addr(0xBB);
    let endpoint = rpc_serving(&real);
    let core = core_with_rpc(&endpoint);
    let r = core
        .verify_async(&input_with_sibling(&addr(0x7A), &fabricated))
        .await
        .expect("verification must reach a verdict");
    assert_eq!(
        l2(&r).status,
        LayerStatus::Failed,
        "GFX-107: a declared sibling named {fabricated} at a lookup-table \
         position that actually resolves to {real}, and the declaration was \
         accepted as describing it. L2 said: {}",
        l2(&r).reason
    );
    assert!(!r.approved);
}

/// The tables are the thing the fix above depends on. When they do not come
/// back, `instruction_accounts_for_comparison` falls back to the unresolved
/// list and every lookup position in a sibling is a wildcard again — exactly
/// the state GFX-107 removed. That fallback is deliberate, and the design says
/// it is disclosed by the `lookup_tables_unresolved` residual rather than
/// papered over. So what has to hold here is not "L2 fails" but the property
/// the disclosure exists to protect:
///
///   a fabricated address at an unresolvable lookup position cannot reach an
///   approved, artifact-bound verdict whose residuals are all inherent
///
/// — because that is the shape a default `ResidualPolicy` signs. Written as a
/// regression guard on my own fix: if a later change makes the fallback quiet,
/// GFX-107 reopens through the RPC rather than through the comparison.
#[tokio::test]
async fn a_fabricated_lookup_account_cannot_be_approved_when_the_table_never_resolves() {
    // An RPC that answers every method with `null`, so the table is missing
    // rather than malformed — the ordinary way resolution fails in the field.
    let endpoint = serve(HashMap::new());
    let core = core_with_rpc(&endpoint);
    let fabricated = addr(0xBB);
    let r = core
        .verify_async(&input_with_sibling(&addr(0x7A), &fabricated))
        .await
        .expect("verification must reach a verdict");

    let codes = r.scope.unobserved_codes();
    let signable = r.approved && codes.iter().all(|c| c.inherent());
    assert!(
        !signable,
        "a fabricated address at a lookup position the tables never resolved \
         reached an approved verdict carrying only inherent residuals — the \
         shape a default ResidualPolicy accepts. codes: {codes:?}"
    );
    assert!(
        codes.contains(&UnobservedCode::LookupTablesUnresolved),
        "the unresolved tables were not disclosed, so the wildcard fallback in \
         instruction_accounts_for_comparison is silent rather than declared. \
         codes: {codes:?}"
    );
}
