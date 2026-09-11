//! Requires the `rpc` feature: resolving a lookup table means fetching it.
#![cfg(feature = "rpc")]

//! An account that arrives through a lookup table has privileges too.
//!
//! `privilege_from_artifact.rs` covers the case where the described accounts are
//! in the message's static key list: the header says which are signed and which
//! are writable, and Graphite reads it instead of asking the caller. An account
//! reached through an address lookup table is not in that list. Its privilege is
//! in the table resolution — which half of the lookup the index sits in — and
//! that was resolved too late to matter: inside the simulation block, long after
//! account resolution had already compared the manifest against whatever
//! `real_account_metas` the request supplied.
//!
//! So for exactly the accounts a v0 transaction can reach without naming them,
//! the privilege check ran against the description rather than the transaction.
//! Resolution now happens before account resolution, and these two artifacts
//! differ in one thing: whether the index sits in the table's writable list or
//! its readonly list. Same table, same index, same resolved account, identical
//! counts.
//!
//! The mock RPC serves the lookup table and nothing else of substance. It is a
//! local socket; no public endpoint is contacted and nothing is signed or sent.

use base64::Engine;
use graphite_core::manifest::load_seed_manifests;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::verification::{
    GraphiteCore, ProposedIntent, VerificationInput, VerificationResult,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

fn fixture() -> serde_json::Value {
    let raw = include_str!("../fixtures/artifacts/alt_privilege.json");
    serde_json::from_str(raw).expect("fixture must parse")
}

fn b64(v: &serde_json::Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(v.as_str().expect("base64"))
        .expect("must decode")
}

fn acct(name: &str) -> String {
    fixture()["accounts"][name]
        .as_str()
        .expect("account")
        .to_string()
}

/// A mock that answers by WHAT was asked for, not only by method name.
///
/// `getMultipleAccounts` carries both the lookup-table fetch and the pre/post
/// state fetch, so routing on the method alone would hand the table's bytes to
/// the state diff and the state's bytes to the resolver. The table address in
/// the request body is what tells them apart.
fn serve_table() -> String {
    let table = fixture()["table_account_base64"]
        .as_str()
        .expect("table data")
        .to_string();
    let table_address = acct("table");

    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").unwrap());
    let addr = listener.local_addr().unwrap();
    let server = Arc::clone(&listener);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = server.accept() {
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).unwrap_or(0);
            let body = String::from_utf8_lossy(&buf[..n]).to_string();

            let payload = if body.contains(&table_address) {
                format!(
                    r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":[
                        {{"lamports":1000000,"owner":"AddressLookupTab1e1111111111111111111111111",
                          "data":["{table}","base64"],"executable":false,"rentEpoch":0}}]}}}}"#
                )
            } else {
                // Everything else fails honestly. Nothing below the privilege
                // check depends on it, and a mock that invents a simulation
                // would be inventing evidence.
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"not served by this test"}}"#
                    .to_string()
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                payload.len(),
                payload
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}")
}

/// Slot 1 is declared read-only. That is the claim the table has to be checked
/// against.
fn manifest_json() -> String {
    format!(
        r#"{{
        "graphite_manifest_version": "1.0",
        "protocol": {{
            "name": "Test ALT Privilege Protocol",
            "program_id": "{pid}",
            "website": "",
            "github": ""
        }},
        "version": {{ "label": "1.0" }},
        "trust_tier": "OfficialManifest",
        "instructions": [
            {{
                "name": "TestInstruction",
                "discriminator": "cccccccccccccccc",
                "accounts": [
                    {{ "name": "authority", "role": "signer", "is_writable": true, "is_signer": true, "pda_seeds": [] }},
                    {{ "name": "target", "role": "readonly", "is_writable": false, "is_signer": false, "pda_seeds": [] }}
                ],
                "expected_state_changes": ["reads accounts.target"],
                "allowed_cpis": [],
                "risk_rules": []
            }}
        ]
    }}"#,
        pid = acct("program")
    )
}

async fn verify(endpoint: &str, artifact: &str) -> VerificationResult {
    let mut registry = load_seed_manifests();
    registry
        .load_from_json(&manifest_json())
        .expect("test manifest must load");
    let mut core = GraphiteCore::with_registry(registry);
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    }));

    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "test".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: acct("program"),
        protocol_version: "1.0".to_string(),
        instruction_discriminator: "cccccccccccccccc".to_string(),
        account_addresses: vec![acct("payer"), acct("target")],
        instruction_data: Some(
            hex::decode(fixture()["instruction_data_hex"].as_str().expect("data")).expect("hex"),
        ),
        cpi_targets: vec![],
        // The most permissive profile: an escalation that only a strict profile
        // catches has not been caught, it has been outvoted.
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: Default::default(),
        compute_units: 150,
        account_writes: 1,
        cpi_hops: 0,
        signed_transaction: Some(b64(&fixture()[artifact]["raw_base64"])),
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: true,
        lookup_table_count: 1,
        // Deliberately empty. Before the tables were resolved in time, this was
        // the ONLY source of privilege for an ALT-resolved account, so an empty
        // list meant the check simply did not run.
        real_account_metas: vec![],
        state_diff: None,
    };
    core.verify_async(&input)
        .await
        .expect("verification must complete")
}

fn blocked_on_privilege(r: &VerificationResult) -> bool {
    r.risk_verdict.status == "Blocked"
        && r.risk_verdict
            .findings
            .iter()
            .any(|f| f.reason.contains("kind=privilege"))
}

fn l1(r: &VerificationResult) -> String {
    r.layers
        .iter()
        .find(|l| l.layer == "L1_AccountResolution")
        .map(|l| l.reason.clone())
        .expect("L1 must always be reported")
}

fn dump(label: &str, r: &VerificationResult) {
    println!("--- {label} ---");
    println!("  L1: {}", l1(r));
    println!(
        "  status={} findings={:?}",
        r.risk_verdict.status,
        r.risk_verdict
            .findings
            .iter()
            .map(|f| (f.pattern.clone(), f.reason.clone()))
            .collect::<Vec<_>>()
    );
    for u in r.scope.unobserved() {
        println!("  unobserved: {u}");
    }
}

/// The fixtures reach the account only through the table.
///
/// If the target were in the static keys, the header would answer and this
/// whole file would be testing the path `privilege_from_artifact.rs` covers.
#[test]
fn the_target_is_reachable_only_through_the_lookup_table() {
    for variant in ["target_arrives_writable", "target_arrives_readonly"] {
        let m =
            graphite_core::tx_artifact::parse_transaction(&b64(&fixture()[variant]["raw_base64"]))
                .expect("v0 fixture must parse");
        assert_eq!(m.version, Some(0));
        assert!(
            !m.static_keys.contains(&acct("target")),
            "{variant}: the target must not be in the static keys"
        );
        assert_eq!(m.alt_table_count(), 1);
        assert_eq!(m.alt_account_count(), 1);
    }
}

/// The control: the table resolves the account read-only, which is what the
/// manifest declares. Nothing to report.
#[test]
fn an_account_the_table_resolves_readonly_raises_nothing() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let endpoint = serve_table();
    let r = rt.block_on(verify(&endpoint, "target_arrives_readonly"));
    dump("table resolves it readonly", &r);
    assert!(
        !blocked_on_privilege(&r),
        "the transaction agrees with the manifest and must not be blocked on privilege"
    );
    assert!(
        l1(&r).contains("address lookup tables Graphite fetched and decoded"),
        "the flags were established from the table, and the layer must say a table was          involved rather than implying the header answered: {}",
        l1(&r)
    );
}

/// The attack: the same index moved into the table's WRITABLE half.
///
/// The manifest says this slot is read-only. The transaction hands the program
/// write access to it, and says so nowhere the request can see — the account is
/// not in the static keys, and no meta was supplied. Only the table says it.
#[test]
fn an_account_the_table_resolves_writable_against_a_readonly_slot_is_blocked() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let endpoint = serve_table();
    let r = rt.block_on(verify(&endpoint, "target_arrives_writable"));
    dump("table resolves it writable", &r);
    assert!(
        blocked_on_privilege(&r),
        "a manifest-readonly account resolved writable through a lookup table must block"
    );
    assert!(
        r.risk_verdict
            .findings
            .iter()
            .any(|f| f.reason.contains(&acct("target")[..8])),
        "the finding must name the account: {:?}",
        r.risk_verdict.findings
    );
    assert!(!r.approved);
}

/// Two transactions that differ by which half of one lookup an index sits in
/// must not produce the same verdict.
#[test]
fn the_two_artifacts_are_distinguishable() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let endpoint = serve_table();
    let readonly = rt.block_on(verify(&endpoint, "target_arrives_readonly"));
    let writable = rt.block_on(verify(&endpoint, "target_arrives_writable"));
    assert_ne!(
        readonly.risk_verdict.status, writable.risk_verdict.status,
        "the only difference between these transactions is a privilege escalation"
    );
}

/// With no table to resolve from, the flags are not invented.
///
/// An endpoint that cannot serve the table must leave the account unidentified
/// and the privilege unestablished — reported, never assumed clean. This is the
/// fail-closed half: the attack artifact stops being blocked, and the verdict
/// has to say why rather than quietly passing.
#[test]
fn an_unresolvable_table_leaves_the_privilege_unestablished_and_says_so() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    // A listener that answers every request with an error, including the table.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut buf = vec![0u8; 65536];
            let _ = stream.read(&mut buf);
            let payload =
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"table unavailable"}}"#;
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    payload.len(),
                    payload
                )
                .as_bytes(),
            );
        }
    });
    let r = rt.block_on(verify(&format!("http://{addr}"), "target_arrives_writable"));
    dump("table unavailable", &r);

    assert!(
        l1(&r).contains("came from the caller")
            || l1(&r).contains("neither supplied nor derivable"),
        "with no table, L1 must not claim the header answered for this account: {}",
        l1(&r)
    );
    let unobserved = r.scope.unobserved().join(" | ");
    assert!(
        unobserved.contains("lookup table"),
        "the verdict must say the lookup-table accounts were not identified: {unobserved}"
    );
    assert!(
        !r.approved,
        "nothing about an unresolvable table should produce an approval"
    );
}
