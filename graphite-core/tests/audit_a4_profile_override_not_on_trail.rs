//! A4-06 (2026-09-29 audit): the audit record says which wallet profile a
//! verdict was judged under, including a server override.
//!
//! `verify_handler` clamps a caller-supplied `Custom` wallet profile weaker
//! than any built-in and discloses it, on the rule that an overridden policy
//! must never be applied silently. The disclosure reached the response only:
//! `AuditRecord` had no summary or profile field, and the note was appended to
//! `result.summary` after `log.append`. The durable record of a verdict said
//! neither which profile or threshold produced it nor that the caller's
//! requested policy was overridden, so the same `approved`/`confidence` row
//! read identically under Treasury (0.80) and Gaming (0.55), which is what a
//! dispute or an L8 investigation needs to know.
//!
//! The fix adds `AuditRecord.wallet_profile`: the profile that applied and,
//! when the server overrode the caller, the override (`serde(default)` for
//! rows written before).
//!
//! The test sends a `Custom` profile with `min_confidence` 0.0 and pins that
//! the response discloses the clamp and that the audit line for the same
//! `audit_trail_id` carries the wallet profile.
#![cfg(feature = "server")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

fn start_server() -> (SocketAddr, std::path::PathBuf) {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "graphite-a4-profile-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for k in [
        "GRAPHITE_API_KEY",
        "GRAPHITE_ADMIN_API_KEY",
        "GRAPHITE_RPC_URL",
        "GRAPHITE_RPC_WITNESS_URL",
        "GRAPHITE_PLUGINS_DIR",
        "GRAPHITE_PLUGIN_EVENTS_FILE",
        "GRAPHITE_WALLET_PROFILE",
        "GRAPHITE_ALLOW_PERMISSIVE_PROFILES",
        "GRAPHITE_TRUST_PROXY",
        "GRAPHITE_RATE_LIMIT",
        "GRAPHITE_AUDIT_ROTATE_BYTES",
        "GRAPHITE_AUDIT_MAX_ARCHIVES",
        "GRAPHITE_MAX_CONCURRENT",
        "GRAPHITE_ALLOW_DURABLE_NONCE",
        "GRAPHITE_CORS_ORIGINS",
    ] {
        std::env::remove_var(k);
    }
    std::env::set_var("GRAPHITE_DEV_MODE", "1");
    std::env::set_var("GRAPHITE_DATA_DIR", &dir);
    std::env::set_var("GRAPHITE_REGISTRY_STATE", dir.join("no-registry.json"));
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        if let Err(e) = rt.block_on(graphite_core::server::run_server(addr)) {
            eprintln!("server exited: {e}");
        }
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return (addr, dir);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("server did not start");
}

fn post_json(addr: SocketAddr, path: &str, body: &str) -> (u16, serde_json::Value) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let json = text
        .split("\r\n\r\n")
        .nth(1)
        .and_then(|b| serde_json::from_str(b).ok())
        .unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[test]
fn an_overridden_wallet_profile_is_on_the_audit_record() {
    let (addr, dir) = start_server();
    let body = serde_json::json!({
        "proposed_intent": {
            "intent_type": "transfer",
            "raw_natural_language": "Transfer 1 SOL to friend",
            "confidence_of_parse": 0.95
        },
        "program_id": "11111111111111111111111111111111",
        "protocol_version": "1.0.0",
        "instruction_discriminator": "02000000",
        "account_addresses": [
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"
        ],
        // Weaker than any built-in: the server clamps it and discloses that.
        "wallet_profile": { "Custom": { "min_confidence": 0.0, "min_trust_tier": "Unknown" } }
    })
    .to_string();
    let (status, resp) = post_json(addr, "/verify", &body);
    assert_eq!(status, 200, "verify must answer: {resp}");
    let summary = resp["summary"].as_str().unwrap_or_default().to_string();
    let id = resp["audit_trail_id"].as_str().unwrap().to_string();
    // Precondition: the response discloses the override.
    assert!(
        summary.contains("was raised to"),
        "precondition: the response discloses the clamp; summary = {summary}"
    );

    let trail = std::fs::read_to_string(graphite_core::durable::audit_path(&dir)).unwrap();
    let line = trail
        .lines()
        .find(|l| l.contains(&id))
        .expect("the verification is on the trail");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        line.contains("was raised to") || line.contains("wallet_profile"),
        "the audit record for {id} carries neither the effective wallet profile nor the \
         disclosed override, though the response says the policy was changed:\n  response \
         summary: {summary}\n  audit line: {line}"
    );
}
