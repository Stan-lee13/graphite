//! A4-07 (2026-09-29 audit): a `/verify` refused for its wallet profile leaves
//! an audit row, like every other refusal.
//!
//! `verify_handler` audits its other refusal paths, the 422 for an
//! unparseable body and every `VerificationError`, because probing attacks
//! against `/verify` must leave a trail. The 400 it returned for an invalid
//! wallet profile (`enforce_wallet_profile` returning `Err`, e.g.
//! `min_confidence` 2.0, the Round 17 F-16-08 / Round 19 F-19-27 input)
//! returned before either append, so probing the profile gate was invisible
//! on the trail.
//!
//! The fix appends an `AuditErrorRecord` on that path too, the same as the 422
//! and `VerificationError` paths.
//!
//! The control pins that the 422 path writes an error record; the test pins
//! that the profile refusal is a 400 and writes one as well.
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
        "graphite-a4-p400-{}-{}",
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

fn post_status(addr: SocketAddr, body: &str) -> u16 {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let req = format!(
        "POST /verify HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out)
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

#[test]
fn a_refused_wallet_profile_leaves_a_trail_like_every_other_refusal() {
    let (addr, dir) = start_server();
    let audit = graphite_core::durable::audit_path(&dir);
    let lines = |p: &std::path::Path| {
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count()
    };

    // Control: an unparseable body (422) is audited.
    let before = lines(&audit);
    assert_eq!(post_status(addr, "{not json"), 422);
    assert_eq!(
        lines(&audit),
        before + 1,
        "control: the 422 path writes an error record"
    );

    // The profile refusal.
    let body = serde_json::json!({
        "proposed_intent": {
            "intent_type": "transfer",
            "raw_natural_language": "Transfer 1 SOL",
            "confidence_of_parse": 0.95
        },
        "program_id": "11111111111111111111111111111111",
        "instruction_discriminator": "02000000",
        "account_addresses": [
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"
        ],
        "wallet_profile": { "Custom": { "min_confidence": 2.0, "min_trust_tier": "BattleTested" } }
    })
    .to_string();
    let before = lines(&audit);
    assert_eq!(
        post_status(addr, &body),
        400,
        "precondition: refused up front"
    );
    let after = lines(&audit);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        after,
        before + 1,
        "a /verify refused for its wallet_profile left no error record on the trail"
    );
}
