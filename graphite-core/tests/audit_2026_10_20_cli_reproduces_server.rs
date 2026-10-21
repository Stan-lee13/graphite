//! Audit 2026-10-20 (L10, L11): the CLI, through the real binary.
//!
//! L11: `graphite verify` is how an operator asks "what would the gate decide
//! about this?", and it ignored the server's boundary settings: a weak
//! caller-supplied `Custom` profile was judged as given (the server clamps
//! it), `GRAPHITE_WALLET_PROFILE` was not applied and a malformed one was not
//! noticed. The binary now reads them through the server's own code.
//!
//! L10: `graphite execution` exited 0 when nothing could be checked. A check
//! that cannot run exits 3 ("unavailable"), never 0 and never the
//! discrepancy's 1.
#![cfg(feature = "cli")]

use std::path::PathBuf;
use std::process::Command;

fn graphite() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_graphite"));
    for k in [
        "GRAPHITE_WALLET_PROFILE",
        "GRAPHITE_ALLOW_PERMISSIVE_PROFILES",
        "GRAPHITE_ALLOW_DURABLE_NONCE",
        "GRAPHITE_QUARANTINE_ON_UPGRADE",
        "GRAPHITE_PLUGINS_DIR",
        "GRAPHITE_RPC_URL",
        "GRAPHITE_RPC_WITNESS_URL",
    ] {
        c.env_remove(k);
    }
    c
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("graphite-cli-l11-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A System transfer whose own profile asks for no gate at all.
fn weak_input(dir: &std::path::Path) -> PathBuf {
    let p = dir.join("input.json");
    std::fs::write(
        &p,
        serde_json::json!({
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
            "wallet_profile": { "Custom": { "min_confidence": 0.0, "min_trust_tier": "Unknown" } }
        })
        .to_string(),
    )
    .unwrap();
    p
}

#[test]
fn verify_applies_the_servers_boundary_settings() {
    let dir = scratch("verify");
    let input = weak_input(&dir);
    let base = |c: &mut Command| {
        c.env("GRAPHITE_DATA_DIR", dir.join("data"))
            .env("GRAPHITE_REGISTRY_STATE", dir.join("no-registry.json"))
            .args(["verify", "--file"])
            .arg(&input);
    };

    // The clamp, disclosed where the verdict is read.
    let mut c = graphite();
    base(&mut c);
    let out = c.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{e}: {stdout}\n{}", String::from_utf8_lossy(&out.stderr)));
    assert!(
        result["summary"]
            .as_str()
            .unwrap()
            .contains("weaker than any built-in"),
        "the server's clamp was not applied: {}",
        result["summary"]
    );

    // A pin wins over the input, and is named.
    let mut c = graphite();
    base(&mut c);
    let out = c
        .env("GRAPHITE_WALLET_PROFILE", "treasury")
        .output()
        .unwrap();
    let result: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(
        result["summary"].as_str().unwrap().contains("pinned"),
        "{}",
        result["summary"]
    );

    // A malformed setting is an error, as it is a startup error at the server.
    let mut c = graphite();
    base(&mut c);
    let out = c
        .env("GRAPHITE_WALLET_PROFILE", "treasry")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("GRAPHITE_WALLET_PROFILE"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut c = graphite();
    base(&mut c);
    let out = c
        .env("GRAPHITE_PLUGINS_DIR", dir.join("no-such-plugins-dir"))
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "an unloadable plugins dir must not be skipped"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("GRAPHITE_PLUGINS_DIR"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "rpc")]
#[test]
fn an_execution_check_that_cannot_run_is_not_a_pass() {
    let dir = scratch("execution");
    let out = graphite()
        .env("GRAPHITE_DATA_DIR", dir.join("data"))
        .args(["execution", "--signature"])
        .arg(bs58::encode([7u8; 64]).into_string())
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(3),
        "no RPC endpoint: unavailable, not 0 and not the discrepancy's 1: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
