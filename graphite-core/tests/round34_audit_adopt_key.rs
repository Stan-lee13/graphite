//! Round 34: `graphite audit verify` exit 4 and `graphite audit adopt-key`,
//! through the real binary, against trails the library wrote.
//!
//! Exit codes (docs/ops/keys.md): 0 nothing failed, 1 a break or a
//! checkpoint that does not hold, 2 the walk could not prove what it was
//! asked to, 3 the trail could not be read, 4 keys were supplied and
//! something is not covered by them.
#![cfg(feature = "cli")]

use graphite_core::durable::{
    audit_path, AuditKey, AuditLog, AuditOptions, AuditRecord, LifecycleEvent,
};
use std::path::{Path, PathBuf};
use std::process::Command;

fn graphite() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_graphite"));
    for k in [
        "GRAPHITE_DATA_DIR",
        "GRAPHITE_AUDIT_KEY_FILE",
        "GRAPHITE_AUDIT_PREVIOUS_KEY_FILE",
        "GRAPHITE_AUDIT_ANCHOR_DIR",
    ] {
        c.env_remove(k);
    }
    c
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "graphite-r34-adopt-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn key_file(tag: &str, byte: u8) -> (PathBuf, AuditKey) {
    let path = temp_dir(&format!("key-{tag}")).join("audit.key");
    std::fs::write(&path, hex::encode([byte; 32])).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let key = AuditKey::load(&path, None).unwrap();
    (path, key)
}

fn rec(i: usize) -> AuditRecord {
    AuditRecord {
        event_type: LifecycleEvent::Verification,
        timestamp: "2026-10-22T00:00:00.000Z".into(),
        audit_trail_id: format!("gr-{i}"),
        content_hash: format!("ch-{i}"),
        transaction_sha256: None,
        program_id: "11111111111111111111111111111111".into(),
        instruction_name: "transfer".into(),
        protocol_name: "system-program".into(),
        manifest_version: None,
        approved: true,
        decision: None,
        executable: None,
        confidence: 0.731_234_987_123_4,
        risk_status: "Clear".into(),
        policy_verdict: "Approved".into(),
        l3_status: "passed".into(),
        l8_status: "inconclusive".into(),
        wallet_profile: None,
    }
}

fn verify(dir: &Path, extra: &[&str]) -> (i32, String) {
    let out = graphite()
        .args(["audit", "verify", "--data-dir"])
        .arg(dir)
        .args(extra)
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn an_unkeyed_trail_exits_4_under_a_key_until_it_is_adopted() {
    let dir = temp_dir("adopt");
    let log = AuditLog::open(audit_path(&dir)).unwrap();
    for i in 0..3 {
        assert!(log.append(&rec(i)));
    }
    drop(log);
    let (key_path, key) = key_file("adopt", 41);
    let key_arg = key_path.to_str().unwrap();

    // Unkeyed and walked without a key: what an unkeyed trail proves.
    assert_eq!(verify(&dir, &[]).0, 0);
    // Under a key, the unkeyed records are not covered: 4, and said so.
    let (code, out) = verify(&dir, &["--key-file", key_arg]);
    assert_eq!(code, 4, "{out}");
    assert!(out.contains("UNKEYED"), "{out}");

    // A keyed server refuses to resume onto the unkeyed head.
    let refused = AuditLog::open_with_options(
        audit_path(&dir),
        AuditOptions {
            key: Some(key.clone()),
            ..AuditOptions::default()
        },
    );
    assert!(refused.is_err());

    // The operator adopts the key.
    let out = graphite()
        .args(["audit", "adopt-key", "--data-dir"])
        .arg(&dir)
        .args(["--key-file", key_arg])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let (code, out) = verify(&dir, &["--key-file", key_arg]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("TamperEvident"), "{out}");
    assert!(out.contains(key.id()), "{out}");

    // A second adoption has nothing to do.
    let again = graphite()
        .args(["audit", "adopt-key", "--data-dir"])
        .arg(&dir)
        .args(["--key-file", key_arg])
        .output()
        .unwrap();
    assert_eq!(again.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&again.stdout).contains("nothing to adopt"));

    // The server now resumes under the key.
    let log = AuditLog::open_with_options(
        audit_path(&dir),
        AuditOptions {
            key: Some(key.clone()),
            ..AuditOptions::default()
        },
    )
    .unwrap();
    assert!(log.append(&rec(3)));
    drop(log);
    assert_eq!(verify(&dir, &["--key-file", key_arg]).0, 0);
}

#[test]
fn adopt_key_refuses_a_broken_trail_and_a_running_writer() {
    let dir = temp_dir("broken");
    let (key_path, _) = key_file("broken", 42);
    let log = AuditLog::open(audit_path(&dir)).unwrap();
    for i in 0..3 {
        assert!(log.append(&rec(i)));
    }
    // A writer holds the trail: refused.
    let out = graphite()
        .args(["audit", "adopt-key", "--data-dir"])
        .arg(&dir)
        .arg("--key-file")
        .arg(&key_path)
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
    drop(log);

    let path = audit_path(&dir);
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        text.replacen("\"approved\":true", "\"approved\":false", 1),
    )
    .unwrap();
    let out = graphite()
        .args(["audit", "adopt-key", "--data-dir"])
        .arg(&dir)
        .arg("--key-file")
        .arg(&key_path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("broken"));
    // Nothing was written.
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 3);
}
