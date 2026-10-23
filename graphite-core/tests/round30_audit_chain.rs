//! Round 30 (G-07): `graphite audit verify` and `graphite audit checkpoint`,
//! through the real binary, against a trail the library wrote.
//!
//! The exit codes are the interface a monitoring job reads: 0 nothing
//! failed, 1 a break or a checkpoint that does not hold, 2 the walk could
//! not prove what it was asked to, 3 the trail could not be read.
#![cfg(feature = "cli")]

use graphite_core::durable::{
    audit_path, AuditKey, AuditLog, AuditOptions, AuditRecord, LifecycleEvent,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard};

/// Forks and writer lifetimes, one at a time (Round 35). A `graphite` child
/// holds a copy of every descriptor this test process has open from its fork
/// to its exec — a sibling test's writer lock included — so a writer that
/// dropped its log and opened it again in that window was refused as a
/// second writer (6 of 200 parallel runs; 0 of 200 serial). The product never
/// spawns a process; this is the harness's own race.
static FORK: Mutex<()> = Mutex::new(());

fn fork_guard() -> MutexGuard<'static, ()> {
    FORK.lock().unwrap_or_else(|e| e.into_inner())
}

/// `Command::output` under the fork guard.
fn run(c: &mut Command) -> Output {
    let _g = fork_guard();
    c.output().unwrap()
}

fn graphite() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_graphite"));
    for k in [
        "GRAPHITE_DATA_DIR",
        "GRAPHITE_AUDIT_KEY_FILE",
        "GRAPHITE_AUDIT_ANCHOR_DIR",
    ] {
        c.env_remove(k);
    }
    c
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "graphite-r30-chain-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn key_file(tag: &str) -> (PathBuf, AuditKey) {
    let path = temp_dir(&format!("key-{tag}")).join("audit.key");
    std::fs::write(&path, "ab".repeat(32)).unwrap();
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
        confidence: 0.9,
        risk_status: "Clear".into(),
        policy_verdict: "Approved".into(),
        l3_status: "passed".into(),
        l8_status: "inconclusive".into(),
        wallet_profile: None,
    }
}

fn keyed_trail(dir: &Path, key: &AuditKey, n: usize, rotate_bytes: u64) {
    let _g = fork_guard();
    let log = AuditLog::open_with_options(
        audit_path(dir),
        AuditOptions {
            rotate_bytes,
            key: Some(key.clone()),
            ..AuditOptions::default()
        },
    )
    .unwrap();
    for i in 0..n {
        assert!(log.append(&rec(i)));
    }
}

fn verify(dir: &Path, extra: &[&str]) -> (i32, String) {
    let out = run(graphite()
        .args(["audit", "verify", "--data-dir"])
        .arg(dir)
        .args(extra));
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn verify_exits_by_what_the_walk_proved() {
    let dir = temp_dir("verify");
    let (key_path, key) = key_file("verify");
    keyed_trail(&dir, &key, 30, 1_500);
    let key_arg = key_path.to_str().unwrap();

    let (code, out) = verify(&dir, &["--key-file", key_arg]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("TamperEvident"), "{out}");

    // Without the key the MACs cannot be checked: 2, never 0.
    let (code, out) = verify(&dir, &[]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("CorruptionEvident"));

    // The key through the environment, as the server takes it.
    let out = run(graphite()
        .args(["audit", "verify", "--json", "--data-dir"])
        .arg(&dir)
        .env("GRAPHITE_AUDIT_KEY_FILE", &key_path));
    assert_eq!(out.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["integrity"], "tamper_evident");
    assert_eq!(report["chained_records"], 30);

    // An edited record anywhere: 1, and the break is named.
    // (In an archive: the active file may be empty right after a rotation.)
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| {
            std::fs::read_to_string(p)
                .map(|t| t.contains("\"approved\":true"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    let target = &files[0];
    let text = std::fs::read_to_string(target).unwrap();
    std::fs::write(
        target,
        text.replacen("\"approved\":true", "\"approved\":false", 1),
    )
    .unwrap();
    let (code, out) = verify(&dir, &["--key-file", key_arg]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("BREAK"), "{out}");
}

#[test]
fn a_checkpoint_exported_by_the_cli_catches_a_stale_restore() {
    let dir = temp_dir("checkpoint");
    let (key_path, key) = key_file("checkpoint");
    keyed_trail(&dir, &key, 3, 0);
    let backup = std::fs::read(audit_path(&dir)).unwrap();
    // Appending more, from a fresh writer (the first one was dropped).
    let guard = fork_guard();
    let log = AuditLog::open_with_options(
        audit_path(&dir),
        AuditOptions {
            rotate_bytes: 0,
            key: Some(key.clone()),
            ..AuditOptions::default()
        },
    )
    .unwrap();
    for i in 3..6 {
        assert!(log.append(&rec(i)));
    }
    drop(log);
    drop(guard);

    let cp = temp_dir("checkpoint-out").join("cp.json");
    let out = run(graphite()
        .args(["audit", "checkpoint", "--data-dir"])
        .arg(&dir)
        .arg("--key-file")
        .arg(&key_path)
        .arg("--out")
        .arg(&cp));
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Never over an existing file.
    let again = run(graphite()
        .args(["audit", "checkpoint", "--data-dir"])
        .arg(&dir)
        .arg("--out")
        .arg(&cp));
    assert_ne!(again.status.code(), Some(0));

    let cp_arg = cp.to_str().unwrap();
    let key_arg = key_path.to_str().unwrap();
    assert_eq!(
        verify(&dir, &["--key-file", key_arg, "--checkpoint", cp_arg]).0,
        0
    );

    // The restore: a valid chain on its own, caught against the checkpoint.
    std::fs::write(audit_path(&dir), &backup).unwrap();
    assert_eq!(verify(&dir, &["--key-file", key_arg]).0, 0);
    let (code, out) = verify(&dir, &["--key-file", key_arg, "--checkpoint", cp_arg]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("Truncated"), "{out}");
}

#[test]
fn a_trail_with_no_chained_record_cannot_be_proved() {
    let dir = temp_dir("legacy");
    let line = serde_json::to_string(&rec(0)).unwrap();
    std::fs::write(audit_path(&dir), format!("{line}\n")).unwrap();
    let (code, out) = verify(&dir, &[]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("LegacyUnchained"));
}
