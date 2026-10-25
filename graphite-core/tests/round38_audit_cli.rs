//! Round 38 (R37-14, T-12, T-13, T-14): `graphite audit` exit codes and
//! refusals through the real binary, against trails the library wrote.
//!
//! 0 nothing failed, 1 a break, 2 unproven, 3 the trail, a key file or a
//! checkpoint could not be read, 4 keys supplied that do not cover the
//! trail, 64 a usage error (docs/ops/keys.md).
#![cfg(feature = "cli")]

use graphite_core::durable::{
    audit_path, AuditKey, AuditLog, AuditOptions, AuditRecord, LifecycleEvent,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard};

/// Forks and writer lifetimes, one at a time (as round30_audit_chain.rs).
static FORK: Mutex<()> = Mutex::new(());

fn fork_guard() -> MutexGuard<'static, ()> {
    FORK.lock().unwrap_or_else(|e| e.into_inner())
}

fn run(c: &mut Command) -> Output {
    let _g = fork_guard();
    c.output().unwrap()
}

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
        "graphite-r39-{tag}-{}-{}",
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
    std::fs::write(&path, hex_of(byte)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let key = AuditKey::load(&path, None).unwrap();
    (path, key)
}

fn hex_of(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn rec(i: usize) -> AuditRecord {
    AuditRecord {
        event_type: LifecycleEvent::Verification,
        timestamp: "2026-10-24T00:00:00.000Z".into(),
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

fn trail(dir: &Path, key: Option<&AuditKey>, n: usize, rotate_bytes: u64) {
    let _g = fork_guard();
    let log = AuditLog::open_with_options(
        audit_path(dir),
        AuditOptions {
            rotate_bytes,
            key: key.cloned(),
            ..AuditOptions::default()
        },
    )
    .unwrap();
    for i in 0..n {
        assert!(log.append(&rec(i)));
    }
}

fn audit(dir: &Path, args: &[&str]) -> (i32, String) {
    let out = run(graphite()
        .arg("audit")
        .args(args)
        .arg("--data-dir")
        .arg(dir));
    (
        out.status.code().unwrap(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// T-12: keys supplied, and the trail under none of them, exits 4.
#[test]
fn verify_under_a_key_the_trail_is_not_under_exits_4() {
    let dir = temp_dir("t12");
    let (_, k1) = key_file("t12", 0x31);
    let (other, _) = key_file("t12-other", 0x32);
    trail(&dir, Some(&k1), 3, 0);
    let (code, out) = audit(&dir, &["verify", "--key-file", other.to_str().unwrap()]);
    assert_eq!(code, 4, "{out}");
}

/// T-13: `audit checkpoint` signs only a head the keys given cover, and
/// signs it under the key the head is under.
#[test]
fn checkpoint_refuses_a_head_the_keys_do_not_cover() {
    let dir = temp_dir("t13");
    let (k1_path, k1) = key_file("t13", 0x33);
    let (other, _) = key_file("t13-other", 0x34);
    trail(&dir, Some(&k1), 3, 0);
    let out_dir = temp_dir("t13-out");
    // Under a key the trail is not under: the head's MAC was never checked.
    let cp = out_dir.join("cp-other.json");
    let (code, out) = audit(
        &dir,
        &[
            "checkpoint",
            "--key-file",
            other.to_str().unwrap(),
            "--out",
            cp.to_str().unwrap(),
        ],
    );
    assert_ne!(code, 0, "{out}");
    assert!(
        !cp.exists(),
        "a checkpoint of an unchecked head was written"
    );
    // A keyed trail and no key: an unsigned checkpoint would confirm nothing.
    let cp = out_dir.join("cp-none.json");
    let (code, out) = audit(&dir, &["checkpoint", "--out", cp.to_str().unwrap()]);
    assert_ne!(code, 0, "{out}");
    assert!(
        !cp.exists(),
        "an unsigned checkpoint of a keyed trail was written"
    );
    // The trail's key: written, MAC'd under it, and it confirms the trail.
    let cp = out_dir.join("cp-k1.json");
    let (code, out) = audit(
        &dir,
        &[
            "checkpoint",
            "--key-file",
            k1_path.to_str().unwrap(),
            "--out",
            cp.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "{out}");
    let (code, out) = audit(
        &dir,
        &[
            "verify",
            "--key-file",
            k1_path.to_str().unwrap(),
            "--checkpoint",
            cp.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "{out}");
}

/// T-14: a key file or a checkpoint that cannot be read is exit 3 (the check
/// could not be made), never 1 (a break); a usage error is 64, never 2
/// (unproven).
#[test]
fn audit_exit_codes_tell_an_unreadable_input_and_a_usage_error_from_a_verdict() {
    let dir = temp_dir("t14");
    let (k1_path, k1) = key_file("t14", 0x35);
    trail(&dir, Some(&k1), 2, 0);
    let missing = dir.join("no-such.key");
    let (code, out) = audit(&dir, &["verify", "--key-file", missing.to_str().unwrap()]);
    assert_eq!(code, 3, "{out}");
    let bad_cp = dir.join("not-a-checkpoint.json");
    std::fs::write(&bad_cp, "not json").unwrap();
    let (code, out) = audit(
        &dir,
        &[
            "verify",
            "--key-file",
            k1_path.to_str().unwrap(),
            "--checkpoint",
            bad_cp.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 3, "{out}");
    let (code, out) = audit(&dir, &["verify", "--no-such-flag"]);
    assert_eq!(code, 64, "{out}");
    let (code, out) = audit(
        &dir,
        &["checkpoint", "--key-file", missing.to_str().unwrap()],
    );
    assert_eq!(code, 3, "{out}");
}

/// R37-14: `graphite audit acknowledge-prune` writes the prune record a
/// trail pruned before Round 38 lacks, and refuses anything else.
#[test]
fn acknowledge_prune_accepts_only_a_missing_prune_record() {
    let dir = temp_dir("r37-14");
    let (k_path, key) = key_file("r37-14", 0x36);
    trail(&dir, Some(&key), 40, 1_500);
    let k = k_path.to_str().unwrap();
    // Nothing to acknowledge yet.
    let (code, out) = audit(&dir, &["acknowledge-prune", "--key-file", k]);
    assert_ne!(code, 0, "{out}");
    let mut archives: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("audit.jsonl.") && !n.ends_with(".lock"))
        })
        .collect();
    archives.sort();
    assert!(archives.len() >= 2);
    std::fs::remove_file(&archives[0]).unwrap();
    let (code, out) = audit(&dir, &["verify", "--key-file", k]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("acknowledge-prune"), "{out}");
    let (code, out) = audit(&dir, &["acknowledge-prune", "--key-file", k]);
    assert_eq!(code, 0, "{out}");
    let (code, out) = audit(&dir, &["verify", "--key-file", k]);
    assert_eq!(code, 0, "{out}");
}
