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
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard};

/// Forks and writer lifetimes, one at a time (Round 35). A `graphite` child
/// holds a copy of every descriptor this test process has open from its fork
/// to its exec — a sibling test's writer lock included — so a writer opened
/// in that window was refused as a second writer (1 of 200 parallel runs).
/// The product never spawns a process; this is the harness's own race.
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
fn an_unkeyed_trail_exits_4_under_a_key_until_it_is_adopted() {
    let dir = temp_dir("adopt");
    let guard = fork_guard();
    let log = AuditLog::open(audit_path(&dir)).unwrap();
    for i in 0..3 {
        assert!(log.append(&rec(i)));
    }
    drop(log);
    drop(guard);
    let (key_path, key) = key_file("adopt", 41);
    let key_arg = key_path.to_str().unwrap();

    // Unkeyed and walked without a key: what an unkeyed trail proves.
    assert_eq!(verify(&dir, &[]).0, 0);
    // Under a key, the unkeyed records are not covered: 4, and said so.
    let (code, out) = verify(&dir, &["--key-file", key_arg]);
    assert_eq!(code, 4, "{out}");
    assert!(out.contains("UNKEYED"), "{out}");

    // A keyed server refuses to resume onto the unkeyed head.
    let guard = fork_guard();
    let refused = AuditLog::open_with_options(
        audit_path(&dir),
        AuditOptions {
            key: Some(key.clone()),
            ..AuditOptions::default()
        },
    );
    assert!(refused.is_err());
    drop(refused);
    drop(guard);

    // The operator adopts the key.
    let out = run(graphite()
        .args(["audit", "adopt-key", "--data-dir"])
        .arg(&dir)
        .args(["--key-file", key_arg]));
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
    let again = run(graphite()
        .args(["audit", "adopt-key", "--data-dir"])
        .arg(&dir)
        .args(["--key-file", key_arg]));
    assert_eq!(again.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&again.stdout).contains("nothing to adopt"));

    // The server now resumes under the key.
    let guard = fork_guard();
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
    drop(guard);
    assert_eq!(verify(&dir, &["--key-file", key_arg]).0, 0);
}

#[test]
fn adopt_key_refuses_a_broken_trail_and_a_running_writer() {
    let dir = temp_dir("broken");
    let (key_path, _) = key_file("broken", 42);
    // One guard over the writer and its own child: the child must see this
    // writer's lock, and no other test's.
    let guard = fork_guard();
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
    drop(guard);

    let path = audit_path(&dir);
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        text.replacen("\"approved\":true", "\"approved\":false", 1),
    )
    .unwrap();
    let out = run(graphite()
        .args(["audit", "adopt-key", "--data-dir"])
        .arg(&dir)
        .arg("--key-file")
        .arg(&key_path));
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("broken"));
    // Nothing was written.
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 3);
}

/// A torn write a pre-Round-34 writer left (terminated, nothing naming it)
/// is a break until `graphite audit acknowledge-tear` names it; a line that
/// is not that tear is refused.
#[test]
fn acknowledge_tear_clears_exactly_the_tear_it_names() {
    let dir = temp_dir("tear");
    let (key_path, key) = key_file("tear", 43);
    let key_arg = key_path.to_str().unwrap();
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
    for i in 0..4 {
        assert!(log.append(&rec(i)));
    }
    drop(log);
    drop(guard);
    let path = audit_path(&dir);
    let text = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    let half = &lines[1][..lines[1].len() / 2];
    lines.insert(2, half);
    let offset = lines[0].len() + lines[1].len() + 2;
    std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

    let (code, out) = verify(&dir, &["--key-file", key_arg]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("TEAR"), "{out}");

    let ack = |off: usize| {
        run(graphite()
            .args(["audit", "acknowledge-tear", "--data-dir"])
            .arg(&dir)
            .args(["--file", "audit.jsonl", "--offset", &off.to_string()])
            .args(["--key-file", key_arg]))
    };
    // Not the tear: the first record.
    let wrong = ack(0);
    assert_eq!(wrong.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("no unacknowledged torn write"));
    let right = ack(offset);
    assert_eq!(
        right.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&right.stderr)
    );
    let (code, out) = verify(&dir, &["--key-file", key_arg]);
    assert_eq!(code, 0, "{out}");
}
