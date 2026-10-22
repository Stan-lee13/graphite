//! The audit trail's hash chain end to end (Round 30, G-07): every way a
//! trail can be altered, and what each integrity mode does and does not
//! catch.

use super::*;

fn rec(id: &str, approved: bool) -> AuditRecord {
    AuditRecord {
        event_type: LifecycleEvent::Verification,
        timestamp: "2026-10-22T00:00:00.000Z".to_string(),
        audit_trail_id: id.to_string(),
        content_hash: format!("ch-{id}"),
        transaction_sha256: Some(format!("{:0>64}", id.len())),
        program_id: "11111111111111111111111111111111".to_string(),
        instruction_name: "transfer".to_string(),
        protocol_name: "system-program".to_string(),
        manifest_version: None,
        approved,
        decision: None,
        executable: None,
        confidence: 0.9,
        risk_status: "Clear".to_string(),
        policy_verdict: "Approved".to_string(),
        l3_status: "passed".to_string(),
        l8_status: "inconclusive".to_string(),
        wallet_profile: None,
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "graphite-chain-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A key file outside `data`, mode 600, holding `byte` repeated.
fn key_file(tag: &str, byte: u8) -> (PathBuf, AuditKey) {
    let dir = temp_dir(&format!("key-{tag}"));
    let path = dir.join("audit.key");
    std::fs::write(&path, hex::encode([byte; 32])).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let key = AuditKey::load(&path, None).unwrap();
    (path, key)
}

fn keyed(path: &Path, key: &AuditKey, rotate_bytes: u64) -> AuditLog {
    AuditLog::open_with_options(
        path,
        AuditOptions {
            rotate_bytes,
            key: Some(key.clone()),
            ..AuditOptions::default()
        },
    )
    .unwrap()
}

/// Drop a writer once no background job holds it, so its lock is free for
/// the next one.
fn close(log: AuditLog) {
    log.wait_for_index_jobs();
    drop(log);
}

fn write_n(log: &AuditLog, from: usize, n: usize) {
    for i in from..from + n {
        assert!(log.append(&rec(&format!("gr-{i:05}"), i % 3 != 0)));
    }
}

/// Every file of the trail, oldest first: archives, then the active file.
fn trail_files(path: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = archives_of(path).into_iter().map(|(_, p)| p).collect();
    files.push(path.to_path_buf());
    files
}

fn lines_of(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

fn write_lines(path: &Path, lines: &[String]) {
    let mut text = lines.join("\n");
    text.push('\n');
    std::fs::write(path, text).unwrap();
}

fn verify(path: &Path, keys: &[AuditKey]) -> TrailReport {
    verify_audit_trail(path, keys, None).unwrap()
}

/// Recompute `chain` for every chained line from `from` on, the way a
/// writer without the key would: hashes right, MACs dropped.
fn rechain_without_key(lines: &mut [String], from: usize) {
    let mut head = {
        let v: serde_json::Value = serde_json::from_str(&lines[from - 1]).unwrap();
        let link: ChainLink = serde_json::from_value(v[CHAIN_FIELD].clone()).unwrap();
        chain::ChainHead {
            next_seq: link.seq + 1,
            prev: hex::decode(&link.hash).unwrap().try_into().unwrap(),
            keyed: false,
        }
    };
    for line in lines.iter_mut().skip(from) {
        let serde_json::Value::Object(map) = serde_json::from_str(line).unwrap() else {
            panic!()
        };
        let (sealed, next) = chain::seal(map, &head, None);
        *line = sealed;
        head = next;
    }
}

#[test]
fn a_keyed_trail_verifies_across_rotation() {
    let dir = temp_dir("rotation");
    let path = audit_path(&dir);
    let (_, key) = key_file("rotation", 1);
    let log = keyed(&path, &key, 2_000);
    write_n(&log, 0, 60);
    assert!(log.health().rotations_ok >= 3, "{:?}", log.health());
    let report = verify(&path, std::slice::from_ref(&key));
    assert_eq!(report.integrity, Integrity::TamperEvident, "{report:?}");
    assert_eq!(report.chained_records, 60);
    assert_eq!(report.macs_verified, 60);
    assert_eq!((report.first_seq, report.head_seq), (Some(0), Some(59)));
    assert!(report.files.len() >= 4);
    assert!(report.intact());
    assert_eq!(log.health().chain_head_seq, Some(59));
    assert!(log.health().tamper_evident);
    // The writer's own view of the head is the one the walk found.
    let cp = log.checkpoint().unwrap();
    assert_eq!(
        (cp.seq, Some(cp.hash.clone())),
        (59, report.head_hash.clone())
    );
    assert_eq!(cp.mac_verifies(std::slice::from_ref(&key)), Some(true));
}

#[test]
fn every_alteration_of_a_record_breaks_the_chain() {
    let dir = temp_dir("alter");
    let path = audit_path(&dir);
    let (_, key) = key_file("alter", 2);
    let log = keyed(&path, &key, 0);
    write_n(&log, 0, 10);
    close(log);
    let original = lines_of(&path);
    let keys = std::slice::from_ref(&key);

    let cases: Vec<(&str, Vec<String>, &str)> = vec![
        (
            "deleted",
            {
                let mut l = original.clone();
                l.remove(4);
                l
            },
            "where 4 was expected",
        ),
        (
            "duplicated",
            {
                let mut l = original.clone();
                l.insert(5, original[4].clone());
                l
            },
            "where 5 was expected",
        ),
        (
            "reordered",
            {
                let mut l = original.clone();
                l.swap(3, 6);
                l
            },
            "where 3 was expected",
        ),
        (
            "edited",
            {
                let mut l = original.clone();
                l[5] = l[5].replacen("\"approved\":true", "\"approved\":false", 1);
                assert_ne!(l[5], original[5]);
                l
            },
            "does not match its own chain hash",
        ),
        (
            "unchained insert",
            {
                let mut l = original.clone();
                l.insert(7, serde_json::to_string(&rec("gr-forged", true)).unwrap());
                l
            },
            "without a chain link after chained records",
        ),
        (
            "rechained without the key",
            {
                let mut l = original.clone();
                l[5] = l[5].replacen("\"approved\":true", "\"approved\":false", 1);
                rechain_without_key(&mut l, 5);
                l
            },
            "without a MAC after MAC'd records",
        ),
        (
            "rechained, old MACs kept",
            {
                let mut l = original.clone();
                l[5] = l[5].replacen("\"approved\":true", "\"approved\":false", 1);
                let macs: Vec<serde_json::Value> = original
                    .iter()
                    .map(|s| {
                        serde_json::from_str::<serde_json::Value>(s).unwrap()[CHAIN_FIELD].clone()
                    })
                    .collect();
                rechain_without_key(&mut l, 5);
                for (i, line) in l.iter_mut().enumerate().skip(5) {
                    let mut v: serde_json::Value = serde_json::from_str(line).unwrap();
                    v[CHAIN_FIELD]["key_id"] = macs[i]["key_id"].clone();
                    v[CHAIN_FIELD]["mac"] = macs[i]["mac"].clone();
                    *line = v.to_string();
                }
                l
            },
            "does not verify",
        ),
    ];
    for (name, lines, expected) in cases {
        write_lines(&path, &lines);
        let report = verify(&path, keys);
        let b = report
            .first_break
            .as_ref()
            .unwrap_or_else(|| panic!("{name}: not caught: {report:?}"));
        assert!(b.reason.contains(expected), "{name}: {b:?}");
        assert_eq!(report.integrity, Integrity::Broken, "{name}");
        assert!(!report.intact());
    }
    // And the original verifies.
    write_lines(&path, &original);
    assert!(verify(&path, keys).intact());
}

#[test]
fn an_unkeyed_trail_is_only_corruption_evident_and_an_anchored_checkpoint_catches_the_rewrite() {
    let dir = temp_dir("unkeyed");
    let path = audit_path(&dir);
    let log = AuditLog::open(&path).unwrap();
    write_n(&log, 0, 8);
    assert!(!log.health().tamper_evident);
    let cp = log.checkpoint().unwrap();
    assert!(cp.mac.is_none());
    close(log);
    let report = verify(&path, &[]);
    assert_eq!(report.integrity, Integrity::CorruptionEvident);
    assert_eq!(report.unkeyed_records, 8);

    // The limit, stated as a test: a writer who recomputes the chain
    // rewrites an unkeyed trail coherently.
    let mut lines = lines_of(&path);
    lines[2] = lines[2].replacen("\"approved\":true", "\"approved\":false", 1);
    rechain_without_key(&mut lines, 2);
    write_lines(&path, &lines);
    let rewritten = verify(&path, &[]);
    assert!(rewritten.intact(), "{rewritten:?}");
    assert_eq!(rewritten.integrity, Integrity::CorruptionEvident);

    // Against the checkpoint exported before the rewrite, it is caught.
    let anchored = verify_audit_trail(&path, &[], Some(&cp)).unwrap();
    assert_eq!(anchored.checkpoint, Some(CheckpointStatus::Rewritten));
    assert!(!anchored.intact());
}

#[test]
fn truncation_and_a_stale_restore_are_caught_only_against_a_checkpoint() {
    let dir = temp_dir("truncate");
    let path = audit_path(&dir);
    let (_, key) = key_file("truncate", 3);
    let keys = std::slice::from_ref(&key);
    let log = keyed(&path, &key, 0);
    write_n(&log, 0, 5);
    close(log);
    // A backup taken now…
    let backup = std::fs::read(&path).unwrap();
    let log = keyed(&path, &key, 0);
    write_n(&log, 5, 5);
    // …and a checkpoint anchored after it.
    let cp = log.checkpoint().unwrap();
    assert_eq!(cp.seq, 9);
    close(log);

    // Dropping the newest records leaves a valid chain: verify alone
    // cannot know the trail was longer.
    let mut lines = lines_of(&path);
    lines.truncate(7);
    write_lines(&path, &lines);
    assert!(verify(&path, keys).intact());
    let against = verify_audit_trail(&path, keys, Some(&cp)).unwrap();
    assert_eq!(
        against.checkpoint,
        Some(CheckpointStatus::Truncated { head_seq: Some(6) })
    );
    assert!(!against.intact());

    // Restoring the older backup: the same.
    std::fs::write(&path, &backup).unwrap();
    let restored = verify_audit_trail(&path, keys, Some(&cp)).unwrap();
    assert_eq!(
        restored.checkpoint,
        Some(CheckpointStatus::Truncated { head_seq: Some(4) })
    );

    // A forged checkpoint (its seq moved back to fit the restore) does not
    // carry a MAC that verifies.
    let mut forged = cp.clone();
    forged.seq = 4;
    let r = verify_audit_trail(&path, keys, Some(&forged)).unwrap();
    assert_eq!(r.checkpoint, Some(CheckpointStatus::ForgedCheckpoint));
}

#[test]
fn a_substituted_archive_breaks_the_chain_and_an_index_is_never_consulted() {
    let dir = temp_dir("substitute");
    let path = audit_path(&dir);
    let (_, key) = key_file("substitute", 4);
    let keys = std::slice::from_ref(&key);
    let log = keyed(&path, &key, 1_500);
    write_n(&log, 0, 40);
    close(log);
    let files = trail_files(&path);
    assert!(files.len() >= 4);

    // Every index file replaced with garbage: the walk does not read them.
    let index_dir = dir.join("audit.jsonl-index");
    let mut indexes = 0;
    if let Ok(entries) = std::fs::read_dir(&index_dir) {
        for e in entries.flatten() {
            std::fs::write(e.path(), b"forged index").unwrap();
            indexes += 1;
        }
    }
    assert!(indexes > 0, "the rotated archives were indexed");
    assert_eq!(verify(&path, keys).integrity, Integrity::TamperEvident);

    // An archive from ANOTHER trail written under the same key, put in
    // place of a real one: the chain does not continue through it.
    let other_dir = temp_dir("substitute-other");
    let other_path = audit_path(&other_dir);
    let other = keyed(&other_path, &key, 1_500);
    write_n(&other, 1000, 40);
    close(other);
    let other_files = trail_files(&other_path);
    std::fs::copy(&other_files[1], &files[1]).unwrap();
    let report = verify(&path, keys);
    assert_eq!(report.integrity, Integrity::Broken, "{report:?}");
    let b = report.first_break.unwrap();
    assert_eq!(b.file, files[1].file_name().unwrap().to_string_lossy());
}

#[test]
fn a_failed_append_does_not_advance_the_chain() {
    let dir = temp_dir("failed-append");
    let path = audit_path(&dir);
    let (_, key) = key_file("failed-append", 5);
    let log = keyed(&path, &key, 0);
    write_n(&log, 0, 3);

    // A write whose device sync fails: cut back, not acknowledged.
    log.faults.store(FAULT_SYNC, Ordering::SeqCst);
    assert!(!log.append(&rec("gr-lost", true)));
    log.faults.store(0, Ordering::SeqCst);
    assert_eq!(log.health().chain_head_seq, Some(2));
    write_n(&log, 3, 2);

    // A write that fails AND cannot be cut back (a disk that went full or
    // read-only): later appends are refused until the cut succeeds.
    log.faults
        .store(FAULT_SYNC | FAULT_TRUNCATE, Ordering::SeqCst);
    assert!(!log.append(&rec("gr-stuck", true)));
    log.faults.store(FAULT_TRUNCATE, Ordering::SeqCst);
    assert!(!log.append(&rec("gr-refused", true)));
    log.faults.store(0, Ordering::SeqCst);
    write_n(&log, 5, 2);
    let report = verify(&path, std::slice::from_ref(&key));
    assert!(report.intact(), "{report:?}");
    assert_eq!((report.chained_records, report.head_seq), (7, Some(6)));
    let text = std::fs::read_to_string(&path).unwrap();
    for gone in ["gr-lost", "gr-stuck", "gr-refused"] {
        assert!(!text.contains(gone), "{gone} is not in the trail");
    }
}

#[test]
fn a_torn_line_from_a_crash_is_reported_and_the_chain_resumes_past_it() {
    let dir = temp_dir("torn");
    let path = audit_path(&dir);
    let (_, key) = key_file("torn", 6);
    let log = keyed(&path, &key, 0);
    write_n(&log, 0, 3);
    close(log);
    // The crash: half a record, no newline.
    let mut text = std::fs::read_to_string(&path).unwrap();
    let half = lines_of(&path)[1].clone();
    text.push_str(&half[..half.len() / 2]);
    std::fs::write(&path, &text).unwrap();
    let before = verify(&path, std::slice::from_ref(&key));
    assert!(before.intact());
    assert_eq!(before.unparseable_lines, 1);

    let log = keyed(&path, &key, 0);
    write_n(&log, 3, 2);
    let after = verify(&path, std::slice::from_ref(&key));
    assert!(after.intact(), "{after:?}");
    assert_eq!((after.chained_records, after.unparseable_lines), (5, 1));
}

#[test]
fn a_rotated_key_verifies_with_both_keys_and_a_lost_key_cannot_continue_the_trail() {
    let dir = temp_dir("rotate-key");
    let path = audit_path(&dir);
    let (_, old) = key_file("rotate-old", 7);
    let (_, new) = key_file("rotate-new", 8);
    let log = keyed(&path, &old, 0);
    write_n(&log, 0, 4);
    close(log);
    // Round 34 (R33-13): re-pinned. Restarting under the new key alone used
    // to resume onto a head MAC'd under any other key id — the same thing a
    // rewrite under an invented key id looks like. A rotation now gives the
    // writer the previous key, which checks the head under it and writes a
    // key-adoption record; without it the start is refused.
    let refused = keyed_with_previous(&path, &new, None).unwrap_err();
    assert!(
        refused
            .to_string()
            .contains("GRAPHITE_AUDIT_PREVIOUS_KEY_FILE"),
        "{refused}"
    );
    let log = keyed_with_previous(&path, &new, Some(&old)).unwrap();
    write_n(&log, 4, 4);
    close(log);

    // 4 records under the old key, the adoption record and 4 under the new.
    let both = verify(&path, &[old.clone(), new.clone()]);
    assert_eq!(both.integrity, Integrity::TamperEvident);
    assert_eq!(both.exit_code(), 0);
    assert_eq!(
        both.key_ids_seen,
        vec![old.id().to_string(), new.id().to_string()]
    );
    assert_eq!(both.key_adoptions, 1);
    let ranges: Vec<(&str, u64, u64, &str)> = both
        .key_ranges
        .iter()
        .map(|r| {
            (
                r.key_id.as_str(),
                r.first_seq,
                r.last_seq,
                r.introduced_by.as_str(),
            )
        })
        .collect();
    assert_eq!(
        ranges,
        vec![
            (old.id(), 0, 3, "first_keyed_record"),
            (new.id(), 4, 8, "adoption_checked")
        ]
    );
    let only_new = verify(&path, std::slice::from_ref(&new));
    assert_eq!(only_new.integrity, Integrity::CorruptionEvident);
    assert_eq!((only_new.macs_verified, only_new.macs_unverified), (5, 4));
    assert_eq!(only_new.exit_code(), 2);
    // The previous key may stay configured: once the head is under the new
    // key it is not consulted.
    close(keyed_with_previous(&path, &new, Some(&old)).unwrap());
    assert_eq!(verify(&path, &[old.clone(), new.clone()]).key_adoptions, 1);

    // The key is lost: the trail cannot be continued unkeyed (that would
    // be a silent downgrade), and a walk without it proves only the chain.
    let err = AuditLog::open(&path).unwrap_err();
    assert!(err.to_string().contains("no key is configured"), "{err}");
    let none = verify(&path, &[]);
    assert_eq!(none.integrity, Integrity::CorruptionEvident);
    assert_eq!(none.macs_unverified, 9);
}

fn keyed_with_previous(
    path: &Path,
    key: &AuditKey,
    previous: Option<&AuditKey>,
) -> std::io::Result<AuditLog> {
    AuditLog::open_with_options(
        path,
        AuditOptions {
            rotate_bytes: 0,
            key: Some(key.clone()),
            previous_key: previous.cloned(),
            ..AuditOptions::default()
        },
    )
}

#[test]
fn a_tampered_newest_record_is_refused_at_open() {
    let dir = temp_dir("tampered-head");
    let path = audit_path(&dir);
    let (_, key) = key_file("tampered-head", 9);
    let log = keyed(&path, &key, 0);
    write_n(&log, 0, 3);
    close(log);
    let mut lines = lines_of(&path);
    lines[2] = lines[2].replacen("transfer", "transfeR", 1);
    write_lines(&path, &lines);
    let err = AuditLog::open_with_options(
        &path,
        AuditOptions {
            key: Some(key.clone()),
            ..AuditOptions::default()
        },
    )
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains("does not match its own hash"),
        "{err}"
    );
}

#[test]
fn parallel_appends_keep_one_unbroken_chain() {
    let dir = temp_dir("parallel");
    let path = audit_path(&dir);
    let (_, key) = key_file("parallel", 10);
    let log = keyed(&path, &key, 4_000);
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let log = log.clone();
            std::thread::spawn(move || {
                for i in 0..50 {
                    assert!(log.append(&rec(&format!("gr-{t}-{i:03}"), i % 2 == 0)));
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let report = verify(&path, std::slice::from_ref(&key));
    assert!(report.intact(), "{report:?}");
    assert_eq!(report.chained_records, 400);
    assert_eq!(report.head_seq, Some(399));
    assert!(report.files.len() > 2);
}

#[test]
fn a_second_writer_is_refused_and_a_reader_runs_beside_the_writer() {
    let dir = temp_dir("single-writer");
    let path = audit_path(&dir);
    let writer = AuditLog::open(&path).unwrap();
    write_n(&writer, 0, 2);
    let second = AuditLog::open(&path).unwrap_err();
    assert_eq!(second.kind(), std::io::ErrorKind::WouldBlock);
    assert!(second.to_string().contains("held by another writer"));

    let reader = AuditLog::open_read_only(&path).unwrap();
    assert_eq!(reader.read_tail_filtered(10, AuditSelector::All).2, 2);
    assert!(!reader.append(&rec("gr-from-reader", true)));
    assert_eq!(reader.health().writes_failed, 1);
    write_n(&writer, 2, 1);
    assert!(verify(&path, &[]).intact());

    close(writer);
    let again = AuditLog::open(&path).unwrap();
    write_n(&again, 3, 1);
    let report = verify(&path, &[]);
    assert!(report.intact());
    assert_eq!(report.head_seq, Some(3));
    // A missing trail is not created by a reader.
    let empty = temp_dir("single-writer-empty");
    assert!(AuditLog::open_read_only(audit_path(&empty)).is_err());
    assert!(!audit_path(&empty).exists());
}

#[test]
fn legacy_records_stay_readable_and_are_never_counted_as_tamper_evident() {
    let dir = temp_dir("legacy");
    let path = audit_path(&dir);
    let legacy: Vec<String> = (0..3)
        .map(|i| serde_json::to_string(&rec(&format!("gr-old-{i}"), true)).unwrap())
        .collect();
    write_lines(&path, &legacy);
    let report = verify(&path, &[]);
    assert_eq!(report.integrity, Integrity::LegacyUnchained);
    assert_eq!(report.exit_code(), 2);

    let (_, key) = key_file("legacy", 11);
    let log = keyed(&path, &key, 0);
    // The legacy records are still read.
    assert_eq!(log.read_tail_filtered(10, AuditSelector::All).2, 3);
    write_n(&log, 0, 2);
    close(log);
    let report = verify(&path, std::slice::from_ref(&key));
    assert_eq!(report.integrity, Integrity::TamperEvident);
    assert_eq!(
        (report.legacy_unchained_records, report.chained_records),
        (3, 2)
    );
    // An unchained record AFTER the chain began is an insertion.
    let mut lines = lines_of(&path);
    lines.push(legacy[0].clone());
    write_lines(&path, &lines);
    assert_eq!(verify(&path, &[key]).integrity, Integrity::Broken);
}

#[test]
fn a_key_file_must_be_hex_private_and_outside_the_data_directory() {
    let data = temp_dir("keyfile-data");
    let outside = temp_dir("keyfile-outside");
    let good = outside.join("k");
    std::fs::write(&good, format!("{}\n", hex::encode([3u8; 32]))).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(AuditKey::load(&good, Some(&data)).is_ok());
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = AuditKey::load(&good, Some(&data)).unwrap_err();
        assert!(e.contains("chmod 600"), "{e}");
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let inside = data.join("k");
    std::fs::copy(&good, &inside).unwrap();
    let e = AuditKey::load(&inside, Some(&data)).unwrap_err();
    assert!(e.contains("inside the data directory"), "{e}");

    let not_hex = outside.join("n");
    std::fs::write(&not_hex, "correct horse battery staple correct horse").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&not_hex, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(AuditKey::load(&not_hex, None).unwrap_err().contains("hex"));

    // The environment values, as the server reads them.
    let base = AuditOptions::default();
    assert!(base
        .clone()
        .with_env_values(Some(" "), None, &data)
        .is_err());
    assert!(base.clone().with_env_values(None, Some(""), &data).is_err());
    assert!(base
        .clone()
        .with_env_values(None, Some(data.to_str().unwrap()), &data)
        .unwrap_err()
        .contains("inside the data directory"));
    let ok = base
        .with_env_values(good.to_str(), outside.to_str(), &data)
        .unwrap();
    assert!(ok.key.is_some() && ok.anchor_dir.is_some());
}

#[test]
fn rotation_writes_an_anchor_checkpoint_that_later_confirms_the_trail() {
    let dir = temp_dir("anchor");
    let anchor = temp_dir("anchor-dir");
    let path = audit_path(&dir);
    let (_, key) = key_file("anchor", 12);
    let log = AuditLog::open_with_options(
        &path,
        AuditOptions {
            rotate_bytes: 2_000,
            key: Some(key.clone()),
            anchor_dir: Some(anchor.clone()),
            ..AuditOptions::default()
        },
    )
    .unwrap();
    write_n(&log, 0, 30);
    let rotations = log.health().rotations_ok;
    let mut anchored: Vec<PathBuf> = std::fs::read_dir(&anchor)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    anchored.sort();
    assert_eq!(anchored.len() as u64, rotations);
    assert_eq!(log.health().anchors_failed, 0);
    close(log);
    for file in &anchored {
        let cp: Checkpoint = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
        let r = verify_audit_trail(&path, std::slice::from_ref(&key), Some(&cp)).unwrap();
        assert_eq!(r.checkpoint, Some(CheckpointStatus::Confirmed), "{file:?}");
    }

    // An anchor directory that went away: counted, and the trail goes on.
    let gone = temp_dir("anchor-gone");
    let log = AuditLog::open_with_options(
        &path,
        AuditOptions {
            rotate_bytes: 2_000,
            key: Some(key.clone()),
            anchor_dir: Some(gone.clone()),
            ..AuditOptions::default()
        },
    )
    .unwrap();
    std::fs::remove_dir_all(&gone).unwrap();
    write_n(&log, 30, 30);
    assert!(log.health().anchors_failed > 0);
    assert!(verify(&path, &[key]).intact());
}

#[test]
fn pruned_archives_leave_a_chain_that_starts_later_and_an_old_checkpoint_unconfirmable() {
    let dir = temp_dir("pruned");
    let path = audit_path(&dir);
    let (_, key) = key_file("pruned", 13);
    let log = AuditLog::open_with_options(
        &path,
        AuditOptions {
            rotate_bytes: 1_500,
            max_archives: 2,
            key: Some(key.clone()),
            ..AuditOptions::default()
        },
    )
    .unwrap();
    write_n(&log, 0, 3);
    let early = log.checkpoint().unwrap();
    write_n(&log, 3, 60);
    close(log);
    let report = verify_audit_trail(&path, std::slice::from_ref(&key), Some(&early)).unwrap();
    assert!(report.first_break.is_none(), "{report:?}");
    assert!(report.first_seq.unwrap() > 2);
    assert!(matches!(
        report.checkpoint,
        Some(CheckpointStatus::NotOnDisk { .. })
    ));
    assert_eq!(report.exit_code(), 2);
}

// ---------------------------------------------------------------------------
// Round 34: one line grammar for the chain walk and every reader, MAC
// downgrade, unsigned checkpoints, invented key ids, a walk beside a
// rotating writer.
// ---------------------------------------------------------------------------

const VICTIM_TX: &str = "abababababababababababababababababababababababababababababababab";

/// A forged approval of `VICTIM_TX`, built from a real line of the trail:
/// it keeps that line's chain link, which no longer matches its content.
fn forged_approval(template: &str) -> String {
    let mut v: serde_json::Value = serde_json::from_str(template).unwrap();
    v["transaction_sha256"] = VICTIM_TX.into();
    v["audit_trail_id"] = "gr-forged".into();
    v["approved"] = true.into();
    v["decision"] = "executable_approved".into();
    v["executable"] = true.into();
    v.to_string()
}

/// What a reader in a fresh process answers for the victim.
fn victim_seen_by_a_reader(path: &Path) -> Option<AuditRecord> {
    let reader = AuditLog::open_read_only(path).unwrap();
    let found = reader.find_verification(VerificationKey::TransactionSha256(VICTIM_TX));
    reader.wait_for_index_jobs();
    found
}

/// A keyed trail of `n` records across several archives.
fn rotated_keyed_trail(tag: &str, byte: u8, n: usize) -> (PathBuf, AuditKey, Vec<PathBuf>) {
    let dir = temp_dir(tag);
    let path = audit_path(&dir);
    let (_, key) = key_file(tag, byte);
    let log = keyed(&path, &key, 1_500);
    write_n(&log, 0, n);
    close(log);
    let archives: Vec<PathBuf> = archives_of(&path).into_iter().map(|(_, p)| p).collect();
    assert!(archives.len() >= 2, "{archives:?}");
    (path, key, archives)
}

fn name_of(p: &Path) -> String {
    p.file_name().unwrap().to_string_lossy().into_owned()
}

/// `forged_approval` with a link recomputed to match its content (no MAC):
/// a line the grammar alone does not refuse, so only the rule that a line
/// without its newline is never read keeps it from the readers.
fn resealed_forgery(template: &str) -> String {
    let serde_json::Value::Object(mut map) =
        serde_json::from_str(&forged_approval(template)).unwrap()
    else {
        panic!()
    };
    map.remove(CHAIN_FIELD);
    let head = chain::ChainHead {
        next_seq: 999,
        prev: [7u8; 32],
        keyed: false,
    };
    chain::seal(map, &head, None).0
}

#[test]
fn a_forged_unterminated_line_in_an_archive_breaks_the_chain_and_is_never_read() {
    let (path, key, archives) = rotated_keyed_trail("forged-unterminated", 21, 30);
    let template = lines_of(&archives[0])[0].clone();
    let mut bytes = std::fs::read(&archives[0]).unwrap();
    bytes.extend_from_slice(resealed_forgery(&template).as_bytes());
    std::fs::write(&archives[0], bytes).unwrap();

    let report = verify(&path, std::slice::from_ref(&key));
    assert_ne!(report.exit_code(), 0, "{report:?}");
    let b = report.first_break.as_ref().expect("a break");
    assert_eq!(b.file, name_of(&archives[0]), "{b:?}");
    assert!(
        victim_seen_by_a_reader(&path).is_none(),
        "a reader resolved the victim to the forged approval"
    );
}

/// The active file's final line without its newline is not judged (a write
/// may be in flight) — and so it is never read either. A keyed writer does
/// not resume onto it: it is a whole record without a MAC.
#[test]
fn a_forged_unterminated_tail_of_the_active_file_is_never_read() {
    let (path, key, _) = rotated_keyed_trail("forged-active-tail", 39, 20);
    let log = keyed(&path, &key, 0);
    write_n(&log, 20, 2);
    close(log);
    let template = lines_of(&path)[0].clone();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(resealed_forgery(&template).as_bytes());
    std::fs::write(&path, bytes).unwrap();
    let report = verify(&path, std::slice::from_ref(&key));
    assert_eq!(report.exit_code(), 0, "{report:?}");
    assert_eq!(report.unparseable_lines, 1);
    assert!(victim_seen_by_a_reader(&path).is_none());
    // The active file's counts are built at open and answered without a
    // read-back: they must not count it either.
    let reader = AuditLog::open_read_only(&path).unwrap();
    assert_eq!(
        reader.count_verifications(VerificationKey::TransactionSha256(VICTIM_TX)),
        (0, 0)
    );
    drop(reader);
    let err = AuditLog::open_with_options(
        &path,
        AuditOptions {
            key: Some(key.clone()),
            ..AuditOptions::default()
        },
    )
    .expect_err("a keyed writer resumed onto an unkeyed forged tail");
    assert!(err.to_string().contains("carries no MAC"), "{err}");
}

#[test]
fn a_line_the_chain_cannot_parse_breaks_the_chain_and_is_never_read() {
    let (path, key, archives) = rotated_keyed_trail("forged-1e400", 22, 30);
    let mut lines = lines_of(&archives[0]);
    let forged = forged_approval(&lines[0]).replacen('{', "{\"x\":1e400,", 1);
    assert!(serde_json::from_str::<serde_json::Value>(&forged).is_err());
    lines.insert(1, forged);
    write_lines(&archives[0], &lines);

    let report = verify(&path, std::slice::from_ref(&key));
    assert_ne!(report.exit_code(), 0, "{report:?}");
    let b = report.first_break.as_ref().expect("a break");
    assert_eq!(
        (b.file.clone(), b.line),
        (name_of(&archives[0]), 2),
        "{b:?}"
    );
    assert!(
        victim_seen_by_a_reader(&path).is_none(),
        "a reader resolved the victim to the forged approval"
    );
}

#[test]
fn a_duplicate_key_breaks_the_chain_and_the_record_stays_visible_or_is_named() {
    let (path, key, archives) = rotated_keyed_trail("dup-key", 23, 30);
    let mut lines = lines_of(&archives[0]);
    assert!(lines[0].starts_with("{\"approved\":false,"), "{}", lines[0]);
    lines[0] = lines[0].replacen("{\"approved\":", "{\"approved\":true,\"approved\":", 1);
    write_lines(&archives[0], &lines);

    let report = verify(&path, std::slice::from_ref(&key));
    let reader = AuditLog::open_read_only(&path).unwrap();
    let visible = reader
        .find_verification(VerificationKey::AuditTrailId("gr-00000"))
        .is_some();
    reader.wait_for_index_jobs();
    match &report.first_break {
        // Named: verify does not exit 0, and points at the line.
        Some(b) => {
            assert_eq!(
                (b.file.clone(), b.line),
                (name_of(&archives[0]), 1),
                "{b:?}"
            );
            assert_ne!(report.exit_code(), 0);
        }
        // Or visible to every reader, exactly as verify counted it.
        None => assert!(
            visible,
            "verify accepted a record no reader can see: {report:?}"
        ),
    }
}

/// Recompute every line's link from genesis with no key, as a writer
/// without the key would after editing the trail.
fn rechain_all_without_key(lines: &mut [String]) {
    let mut head = chain::ChainHead::genesis();
    for line in lines.iter_mut() {
        let serde_json::Value::Object(map) = serde_json::from_str(line).unwrap() else {
            panic!()
        };
        let (sealed, next) = chain::seal(map, &head, None);
        *line = sealed;
        head = next;
    }
}

#[test]
fn a_trail_rewritten_without_macs_does_not_verify_under_its_key() {
    let dir = temp_dir("downgrade");
    let path = audit_path(&dir);
    let (_, key) = key_file("downgrade", 24);
    let log = keyed(&path, &key, 0);
    write_n(&log, 0, 8);
    close(log);
    let mut lines = lines_of(&path);
    assert!(lines[2].contains("\"approved\":true"));
    lines[2] = lines[2].replacen("\"approved\":true", "\"approved\":false", 1);
    rechain_all_without_key(&mut lines);
    write_lines(&path, &lines);

    // The server restarts with its key. If it resumes, it MACs two records
    // on top of the rewritten history.
    if let Ok(log) = AuditLog::open_with_options(
        &path,
        AuditOptions {
            key: Some(key.clone()),
            ..AuditOptions::default()
        },
    ) {
        write_n(&log, 8, 2);
        close(log);
    }
    let report = verify(&path, std::slice::from_ref(&key));
    assert_ne!(
        report.exit_code(),
        0,
        "a rewritten, MAC-stripped trail verified under its key: {report:?}"
    );
}

#[test]
fn a_keyed_writer_refuses_to_resume_onto_an_unkeyed_head() {
    let dir = temp_dir("unkeyed-head");
    let path = audit_path(&dir);
    let log = AuditLog::open(&path).unwrap();
    write_n(&log, 0, 3);
    close(log);
    let (_, key) = key_file("unkeyed-head", 25);
    let opened = AuditLog::open_with_options(
        &path,
        AuditOptions {
            key: Some(key),
            ..AuditOptions::default()
        },
    );
    let err = opened.expect_err("a keyed writer resumed onto an unkeyed head");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("adopt-key"), "{err}");
}

/// A checkpoint of the head of a trail truncated to five records, with its
/// MAC removed or put under a key nobody holds.
#[test]
fn an_unsigned_checkpoint_or_one_under_an_unknown_key_is_not_confirmed() {
    let dir = temp_dir("unsigned-checkpoint");
    let path = audit_path(&dir);
    let (_, key) = key_file("unsigned-checkpoint", 26);
    let log = keyed(&path, &key, 0);
    write_n(&log, 0, 10);
    let genuine = log.checkpoint().unwrap();
    close(log);
    let mut lines = lines_of(&path);
    lines.truncate(5);
    write_lines(&path, &lines);
    let keys = std::slice::from_ref(&key);
    let head = verify(&path, keys);
    assert_eq!(
        verify_audit_trail(&path, keys, Some(&genuine))
            .unwrap()
            .exit_code(),
        1
    );

    let mut unsigned = genuine.clone();
    unsigned.seq = 4;
    unsigned.hash = head.head_hash.clone().unwrap();
    unsigned.key_id = None;
    unsigned.mac = None;
    let mut unknown_key = unsigned.clone();
    unknown_key.key_id = Some("00".repeat(8));
    unknown_key.mac = Some("11".repeat(32));
    for (name, cp) in [("unsigned", unsigned), ("unknown key", unknown_key)] {
        let r = verify_audit_trail(&path, keys, Some(&cp)).unwrap();
        assert_ne!(
            r.checkpoint,
            Some(CheckpointStatus::Confirmed),
            "{name}: {r:?}"
        );
        assert_ne!(r.exit_code(), 0, "{name}: {r:?}");
    }
}

/// The records from seq 5 on rewritten under a key id nobody holds, with
/// MACs that cannot be checked: not the same thing as a rotation.
fn invented_key_id_trail(tag: &str, byte: u8) -> (PathBuf, AuditKey) {
    let dir = temp_dir(tag);
    let path = audit_path(&dir);
    let (_, key) = key_file(tag, byte);
    let log = keyed(&path, &key, 0);
    write_n(&log, 0, 10);
    close(log);
    let mut lines = lines_of(&path);
    assert!(lines[5].contains("\"approved\":true"));
    lines[5] = lines[5].replacen("\"approved\":true", "\"approved\":false", 1);
    rechain_without_key(&mut lines, 5);
    for line in lines.iter_mut().skip(5) {
        let mut v: serde_json::Value = serde_json::from_str(line).unwrap();
        v[CHAIN_FIELD]["key_id"] = "deadbeefdeadbeef".into();
        v[CHAIN_FIELD]["mac"] = "77".repeat(32).into();
        *line = v.to_string();
    }
    write_lines(&path, &lines);
    (path, key)
}

#[test]
fn an_invented_key_id_is_a_break_not_a_rotation() {
    let (path, key) = invented_key_id_trail("invented-key", 27);
    let report = verify(&path, std::slice::from_ref(&key));
    let b = report
        .first_break
        .as_ref()
        .unwrap_or_else(|| panic!("an invented key id read as a rotation: {report:?}"));
    assert_eq!(b.seq, Some(5), "{b:?}");
    assert!(b.reason.contains("deadbeefdeadbeef"), "{b:?}");
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn a_keyed_writer_refuses_to_resume_onto_a_head_under_an_unknown_key() {
    let (path, key) = invented_key_id_trail("invented-key-resume", 28);
    let opened = AuditLog::open_with_options(
        &path,
        AuditOptions {
            key: Some(key),
            ..AuditOptions::default()
        },
    );
    let err =
        opened.expect_err("a keyed writer resumed onto a head under a key id it cannot check");
    assert!(err.to_string().contains("deadbeefdeadbeef"), "{err}");
}

/// `graphite audit verify` is documented as safe beside a running writer.
/// A rotation between listing the archives and walking them made it report
/// a break that is not there (exit 1), a prune an unreadable trail (exit 3).
#[test]
fn a_walk_beside_a_rotating_and_pruning_writer_reports_no_false_break() {
    let dir = temp_dir("walk-beside-writer");
    let path = audit_path(&dir);
    let (_, key) = key_file("walk-beside-writer", 29);
    let log = AuditLog::open_with_options(
        &path,
        AuditOptions {
            rotate_bytes: 1,
            max_archives: 6,
            key: Some(key.clone()),
            ..AuditOptions::default()
        },
    )
    .unwrap();
    write_n(&log, 0, 8);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer = {
        let log = log.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut i = 8;
            while !stop.load(Ordering::SeqCst) {
                assert!(log.append(&rec(&format!("gr-{i:05}"), true)));
                i += 1;
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        })
    };
    let mut failures = Vec::new();
    for _ in 0..150 {
        match verify_audit_trail(&path, std::slice::from_ref(&key), None) {
            Ok(r) if r.exit_code() == 0 => {}
            Ok(r) => failures.push(format!("exit {}: {:?}", r.exit_code(), r.first_break)),
            Err(e) => failures.push(format!("exit 3: {e}")),
        }
    }
    stop.store(true, Ordering::SeqCst);
    writer.join().unwrap();
    close(log);
    assert!(
        failures.is_empty(),
        "{} of 150 walks failed beside the writer: {:?}",
        failures.len(),
        &failures[..failures.len().min(3)]
    );
}

/// The head after the last chained line of `path`.
fn head_of(path: &Path) -> chain::ChainHead {
    let last = lines_of(path).pop().unwrap();
    let v: serde_json::Value = serde_json::from_str(&last).unwrap();
    let link: ChainLink = serde_json::from_value(v[CHAIN_FIELD].clone()).unwrap();
    chain::ChainHead {
        next_seq: link.seq + 1,
        prev: hex::decode(&link.hash).unwrap().try_into().unwrap(),
        keyed: link.mac.is_some(),
    }
}

/// Deterministic form of the walk beside a writer: the active file is
/// rotated away, and a record written to a fresh one, while the walk is in
/// the archives it listed. The first walk would see the chain jump from
/// the last listed archive to the new active file; the listing changed, so
/// the walk is repeated and finds one unbroken chain.
#[test]
fn a_rotation_during_the_walk_is_walked_again() {
    let (path, key, _) = rotated_keyed_trail("rotation-mid-walk", 30, 20);
    let log = keyed(&path, &key, 0);
    write_n(&log, 20, 2);
    close(log);
    let mut attempts = Vec::new();
    let report = verify_audit_trail_with(
        &path,
        std::slice::from_ref(&key),
        None,
        &mut |attempt, file| {
            attempts.push(attempt);
            if (attempt, file) != (0, 1) {
                return;
            }
            let head = head_of(&path);
            let archive = path.with_file_name("audit.jsonl.9999999999999-999999");
            std::fs::rename(&path, &archive).unwrap();
            let serde_json::Value::Object(map) =
                serde_json::to_value(rec("gr-after-rotation", true)).unwrap()
            else {
                panic!()
            };
            let (line, _) = chain::seal(map, &head, Some(&key));
            std::fs::write(&path, format!("{line}\n")).unwrap();
        },
    )
    .unwrap();
    assert!(report.intact(), "{report:?}");
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.chained_records, 23);
    assert!(attempts.contains(&1), "the walk was repeated");
}

/// The control for R33-4: an operator who adds a key to a trail that was
/// never keyed adopts it explicitly, and the trail then verifies under the
/// key. A trail keyed later by a pre-Round-34 writer (no adoption record)
/// exits 4 under its key until the adoption is written.
#[test]
fn legitimate_key_adoption_via_the_marker_verifies() {
    let dir = temp_dir("adopt");
    let path = audit_path(&dir);
    let log = AuditLog::open(&path).unwrap();
    write_n(&log, 0, 3);
    close(log);
    let (_, key) = key_file("adopt", 32);
    let keys = std::slice::from_ref(&key);

    // A pre-Round-34 writer resumed onto the unkeyed head with a key.
    let mut lines = lines_of(&path);
    for i in 3..5 {
        let serde_json::Value::Object(map) =
            serde_json::to_value(rec(&format!("gr-{i:05}"), true)).unwrap()
        else {
            panic!()
        };
        let head = {
            write_lines(&path, &lines);
            head_of(&path)
        };
        lines.push(chain::seal(map, &head, Some(&key)).0);
    }
    write_lines(&path, &lines);
    let before = verify(&path, keys);
    assert!(before.first_break.is_none(), "{before:?}");
    assert_eq!(
        (before.unkeyed_records, before.unkeyed_adopted),
        (3, 0),
        "{before:?}"
    );
    assert_eq!(before.exit_code(), 4);
    // Without keys the unkeyed records are what an unkeyed walk expects.
    assert_eq!(verify(&path, &[]).exit_code(), 2);

    // The adoption.
    let log = AuditLog::open_with_options(
        &path,
        AuditOptions {
            rotate_bytes: 0,
            key: Some(key.clone()),
            adopt_key: true,
            ..AuditOptions::default()
        },
    )
    .unwrap();
    write_n(&log, 5, 2);
    close(log);
    let after = verify(&path, keys);
    assert_eq!(after.exit_code(), 0, "{after:?}");
    assert_eq!(after.integrity, Integrity::TamperEvident);
    assert_eq!(
        (
            after.unkeyed_records,
            after.unkeyed_adopted,
            after.key_adoptions
        ),
        (3, 3, 1)
    );
    // Readers never return the adoption record as a verdict, and see every
    // record the walk counted.
    let reader = AuditLog::open_read_only(&path).unwrap();
    assert_eq!(reader.read_tail_filtered(100, AuditSelector::All).2, 7);
    // A server restart under the key resumes without another adoption.
    close(keyed(&path, &key, 0));
    assert_eq!(verify(&path, keys).key_adoptions, 1);

    // And an unkeyed record after the adoption is a break.
    let mut lines = lines_of(&path);
    let serde_json::Value::Object(map) = serde_json::to_value(rec("gr-unkeyed", true)).unwrap()
    else {
        panic!()
    };
    lines.push(chain::seal(map, &head_of(&path), None).0);
    write_lines(&path, &lines);
    let r = verify(&path, keys);
    assert!(
        r.first_break
            .as_ref()
            .is_some_and(|b| b.reason.contains("without a MAC")),
        "{r:?}"
    );
}

/// A lost key: `adopt_key` without the previous key records the adoption
/// as not checked, and the records under the lost key can then only be
/// walked as chained (exit 2 under the new key).
#[test]
fn a_lost_key_is_adopted_as_not_checked() {
    let dir = temp_dir("lost-key");
    let path = audit_path(&dir);
    let (_, lost) = key_file("lost-key-old", 33);
    let (_, new) = key_file("lost-key-new", 34);
    let log = keyed(&path, &lost, 0);
    write_n(&log, 0, 3);
    close(log);
    let log = AuditLog::open_with_options(
        &path,
        AuditOptions {
            rotate_bytes: 0,
            key: Some(new.clone()),
            adopt_key: true,
            ..AuditOptions::default()
        },
    )
    .unwrap();
    write_n(&log, 3, 1);
    close(log);
    let r = verify(&path, std::slice::from_ref(&new));
    assert!(r.first_break.is_none(), "{r:?}");
    assert_eq!(r.exit_code(), 2);
    assert_eq!(r.key_ranges.len(), 2);
    assert!(!r.key_ranges[0].supplied);
    let marker: serde_json::Value = serde_json::from_str(&lines_of(&path)[3]).unwrap();
    assert_eq!(marker["audit_control"], "key_adoption");
    assert_eq!(marker["previous_key_id"], lost.id());
    assert_eq!(marker["previous_key_checked"], false);
}

/// Every line the real writer emits — verification, error and lifecycle
/// records, with non-ASCII text, control characters, quotes, backslashes
/// and many floats — is a valid chained record under the grammar, and its
/// bytes are exactly what serde_json's own serialization of its parse
/// gives: the line format the Round 30 writer used, so trails written
/// before Round 34 keep verifying.
#[test]
fn every_line_the_writer_emits_is_canonical_and_verifies() {
    let dir = temp_dir("canonical-writer");
    let path = audit_path(&dir);
    let (_, key) = key_file("canonical-writer", 35);
    let log = keyed(&path, &key, 0);
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    for i in 0..400 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let mut r = rec(&format!("gr-{i:05}"), i % 2 == 0);
        r.confidence = (seed >> 11) as f64 / (1u64 << 53) as f64;
        if i % 7 == 0 {
            r.confidence = f64::from_bits(seed % 0x3ff0_0000_0000_0000);
        }
        r.instruction_name = format!("tränsfer \"{i}\" \\ \u{1} \u{7f} \u{2028} 😀");
        assert!(log.append(&r));
    }
    assert!(log.append_error(&AuditErrorRecord {
        timestamp: now_utc_rfc3339(),
        program_id: "p\u{0}\n".into(),
        instruction_name: "ünïcode".into(),
        error: "bad \"input\"".into(),
        error_type: "bad_request".into(),
        status: 400,
    }));
    assert!(log.append_lifecycle(&LifecycleEventRecord {
        event_type: LifecycleEvent::Signing,
        timestamp: now_utc_rfc3339(),
        content_hash: "ch".into(),
        verdict_on_record: None,
        verdict_on_record_key: None,
        transaction_sha256: Some(VICTIM_TX.into()),
        audit_trail_id: Some("gr-00001".into()),
        transaction_signature: Some("sig".into()),
        reported_by: Some("agent \t é".into()),
        detail: Some("slot 1\r\n".into()),
        observed_by_graphite: false,
        sequence_anomalies: vec!["x".into()],
    }));
    close(log);
    for line in lines_of(&path) {
        let class = chain::classify_line(line.as_bytes());
        assert!(
            matches!(class, chain::LineClass::Chained(_)),
            "{class:?}: {line}"
        );
        let reparsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(serde_json::to_string(&reparsed).unwrap(), line);
    }
    let r = verify(&path, std::slice::from_ref(&key));
    assert_eq!(r.exit_code(), 0, "{r:?}");
    assert_eq!(r.chained_records, 402);
}

/// R33-3, as a property: verify and every reader run over the same mutated
/// line. Whenever verify exits 0, every reader sees exactly the records the
/// walk counted; whatever verify says, no reader ever returns a record
/// whose content differs from what was written.
#[test]
fn verify_and_every_reader_agree_on_every_mutated_line() {
    let (path, key, archives) = rotated_keyed_trail("agree", 36, 24);
    let log = keyed(&path, &key, 0);
    write_n(&log, 24, 2);
    close(log);
    let keys = std::slice::from_ref(&key);
    let files = trail_files(&path);
    let pristine: Vec<Vec<u8>> = files.iter().map(|f| std::fs::read(f).unwrap()).collect();
    let tx = format!("{:0>64}", "gr-00000".len());
    let originally_approved = |id: &str| id[3..].parse::<usize>().unwrap() % 3 != 0;

    type Mutation = fn(&str) -> String;
    let line_mutations: Vec<(&str, Mutation)> = vec![
        ("duplicate key", |l| {
            let (k, v) = if l.starts_with("{\"approved\":true") {
                ("{\"approved\":", "false")
            } else {
                ("{\"approved\":", "true")
            };
            l.replacen(k, &format!("{k}{v},\"approved\":"), 1)
        }),
        ("whitespace", |l| l.replacen(',', ", ", 1)),
        ("key order", |l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            let map = v.as_object().unwrap();
            let parts: Vec<String> = map
                .iter()
                .rev()
                .map(|(k, v)| format!("{}:{}", serde_json::to_string(k).unwrap(), v))
                .collect();
            format!("{{{}}}", parts.join(","))
        }),
        ("big number", |l| l.replacen('{', "{\"x\":1e400,", 1)),
        ("extra field", |l| l.replacen('{', "{\"aa\":1,", 1)),
        ("unicode escape", |l| {
            l.replacen("transfer", "\\u0074ransfer", 1)
        }),
        ("trailing garbage", |l| format!("{l} x")),
        ("trailing space", |l| format!("{l} ")),
        ("carriage return", |l| format!("{l}\r")),
        ("verdict flipped", |l| {
            if l.contains("\"approved\":true") {
                l.replacen("\"approved\":true", "\"approved\":false", 1)
            } else {
                l.replacen("\"approved\":false", "\"approved\":true", 1)
            }
        }),
        ("not json", |l| l[..l.len() / 2].to_string()),
    ];
    // (file, line index, mutation) — plus the newline removed from the end
    // of an archive and of the active file.
    let mut cases: Vec<(String, usize, Option<usize>)> = Vec::new();
    for (fi, _) in files.iter().enumerate() {
        for m in 0..line_mutations.len() {
            cases.push((format!("file {fi} line 0"), fi, Some(m)));
        }
        cases.push((format!("file {fi} no final newline"), fi, None));
    }
    for (name, fi, m) in cases {
        for (f, bytes) in files.iter().zip(&pristine) {
            std::fs::write(f, bytes).unwrap();
        }
        let target = &files[fi];
        match m {
            Some(m) => {
                let mut lines = lines_of(target);
                lines[0] = (line_mutations[m].1)(&lines[0]);
                write_lines(target, &lines);
            }
            None => {
                let mut bytes = pristine[fi].clone();
                assert_eq!(bytes.pop(), Some(b'\n'));
                std::fs::write(target, bytes).unwrap();
            }
        }
        let label = match m {
            Some(m) => format!("{name}: {}", line_mutations[m].0),
            None => name,
        };
        let report = verify(&path, keys);
        let reader = AuditLog::open_read_only(&path).unwrap();
        let (tail, _, total, _) = reader.read_tail_filtered(1000, AuditSelector::All);
        let (approved, refused) =
            reader.count_verifications(VerificationKey::TransactionSha256(&tx));
        let mut found = 0u64;
        for i in 0..26 {
            let id = format!("gr-{i:05}");
            if let Some(r) = reader.find_verification(VerificationKey::AuditTrailId(&id)) {
                assert_eq!(
                    r.approved,
                    originally_approved(&id),
                    "{label}: {id} altered"
                );
                found += 1;
            }
        }
        for r in &tail {
            assert_eq!(
                r.approved,
                originally_approved(&r.audit_trail_id),
                "{label}: the tail returned an altered record"
            );
        }
        reader.wait_for_index_jobs();
        drop(reader);
        if report.exit_code() == 0 {
            assert_eq!(
                (found, total as u64, (approved + refused) as u64),
                (
                    report.chained_records,
                    report.chained_records,
                    report.chained_records
                ),
                "{label}: verify exited 0 and the readers disagree: {report:?}"
            );
        } else {
            let b = report.first_break.as_ref();
            assert!(
                b.is_some_and(|b| b.file == name_of(target)),
                "{label}: {report:?}"
            );
        }
        // An archive is never allowed to lose its last newline; the active
        // file's last line in flight is not judged and not read.
        if m.is_none() && fi + 1 < files.len() {
            assert_ne!(report.exit_code(), 0, "{label}");
        }
        if m.is_some() {
            assert_ne!(report.exit_code(), 0, "{label}: {report:?}");
        }
    }
    let _ = archives;
}

/// An index is written beside the trail by whoever can write the data
/// directory. One forged to point at a forged line is never an answer: the
/// read-back applies the line grammar, not the index's word.
#[test]
fn a_forged_index_pointing_at_a_forged_line_is_never_an_answer() {
    let (path, _key, archives) = rotated_keyed_trail("forged-index", 38, 30);
    let mut lines = lines_of(&archives[0]);
    let forged = forged_approval(&lines[0]);
    let offset: u64 = lines[0].len() as u64 + 1;
    lines.insert(1, forged);
    write_lines(&archives[0], &lines);
    let index_dir = path.with_file_name("audit.jsonl-index");
    std::fs::create_dir_all(&index_dir).unwrap();
    let (sha, len) = archive_index::file_sha256(&archives[0]).unwrap();
    let key = format!("tx:{VICTIM_TX}");
    let last: HashMap<String, u64> = [(key.clone(), offset)].into_iter().collect();
    let counts: HashMap<String, (usize, usize)> = [(key, (1, 0))].into_iter().collect();
    archive_index::write(
        &archive_index::index_path(&index_dir, &archives[0]).unwrap(),
        len,
        &sha,
        archive_index::IndexSource {
            last: &last,
            counts: &counts,
            lifecycle: &HashMap::new(),
        },
    )
    .unwrap();
    let reader = AuditLog::open_read_only(&path).unwrap();
    assert!(reader
        .find_verification(VerificationKey::TransactionSha256(VICTIM_TX))
        .is_none());
    assert_eq!(
        reader.count_verifications(VerificationKey::TransactionSha256(VICTIM_TX)),
        (0, 0)
    );
    reader.wait_for_index_jobs();
}

#[test]
fn a_dropped_key_is_wiped() {
    let before = chain::KEYS_WIPED.with(|n| n.get());
    let key = AuditKey::from_bytes(&[9u8; 32]).unwrap();
    let copy = key.clone();
    drop(key);
    drop(copy);
    assert_eq!(chain::KEYS_WIPED.with(|n| n.get()) - before, 2);
}

/// A line that is not JSON in the middle of the trail — a torn write the
/// writer never resumed past, or garbage someone added — is a break; the
/// crash the writer did resume past is not.
#[test]
fn a_torn_line_no_record_names_is_a_break() {
    let dir = temp_dir("torn-unnamed");
    let path = audit_path(&dir);
    let (_, key) = key_file("torn-unnamed", 37);
    let log = keyed(&path, &key, 0);
    write_n(&log, 0, 4);
    close(log);
    let mut lines = lines_of(&path);
    let half = lines[1][..lines[1].len() / 2].to_string();
    lines.insert(2, half);
    write_lines(&path, &lines);
    let r = verify(&path, std::slice::from_ref(&key));
    let b = r.first_break.as_ref().expect("a break");
    assert_eq!(b.line, 3, "{b:?}");
    assert!(b.reason.contains("torn write"), "{b:?}");
}
