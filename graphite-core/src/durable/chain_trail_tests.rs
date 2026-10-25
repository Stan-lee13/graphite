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

/// The trail id a link carries (version 2), for a head that continues it.
fn trail_of(link: &ChainLink) -> Option<[u8; chain::TRAIL_ID_BYTES]> {
    link.trail
        .as_deref()
        .map(|t| hex::decode(t).unwrap().try_into().unwrap())
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
            trail: trail_of(&link),
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
    // Round 38 (R37-2): re-pinned. A keyed writer used to start its chain
    // at genesis after the legacy records, and the walk then accepted any
    // legacy line before the first chained record as TamperEvident — the
    // same thing a forged chain-less approval inserted at line 0 of a
    // keyed trail looks like, which every keyed reader then served. Now
    // the keyed writer refuses a legacy-only trail until the operator
    // adopts it (`graphite audit adopt-key`): the adoption record lists
    // the legacy records (a digest per file), and they are read and
    // covered because it does.
    let refused = keyed_with_previous(&path, &key, None).unwrap_err();
    assert!(refused.to_string().contains("adopt-key"), "{refused}");
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
    // The legacy records are still read.
    assert_eq!(log.read_tail_filtered(10, AuditSelector::All).2, 3);
    write_n(&log, 0, 2);
    close(log);
    let report = verify(&path, std::slice::from_ref(&key));
    assert_eq!(report.integrity, Integrity::TamperEvident);
    assert_eq!(
        (
            report.legacy_unchained_records,
            report.legacy_adopted,
            report.chained_records
        ),
        (3, 3, 3)
    );
    assert_eq!(report.exit_code(), 0);
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
        trail: None,
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
        trail: trail_of(&link),
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
        None,
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

// ---------------------------------------------------------------------------
// Round 34 follow-up: a reader that holds the key checks MACs.
// ---------------------------------------------------------------------------

/// How a forged line's link claims to be MAC'd.
#[derive(Clone, Copy, Debug)]
enum ForgedMac {
    /// No MAC at all.
    None,
    /// The trail's own key id, with a MAC that is not one.
    UnderTheTrailKey,
    /// A key id nobody holds.
    Invented,
}

/// `content` sealed right after `after` (the line it is inserted behind):
/// the next seq, `prev` = that line's hash, a hash that matches — a link
/// that looks valid to anything that does not check the MAC.
fn self_hashed_forgery(
    after: &str,
    content: serde_json::Map<String, serde_json::Value>,
    mac: ForgedMac,
    key: &AuditKey,
) -> String {
    let v: serde_json::Value = serde_json::from_str(after).unwrap();
    let link: ChainLink = serde_json::from_value(v[CHAIN_FIELD].clone()).unwrap();
    let head = chain::ChainHead {
        next_seq: link.seq + 1,
        prev: hex::decode(&link.hash).unwrap().try_into().unwrap(),
        keyed: false,
        trail: trail_of(&link),
    };
    let (line, _) = chain::seal(content, &head, None);
    let mut v: serde_json::Value = serde_json::from_str(&line).unwrap();
    match mac {
        ForgedMac::None => {}
        ForgedMac::UnderTheTrailKey => {
            v[CHAIN_FIELD]["key_id"] = key.id().into();
            v[CHAIN_FIELD]["mac"] = "5a".repeat(32).into();
        }
        ForgedMac::Invented => {
            v[CHAIN_FIELD]["key_id"] = "c0ffeec0ffeec0ff".into();
            v[CHAIN_FIELD]["mac"] = "5a".repeat(32).into();
        }
    }
    let line = v.to_string();
    assert!(
        matches!(
            chain::classify_line(line.as_bytes()),
            chain::LineClass::Chained(_)
        ),
        "the forgery passes the grammar: canonical, and its hash matches"
    );
    line
}

fn map_of<T: serde::Serialize>(r: &T) -> serde_json::Map<String, serde_json::Value> {
    let serde_json::Value::Object(m) = serde_json::to_value(r).unwrap() else {
        panic!()
    };
    m
}

/// A forged approval of `VICTIM_TX` and a forged lifecycle row for it, each
/// with a recomputed hash and a link that continues from the line before
/// it, inserted into an archive and into the active file of a keyed trail.
/// The walk breaks on them (exit 1); a reader that holds the key never
/// returns, counts or indexes them. A reader without a key reads them: that
/// trail is only corruption-evident to it (the documented limit).
#[test]
fn a_self_hashed_forgery_in_a_keyed_trail_is_never_read_by_a_reader_with_the_key() {
    for (n, mac) in [
        ForgedMac::None,
        ForgedMac::UnderTheTrailKey,
        ForgedMac::Invented,
    ]
    .into_iter()
    .enumerate()
    {
        let (path, key, archives) =
            rotated_keyed_trail(&format!("self-hashed-{n}"), 50 + n as u8, 30);
        let log = keyed(&path, &key, 0);
        write_n(&log, 30, 3);
        close(log);
        let mut victim = rec("gr-forged", true);
        victim.transaction_sha256 = Some(VICTIM_TX.into());
        victim.decision = Some("executable_approved".into());
        victim.executable = Some(true);
        let row = LifecycleEventRecord {
            event_type: LifecycleEvent::Submission,
            timestamp: now_utc_rfc3339(),
            content_hash: "ch-forged".into(),
            verdict_on_record: None,
            verdict_on_record_key: None,
            transaction_sha256: Some(VICTIM_TX.into()),
            audit_trail_id: Some("gr-forged".into()),
            transaction_signature: Some("sig-forged".into()),
            reported_by: Some("forger".into()),
            detail: None,
            observed_by_graphite: false,
            sequence_anomalies: Vec::new(),
        };
        let mut lines = lines_of(&archives[0]);
        let forged = self_hashed_forgery(&lines[0], map_of(&victim), mac, &key);
        let archive_offset = lines[0].len() as u64 + 1;
        lines.insert(1, forged);
        write_lines(&archives[0], &lines);
        let mut active = lines_of(&path);
        let forged_row = self_hashed_forgery(&active[0], map_of(&row), mac, &key);
        let forged_victim = self_hashed_forgery(&active[0], map_of(&victim), mac, &key);
        active.insert(1, forged_row);
        active.insert(1, forged_victim);
        write_lines(&path, &active);
        // An index that points at the archive's forgery, as whoever wrote
        // the forgery could also write.
        let index_dir = path.with_file_name("audit.jsonl-index");
        std::fs::create_dir_all(&index_dir).unwrap();
        let (sha, len) = archive_index::file_sha256(&archives[0]).unwrap();
        let ikey = format!("tx:{VICTIM_TX}");
        let last: HashMap<String, u64> = [(ikey.clone(), archive_offset)].into_iter().collect();
        let counts: HashMap<String, (usize, usize)> = [(ikey, (1, 0))].into_iter().collect();
        archive_index::write(
            &archive_index::index_path(&index_dir, &archives[0]).unwrap(),
            len,
            &sha,
            archive_index::IndexSource {
                last: &last,
                counts: &counts,
                lifecycle: &HashMap::new(),
            },
            None,
        )
        .unwrap();

        let report = verify(&path, std::slice::from_ref(&key));
        assert_eq!(report.exit_code(), 1, "{mac:?}: {report:?}");

        // The server: a writer that holds the key.
        let server = keyed(&path, &key, 0);
        let tx = VerificationKey::TransactionSha256(VICTIM_TX);
        assert!(
            server.find_verification(tx).is_none(),
            "{mac:?}: the keyed reader returned the forged approval"
        );
        assert_eq!(server.count_verifications(tx), (0, 0), "{mac:?}");
        assert!(
            server
                .lifecycle_history(LifecycleKey {
                    transaction_signature: Some("sig-forged"),
                    ..LifecycleKey::default()
                })
                .is_empty(),
            "{mac:?}: the keyed reader returned the forged lifecycle row"
        );
        let (_, _, total, _) = server.read_tail_filtered(1000, AuditSelector::All);
        assert_eq!(total, 33, "{mac:?}: only the written records are counted");
        for i in [0usize, 15, 32] {
            let id = format!("gr-{i:05}");
            assert!(
                server
                    .find_verification(VerificationKey::AuditTrailId(&id))
                    .is_some(),
                "{mac:?}: {id} is still found"
            );
        }
        close(server);

        // Without a key the reader cannot tell (corruption-evident only).
        // Round 38 (R37-5): re-pinned. A keyless reader now walks the chain
        // as `verify` does, so the forgery in the archive, which continues
        // the line before it, takes the place of the record it displaced,
        // and nothing after that continues it: the forgery in the active
        // file is no longer reached (`find_verification` answered from it
        // before). The documented limit stands — the keyless reader still
        // reads the archive's forgery when it claims a MAC — and is pinned
        // on the full read. A forgery with no MAC after MAC'd records is
        // refused even without a key: the chain was keyed before it.
        let keyless = AuditLog::open_read_only(&path).unwrap();
        let (tail, _, _, _) = keyless.read_tail_filtered(1000, AuditSelector::All);
        let read = tail.iter().any(|r| r.audit_trail_id == "gr-forged");
        match mac {
            ForgedMac::None => assert!(!read, "an unkeyed record after MAC'd ones was read"),
            _ => assert!(
                read,
                "{mac:?}: documented limit: a reader without the key reads a self-hashed forgery"
            ),
        }
        keyless.wait_for_index_jobs();
    }
}

/// A trail rotated K1 → K2 with a key-adoption record, read by a server
/// that holds K2 alone: the records under K1 are vouched for by the checked
/// adoption record and stay readable; a forgery under K1's id is the
/// residual (admitted on the adoption's word, not checked). With K1 held as
/// the previous key, it is checked and refused.
#[test]
fn records_under_a_rotated_out_key_stay_readable_when_an_adoption_vouches_for_it() {
    let dir = temp_dir("vouched");
    let path = audit_path(&dir);
    let (_, old) = key_file("vouched-old", 60);
    let (_, new) = key_file("vouched-new", 61);
    let log = keyed(&path, &old, 0);
    write_n(&log, 0, 4);
    close(log);
    close(keyed_with_previous(&path, &new, Some(&old)).unwrap());
    let log = keyed(&path, &new, 0);
    write_n(&log, 4, 2);
    assert_eq!(log.read_tail_filtered(100, AuditSelector::All).2, 6);
    assert!(log
        .find_verification(VerificationKey::AuditTrailId("gr-00001"))
        .is_some());
    close(log);
    // A forgery under the old key's id with a MAC that is not one.
    let mut lines = lines_of(&path);
    let mut victim = rec("gr-forged", true);
    victim.transaction_sha256 = Some(VICTIM_TX.into());
    let mut forged: serde_json::Value = serde_json::from_str(&self_hashed_forgery(
        &lines[0],
        map_of(&victim),
        ForgedMac::UnderTheTrailKey,
        &old,
    ))
    .unwrap();
    assert_eq!(forged[CHAIN_FIELD]["key_id"], old.id());
    forged[CHAIN_FIELD]["mac"] = "5a".repeat(32).into();
    lines.insert(1, forged.to_string());
    write_lines(&path, &lines);
    let tx = VerificationKey::TransactionSha256(VICTIM_TX);
    let with_both = keyed_with_previous(&path, &new, Some(&old)).unwrap();
    assert!(with_both.find_verification(tx).is_none());
    close(with_both);
    // Round 38 (R37-5): re-pinned. A server holding K2 alone used to start
    // and answer with the forgery (admitted on the adoption's word, its MAC
    // unchecked). The residual is still there for the reader — it cannot
    // check a MAC under a key it does not hold — but its walk now takes the
    // forgery in place of the genuine seq 1, so nothing after it continues
    // the walk, and the writer refuses to resume onto a head the walk never
    // reaches rather than fork the chain.
    //
    // Round 38 (R37-13): re-pinned. The residual is closed: a record under
    // the vouched K1 is read only where the checked adoption covers it
    // through the hash chain, and the forgery breaks that chain, so nothing
    // under K1 is covered. The walk takes neither the forgery nor the K1
    // records (they are lost to the reader: fail closed, and `verify`
    // reports the break), starts again at the records under K2, which it
    // checks, and reaches the head: the writer resumes after its own head,
    // so no fork, and never reads the forgery.
    let new_only = keyed_with_previous(&path, &new, None).unwrap();
    assert!(
        new_only.find_verification(tx).is_none(),
        "the K2-only server read the forgery under K1"
    );
    assert!(new_only
        .find_verification(VerificationKey::AuditTrailId("gr-00001"))
        .is_none());
    assert!(new_only
        .find_verification(VerificationKey::AuditTrailId("gr-00005"))
        .is_some());
    close(new_only);
    assert_eq!(verify(&path, &[old.clone(), new.clone()]).exit_code(), 1);
}

/// A torn write a pre-Round-34 writer resumed past: terminated by the
/// writer, and the next record continues the chain from the record before
/// it, with nothing naming the tear.
fn historic_tear_trail(tag: &str, byte: u8) -> (PathBuf, AuditKey) {
    let dir = temp_dir(tag);
    let path = audit_path(&dir);
    let (_, key) = key_file(tag, byte);
    let log = keyed(&path, &key, 0);
    write_n(&log, 0, 5);
    close(log);
    let mut lines = lines_of(&path);
    let half = lines[2][..lines[2].len() / 3].to_string();
    lines.insert(2, half);
    write_lines(&path, &lines);
    (path, key)
}

#[test]
fn a_historic_tear_is_a_break_until_the_operator_acknowledges_it() {
    let (path, key) = historic_tear_trail("historic-tear", 62);
    let keys = std::slice::from_ref(&key);
    let before = verify(&path, keys);
    assert_eq!(before.exit_code(), 1, "{before:?}");
    assert!(before.other_break.is_none());
    assert_eq!(before.unacknowledged_tears.len(), 1, "{before:?}");
    let tear = before.unacknowledged_tears[0].clone();
    assert_eq!((tear.line, tear.after_seq), (3, Some(1)));
    // The walk went on past it: every record was checked.
    assert_eq!(before.chained_records, 5);

    let log = keyed(&path, &key, 0);
    log.acknowledge_tear(&tear).unwrap();
    close(log);
    let after = verify(&path, keys);
    assert_eq!(after.exit_code(), 0, "{after:?}");
    assert_eq!((after.tears_acknowledged, after.unparseable_lines), (1, 1));
    assert!(after.unacknowledged_tears.is_empty());
    // The acknowledgement is a control record: no reader returns it.
    let reader = keyed(&path, &key, 0);
    assert_eq!(reader.read_tail_filtered(100, AuditSelector::All).2, 5);
    close(reader);

    // It names exactly those bytes: change one and it is a break again.
    let mut lines = lines_of(&path);
    let torn = lines[2].clone();
    lines[2] = torn.replacen('{', "[", 1);
    assert_ne!(lines[2], torn);
    write_lines(&path, &lines);
    let changed = verify(&path, keys);
    assert_eq!(changed.exit_code(), 1, "{changed:?}");
    assert_eq!(changed.unacknowledged_tears.len(), 1);
}

/// The control: a line that is JSON and breaks the chain is never a tear,
/// so nothing can acknowledge it; and a second tear stays a break when only
/// the first is acknowledged.
#[test]
fn only_a_tear_can_be_acknowledged_and_only_the_one_named() {
    let (path, key) = historic_tear_trail("tear-control", 63);
    let keys = std::slice::from_ref(&key);
    let mut lines = lines_of(&path);
    let second = lines[4][..lines[4].len() / 2].to_string();
    lines.insert(5, second);
    write_lines(&path, &lines);
    let r = verify(&path, keys);
    assert_eq!(r.unacknowledged_tears.len(), 2, "{r:?}");
    let first = r.unacknowledged_tears[0].clone();
    let log = keyed(&path, &key, 0);
    log.acknowledge_tear(&first).unwrap();
    close(log);
    let r = verify(&path, keys);
    assert_eq!(r.exit_code(), 1);
    assert_eq!(r.unacknowledged_tears.len(), 1);
    assert_eq!(r.first_break.as_ref().unwrap().line, 6, "{r:?}");

    // An edited record is JSON: a break, and not a tear.
    let (path, key) = historic_tear_trail("tear-control-json", 64);
    let mut lines = lines_of(&path);
    lines[4] = lines[4].replacen("transfer", "transfeR", 1);
    write_lines(&path, &lines);
    let r = verify(&path, std::slice::from_ref(&key));
    assert_eq!(r.unacknowledged_tears.len(), 1, "only the torn line: {r:?}");
    assert!(
        r.other_break
            .as_ref()
            .is_some_and(|b| b.reason.contains("does not match its own chain hash")),
        "{r:?}"
    );
}

/// What checking every chained line's MAC costs a reader: a full scan of a
/// 64 MiB keyed archive (the dashboard's first read, an index build, a count
/// with no index), with and without the key. Prints the numbers and asserts
/// only that both readers count the same records.
#[test]
#[ignore = "benchmark: writes a 64 MiB archive"]
fn reader_mac_check_cost_on_a_64_mib_archive() {
    use std::time::Instant;
    let (_, key) = key_file("mac-cost", 70);
    let mut body = String::with_capacity(DEFAULT_ROTATE_BYTES as usize + 4096);
    let mut head = chain::ChainHead::genesis();
    let mut n = 0usize;
    while (body.len() as u64) < DEFAULT_ROTATE_BYTES {
        let mut r = rec(&format!("gr-{n:08}"), !n.is_multiple_of(3));
        r.transaction_sha256 = Some(format!("{n:064x}"));
        let (line, next) = chain::seal(map_of(&r), &head, Some(&key));
        body.push_str(&line);
        body.push('\n');
        head = next;
        n += 1;
    }
    let mut runs = Vec::new();
    for keyed_reader in [false, true] {
        let dir = temp_dir(&format!("mac-cost-{keyed_reader}"));
        std::fs::write(dir.join("audit.jsonl.1700000000000-000000"), &body).unwrap();
        // No index can be written: every count scans the archive.
        std::fs::write(dir.join("audit.jsonl-index"), b"x").unwrap();
        let path = audit_path(&dir);
        if keyed_reader {
            // The active file continues the archive's chain.
            let (line, _) = chain::seal(map_of(&rec("gr-active", true)), &head, Some(&key));
            std::fs::write(&path, format!("{line}\n")).unwrap();
        }
        let log = if keyed_reader {
            keyed(&path, &key, 0)
        } else {
            std::fs::write(&path, b"").unwrap();
            AuditLog::open_read_only(&path).unwrap()
        };
        let t = Instant::now();
        let total = log.read_tail_filtered(10, AuditSelector::All).2;
        let scan = t.elapsed().as_secs_f64() * 1000.0;
        let mut counts = Vec::new();
        for _ in 0..3 {
            let t = Instant::now();
            let c = log.count_verifications(VerificationKey::TransactionSha256(&format!(
                "{:064x}",
                n / 2
            )));
            assert_eq!(c.0 + c.1, 1);
            counts.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        counts.sort_by(|a, b| a.partial_cmp(b).unwrap());
        runs.push((keyed_reader, total, scan, counts[1]));
        log.wait_for_index_jobs();
    }
    assert_eq!(runs[0].1 + 1, runs[1].1, "both readers count every record");
    eprintln!("reader MAC check over a 64 MiB keyed archive ({n} records):");
    for (keyed_reader, total, scan, count) in runs {
        eprintln!(
            "  {}: full scan (read_tail_filtered) {scan:.0} ms over {total} records; count_verifications with no index {count:.0} ms (median of 3)",
            if keyed_reader { "with the key   " } else { "without a key  " }
        );
    }
}

// ---------------------------------------------------------------------------
// Round 38: the Round 37 re-audit (R37-2 … R37-5). Each test shows the
// attack at the reader (what a reader holding the key returns) and at
// `verify` (its exit code).
// ---------------------------------------------------------------------------

/// An approval of `VICTIM_TX` that Graphite never wrote.
fn victim_approval(id: &str) -> AuditRecord {
    let mut r = rec(id, true);
    r.transaction_sha256 = Some(VICTIM_TX.into());
    r.decision = Some("executable_approved".into());
    r.executable = Some(true);
    r
}

/// A keyed writer at `path`, or the error it refused the trail with.
fn try_keyed(path: &Path, key: &AuditKey) -> std::io::Result<AuditLog> {
    AuditLog::open_with_options(
        path,
        AuditOptions {
            rotate_bytes: 0,
            key: Some(key.clone()),
            ..AuditOptions::default()
        },
    )
}

/// R37-2: a chain-less ("legacy") line inserted at the top of a keyed trail,
/// or at the top of the oldest archive left after a prune, is neither read
/// by a reader holding the key nor accepted by `verify` under the key.
#[test]
fn a_forged_legacy_line_in_a_keyed_trail_is_neither_read_nor_verified() {
    let legacy_forgery = serde_json::to_string(&victim_approval("gr-legacy")).unwrap();

    // A trail keyed from its first record (seq 0): any legacy line is an
    // insertion.
    let dir = temp_dir("r37-2-born-keyed");
    let path = audit_path(&dir);
    let (_, key) = key_file("r37-2-born-keyed", 80);
    let log = keyed(&path, &key, 0);
    write_n(&log, 0, 5);
    close(log);
    let mut lines = lines_of(&path);
    lines.insert(0, legacy_forgery.clone());
    write_lines(&path, &lines);
    let report = verify(&path, std::slice::from_ref(&key));
    assert_eq!(
        report.exit_code(),
        1,
        "a legacy line before a trail keyed from seq 0 is a break: {report:?}"
    );
    let server = keyed(&path, &key, 0);
    let seen = server.find_verification(VerificationKey::TransactionSha256(VICTIM_TX));
    assert!(
        seen.is_none(),
        "the keyed reader returned the forged legacy approval: {seen:?}"
    );
    assert_eq!(
        server.count_verifications(VerificationKey::TransactionSha256(VICTIM_TX)),
        (0, 0)
    );
    assert_eq!(server.read_tail_filtered(100, AuditSelector::All).2, 5);
    close(server);

    // After a prune, the new oldest archive starts at a seq above 0: a
    // legacy line at its top is not covered by the key (exit 4), and is not
    // read.
    let dir = temp_dir("r37-2-pruned");
    let path = audit_path(&dir);
    let (_, key) = key_file("r37-2-pruned", 81);
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
    write_n(&log, 0, 30);
    close(log);
    let oldest = archives_of(&path).into_iter().next().unwrap().1;
    let before = verify(&path, std::slice::from_ref(&key));
    assert_eq!(before.exit_code(), 0, "{before:?}");
    assert!(before.first_seq.unwrap() > 0, "{before:?}");
    let mut lines = lines_of(&oldest);
    lines.insert(0, legacy_forgery.clone());
    write_lines(&oldest, &lines);
    let report = verify(&path, std::slice::from_ref(&key));
    assert_eq!(
        report.exit_code(),
        4,
        "a legacy line no key-adoption record vouches for is not covered by the key: {report:?}"
    );
    let server = keyed(&path, &key, 0);
    assert!(server
        .find_verification(VerificationKey::TransactionSha256(VICTIM_TX))
        .is_none());
    close(server);

    // The control: a real pre-Round-30 trail adopted under a key. The
    // adoption record vouches for the legacy prefix (its digest), so the
    // records stay readable and verify — and one more legacy line inserted
    // after the adoption is a break and is not read.
    let dir = temp_dir("r37-2-adopted");
    let path = audit_path(&dir);
    let (_, key) = key_file("r37-2-adopted", 82);
    let legacy: Vec<String> = (0..3)
        .map(|i| serde_json::to_string(&rec(&format!("gr-old-{i}"), true)).unwrap())
        .collect();
    write_lines(&path, &legacy);
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
    write_n(&log, 0, 2);
    assert_eq!(log.read_tail_filtered(10, AuditSelector::All).2, 5);
    close(log);
    let adopted = verify(&path, std::slice::from_ref(&key));
    assert_eq!(adopted.exit_code(), 0, "{adopted:?}");
    assert_eq!(adopted.legacy_unchained_records, 3);
    let mut lines = lines_of(&path);
    lines.insert(1, legacy_forgery);
    write_lines(&path, &lines);
    let report = verify(&path, std::slice::from_ref(&key));
    assert_eq!(report.exit_code(), 1, "{report:?}");
    let server = keyed(&path, &key, 0);
    assert!(server
        .find_verification(VerificationKey::TransactionSha256(VICTIM_TX))
        .is_none());
    close(server);
}

/// R37-3: an unkeyed record with a recomputed hash at the start of a file
/// of a keyed trail is never read by a reader holding the key — whether the
/// trail was keyed from genesis, or an unterminated forgery at the end of
/// the newest archive claims the trail was unkeyed there.
#[test]
fn an_unkeyed_forgery_is_never_admitted_after_the_trail_is_keyed() {
    // 1. Keyed from genesis; an unkeyed approval sealed from genesis at
    //    line 0.
    let dir = temp_dir("r37-3-genesis");
    let path = audit_path(&dir);
    let (_, key) = key_file("r37-3-genesis", 83);
    let log = keyed(&path, &key, 0);
    write_n(&log, 0, 5);
    close(log);
    let (forged, _) = chain::seal(
        map_of(&victim_approval("gr-forged")),
        &chain::ChainHead::genesis(),
        None,
    );
    let mut lines = lines_of(&path);
    lines.insert(0, forged);
    write_lines(&path, &lines);
    let report = verify(&path, std::slice::from_ref(&key));
    assert_eq!(report.exit_code(), 1, "{report:?}");
    let server = keyed(&path, &key, 0);
    let seen = server.find_verification(VerificationKey::TransactionSha256(VICTIM_TX));
    assert!(
        seen.is_none(),
        "variant 1: the keyed reader returned the unkeyed forgery: {seen:?}"
    );
    assert!(
        server
            .find_verification(VerificationKey::AuditTrailId("gr-00004"))
            .is_some(),
        "the records the key covers are still read"
    );
    close(server);

    // 2. An unterminated, resealed forgery at the end of the newest archive
    //    (which used to make the active file's gate start "not keyed"), and
    //    an unkeyed approval continuing the archive's chain at line 0 of the
    //    active file. Read after a restart.
    let (path, key, _) = rotated_keyed_trail("r37-3-archive-tail", 84, 30);
    let log = keyed(&path, &key, 0);
    write_n(&log, 30, 3);
    close(log);
    let newest = archives_of(&path).into_iter().last().unwrap().1;
    let last = lines_of(&newest).last().unwrap().clone();
    let mut bytes = std::fs::read(&newest).unwrap();
    bytes.extend_from_slice(resealed_forgery(&last).as_bytes());
    std::fs::write(&newest, bytes).unwrap();
    let mut active = lines_of(&path);
    active.insert(
        0,
        self_hashed_forgery(
            &last,
            map_of(&victim_approval("gr-forged")),
            ForgedMac::None,
            &key,
        ),
    );
    write_lines(&path, &active);
    let report = verify(&path, std::slice::from_ref(&key));
    assert_ne!(report.exit_code(), 0, "{report:?}");
    let server = keyed(&path, &key, 0);
    let seen = server.find_verification(VerificationKey::TransactionSha256(VICTIM_TX));
    assert!(
        seen.is_none(),
        "variant 2: the keyed reader returned the unkeyed forgery after a restart: {seen:?}"
    );
    assert_eq!(
        server.count_verifications(VerificationKey::TransactionSha256(VICTIM_TX)),
        (0, 0)
    );
    close(server);
}

/// R37-4: once a key-adoption record moved the trail from K1 to K2, a record
/// sealed under K1 (a leaked retired key) cannot extend it: `verify` with
/// both keys breaks on it, a reader holding both keys does not read it, and
/// the writer refuses to resume onto it.
#[test]
fn a_retired_key_cannot_extend_the_trail_after_rotation() {
    let dir = temp_dir("r37-4");
    let path = audit_path(&dir);
    let (_, k1) = key_file("r37-4-old", 85);
    let (_, k2) = key_file("r37-4-new", 86);
    let log = keyed(&path, &k1, 0);
    write_n(&log, 0, 4);
    close(log);
    let log = keyed_with_previous(&path, &k2, Some(&k1)).unwrap();
    assert!(!log.previous_key_unused(), "the rotation's start needs it");
    write_n(&log, 4, 2);
    close(log);
    assert_eq!(verify(&path, &[k1.clone(), k2.clone()]).exit_code(), 0);

    // The server is running under K2 with the previous key still set, as
    // docs/ops/keys.md allowed; whoever holds K1 appends a record under it.
    let server = keyed_with_previous(&path, &k2, Some(&k1)).unwrap();
    assert!(
        server.previous_key_unused(),
        "the previous key stayed set after the first start: the server warns"
    );
    let mut lines = lines_of(&path);
    let forged = chain::seal(
        map_of(&victim_approval("gr-forged")),
        &head_of(&path),
        Some(&k1),
    )
    .0;
    lines.push(forged);
    write_lines(&path, &lines);
    let tx = VerificationKey::TransactionSha256(VICTIM_TX);
    assert_eq!(
        server.count_verifications(tx),
        (0, 0),
        "a reader holding both keys counted the record under the retired key"
    );
    assert_eq!(server.read_tail_filtered(100, AuditSelector::All).2, 6);
    close(server);

    let report = verify(&path, &[k1.clone(), k2.clone()]);
    assert_eq!(
        report.exit_code(),
        1,
        "a record under a retired key verified with both keys: {report:?}"
    );
    // A restart with the previous key still set: never a resume onto it.
    match keyed_with_previous(&path, &k2, Some(&k1)) {
        Ok(server) => {
            let seen = server.find_verification(tx);
            close(server);
            panic!("the writer resumed onto a head under the retired key; its reader saw {seen:?}");
        }
        Err(e) => assert!(e.to_string().contains("retired"), "{e}"),
    }
}

/// R37-5: a genuine record copied to a new position — later in its own
/// trail, or from another trail under the same key — is not what a reader
/// answers with, and is not counted.
#[test]
fn a_copied_record_is_not_the_newest_verdict() {
    let dir = temp_dir("r37-5");
    let path = audit_path(&dir);
    let (_, key) = key_file("r37-5", 87);
    let victim = |id: &str, approved: bool| {
        let mut r = victim_approval(id);
        r.approved = approved;
        if !approved {
            r.decision = Some("refused".into());
            r.executable = Some(false);
        }
        r
    };
    let tx = VerificationKey::TransactionSha256(VICTIM_TX);
    let log = keyed(&path, &key, 0);
    assert!(log.append(&rec("gr-00000", true)));
    assert!(log.append(&victim("gr-00001", true)));
    assert!(log.append(&rec("gr-00002", true)));
    assert!(log.append(&victim("gr-00003", false)));
    assert_eq!(log.count_verifications(tx), (1, 1));

    // Beside the running server: the genuine approval copied to the end.
    let mut lines = lines_of(&path);
    lines.push(lines[1].clone());
    write_lines(&path, &lines);
    assert_eq!(
        log.count_verifications(tx),
        (1, 1),
        "the running server counted the copied approval twice"
    );
    assert_eq!(log.read_tail_filtered(100, AuditSelector::All).2, 4);
    close(log);

    let report = verify(&path, std::slice::from_ref(&key));
    assert_eq!(report.exit_code(), 1, "{report:?}");
    // A restart: the writer either refuses the trail outright, or its
    // reader answers with the refusal that was written last.
    if let Ok(server) = try_keyed(&path, &key) {
        let newest = server.find_verification(tx);
        let counts = server.count_verifications(tx);
        close(server);
        let newest = newest.expect("the refusal is still on record");
        assert!(
            !newest.approved && newest.audit_trail_id == "gr-00003",
            "the copied approval became the newest verdict after a restart: {newest:?}"
        );
        assert_eq!(counts, (1, 1));
    }

    // A record of another trail under the same key, copied in.
    let other = audit_path(&temp_dir("r37-5-other"));
    let log = keyed(&other, &key, 0);
    for i in 0..4 {
        assert!(log.append(&rec(&format!("gr-1000{i}"), true)));
    }
    assert!(log.append(&victim("gr-10004", true)));
    close(log);
    let foreign = lines_of(&other)[4].clone();
    let path = audit_path(&temp_dir("r37-5-target"));
    let log = keyed(&path, &key, 0);
    for i in 0..4 {
        assert!(log.append(&rec(&format!("gr-2000{i}"), true)));
    }
    let mut lines = lines_of(&path);
    lines.push(foreign.clone());
    write_lines(&path, &lines);
    assert_eq!(
        log.count_verifications(tx),
        (0, 0),
        "a record of another trail was counted"
    );
    close(log);
    assert_eq!(verify(&path, std::slice::from_ref(&key)).exit_code(), 1);

    // The same record at the top of the target trail, where no record
    // precedes it to continue: the readers pin the trail id of the newest
    // record (the writer's own), so it is not read there either.
    let mut lines = lines_of(&path);
    lines.pop();
    lines.insert(0, foreign);
    write_lines(&path, &lines);
    let report = verify(&path, std::slice::from_ref(&key));
    assert_eq!(report.exit_code(), 1, "{report:?}");
    // Re-pinned in Round 39 (R39-CB-1): the writer started here, pinning its
    // own head's trail id, and its readers skipped the foreign record. The
    // pin is the newest record's id, though, which whoever appends last
    // chooses: the same record at the END made the writer resume onto the
    // other trail (`a_record_of_another_trail_at_the_end_does_not_become_the_trail`).
    // A writer now refuses a trail holding genuine records of two trails,
    // wherever the other trail's record stands. The running writer above
    // still never read one (`(0, 0)`).
    let refused = match try_keyed(&path, &key) {
        Ok(server) => {
            close(server);
            panic!("a trail holding records of two trails was resumed");
        }
        Err(e) => e,
    };
    assert!(refused.to_string().contains("another trail"), "{refused}");
}

// ---------------------------------------------------------------------------
// Round 38: archive indexes MAC'd under the trail key (R37-12), records under
// a vouched key read only where a checked adoption covers them (R37-13),
// prune records (R37-14), the prefilter walk (T-6), a trail under no
// supplied key (T-12), a bound on a line (T-15).
// ---------------------------------------------------------------------------

/// The head a record sealed right after `line` continues.
fn head_after(line: &str) -> chain::ChainHead {
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    let link: ChainLink = serde_json::from_value(v[CHAIN_FIELD].clone()).unwrap();
    chain::ChainHead {
        next_seq: link.seq + 1,
        prev: hex::decode(&link.hash).unwrap().try_into().unwrap(),
        keyed: link.mac.is_some(),
        trail: trail_of(&link),
    }
}

/// The archive of the trail at `path` whose text contains `needle`.
fn archive_with(path: &Path, needle: &str) -> PathBuf {
    archives_of(path)
        .into_iter()
        .map(|(_, p)| p)
        .find(|p| std::fs::read_to_string(p).unwrap().contains(needle))
        .expect("an archive holds it")
}

/// The byte offset of the first line of `file` containing `needle`.
fn offset_of(file: &Path, needle: &str) -> u64 {
    let mut at = 0u64;
    for l in lines_of(file) {
        if l.contains(needle) {
            return at;
        }
        at += l.len() as u64 + 1;
    }
    panic!("{needle} not in {file:?}")
}

/// A refusal of `VICTIM_TX`.
fn victim_refusal(id: &str) -> AuditRecord {
    let mut r = victim_approval(id);
    r.approved = false;
    r.decision = Some("refused".into());
    r.executable = Some(false);
    r
}

/// What whoever can write the data directory, without the key, writes as
/// an archive's index: the format the server reads, built over the
/// archive's real bytes, with the entries the forger chose.
fn forge_index(
    index_path: &Path,
    archive: &Path,
    last: &HashMap<String, u64>,
    counts: &HashMap<String, (usize, usize)>,
) {
    let (sha, len) = archive_index::file_sha256(archive).unwrap();
    archive_index::write(
        index_path,
        len,
        &sha,
        archive_index::IndexSource {
            last,
            counts,
            lifecycle: &HashMap::new(),
        },
        None,
    )
    .unwrap();
}

/// R37-12: an archive index rewritten by someone without the key — one that
/// omits the refusal, so the lookup falls through to an older approval, or
/// one whose counts are inflated while its offset still reads back — is
/// never believed: the archive is walked instead.
#[test]
fn a_rewritten_archive_index_is_never_believed() {
    let dir = temp_dir("r37-12");
    let path = audit_path(&dir);
    let (_, key) = key_file("r37-12", 90);
    let tx = VerificationKey::TransactionSha256(VICTIM_TX);
    let log = keyed(&path, &key, 1_500);
    assert!(log.append(&victim_approval("gr-approved")));
    write_n(&log, 0, 8);
    assert!(log.append(&victim_refusal("gr-refused")));
    write_n(&log, 8, 8);
    assert_eq!(log.count_verifications(tx), (1, 1));
    close(log);
    let archive = archive_with(&path, "gr-refused");
    assert_ne!(archive, archive_with(&path, "gr-approved"));
    // The server builds every archive's index.
    let server = keyed(&path, &key, 0);
    assert_eq!(server.count_verifications(tx), (1, 1));
    assert_eq!(
        server.find_verification(tx).unwrap().audit_trail_id,
        "gr-refused"
    );
    close(server);
    let index_path =
        archive_index::index_path(&path.with_file_name("audit.jsonl-index"), &archive).unwrap();
    assert!(index_path.exists());
    let ikey = format!("tx:{VICTIM_TX}");
    let at = offset_of(&archive, "gr-refused");
    for (case, entry) in [
        ("omits the refusal", None),
        ("inflates the counts", Some((4usize, 1usize))),
    ] {
        let mut last = HashMap::new();
        let mut counts = HashMap::new();
        if let Some(c) = entry {
            last.insert(ikey.clone(), at);
            counts.insert(ikey.clone(), c);
        }
        forge_index(&index_path, &archive, &last, &counts);
        let server = keyed(&path, &key, 0);
        let newest = server.find_verification(tx).expect("on record");
        let counted = server.count_verifications(tx);
        close(server);
        assert_eq!(
            newest.audit_trail_id, "gr-refused",
            "{case}: the lookup answered from a rewritten index"
        );
        assert_eq!(
            counted,
            (1, 1),
            "{case}: the counts came from a rewritten index"
        );
    }
    // Beside a running server that already checked the index: rewritten
    // after the check (in place, past a timestamp tick), it is not read.
    let server = keyed(&path, &key, 0);
    assert_eq!(server.count_verifications(tx), (1, 1));
    std::thread::sleep(std::time::Duration::from_millis(20));
    let rebuilt = std::fs::read(&index_path).unwrap();
    let mut forged_path = index_path.clone();
    forged_path.set_extension("forged");
    forge_index(&forged_path, &archive, &HashMap::new(), &HashMap::new());
    let forged = std::fs::read(&forged_path).unwrap();
    assert_ne!(rebuilt, forged);
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&index_path)
            .unwrap();
        f.write_all(&forged).unwrap();
    }
    assert_eq!(
        server.find_verification(tx).map(|r| r.audit_trail_id),
        Some("gr-refused".into()),
        "a running server read an index rewritten after its check"
    );
    assert_eq!(server.count_verifications(tx), (1, 1));
    close(server);
}

/// R37-13: a record under a key the reader does not hold, vouched for by a
/// checked key-adoption record naming that key, is read only where that
/// adoption covers it through the hash chain, as an unkeyed record is. A
/// forgery under the vouched key that replaces a record (its link continuing
/// the record before it, its MAC one the reader cannot check) breaks the
/// chain to the adoption: nothing under the vouched key is then read, and
/// never the forgery. Round 38's one-way rotation already refused a record
/// under it AFTER the adoption; this is the span before it.
#[test]
fn a_forgery_under_a_vouched_key_is_not_read_in_place_of_the_record_it_replaced() {
    let dir = temp_dir("r37-13");
    let path = audit_path(&dir);
    let (_, k1) = key_file("r37-13-old", 91);
    let (_, k2) = key_file("r37-13-new", 92);
    let log = keyed(&path, &k1, 1_500);
    write_n(&log, 0, 20);
    close(log);
    let log = AuditLog::open_with_options(
        &path,
        AuditOptions {
            rotate_bytes: 1_500,
            key: Some(k2.clone()),
            previous_key: Some(k1.clone()),
            ..AuditOptions::default()
        },
    )
    .unwrap();
    write_n(&log, 20, 4);
    close(log);
    // The server after the rotation, holding K2 only: the records under K1
    // are read (vouched for and covered by the checked adoption).
    let server = keyed(&path, &k2, 0);
    assert_eq!(server.read_tail_filtered(100, AuditSelector::All).2, 24);
    assert!(server
        .find_verification(VerificationKey::AuditTrailId("gr-00001"))
        .is_some());
    // Whoever holds K1 (retired) replaces gr-00001 in the oldest archive with
    // an approval of the victim, MAC'd under K1.
    let oldest = archives_of(&path).into_iter().next().unwrap().1;
    let mut lines = lines_of(&oldest);
    let at = lines.iter().position(|l| l.contains("gr-00001")).unwrap();
    let forged = chain::seal(
        map_of(&victim_approval("gr-forged")),
        &head_after(&lines[at - 1]),
        Some(&k1),
    )
    .0;
    lines[at] = forged;
    write_lines(&oldest, &lines);
    let tx = VerificationKey::TransactionSha256(VICTIM_TX);
    assert!(
        server.find_verification(tx).is_none(),
        "the running server read a forgery under the vouched key"
    );
    assert_eq!(server.count_verifications(tx), (0, 0));
    close(server);
    assert_eq!(verify(&path, &[k1.clone(), k2.clone()]).exit_code(), 1);
}

/// R37-14: deleting the oldest archive, or the oldest lines of it, passed
/// `verify` (a first seq above 0 read as "pruned"). Pruning now writes a
/// chained prune record naming where the trail may start; a first record no
/// prune record names is a break.
#[test]
fn deleting_the_oldest_records_is_a_break_unless_a_prune_record_names_the_start() {
    let dir = temp_dir("r37-14");
    let path = audit_path(&dir);
    let (_, key) = key_file("r37-14", 93);
    let keys = std::slice::from_ref(&key);
    let log = AuditLog::open_with_options(
        &path,
        AuditOptions {
            rotate_bytes: 1_500,
            max_archives: 3,
            key: Some(key.clone()),
            ..AuditOptions::default()
        },
    )
    .unwrap();
    write_n(&log, 0, 60);
    close(log);
    let report = verify(&path, keys);
    assert!(report.first_seq.unwrap() > 0, "{report:?}");
    assert_eq!(report.exit_code(), 0, "the writer's own prune: {report:?}");
    // The oldest archive left, deleted.
    let oldest = archives_of(&path).into_iter().next().unwrap().1;
    let saved = std::fs::read_to_string(&oldest).unwrap();
    std::fs::remove_file(&oldest).unwrap();
    let report = verify(&path, keys);
    assert_eq!(
        report.exit_code(),
        1,
        "the oldest archive deleted: {report:?}"
    );
    // Only its first line deleted.
    let cut = saved.find('\n').unwrap() + 1;
    std::fs::write(&oldest, &saved[cut..]).unwrap();
    let report = verify(&path, keys);
    assert_eq!(report.exit_code(), 1, "the oldest line deleted: {report:?}");
    // Put back as it was: the writer's prune record names it again.
    std::fs::write(&oldest, &saved).unwrap();
    assert_eq!(verify(&path, keys).exit_code(), 0);
}

/// R37-14, legacy rule: a trail pruned before prune records existed carries
/// none. It stays readable, and `verify` reports a break (never a silent
/// pass) until an operator who checked it acknowledges the prune.
#[test]
fn a_trail_pruned_without_a_prune_record_is_readable_and_verifies_only_once_acknowledged() {
    let (path, key, archives) = rotated_keyed_trail("r37-14-legacy", 94, 40);
    let keys = std::slice::from_ref(&key);
    std::fs::remove_file(&archives[0]).unwrap();
    let report = verify(&path, keys);
    assert_eq!(report.exit_code(), 1, "{report:?}");
    assert!(report.pruned_without_record, "{report:?}");
    assert!(report.other_break.is_none(), "{report:?}");
    let reader = keyed(&path, &key, 0);
    let read = reader.read_tail_filtered(100, AuditSelector::All).2;
    assert!(read > 0, "still readable");
    let (seq, _) = reader.acknowledge_prune().unwrap();
    assert_eq!(Some(seq), report.first_seq);
    close(reader);
    let after = verify(&path, keys);
    assert_eq!(after.exit_code(), 0, "{after:?}");
    assert!(!after.pruned_without_record);
    assert_eq!(after.prune_records, 1);
    // A prune acknowledged is a prune named: deleting one more archive is a
    // break again.
    let oldest = archives_of(&path).into_iter().next().unwrap().1;
    std::fs::remove_file(&oldest).unwrap();
    assert_eq!(verify(&path, keys).exit_code(), 1);
}

/// T-6: an archive scanned because its index cannot be had (a file stands
/// where the index directory goes), with the substring prefilter, still
/// walks every line through the gate: the key adoption and the records
/// between two verdicts on one transaction — lines the prefilter does not
/// want — move the walk on, so the later verdict continues it and is the
/// one found, and both are counted. (Before Round 38 a prefiltered line
/// skipped the gate and froze what it knew: the later verdict then did not
/// continue the last line judged, and the scan answered with the earlier.)
#[test]
fn an_archive_scanned_with_a_prefilter_walks_every_line() {
    let dir = temp_dir("t-6");
    let path = audit_path(&dir);
    std::fs::write(path.with_file_name("audit.jsonl-index"), b"not a directory").unwrap();
    let (_, k1) = key_file("t-6-old", 95);
    let (_, k2) = key_file("t-6-new", 96);
    let log = keyed(&path, &k1, 0);
    write_n(&log, 0, 3);
    close(log);
    let log = AuditLog::open_with_options(
        &path,
        AuditOptions {
            rotate_bytes: 9_000,
            key: Some(k2.clone()),
            previous_key: Some(k1.clone()),
            ..AuditOptions::default()
        },
    )
    .unwrap();
    assert!(log.append(&victim_approval("gr-after-adoption")));
    // Lines the prefilter does not want between two records it does: each
    // must move the walk on, or the later one does not continue it.
    write_n(&log, 3, 3);
    assert!(log.append(&victim_refusal("gr-refused-later")));
    write_n(&log, 6, 40);
    close(log);
    let archive = archive_with(&path, "gr-after-adoption");
    let text = std::fs::read_to_string(&archive).unwrap();
    assert!(text.contains(chain::KEY_ADOPTION) && text.contains("gr-refused-later"));
    // K2 only: the K1 records are vouched for by the adoption.
    let server = keyed(&path, &k2, 0);
    let before = server.archive_scans.load(Ordering::Relaxed);
    let tx = VerificationKey::TransactionSha256(VICTIM_TX);
    let found = server.find_verification(tx);
    let counted = server.count_verifications(tx);
    let id = server.find_verification(VerificationKey::AuditTrailId("gr-00001"));
    assert!(
        server.archive_scans.load(Ordering::Relaxed) > before,
        "scanned"
    );
    close(server);
    assert_eq!(
        found.map(|r| r.audit_trail_id),
        Some("gr-refused-later".into()),
        "the scan did not reach the newest verdict"
    );
    assert_eq!(counted, (1, 1));
    assert!(id.is_some(), "a record under K1, before the adoption");
}

/// T-12: keys were supplied and the trail is under none of them: nothing is
/// covered by the keys given, exit 4. It was 2, which is what a lost key
/// whose records a checked adoption covers exits.
#[test]
fn a_trail_under_no_supplied_key_is_not_covered() {
    let dir = temp_dir("t-12");
    let path = audit_path(&dir);
    let (_, k1) = key_file("t-12", 97);
    let (_, other) = key_file("t-12-other", 98);
    let log = keyed(&path, &k1, 0);
    write_n(&log, 0, 4);
    close(log);
    assert_eq!(verify(&path, std::slice::from_ref(&other)).exit_code(), 4);
    assert_eq!(verify(&path, &[]).exit_code(), 2, "no key at all: unproven");
    assert_eq!(verify(&path, std::slice::from_ref(&k1)).exit_code(), 0);
}

/// T-15: a line longer than the bound (`chain::MAX_LINE_BYTES`, 8 MiB) is a
/// break, and no reader reads it. A self-hashed record continuing the head
/// of an unkeyed trail is otherwise a record like any other.
#[test]
fn a_line_over_the_bound_is_a_break_and_never_read() {
    let dir = temp_dir("t-15");
    let path = audit_path(&dir);
    let log = AuditLog::open_with_rotation(&path, 0, 0).unwrap();
    write_n(&log, 0, 3);
    close(log);
    let mut victim = victim_approval("gr-huge");
    victim.instruction_name = "x".repeat(chain::MAX_LINE_BYTES + 1);
    let mut lines = lines_of(&path);
    lines.push(chain::seal(map_of(&victim), &head_of(&path), None).0);
    write_lines(&path, &lines);
    let report = verify(&path, &[]);
    assert_eq!(report.exit_code(), 1, "{:?}", report.first_break);
    let reader = AuditLog::open_read_only(&path).unwrap();
    let found = reader.find_verification(VerificationKey::TransactionSha256(VICTIM_TX));
    let total = reader.read_tail_filtered(100, AuditSelector::All).2;
    reader.wait_for_index_jobs();
    assert!(found.is_none(), "a line over the bound was read");
    assert_eq!(total, 3);
    // The writer refuses to write one.
    let log = AuditLog::open_with_rotation(audit_path(&temp_dir("t-15-w")), 0, 0).unwrap();
    assert!(!log.append(&victim), "a record over the bound was written");
    assert!(log.append(&rec("gr-small", true)));
    close(log);
}

/// T-15: the bounded line reader keeps at most the bound in memory and
/// reads past the rest of a longer line.
#[test]
fn the_line_reader_holds_at_most_the_bound() {
    let mut input = vec![b'a'; 3 * 1024 + 7];
    input.push(b'\n');
    input.extend_from_slice(b"short\nnone");
    let mut r = std::io::BufReader::with_capacity(64, &input[..]);
    let mut buf = Vec::new();
    let (n, end) = chain::read_line_bounded(&mut r, &mut buf, 1024).unwrap();
    assert_eq!(
        (n, end),
        (3 * 1024 + 8, chain::LineEnd::Oversized { terminated: true })
    );
    assert!(buf.capacity() <= 1024 + 64, "{}", buf.capacity());
    assert!(buf.is_empty());
    assert_eq!(
        chain::read_line_bounded(&mut r, &mut buf, 1024).unwrap(),
        (6, chain::LineEnd::Terminated)
    );
    assert_eq!(buf, b"short");
    assert_eq!(
        chain::read_line_bounded(&mut r, &mut buf, 1024).unwrap(),
        (4, chain::LineEnd::Unterminated)
    );
    assert_eq!(
        chain::read_line_bounded(&mut r, &mut buf, 1024).unwrap(),
        (0, chain::LineEnd::Eof)
    );
}

/// T-11: `graphite execution` read the trail with no key, so a self-hashed
/// approval claiming a MAC under the trail's key (one that does not verify)
/// was the verdict it reconciled against. It now reads with the keys the
/// server is configured with, and refuses a keyed trail it has no key for.
#[cfg(feature = "cli")]
#[test]
fn graphite_execution_reads_the_trail_with_the_configured_keys() {
    let dir = temp_dir("t-11");
    let path = audit_path(&dir);
    let (key_path, key) = key_file("t-11", 99);
    let (other_path, _) = key_file("t-11-other", 100);
    let log = keyed(&path, &key, 0);
    write_n(&log, 0, 3);
    close(log);
    let mut lines = lines_of(&path);
    let last = lines.last().unwrap().clone();
    lines.push(self_hashed_forgery(
        &last,
        map_of(&victim_approval("gr-forged")),
        ForgedMac::UnderTheTrailKey,
        &key,
    ));
    write_lines(&path, &lines);
    let tx = VerificationKey::TransactionSha256(VICTIM_TX);
    // What `graphite execution` read until Round 38.
    let keyless = AuditLog::open_read_only(&path).unwrap();
    assert!(
        keyless.find_verification(tx).is_some(),
        "documented limit: a reader without the key reads the forgery"
    );
    keyless.wait_for_index_jobs();
    let key_arg = key_path.to_str().unwrap();
    let reader = crate::cli::execution_audit_log(&dir, Some(key_arg), None).unwrap();
    assert!(
        reader.find_verification(tx).is_none(),
        "graphite execution read a forged approval"
    );
    assert!(reader
        .find_verification(VerificationKey::AuditTrailId("gr-00001"))
        .is_some());
    reader.wait_for_index_jobs();
    let none = crate::cli::execution_audit_log(&dir, None, None).unwrap_err();
    assert!(none.contains("no key is configured"), "{none}");
    let other = crate::cli::execution_audit_log(&dir, other_path.to_str(), None).unwrap_err();
    assert!(other.contains("not a configured key"), "{other}");
    assert!(crate::cli::execution_audit_log(&dir, Some("/no/such/key"), None).is_err());
}

// ---------------------------------------------------------------------------
// Round 39 (core-boundary audit): R39-CB-1.
// ---------------------------------------------------------------------------

/// R39-CB-1: a record of another trail under the same key, appended to the
/// end of the active file. The readers pin the trail id of the trail's
/// newest record, and the newest record is whoever appended last: under that
/// pin every genuine record was refused, the foreign record was the only line
/// the walk admitted, and so it "continued" the walk. A restarted writer (the
/// server) resumed onto the other trail: its readers saw none of the real
/// history (the victim's refusal was gone, the foreign trail's approval of the
/// same transaction was the verdict on record), and its next records extended
/// the other trail. `graphite audit verify` reported the break; the writer
/// did not. A writer now refuses to resume, and a keyed read-only reader
/// (`graphite execution`) to open, a trail that holds MAC-verified records
/// of two trails.
#[test]
fn a_record_of_another_trail_at_the_end_does_not_become_the_trail() {
    let (_, key) = key_file("r39-cb-1", 41);
    let tx = VerificationKey::TransactionSha256(VICTIM_TX);
    // Another trail under the same key, whose newest record approves the
    // victim's transaction.
    let other = audit_path(&temp_dir("r39-cb-1-other"));
    let log = keyed(&other, &key, 0);
    write_n(&log, 0, 3);
    assert!(log.append(&victim_approval("gr-foreign")));
    close(log);
    let foreign = lines_of(&other).last().unwrap().clone();

    // The target trail, which refused that transaction.
    let path = audit_path(&temp_dir("r39-cb-1"));
    let log = keyed(&path, &key, 0);
    write_n(&log, 100, 4);
    let mut refusal = victim_approval("gr-refused");
    refusal.approved = false;
    refusal.decision = Some("blocked".into());
    refusal.executable = Some(false);
    assert!(log.append(&refusal));
    close(log);
    let genuine = lines_of(&path);

    let mut lines = genuine.clone();
    lines.push(foreign.clone());
    write_lines(&path, &lines);
    assert_eq!(verify(&path, std::slice::from_ref(&key)).exit_code(), 1);
    match try_keyed(&path, &key) {
        Ok(server) => {
            let newest = server.find_verification(tx);
            let readable = server.read_tail_filtered(100, AuditSelector::All).2;
            close(server);
            panic!(
                "the writer resumed onto another trail: the victim's verdict on record is {newest:?}, {readable} of 5 genuine records readable"
            );
        }
        Err(e) => {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "{e}");
            assert!(e.to_string().contains("another trail"), "{e}");
        }
    }
    // `graphite execution`'s reader refuses it too.
    match AuditLog::open_read_only_keyed(&path, vec![key.clone()]) {
        Ok(reader) => {
            let newest = reader.find_verification(tx);
            reader.wait_for_index_jobs();
            panic!(
                "a keyed reader opened a trail of two trails: the victim's verdict on record is {newest:?}"
            );
        }
        Err(e) => assert!(e.to_string().contains("another trail"), "{e}"),
    }

    // The same record at the top of the trail (R37-5's top insertion) is two
    // trails on disk as well: refused at start now (re-pinned from Round 38,
    // where the writer started and pinned its own head's id), since nothing
    // in the trail says which of two trails under one key is this one.
    let mut lines = genuine.clone();
    lines.insert(0, foreign.clone());
    write_lines(&path, &lines);
    assert!(
        try_keyed(&path, &key).is_err(),
        "two trails on disk, resumed"
    );

    // Benign control: the genuine trail resumes, its refusal is the verdict.
    write_lines(&path, &genuine);
    let server = try_keyed(&path, &key).expect("the genuine trail resumes");
    let newest = server
        .find_verification(tx)
        .expect("the refusal is on record");
    assert!(
        !newest.approved && newest.audit_trail_id == "gr-refused",
        "{newest:?}"
    );
    assert_eq!(server.read_tail_filtered(100, AuditSelector::All).2, 5);
    // Appended beside the running writer, the foreign record is still never
    // read: the running writer's pin is its own trail's id.
    let mut lines = lines_of(&path);
    lines.push(foreign);
    write_lines(&path, &lines);
    let newest = server
        .find_verification(tx)
        .expect("the refusal is on record");
    assert_eq!(newest.audit_trail_id, "gr-refused");
    close(server);
}

/// Resident memory of this process, in KiB (Linux).
#[cfg(target_os = "linux")]
fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
        .unwrap()
}

/// R39-CB-5 (measurement, not a gate): what a keyed reader holds for a
/// history of unkeyed records a key adoption covers. `TrailFacts::covered`
/// keeps one `(seq, 16-byte hash)` per covered record for the life of the
/// process (the server computes it at start), so the memory grows with the
/// unkeyed history, not with anything bounded. The trail is opened in a
/// fresh child process (this test, re-run with `CB5_OPEN`), so what earlier
/// steps allocated and freed does not hide what the reader holds. Run with
/// `cargo test --lib keyed_reader_memory -- --ignored --nocapture`.
#[cfg(target_os = "linux")]
#[test]
#[ignore]
fn keyed_reader_memory_for_an_adopted_unkeyed_history() {
    if let Ok(dir) = std::env::var("CB5_OPEN") {
        let path = audit_path(Path::new(&dir));
        let key = AuditKey::from_bytes(&[77u8; 32]).unwrap();
        let before = rss_kib();
        let t = std::time::Instant::now();
        let server = keyed(&path, &key, 0);
        let opened = t.elapsed();
        let after = rss_kib();
        println!("CB5 {before} {after} {}", opened.as_millis());
        close(server);
        return;
    }
    let n: u64 = std::env::var("CB5_RECORDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300_000);
    let dir = temp_dir("r39-cb-5");
    let path = audit_path(&dir);
    {
        // Unkeyed chained records, written as an unkeyed writer seals them.
        use std::io::Write;
        let mut out = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        let mut head = chain::ChainHead {
            next_seq: 0,
            prev: chain::GENESIS,
            keyed: false,
            trail: Some(chain::new_trail_id(b"r39-cb-5")),
        };
        for i in 0..n {
            let mut m = serde_json::Map::new();
            m.insert("i".into(), serde_json::json!(i));
            let (line, next) = chain::seal(m, &head, None);
            out.write_all(line.as_bytes()).unwrap();
            out.write_all(b"\n").unwrap();
            head = next;
        }
    }
    // The history in a rotated archive, so the active file's own indexes
    // (bounded by rotation) do not count in what is measured.
    let archive = path.with_extension("jsonl.1000-000000");
    std::fs::rename(&path, &archive).unwrap();
    let (_, key) = key_file("r39-cb-5", 77);
    let adopt = AuditLog::open_with_options(
        &path,
        AuditOptions {
            rotate_bytes: 0,
            key: Some(key.clone()),
            adopt_key: true,
            ..AuditOptions::default()
        },
    )
    .unwrap();
    close(adopt);
    let size = std::fs::metadata(&archive).unwrap().len();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "durable::chain_trail_tests::keyed_reader_memory_for_an_adopted_unkeyed_history",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("CB5_OPEN", &dir)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text
        .lines()
        .find_map(|l| l.split_once("CB5 ").map(|(_, rest)| rest))
        .unwrap_or_else(|| panic!("the child did not report: {text}"));
    let v: Vec<u64> = line
        .split_whitespace()
        .map(|x| x.parse().unwrap())
        .collect();
    let grown = v[1].saturating_sub(v[0]);
    eprintln!(
        "R39-CB-5: {n} unkeyed records ({} MiB, in an archive) under a key adoption: a keyed writer opened in {:.1} s, its resident memory {} KiB -> {} KiB ({:.0} bytes per covered record)",
        size >> 20,
        v[2] as f64 / 1000.0,
        v[0],
        v[1],
        grown as f64 * 1024.0 / n as f64
    );
    std::fs::remove_dir_all(&dir).ok();
}
