//! Round 40 (bootstrap): `graphite evidence import-census` through the real
//! binary — dry run, import, idempotence, skipped records, a tampered census
//! file, the audit rows, and a keyed trail (docs/ops/keys.md).
#![cfg(feature = "cli")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SYSTEM: &str = "11111111111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const BUBBLEGUM: &str = "BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY";

fn graphite() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_graphite"));
    for k in [
        "GRAPHITE_DATA_DIR",
        "GRAPHITE_AUDIT_KEY_FILE",
        "GRAPHITE_AUDIT_PREVIOUS_KEY_FILE",
        "GRAPHITE_AUDIT_ANCHOR_DIR",
        "GRAPHITE_AUDIT_ROTATE_BYTES",
        "GRAPHITE_AUDIT_MAX_ARCHIVES",
    ] {
        c.env_remove(k);
    }
    c
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "graphite-r40-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn import(data: &Path, extra: &[&str], key: Option<&Path>) -> Output {
    let mut c = graphite();
    c.args([
        "evidence",
        "import-census",
        "--cluster",
        "mainnet-beta",
        "--data-dir",
    ])
    .arg(data)
    .args(extra);
    if let Some(k) = key {
        c.env("GRAPHITE_AUDIT_KEY_FILE", k);
    }
    c.output().unwrap()
}

fn operator_rows(data: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(data.join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["event_type"] == "operator_action")
        .collect()
}

fn show(data: &Path, program: &str) -> String {
    text(
        &graphite()
            .args(["evidence", "show", "--data-dir"])
            .arg(data)
            .args(["--program", program])
            .output()
            .unwrap(),
    )
}

fn census_sha256() -> String {
    graphite_core::census_import::embedded_census_sha256()
}

#[test]
fn a_dry_run_reports_and_writes_nothing() {
    let root = temp_dir("dry");
    let data = root.join("data");
    let o = import(&data, &["--dry-run"], None);
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    assert!(
        out.contains(&format!("sha256={}", census_sha256())),
        "{out}"
    );
    assert!(out.contains("114 to import, 23 skipped"), "{out}");
    assert!(
        out.contains("standalone confidence 0.4400 -> 0.5900"),
        "{out}"
    );
    assert!(out.contains("DRY RUN: nothing was written"), "{out}");
    assert!(
        !data.join("semantic_graph.json").exists() && !data.join("audit.jsonl").exists(),
        "a dry run wrote to the data directory"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_import_records_each_program_once_and_a_rerun_imports_nothing() {
    let root = temp_dir("import");
    let data = root.join("data");
    let o = import(&data, &[], None);
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    assert!(out.contains("IMPORTED 114 program(s)"), "{out}");
    // Skipped records are listed with their reason.
    assert!(
        out.lines()
            .any(|l| l.starts_with(&format!("SKIP    {BUBBLEGUM}"))
                && l.contains("decode rate 0.057")),
        "{out}"
    );
    let rows = operator_rows(&data);
    assert_eq!(rows.len(), 114, "one operator_action row per import");
    let system = rows.iter().find(|r| r["content_hash"] == SYSTEM).unwrap();
    let detail = system["detail"].as_str().unwrap();
    for needle in [
        "census-measured",
        &format!("battle_tested_evidence.json sha256={}", census_sha256()),
        "measured_at 2026-09-23T00:15:01Z",
        "battle_tested 0 -> 1456",
        "evidence bound to slot 449537377",
        "graph tier recomputed to HeuristicInferred",
    ] {
        assert!(detail.contains(needle), "{needle}: {detail}");
    }
    assert!(show(&data, SYSTEM).contains("battle_tested=1456"));
    assert!(show(&data, TOKEN).contains("signed_manifest=false"));

    // Idempotent: nothing new, no new row.
    let o = import(&data, &[], None);
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    assert!(out.contains("0 to import, 137 skipped"), "{out}");
    assert!(out.contains("Nothing imported"), "{out}");
    assert_eq!(operator_rows(&data).len(), 114);

    let v = graphite()
        .args(["audit", "verify", "--data-dir"])
        .arg(&data)
        .output()
        .unwrap();
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_program_filter_imports_only_what_it_names() {
    let root = temp_dir("filter");
    let data = root.join("data");
    let o = import(&data, &["--program", SYSTEM, "--program", TOKEN], None);
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    assert!(
        out.contains("2 to import, 0 skipped, 135 not selected"),
        "{out}"
    );
    assert_eq!(operator_rows(&data).len(), 2);
    let o = import(&data, &["--program", "not-a-key"], None);
    assert!(!o.status.success());
    let o = import(
        &data,
        &["--program", "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7"],
        None,
    );
    assert!(!o.status.success());
    assert!(text(&o).contains("no record"), "{}", text(&o));
    assert_eq!(operator_rows(&data).len(), 2);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_tampered_census_file_is_refused_and_nothing_is_written() {
    let root = temp_dir("tamper");
    let data = root.join("data");
    let committed = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/protocols/battle_tested_evidence.json"
    );
    // The committed file itself is accepted.
    let o = import(&data, &["--census", committed, "--dry-run"], None);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("identical to the copy compiled into this build"));

    // A count raised where the record's own verdict does not change (System
    // Program's 1,456 to 145,600): only the hash can show it.
    let original = std::fs::read_to_string(committed).unwrap();
    let edited = original.replacen(
        "\"successful_transactions_counted\": 1456,",
        "\"successful_transactions_counted\": 145600,",
        1,
    );
    assert_ne!(original, edited, "the fixture edit applies");
    let tampered = root.join("battle_tested_evidence.json");
    std::fs::write(&tampered, edited).unwrap();
    let o = import(&data, &["--census", tampered.to_str().unwrap()], None);
    let out = text(&o);
    assert!(!o.status.success(), "{out}");
    assert!(
        out.contains("refusing the census file") && out.contains("sha256"),
        "{out}"
    );
    assert!(
        !data.join("semantic_graph.json").exists() && operator_rows(&data).is_empty(),
        "a refused census changed the data directory"
    );
    let _ = std::fs::remove_dir_all(&root);
}

fn key_file(root: &Path, byte: u8) -> PathBuf {
    let path = root.join(format!("audit-{byte:02x}.key"));
    std::fs::write(&path, format!("{byte:02x}").repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

/// As `evidence seed` (docs/ops/keys.md): with `GRAPHITE_AUDIT_KEY_FILE` the
/// rows are MAC'd under the server's key and `audit verify` proves them; a
/// keyed trail refuses an import run without its key, before any change.
#[test]
fn a_keyed_trail_takes_the_rows_under_its_key_and_refuses_an_unkeyed_import() {
    let root = temp_dir("keyed");
    let data = root.join("data");
    let key = key_file(&root, 0x41);
    let o = import(&data, &["--program", SYSTEM], Some(&key));
    assert!(o.status.success(), "{}", text(&o));
    let v = graphite()
        .args(["audit", "verify", "--key-file"])
        .arg(&key)
        .arg("--data-dir")
        .arg(&data)
        .output()
        .unwrap();
    let out = text(&v);
    assert_eq!(v.status.code(), Some(0), "{out}");
    assert!(out.contains("1 verified"), "{out}");

    let graph = std::fs::read(data.join("semantic_graph.json")).unwrap();
    let o = import(&data, &["--program", TOKEN], None);
    assert!(
        !o.status.success(),
        "an unkeyed import continued a keyed trail"
    );
    assert!(
        text(&o).contains("refusing an operator action that could not be recorded"),
        "{}",
        text(&o)
    );
    assert_eq!(
        std::fs::read(data.join("semantic_graph.json")).unwrap(),
        graph,
        "the refused import changed the graph"
    );
    assert_eq!(operator_rows(&data).len(), 1);

    // With the key it proceeds.
    let o = import(&data, &["--program", TOKEN], Some(&key));
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(operator_rows(&data).len(), 2);
    let _ = std::fs::remove_dir_all(&root);
}
