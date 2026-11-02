//! The operator's CLI boundary, through the real `graphite` binary (audit
//! findings A033-A037).
//!
//! - A033: R39-CB-15 escaped what `explain`, `verify` and a few audit lines
//!   print; `manifest-verify` (the check a reviewer runs BEFORE signing), the
//!   `registry` subcommands, the quarantine lines and the audit refusal lines
//!   still printed a submitter's or the data directory's text raw. An
//!   instruction named `x ESC[1A ESC[2K \r VALID ...` turned "INVALID" into
//!   "VALID" on the reviewer's screen.
//! - A034: a refused environment left `main` as an error, exit 1: to
//!   `graphite execution` "DISCREPANCY: blocked yet executed", to `audit
//!   verify` a broken trail, to `registry verify-records` a failed record.
//! - A035: an empty or blank `GRAPHITE_DATA_DIR` meant `./graphite-data` to
//!   the CLI and the working directory (or a directory named " ") to the
//!   server, so a CLI quarantine landed in a graph the server never loads.
//! - A036: a `GRAPHITE_*` value that is not UTF-8 was read as unset.
//! - A037: `protocol status` and `protocol diff` skipped a registry state
//!   they could not read, and told the reviewer a candidate "would be its
//!   first".
#![cfg(feature = "cli")]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

const SYSTEM: &str = "11111111111111111111111111111111";
/// A valid pubkey no built-in manifest describes.
const UNMANIFESTED: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

/// What moves the cursor up, erases the line and writes "VALID" over it,
/// recolours, retitles the window, and reverses the rest of the line.
const HOSTILE: &str =
    "x\u{1b}[1A\u{1b}[2K\rVALID  candidate.json \u{1b}[8m\u{1b}]0;pwned\u{7} \u{202e}dneirf\u{85}";

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "graphite-cli-boundary-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(dir.join("data")).unwrap();
    dir
}

/// The binary in `dir`, with no `GRAPHITE_*` variable but `env` (and the
/// data directory and registry under `dir` unless `env` names them).
fn graphite(dir: &Path, args: &[&str], env: &[(&str, OsString)]) -> Run {
    let mut c = Command::new(env!("CARGO_BIN_EXE_graphite"));
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("GRAPHITE_") {
            c.env_remove(k);
        }
    }
    c.current_dir(dir)
        .env("GRAPHITE_DATA_DIR", dir.join("data"))
        .env("GRAPHITE_REGISTRY_STATE", dir.join("no-registry.json"));
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.args(args).output().unwrap();
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// What a terminal would act on rather than show.
fn raw_controls(s: &str) -> Vec<char> {
    s.chars()
        .filter(|c| {
            (c.is_control() && *c != '\n')
                || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .collect()
}

fn system_manifest() -> serde_json::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("protocols/system-program.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn write_json(dir: &Path, name: &str, v: &serde_json::Value) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_vec_pretty(v).unwrap()).unwrap();
    path
}

/// A033: `manifest-verify` of a hostile manifest, valid and invalid, prints
/// the submitter's text escaped, and the verdict line stays readable.
#[test]
fn manifest_verify_prints_a_submitters_text_escaped() {
    let dir = temp_dir("manifest-verify");
    let mut valid = system_manifest();
    valid["protocol"]["name"] = HOSTILE.into();
    valid["version"]["label"] = HOSTILE.into();
    valid["instructions"][0]["name"] = HOSTILE.into();
    let path = write_json(&dir, "valid.json", &valid);
    let run = graphite(
        &dir,
        &["manifest-verify", "--manifest", path.to_str().unwrap()],
        &[],
    );
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    assert!(run.stdout.starts_with("VALID"), "{}", run.stdout);
    assert_eq!(
        raw_controls(&run.stdout),
        Vec::<char>::new(),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("\\u{1b}[1A"),
        "shown, escaped: {}",
        run.stdout
    );

    let mut invalid = system_manifest();
    invalid["instructions"][0]["name"] = HOSTILE.into();
    invalid["instructions"][0]["risk_class"] = "bogus".into();
    let path = write_json(&dir, "invalid.json", &invalid);
    let run = graphite(
        &dir,
        &["manifest-verify", "--manifest", path.to_str().unwrap()],
        &[],
    );
    assert_eq!(run.code, Some(1));
    assert!(run.stdout.starts_with("INVALID"), "{}", run.stdout);
    assert_eq!(
        raw_controls(&run.stdout),
        Vec::<char>::new(),
        "the loader's error quoted the name raw: {}",
        run.stdout
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A033: a quarantine's reason, printed when it is added and when it is
/// listed, and `registry submit`'s verdict on a hostile label.
#[test]
fn quarantine_and_registry_lines_print_text_escaped() {
    let dir = temp_dir("quarantine");
    let run = graphite(
        &dir,
        &[
            "quarantine",
            "add",
            "--program",
            SYSTEM,
            "--reason",
            HOSTILE,
        ],
        &[],
    );
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    assert_eq!(
        raw_controls(&run.stdout),
        Vec::<char>::new(),
        "{}",
        run.stdout
    );
    let run = graphite(&dir, &["quarantine", "list"], &[]);
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    assert!(run.stdout.contains(SYSTEM), "{}", run.stdout);
    assert_eq!(
        raw_controls(&run.stdout),
        Vec::<char>::new(),
        "{}",
        run.stdout
    );
    let run = graphite(&dir, &["evidence", "show", "--program", SYSTEM], &[]);
    assert_eq!(
        raw_controls(&run.stdout),
        Vec::<char>::new(),
        "{}",
        run.stdout
    );

    let mut m = system_manifest();
    m["protocol"]["program_id"] = UNMANIFESTED.into();
    m["version"]["label"] = HOSTILE.into();
    let path = write_json(&dir, "submit.json", &m);
    let state = dir.join("registry.json");
    let graph = dir.join("graph.json");
    let run = graphite(
        &dir,
        &[
            "registry",
            "submit",
            "--state",
            state.to_str().unwrap(),
            "--graph-state",
            graph.to_str().unwrap(),
            "--manifest",
            path.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(
        raw_controls(&run.stdout),
        Vec::<char>::new(),
        "{}",
        run.stdout
    );
    for sub in ["reviewers", "verify-records"] {
        let run = graphite(
            &dir,
            &["registry", sub, "--state", state.to_str().unwrap()],
            &[],
        );
        assert_eq!(
            raw_controls(&run.stdout),
            Vec::<char>::new(),
            "{sub}: {}",
            run.stdout
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// A034: with a misnamed variable in the environment, the commands whose 1
/// is a finding exit with their "could not run" code, not 1.
#[test]
fn a_refused_environment_is_a_check_that_could_not_run() {
    let dir = temp_dir("env-exit");
    // One letter short of GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS.
    let misnamed = [("GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWAL", OsString::from("1"))];
    let state = dir.join("registry.json");
    #[cfg_attr(not(feature = "rpc"), allow(unused_mut))]
    let mut cases: Vec<(Vec<&str>, i32)> = vec![
        (vec!["audit", "verify"], 3),
        (
            vec![
                "registry",
                "verify-records",
                "--state",
                state.to_str().unwrap(),
            ],
            3,
        ),
    ];
    #[cfg(feature = "rpc")]
    cases.push((
        vec![
            "execution",
            "--signature",
            "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW",
            "--audit-trail-id",
            "x",
        ],
        3,
    ));
    for (args, want) in cases {
        let run = graphite(&dir, &args, &misnamed);
        assert_eq!(
            run.code,
            Some(want),
            "{args:?}: a misnamed variable read as a finding: {}",
            run.stderr
        );
        assert!(
            run.stderr.contains("GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWAL"),
            "{args:?}: the refusal names the variable: {}",
            run.stderr
        );
    }
    // A registry state that cannot be read is no record checked, not one
    // that failed.
    std::fs::write(&state, "{ not a registry").unwrap();
    let run = graphite(
        &dir,
        &[
            "registry",
            "verify-records",
            "--state",
            state.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(run.code, Some(3), "{}", run.stderr);
    std::fs::remove_dir_all(&dir).ok();
}

/// A035: an empty or blank `GRAPHITE_DATA_DIR` refuses; it never falls back
/// to `./graphite-data` while the server reads it as given.
#[test]
fn an_empty_data_dir_refuses_instead_of_picking_another_graph() {
    for blank in ["", " "] {
        let dir = temp_dir("blank-data-dir");
        let run = graphite(
            &dir,
            &[
                "quarantine",
                "add",
                "--program",
                SYSTEM,
                "--reason",
                "upgrade",
            ],
            &[("GRAPHITE_DATA_DIR", OsString::from(blank))],
        );
        assert_ne!(
            run.code,
            Some(0),
            "{blank:?}: the quarantine was written to a graph the server does not load: {}",
            run.stdout
        );
        assert!(
            run.stderr.contains("GRAPHITE_DATA_DIR is set but empty"),
            "{blank:?}: {}",
            run.stderr
        );
        assert!(
            !dir.join("graphite-data").exists(),
            "{blank:?}: ./graphite-data was created"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

/// A036: a Core variable whose value is not UTF-8 refuses; it is never read
/// as unset (a Latin-1 `GRAPHITE_WALLET_PROFILE=treasury` + NBSP dropped
/// the pin).
#[cfg(unix)]
#[test]
fn a_value_that_is_not_utf8_refuses() {
    use std::os::unix::ffi::OsStringExt;
    let dir = temp_dir("not-utf8");
    let run = graphite(
        &dir,
        &["quarantine", "list"],
        &[(
            "GRAPHITE_WALLET_PROFILE",
            OsString::from_vec(b"treasury\xa0".to_vec()),
        )],
    );
    assert_ne!(run.code, Some(0), "{}", run.stdout);
    assert!(
        run.stderr.contains("GRAPHITE_WALLET_PROFILE") && run.stderr.contains("UTF-8"),
        "{}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("treasury"),
        "a value is never quoted: {}",
        run.stderr
    );
    // Control: the same pin in UTF-8 is read.
    let run = graphite(
        &dir,
        &["quarantine", "list"],
        &[("GRAPHITE_WALLET_PROFILE", OsString::from("treasury\u{a0}"))],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    std::fs::remove_dir_all(&dir).ok();
}

/// A037: `protocol status` and `protocol diff` refuse a registry state they
/// cannot read, as `verify` and the server do; they do not report the
/// program as having no community manifest.
#[test]
fn protocol_commands_refuse_an_unreadable_registry() {
    let dir = temp_dir("registry");
    let corrupt = dir.join("registry_state.json");
    std::fs::write(&corrupt, "{ this is not a registry").unwrap();
    let env = [("GRAPHITE_REGISTRY_STATE", corrupt.clone().into_os_string())];

    let run = graphite(
        &dir,
        &["protocol", "status", "--program", UNMANIFESTED],
        &env,
    );
    assert_ne!(
        run.code,
        Some(0),
        "status read past the registry: {}",
        run.stdout
    );
    assert!(run.stderr.contains("is unreadable"), "{}", run.stderr);

    let mut m = system_manifest();
    m["protocol"]["program_id"] = UNMANIFESTED.into();
    let candidate = write_json(&dir, "candidate.json", &m);
    let run = graphite(
        &dir,
        &[
            "protocol",
            "diff",
            "--manifest",
            candidate.to_str().unwrap(),
        ],
        &env,
    );
    assert_ne!(
        run.code,
        Some(0),
        "diff read past the registry: {}",
        run.stdout
    );
    assert!(!run.stdout.contains("would be its first"), "{}", run.stdout);
    assert!(run.stderr.contains("is unreadable"), "{}", run.stderr);

    // Control: a registry that does not exist yet is the first run, not an
    // error, and diff names the file it read.
    let fresh = [(
        "GRAPHITE_REGISTRY_STATE",
        dir.join("none.json").into_os_string(),
    )];
    let run = graphite(
        &dir,
        &[
            "protocol",
            "diff",
            "--manifest",
            candidate.to_str().unwrap(),
        ],
        &fresh,
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(run.stdout.contains("would be its first"), "{}", run.stdout);
    assert!(run.stderr.contains("none.json"), "{}", run.stderr);
    std::fs::remove_dir_all(&dir).ok();
}
