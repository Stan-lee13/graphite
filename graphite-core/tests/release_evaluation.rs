//! The release evaluation (`graphite benchmark --json`), pinned for the
//! committed inputs (roadmap R-P1, Round 30).
//!
//! Two things are pinned here, and they fail for different reasons:
//!
//! 1. **The sealed holdout has not moved.** The SHA-256 of each holdout source
//!    and of the holdout rows in `fixtures/corpus` is fixed. A script that
//!    rewrites the holdout — re-fetching, re-labelling, "fixing" a row the
//!    engine gets wrong — fails this test instead of quietly moving the
//!    target. Replacing the holdout is a deliberate reseal: new hashes, a new
//!    pin, and a note in the round report saying the holdout changed.
//! 2. **The numbers are what they are.** Every split's confusion matrix and
//!    every misclassified row is pinned. A change in any verdict on a
//!    committed labelled input fails this test; the fix is to look at which
//!    row moved and why, then re-pin with that attribution — exactly as
//!    `tests/mainnet_conformance.rs` does for the unlabelled blocks. A number
//!    that changes without anyone looking at why is how a benchmark drifts
//!    into a claim.

use graphite_core::release_eval::{evaluate, SplitReport, HOLDOUT_SOURCES, REPORT_SCHEMA};
use sha2::{Digest, Sha256};
use std::path::Path;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn sha256_file(rel: &str) -> String {
    let bytes = std::fs::read(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
    hex::encode(Sha256::digest(&bytes))
}

/// The holdout's sources, by SHA-256. Changing either is a reseal.
const SEALED_HOLDOUT: &[(&str, &str)] = &[
    (
        "tests/fixtures/exploit_corpus.json",
        "a08f1bbce0ff7e1115e282eb75f6d3853d7178121950fc00a9fc144643cc3d39",
    ),
    (
        "tests/fixtures/real_mainnet_jup.json",
        "ce99433707dd5799bfa6744e05e978a59e7a22b7468fb0f61da16a8c762c1caf",
    ),
];

/// SHA-256 over the holdout rows of `fixtures/corpus` (every fixture whose
/// source is `real-…`), sorted by content hash, each as
/// `content_hash\0integrity_hash\0expected_approved\n`. The rows are derived
/// from the sealed sources by `tests/regression_corpus.rs`; this catches a
/// regeneration that changed them.
const SEALED_HOLDOUT_ROWS_SHA256: &str =
    "2db78c121190123cfd9b20b39612b4b1c8db12b307843aca157861c355c5e8d7";

#[test]
fn the_sealed_holdout_has_not_moved() {
    assert_eq!(
        HOLDOUT_SOURCES.len(),
        SEALED_HOLDOUT.len(),
        "every holdout source is pinned"
    );
    for (rel, pinned) in SEALED_HOLDOUT {
        assert!(
            HOLDOUT_SOURCES.contains(rel),
            "{rel} is not a holdout source"
        );
        assert_eq!(
            &sha256_file(rel),
            pinned,
            "{rel} changed: the holdout is sealed. Replacing it is a reseal — re-pin here and say so in the round report"
        );
    }

    let mut rows: Vec<String> = Vec::new();
    let dir = root().join("fixtures/corpus");
    for entry in std::fs::read_dir(&dir).expect("fixtures/corpus") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        for f in doc.as_array().expect("array of fixtures") {
            if f["source"].as_str().unwrap_or("").starts_with("real-") {
                rows.push(format!(
                    "{}\0{}\0{}\n",
                    f["content_hash"].as_str().expect("content_hash"),
                    f["integrity_hash"].as_str().unwrap_or(""),
                    f["expected_approved"].as_bool().expect("expected_approved"),
                ));
            }
        }
    }
    rows.sort();
    assert_eq!(rows.len(), 38, "37 real exploits + 1 real benign swap");
    let digest = hex::encode(Sha256::digest(rows.concat().as_bytes()));
    assert_eq!(
        digest, SEALED_HOLDOUT_ROWS_SHA256,
        "the holdout rows in fixtures/corpus changed: regenerating the corpus must not move the holdout"
    );
}

/// The one script that writes a holdout source refuses to overwrite it
/// unless the reseal is explicit, and no other file in the repository writes
/// one on the same line it names it.
#[test]
fn only_an_explicit_reseal_can_write_the_holdout() {
    let builder = root().join("../integrations/agent-guard/build_exploit_corpus.mts");
    let text = std::fs::read_to_string(&builder).expect("the holdout builder");
    let guard = text
        .find("GRAPHITE_RESEAL_HOLDOUT")
        .expect("the builder checks GRAPHITE_RESEAL_HOLDOUT");
    let write = text
        .find("fs.writeFileSync(target")
        .expect("the builder writes through the guarded `target`");
    assert!(guard < write, "the reseal check comes before the write");

    let repo = root().join("..");
    let mut offenders = Vec::new();
    let mut stack = vec![repo.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read_dir") {
            let path = entry.expect("dir entry").path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if path.is_dir() {
                if !matches!(
                    name,
                    "target" | "node_modules" | ".git" | ".claude" | "dist"
                ) {
                    stack.push(path);
                }
                continue;
            }
            if !matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("py" | "ts" | "mts" | "js" | "cjs" | "mjs" | "sh" | "rs" | "go")
            ) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            for line in text.lines() {
                let names_holdout = HOLDOUT_SOURCES
                    .iter()
                    .any(|h| line.contains(Path::new(h).file_name().unwrap().to_str().unwrap()));
                let writes = [
                    "writeFileSync",
                    "write_text",
                    "fs::write",
                    "File::create",
                    "open(",
                ]
                .iter()
                .any(|w| line.contains(w))
                    && !line.contains("include_str!");
                if names_holdout && writes {
                    offenders.push(format!("{}: {}", path.display(), line.trim()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a file writes a sealed holdout source directly: {offenders:#?}"
    );
}

fn split<'a>(splits: &'a [SplitReport], name: &str) -> &'a SplitReport {
    splits
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no split {name}"))
}

/// `(name, rows, errors, unscored, TP, TN, FP, FN)`.
type Pin = (
    &'static str,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
);

const PINNED: &[Pin] = &[
    ("holdout", 38, 0, 0, 37, 0, 1, 0),
    ("regression", 32, 6, 0, 21, 5, 0, 0),
    ("dev", 12_943, 38, 0, 11_808, 1_097, 0, 0),
    ("hand-built", 24, 0, 2, 15, 7, 0, 0),
];

#[test]
fn the_release_evaluation_is_pinned_for_the_committed_inputs() {
    let report = evaluate(root()).expect("the committed inputs evaluate");
    assert_eq!(report.schema, REPORT_SCHEMA);
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&report).expect("report serializes")
    );

    let names: Vec<&str> = report.splits.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["holdout", "regression", "dev", "hand-built"]);
    for &(name, rows, errors, unscored, tp, tn, fp, fn_) in PINNED {
        let s = split(&report.splits, name);
        assert_eq!(
            (s.rows, s.errors, s.unscored, s.true_positives, s.true_negatives, s.false_positives, s.false_negatives),
            (rows, errors, unscored, tp, tn, fp, fn_),
            "{name}: (rows, errors, unscored, TP, TN, FP, FN) moved — find the row that changed and why, then re-pin with that attribution"
        );
        // The matrix accounts for every row exactly once.
        assert_eq!(s.rows, s.errors + s.unscored + s.scored);
        assert_eq!(s.scored, tp + tn + fp + fn_);
        assert_eq!(s.misclassified.len(), fp + fn_ + s.errors_on_approve_labels);
    }

    // The holdout's one error is the one benign row: the real Jupiter swap,
    // refused at account resolution because its lookup tables cannot be
    // resolved offline. Every exploit is refused by a layer, none by an error.
    let holdout = split(&report.splits, "holdout");
    assert_eq!(
        holdout.misclassified,
        ["be9eea02a8d77deb3cf32a226ce661f697921675c96e8efad5eb1524336f8857"]
    );
    assert_eq!(
        holdout.refusal_reasons.get("L1_AccountResolution failed"),
        Some(&1)
    );

    // Errors are not detections, and which rows error is pinned too: the
    // regression replay counts these as passes (a gate refuses what it
    // cannot verify), and this report shows they are refusals by error.
    let causes = |name: &str| -> Vec<(String, usize)> {
        split(&report.splits, name)
            .error_reasons
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    };
    assert_eq!(
        causes("regression"),
        [
            ("account resolution failed".to_string(), 5),
            ("transaction build failed".to_string(), 1)
        ]
    );
    assert_eq!(
        causes("dev"),
        [("transaction build failed".to_string(), 38)]
    );
    assert!(causes("holdout").is_empty() && causes("hand-built").is_empty());

    let mainnet = &report.mainnet_sample;
    assert_eq!(mainnet.rows, 2_284);
    assert_eq!(mainnet.parsed, 2_284, "{:?}", mainnet.parse_failures);
    assert_eq!(mainnet.failed_on_chain, 366);

    // Every input the numbers came from is named with its hash, and so is the
    // registry: two reports with the same `deterministic_sha256` scored the
    // same inputs against the same manifests.
    let paths: Vec<&str> = report.inputs.iter().map(|i| i.path.as_str()).collect();
    for p in HOLDOUT_SOURCES {
        assert!(paths.contains(p), "{p} is not recorded as an input");
    }
    assert!(paths.contains(&"fixtures/corpus"));
    assert!(report.registry.manifests > 0 && report.registry.instructions > 0);
    assert_eq!(report.deterministic_sha256.len(), 64);
    // The code is named by its commit, read from the checkout's own files.
    assert!(
        report
            .code
            .git_head
            .as_deref()
            .is_some_and(|h| h.len() == 40 && h.chars().all(|c| c.is_ascii_hexdigit())),
        "{:?}",
        report.code
    );
    assert!(!report.sample_bias.is_empty());
}
