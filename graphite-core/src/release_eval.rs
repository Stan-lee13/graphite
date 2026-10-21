//! Release evaluation: a reproducible, machine-readable account of what the
//! engine does on every committed labelled input (roadmap R-P1, Round 30).
//!
//! `graphite benchmark --json` prints it. Everything it scores is read from
//! files in the repository — the regression corpus (`fixtures/corpus/`), the
//! real-mainnet holdout sources (`tests/fixtures/`), the committed mainnet
//! blocks (`fixtures/mainnet/`) and the hand-built benchmark cases — and the
//! report records the SHA-256 of each, the code HEAD, the manifest registry's
//! digest and the environment, so two runs can be compared and a number in a
//! document can be traced to the inputs that produced it.
//!
//! What it is careful NOT to claim:
//!
//! - The splits are scored separately and never pooled. Their labels mean
//!   different things: the holdout's come from provenance (a real exploit, a
//!   real successful swap), the regression split's from the attack class each
//!   fixture re-pins, the dev split's from DOCUMENTED RULES (so agreement there
//!   is rule conformance, not detection), and the hand-built cases' from the
//!   ground-truth sentence each one carries.
//! - The committed mainnet blocks carry no maliciousness label at all: a
//!   transaction the chain executed is not thereby benign. Only parse coverage
//!   is reported for them; their verdicts are pinned by
//!   `tests/mainnet_conformance.rs`.
//! - Every labelled input is verified in descriptive mode or with supplied
//!   evidence — no RPC, no simulation, no state diff. The numbers measure the
//!   rule engine, not an executable approval (`approved` here is the core
//!   verdict, not permission to sign).
//! - Proportions carry a Wilson 95% interval, because a holdout of 38 rows
//!   supports a much weaker statement than its point estimate suggests.

use crate::regression_engine::RegressionFixture;
use crate::verification::{GraphiteCore, LayerStatus, VerificationResult};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Schema identifier of the JSON this module emits. Bumped on any change to
/// the shape, never to the numbers.
pub const REPORT_SCHEMA: &str = "graphite.release-evaluation/1";

/// The sealed holdout's sources. The holdout is evaluated last and is never
/// used to tune anything; `tests/release_evaluation.rs` pins the SHA-256 of
/// each so a script that rewrites one fails the build instead of quietly
/// moving the target.
pub const HOLDOUT_SOURCES: &[&str] = &[
    "tests/fixtures/exploit_corpus.json",
    "tests/fixtures/real_mainnet_jup.json",
];

/// The committed mainnet blocks (unlabelled real traffic).
pub const MAINNET_SAMPLE: &str = "fixtures/mainnet/sample-2026-09-23-last-2-blocks.json";

/// The regression corpus directory.
pub const CORPUS_DIR: &str = "fixtures/corpus";

#[derive(Debug, thiserror::Error)]
pub enum ReleaseEvalError {
    #[error("{path}: {err}")]
    Read { path: String, err: String },
    #[error("{path}: {err}")]
    Parse { path: String, err: String },
    #[error("{path}: fixture {content_hash} fails its integrity check: {err}")]
    Integrity {
        path: String,
        content_hash: String,
        err: String,
    },
}

/// A proportion with its Wilson score interval (95%).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Rate {
    pub numerator: usize,
    pub denominator: usize,
    /// `None` when the denominator is zero: there is no rate to state.
    pub value: Option<f64>,
    pub wilson95: Option<[f64; 2]>,
}

impl Rate {
    pub fn new(numerator: usize, denominator: usize) -> Self {
        if denominator == 0 {
            return Self {
                numerator,
                denominator,
                value: None,
                wilson95: None,
            };
        }
        let (lo, hi) = wilson95(numerator, denominator);
        Self {
            numerator,
            denominator,
            value: Some(round6(numerator as f64 / denominator as f64)),
            wilson95: Some([round6(lo), round6(hi)]),
        }
    }
}

/// Wilson score interval at z = 1.96 for `k` successes out of `n`.
pub fn wilson95(k: usize, n: usize) -> (f64, f64) {
    assert!(n > 0 && k <= n, "wilson95 needs 0 <= k <= n, n > 0");
    let z = 1.959_963_984_540_054_f64;
    let n_f = n as f64;
    let p = k as f64 / n_f;
    let z2 = z * z;
    let denom = 1.0 + z2 / n_f;
    let center = (p + z2 / (2.0 * n_f)) / denom;
    let half = z * (p * (1.0 - p) / n_f + z2 / (4.0 * n_f * n_f)).sqrt() / denom;
    ((center - half).max(0.0), (center + half).min(1.0))
}

fn round6(x: f64) -> f64 {
    (x * 1e6).round() / 1e6
}

/// One split's outcome. "Positive" means the label says REFUSE: a true
/// positive is a refusal the label asked for, a false negative an approval it
/// did not.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SplitReport {
    pub name: String,
    /// What the labels in this split mean, in one sentence.
    pub label_meaning: String,
    pub rows: usize,
    /// Rows that verified and were scored.
    pub scored: usize,
    /// Rows with no label to score against (counted, never scored).
    pub unscored: usize,
    /// Rows whose verification returned an error. Counted on their own —
    /// an error is not a detection. (The regression engine's replay, and so
    /// the corpus tests, count an error as a block: right for a signing gate,
    /// which refuses what it cannot verify, but not evidence that a detector
    /// fired. Here they are kept apart, with their causes below.)
    pub errors: usize,
    /// Errors by cause (the error's text up to its first colon).
    pub error_reasons: BTreeMap<String, usize>,
    /// Errors on rows the label says to APPROVE. To the user these are
    /// refusals of a benign transaction, so they are counted in the
    /// false-refusal rate (and listed in `misclassified`), never hidden in
    /// `errors`.
    pub errors_on_approve_labels: usize,
    pub true_positives: usize,
    pub true_negatives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    /// Of the refusals the label asked for, how many were refused.
    pub recall: Rate,
    /// Of the refusals made on labelled rows, how many the label asked for.
    pub precision: Rate,
    /// Of the rows the label says to approve, how many were refused —
    /// by a layer or by an error.
    pub false_refusal_rate: Rate,
    /// For every refusal: the first layer that did not pass (or the risk
    /// verdict when every layer passed), with a count.
    pub refusal_reasons: BTreeMap<String, usize>,
    /// Row counts by the fixture's recorded source.
    pub sources: BTreeMap<String, usize>,
    /// Labels of rows the engine got wrong — a false positive, a false
    /// negative, or an error on an approve-labelled row — sorted (the
    /// content hash or case label, never the verdict text).
    pub misclassified: Vec<String>,
}

/// Parse coverage of the committed (unlabelled) mainnet blocks.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MainnetSampleReport {
    pub rows: usize,
    /// Rows the chain itself reports as failed (`err: true`).
    pub failed_on_chain: usize,
    pub by_version: BTreeMap<String, usize>,
    pub parsed: usize,
    /// Parse failures by error class. A frame the chain accepted and executed
    /// is one Graphite must read, so every entry here is a parser gap.
    pub parse_failures: BTreeMap<String, usize>,
    pub parse_rate: Rate,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct InputFile {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    /// For a directory: how many files were hashed (sorted by name, each as
    /// `name\0sha256\n`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<usize>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RegistryFacts {
    pub manifests: usize,
    pub instructions: usize,
    /// SHA-256 over every compiled-in seed manifest, in registry order, each
    /// as `file\0sha256(json)\n`.
    pub seed_manifests_sha256: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Environment {
    pub crate_version: String,
    pub os: String,
    pub arch: String,
    pub debug_assertions: bool,
    pub features: Vec<String>,
    /// `rustc --version` of the toolchain on PATH when the report ran, which
    /// is not necessarily the one that built this binary.
    pub rustc_on_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CodeIdentity {
    pub git_head: Option<String>,
    /// Tracked files differ from HEAD: the numbers are for uncommitted code.
    pub git_dirty: Option<bool>,
}

/// The whole report.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ReleaseEvaluation {
    pub schema: String,
    pub code: CodeIdentity,
    pub environment: Environment,
    pub registry: RegistryFacts,
    pub inputs: Vec<InputFile>,
    pub splits: Vec<SplitReport>,
    pub mainnet_sample: MainnetSampleReport,
    /// SHA-256 of the canonical JSON of `registry`, `inputs`, `splits` and
    /// `mainnet_sample` — everything that should be identical on any machine
    /// for the same inputs and engine.
    pub deterministic_sha256: String,
    /// Known biases of the inputs, stated so no number here is read as more
    /// than it is.
    pub sample_bias: Vec<String>,
}

/// Run the evaluation over the committed inputs under `root` (the
/// `graphite-core` directory).
pub fn evaluate(root: &Path) -> Result<ReleaseEvaluation, ReleaseEvalError> {
    let corpus = load_corpus(&root.join(CORPUS_DIR))?;

    let mut holdout = Vec::new();
    let mut regression = Vec::new();
    let mut dev = Vec::new();
    for f in corpus {
        if f.source.starts_with("real-") {
            holdout.push(f);
        } else if f.source == "synthetic-attack" || f.source == "synthetic-benign" {
            regression.push(f);
        } else {
            dev.push(f);
        }
    }

    let mut splits = vec![
        score_fixtures(
            "holdout",
            "provenance: a real mainnet exploit (refuse) or a real successful mainnet swap by an ordinary wallet (approve); never used for tuning",
            &holdout,
        ),
        score_fixtures(
            "regression",
            "attack class: each fixture re-pins one fixed attack shape (refuse) or a benign control (approve)",
            &regression,
        ),
        score_fixtures(
            "dev",
            "documented rule: the outcome Graphite's documented gates prescribe for a synthetic instruction — agreement is rule conformance, not detection",
            &dev,
        ),
    ];
    splits.push(score_hand_built());

    let mainnet_sample = mainnet_parse_coverage(&root.join(MAINNET_SAMPLE))?;

    let mut inputs = vec![hash_dir(root, CORPUS_DIR)?];
    for p in HOLDOUT_SOURCES.iter().chain([&MAINNET_SAMPLE]) {
        inputs.push(hash_file(root, p)?);
    }
    let registry = registry_facts();

    let deterministic_sha256 = {
        let canonical = serde_json::json!({
            "registry": registry,
            "inputs": inputs,
            "splits": splits,
            "mainnet_sample": mainnet_sample,
        });
        hex::encode(Sha256::digest(canonical.to_string().as_bytes()))
    };

    Ok(ReleaseEvaluation {
        schema: REPORT_SCHEMA.to_string(),
        code: code_identity(root),
        environment: environment(),
        registry,
        inputs,
        splits,
        mainnet_sample,
        deterministic_sha256,
        sample_bias: sample_bias(),
    })
}

fn sample_bias() -> Vec<String> {
    [
        "holdout: 37 of 38 rows are exploits and 1 is benign, so its false-refusal rate rests on one row and its precision is close to vacuous; 35 of the 37 exploits come from one study (SolPhishHunter, arXiv:2505.04094) and 31 of them are one class (ISA, an impersonated system or ComputeBudget account)",
        "holdout: the exploits are verified in descriptive mode (instruction shape, no transaction bytes, no simulation) with request-body evidence the engine does not let raise a tier; the Jupiter swap is refused offline because its lookup tables cannot be resolved without an RPC",
        "regression: synthetic shapes written to re-pin attacks already fixed — a perfect score shows those fixes hold, not that unseen attacks are caught",
        "dev: labels are derived from the same documented rules the engine implements, so this split measures conformance to the rules, not whether the rules are right",
        "hand-built: labels are written beside the engine they score; each case states its ground truth in words",
        "mainnet sample: two consecutive finalized blocks from one day (2026-09-23); real, uncurated traffic, but unlabelled and from a single two-block window",
        "nothing here is an executable verdict: no row is simulated, no state diff is observed, and `approved` is scored as the core verdict, not as permission to sign",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn load_corpus(dir: &Path) -> Result<Vec<RegressionFixture>, ReleaseEvalError> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| ReleaseEvalError::Read {
            path: dir.display().to_string(),
            err: e.to_string(),
        })?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    files.sort();
    let mut out = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).map_err(|e| ReleaseEvalError::Read {
            path: path.display().to_string(),
            err: e.to_string(),
        })?;
        let fixtures: Vec<RegressionFixture> =
            serde_json::from_str(&text).map_err(|e| ReleaseEvalError::Parse {
                path: path.display().to_string(),
                err: e.to_string(),
            })?;
        for f in fixtures {
            // The same check the regression engine applies on load: a fixture
            // edited without resealing is refused, not scored.
            f.verify_integrity()
                .map_err(|err| ReleaseEvalError::Integrity {
                    path: path.display().to_string(),
                    content_hash: f.content_hash.clone(),
                    err,
                })?;
            if !f.deprecated {
                out.push(f);
            }
        }
    }
    // File order, then content hash: independent of the directory listing.
    out.sort_by(|a, b| {
        (a.program_id.as_str(), a.content_hash.as_str())
            .cmp(&(b.program_id.as_str(), b.content_hash.as_str()))
    });
    Ok(out)
}

/// Why a refused verdict was refused: the first layer that did not pass,
/// or the risk verdict when every layer passed.
fn refusal_reason(result: &VerificationResult) -> String {
    if let Some(layer) = result
        .layers
        .iter()
        .find(|l| l.status == LayerStatus::Failed)
    {
        return format!("{} failed", layer.layer);
    }
    if result.risk_verdict.status != "Clear" {
        return format!("risk {}", result.risk_verdict.status);
    }
    if let Some(layer) = result
        .layers
        .iter()
        .find(|l| l.status == LayerStatus::Inconclusive)
    {
        return format!("{} inconclusive", layer.layer);
    }
    "policy (every layer passed)".to_string()
}

#[derive(Default)]
struct Tally {
    rows: usize,
    scored: usize,
    unscored: usize,
    errors: usize,
    error_reasons: BTreeMap<String, usize>,
    errors_on_approve: usize,
    tp: usize,
    tn: usize,
    fp: usize,
    fn_: usize,
    reasons: BTreeMap<String, usize>,
    sources: BTreeMap<String, usize>,
    wrong: Vec<String>,
}

impl Tally {
    /// `expected_approved: None` is an unlabelled row.
    fn record(
        &mut self,
        id: &str,
        source: &str,
        expected_approved: Option<bool>,
        outcome: Result<VerificationResult, String>,
    ) {
        self.rows += 1;
        *self.sources.entry(source.to_string()).or_default() += 1;
        let result = match outcome {
            Ok(r) => r,
            Err(e) => {
                self.errors += 1;
                let cause = e.split(':').next().unwrap_or("").trim().to_string();
                *self.error_reasons.entry(cause).or_default() += 1;
                if expected_approved == Some(true) {
                    self.errors_on_approve += 1;
                    self.wrong.push(id.to_string());
                }
                return;
            }
        };
        if !result.approved {
            *self.reasons.entry(refusal_reason(&result)).or_default() += 1;
        }
        let Some(expected) = expected_approved else {
            self.unscored += 1;
            return;
        };
        self.scored += 1;
        match (expected, result.approved) {
            (false, false) => self.tp += 1,
            (true, true) => self.tn += 1,
            (true, false) => {
                self.fp += 1;
                self.wrong.push(id.to_string());
            }
            (false, true) => {
                self.fn_ += 1;
                self.wrong.push(id.to_string());
            }
        }
    }

    fn finish(mut self, name: &str, label_meaning: &str) -> SplitReport {
        self.wrong.sort();
        SplitReport {
            name: name.to_string(),
            label_meaning: label_meaning.to_string(),
            rows: self.rows,
            scored: self.scored,
            unscored: self.unscored,
            errors: self.errors,
            error_reasons: self.error_reasons,
            errors_on_approve_labels: self.errors_on_approve,
            true_positives: self.tp,
            true_negatives: self.tn,
            false_positives: self.fp,
            false_negatives: self.fn_,
            recall: Rate::new(self.tp, self.tp + self.fn_),
            precision: Rate::new(self.tp, self.tp + self.fp),
            false_refusal_rate: Rate::new(
                self.fp + self.errors_on_approve,
                self.fp + self.tn + self.errors_on_approve,
            ),
            refusal_reasons: self.reasons,
            sources: self.sources,
            misclassified: self.wrong,
        }
    }
}

fn score_fixtures(name: &str, label_meaning: &str, fixtures: &[RegressionFixture]) -> SplitReport {
    // One fresh core per split, so no split's verdicts depend on another's.
    let core = GraphiteCore::new();
    let mut tally = Tally::default();
    for f in fixtures {
        let source = if f.source.starts_with("real-mainnet-exploit:") {
            "real-mainnet-exploit"
        } else {
            f.source.as_str()
        };
        tally.record(
            &f.content_hash,
            source,
            Some(f.expected_approved),
            core.verify(&f.input).map_err(|e| e.to_string()),
        );
    }
    tally.finish(name, label_meaning)
}

fn score_hand_built() -> SplitReport {
    let core = crate::benchmark::seeded_benchmark_core();
    let mut tally = Tally::default();
    for (label, category, expected, input) in crate::benchmark::cases_for_release_evaluation() {
        let expected = (category != "unknown").then_some(expected);
        tally.record(
            &label,
            category,
            expected,
            core.verify(&input).map_err(|e| e.to_string()),
        );
    }
    tally.finish(
        "hand-built",
        "ground truth written in words beside each case: what the transaction does (safe → approve, malicious → refuse); unknown-protocol cases are counted but unscored",
    )
}

fn mainnet_parse_coverage(path: &Path) -> Result<MainnetSampleReport, ReleaseEvalError> {
    use base64::Engine as _;
    let text = std::fs::read_to_string(path).map_err(|e| ReleaseEvalError::Read {
        path: path.display().to_string(),
        err: e.to_string(),
    })?;
    let doc: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| ReleaseEvalError::Parse {
            path: path.display().to_string(),
            err: e.to_string(),
        })?;
    let rows = doc["rows"]
        .as_array()
        .ok_or_else(|| ReleaseEvalError::Parse {
            path: path.display().to_string(),
            err: "no `rows` array".to_string(),
        })?;
    let mut by_version = BTreeMap::new();
    let mut failures: BTreeMap<String, usize> = BTreeMap::new();
    let mut failed_on_chain = 0;
    let mut parsed = 0;
    for row in rows {
        *by_version
            .entry(row["version"].as_str().unwrap_or("unrecorded").to_string())
            .or_default() += 1;
        if row["err"].as_bool() == Some(true) {
            failed_on_chain += 1;
        }
        let bytes = row["b64"]
            .as_str()
            .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok());
        match bytes.map(|b| crate::tx_artifact::parse_transaction(&b)) {
            Some(Ok(_)) => parsed += 1,
            Some(Err(e)) => {
                let class = format!("{e:?}");
                let class = class.split(['(', ' ', '{']).next().unwrap_or("").to_string();
                *failures.entry(class).or_default() += 1;
            }
            None => *failures.entry("UnreadableBase64".to_string()).or_default() += 1,
        }
    }
    Ok(MainnetSampleReport {
        rows: rows.len(),
        failed_on_chain,
        by_version,
        parsed,
        parse_failures: failures,
        parse_rate: Rate::new(parsed, rows.len()),
        note: "unlabelled: a transaction the chain executed is not thereby benign, so no verdict on these rows is scored here; tests/mainnet_conformance.rs pins every verdict on them".to_string(),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn hash_file(root: &Path, rel: &str) -> Result<InputFile, ReleaseEvalError> {
    let path = root.join(rel);
    let bytes = std::fs::read(&path).map_err(|e| ReleaseEvalError::Read {
        path: path.display().to_string(),
        err: e.to_string(),
    })?;
    Ok(InputFile {
        path: rel.to_string(),
        sha256: sha256_hex(&bytes),
        bytes: bytes.len() as u64,
        files: None,
    })
}

fn hash_dir(root: &Path, rel: &str) -> Result<InputFile, ReleaseEvalError> {
    let dir = root.join(rel);
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .map_err(|e| ReleaseEvalError::Read {
            path: dir.display().to_string(),
            err: e.to_string(),
        })?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    let mut listing = String::new();
    let mut total = 0u64;
    for name in &names {
        let f = hash_file(&dir, name)?;
        total += f.bytes;
        listing.push_str(&format!("{name}\0{}\n", f.sha256));
    }
    Ok(InputFile {
        path: rel.to_string(),
        sha256: sha256_hex(listing.as_bytes()),
        bytes: total,
        files: Some(names.len()),
    })
}

fn registry_facts() -> RegistryFacts {
    let mut listing = String::new();
    for (file, json) in crate::manifest::SEED_MANIFESTS {
        listing.push_str(&format!("{file}\0{}\n", sha256_hex(json.as_bytes())));
    }
    let core = GraphiteCore::new();
    let manifests = core.list_manifests();
    RegistryFacts {
        manifests: manifests.len(),
        instructions: manifests.iter().map(|m| m.instructions.len()).sum(),
        seed_manifests_sha256: sha256_hex(listing.as_bytes()),
    }
}

fn environment() -> Environment {
    let mut features = Vec::new();
    for (name, on) in [
        ("rpc", cfg!(feature = "rpc")),
        ("server", cfg!(feature = "server")),
        ("cli", cfg!(feature = "cli")),
    ] {
        if on {
            features.push(name.to_string());
        }
    }
    let rustc_on_path = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    Environment {
        crate_version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        debug_assertions: cfg!(debug_assertions),
        features,
        rustc_on_path,
    }
}

fn code_identity(root: &Path) -> CodeIdentity {
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    CodeIdentity {
        git_head: git(&["rev-parse", "HEAD"]),
        git_dirty: git(&["status", "--porcelain", "--untracked-files=no"]).map(|s| !s.is_empty()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wilson_interval_matches_the_textbook_values() {
        // n = 10, k = 5: (0.2366, 0.7634) to four places.
        let (lo, hi) = wilson95(5, 10);
        assert!((lo - 0.2366).abs() < 1e-4 && (hi - 0.7634).abs() < 1e-4, "{lo} {hi}");
        // k = n keeps the upper bound at 1 and the lower bound well below it:
        // 37/37 is not "100% recall" with any confidence worth the name.
        let (lo, hi) = wilson95(37, 37);
        assert_eq!(hi, 1.0);
        assert!((lo - 0.9060).abs() < 1e-3, "{lo}");
        let (lo, hi) = wilson95(0, 1);
        assert_eq!(lo, 0.0);
        assert!((hi - 0.7935).abs() < 1e-3, "{hi}");
    }

    #[test]
    fn an_empty_denominator_states_no_rate() {
        let r = Rate::new(0, 0);
        assert_eq!(r.value, None);
        assert_eq!(r.wilson95, None);
    }
}
