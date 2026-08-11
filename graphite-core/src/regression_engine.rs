//! Regression Engine — ARCHITECTURE.md 3.9 / Constitution P10.
//!
//! The Regression Engine is Graphite's P10 gate: no protocol version may be
//! promoted (Semantic Graph / Manifest Registry) without a recorded regression
//! run over that protocol's historical fixtures passing. It replays a corpus
//! of recorded verification outcomes through the full pipeline and reports
//! the pass rate; `decide_promotion` turns the run into the P10 verdict.
//!
//! Honest model (P2, P4, P10):
//! - **Fixtures are append-only.** `add_fixture` never mutates an existing
//!   fixture; the corpus dedupes by `content_hash`, so a re-recorded outcome
//!   is dropped, never rewritten.
//! - **Replay is deterministic.** `replay_corpus` runs each fixture through
//!   `GraphiteCore::verify` and compares only the binary `approved` outcome.
//!   The same corpus + same core state ⇒ the same run (P2).
//! - **Recording is explicit.** `record_fixture` is a named action; `verify()`
//!   itself never records as a side effect — verification must stay pure (P2).
//!   Integrations (SAK bridge, server, SDKs) call `record_fixture` after each
//!   verification that reaches a recorded trust tier.
//! - **Deprecated fixtures are excluded** from the pass-rate denominator.
//! - **P10 gate**: `decide_promotion` returns `Block` unless ≥ 99.5% of
//!   non-deprecated fixtures pass. An empty corpus always blocks — no
//!   recorded evidence, no promotion.
//!
//! A verify error is treated as fail-closed (blocked) — the same convention
//! the benchmark suite uses — so a fixture that errors counts as passed only
//! if it expected a block.

use crate::verification::{GraphiteCore, VerificationInput};
use std::path::Path;
use thiserror::Error;

/// Pass threshold for promotion (P10): 99.5% of non-deprecated fixtures.
pub const PROMOTION_PASS_RATE: f64 = 0.995;

/// Error cases for corpus persistence.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegressionError {
    #[error("corpus directory does not exist: {0}")]
    MissingDirectory(String),
    #[error("corrupt regression fixture file {file}: {err}")]
    CorruptFixture { file: String, err: String },
    #[error("invalid fixture: {0}")]
    InvalidFixture(String),
}

/// A single recorded verification outcome, self-contained and replayable
/// without external state (P2).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RegressionFixture {
    /// Program ID the fixture belongs to (same as `input.program_id`).
    pub program_id: String,
    /// Protocol version label observed when the fixture was recorded.
    pub version: String,
    /// Deterministic identity: sha256 of the canonical serialized input
    /// PLUS the provenance source. Used for append-only deduplication — a
    /// re-recorded outcome with the same hash is dropped, never rewritten
    /// (P4). The provenance is part of the identity so two DISTINCT real
    /// transactions with byte-identical instruction shapes (e.g. two
    /// different signatures draining the same way) are distinct fixtures,
    /// while re-recording the same input under the same provenance is a
    /// duplicate.
    pub content_hash: String,
    /// The outcome recorded when the fixture was captured.
    pub expected_approved: bool,
    /// Provenance: "benchmark" | "recorded" | "manual".
    pub source: String,
    /// Deprecated fixtures are excluded from the pass-rate denominator.
    #[serde(default)]
    pub deprecated: bool,
    /// The full verification input so the fixture replays deterministically.
    pub input: VerificationInput,
}

impl RegressionFixture {
    /// Build a fixture, computing `content_hash` deterministically from the
    /// input plus its provenance (sha256 of the canonical JSON serialization
    /// of input and source).
    pub fn new(input: VerificationInput, expected_approved: bool, source: &str) -> Self {
        let program_id = input.program_id.clone();
        let content_hash = Self::content_hash(&input, source);
        Self {
            program_id,
            version: input.protocol_version.clone(),
            content_hash,
            expected_approved,
            source: source.to_string(),
            deprecated: false,
            input,
        }
    }

    fn content_hash(input: &VerificationInput, source: &str) -> String {
        use sha2::{Digest, Sha256};
        // VerificationInput is a flat struct of Strings/Option/Vec — canonical
        // JSON serialization cannot fail for it (all fields are plain data).
        let canonical =
            serde_json::to_string(input).expect("VerificationInput is always serializable");
        hex::encode(Sha256::digest(format!("{source}\n{canonical}").as_bytes()))
    }
}

/// Append-only corpus of recorded verification outcomes (Constitution P4).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RegressionCorpus {
    fixtures: Vec<RegressionFixture>,
}

impl RegressionCorpus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.fixtures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fixtures.is_empty()
    }

    pub fn all(&self) -> &[RegressionFixture] {
        &self.fixtures
    }

    /// Append a fixture. Never mutates existing fixtures (P4): an identical
    /// content_hash (same input, re-recorded) is dropped as a duplicate, and
    /// a fixture with a poison (empty/whitespace) program_id is dropped —
    /// both are deliberate silent no-ops (dedupe is the normal corpus
    /// operation; a poison key can never be replayed, so recording it would
    /// just bloat the corpus).
    pub fn add_fixture(&mut self, fixture: RegressionFixture) {
        // A fixture for a malformed program ID would poison the corpus
        // (same poison-key class as empty/whitespace baselines).
        if fixture.program_id.trim().is_empty() || fixture.input.program_id.trim().is_empty() {
            return;
        }
        if self
            .fixtures
            .iter()
            .any(|f| f.content_hash == fixture.content_hash)
        {
            return;
        }
        self.fixtures.push(fixture);
    }

    /// All fixtures for a program (append-only history for that program).
    pub fn fixtures_for(&self, program_id: &str) -> Vec<&RegressionFixture> {
        self.fixtures
            .iter()
            .filter(|f| f.program_id == program_id)
            .collect()
    }

    /// Persist the corpus as one JSON file per program under `dir`
    /// (e.g. `regression_corpus/{program_id}.json`).
    ///
    /// Snapshot semantics: each per-program file is a full serialization of
    /// the in-memory corpus for that program. The in-memory model is
    /// append-only (P4); the file is a snapshot of that model. Save after
    /// load preserves the loaded set exactly; save is never used to "merge"
    /// two partial corpora.
    pub fn save_to_dir(&self, dir: &Path) -> Result<(), RegressionError> {
        std::fs::create_dir_all(dir).map_err(|e| {
            RegressionError::InvalidFixture(format!("cannot create corpus dir: {e}"))
        })?;
        let mut by_program: std::collections::BTreeMap<&str, Vec<&RegressionFixture>> =
            std::collections::BTreeMap::new();
        for f in &self.fixtures {
            by_program.entry(f.program_id.as_str()).or_default().push(f);
        }
        for (program_id, fixtures) in by_program {
            // Guard: program IDs are base58; anything with path separators or
            // a leading dot must never become a filename.
            if program_id.starts_with('.') || program_id.contains(['/', '\\']) {
                return Err(RegressionError::InvalidFixture(format!(
                    "program_id cannot be used as a filename: {program_id}"
                )));
            }
            let file = dir.join(format!("{program_id}.json"));
            let json = serde_json::to_string_pretty(&fixtures).map_err(|e| {
                RegressionError::InvalidFixture(format!("serialize {program_id}: {e}"))
            })?;
            std::fs::write(&file, json)
                .map_err(|e| RegressionError::InvalidFixture(format!("write {file:?}: {e}")))?;
        }
        Ok(())
    }

    /// Load a corpus from `dir` (one JSON file per program). Fail-closed: a
    /// corrupt file is an error, never silently skipped — a regression corpus
    /// that cannot be trusted must not be replayed.
    pub fn load_from_dir(dir: &Path) -> Result<Self, RegressionError> {
        if !dir.is_dir() {
            return Err(RegressionError::MissingDirectory(dir.display().to_string()));
        }
        let mut corpus = RegressionCorpus::new();
        for entry in std::fs::read_dir(dir)
            .map_err(|e| RegressionError::MissingDirectory(format!("{dir:?}: {e}")))?
        {
            let path = entry
                .map_err(|e| RegressionError::CorruptFixture {
                    file: "<dir>".to_string(),
                    err: e.to_string(),
                })?
                .path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let content =
                std::fs::read_to_string(&path).map_err(|e| RegressionError::CorruptFixture {
                    file: path.display().to_string(),
                    err: e.to_string(),
                })?;
            let fixtures: Vec<RegressionFixture> =
                serde_json::from_str(&content).map_err(|e| RegressionError::CorruptFixture {
                    file: path.display().to_string(),
                    err: e.to_string(),
                })?;
            for f in fixtures {
                corpus.add_fixture(f);
            }
        }
        Ok(corpus)
    }
}

/// A single fixture whose replay outcome diverged from what was recorded.
#[derive(Debug, Clone, PartialEq)]
pub struct FixtureFailure {
    pub program_id: String,
    pub content_hash: String,
    pub expected: bool,
    pub got: bool,
}

/// Result of replaying a corpus through the verification pipeline.
#[derive(Debug, Clone, PartialEq)]
pub struct RegressionRun {
    /// Non-deprecated fixtures considered.
    pub total: usize,
    pub passed: usize,
    /// passed / total (0.0 when total == 0).
    pub pass_rate: f64,
    pub failures: Vec<FixtureFailure>,
}

/// Replay a corpus through `GraphiteCore::verify` (deterministic, P2).
///
/// A verification error is fail-closed (treated as blocked), matching the
/// benchmark suite's convention — so an erroring fixture counts as passed
/// only when it expected a block.
///
/// Determinism note (load-bearing invariant): `verify` takes `&self` and
/// never mutates the semantic graph or baselines, so all fixtures in a run
/// observe the same core state regardless of order. Do not pass a core whose
/// state can change between calls (e.g. one that records fixtures as a side
/// effect of verify).
pub fn replay_corpus(core: &GraphiteCore, corpus: &RegressionCorpus) -> RegressionRun {
    replay_corpus_filtered(core, corpus, None)
}

/// Replay only the fixtures recorded for one program.
///
/// The Manifest Registry's P10 gate uses this: promotion is a per-program
/// decision, and the run is produced by the ENGINE's own replay over the real
/// corpus — never by a caller-supplied run that could be fabricated.
pub fn replay_corpus_for_program(
    core: &GraphiteCore,
    corpus: &RegressionCorpus,
    program_id: &str,
) -> RegressionRun {
    replay_corpus_filtered(core, corpus, Some(program_id))
}

fn replay_corpus_filtered(
    core: &GraphiteCore,
    corpus: &RegressionCorpus,
    program_id: Option<&str>,
) -> RegressionRun {
    let mut total = 0;
    let mut passed = 0;
    let mut failures = Vec::new();
    for fixture in corpus.all() {
        if fixture.deprecated {
            continue;
        }
        if let Some(pid) = program_id {
            if fixture.program_id != pid {
                continue;
            }
        }
        total += 1;
        let got = match core.verify(&fixture.input) {
            Ok(result) => result.approved,
            // Verification error = fail-closed block.
            Err(_) => false,
        };
        if got == fixture.expected_approved {
            passed += 1;
        } else {
            failures.push(FixtureFailure {
                program_id: fixture.program_id.clone(),
                content_hash: fixture.content_hash.clone(),
                expected: fixture.expected_approved,
                got,
            });
        }
    }
    let pass_rate = if total == 0 {
        0.0
    } else {
        passed as f64 / total as f64
    };
    RegressionRun {
        total,
        passed,
        pass_rate,
        failures,
    }
}

/// P10 promotion decision derived from a regression run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionDecision {
    Promote,
    Block { reason: String },
}

/// P10 gate: promote only when ≥ 99.5% of non-deprecated fixtures pass.
/// An empty corpus always blocks — no recorded evidence, no promotion.
pub fn decide_promotion(run: &RegressionRun) -> PromotionDecision {
    if run.total == 0 {
        return PromotionDecision::Block {
            reason: "regression gate requires at least one non-deprecated fixture (P10)"
                .to_string(),
        };
    }
    if run.pass_rate >= PROMOTION_PASS_RATE {
        PromotionDecision::Promote
    } else {
        PromotionDecision::Block {
            reason: format!(
                "pass rate {:.4} below required {:.3} ({} failed / {} non-deprecated fixtures)",
                run.pass_rate,
                PROMOTION_PASS_RATE,
                run.failures.len(),
                run.total
            ),
        }
    }
}

/// Record a verification outcome into a corpus (explicit, P2-safe — never a
/// side effect of `verify()` itself). Integrations call this after each
/// verification they wish to pin.
pub fn record_fixture(
    corpus: &mut RegressionCorpus,
    input: &VerificationInput,
    approved: bool,
    source: &str,
) {
    corpus.add_fixture(RegressionFixture::new(input.clone(), approved, source));
}

/// Seed the initial corpus from the P16 benchmark cases (the reproducible
/// evidence base). The two simulation-baseline-dependent cases are excluded:
/// they require operator-seeded RPC baselines and are recorded at runtime,
/// never seedable — including them would make replay depend on external state.
pub fn seed_corpus_from_benchmark() -> RegressionCorpus {
    let mut corpus = RegressionCorpus::new();
    for (expected_approved, input) in crate::benchmark::benchmark_fixture_seed() {
        corpus.add_fixture(RegressionFixture::new(
            input,
            expected_approved,
            "benchmark",
        ));
    }
    corpus
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_engine::WalletProfile;
    use crate::semantic_graph_store::BehaviorEvidence;
    use crate::verification::ProposedIntent;

    const SYSTEM: &str = "11111111111111111111111111111111";
    const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

    fn make_input(program: &str, disc: &str, accounts: &[&str]) -> VerificationInput {
        VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "transfer".to_string(),
                raw_natural_language: "test".to_string(),
                confidence_of_parse: 0.9,
                extracted_parameters: None,
            },
            program_id: program.to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: disc.to_string(),
            account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
            instruction_data: None,
            cpi_targets: vec![],
            wallet_profile: WalletProfile::Custom {
                min_confidence: 0.40,
                min_trust_tier: crate::semantic_graph_store::TrustTier::OfficialManifest,
            },
            behavior_evidence: BehaviorEvidence::default(),
            compute_units: 150,
            account_writes: 2,
            cpi_hops: 0,
            signed_transaction: None,
            transaction_instructions: vec![],
            cpi_trace: None,
        }
    }

    fn safe_system_transfer() -> VerificationInput {
        make_input(
            SYSTEM,
            "02000000",
            &[
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
            ],
        )
    }

    fn malicious_set_authority() -> VerificationInput {
        make_input(
            TOKEN,
            "06",
            &[
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
            ],
        )
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("graphite-regression-{tag}-{}", std::process::id()))
    }

    #[test]
    fn add_fixture_is_append_only_and_dedupes_by_content_hash() {
        let mut corpus = RegressionCorpus::new();
        let input = safe_system_transfer();
        corpus.add_fixture(RegressionFixture::new(input.clone(), true, "manual"));
        // Identical input re-recorded → dropped, never rewritten (P4).
        corpus.add_fixture(RegressionFixture::new(input, false, "manual"));
        assert_eq!(corpus.len(), 1, "duplicate content_hash must be dropped");
        let recorded = &corpus.all()[0];
        assert!(
            recorded.expected_approved,
            "first recorded outcome must win"
        );
        assert_eq!(corpus.fixtures_for(SYSTEM).len(), 1);
    }

    #[test]
    fn fixture_content_hash_is_deterministic() {
        let a = RegressionFixture::new(safe_system_transfer(), true, "manual");
        let b = RegressionFixture::new(safe_system_transfer(), true, "manual");
        assert_eq!(
            a.content_hash, b.content_hash,
            "same input ⇒ same hash (P2)"
        );
        let c = RegressionFixture::new(malicious_set_authority(), false, "manual");
        assert_ne!(a.content_hash, c.content_hash);
        assert_eq!(a.content_hash.len(), 64, "sha256 hex");
    }

    #[test]
    fn add_fixture_rejects_poison_program_ids() {
        let mut corpus = RegressionCorpus::new();
        corpus.add_fixture(RegressionFixture::new(
            make_input("", "01", &[]),
            false,
            "manual",
        ));
        assert!(
            corpus.is_empty(),
            "empty program_id fixture must be dropped"
        );
    }

    #[test]
    fn save_and_load_roundtrip_one_file_per_program() {
        let dir = temp_dir("roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        let mut corpus = RegressionCorpus::new();
        corpus.add_fixture(RegressionFixture::new(
            safe_system_transfer(),
            true,
            "benchmark",
        ));
        corpus.add_fixture(RegressionFixture::new(
            malicious_set_authority(),
            false,
            "benchmark",
        ));
        corpus.save_to_dir(&dir).unwrap();
        assert!(dir.join(format!("{SYSTEM}.json")).exists());
        assert!(dir.join(format!("{TOKEN}.json")).exists());

        let loaded = RegressionCorpus::load_from_dir(&dir).unwrap();
        assert_eq!(loaded.len(), 2);
        let sys = loaded.fixtures_for(SYSTEM);
        assert_eq!(sys.len(), 1);
        assert!(sys[0].expected_approved);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_corrupt_file_fails_closed() {
        let dir = temp_dir("corrupt");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("bad.json"), "{ not json").unwrap();
        assert!(matches!(
            RegressionCorpus::load_from_dir(&dir),
            Err(RegressionError::CorruptFixture { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_missing_directory_errors() {
        assert!(matches!(
            RegressionCorpus::load_from_dir(&temp_dir("does-not-exist")),
            Err(RegressionError::MissingDirectory(_))
        ));
    }

    #[test]
    fn benchmark_seeded_corpus_replays_clean_and_promotes() {
        let core = GraphiteCore::new();
        let corpus = seed_corpus_from_benchmark();
        // 18 benchmark cases − 2 simulation-baseline-dependent (excluded) = 16.
        // No content_hash dedupe collapse: the REAL AAT case (pinned mainnet
        // transaction_instructions + CPI trace) is structurally distinct from
        // the SYNTHETIC AAT case.
        assert_eq!(
            corpus.len(),
            16,
            "benchmark seed must pin exactly 16 non-duplicate fixtures"
        );
        let run = replay_corpus(&core, &corpus);
        assert!(
            run.total > 0 && run.total == corpus.len(),
            "all seeded fixtures must be non-deprecated"
        );
        assert_eq!(
            run.pass_rate, 1.0,
            "benchmark-derived fixtures must replay cleanly on a fresh core, failures: {:?}",
            run.failures
        );
        assert_eq!(decide_promotion(&run), PromotionDecision::Promote);
    }

    #[test]
    fn regression_detected_blocks_promotion() {
        let core = GraphiteCore::new();
        let mut corpus = RegressionCorpus::new();
        // A regression: this SetAuthority input is recorded as "approved" —
        // replay will block it, so the fixture fails and the gate blocks.
        corpus.add_fixture(RegressionFixture::new(
            malicious_set_authority(),
            true,
            "manual",
        ));
        corpus.add_fixture(RegressionFixture::new(
            safe_system_transfer(),
            true,
            "manual",
        ));
        let run = replay_corpus(&core, &corpus);
        assert_eq!(run.total, 2);
        assert_eq!(run.passed, 1);
        assert_eq!(run.failures.len(), 1);
        assert!(run.pass_rate < PROMOTION_PASS_RATE);
        assert!(matches!(
            decide_promotion(&run),
            PromotionDecision::Block { reason } if reason.contains("pass rate")
        ));
    }

    #[test]
    fn empty_corpus_blocks_promotion_p10() {
        let core = GraphiteCore::new();
        let run = replay_corpus(&core, &RegressionCorpus::new());
        assert_eq!(run.total, 0);
        assert_eq!(run.pass_rate, 0.0);
        assert!(matches!(
            decide_promotion(&run),
            PromotionDecision::Block { reason } if reason.contains("at least one")
        ));
    }

    #[test]
    fn deprecated_fixtures_excluded_from_denominator() {
        let core = GraphiteCore::new();
        let mut corpus = RegressionCorpus::new();
        let mut old = RegressionFixture::new(
            make_input(SYSTEM, "02000000", &["bad-account"]),
            false,
            "manual",
        );
        // Mark deprecated BEFORE adding (the corpus records history; a
        // deprecated fixture is a historical record that no longer counts).
        old.deprecated = true;
        corpus.add_fixture(old);
        corpus.add_fixture(RegressionFixture::new(
            safe_system_transfer(),
            true,
            "manual",
        ));
        let run = replay_corpus(&core, &corpus);
        assert_eq!(run.total, 1, "deprecated fixture must not count");
        assert_eq!(run.pass_rate, 1.0);
        assert_eq!(decide_promotion(&run), PromotionDecision::Promote);
    }

    #[test]
    fn replay_is_deterministic() {
        let core = GraphiteCore::new();
        let corpus = seed_corpus_from_benchmark();
        let first = replay_corpus(&core, &corpus);
        let second = replay_corpus(&core, &corpus);
        assert_eq!(first, second, "same corpus + same core ⇒ same run (P2)");
    }

    #[test]
    fn record_fixture_roundtrips_and_dedupes() {
        let mut corpus = RegressionCorpus::new();
        let input = safe_system_transfer();
        record_fixture(&mut corpus, &input, true, "recorded");
        assert_eq!(corpus.len(), 1);
        assert_eq!(corpus.all()[0].source, "recorded");
        assert!(corpus.all()[0].expected_approved);
        // Re-recording the same input dedupes by content_hash (append-only).
        record_fixture(&mut corpus, &input, false, "recorded");
        assert_eq!(corpus.len(), 1);
        assert!(
            corpus.all()[0].expected_approved,
            "first recorded outcome wins"
        );
    }

    #[test]
    fn verify_error_counts_as_fail_closed() {
        let core = GraphiteCore::new();
        let mut corpus = RegressionCorpus::new();
        // An input that errors (invalid account pubkey) is fail-closed →
        // blocked. Recorded as blocked ⇒ passes; recorded as approved ⇒ fails.
        let erroring = make_input(SYSTEM, "02000000", &["not-a-valid-base58-pubkey-address"]);
        corpus.add_fixture(RegressionFixture::new(erroring.clone(), false, "manual"));
        let run = replay_corpus(&core, &corpus);
        assert_eq!(run.passed, 1, "fail-closed error must match expected block");

        let mut corpus2 = RegressionCorpus::new();
        corpus2.add_fixture(RegressionFixture::new(erroring, true, "manual"));
        let run2 = replay_corpus(&core, &corpus2);
        assert_eq!(
            run2.passed, 0,
            "fail-closed error must NOT match expected approval"
        );
        assert!(
            !run2.failures[0].got,
            "fail-closed error must record got=false"
        );
    }
}
