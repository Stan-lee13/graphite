//! CLI module for Graphite Core.

use crate::confidence_engine::TrustTier;
use crate::policy_engine::WalletProfile;
use crate::verification::{GraphiteCore, VerificationInput};
use std::path::{Path, PathBuf};

/// CLI-supplied policy profile override for `verify`.
///
/// A named preset (`treasury|trading|gaming|enterprise`) replaces the
/// wallet profile wholesale; `custom` requires explicit thresholds. When
/// `--profile` is absent the input's own `wallet_profile` is used as-is.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProfileArg {
    pub name: Option<String>,
    pub min_confidence: Option<f64>,
    pub min_trust_tier: Option<String>,
}

impl ProfileArg {
    /// True when the caller supplied any override flag.
    pub fn is_empty(&self) -> bool {
        self.name.is_none() && self.min_confidence.is_none() && self.min_trust_tier.is_none()
    }
}

/// Resolve a CLI profile argument into a concrete `WalletProfile`.
///
/// Returns `Ok(None)` when no override was requested (the input's own
/// profile applies). Fail-closed: unknown profile names and invalid
/// thresholds are errors, never silently ignored.
pub fn resolve_profile(arg: &ProfileArg) -> Result<Option<WalletProfile>, String> {
    if arg.is_empty() {
        return Ok(None);
    }
    let name = match &arg.name {
        Some(n) => n.trim().to_ascii_lowercase(),
        None => {
            // Threshold-only override: partial customization is rejected —
            // a `custom` profile is meaningless without both bounds.
            return Err("--min-confidence/--min-trust-tier require --profile custom".to_string());
        }
    };
    match name.as_str() {
        "treasury" => Ok(Some(WalletProfile::Treasury)),
        "trading" | "tradingbot" => Ok(Some(WalletProfile::TradingBot)),
        "gaming" => Ok(Some(WalletProfile::Gaming)),
        "enterprise" => Ok(Some(WalletProfile::Enterprise)),
        "custom" => {
            let min_confidence = arg
                .min_confidence
                .ok_or_else(|| "--profile custom requires --min-confidence <0..1>".to_string())?;
            if min_confidence.is_nan()
                || min_confidence.is_infinite()
                || !(0.0..=1.0).contains(&min_confidence)
            {
                return Err("--min-confidence must be a finite value in [0.0, 1.0]".to_string());
            }
            let tier_str = arg
                .min_trust_tier
                .as_deref()
                .ok_or_else(|| "--profile custom requires --min-trust-tier <tier>".to_string())?;
            // FAIL-CLOSED tier parsing: this is an OPERATOR-SUPPLIED policy
            // threshold, so an unrecognized string must ERROR — silently
            // resolving to HeuristicInferred would LOWER the required bar and
            // make the profile strictly more permissive than requested.
            // (`TrustTier::from_manifest_str`'s leniency is correct for
            // protocol self-descriptions — P6 — but wrong here.)
            let min_trust_tier = match tier_str.trim() {
                "Unknown" => TrustTier::Unknown,
                "HeuristicInferred" => TrustTier::HeuristicInferred,
                "OfficialManifest" => TrustTier::OfficialManifest,
                "SimulationValidated" => TrustTier::SimulationValidated,
                "CommunityVerified" => TrustTier::CommunityVerified,
                "BattleTested" => TrustTier::BattleTested,
                other => {
                    return Err(format!(
                        "unknown trust tier '{other}' (expected Unknown|HeuristicInferred|OfficialManifest|SimulationValidated|CommunityVerified|BattleTested)"
                    ))
                }
            };
            Ok(Some(WalletProfile::Custom {
                min_confidence,
                min_trust_tier,
            }))
        }
        other => Err(format!(
            "unknown profile '{other}' (expected treasury|trading|gaming|enterprise|custom)"
        )),
    }
}

pub enum CliCommand {
    Verify {
        input: Box<VerificationInput>,
        profile: ProfileArg,
    },
    #[cfg(feature = "server")]
    Server {
        port: u16,
    },
    Manifests,
    /// List wallet policy profiles and their thresholds.
    Profiles,
    Benchmark,
    /// Replay a regression corpus and enforce the P10 promotion gate.
    /// Exits 0 on PROMOTE, 1 on BLOCK (usable as a CI gate).
    Regression {
        corpus_dir: PathBuf,
    },
    /// List registered plugins and apply the manifest review gate (P8).
    /// Only `approved` manifests activate; pending/rejected are skipped.
    Plugins {
        /// Directory of plugin manifests (JSON files) to discover + register.
        dir: Option<PathBuf>,
    },
    /// Manifest Registry operator actions (Phase 2 operator API; the public
    /// PR workflow + on-chain stake lookup are Phase 3).
    Registry {
        action: RegistryAction,
    },
    /// Collect REAL on-chain transactions into the regression corpus
    /// (Phase 2 exit: "benchmark uses real on-chain data, not synthetic").
    #[cfg(feature = "rpc")]
    RegressionSeedLive {
        rpc_url: String,
        corpus_dir: PathBuf,
        count: usize,
        network: String,
    },
}

/// Registry operator action (dispatched by `CliCommand::Registry`).
///
/// All actions persist engine state as JSON (default `registry_state.json`,
/// override with `--state` or `GRAPHITE_REGISTRY_STATE`) and the Semantic
/// Graph state for submissions (default `graph_state.json`, override with
/// `--graph-state` or `GRAPHITE_GRAPH_STATE`) — the server and CLI share this
/// contract so operator registrations survive restarts.
pub enum RegistryAction {
    /// List registered reviewers (G5 identities) and the acceptance log.
    Reviewers { state: Option<PathBuf> },
    /// Register a reviewer identity with a demonstrated reputation score
    /// (operator-verified stake/GitHub claim in Phase 2).
    RegisterReviewer {
        state: Option<PathBuf>,
        pubkey: String,
        reputation: u64,
    },
    /// Submit a community manifest. A `--signer-key` (ed25519 secret) signs
    /// the submission; `attestations` are independent reviewer signatures
    /// (`<pubkey>:<signature_hex>`). A `--corpus-dir` supplies the regression
    /// corpus the engine itself replays for the P10 promotion gate.
    Submit {
        state: Option<PathBuf>,
        graph_state: Option<PathBuf>,
        manifest_path: PathBuf,
        signer_key_hex: Option<String>,
        attestations: Vec<String>,
        corpus_dir: Option<PathBuf>,
    },
}

pub fn run(command: CliCommand) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        CliCommand::Verify { input, profile } => {
            let mut core = GraphiteCore::new();
            // C53: merge community-accepted manifests from the registry state
            // (same contract as the server: `registry_state.json` or
            // GRAPHITE_REGISTRY_STATE) so `graphite verify` sees the same
            // registry as the running server. A missing or corrupt file is
            // non-fatal — verification still runs against the seed registry.
            let registry_path = registry_state_path(None);
            match load_registry(&registry_path) {
                Ok(engine) => {
                    let merged = core.merge_community_manifests(&engine);
                    if merged > 0 {
                        eprintln!(
                            "merged {merged} community-accepted manifest(s) from {}",
                            registry_path.display()
                        );
                    }
                }
                Err(e) => eprintln!(
                    "warning: registry state unreadable ({}): {}",
                    registry_path.display(),
                    e
                ),
            }
            let mut input = *input;
            // Apply the --profile override (fail-closed on unknown names).
            if let Some(profile) = resolve_profile(&profile)? {
                input.wallet_profile = profile;
            }
            let result = core.verify(&input)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            // SECURITY FIX: Exit 1 on REJECT so CLI can be used as CI gate
            if !result.approved {
                std::process::exit(1);
            }
            Ok(())
        }
        CliCommand::Profiles => {
            println!("Wallet policy profiles — passed as `wallet_profile` in VerificationInput, or overridden on the CLI with `--profile`:");
            println!();
            println!(
                "  {:<12} {:<10} {:<26} {:<34}",
                "Profile", "Min Conf", "Min Trust Tier", "Intended use"
            );
            println!("  {}", "─".repeat(88));
            println!(
                "  {:<12} {:<10.2} {:<26} {:<34}",
                "Treasury",
                0.95,
                "CommunityVerified (T4)",
                "conservative custody; human approval gate above $ threshold"
            );
            println!(
                "  {:<12} {:<10.2} {:<26} {:<34}",
                "TradingBot",
                0.80,
                "SimulationValidated (T3)",
                "automated swaps; confidence threshold, no human gate"
            );
            println!(
                "  {:<12} {:<10.2} {:<26} {:<34}",
                "Gaming",
                0.55,
                "HeuristicInferred (T1)",
                "fast-mode game transactions; lowest requirements"
            );
            println!(
                "  {:<12} {:<10.2} {:<26} {:<34}",
                "Enterprise", 0.99, "BattleTested (T5)", "highest bar; full audit export expected"
            );
            println!();
            println!("  Custom: --profile custom --min-confidence <0..1> --min-trust-tier <tier>");
            println!();
            println!("  Confidence is earned, not asserted: the three evidence signals (SimulationMatch,");
            println!("  HistoricalVolume, CommunityVerification) read from the Semantic Graph's internal");
            println!("  accumulator (G4) — a fresh core scores a known protocol at ~0.44, so the built-in");
            println!(
                "  presets require earned evidence (RPC-verified simulations, verified volume,"
            );
            println!("  community verifications) to be satisfiable.");
            Ok(())
        }
        CliCommand::Manifests => {
            let core = GraphiteCore::new();
            for m in core.list_manifests() {
                println!(
                    "  {} ({}) — {} instructions",
                    m.protocol.name,
                    m.protocol.program_id,
                    m.instructions.len()
                );
            }
            Ok(())
        }
        CliCommand::Benchmark => {
            crate::benchmark::run_benchmark();
            Ok(())
        }
        CliCommand::Regression { corpus_dir } => {
            use crate::regression_engine::{decide_promotion, replay_corpus, RegressionCorpus};
            let corpus = RegressionCorpus::load_from_dir(&corpus_dir)?;
            let core = GraphiteCore::new();
            let run = replay_corpus(&core, &corpus);
            println!(
                "regression: {}/{} passed ({:.2}%)",
                run.passed,
                run.total,
                run.pass_rate * 100.0
            );
            match decide_promotion(&run) {
                crate::regression_engine::PromotionDecision::Promote => {
                    println!("P10 gate: PROMOTE");
                    Ok(())
                }
                crate::regression_engine::PromotionDecision::Block { reason } => {
                    println!("P10 gate: BLOCK — {}", reason);
                    std::process::exit(1);
                }
            }
        }
        CliCommand::Plugins { dir } => {
            let mut core = GraphiteCore::new();
            println!("Registered plugins (built-in core):");
            for p in core.plugins().registered_plugins() {
                println!("  ✓ {}", p);
            }
            println!(
                "  analytics observers: {}",
                core.plugins().analytics_count()
            );
            if let Some(dir) = dir {
                let summary = core.attach_plugins_dir(&dir)?;
                println!(
                    "\nReview gate ({}) — only approved manifests activate:",
                    dir.display()
                );
                println!(
                    "  registered: {} | skipped pending: {} | skipped rejected: {}",
                    summary.registered, summary.skipped_pending, summary.skipped_rejected
                );
                for p in core.plugins().registered_plugins() {
                    println!("  ✓ {}", p);
                }
            }
            Ok(())
        }
        CliCommand::Registry { action } => run_registry(action),
        #[cfg(feature = "rpc")]
        CliCommand::RegressionSeedLive {
            rpc_url,
            corpus_dir,
            count,
            network,
        } => run_regression_seed_live(rpc_url, corpus_dir, count, network),
        #[cfg(feature = "server")]
        CliCommand::Server { port } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(crate::server::run_server(([0, 0, 0, 0], port).into()))?;
            Ok(())
        }
    }
}

/// Resolve the registry state file path (explicit flag, env, or default).
fn registry_state_path(explicit: Option<PathBuf>) -> PathBuf {
    explicit
        .or_else(|| {
            std::env::var("GRAPHITE_REGISTRY_STATE")
                .ok()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from("registry_state.json"))
}

/// Resolve the Semantic Graph state file path for registry submissions.
fn graph_state_path(explicit: Option<PathBuf>) -> PathBuf {
    explicit
        .or_else(|| {
            std::env::var("GRAPHITE_GRAPH_STATE")
                .ok()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from("graph_state.json"))
}

/// Load registry engine state; a missing file starts a fresh engine
/// (first-run semantics), but a CORRUPT file is an error (never silently
/// reset — losing reviewer reputations would be a security regression).
fn load_registry(
    path: &Path,
) -> Result<crate::manifest_registry::ManifestRegistryEngine, Box<dyn std::error::Error>> {
    match std::fs::read_to_string(path) {
        Ok(json) => Ok(crate::manifest_registry::ManifestRegistryEngine::from_json(
            &json,
        )?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(crate::manifest_registry::ManifestRegistryEngine::new())
        }
        Err(e) => Err(Box::new(e)),
    }
}

fn save_registry(
    engine: &crate::manifest_registry::ManifestRegistryEngine,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(path, engine.to_json()?)?;
    Ok(())
}

fn load_graph(
    path: &Path,
) -> Result<crate::semantic_graph_store::SemanticGraphStore, Box<dyn std::error::Error>> {
    match std::fs::read_to_string(path) {
        Ok(json) => Ok(crate::semantic_graph_store::SemanticGraphStore::from_json(
            &json,
        )?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(crate::semantic_graph_store::SemanticGraphStore::new())
        }
        Err(e) => Err(Box::new(e)),
    }
}

fn save_graph(
    store: &crate::semantic_graph_store::SemanticGraphStore,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(path, store.to_json()?)?;
    Ok(())
}

/// Load the corpus for a live seed. A missing directory starts a fresh corpus
/// (first run); ANY other load failure (e.g. a corrupt fixture file) is an
/// error. Silently resetting a corrupt corpus and then saving would DROP the
/// fixtures of every program whose file was on disk (save_to_dir snapshots
/// the in-memory model per program) — data loss on partial corruption.
#[cfg(any(feature = "rpc", test))]
fn load_corpus_for_seed(
    dir: &Path,
) -> Result<crate::regression_engine::RegressionCorpus, crate::regression_engine::RegressionError> {
    use crate::regression_engine::{RegressionCorpus, RegressionError};
    match RegressionCorpus::load_from_dir(dir) {
        Ok(c) => Ok(c),
        Err(RegressionError::MissingDirectory(_)) => Ok(RegressionCorpus::new()),
        Err(e) => Err(e),
    }
}

fn run_registry(action: RegistryAction) -> Result<(), Box<dyn std::error::Error>> {
    use crate::manifest_registry::{
        ManifestSubmission, RegistryDecision, ReviewerAttestation, MIN_REVIEWER_REPUTATION,
    };
    match action {
        RegistryAction::Reviewers { state } => {
            let path = registry_state_path(state);
            let engine = load_registry(&path)?;
            let reviewers = engine.reviewers();
            println!(
                "Manifest Registry ({}): reviewers with reputation >= {} count toward CommunityVerified (G5)",
                path.display(),
                MIN_REVIEWER_REPUTATION
            );
            if reviewers.is_empty() {
                println!("  (no reviewers registered)");
            }
            for r in reviewers.values() {
                println!("  {} — reputation {}", r.pubkey, r.reputation_score);
            }
            let records = engine.records();
            println!(
                "\nAcceptance log ({} records, append-only P4):",
                records.len()
            );
            for rec in records {
                println!(
                    "  {} v{} — {:?} — source {}",
                    rec.program_id, rec.version_label, rec.trust_tier, rec.source
                );
            }
            Ok(())
        }
        RegistryAction::RegisterReviewer {
            state,
            pubkey,
            reputation,
        } => {
            let path = registry_state_path(state);
            let mut engine = load_registry(&path)?;
            engine.register_reviewer(&pubkey, reputation)?;
            save_registry(&engine, &path)?;
            println!(
                "registered reviewer {pubkey} with reputation {reputation} (state: {})",
                path.display()
            );
            Ok(())
        }
        RegistryAction::Submit {
            state,
            graph_state,
            manifest_path,
            signer_key_hex,
            attestations,
            corpus_dir,
        } => {
            let state_path = registry_state_path(state);
            let graph_path = graph_state_path(graph_state);
            let content = std::fs::read_to_string(&manifest_path)?;
            let manifest: crate::manifest::ProtocolManifest = serde_json::from_str(&content)?;
            let mut submission = ManifestSubmission {
                manifest,
                signer_pubkey: None,
                signature_hex: None,
                attestations: Vec::new(),
            };
            if let Some(key_hex) = signer_key_hex {
                let bytes = hex::decode(&key_hex).map_err(|e| {
                    format!("--signer-key must be 64 hex chars (32-byte ed25519 seed): {e}")
                })?;
                let seed: [u8; 32] = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                    "--signer-key must be exactly 32 bytes (64 hex chars)".to_string()
                })?;
                let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
                use ed25519_dalek::Signer;
                let hash = submission.content_hash();
                let sig = hex::encode(signing.sign(hash.as_bytes()).to_bytes());
                submission.signer_pubkey =
                    Some(bs58::encode(signing.verifying_key().to_bytes()).into_string());
                submission.signature_hex = Some(sig);
            }
            for a in &attestations {
                let (reviewer_pubkey, signature_hex) = a.split_once(':').ok_or_else(|| {
                    format!("--attestation must be <pubkey>:<signature_hex>, got: {a}")
                })?;
                submission.attestations.push(ReviewerAttestation {
                    reviewer_pubkey: reviewer_pubkey.to_string(),
                    signature_hex: signature_hex.to_string(),
                });
            }
            let mut engine = load_registry(&state_path)?;
            let mut store = load_graph(&graph_path)?;
            let regression = match corpus_dir {
                Some(dir) => Some((
                    crate::regression_engine::RegressionCorpus::load_from_dir(&dir)?,
                    GraphiteCore::new(),
                )),
                None => None,
            };
            let decision = engine.submit(
                &mut store,
                submission,
                regression.as_ref().map(|(c, core)| (c, core)),
            )?;
            match decision {
                RegistryDecision::Accepted {
                    trust_tier,
                    version_label,
                } => {
                    println!("ACCEPTED — {version_label} at trust tier {trust_tier:?}");
                    save_registry(&engine, &state_path)?;
                    save_graph(&store, &graph_path)?;
                    println!("engine state: {}", state_path.display());
                    println!("graph state:  {}", graph_path.display());
                    Ok(())
                }
                RegistryDecision::Rejected { reason } => {
                    println!("REJECTED — {reason}");
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Collect REAL on-chain transactions into the regression corpus.
///
/// Fetches recent non-empty blocks, runs the full pipeline over each real
/// transaction (preferring known-manifest programs over System/ComputeBudget
/// setup instructions), and appends fixtures (deduped by content hash, P4).
#[cfg(feature = "rpc")]
fn run_regression_seed_live(
    rpc_url: String,
    corpus_dir: PathBuf,
    count: usize,
    network: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::live_corpus::seed_corpus_from_live;
    use crate::rpc_client::{RpcConfig, SolanaRpcClient};

    let client = SolanaRpcClient::new(RpcConfig {
        endpoint: rpc_url.clone(),
        ..Default::default()
    });
    let core = GraphiteCore::new();
    let mut corpus = match load_corpus_for_seed(&corpus_dir) {
        Ok(c) => c,
        Err(e) => {
            return Err(Box::new(e));
        }
    };
    if corpus.is_empty() {
        eprintln!(
            "no existing corpus at {} — starting fresh",
            corpus_dir.display()
        );
    }
    let prefer: Vec<String> = core
        .list_manifests()
        .iter()
        .map(|m| m.protocol.program_id.clone())
        .collect();
    let prefer: Vec<&str> = prefer.iter().map(|s| s.as_str()).collect();
    let rt = tokio::runtime::Runtime::new()?;
    let stats = rt.block_on(seed_corpus_from_live(
        &client,
        &core,
        &mut corpus,
        count,
        &format!("live-{network}"),
        &prefer,
    ));
    println!(
        "live seed ({network}): verified={} approved={} recorded={} skipped={}",
        stats.verified, stats.approved, stats.recorded, stats.skipped
    );
    if stats.recorded == 0 {
        eprintln!(
            "no fixtures recorded — check the RPC endpoint and --network; nothing was written"
        );
        std::process::exit(1);
    }
    corpus.save_to_dir(&corpus_dir)?;
    println!("corpus saved to {}", corpus_dir.display());
    Ok(())
}

pub fn verify_from_file(
    path: &PathBuf,
    profile: ProfileArg,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let input: VerificationInput = serde_json::from_str(&content)?;
    run(CliCommand::Verify {
        input: Box::new(input),
        profile,
    })
}

pub fn verify_from_stdin(profile: ProfileArg) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut content = String::new();
    std::io::stdin().read_to_string(&mut content)?;
    let input: VerificationInput = serde_json::from_str(&content)?;
    run(CliCommand::Verify {
        input: Box::new(input),
        profile,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_REG_DIR: AtomicU64 = AtomicU64::new(0);

    fn reg_dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "gr-cli-reg-{}-{}",
            std::process::id(),
            NEXT_REG_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Deterministic E2E of the registry operator path: register a reviewer,
    /// submit a signed manifest, and assert the acceptance log + state
    /// persistence (Phase 2 exit criterion: registry accepts signed community
    /// submissions through an operator path).
    #[test]
    fn registry_cli_register_and_submit_persists() {
        use crate::manifest::ProtocolManifest;

        let dir = reg_dir();
        let state = dir.join("state.json");
        let graph = dir.join("graph.json");

        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let pubkey = bs58::encode(key.verifying_key().to_bytes()).into_string();

        run_registry(RegistryAction::RegisterReviewer {
            state: Some(state.clone()),
            pubkey: pubkey.clone(),
            reputation: 500,
        })
        .unwrap();

        let manifest_json = r#"{
          "graphite_manifest_version": "1.0",
          "protocol": {
            "name": "Test Audit Protocol",
            "program_id": "AuditTest1111111111111111111111111111111111",
            "website": "https://example.com",
            "github": "https://github.com/example"
          },
          "version": { "label": "1.0.0", "effective_from_slot": 0, "previous_version_ref": null },
          "instructions": [
            {
              "name": "Ping",
              "discriminator": "aabbccdd",
              "accounts": [
                {"name": "signer", "role": "signer", "is_writable": false, "is_signer": true, "pda_seeds": []}
              ],
              "expected_state_changes": ["no state changes"],
              "allowed_cpis": [],
              "risk_rules": ["signer must be a signer"]
            }
          ],
          "trust_tier": "HeuristicInferred"
        }"#;
        let _: ProtocolManifest = serde_json::from_str(manifest_json).unwrap();
        let manifest_path = dir.join("manifest.json");
        std::fs::write(&manifest_path, manifest_json).unwrap();

        run_registry(RegistryAction::Submit {
            state: Some(state.clone()),
            graph_state: Some(graph.clone()),
            manifest_path,
            signer_key_hex: Some(hex::encode([7u8; 32])),
            attestations: vec![],
            corpus_dir: None,
        })
        .unwrap();

        // Persistence: reload and assert the append-only acceptance record and
        // the Semantic Graph entry (tier DERIVED — OfficialManifest for a
        // registered-reporter signature, P7).
        let engine = load_registry(&state).unwrap();
        assert_eq!(engine.records().len(), 1, "exactly one accepted record");
        assert_eq!(
            engine.records()[0].program_id,
            "AuditTest1111111111111111111111111111111111"
        );
        assert_eq!(engine.records()[0].source, "signed");
        let store = load_graph(&graph).unwrap();
        let behavior = store
            .get("AuditTest1111111111111111111111111111111111")
            .expect("submission must be appended to the Semantic Graph");
        assert_eq!(
            behavior.trust_tier,
            crate::confidence_engine::TrustTier::OfficialManifest
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A corrupt corpus must abort the seed (fail-closed), while a missing
    /// directory starts fresh — otherwise seed-live + save could silently
    /// drop the fixtures of every program on disk.
    #[test]
    fn seed_live_corpus_load_fails_closed_on_corruption() {
        let dir = reg_dir();
        // Corrupt fixture file → error, never a fresh start.
        std::fs::write(
            dir.join("11111111111111111111111111111111.json"),
            "{ not valid json",
        )
        .unwrap();
        assert!(
            load_corpus_for_seed(&dir).is_err(),
            "corrupt corpus must fail closed"
        );
        // Missing directory → fresh corpus (first run).
        let missing = dir.join("does-not-exist");
        assert!(
            load_corpus_for_seed(&missing).is_ok(),
            "missing dir must start fresh"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The registry CLI must REJECT an unregistered signer (P7: anonymous
    /// signing is worthless) without writing any state.
    #[test]
    fn registry_cli_rejects_unregistered_signer() {
        let dir = reg_dir();
        let state = dir.join("state.json");
        let graph = dir.join("graph.json");
        let manifest_path = dir.join("manifest.json");
        std::fs::write(
            &manifest_path,
            r#"{
              "graphite_manifest_version": "1.0",
              "protocol": {
                "name": "Test Audit Protocol",
                "program_id": "AuditTest1111111111111111111111111111111111",
                "website": "", "github": ""
              },
              "version": { "label": "1.0.0", "effective_from_slot": 0, "previous_version_ref": null },
              "instructions": [
                {"name": "Ping", "discriminator": "aabbccdd", "accounts": [],
                 "expected_state_changes": [], "allowed_cpis": [], "risk_rules": []}
              ],
              "trust_tier": "HeuristicInferred"
            }"#,
        )
        .unwrap();
        let err = run_registry(RegistryAction::Submit {
            state: Some(state.clone()),
            graph_state: Some(graph.clone()),
            manifest_path,
            signer_key_hex: Some(hex::encode([9u8; 32])),
            attestations: vec![],
            corpus_dir: None,
        })
        .unwrap_err();
        assert!(
            format!("{err}").contains("not a registered reviewer"),
            "unregistered signer must fail closed: {err}"
        );
        assert!(
            !state.exists(),
            "a rejected submission must not write registry state"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn arg(name: &str) -> ProfileArg {
        ProfileArg {
            name: Some(name.to_string()),
            min_confidence: None,
            min_trust_tier: None,
        }
    }

    #[test]
    fn test_empty_arg_resolves_to_none() {
        assert_eq!(resolve_profile(&ProfileArg::default()).unwrap(), None);
        assert!(ProfileArg::default().is_empty());
    }

    #[test]
    fn test_named_presets_resolve() {
        assert_eq!(
            resolve_profile(&arg("Treasury")).unwrap(),
            Some(WalletProfile::Treasury)
        );
        assert_eq!(
            resolve_profile(&arg("tradingbot")).unwrap(),
            Some(WalletProfile::TradingBot)
        );
        assert_eq!(
            resolve_profile(&arg("gaming")).unwrap(),
            Some(WalletProfile::Gaming)
        );
        assert_eq!(
            resolve_profile(&arg("enterprise")).unwrap(),
            Some(WalletProfile::Enterprise)
        );
    }

    #[test]
    fn test_unknown_profile_fails_closed() {
        assert!(resolve_profile(&arg("hacker")).is_err());
        assert!(resolve_profile(&arg("")).is_err());
    }

    #[test]
    fn test_thresholds_without_custom_rejected() {
        let partial = ProfileArg {
            name: None,
            min_confidence: Some(0.5),
            min_trust_tier: None,
        };
        assert!(resolve_profile(&partial).is_err());
        // Named presets ignore stray thresholds (documented, safe).
        let stray = ProfileArg {
            name: Some("treasury".to_string()),
            min_confidence: Some(0.1),
            min_trust_tier: None,
        };
        assert_eq!(
            resolve_profile(&stray).unwrap(),
            Some(WalletProfile::Treasury)
        );
    }

    #[test]
    fn test_custom_requires_both_thresholds() {
        let no_conf = ProfileArg {
            name: Some("custom".to_string()),
            min_confidence: None,
            min_trust_tier: Some("SimulationValidated".to_string()),
        };
        assert!(resolve_profile(&no_conf).is_err());
        let no_tier = ProfileArg {
            name: Some("custom".to_string()),
            min_confidence: Some(0.7),
            min_trust_tier: None,
        };
        assert!(resolve_profile(&no_tier).is_err());
        let ok = ProfileArg {
            name: Some("custom".to_string()),
            min_confidence: Some(0.7),
            min_trust_tier: Some("SimulationValidated".to_string()),
        };
        assert_eq!(
            resolve_profile(&ok).unwrap(),
            Some(WalletProfile::Custom {
                min_confidence: 0.7,
                min_trust_tier: TrustTier::SimulationValidated,
            })
        );
    }

    #[test]
    fn test_custom_unknown_tier_fails_closed() {
        // Operator-supplied thresholds must ERROR on unrecognized tiers —
        // silently lowering the required bar would make the profile strictly
        // MORE permissive than requested (fail-open on a typo). This is the
        // opposite of manifest-string parsing, where P6 under-trusting is safe.
        let bad = ProfileArg {
            name: Some("custom".to_string()),
            min_confidence: Some(0.5),
            min_trust_tier: Some("BattleTestedX".to_string()),
        };
        assert!(
            resolve_profile(&bad).is_err(),
            "unknown tier must fail closed"
        );
        let empty = ProfileArg {
            name: Some("custom".to_string()),
            min_confidence: Some(0.5),
            min_trust_tier: Some("".to_string()),
        };
        assert!(
            resolve_profile(&empty).is_err(),
            "empty tier must fail closed"
        );
    }

    #[test]
    fn test_custom_rejects_invalid_confidence() {
        for bad in [f64::NAN, f64::INFINITY, -0.1, 1.5] {
            let arg = ProfileArg {
                name: Some("custom".to_string()),
                min_confidence: Some(bad),
                min_trust_tier: Some("SimulationValidated".to_string()),
            };
            assert!(resolve_profile(&arg).is_err(), "confidence {bad} must fail");
        }
        // Boundary values are valid.
        for ok in [0.0, 1.0] {
            let arg = ProfileArg {
                name: Some("custom".to_string()),
                min_confidence: Some(ok),
                min_trust_tier: Some("SimulationValidated".to_string()),
            };
            assert!(resolve_profile(&arg).is_ok());
        }
    }
}
