//! CLI module for Graphite Core.

use crate::confidence_engine::TrustTier;
use crate::manifest::ProtocolManifest;
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
        host: String,
    },
    #[cfg(feature = "server")]
    Healthcheck {
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
    /// Withdraw a program from trust, restore it, or list what is withdrawn
    /// (ARCHITECTURE.md 3.8).
    Quarantine {
        action: QuarantineAction,
    },
    /// Verify a transaction and render WHY, layer by layer, instead of JSON.
    ///
    /// Same pipeline and same verdict as `verify` — this is a renderer, not a
    /// second decision path. P3 says a verdict must be explainable; a JSON blob
    /// is auditable but not readable, and the operator deciding whether to
    /// override a block is reading it under time pressure.
    Explain {
        input: Box<VerificationInput>,
        profile: ProfileArg,
    },
    /// Inspect what the gate knows about one program, or compare manifests.
    Protocol {
        action: ProtocolAction,
    },
    /// Validate a manifest against the runtime loader's schema without
    /// submitting it.
    ///
    /// The registry rejects a malformed manifest, but only after a reviewer has
    /// signed it — which is the wrong order. This is the check that belongs
    /// before the signature.
    ManifestVerify {
        path: PathBuf,
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
    /// Record a regression fixture for a program under a manifest that is not
    /// installed yet.
    ///
    /// This is the onboarding step the P10 gate requires. A brand-new program
    /// has no fixtures, and a fixture cannot be recorded through the ordinary
    /// path because the manifest that gives the program its shape has not been
    /// accepted — so verification would run in unknown-protocol mode and pin
    /// the wrong behaviour. This replays the input against the CANDIDATE
    /// manifest and appends what it observed.
    ///
    /// It pins observed behaviour; it does not judge it. Read the printed
    /// outcome before submitting — pinning a transaction you have not looked
    /// at makes the baseline every future upgrade is held to meaningless.
    RecordFixture {
        corpus_dir: PathBuf,
        /// The candidate manifest, so the replay sees the program's real shape.
        manifest_path: PathBuf,
        /// A `VerificationInput` JSON file — the same shape `graphite verify`
        /// reads.
        input_path: PathBuf,
    },
}

/// Quarantine operator action (dispatched by `CliCommand::Quarantine`).
///
/// Quarantine is deliberately an operator decision, never automatic — see
/// `GraphiteCore::quarantine_program` for the recorded tradeoff (P14).
///
/// These operate on the SERVER'S durable semantic graph (`GRAPHITE_DATA_DIR`,
/// default `./graphite-data`), not on the registry CLI's `graph_state.json`.
/// Those are two different stores: the server snapshots earned trust into its
/// data directory and never reads `graph_state.json`, so a quarantine written
/// there would be invisible to the thing doing the verifying. A running server
/// also has `POST /admin/quarantine`, which does not require a restart.
pub enum QuarantineAction {
    /// Withdraw a program from trust, forcing its tier to Unknown.
    Add {
        data_dir: Option<PathBuf>,
        program_id: String,
        reason: String,
    },
    /// Restore a quarantined program, recomputing its tier from evidence (P7).
    Lift {
        data_dir: Option<PathBuf>,
        program_id: String,
    },
    /// List every currently quarantined program and why.
    List { data_dir: Option<PathBuf> },
}

/// Protocol inspection action (dispatched by `CliCommand::Protocol`).
pub enum ProtocolAction {
    /// Everything the gate knows about one program: its manifest, the trust
    /// tier it has earned and the evidence behind it, its simulation baseline,
    /// its declared CPI targets, and whether it is quarantined.
    Status {
        data_dir: Option<PathBuf>,
        program_id: String,
    },
    /// Compare a candidate manifest against the one currently in force for the
    /// same program (or against another file).
    ///
    /// This is the reviewer's missing tool. The registry asks a reviewer to
    /// sign a manifest, and until now gave them nothing to see what they were
    /// signing off on — which instructions moved, which account roles changed,
    /// which CPI targets were added. A reviewer who cannot see the change
    /// cannot meaningfully attest to it, and their attestation is what earns
    /// the program a trust tier.
    Diff {
        candidate: PathBuf,
        /// Compare against this file instead of the manifest in force.
        against: Option<PathBuf>,
        data_dir: Option<PathBuf>,
    },
}

/// The server's durable state directory: `--data-dir`, else
/// `GRAPHITE_DATA_DIR`, else `./graphite-data` — the same resolution order
/// `serve` uses, so the CLI and the server agree on which graph they mean.
fn data_dir_path(explicit: Option<PathBuf>) -> PathBuf {
    explicit
        .or_else(|| {
            std::env::var("GRAPHITE_DATA_DIR")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from("graphite-data"))
}

pub fn run(command: CliCommand) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        CliCommand::Verify { input, profile } => {
            // Load the SERVER'S durable semantic graph, not a blank one.
            // `graphite verify` is how an operator asks "what would the gate
            // decide about this?", and a core with no earned trust, no
            // simulation baselines and no quarantines answers a different
            // question. Most visibly: a program the operator has withdrawn
            // from trust would still verify as OfficialManifest here while the
            // server blocked it. A missing directory is the normal first-run
            // case and starts a fresh store.
            let data_dir = data_dir_path(None);
            let mut core = GraphiteCore::with_data_dir(data_dir.clone());
            let quarantined = core.quarantined_programs().len();
            if quarantined > 0 {
                eprintln!(
                    "graph: {} ({quarantined} quarantined program(s))",
                    data_dir.display()
                );
            }
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
        CliCommand::Quarantine { action } => run_quarantine(action),
        CliCommand::Explain { input, profile } => run_explain(*input, &profile),
        CliCommand::Protocol { action } => run_protocol(action),
        CliCommand::ManifestVerify { path } => run_manifest_verify(&path),
        #[cfg(feature = "rpc")]
        CliCommand::RegressionSeedLive {
            rpc_url,
            corpus_dir,
            count,
            network,
        } => run_regression_seed_live(rpc_url, corpus_dir, count, network),
        #[cfg(feature = "server")]
        CliCommand::Server { port, host } => {
            // Bind address is explicit and defaults to loopback (see the
            // `--host` doc on the CLI): binding 0.0.0.0 unconditionally meant
            // `graphite server` on a laptop or cloud VM published an
            // API — unauthenticated, when GRAPHITE_API_KEY is unset — to
            // every network the host could be reached on. Publishing is now
            // an explicit, deliberate act.
            let ip: std::net::IpAddr = host.parse().map_err(|_| {
                format!(
                    "invalid --host {host:?}: expected an IP address, e.g. 127.0.0.1 or 0.0.0.0"
                )
            })?;
            let addr = std::net::SocketAddr::new(ip, port);
            // Refuse the genuinely dangerous combination outright: a
            // non-loopback bind with no API key set is an unauthenticated,
            // network-reachable verification API and dashboard. Fail closed
            // with an actionable message rather than starting it.
            let publicly_bound = !ip.is_loopback();
            let keyless = std::env::var("GRAPHITE_API_KEY")
                .map(|k| k.trim().is_empty())
                .unwrap_or(true);
            if publicly_bound && keyless {
                return Err(format!(
                    "refusing to bind {addr} without GRAPHITE_API_KEY: that would expose an \
                     unauthenticated verification API and dashboard to the network. Set \
                     GRAPHITE_API_KEY, or bind loopback with --host 127.0.0.1 for local \
                     development."
                )
                .into());
            }
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(crate::server::run_server(addr))?;
            Ok(())
        }
        #[cfg(feature = "server")]
        CliCommand::Healthcheck { port } => {
            let rt = tokio::runtime::Runtime::new()?;
            let url = format!("http://127.0.0.1:{port}/health");
            let ok = rt.block_on(async move {
                match reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(4))
                    .build()
                {
                    Ok(client) => match client.get(&url).send().await {
                        Ok(res) => res.status().is_success(),
                        Err(_) => false,
                    },
                    Err(_) => false,
                }
            });
            if ok {
                Ok(())
            } else {
                // Non-zero exit is what Docker's HEALTHCHECK reads.
                Err("health check failed".into())
            }
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

/// Load a corpus for appending to. A missing directory starts a fresh corpus
/// (first run); ANY other load failure (e.g. a corrupt fixture file) is an
/// error. Silently resetting a corrupt corpus and then saving would DROP the
/// fixtures of every program whose file was on disk (save_to_dir snapshots
/// the in-memory model per program) — data loss on partial corruption.
///
/// Not feature-gated: `registry record-fixture` needs it in every build, not
/// only under `rpc`. (It was `#[cfg(any(feature = "rpc", test))]`, which
/// `--all-features` can never catch — the same shape as the CI break where a
/// `server`-gated enum variant had an ungated match arm.)
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

/// Build the same core `verify` uses, so an explanation cannot disagree with a
/// verdict. Shared by `verify` and `explain`.
fn operator_core() -> GraphiteCore {
    let data_dir = data_dir_path(None);
    let mut core = GraphiteCore::with_data_dir(data_dir);
    let registry_path = registry_state_path(None);
    if let Ok(engine) = load_registry(&registry_path) {
        core.merge_community_manifests(&engine);
    }
    core
}

fn tier_label(tier: TrustTier) -> String {
    format!("{tier:?}")
}

/// Render a verification result as prose rather than JSON.
fn run_explain(
    mut input: VerificationInput,
    profile: &ProfileArg,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(p) = resolve_profile(profile)? {
        input.wallet_profile = p;
    }
    let core = operator_core();
    let result = core.verify(&input)?;
    let (min_confidence, min_tier) = input.wallet_profile.thresholds();

    println!(
        "{} {}",
        result.protocol_name,
        result
            .manifest_version
            .as_deref()
            .map(|v| format!("v{v}"))
            .unwrap_or_else(|| "(no manifest)".to_string())
    );
    println!("  program      {}", input.program_id);
    println!(
        "  instruction  {} ({})",
        result.instruction_name, input.instruction_discriminator
    );
    println!(
        "  intent       {} — {:?}",
        input.proposed_intent.intent_type, input.proposed_intent.raw_natural_language
    );
    println!("  content hash {}", result.content_hash);
    println!();

    println!(
        "VERDICT  {}",
        if result.approved {
            "APPROVED"
        } else {
            "BLOCKED"
        }
    );
    println!(
        "  confidence   {:.2}   (profile {} requires {:.2})",
        result.confidence,
        input.wallet_profile.label(),
        min_confidence
    );
    println!(
        "  trust tier   {}   (profile requires {})",
        result.trust_tier,
        tier_label(min_tier)
    );
    println!("  policy       {}", result.policy_verdict);
    println!("  risk         {}", result.risk_verdict.status);
    println!();

    println!("Layers");
    for layer in &result.layers {
        // The tri-state matters more than pass/fail: Inconclusive means "not
        // enough evidence to judge", which is a different thing from "checked
        // and fine" and must not read like it.
        let mark = match layer.status {
            crate::verification::LayerStatus::Passed => "pass",
            crate::verification::LayerStatus::Failed => "FAIL",
            crate::verification::LayerStatus::Inconclusive => "n/a ",
        };
        println!("  {mark}  {:<26} {}", layer.layer, layer.reason);
    }
    println!();

    println!("Confidence breakdown");
    if result.breakdown.is_empty() {
        println!("  (no signals contributed)");
    } else {
        for item in &result.breakdown {
            println!(
                "  {:<24} raw {:>5.2}  weight {:>5.2}  ->  {:+.3}",
                item.kind, item.raw_value, item.weight, item.contribution
            );
        }
        let total: f64 = result.breakdown.iter().map(|b| b.contribution).sum();
        println!("  {:<24} {:>36.3}", "sum of contributions", total);
        // P3: the breakdown must explain the score it is presented alongside.
        // A mismatch is a bug worth surfacing rather than hiding.
        if (total - result.confidence).abs() > 0.005 {
            println!(
                "  NOTE: the contributions sum to {total:.3} but the final confidence is {:.2} — \
                 a ceiling or penalty was applied after scoring.",
                result.confidence
            );
        }
    }
    println!();

    println!("Risk findings");
    if result.risk_verdict.findings.is_empty() {
        println!("  (none)");
    } else {
        for f in &result.risk_verdict.findings {
            println!("  {:<26} {}", f.pattern, f.reason);
        }
    }
    println!();

    println!("Accounts");
    for (i, a) in result.resolved_accounts.iter().enumerate() {
        let mut flags: Vec<&str> = Vec::new();
        if a.is_signer {
            flags.push("signer");
        }
        if a.is_writable {
            flags.push("writable");
        }
        if a.is_pda {
            flags.push("pda");
        }
        if a.expected_address_mismatch {
            flags.push("EXPECTED-ADDRESS-MISMATCH");
        }
        if a.pda_mismatch {
            flags.push("PDA-MISMATCH");
        }
        if a.privilege_mismatch {
            flags.push("PRIVILEGE-MISMATCH");
        }
        println!(
            "  #{i:<3} {:<14} {}  {}",
            a.role,
            a.address,
            flags.join(" ")
        );
    }
    println!();
    println!("{}", result.summary);

    if !result.approved {
        // Same convention as `regression`: usable as a shell gate.
        std::process::exit(1);
    }
    Ok(())
}

fn run_protocol(action: ProtocolAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        ProtocolAction::Status {
            data_dir,
            program_id,
        } => {
            let dir = data_dir_path(data_dir);
            let mut core = GraphiteCore::with_data_dir(dir.clone());
            let registry_path = registry_state_path(None);
            if let Ok(engine) = load_registry(&registry_path) {
                core.merge_community_manifests(&engine);
            }

            let snapshot = core.graph_snapshot();
            let node = snapshot.nodes.iter().find(|n| n.program_id == program_id);
            let manifest = core.registry().get(&program_id);

            if node.is_none() && manifest.is_none() {
                println!("{program_id}");
                println!("  UNKNOWN — no manifest and no behaviour record.");
                println!(
                    "  Verification would run in unknown-protocol mode, capped at the P6 \
                     confidence ceiling."
                );
                return Ok(());
            }

            println!("{}", node.map(|n| n.name.as_str()).unwrap_or("(unnamed)"));
            println!("  program        {program_id}");
            match manifest {
                Some(m) => {
                    println!("  manifest       v{}", m.version.label);
                    println!("  instructions   {}", m.instructions.len());
                }
                None => println!("  manifest       (none — behaviour record only)"),
            }

            // P7: a manifest's declared tier is the protocol's claim about
            // itself; only a behaviour record is earned. `graph_snapshot`
            // merges the two, which is right for a dashboard and wrong here —
            // printing "BattleTested" beside zero evidence would read as fact.
            let earned = core.program_behavior(&program_id);
            match &earned {
                Some(b) => {
                    println!("  trust tier     {:?}   (earned)", b.trust_tier);
                    println!(
                        "  evidence       battle-tested {} tx, community-verified {}, \
                         simulation matches {}, signed manifest {}",
                        b.evidence.battle_tested_tx_count,
                        b.evidence.community_verified_count,
                        b.evidence.simulation_match_count,
                        b.evidence.has_signed_manifest
                    );
                }
                None => {
                    println!(
                        "  trust tier     {}   (DECLARED by the manifest, not earned)",
                        manifest.map(|m| m.trust_tier.as_str()).unwrap_or("Unknown")
                    );
                    println!(
                        "  evidence       none — nothing recorded, so the verify path caps this \
                         program at OfficialManifest (P7)"
                    );
                }
            }
            if let Some(n) = node {
                println!(
                    "  sim baseline   {}",
                    match n.baseline_samples {
                        Some(c) if c > 0 => format!("{c} samples"),
                        _ => "none — L3 cannot judge divergence yet".to_string(),
                    }
                );
                if n.quarantined {
                    println!(
                        "  QUARANTINED    {}",
                        n.quarantine_reason
                            .as_deref()
                            .unwrap_or("no reason recorded")
                    );
                    println!(
                        "                 tier is forced to Unknown and verification hard-blocks"
                    );
                }
                if !n.cpi_targets.is_empty() {
                    println!("  declared CPI   {}", n.cpi_targets.join(", "));
                }
            }

            if let Some(m) = manifest {
                println!();
                println!("Instructions");
                for ix in &m.instructions {
                    let class = if ix.risk_class.is_empty() {
                        String::new()
                    } else {
                        format!("  [{}]", ix.risk_class)
                    };
                    println!("  {:<28} {}{}", ix.name, ix.discriminator, class);
                    if !ix.expected_state_changes.is_empty() {
                        println!("      changes: {}", ix.expected_state_changes.join("; "));
                    }
                    if !ix.allowed_cpis.is_empty() {
                        println!("      cpi:     {}", ix.allowed_cpis.join(", "));
                    }
                }
            }
            Ok(())
        }

        ProtocolAction::Diff {
            candidate,
            against,
            data_dir,
        } => {
            let candidate_manifest: ProtocolManifest = serde_json::from_str(
                &std::fs::read_to_string(&candidate)
                    .map_err(|e| format!("reading {}: {e}", candidate.display()))?,
            )
            .map_err(|e| format!("parsing {}: {e}", candidate.display()))?;

            let baseline: ProtocolManifest = match against {
                Some(path) => serde_json::from_str(
                    &std::fs::read_to_string(&path)
                        .map_err(|e| format!("reading {}: {e}", path.display()))?,
                )
                .map_err(|e| format!("parsing {}: {e}", path.display()))?,
                None => {
                    let dir = data_dir_path(data_dir);
                    let mut core = GraphiteCore::with_data_dir(dir);
                    if let Ok(engine) = load_registry(&registry_state_path(None)) {
                        core.merge_community_manifests(&engine);
                    }
                    match core.registry().get(&candidate_manifest.protocol.program_id) {
                        Some(m) => m.clone(),
                        None => {
                            println!(
                                "no manifest in force for {} — this candidate would be its first",
                                candidate_manifest.protocol.program_id
                            );
                            return Ok(());
                        }
                    }
                }
            };

            for line in manifest_diff(&baseline, &candidate_manifest) {
                println!("{line}");
            }
            Ok(())
        }
    }
}

/// Compare two manifests instruction by instruction.
///
/// Deliberately structural rather than textual: a reviewer needs to see that a
/// discriminator moved or an account became writable, not that a JSON key was
/// reordered. Ordering is by name so the output is stable (P2).
/// Everything that differs between two versions of one instruction, as lines a
/// reviewer can read. Shared by the changed-in-place path and the rename path,
/// so a rename can never hide a privilege change riding along with it.
fn instruction_changes(
    a: &crate::manifest::InstructionDef,
    b: &crate::manifest::InstructionDef,
) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    if a.discriminator != b.discriminator {
        lines.push(format!(
            "discriminator {} -> {}",
            a.discriminator, b.discriminator
        ));
    }
    if a.accounts.len() != b.accounts.len() {
        lines.push(format!(
            "account count {} -> {}",
            a.accounts.len(),
            b.accounts.len()
        ));
    }
    for (i, (x, y)) in a.accounts.iter().zip(b.accounts.iter()).enumerate() {
        if x.name != y.name || x.is_signer != y.is_signer || x.is_writable != y.is_writable {
            lines.push(format!(
                "account #{i}: {} (signer {}, writable {}) -> {} (signer {}, writable {})",
                x.name, x.is_signer, x.is_writable, y.name, y.is_signer, y.is_writable
            ));
        }
    }
    if a.expected_state_changes != b.expected_state_changes {
        lines.push(format!(
            "declared changes {:?} -> {:?}",
            a.expected_state_changes, b.expected_state_changes
        ));
    }
    if a.allowed_cpis != b.allowed_cpis {
        lines.push(format!(
            "allowed CPI {:?} -> {:?}",
            a.allowed_cpis, b.allowed_cpis
        ));
    }
    if a.risk_class != b.risk_class {
        lines.push(format!(
            "risk class {:?} -> {:?}",
            a.risk_class, b.risk_class
        ));
    }
    if a.variable_accounts != b.variable_accounts {
        lines.push(format!(
            "variable accounts {} -> {}",
            a.variable_accounts, b.variable_accounts
        ));
    }
    lines
}

pub fn manifest_diff(before: &ProtocolManifest, after: &ProtocolManifest) -> Vec<String> {
    use std::collections::BTreeMap;
    let mut out: Vec<String> = Vec::new();

    out.push(format!(
        "{} : v{} -> v{}",
        after.protocol.program_id, before.version.label, after.version.label
    ));
    if before.protocol.program_id != after.protocol.program_id {
        out.push(format!(
            "  !! PROGRAM ID DIFFERS: {} -> {} — these are not versions of the same protocol",
            before.protocol.program_id, after.protocol.program_id
        ));
    }
    if before.protocol.name != after.protocol.name {
        out.push(format!(
            "  name           {:?} -> {:?}",
            before.protocol.name, after.protocol.name
        ));
    }

    let old: BTreeMap<&str, _> = before
        .instructions
        .iter()
        .map(|i| (i.name.as_str(), i))
        .collect();
    let new: BTreeMap<&str, _> = after
        .instructions
        .iter()
        .map(|i| (i.name.as_str(), i))
        .collect();

    // An instruction that vanished from one side and appeared on the other with
    // the SAME discriminator was renamed, not removed and re-added. The
    // distinction is the reviewer's to make: a rename is cosmetic, a genuine
    // removal is breaking, and reporting both as "- X / + Y" invites approving
    // one while believing it is the other.
    let renames: BTreeMap<&str, &str> = old
        .iter()
        .filter(|(name, _)| !new.contains_key(*name))
        .filter_map(|(old_name, old_ix)| {
            new.iter()
                .find(|(new_name, new_ix)| {
                    !old.contains_key(*new_name) && new_ix.discriminator == old_ix.discriminator
                })
                .map(|(new_name, _)| (*old_name, *new_name))
        })
        .collect();
    let renamed_to: std::collections::BTreeSet<&str> = renames.values().copied().collect();

    let mut changed = false;
    for (old_name, new_name) in &renames {
        changed = true;
        out.push(format!(
            "  ~ {old_name} -> {new_name}  (renamed, discriminator {} unchanged)",
            old[old_name].discriminator
        ));
        // A rename can carry other changes with it; show them here rather than
        // letting the rename line stand in for a full comparison.
        for line in instruction_changes(old[old_name], new[new_name]) {
            out.push(format!("      {line}"));
        }
    }
    for (name, ix) in &new {
        if !old.contains_key(name) && !renamed_to.contains(name) {
            changed = true;
            out.push(format!("  + {name}  ({})", ix.discriminator));
            if !ix.expected_state_changes.is_empty() {
                out.push(format!(
                    "      changes: {}",
                    ix.expected_state_changes.join("; ")
                ));
            }
        }
    }
    for (name, ix) in &old {
        if !new.contains_key(name) && !renames.contains_key(name) {
            changed = true;
            out.push(format!("  - {name}  ({}) removed", ix.discriminator));
        }
    }
    for (name, a) in &old {
        let Some(b) = new.get(name) else { continue };
        let lines = instruction_changes(a, b);
        if !lines.is_empty() {
            changed = true;
            out.push(format!("  ~ {name}"));
            for l in lines {
                out.push(format!("      {l}"));
            }
        }
    }

    if !changed {
        out.push("  no instruction-level changes".to_string());
    }
    out
}

/// Validate a manifest exactly as the runtime loader would.
fn run_manifest_verify(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let json =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let manifest: ProtocolManifest =
        serde_json::from_str(&json).map_err(|e| format!("parsing {}: {e}", path.display()))?;

    // Run the REAL loader rather than a re-implementation of its rules: a
    // second copy of the schema check would eventually accept something the
    // loader rejects, and this command exists to predict the loader.
    let mut registry = crate::manifest::ManifestRegistry::new();
    match registry.load_from_json(&json) {
        Ok(_) => {
            println!("VALID  {}", path.display());
            println!("  protocol      {}", manifest.protocol.name);
            println!("  program       {}", manifest.protocol.program_id);
            println!("  version       v{}", manifest.version.label);
            println!("  instructions  {}", manifest.instructions.len());
            for ix in &manifest.instructions {
                println!(
                    "    {:<28} {:<20} {} account(s)",
                    ix.name,
                    ix.discriminator,
                    ix.accounts.len()
                );
            }
            println!();
            println!(
                "This is the loader's schema check only. It does not verify the manifest is TRUE \
                 about the program — that is what a reviewer attestation and the P10 regression \
                 gate are for."
            );
            Ok(())
        }
        Err(e) => {
            println!("INVALID  {}", path.display());
            println!("  {e}");
            std::process::exit(1);
        }
    }
}

/// Withdraw a program from trust, restore it, or list what is withdrawn.
///
/// Goes through `GraphiteCore`, so the change lands in the same durable
/// semantic graph the server loads at startup — writing to a store nothing
/// verifies against would be the whole point missed.
fn run_quarantine(action: QuarantineAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        QuarantineAction::Add {
            data_dir,
            program_id,
            reason,
        } => {
            let dir = data_dir_path(data_dir);
            let core = GraphiteCore::with_data_dir(dir.clone());
            core.quarantine_program(&program_id, &reason)?;
            println!("QUARANTINED {program_id} — {}", reason.trim());
            println!(
                "trust tier forced to Unknown until lifted; graph: {}",
                dir.display()
            );
            println!("A running server keeps its own copy in memory — restart it, or use POST /admin/quarantine.");
            Ok(())
        }
        QuarantineAction::Lift {
            data_dir,
            program_id,
        } => {
            let dir = data_dir_path(data_dir);
            let core = GraphiteCore::with_data_dir(dir.clone());
            core.lift_program_quarantine(&program_id)?;
            println!("LIFTED {program_id} — tier recomputed from evidence (P7)");
            println!("graph: {}", dir.display());
            Ok(())
        }
        QuarantineAction::List { data_dir } => {
            let dir = data_dir_path(data_dir);
            let core = GraphiteCore::with_data_dir(dir.clone());
            let active = core.quarantined_programs();
            if active.is_empty() {
                println!("no programs are quarantined ({})", dir.display());
            } else {
                println!(
                    "{} quarantined program(s) ({}):",
                    active.len(),
                    dir.display()
                );
                for (program, reason) in active {
                    let reason = if reason.is_empty() {
                        "(no reason recorded)".to_string()
                    } else {
                        reason
                    };
                    println!("  {program}  {reason}");
                }
            }
            Ok(())
        }
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
        RegistryAction::RecordFixture {
            corpus_dir,
            manifest_path,
            input_path,
        } => {
            let manifest_json = std::fs::read_to_string(&manifest_path)
                .map_err(|e| format!("reading {}: {e}", manifest_path.display()))?;
            let manifest: crate::manifest::ProtocolManifest = serde_json::from_str(&manifest_json)
                .map_err(|e| format!("parsing {}: {e}", manifest_path.display()))?;
            let input_json = std::fs::read_to_string(&input_path)
                .map_err(|e| format!("reading {}: {e}", input_path.display()))?;
            let input: crate::verification::VerificationInput =
                serde_json::from_str(&input_json)
                    .map_err(|e| format!("parsing {}: {e}", input_path.display()))?;

            if input.program_id != manifest.protocol.program_id {
                return Err(format!(
                    "input program_id {} does not match the manifest's {} — a fixture \
                     recorded for a different program would never be replayed by the gate",
                    input.program_id, manifest.protocol.program_id
                )
                .into());
            }

            // Replay against the manifest as it WOULD be installed. Without
            // this the program is unknown and the pinned outcome describes
            // unknown-protocol mode rather than the protocol.
            let core = GraphiteCore::new().with_candidate_manifest(&manifest)?;
            let result = core.verify(&input)?;

            let mut corpus = load_corpus_for_seed(&corpus_dir)?;
            let before = corpus.len();
            crate::regression_engine::record_fixture(
                &mut corpus,
                &input,
                result.approved,
                "onboarding",
            );
            corpus.save_to_dir(&corpus_dir)?;

            println!(
                "{} — confidence {:.2}, tier {}, {}",
                if result.approved {
                    "APPROVED"
                } else {
                    "BLOCKED"
                },
                result.confidence,
                result.trust_tier,
                result.summary
            );
            if corpus.len() == before {
                println!("fixture already present (deduped by content hash) — corpus unchanged");
            } else {
                println!("recorded 1 fixture into {}", corpus_dir.display());
            }
            println!(
                "This pins what the pipeline DID, not what it should do. Every future \
                 version of this manifest is regressed against it — check the outcome above."
            );
            Ok(())
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

    // ── Manifest diff (the reviewer's tool) ─────────────────────────────────

    fn diff_manifest(program: &str, version: &str) -> ProtocolManifest {
        use crate::manifest::{AccountRoleDef, InstructionDef, ManifestVersion, ProtocolInfo};
        ProtocolManifest {
            graphite_manifest_version: "1.0".to_string(),
            protocol: ProtocolInfo {
                name: "Demo".to_string(),
                program_id: program.to_string(),
                website: String::new(),
                github: String::new(),
                category: String::new(),
            },
            version: ManifestVersion {
                label: version.to_string(),
                effective_from_slot: 0,
                previous_version_ref: None,
            },
            instructions: vec![InstructionDef {
                name: "Deposit".to_string(),
                discriminator: "01".to_string(),
                accounts: vec![AccountRoleDef {
                    name: "vault".to_string(),
                    role: "vault".to_string(),
                    is_writable: false,
                    is_signer: false,
                    pda_seeds: vec![],
                    expected_address: vec![],
                }],
                expected_state_changes: vec!["debits depositor".to_string()],
                allowed_cpis: vec![],
                risk_rules: vec![],
                variable_accounts: false,
                risk_class: String::new(),
            }],
            trust_tier: String::new(),
        }
    }

    const DIFF_PROGRAM: &str = "GdP9U5aYx7f2kQzVwNmT8jRcL4hB6eX3sDnWqA1uMoH";

    #[test]
    fn an_unchanged_manifest_diffs_to_nothing() {
        let a = diff_manifest(DIFF_PROGRAM, "1.0");
        let out = manifest_diff(&a, &a);
        assert!(
            out.iter()
                .any(|l| l.contains("no instruction-level changes")),
            "{out:?}"
        );
    }

    #[test]
    fn the_diff_surfaces_every_change_a_reviewer_is_attesting_to() {
        // A reviewer's signature is what earns the program a trust tier, so
        // each of these has to be visible before they sign. A privilege
        // change in particular is invisible in a version bump.
        let before = diff_manifest(DIFF_PROGRAM, "1.0");
        let mut after = diff_manifest(DIFF_PROGRAM, "2.0");
        after.instructions[0].accounts[0].is_writable = true;
        after.instructions[0].allowed_cpis =
            vec!["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()];
        after.instructions[0].risk_class = "withdraw".to_string();
        after.instructions[0].expected_state_changes = vec![
            "debits depositor".to_string(),
            "assigns authority".to_string(),
        ];
        let mut added = after.instructions[0].clone();
        added.name = "EmergencyWithdraw".to_string();
        added.discriminator = "ff".to_string();
        after.instructions.push(added);

        let out = manifest_diff(&before, &after).join("\n");
        assert!(out.contains("v1.0 -> v2.0"), "{out}");
        assert!(
            out.contains("+ EmergencyWithdraw"),
            "new instruction: {out}"
        );
        assert!(out.contains("writable false"), "privilege change: {out}");
        assert!(out.contains("allowed CPI"), "new CPI target: {out}");
        assert!(out.contains("risk class"), "risk class change: {out}");
        assert!(out.contains("assigns authority"), "declared changes: {out}");
    }

    #[test]
    fn a_rename_is_not_reported_as_a_removal_plus_an_addition() {
        // A rename is cosmetic; a removal is breaking. Reporting both the same
        // way invites a reviewer to approve one while believing it is the
        // other. The discriminator staying put is what identifies the rename.
        let before = diff_manifest(DIFF_PROGRAM, "1.0");
        let mut after = diff_manifest(DIFF_PROGRAM, "2.0");
        after.instructions[0].name = "DepositV2".to_string();

        let out = manifest_diff(&before, &after).join(
            "
",
        );
        assert!(out.contains("Deposit -> DepositV2"), "{out}");
        assert!(out.contains("renamed"), "{out}");
        assert!(!out.contains("removed"), "a rename is not a removal: {out}");
        assert!(!out.contains("+ DepositV2"), "nor an addition: {out}");
    }

    #[test]
    fn a_rename_cannot_hide_a_privilege_change_riding_along_with_it() {
        // The dangerous case: the eye reads "renamed" and stops. Whatever else
        // moved has to be on the same screen.
        let before = diff_manifest(DIFF_PROGRAM, "1.0");
        let mut after = diff_manifest(DIFF_PROGRAM, "2.0");
        after.instructions[0].name = "DepositV2".to_string();
        after.instructions[0].accounts[0].is_writable = true;
        after.instructions[0].risk_class = "withdraw".to_string();

        let out = manifest_diff(&before, &after).join(
            "
",
        );
        assert!(out.contains("renamed"), "{out}");
        assert!(out.contains("writable false"), "privilege change: {out}");
        assert!(out.contains("risk class"), "risk class change: {out}");
    }

    #[test]
    fn a_genuine_removal_is_still_reported_as_one() {
        // The guard on the rename heuristic: a removal whose discriminator does
        // not reappear anywhere must not be quietly paired with an unrelated
        // new instruction.
        let before = diff_manifest(DIFF_PROGRAM, "1.0");
        let mut after = diff_manifest(DIFF_PROGRAM, "2.0");
        after.instructions[0].name = "SomethingElse".to_string();
        after.instructions[0].discriminator = "ff".to_string();

        let out = manifest_diff(&before, &after).join(
            "
",
        );
        assert!(out.contains("- Deposit"), "{out}");
        assert!(out.contains("+ SomethingElse"), "{out}");
        assert!(!out.contains("renamed"), "different discriminators: {out}");
    }

    #[test]
    fn a_removed_instruction_is_reported() {
        let before = diff_manifest(DIFF_PROGRAM, "1.0");
        let mut after = diff_manifest(DIFF_PROGRAM, "2.0");
        after.instructions.clear();
        let out = manifest_diff(&before, &after).join("\n");
        assert!(out.contains("- Deposit"), "{out}");
    }

    #[test]
    fn a_diff_across_two_different_programs_says_so_loudly() {
        // Diffing unrelated manifests produces a plausible-looking instruction
        // diff. Without this line a reviewer could read it as a version change.
        let before = diff_manifest(DIFF_PROGRAM, "1.0");
        let after = diff_manifest("11111111111111111111111111111111", "2.0");
        let out = manifest_diff(&before, &after).join("\n");
        assert!(out.contains("PROGRAM ID DIFFERS"), "{out}");
    }

    #[test]
    fn the_diff_is_deterministic_regardless_of_instruction_order() {
        // Manifests are hand-authored JSON; instruction order is not
        // meaningful, and a diff that changed with it would be unreviewable.
        let before = diff_manifest(DIFF_PROGRAM, "1.0");
        let mut after = diff_manifest(DIFF_PROGRAM, "2.0");
        let mut b = after.instructions[0].clone();
        b.name = "Withdraw".to_string();
        b.discriminator = "02".to_string();
        after.instructions.push(b);

        let forward = manifest_diff(&before, &after);
        after.instructions.reverse();
        let reversed = manifest_diff(&before, &after);
        assert_eq!(forward, reversed);
    }

    // ── Profile thresholds (single source of truth) ─────────────────────────

    #[test]
    fn reported_profile_thresholds_are_the_ones_the_policy_engine_enforces() {
        // These were inlined inside `evaluate_policy`, so anything that DISPLAYED
        // a threshold restated it. A restated constant drifts, and the number on
        // screen is exactly the one an operator trusts.
        use crate::policy_engine::{evaluate_policy, PolicyInput, PolicyVerdict};
        for profile in [
            WalletProfile::Treasury,
            WalletProfile::TradingBot,
            WalletProfile::Gaming,
            WalletProfile::Enterprise,
        ] {
            let (min_conf, _) = profile.thresholds();
            // Just below the reported threshold must be rejected for being
            // below threshold, and the engine must report the same number.
            let verdict = evaluate_policy(&PolicyInput {
                profile,
                confidence_result: crate::confidence_engine::ConfidenceResult {
                    confidence: min_conf - 0.01,
                    breakdown: vec![],
                    trust_tier_applied: TrustTier::BattleTested,
                    ceiling_triggered: false,
                    ceiling_applied: 1.0,
                },
                risk_verdict: crate::risk_engine::RiskVerdict::Passed,
            })
            .expect("policy evaluation");
            match verdict {
                PolicyVerdict::RejectedBelowThreshold { required, .. } => {
                    assert!(
                        (required - min_conf).abs() < 1e-9,
                        "{profile:?}: reported {min_conf}, enforced {required}"
                    );
                }
                other => panic!("{profile:?}: expected a threshold rejection, got {other:?}"),
            }
        }
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

        // A first submission earns a tier, which is a promotion, which the P10
        // gate requires a regression baseline for. This walks the real
        // onboarding flow rather than reaching past it: record a fixture under
        // the candidate manifest, then submit against that corpus.
        let corpus_dir = dir.join("corpus");
        let input_path = dir.join("input.json");
        let input_json = serde_json::json!({
            "proposed_intent": {
                "intent_type": "transfer",
                "raw_natural_language": "ping the audit test program",
                "confidence_of_parse": 0.9
            },
            "program_id": "AuditTest1111111111111111111111111111111111",
            "protocol_version": "1.0.0",
            "instruction_discriminator": "aabbccdd",
            "account_addresses": ["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"],
            "compute_units": 150,
            "account_writes": 1,
            "cpi_hops": 0
        });
        std::fs::write(&input_path, input_json.to_string()).unwrap();
        run_registry(RegistryAction::RecordFixture {
            corpus_dir: corpus_dir.clone(),
            manifest_path: manifest_path.clone(),
            input_path,
        })
        .expect("recording an onboarding fixture must work, or the gate is unreachable");

        run_registry(RegistryAction::Submit {
            state: Some(state.clone()),
            graph_state: Some(graph.clone()),
            manifest_path,
            signer_key_hex: Some(hex::encode([7u8; 32])),
            attestations: vec![],
            corpus_dir: Some(corpus_dir),
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
