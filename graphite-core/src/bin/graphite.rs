use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "graphite",
    about = "Graphite — Transaction verification for Solana AI agents",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify a transaction from a JSON file
    Verify {
        /// Path to JSON verification input
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Read JSON from stdin instead of file
        #[arg(long)]
        stdin: bool,
        /// Override the wallet policy profile
        /// (treasury|trading|gaming|enterprise|custom)
        #[arg(long)]
        profile: Option<String>,
        /// Custom profile: minimum confidence in [0.0, 1.0]
        #[arg(long)]
        min_confidence: Option<f64>,
        /// Custom profile: minimum trust tier
        /// (Unknown|HeuristicInferred|OfficialManifest|SimulationValidated|CommunityVerified|BattleTested)
        #[arg(long)]
        min_trust_tier: Option<String>,
    },
    /// List loaded protocol manifests
    Manifests,
    /// List wallet policy profiles and their thresholds
    Profiles,
    /// Start the HTTP verification server
    #[cfg(feature = "server")]
    Server {
        /// Port to listen on (default: 7331)
        #[arg(short, long, default_value = "7331")]
        port: u16,
        /// Address to bind (default: 127.0.0.1).
        ///
        /// Loopback by default so `graphite server` on a laptop, shared box,
        /// or cloud VM is not silently exposed to the whole network — pass
        /// 0.0.0.0 to publish deliberately. In a container, 0.0.0.0 is
        /// required for the port mapping to work; the container boundary is
        /// what limits exposure there.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
    },
    /// Probe a running server's /health endpoint (container HEALTHCHECK).
    ///
    /// Exists so the runtime image does not need `curl` installed purely to
    /// satisfy the Docker healthcheck — one fewer binary and dependency tree
    /// in the production image.
    #[cfg(feature = "server")]
    Healthcheck {
        /// Port to probe (default: 7331)
        #[arg(short, long, default_value = "7331")]
        port: u16,
    },
    /// Run the benchmark suite
    Benchmark,
    /// Regression corpus: replay (P10 gate) or seed from real on-chain data
    Regression {
        #[command(subcommand)]
        action: RegressionAction,
    },
    /// Withdraw a program from trust, restore it, or list what is withdrawn
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },
    /// Verify a transaction and print WHY, layer by layer, instead of JSON
    ///
    /// Same pipeline and same verdict as `verify` — a renderer, not a second
    /// decision path. Exits 1 when the transaction is blocked.
    Explain {
        /// Path to a VerificationInput JSON file
        #[arg(long)]
        file: PathBuf,
        /// Override the input's wallet profile
        #[arg(long)]
        profile: Option<String>,
        /// Minimum confidence for --profile custom
        #[arg(long)]
        min_confidence: Option<f64>,
        /// Minimum trust tier for --profile custom
        #[arg(long)]
        min_trust_tier: Option<String>,
    },
    /// Seed operator-asserted evidence or a simulation baseline
    ///
    /// Bootstrapping and state restore. A fresh graph has no evidence, and the
    /// evidence-derived confidence signals are half the available weight, so
    /// nothing clears a profile threshold until the graph holds something.
    Evidence {
        #[command(subcommand)]
        action: EvidenceAction,
    },
    /// Inspect what the gate knows about a program, or compare manifests
    Protocol {
        #[command(subcommand)]
        action: ProtocolAction,
    },
    /// Validate a manifest against the runtime loader's schema
    ///
    /// The check that belongs BEFORE a reviewer signs. Exits 1 when invalid.
    ManifestVerify {
        /// Path to the protocol manifest JSON
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Manifest Registry operator actions (G5 reviewers + signed submissions)
    Registry {
        #[command(subcommand)]
        action: RegistryAction,
    },
    /// List registered plugins and apply the manifest review gate (P8)
    Plugins {
        /// Directory of plugin manifests (JSON files) to discover + register
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum RegressionAction {
    /// Replay a corpus and enforce the P10 promotion gate (exit 1 on BLOCK)
    Replay {
        /// Directory containing regression fixture files (one per program)
        #[arg(long)]
        corpus_dir: PathBuf,
    },
    /// Collect REAL on-chain transactions into the regression corpus
    #[cfg(feature = "rpc")]
    SeedLive {
        /// RPC endpoint (e.g. https://api.mainnet-beta.solana.com)
        #[arg(long)]
        rpc: String,
        /// Corpus directory to merge into (created if missing)
        #[arg(long)]
        corpus_dir: PathBuf,
        /// Number of real transactions to verify and record
        #[arg(long, default_value_t = 25)]
        count: usize,
        /// Network label for fixture provenance (mainnet|devnet)
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
}

#[derive(Subcommand)]
enum EvidenceAction {
    /// Seed behaviour evidence for a program (the tier is recomputed, never set)
    Seed {
        /// Server durable state dir (default: GRAPHITE_DATA_DIR, else ./graphite-data)
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Program ID (base58)
        #[arg(long)]
        program: String,
        /// The protocol published a signed manifest
        #[arg(long)]
        signed_manifest: bool,
        /// Distinct reviewer attestations (2+ earns CommunityVerified)
        #[arg(long, default_value_t = 0)]
        community_verified: u32,
        /// Observed mainnet transactions (1000+ with credibility earns BattleTested)
        #[arg(long, default_value_t = 0)]
        battle_tested: u64,
        /// Simulation matches observed (3+ earns SimulationValidated)
        #[arg(long, default_value_t = 0)]
        simulation_matches: u64,
    },
    /// Seed a simulation baseline so L3 can judge divergence
    Baseline {
        /// Server durable state dir (default: GRAPHITE_DATA_DIR, else ./graphite-data)
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Program ID (base58)
        #[arg(long)]
        program: String,
        /// Mean compute units
        #[arg(long)]
        mean_compute_units: f64,
        /// Standard deviation of compute units
        #[arg(long, default_value_t = 1.0)]
        std_compute_units: f64,
        /// Number of samples the baseline represents (must be >= MIN_SAMPLES)
        #[arg(long)]
        samples: u64,
        /// Mean account writes
        #[arg(long, default_value_t = 2.0)]
        mean_account_writes: f64,
        /// Mean CPI hops
        #[arg(long, default_value_t = 0.0)]
        mean_cpi_hops: f64,
    },
    /// Show what the graph currently holds for a program
    Show {
        /// Server durable state dir (default: GRAPHITE_DATA_DIR, else ./graphite-data)
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Program ID (base58)
        #[arg(long)]
        program: String,
    },
}

#[derive(Subcommand)]
enum ProtocolAction {
    /// Show the manifest, earned trust tier, evidence, baseline and quarantine
    /// state for one program
    Status {
        /// Server durable state dir (default: GRAPHITE_DATA_DIR, else ./graphite-data)
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Program ID (base58)
        #[arg(long)]
        program: String,
    },
    /// Compare a candidate manifest against the one currently in force
    ///
    /// The reviewer's tool: see which instructions moved, which account roles
    /// changed and which CPI targets were added before attesting to a
    /// submission.
    Diff {
        /// The candidate manifest JSON
        #[arg(long)]
        manifest: PathBuf,
        /// Compare against this file instead of the manifest in force
        #[arg(long)]
        against: Option<PathBuf>,
        /// Server durable state dir (default: GRAPHITE_DATA_DIR, else ./graphite-data)
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum QuarantineAction {
    /// Withdraw a program from trust (forces its tier to Unknown)
    Add {
        /// Server durable state dir (default: GRAPHITE_DATA_DIR, else ./graphite-data)
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Program ID (base58) to withdraw from trust
        #[arg(long)]
        program: String,
        /// Why — recorded on the append-only graph and shown in listings
        #[arg(long)]
        reason: String,
    },
    /// Restore a quarantined program, recomputing its tier from evidence
    Lift {
        /// Server durable state dir (default: GRAPHITE_DATA_DIR, else ./graphite-data)
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Program ID (base58) to restore
        #[arg(long)]
        program: String,
    },
    /// List every currently quarantined program and why
    List {
        /// Server durable state dir (default: GRAPHITE_DATA_DIR, else ./graphite-data)
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum RegistryAction {
    /// List registered reviewers and the acceptance log
    Reviewers {
        /// Registry state file (default: registry_state.json)
        #[arg(long)]
        state: Option<PathBuf>,
    },
    /// Register a reviewer identity with a demonstrated reputation (G5)
    RegisterReviewer {
        /// Registry state file (default: registry_state.json)
        #[arg(long)]
        state: Option<PathBuf>,
        /// Reviewer Solana pubkey (base58)
        #[arg(long)]
        pubkey: String,
        /// Demonstrated reputation score (>= 100 counts toward Tier 4)
        #[arg(long)]
        reputation: u64,
    },
    /// Submit a signed community manifest
    Submit {
        /// Registry state file (default: registry_state.json)
        #[arg(long)]
        state: Option<PathBuf>,
        /// Semantic Graph state file (default: graph_state.json)
        #[arg(long)]
        graph_state: Option<PathBuf>,
        /// Path to the protocol manifest JSON to submit
        #[arg(long)]
        manifest: PathBuf,
        /// ed25519 secret key as 64 hex chars — signs the submission.
        ///
        /// DEPRECATED and insecure: a value passed here is visible in shell
        /// history and to every other user on the machine via `ps`/
        /// `/proc/<pid>/cmdline`. Prefer `--signer-key-file` (or
        /// `GRAPHITE_SIGNER_KEY_FILE`), which reads the key from a file whose
        /// permissions you control. Kept only for backward compatibility;
        /// using it prints a warning.
        #[arg(long)]
        signer_key: Option<String>,
        /// Path to a file containing the ed25519 secret key (64 hex chars).
        ///
        /// The file's contents are trimmed, so a trailing newline is fine.
        /// Overrides `--signer-key` when both are given. Also settable via
        /// `GRAPHITE_SIGNER_KEY_FILE`.
        #[arg(long)]
        signer_key_file: Option<PathBuf>,
        /// Reviewer attestation as <pubkey>:<signature_hex> (repeatable)
        #[arg(long)]
        attestation: Vec<String>,
        /// Regression corpus the engine replays for the P10 promotion gate
        #[arg(long)]
        corpus_dir: Option<PathBuf>,
    },
    /// Record a regression fixture under a manifest that is not installed yet
    ///
    /// The onboarding step the P10 gate requires: a brand-new program has no
    /// fixtures, and recording one the ordinary way would pin unknown-protocol
    /// behaviour rather than the protocol's. Prints the outcome it pinned —
    /// read it before submitting.
    RecordFixture {
        /// Regression corpus directory to append to (created if absent)
        #[arg(long)]
        corpus_dir: PathBuf,
        /// The candidate protocol manifest JSON
        #[arg(long)]
        manifest: PathBuf,
        /// A VerificationInput JSON file, same shape `graphite verify` reads
        #[arg(long)]
        input: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Verify {
            file: Some(path),
            stdin: false,
            profile,
            min_confidence,
            min_trust_tier,
        } => graphite_core::cli::verify_from_file(
            &path,
            graphite_core::cli::ProfileArg {
                name: profile,
                min_confidence,
                min_trust_tier,
            },
        ),
        Commands::Verify {
            file: None,
            stdin: true,
            profile,
            min_confidence,
            min_trust_tier,
        } => graphite_core::cli::verify_from_stdin(graphite_core::cli::ProfileArg {
            name: profile,
            min_confidence,
            min_trust_tier,
        }),
        Commands::Verify { .. } => {
            eprintln!("Error: specify --file <path> or --stdin");
            std::process::exit(1);
        }
        Commands::Manifests => graphite_core::cli::run(graphite_core::cli::CliCommand::Manifests),
        Commands::Profiles => graphite_core::cli::run(graphite_core::cli::CliCommand::Profiles),
        #[cfg(feature = "server")]
        Commands::Server { port, host } => {
            graphite_core::cli::run(graphite_core::cli::CliCommand::Server { port, host })
        }
        // Must carry the same gate as the variant it matches: `Healthcheck` is
        // `#[cfg(feature = "server")]`, so without that feature the variant
        // does not exist and an ungated arm fails to compile. Caught by CI's
        // `--no-default-features --features cli` job, which is exactly why
        // that job exists — `--all-features` can never surface this.
        #[cfg(feature = "server")]
        Commands::Healthcheck { port } => {
            graphite_core::cli::run(graphite_core::cli::CliCommand::Healthcheck { port })
        }
        Commands::Benchmark => graphite_core::cli::run(graphite_core::cli::CliCommand::Benchmark),
        Commands::Regression { action } => match action {
            RegressionAction::Replay { corpus_dir } => {
                graphite_core::cli::run(graphite_core::cli::CliCommand::Regression { corpus_dir })
            }
            #[cfg(feature = "rpc")]
            RegressionAction::SeedLive {
                rpc,
                corpus_dir,
                count,
                network,
            } => graphite_core::cli::run(graphite_core::cli::CliCommand::RegressionSeedLive {
                rpc_url: rpc,
                corpus_dir,
                count,
                network,
            }),
        },
        Commands::Registry { action } => match action {
            RegistryAction::Reviewers { state } => {
                graphite_core::cli::run(graphite_core::cli::CliCommand::Registry {
                    action: graphite_core::cli::RegistryAction::Reviewers { state },
                })
            }
            RegistryAction::RegisterReviewer {
                state,
                pubkey,
                reputation,
            } => graphite_core::cli::run(graphite_core::cli::CliCommand::Registry {
                action: graphite_core::cli::RegistryAction::RegisterReviewer {
                    state,
                    pubkey,
                    reputation,
                },
            }),
            RegistryAction::Submit {
                state,
                graph_state,
                manifest,
                signer_key,
                signer_key_file,
                attestation,
                corpus_dir,
            } => {
                // Resolve the signing key without ever requiring it on the
                // command line: --signer-key-file wins, then the env var
                // pointing at a file, then the deprecated inline flag.
                let key_file = signer_key_file.or_else(|| {
                    std::env::var("GRAPHITE_SIGNER_KEY_FILE")
                        .ok()
                        .filter(|s| !s.trim().is_empty())
                        .map(PathBuf::from)
                });
                let signer_key_hex = match key_file {
                    Some(path) => {
                        let raw = std::fs::read_to_string(&path).map_err(|e| {
                            format!("failed to read signer key file {}: {e}", path.display())
                        })?;
                        Some(raw.trim().to_string())
                    }
                    None => {
                        if signer_key.is_some() {
                            eprintln!(
                                "[graphite] WARNING: --signer-key exposes the secret key in shell \
                                 history and to other users via `ps`. Use --signer-key-file (or \
                                 GRAPHITE_SIGNER_KEY_FILE) instead."
                            );
                        }
                        signer_key
                    }
                };
                graphite_core::cli::run(graphite_core::cli::CliCommand::Registry {
                    action: graphite_core::cli::RegistryAction::Submit {
                        state,
                        graph_state,
                        manifest_path: manifest,
                        signer_key_hex,
                        attestations: attestation,
                        corpus_dir,
                    },
                })
            }
            RegistryAction::RecordFixture {
                corpus_dir,
                manifest,
                input,
            } => graphite_core::cli::run(graphite_core::cli::CliCommand::Registry {
                action: graphite_core::cli::RegistryAction::RecordFixture {
                    corpus_dir,
                    manifest_path: manifest,
                    input_path: input,
                },
            }),
        },
        Commands::Quarantine { action } => match action {
            QuarantineAction::Add {
                data_dir,
                program,
                reason,
            } => graphite_core::cli::run(graphite_core::cli::CliCommand::Quarantine {
                action: graphite_core::cli::QuarantineAction::Add {
                    data_dir,
                    program_id: program,
                    reason,
                },
            }),
            QuarantineAction::Lift { data_dir, program } => {
                graphite_core::cli::run(graphite_core::cli::CliCommand::Quarantine {
                    action: graphite_core::cli::QuarantineAction::Lift {
                        data_dir,
                        program_id: program,
                    },
                })
            }
            QuarantineAction::List { data_dir } => {
                graphite_core::cli::run(graphite_core::cli::CliCommand::Quarantine {
                    action: graphite_core::cli::QuarantineAction::List { data_dir },
                })
            }
        },
        Commands::Explain {
            file,
            profile,
            min_confidence,
            min_trust_tier,
        } => {
            let json = std::fs::read_to_string(&file)
                .map_err(|e| format!("failed to read {}: {e}", file.display()))?;
            let input: graphite_core::verification::VerificationInput = serde_json::from_str(&json)
                .map_err(|e| format!("failed to parse {}: {e}", file.display()))?;
            graphite_core::cli::run(graphite_core::cli::CliCommand::Explain {
                input: Box::new(input),
                profile: graphite_core::cli::ProfileArg {
                    name: profile,
                    min_confidence,
                    min_trust_tier,
                },
            })
        }
        Commands::Evidence { action } => match action {
            EvidenceAction::Seed {
                data_dir,
                program,
                signed_manifest,
                community_verified,
                battle_tested,
                simulation_matches,
            } => graphite_core::cli::run(graphite_core::cli::CliCommand::Evidence {
                action: graphite_core::cli::EvidenceAction::Seed {
                    data_dir,
                    program_id: program,
                    signed_manifest,
                    community_verified,
                    battle_tested,
                    simulation_matches,
                },
            }),
            EvidenceAction::Baseline {
                data_dir,
                program,
                mean_compute_units,
                std_compute_units,
                samples,
                mean_account_writes,
                mean_cpi_hops,
            } => graphite_core::cli::run(graphite_core::cli::CliCommand::Evidence {
                action: graphite_core::cli::EvidenceAction::Baseline {
                    data_dir,
                    program_id: program,
                    mean_compute_units,
                    std_compute_units,
                    samples,
                    mean_account_writes,
                    mean_cpi_hops,
                },
            }),
            EvidenceAction::Show { data_dir, program } => {
                graphite_core::cli::run(graphite_core::cli::CliCommand::Evidence {
                    action: graphite_core::cli::EvidenceAction::Show {
                        data_dir,
                        program_id: program,
                    },
                })
            }
        },
        Commands::Protocol { action } => match action {
            ProtocolAction::Status { data_dir, program } => {
                graphite_core::cli::run(graphite_core::cli::CliCommand::Protocol {
                    action: graphite_core::cli::ProtocolAction::Status {
                        data_dir,
                        program_id: program,
                    },
                })
            }
            ProtocolAction::Diff {
                manifest,
                against,
                data_dir,
            } => graphite_core::cli::run(graphite_core::cli::CliCommand::Protocol {
                action: graphite_core::cli::ProtocolAction::Diff {
                    candidate: manifest,
                    against,
                    data_dir,
                },
            }),
        },
        Commands::ManifestVerify { manifest } => {
            graphite_core::cli::run(graphite_core::cli::CliCommand::ManifestVerify {
                path: manifest,
            })
        }
        Commands::Plugins { dir } => {
            graphite_core::cli::run(graphite_core::cli::CliCommand::Plugins { dir })
        }
    }
}
