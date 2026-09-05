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
        /// ed25519 secret key as 64 hex chars — signs the submission
        #[arg(long)]
        signer_key: Option<String>,
        /// Reviewer attestation as <pubkey>:<signature_hex> (repeatable)
        #[arg(long)]
        attestation: Vec<String>,
        /// Regression corpus the engine replays for the P10 promotion gate
        #[arg(long)]
        corpus_dir: Option<PathBuf>,
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
                attestation,
                corpus_dir,
            } => graphite_core::cli::run(graphite_core::cli::CliCommand::Registry {
                action: graphite_core::cli::RegistryAction::Submit {
                    state,
                    graph_state,
                    manifest_path: manifest,
                    signer_key_hex: signer_key,
                    attestations: attestation,
                    corpus_dir,
                },
            }),
        },
        Commands::Plugins { dir } => {
            graphite_core::cli::run(graphite_core::cli::CliCommand::Plugins { dir })
        }
    }
}
