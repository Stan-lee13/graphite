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
    /// Verify a transaction from a JSON file, as the server would
    ///
    /// Reads the server's data directory, registry state and boundary
    /// settings (GRAPHITE_WALLET_PROFILE, GRAPHITE_ALLOW_PERMISSIVE_PROFILES,
    /// GRAPHITE_PLUGINS_DIR, GRAPHITE_ALLOW_DURABLE_NONCE,
    /// GRAPHITE_QUARANTINE_ON_UPGRADE). Exits 0 only when the verdict is
    /// `executable_approved`, 1 when it is refused, 3 when it is approved
    /// but `analysis_only` (this command attaches no RPC, so nothing it
    /// verifies is simulated).
    Verify {
        /// Path to JSON verification input
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Read JSON from stdin instead of file
        #[arg(long)]
        stdin: bool,
        /// Override the input's wallet policy profile
        /// (treasury|trading|gaming|enterprise|custom). Treated as the request
        /// body's profile: a server pin wins, and a weak custom profile is
        /// clamped as the server clamps it.
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
        /// Address to probe: an IP (IPv4 or IPv6) or `localhost`
        /// (default: 127.0.0.1). An unspecified bind address (0.0.0.0, ::)
        /// is probed on the loopback address of its family.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Also fail when /health reports `degraded: true` (for example,
        /// failing audit writes). Off by default so a load balancer keeps a
        /// node that still refuses correctly.
        #[arg(long)]
        strict: bool,
    },
    /// Run the benchmark suite
    Benchmark {
        /// Print the release evaluation instead: every committed labelled
        /// input scored per split, as JSON, with input hashes, code HEAD and
        /// Wilson intervals.
        #[arg(long)]
        json: bool,
        /// The graphite-core directory holding the committed inputs
        /// (default: the current directory, or its graphite-core child).
        #[arg(long)]
        root: Option<std::path::PathBuf>,
    },
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
    /// decision path. Exits as `verify` does: 0 executable, 1 refused, 3 analysis_only.
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
    /// L8 - confirm a submitted transaction and reconcile it against the record
    ///
    /// Exit status, for use as a monitoring check:
    ///   0  reconciled; nothing to alarm on
    ///   1  DISCREPANCY: Graphite blocked a transaction that executed anyway
    ///   2  usage error (bad arguments)
    ///   3  unavailable: the check could not be made (no RPC answer, no
    ///      audit trail, or a configuration error)
    ///   4  the RPC returned transaction bytes not bound to the signature
    ///   5  the primary RPC contradicted itself about the signature
    ///   6  the inclusion witness disagreed, or could not be asked
    #[cfg(feature = "rpc")]
    #[command(verbatim_doc_comment)]
    Execution {
        /// Server durable state dir (default: GRAPHITE_DATA_DIR, else ./graphite-data)
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// On-chain transaction signature (base58)
        #[arg(long)]
        signature: String,
        /// content_hash of the verification this execution corresponds to
        /// (instruction-level; names every transaction carrying that instruction).
        /// Also accepted as --instruction-bind-key, its name since Round 30
        #[arg(long, alias = "instruction-bind-key")]
        content_hash: Option<String>,
        /// scope.transaction_sha256 of the verification: the exact transaction
        #[arg(long)]
        transaction_sha256: Option<String>,
        /// audit_trail_id of the verification: the exact record
        #[arg(long)]
        audit_trail_id: Option<String>,
        /// RPC endpoint (default: GRAPHITE_RPC_URL)
        #[arg(long)]
        rpc_url: Option<String>,
        /// A second, independent RPC asked about inclusion (default:
        /// GRAPHITE_RPC_WITNESS_URL). Without one every conclusion rests on
        /// the primary RPC's word that the signature landed.
        #[arg(long)]
        witness_url: Option<String>,
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
    /// Check the audit trail's hash chain, export a checkpoint of its head,
    /// or adopt a key
    ///
    /// `verify` and `checkpoint` are read-only and safe beside a running
    /// server; `adopt-key` writes, and needs the server stopped.
    Audit {
        #[command(subcommand)]
        action: AuditAction,
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
    /// Seed HistoricalVolume from the committed, measured mainnet census
    /// (Round 40)
    ///
    /// Reads protocols/battle_tested_evidence.json as compiled into this
    /// build (or a --census file, which must be byte-identical to it). Only
    /// records that clear every threshold, of a program with a loaded
    /// manifest that exists and is executable, are imported; each import is
    /// one operator_action row on the audit trail. The tier is recomputed
    /// from the evidence (P7); no signature is asserted. Re-running imports
    /// nothing the graph already holds.
    ImportCensus {
        /// Server durable state dir (default: GRAPHITE_DATA_DIR, else ./graphite-data)
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// A census file to check against the compiled-in copy
        #[arg(long)]
        census: Option<PathBuf>,
        /// Import only this program (repeatable; default: every record)
        #[arg(long = "program")]
        programs: Vec<String>,
        /// Print what would be imported, and the resulting tier and
        /// confidence per program, without writing anything
        #[arg(long)]
        dry_run: bool,
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
    /// Replace a frozen simulation baseline with the clean executions it
    /// refused (/health counts them in `frozen_baseline_count`; the
    /// authenticated GET /api/frozen-baselines lists them)
    PromoteShadow {
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
enum AuditAction {
    /// Walk every archive and the active file against the hash chain
    ///
    /// Exits 0 when nothing failed, 1 on a break or a checkpoint that does
    /// not hold, 2 when the walk could not prove what it was asked to (MACs
    /// under a key not supplied that a checked key-adoption record covers,
    /// no chained record, a pruned checkpoint), 3 when the trail, a key file
    /// or the checkpoint could not be read, 4 when keys were supplied and
    /// something is not covered by them (unkeyed records no key-adoption
    /// record covers, MACs under keys not supplied that nothing covers, an
    /// unsigned checkpoint), 64 on a usage error. See docs/ops/keys.md.
    Verify {
        /// Server durable state dir (default: GRAPHITE_DATA_DIR, else ./graphite-data)
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// A key file whose MACs to check (repeatable: old keys after a
        /// rotation). GRAPHITE_AUDIT_KEY_FILE is added when set.
        #[arg(long = "key-file")]
        key_files: Vec<PathBuf>,
        /// A checkpoint exported earlier: detects rewrite, truncation and
        /// stale restores up to its sequence number
        #[arg(long)]
        checkpoint: Option<PathBuf>,
        /// Print the full report as JSON
        #[arg(long)]
        json: bool,
    },
    /// Verify the trail, then export a checkpoint of its head for anchoring
    ///
    /// MAC'd under the key the head is under. Refused, with `verify`'s exit
    /// code, unless the keys given cover the head: `verify` exits 0 with
    /// them, or 2 only for a lost key a checked key-adoption record closes.
    Checkpoint {
        /// Server durable state dir (default: GRAPHITE_DATA_DIR, else ./graphite-data)
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Key file to MAC the checkpoint with (default: GRAPHITE_AUDIT_KEY_FILE)
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// Write here instead of stdout (never over an existing file)
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Continue the trail under a key whose head cannot be checked under it
    ///
    /// With the server stopped: writes a key-adoption record MAC'd under
    /// --key-file. For a trail that was never keyed, one keyed before
    /// key-adoption records existed, or one whose previous key is lost.
    /// Walks the trail first and refuses a broken one. Check the history
    /// before adopting it: the adoption vouches for it (docs/ops/keys.md).
    AdoptKey {
        /// Server durable state dir (default: GRAPHITE_DATA_DIR, else ./graphite-data)
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// The key to continue under
        #[arg(long)]
        key_file: PathBuf,
        /// The key the trail's head is under, when it is still held: the
        /// head is checked under it and the adoption recorded as checked
        #[arg(long)]
        previous_key_file: Option<PathBuf>,
    },
    /// Accept a torn write a pre-Round-34 writer left in the trail
    ///
    /// With the server stopped: appends a chained record (MAC'd when the
    /// trail is keyed) naming the line that is not JSON at --offset of
    /// --file, after which `audit verify` tolerates exactly that line.
    /// Refuses a trail broken by anything else, and any line that is not
    /// an unacknowledged tear `audit verify` lists. Inspect the line first.
    AcknowledgeTear {
        /// Server durable state dir (default: GRAPHITE_DATA_DIR, else ./graphite-data)
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// The trail file holding the tear, as `audit verify` names it
        #[arg(long)]
        file: String,
        /// The tear's byte offset in that file, as `audit verify` gives it
        #[arg(long)]
        offset: u64,
        /// Key file to MAC the acknowledgement with (default: GRAPHITE_AUDIT_KEY_FILE)
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
    /// Record a prune of the oldest archives that nothing recorded
    ///
    /// With the server stopped. A trail pruned before Round 38 starts above
    /// seq 0 with no prune record, and `audit verify` reports a break: the
    /// records before it could as well have been deleted. Check the trail
    /// against an anchored checkpoint or a backup first; this then appends a
    /// prune record naming where the trail starts now. Refuses a trail
    /// broken by anything else.
    AcknowledgePrune {
        /// Server durable state dir (default: GRAPHITE_DATA_DIR, else ./graphite-data)
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Key file the trail's head is under (default: GRAPHITE_AUDIT_KEY_FILE)
        #[arg(long)]
        key_file: Option<PathBuf>,
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
    /// Check every acceptance record from its own contents: exit 0 all
    /// verified, 1 one failed, 2 one predates retained signatures
    VerifyRecords {
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
    /// Revoke a reviewer: its signatures and attestations stop counting, and
    /// the tiers they helped earn are recomputed (permanent)
    RevokeReviewer {
        /// Registry state file (default: registry_state.json)
        #[arg(long)]
        state: Option<PathBuf>,
        /// Semantic Graph state file (default: graph_state.json)
        #[arg(long)]
        graph_state: Option<PathBuf>,
        /// Reviewer Solana pubkey (base58)
        #[arg(long)]
        pubkey: String,
    },
    /// Retire one fixture of the registry's own regression corpus
    DeprecateFixture {
        /// Registry state file (default: registry_state.json)
        #[arg(long)]
        state: Option<PathBuf>,
        /// The fixture's content_hash
        #[arg(long)]
        content_hash: String,
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
    // Round 38 (T-14): a usage error under `audit` exits 64, not clap's 2,
    // which `audit verify` uses for "unproven": a script reading 2 as a lost
    // key went on to check a report a mistyped command never produced. Help
    // and version still exit 0; every other command keeps clap's 2 (which
    // `graphite execution` documents as its usage error).
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let audit = std::env::args_os().nth(1).is_some_and(|a| a == "audit");
            if audit && e.use_stderr() {
                let _ = e.print();
                std::process::exit(64);
            }
            e.exit()
        }
    };
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
        Commands::Healthcheck { port, host, strict } => {
            graphite_core::cli::run(graphite_core::cli::CliCommand::Healthcheck {
                port,
                host,
                strict,
            })
        }
        Commands::Benchmark { json, root } => {
            graphite_core::cli::run(graphite_core::cli::CliCommand::Benchmark { json, root })
        }
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
            RegistryAction::VerifyRecords { state } => {
                graphite_core::cli::run(graphite_core::cli::CliCommand::Registry {
                    action: graphite_core::cli::RegistryAction::VerifyRecords { state },
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
                    // Round 40 (R39-CB-14): refused when group or others
                    // can read or write it, as the audit key file is.
                    Some(path) => Some(graphite_core::cli::read_signer_key_file(&path)?),
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
            RegistryAction::RevokeReviewer {
                state,
                graph_state,
                pubkey,
            } => graphite_core::cli::run(graphite_core::cli::CliCommand::Registry {
                action: graphite_core::cli::RegistryAction::RevokeReviewer {
                    state,
                    graph_state,
                    pubkey,
                },
            }),
            RegistryAction::DeprecateFixture {
                state,
                content_hash,
            } => graphite_core::cli::run(graphite_core::cli::CliCommand::Registry {
                action: graphite_core::cli::RegistryAction::DeprecateFixture {
                    state,
                    content_hash,
                },
            }),
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
        Commands::Audit { action } => match action {
            AuditAction::Verify {
                data_dir,
                key_files,
                checkpoint,
                json,
            } => graphite_core::cli::run(graphite_core::cli::CliCommand::Audit {
                action: graphite_core::cli::AuditAction::Verify {
                    data_dir,
                    key_files,
                    checkpoint,
                    json,
                },
            }),
            AuditAction::Checkpoint {
                data_dir,
                key_file,
                out,
            } => graphite_core::cli::run(graphite_core::cli::CliCommand::Audit {
                action: graphite_core::cli::AuditAction::Checkpoint {
                    data_dir,
                    key_file,
                    out,
                },
            }),
            AuditAction::AdoptKey {
                data_dir,
                key_file,
                previous_key_file,
            } => graphite_core::cli::run(graphite_core::cli::CliCommand::Audit {
                action: graphite_core::cli::AuditAction::AdoptKey {
                    data_dir,
                    key_file,
                    previous_key_file,
                },
            }),
            AuditAction::AcknowledgeTear {
                data_dir,
                file,
                offset,
                key_file,
            } => graphite_core::cli::run(graphite_core::cli::CliCommand::Audit {
                action: graphite_core::cli::AuditAction::AcknowledgeTear {
                    data_dir,
                    file,
                    offset,
                    key_file,
                },
            }),
            AuditAction::AcknowledgePrune { data_dir, key_file } => {
                graphite_core::cli::run(graphite_core::cli::CliCommand::Audit {
                    action: graphite_core::cli::AuditAction::AcknowledgePrune {
                        data_dir,
                        key_file,
                    },
                })
            }
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
        #[cfg(feature = "rpc")]
        Commands::Execution {
            data_dir,
            signature,
            content_hash,
            transaction_sha256,
            audit_trail_id,
            rpc_url,
            witness_url,
        } => graphite_core::cli::run(graphite_core::cli::CliCommand::Execution {
            data_dir,
            signature,
            content_hash,
            transaction_sha256,
            audit_trail_id,
            rpc_url,
            witness_url,
        }),
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
            EvidenceAction::PromoteShadow { data_dir, program } => {
                graphite_core::cli::run(graphite_core::cli::CliCommand::Evidence {
                    action: graphite_core::cli::EvidenceAction::PromoteShadow {
                        data_dir,
                        program_id: program,
                    },
                })
            }
            EvidenceAction::ImportCensus {
                data_dir,
                census,
                programs,
                dry_run,
            } => graphite_core::cli::run(graphite_core::cli::CliCommand::Evidence {
                action: graphite_core::cli::EvidenceAction::ImportCensus {
                    data_dir,
                    census,
                    programs,
                    dry_run,
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
