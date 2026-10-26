//! CLI module for Graphite Core.

use crate::confidence_engine::TrustTier;
use crate::manifest::ProtocolManifest;
use crate::policy_engine::WalletProfile;
use crate::verification::{GraphiteCore, VerificationInput, VerificationResult};
use std::path::{Path, PathBuf};

/// The operator-boundary rules (`GRAPHITE_WALLET_PROFILE`, the weak-`Custom`
/// clamp, durable nonces, upgrade quarantine, plugins) the server applies,
/// shared so `graphite verify`/`explain` answer with the same gate.
pub use crate::operator_boundary as boundary;

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
    let resolved = match name.as_str() {
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
    };
    // A `--profile` here stands where the request body's profile stands at
    // the server, and goes through the same boundary (`effective_input`):
    // the pin and the weak-`Custom` clamp apply to it as they would there
    // (audit 2026-10-20, L11). This tool used to apply the operator's number
    // unclamped and warn that the server would not.
    resolved
}

/// The input as the server would judge it: `--profile` replaces the input's
/// own profile (as a request body's would), then the server's boundary rules
/// apply — `GRAPHITE_WALLET_PROFILE` pins it, a weak `Custom` is clamped
/// unless `GRAPHITE_ALLOW_PERMISSIVE_PROFILES` is on. Returns the disclosure
/// the server would attach to the verdict's summary, when there is one.
pub fn effective_input(
    mut input: VerificationInput,
    arg: &ProfileArg,
    policy: &boundary::OperatorPolicy,
) -> Result<(VerificationInput, Option<String>), String> {
    if let Some(p) = resolve_profile(arg)? {
        input.wallet_profile = p;
    }
    let (profile, note) = boundary::enforce_wallet_profile(
        input.wallet_profile,
        policy.pinned_profile,
        policy.allow_permissive_profiles,
    )?;
    if note.is_none() && profile.is_weaker_than_any_builtin() {
        // Only reachable under GRAPHITE_ALLOW_PERMISSIVE_PROFILES (or a weak
        // pin): the server would apply it too, and the transcript says so.
        let (bar, _) = profile.thresholds();
        eprintln!(
            "WARNING: the effective profile's min_confidence {bar} is below the weakest built-in \
             profile ({}); the confidence gate is effectively disabled, as it is at a server with \
             the same configuration.",
            crate::policy_engine::WEAKEST_BUILTIN_MIN_CONFIDENCE
        );
    }
    input.wallet_profile = profile;
    Ok((input, note))
}

pub enum CliCommand {
    Verify {
        input: Box<VerificationInput>,
        profile: ProfileArg,
    },
    /// Check the audit trail's hash chain, or export a checkpoint of its
    /// head (Round 30, G-07). Read-only: safe beside a running server.
    Audit {
        action: AuditAction,
    },
    #[cfg(feature = "server")]
    Server {
        port: u16,
        host: String,
    },
    #[cfg(feature = "server")]
    Healthcheck {
        port: u16,
        /// The address to probe: an IP literal or `localhost` (audit
        /// 2026-10-20, L14: the probe was hard-coded to 127.0.0.1, so a server
        /// bound only to `::1` or to one interface could not be checked).
        host: String,
        /// Also fail when the node reports `degraded: true` (A6-13).
        strict: bool,
    },
    Manifests,
    /// List wallet policy profiles and their thresholds.
    Profiles,
    /// The hand-built benchmark, or with `json` the release evaluation over
    /// every committed labelled input (`release_eval`).
    Benchmark {
        json: bool,
        /// The `graphite-core` directory holding the committed inputs.
        root: Option<PathBuf>,
    },
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
    /// L8 — confirm a submitted transaction on-chain and reconcile it against
    /// the verdict Graphite recorded for it.
    ///
    /// Requires an RPC endpoint (`GRAPHITE_RPC_URL`). Exits non-zero whenever
    /// the answer is not a clean reconciliation — 1 on a discrepancy, and a
    /// distinct code for each way the check itself could not be trusted (see
    /// [`execution_exit_code`]) — so it can be used as a monitoring check.
    #[cfg(feature = "rpc")]
    Execution {
        data_dir: Option<PathBuf>,
        signature: String,
        content_hash: Option<String>,
        transaction_sha256: Option<String>,
        audit_trail_id: Option<String>,
        rpc_url: Option<String>,
        witness_url: Option<String>,
    },
    /// Seed operator-asserted evidence or a simulation baseline into the
    /// durable semantic graph.
    ///
    /// Bootstrapping and state restore. A fresh deployment has an empty graph,
    /// and the three evidence-derived confidence signals — simulation matches,
    /// historical volume, community verification — are half the available
    /// weight, so nothing can clear any profile's threshold until the graph has
    /// something in it. Evidence is normally EARNED (RPC-verified simulation,
    /// observed volume, reviewer attestations); this is the operator path for
    /// restoring an export or standing an instance up before that history
    /// exists.
    Evidence {
        action: EvidenceAction,
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
    /// Check every acceptance record from its own contents (Round 36, F-008;
    /// Round 38, V-5: `verify_offline` had no caller outside a unit test).
    /// Exit 0 when every record verifies, 1 when one does not, 2 when none
    /// fails and one predates retained signatures and cannot be checked.
    VerifyRecords { state: Option<PathBuf> },
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
    /// Revoke a reviewer (audit 2026-10-20, MR-6): the key no longer signs or
    /// attests, and the graph tiers its attestations helped earn are
    /// recomputed without it. Permanent.
    RevokeReviewer {
        state: Option<PathBuf>,
        graph_state: Option<PathBuf>,
        pubkey: String,
    },
    /// Retire one fixture of the registry's own regression corpus (audit
    /// 2026-10-20, MR-1): a submission cannot drop a fixture the registry
    /// holds, so an outdated one is retired here, by the operator.
    DeprecateFixture {
        state: Option<PathBuf>,
        content_hash: String,
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

/// Operator evidence-seeding action (dispatched by `CliCommand::Evidence`).
///
/// CLI-only by design. Nothing on the HTTP surface may write here: caller
/// evidence is request-body JSON, and honouring it would let anyone mint an
/// earned-looking tier for a program with no on-chain reputation (G4). Reaching
/// this requires the same access as editing the deployment's configuration.
///
/// P7 is preserved because what is seeded is EVIDENCE, not a tier: `append`
/// recomputes the tier from that evidence exactly as it does for an earned
/// record, so an operator cannot name a tier directly.
pub enum EvidenceAction {
    /// Seed behaviour evidence for a program (tier is recomputed, never set).
    Seed {
        data_dir: Option<PathBuf>,
        program_id: String,
        signed_manifest: bool,
        community_verified: u32,
        battle_tested: u64,
        simulation_matches: u64,
    },
    /// Seed a simulation baseline so L3 can judge divergence.
    Baseline {
        data_dir: Option<PathBuf>,
        program_id: String,
        mean_compute_units: f64,
        std_compute_units: f64,
        samples: u64,
        mean_account_writes: f64,
        mean_cpi_hops: f64,
    },
    /// Round 40 (bootstrap): seed each program's HistoricalVolume from the
    /// committed, measured mainnet census (`protocols/battle_tested_evidence.json`)
    /// instead of typed numbers. See `census_import`.
    ImportCensus {
        data_dir: Option<PathBuf>,
        /// A census file to check against the compiled-in copy (default: the
        /// compiled-in copy itself).
        census: Option<PathBuf>,
        /// Restrict the import to these programs (default: every record).
        programs: Vec<String>,
        /// Print what would be imported, and the resulting tier and
        /// confidence per program, without writing anything.
        dry_run: bool,
        /// The cluster this Core verifies (`--cluster`): required, and only
        /// `mainnet-beta` is accepted — the census measures mainnet-beta.
        cluster: Option<String>,
    },
    /// Show what the graph currently holds for a program.
    Show {
        data_dir: Option<PathBuf>,
        program_id: String,
    },
    /// Replace a frozen trusted baseline with the clean executions it refused
    /// (the shadow accumulator), Round 17 F-16-02.
    PromoteShadow {
        data_dir: Option<PathBuf>,
        program_id: String,
    },
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

/// Audit-trail integrity action (dispatched by `CliCommand::Audit`).
pub enum AuditAction {
    /// Walk every archive and the active file against the hash chain and
    /// the MACs, and against `checkpoint` when one is given. Exits 0 when
    /// nothing failed, 1 on a break or a checkpoint that does not hold, 2
    /// when the walk could not prove what it was asked to (MACs under a key
    /// not supplied that a checked key-adoption record covers, a trail with
    /// no chained record, a checkpoint whose records were pruned), 3 when
    /// the trail, a key file or the checkpoint could not be read, 4 when
    /// keys were supplied and something is not covered by them (unkeyed
    /// records no key-adoption record covers, MACs under keys not supplied
    /// that nothing covers, a checkpoint with no MAC or under a key not
    /// supplied), 64 on a usage error. docs/ops/keys.md has the table.
    Verify {
        data_dir: Option<PathBuf>,
        /// Key files whose MACs to check; `GRAPHITE_AUDIT_KEY_FILE` is
        /// added when set. Old keys after a rotation go here too.
        key_files: Vec<PathBuf>,
        checkpoint: Option<PathBuf>,
        json: bool,
    },
    /// Verify the trail, then print (or write to `out`, never over an
    /// existing file) a checkpoint of its head — MAC'd under the key the
    /// head is under — for the operator to keep where the writer cannot
    /// alter it. Refused (with `verify`'s exit code) unless the keys given
    /// cover the head (Round 38, T-13): `verify` exits 0 under them, or 2
    /// only for a lost key a checked key-adoption record closes.
    Checkpoint {
        data_dir: Option<PathBuf>,
        key_file: Option<PathBuf>,
        out: Option<PathBuf>,
    },
    /// Write a key-adoption record under `key_file` (Round 34), with the
    /// server stopped: the operator's explicit decision to continue the
    /// trail under a key when its head cannot be checked under it — a trail
    /// that was never keyed, one keyed before key-adoption records existed,
    /// or one whose previous key is lost (`previous_key_file` checks the
    /// head under the previous key instead). Walks the trail first and
    /// refuses a broken one.
    AdoptKey {
        data_dir: Option<PathBuf>,
        key_file: PathBuf,
        previous_key_file: Option<PathBuf>,
    },
    /// Acknowledge a torn write (Round 34), with the server stopped: a line
    /// that is not JSON, at byte `offset` of the trail file named `file`,
    /// that no record names — a crash a pre-Round-34 writer resumed past.
    /// Walks the trail first; refuses a trail broken by anything but
    /// unacknowledged tears, and any line that is not one of them (a JSON
    /// line is never a tear). Appends a chained record naming the tear —
    /// MAC'd under `key_file` (else `GRAPHITE_AUDIT_KEY_FILE`) when the
    /// trail is keyed — after which the walk tolerates exactly that line.
    AcknowledgeTear {
        data_dir: Option<PathBuf>,
        file: String,
        offset: u64,
        key_file: Option<PathBuf>,
    },
    /// Record a prune that nothing recorded (Round 38, R37-14), with the
    /// server stopped: a trail pruned before prune records existed starts
    /// above seq 0 and `verify` reports that as a break. Once the operator
    /// has checked the trail against an anchored checkpoint or a backup,
    /// this appends a prune record naming where the trail starts now —
    /// MAC'd under the key the head is under (`key_file`, else
    /// `GRAPHITE_AUDIT_KEY_FILE`). Refuses a trail broken by anything else.
    AcknowledgePrune {
        data_dir: Option<PathBuf>,
        key_file: Option<PathBuf>,
    },
}

/// The keys `audit` commands check with: each named file, plus
/// `GRAPHITE_AUDIT_KEY_FILE` when it is set and not already named.
fn audit_keys(files: &[PathBuf], dir: &Path) -> Result<Vec<crate::durable::AuditKey>, String> {
    let mut paths: Vec<PathBuf> = files.to_vec();
    if let Some(env) = std::env::var(crate::durable::AUDIT_KEY_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
    {
        let env = PathBuf::from(env.trim());
        if !paths.contains(&env) {
            paths.push(env);
        }
    }
    paths
        .iter()
        .map(|p| crate::durable::AuditKey::load(p, Some(dir)))
        .collect()
}

fn run_audit(action: AuditAction) -> Result<i32, Box<dyn std::error::Error>> {
    match action {
        AuditAction::Verify {
            data_dir,
            key_files,
            checkpoint,
            json,
        } => {
            let dir = data_dir_path(data_dir);
            // Round 38 (T-14): an input that cannot be read is exit 3 (the
            // check could not be made), never 1, which a monitor reads as a
            // break.
            let keys = match audit_keys(&key_files, &dir) {
                Ok(k) => k,
                Err(e) => return Ok(unreadable(&e)),
            };
            let checkpoint = match checkpoint {
                Some(p) => match read_checkpoint(&p) {
                    Ok(cp) => Some(cp),
                    Err(e) => return Ok(unreadable(&e)),
                },
                None => None,
            };
            // Round 39 (R39-CB-6): a data directory with no trail in it (a
            // mistyped --data-dir, an unmounted volume) walked zero files and
            // exited 2, "a trail with no chained record". Nothing was read:
            // that is 3.
            let trail = crate::durable::audit_path(&dir);
            let stem = crate::durable::AUDIT_FILENAME;
            let any_file = std::fs::read_dir(&dir).is_ok_and(|mut entries| {
                entries.any(|e| {
                    e.ok().is_some_and(|e| {
                        let name = e.file_name();
                        let name = name.to_string_lossy();
                        name == stem || name.starts_with(&format!("{stem}."))
                    })
                })
            });
            if !any_file {
                return Ok(unreadable(&format!(
                    "no audit trail in {} ({} does not exist, and no archive of it): nothing was verified",
                    dir.display(),
                    trail.display()
                )));
            }
            let report = match crate::durable::verify_audit_trail(
                &crate::durable::audit_path(&dir),
                &keys,
                checkpoint.as_ref(),
            ) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("audit trail {} could not be read: {e}", dir.display());
                    return Ok(3);
                }
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("integrity        {:?}", report.integrity);
                println!("files            {}", report.files.len());
                println!(
                    "records          {} chained, {} legacy (unchained; {} listed by a checked key-adoption record)",
                    report.chained_records, report.legacy_unchained_records, report.legacy_adopted
                );
                if let Some(id) = &report.trail_id {
                    println!("trail id         {id}");
                }
                println!(
                    "MACs             {} verified, {} under a key not supplied, {} records unkeyed ({} covered by a key-adoption record)",
                    report.macs_verified,
                    report.macs_unverified,
                    report.unkeyed_records,
                    report.unkeyed_adopted
                );
                // Every key, with the records it covers (Round 34): a key id
                // the operator never held is an incident, not a missing file.
                for r in &report.key_ranges {
                    println!(
                        "key              {}  seq {}-{} ({} records)  {}  [{}]",
                        r.key_id,
                        r.first_seq,
                        r.last_seq,
                        r.records,
                        if r.supplied {
                            "supplied, MACs checked"
                        } else {
                            "NOT SUPPLIED, MACs not checked"
                        },
                        r.introduced_by
                    );
                }
                for t in &report.unacknowledged_tears {
                    println!(
                        "TEAR             {} line {} (byte {}, {} bytes): not JSON, and no record names it — a crash a pre-Round-34 writer resumed past, or bytes someone added. Inspect it; `graphite audit acknowledge-tear --file {} --offset {}` accepts it",
                        t.file, t.line, t.offset, t.length, t.file, t.offset
                    );
                }
                if report.keys_supplied && report.unkeyed_not_adopted() > 0 {
                    println!(
                        "UNKEYED          {} chained record(s) carry no MAC and no key-adoption record covers them: a trail keyed later, or one rewritten with its MACs stripped (docs/ops/keys.md, `graphite audit adopt-key`)",
                        report.unkeyed_not_adopted()
                    );
                }
                if report.keys_supplied && report.legacy_not_adopted() > 0 {
                    println!(
                        "LEGACY           {} record(s) without a chain link that no checked key-adoption record lists: not covered by the key, and not read by a server that holds it{} (docs/ops/keys.md, `graphite audit adopt-key`)",
                        report.legacy_not_adopted(),
                        if report.legacy_before_keyed_genesis {
                            "; before a chain keyed from seq 0 they are a break — inserted, unless you know where they came from"
                        } else {
                            ""
                        }
                    );
                }
                if report.unparseable_lines > 0 {
                    println!(
                        "unparseable      {} line(s): torn writes the writer named when it resumed, or the active file's unterminated last line — never read; any other line that is not a record is a break",
                        report.unparseable_lines
                    );
                }
                if let (Some(seq), Some(hash)) = (report.head_seq, &report.head_hash) {
                    println!("head             seq {seq} hash {hash}");
                }
                if let Some(first) = report.first_seq.filter(|s| *s > 0) {
                    if report.pruned_without_record {
                        println!(
                            "first on disk    seq {first}: NO prune record names it — the records before it were deleted, or pruned by a writer before Round 38. Check the trail against an anchored checkpoint or a backup; `graphite audit acknowledge-prune` records the prune"
                        );
                    } else {
                        println!(
                            "first on disk    seq {first} (older records pruned; a prune record names this start)"
                        );
                    }
                }
                if report.keys_supplied && report.macs_not_covered > 0 {
                    println!(
                        "NOT COVERED      {} MAC(s) under a key not supplied that no checked key-adoption record after them covers: the keys given do not reach them (a trail under another key, or its newest key not given)",
                        report.macs_not_covered
                    );
                }
                if let Some(b) = &report.first_break {
                    println!(
                        "BREAK            {} line {} (byte {}){}: {}",
                        b.file,
                        b.line,
                        b.offset,
                        b.seq.map(|s| format!(", seq {s}")).unwrap_or_default(),
                        b.reason
                    );
                }
                if let Some(cp) = &report.checkpoint {
                    println!("checkpoint       {cp:?}");
                }
            }
            Ok(report.exit_code())
        }
        AuditAction::Checkpoint {
            data_dir,
            key_file,
            out,
        } => {
            let dir = data_dir_path(data_dir);
            let keys = match audit_keys(key_file.as_slice(), &dir) {
                Ok(k) => k,
                Err(e) => return Ok(unreadable(&e)),
            };
            let path = crate::durable::audit_path(&dir);
            let report = match crate::durable::verify_audit_trail(&path, &keys, None) {
                Ok(r) => r,
                Err(e) => {
                    return Ok(unreadable(&format!(
                        "audit trail {} could not be read: {e}",
                        dir.display()
                    )))
                }
            };
            if let Some(b) = &report.first_break {
                eprintln!(
                    "the trail is broken at {} line {}: {} — no checkpoint of a broken trail",
                    b.file, b.line, b.reason
                );
                return Ok(1);
            }
            let (Some(seq), Some(hash)) = (report.head_seq, report.head_hash.clone()) else {
                eprintln!("the trail holds no chained record yet; nothing to checkpoint");
                return Ok(2);
            };
            // Round 38 (T-13): a checkpoint vouches for the head and, through
            // the hash chain, for everything before it. It is signed only when
            // the keys given cover that — `audit verify` exits 0 under them,
            // or 2 only for MACs under keys a checked key-adoption record
            // closes (a lost key) — and under the key the head is MAC'd
            // under. It used to sign whatever head the walk ended at, under
            // the first key given: a head under a key not given (its MAC never
            // checked), or, with no key, an unsigned checkpoint of a keyed
            // trail.
            if !report.head_covered() {
                let code = report.exit_code();
                eprintln!(
                    "the keys given do not cover the trail's head (`graphite audit verify` exits {code} with them): no checkpoint of a head they do not cover. Give the key the server writes under ({})",
                    report.head_key_id.as_deref().unwrap_or("the trail is unkeyed")
                );
                return Ok(code);
            }
            let signer = match &report.head_key_id {
                Some(id) => match keys.iter().find(|k| k.id() == id) {
                    Some(k) => Some(k),
                    None => {
                        eprintln!("the trail's head is under key {id}, which is not a key given: no checkpoint");
                        return Ok(4);
                    }
                },
                None if keys.is_empty() => None,
                None => {
                    eprintln!("the trail's head carries no MAC and a key is given: no checkpoint");
                    return Ok(4);
                }
            };
            let log = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let cp =
                crate::durable::Checkpoint::new(&log, seq, &hash, report.chained_records, signer);
            let text = serde_json::to_string_pretty(&cp)?;
            match out {
                Some(out) => {
                    use std::io::Write;
                    let written = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&out)
                        .and_then(|mut f| {
                            f.write_all(text.as_bytes())?;
                            f.write_all(b"\n")?;
                            f.sync_all()
                        });
                    if let Err(e) = written {
                        return Ok(unreadable(&format!(
                            "checkpoint {} could not be written: {e}",
                            out.display()
                        )));
                    }
                    eprintln!(
                        "checkpoint seq {seq} written to {} — keep it where the server cannot alter it (WORM, object lock, another system)",
                        out.display()
                    );
                }
                None => println!("{text}"),
            }
            Ok(0)
        }
        AuditAction::AdoptKey {
            data_dir,
            key_file,
            previous_key_file,
        } => {
            let dir = data_dir_path(data_dir);
            let key = match crate::durable::AuditKey::load(&key_file, Some(&dir)) {
                Ok(k) => k,
                Err(e) => return Ok(unreadable(&e)),
            };
            let previous = match previous_key_file
                .map(|p| crate::durable::AuditKey::load(&p, Some(&dir)))
                .transpose()
            {
                Ok(p) => p,
                Err(e) => return Ok(unreadable(&e)),
            };
            let path = crate::durable::audit_path(&dir);
            let mut keys = vec![key.clone()];
            keys.extend(previous.iter().cloned());
            let report = match crate::durable::verify_audit_trail(&path, &keys, None) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("audit trail {} could not be read: {e}", dir.display());
                    return Ok(3);
                }
            };
            // Round 38 (R37-2): legacy records before a chain keyed from
            // seq 0 are a break only because nothing lists them; the
            // operator who has checked them lists them here. Any other
            // break refuses.
            let only_legacy = report.legacy_before_keyed_genesis && report.other_break.is_none();
            if let Some(b) = report.first_break.as_ref().filter(|_| !only_legacy) {
                eprintln!(
                    "the trail is broken at {} line {}: {} — a key adoption would vouch for it; nothing written",
                    b.file, b.line, b.reason
                );
                return Ok(1);
            }
            if report.chained_records == 0 && report.legacy_unchained_records == 0 {
                println!(
                    "nothing to adopt: the trail holds no record, and a server with key {} starts its chain under it",
                    key.id()
                );
                return Ok(0);
            }
            if report.head_key_id.as_deref() == Some(key.id())
                && report.unkeyed_not_adopted() == 0
                && report.legacy_not_adopted() == 0
            {
                println!(
                    "nothing to adopt: the trail is under key {} and no unkeyed or legacy record is uncovered",
                    key.id()
                );
                return Ok(0);
            }
            let options = crate::durable::AuditOptions {
                rotate_bytes: 0,
                key: Some(key.clone()),
                previous_key: previous,
                adopt_key: true,
                ..Default::default()
            };
            let log = match crate::durable::AuditLog::open_with_options(&path, options) {
                Ok(log) => log,
                Err(e) => {
                    return Ok(writer_refused(
                        &e,
                        &format!(
                            "the audit trail {} cannot be opened to write the adoption ({e}); stop the server first",
                            path.display()
                        ),
                    ))
                }
            };
            let head = log.health().chain_head_seq;
            drop(log);
            println!(
                "key {} adopted at seq {}: the {} unkeyed record(s) and {} legacy record(s) before it{} are now covered by its MAC. Run `graphite audit verify --key-file {}`",
                key.id(),
                head.map(|s| s.to_string()).unwrap_or_else(|| "?".into()),
                report.unkeyed_not_adopted(),
                report.legacy_not_adopted(),
                match &report.head_key_id {
                    Some(id) if id != key.id() => format!(", and the switch from key {id},"),
                    _ => String::new(),
                },
                key_file.display()
            );
            Ok(0)
        }
        AuditAction::AcknowledgeTear {
            data_dir,
            file,
            offset,
            key_file,
        } => {
            let dir = data_dir_path(data_dir);
            let keys = match audit_keys(key_file.as_slice(), &dir) {
                Ok(k) => k,
                Err(e) => return Ok(unreadable(&e)),
            };
            let path = crate::durable::audit_path(&dir);
            let report = match crate::durable::verify_audit_trail(&path, &keys, None) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("audit trail {} could not be read: {e}", dir.display());
                    return Ok(3);
                }
            };
            if let Some(b) = report
                .other_break
                .as_ref()
                .or(report.first_break.as_ref().filter(|_| {
                    report.unacknowledged_tears.is_empty() || report.legacy_before_keyed_genesis
                }))
            {
                eprintln!(
                    "the trail is broken at {} line {} by more than a torn write: {} — nothing written",
                    b.file, b.line, b.reason
                );
                return Ok(1);
            }
            let Some(tear) = report
                .unacknowledged_tears
                .iter()
                .find(|t| t.file == file && t.offset == offset)
            else {
                eprintln!(
                    "no unacknowledged torn write at byte {offset} of {file}: only a line that is not JSON and that no record names can be acknowledged{}",
                    if report.unacknowledged_tears.is_empty() {
                        String::new()
                    } else {
                        format!(
                            " (unacknowledged: {})",
                            report
                                .unacknowledged_tears
                                .iter()
                                .map(|t| format!("{} byte {}", t.file, t.offset))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    }
                );
                return Ok(1);
            };
            let options = crate::durable::AuditOptions {
                rotate_bytes: 0,
                key: keys.first().cloned(),
                ..Default::default()
            }
            .with_previous_key_value(
                std::env::var(crate::durable::AUDIT_PREVIOUS_KEY_ENV)
                    .ok()
                    .as_deref(),
                &dir,
            )?;
            let log = match crate::durable::AuditLog::open_with_options(&path, options) {
                Ok(log) => log,
                Err(e) => {
                    return Ok(writer_refused(
                        &e,
                        &format!(
                            "the audit trail {} cannot be opened to write the acknowledgement ({e}); stop the server first",
                            path.display()
                        ),
                    ))
                }
            };
            log.acknowledge_tear(tear)?;
            drop(log);
            println!(
                "acknowledged the torn write at byte {} of {} ({} bytes, sha256 {}); run `graphite audit verify`",
                tear.offset, tear.file, tear.length, tear.sha256
            );
            Ok(0)
        }
        AuditAction::AcknowledgePrune { data_dir, key_file } => {
            let dir = data_dir_path(data_dir);
            let keys = match audit_keys(key_file.as_slice(), &dir) {
                Ok(k) => k,
                Err(e) => return Ok(unreadable(&e)),
            };
            let path = crate::durable::audit_path(&dir);
            let report = match crate::durable::verify_audit_trail(&path, &keys, None) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("audit trail {} could not be read: {e}", dir.display());
                    return Ok(3);
                }
            };
            if !report.pruned_without_record {
                eprintln!(
                    "nothing to acknowledge: {}",
                    match report.first_seq {
                        Some(s) if s > 0 =>
                            format!("a prune record already names the trail's start (seq {s})"),
                        _ => "the trail starts at seq 0".to_string(),
                    }
                );
                return Ok(1);
            }
            if let Some(b) = &report.other_break {
                eprintln!(
                    "the trail is broken at {} line {} by more than a missing prune record: {} — nothing written",
                    b.file, b.line, b.reason
                );
                return Ok(1);
            }
            // Written under the key the trail's head is under.
            let key = match &report.head_key_id {
                Some(id) => match keys.iter().find(|k| k.id() == id) {
                    Some(k) => Some(k.clone()),
                    None => {
                        eprintln!("the trail's head is under key {id}, which is not a key given: nothing written");
                        return Ok(4);
                    }
                },
                None => None,
            };
            let options = crate::durable::AuditOptions {
                rotate_bytes: 0,
                key,
                ..Default::default()
            };
            let log = match crate::durable::AuditLog::open_with_options(&path, options) {
                Ok(log) => log,
                Err(e) => {
                    return Ok(writer_refused(
                        &e,
                        &format!(
                            "the audit trail {} cannot be opened to write the prune record ({e}); stop the server first",
                            path.display()
                        ),
                    ))
                }
            };
            let (seq, prev) = log.acknowledge_prune()?;
            drop(log);
            println!(
                "acknowledged the prune: the trail starts at seq {seq} (after the record with hash {prev}); run `graphite audit verify`"
            );
            Ok(0)
        }
    }
}

/// Report an input `audit` could not read — a key file, a checkpoint, the
/// trail — or an output it could not write: exit 3 (Round 38, T-14). It was
/// an error out of `main`, exit 1, which reads as a break.
fn unreadable(why: &str) -> i32 {
    eprintln!("{why}");
    3
}

/// Report a writer the trail refused to open: exit 75 when another writer
/// holds it (the server is running; `restore.sh` and `backup.sh` use 75 for
/// that too), 1 otherwise (the trail refused it: a break, or a head the
/// writer cannot continue).
fn writer_refused(e: &std::io::Error, why: &str) -> i32 {
    eprintln!("{why}");
    if e.kind() == std::io::ErrorKind::WouldBlock {
        75
    } else {
        1
    }
}

/// A checkpoint file, read up to 64 KiB (Round 38, T-15: a checkpoint is a
/// few hundred bytes; anything longer is not one).
fn read_checkpoint(path: &Path) -> Result<crate::durable::Checkpoint, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(64 * 1024 + 1).read_to_end(&mut bytes))
        .map_err(|e| format!("checkpoint {}: {e}", path.display()))?;
    if bytes.len() > 64 * 1024 {
        return Err(format!(
            "checkpoint {}: longer than 64 KiB, not a checkpoint",
            path.display()
        ));
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("checkpoint {}: {e}", path.display()))
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

/// Where `graphite benchmark --json` finds the committed inputs when no
/// `--root` is given: the current directory if it is `graphite-core`, its
/// `graphite-core` child if it is the repository root.
fn release_eval_root() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    [cwd.clone(), cwd.join("graphite-core")]
        .into_iter()
        .find(|dir| dir.join(crate::release_eval::CORPUS_DIR).is_dir())
}

pub fn run(command: CliCommand) -> Result<(), Box<dyn std::error::Error>> {
    // Round 38 (Round 37, V-2): the CLI reads the same variables the server
    // does (`GRAPHITE_DATA_DIR`, `GRAPHITE_AUDIT_KEY_FILE`, the L4 opt-outs),
    // and a misspelled one is a decision it never sees either.
    let env_names: Vec<String> = std::env::vars_os()
        .filter_map(|(k, _)| k.into_string().ok())
        .collect();
    crate::operator_boundary::check_env_names(env_names.iter().map(String::as_str))?;
    match command {
        CliCommand::Verify { input, profile } => {
            // The SERVER'S durable semantic graph, registry and boundary
            // policy, not a blank core: `graphite verify` is how an operator
            // asks "what would the gate decide about this?". See
            // `operator_core` and `effective_input`.
            let (core, policy) = operator_core()?;
            let (input, note) = effective_input(*input, &profile, &policy)?;
            let mut result = core.verify(&input)?;
            if let Some(note) = note {
                // Disclosed where the verdict is read, as the server discloses
                // it in the response's summary.
                eprintln!("policy: {note}");
                result.summary = format!("{} | policy: {}", result.summary, note);
            }
            println!("{}", serde_json::to_string_pretty(&result)?);
            // SECURITY FIX: Exit 1 on REJECT so CLI can be used as CI gate.
            // Round 30 (G-01): and 3 on an approval that does not permit
            // signing (`analysis_only`) — this command attaches no RPC, so
            // nothing it verifies is simulated, and a shell gate written as
            // `graphite verify x && sign` must not read exit 0 as permission.
            std::process::exit(verify_exit_code(&result));
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
        CliCommand::Benchmark { json: false, .. } => {
            crate::benchmark::run_benchmark();
            Ok(())
        }
        CliCommand::Benchmark { json: true, root } => {
            let root = match root {
                Some(root) => root,
                None => release_eval_root().ok_or(
                    "cannot find the committed inputs (fixtures/corpus): run from graphite-core or the repository root, or pass --root",
                )?,
            };
            let report = crate::release_eval::evaluate(&root)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
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
                    "  registered: {} | skipped pending: {} | skipped rejected: {} | already registered (not run again): {}",
                    summary.registered,
                    summary.skipped_pending,
                    summary.skipped_rejected,
                    summary.already_registered
                );
                for p in core.plugins().registered_plugins() {
                    println!("  ✓ {}", p);
                }
            }
            Ok(())
        }
        CliCommand::Registry { action } => run_registry(action),
        CliCommand::Quarantine { action } => run_quarantine(action),
        CliCommand::Audit { action } => {
            let code = run_audit(action)?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        CliCommand::Explain { input, profile } => run_explain(*input, &profile),
        CliCommand::Protocol { action } => run_protocol(action),
        CliCommand::Evidence { action } => run_evidence(action),
        #[cfg(feature = "rpc")]
        CliCommand::Execution {
            data_dir,
            signature,
            content_hash,
            transaction_sha256,
            audit_trail_id,
            rpc_url,
            witness_url,
        } => {
            // Every outcome has its own exit status (see
            // `execution_exit_code`); a check that could not run at all —
            // no endpoint, an unusable one, an unreadable data directory —
            // is "unavailable", never the discrepancy's 1.
            match run_execution(
                data_dir,
                &signature,
                crate::verification::ExecutionKeys {
                    content_hash: content_hash.as_deref(),
                    transaction_sha256: transaction_sha256.as_deref(),
                    audit_trail_id: audit_trail_id.as_deref(),
                },
                rpc_url,
                witness_url,
            ) {
                Ok(0) => Ok(()),
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(EXIT_EXECUTION_UNAVAILABLE);
                }
            }
        }
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
            // Authenticated by default. A missing GRAPHITE_API_KEY is a
            // startup error unless GRAPHITE_DEV_MODE=1 is set, and even then
            // the instance may only bind loopback. Decided here, before the
            // runtime exists, so the message is the first and only line of
            // output; `run_server` decides it again for embedders that never
            // pass through this command.
            crate::server::auth_posture(
                addr,
                std::env::var("GRAPHITE_API_KEY").ok().as_deref(),
                crate::server::dev_mode_from_env(),
            )?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(crate::server::run_server(addr))?;
            Ok(())
        }
        #[cfg(feature = "server")]
        CliCommand::Healthcheck { port, host, strict } => {
            let url = health_url(&host, port)?;
            let rt = tokio::runtime::Runtime::new()?;
            let verdict = rt.block_on(async move {
                // Round 39 (R39-CB-3): no redirect and no proxy. The probe
                // followed up to ten redirects, to any host, and went through
                // HTTP_PROXY / ALL_PROXY from the environment: a 302 from
                // whatever answers on the port, to anything that answers
                // `{"degraded":false}`, passed the strict check. /health never
                // redirects, and the probe is for the process on this host.
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(4))
                    .redirect(reqwest::redirect::Policy::none())
                    .no_proxy()
                    .build()
                    .map_err(|_| "health check failed: no HTTP client".to_string())?;
                let res = client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|_| "health check failed: /health did not answer".to_string())?;
                let success = res.status().is_success();
                let body = res.json::<serde_json::Value>().await.ok();
                health_verdict(success, body.as_ref(), strict)
            });
            // Non-zero exit is what Docker's HEALTHCHECK reads.
            verdict.map_err(Into::into)
        }
    }
}

/// The URL `graphite healthcheck` probes (audit 2026-10-20, L14).
///
/// `host` takes what `graphite server --host` takes, an IP literal, plus
/// `localhost`. An IPv6 address is bracketed. The unspecified address
/// (`0.0.0.0`, `::`), which a server binds to listen everywhere, is probed on
/// the loopback address of the same family: it is not an address a client
/// can connect to on every platform.
#[cfg(feature = "server")]
pub fn health_url(host: &str, port: u16) -> Result<String, String> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    let host = host.trim();
    let ip: IpAddr = if host.eq_ignore_ascii_case("localhost") {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .map_err(|_| {
                format!(
                    "invalid --host {host:?}: expected an IP address (e.g. 127.0.0.1 or ::1) or localhost"
                )
            })?
    };
    let ip = match ip {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    };
    Ok(format!("http://{}/health", SocketAddr::new(ip, port)))
}

/// Whether a `/health` answer passes the healthcheck.
///
/// `/health` answers 200 with `"degraded": true` when the node still serves
/// but, for example, its audit writes are failing, so that a load balancer
/// keeps a node that can still refuse. A verdict that cannot be recorded is
/// refused with 503, so nothing is approved off the trail. The default check
/// therefore passes on any 2xx, and Docker never saw a degraded trail (A6-13,
/// 2026-09-29 audit). `--strict` also requires `degraded` to be present and
/// false, for orchestrators that should replace such a node. A body that is
/// not the expected JSON fails the strict check rather than passing it.
#[cfg(feature = "server")]
fn health_verdict(
    success: bool,
    body: Option<&serde_json::Value>,
    strict: bool,
) -> Result<(), String> {
    if !success {
        return Err("health check failed: /health did not answer 2xx".to_string());
    }
    if !strict {
        return Ok(());
    }
    match body
        .and_then(|b| b.get("degraded"))
        .and_then(|d| d.as_bool())
    {
        Some(false) => Ok(()),
        Some(true) => {
            let reasons = body
                .and_then(|b| b.get("degraded_reasons"))
                .map(|r| r.to_string())
                .unwrap_or_default();
            Err(format!(
                "health check failed (strict): the node is degraded {reasons}"
            ))
        }
        None => Err("health check failed (strict): /health carried no `degraded` flag".to_string()),
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

/// Written to a temporary file and renamed into place (W12, external review):
/// a plain write torn by a crash left a registry that does not parse, which
/// the server reads as empty.
fn save_registry(
    engine: &crate::manifest_registry::ManifestRegistryEngine,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::verification::persist_json_atomic(path, &engine.to_json()?)?;
    Ok(())
}

/// Held for a registry command's read-modify-write (W12, external review):
/// two submits at once each read the log, each appended, and the second
/// write dropped the first's record — possibly a correction, putting the
/// older version back in force.
fn lock_registry(state_path: &Path) -> Result<std::fs::File, Box<dyn std::error::Error>> {
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(state_path.with_extension("lock"))?;
    lock.lock()?;
    Ok(lock)
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
    crate::verification::persist_json_atomic(path, &store.to_json()?)?;
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

/// Build the core the server would verify with, so the CLI's answer is the
/// server's. Shared by `verify` and `explain`, so an explanation cannot
/// disagree with a verdict.
///
/// The server's durable semantic graph, not a blank one: a core with no
/// earned trust, no simulation baselines and no quarantines answers a
/// different question — most visibly, a program the operator has withdrawn
/// from trust would still verify as OfficialManifest here while the server
/// blocked it. A missing directory is the normal first-run case and starts a
/// fresh store. Read-only (Round 19, F-19-12): this inspects the server's
/// store and may run beside it, so it takes no lock and writes nothing back.
///
/// C53: the community-accepted manifests from the registry state (same
/// contract as the server: `registry_state.json` or
/// `GRAPHITE_REGISTRY_STATE`). A corrupt or unreadable registry file is an
/// error, as it is for the server, which refuses to start on one (audit
/// 2026-10-20); a missing one is the first-run case.
///
/// The operator's boundary policy (L11, audit 2026-10-20): see
/// [`boundary`]. A setting that does not parse is an error here as it is a
/// startup error there.
fn operator_core() -> Result<(GraphiteCore, boundary::OperatorPolicy), String> {
    let policy = boundary::OperatorPolicy::from_env()?;
    let data_dir = data_dir_path(None);
    let mut core = GraphiteCore::open_data_dir_read_only(&data_dir)?;
    let quarantined = core.quarantined_programs().len();
    if quarantined > 0 {
        eprintln!(
            "graph: {} ({quarantined} quarantined program(s))",
            data_dir.display()
        );
    }
    let registry_path = registry_state_path(None);
    let engine = load_registry(&registry_path).map_err(|e| {
        format!(
            "registry state {} is unreadable: {e} — the server refuses to start on it, so there is no decision to reproduce",
            registry_path.display()
        )
    })?;
    let merged = core.merge_community_manifests(&engine);
    if merged > 0 {
        eprintln!(
            "merged {merged} community-accepted manifest(s) from {}",
            registry_path.display()
        );
    }
    if let Some(summary) = policy.apply_to_core(&mut core)? {
        eprintln!(
            "plugins: {} registered from GRAPHITE_PLUGINS_DIR",
            summary.registered
        );
    }
    if let Some(p) = policy.pinned_profile {
        eprintln!("wallet profile PINNED by GRAPHITE_WALLET_PROFILE: {p:?}");
    }
    for (on, name) in [
        (
            policy.allow_unreadable_value_declarations,
            "GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS",
        ),
        (
            policy.allow_signer_lamports_outside_declared_debit,
            "GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT",
        ),
        (
            policy.allow_unbounded_withdrawals,
            "GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS",
        ),
    ] {
        if on {
            eprintln!("production default RELAXED by {name}=1 (as at the server)");
        }
    }
    Ok((core, policy))
}

fn tier_label(tier: TrustTier) -> String {
    format!("{tier:?}")
}

/// Render a verification result as prose rather than JSON.
fn run_explain(
    input: VerificationInput,
    profile: &ProfileArg,
) -> Result<(), Box<dyn std::error::Error>> {
    let (core, policy) = operator_core()?;
    let (input, note) = effective_input(input, profile, &policy)?;
    let mut result = core.verify(&input)?;
    if let Some(note) = &note {
        result.summary = format!("{} | policy: {}", result.summary, note);
    }
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
        "VERDICT  {}  (decision: {}{})",
        if result.approved {
            "APPROVED"
        } else {
            "BLOCKED"
        },
        result.decision.as_str(),
        if result.executable {
            ""
        } else {
            " — not permission to sign"
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
    if let Some(note) = &note {
        println!("  profile      {note}");
    }
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

    // Same convention as `verify`: usable as a shell gate.
    match verify_exit_code(&result) {
        0 => Ok(()),
        code => std::process::exit(code),
    }
}

/// The exit code of `graphite verify` and `graphite explain` (Round 30,
/// G-01): 0 only for `executable_approved`, 1 for a refusal (`blocked` or
/// `inconclusive`), 3 for an approval that is `analysis_only`. Exit 0 used
/// to mean "approved", and these commands attach no RPC, so it meant an
/// approval nothing had simulated.
pub fn verify_exit_code(result: &VerificationResult) -> i32 {
    use crate::verification::ExecutionDecision;
    match result.decision {
        ExecutionDecision::ExecutableApproved if result.is_executable() => 0,
        ExecutionDecision::Blocked | ExecutionDecision::Inconclusive => 1,
        _ if !result.approved => 1,
        _ => 3,
    }
}

fn run_protocol(action: ProtocolAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        ProtocolAction::Status {
            data_dir,
            program_id,
        } => {
            let dir = data_dir_path(data_dir);
            let mut core = GraphiteCore::open_data_dir_read_only(&dir)?;
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
                    println!(
                        "  trust tier     {:?}   (computed from the graph's evidence; battle-tested volume is operator-asserted)",
                        b.trust_tier
                    );
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
                    let mut core = GraphiteCore::open_data_dir_read_only(&dir)?;
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

/// The differences between two account lists, slot by slot. `prefix` names
/// which list (the main one, or an alternative layout).
fn slot_changes(
    prefix: &str,
    a: &[crate::manifest::AccountRoleDef],
    b: &[crate::manifest::AccountRoleDef],
) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    if a.len() != b.len() {
        lines.push(format!("{prefix}account count {} -> {}", a.len(), b.len()));
    }
    for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        if x.name != y.name || x.is_signer != y.is_signer || x.is_writable != y.is_writable {
            lines.push(format!(
                "{prefix}account #{i}: {} (signer {}, writable {}) -> {} (signer {}, writable {})",
                x.name, x.is_signer, x.is_writable, y.name, y.is_signer, y.is_writable
            ));
        }
        // Round 39 (R39-CB-12): everything else the runtime judges a slot
        // by. A dropped expected address or changed seed formula weakens a
        // verdict exactly as much as a privilege change does.
        let mut slot: Vec<String> = Vec::new();
        if x.role != y.role {
            slot.push(format!("role {:?} -> {:?}", x.role, y.role));
        }
        if x.pda_seeds != y.pda_seeds {
            slot.push(format!("pda seeds {:?} -> {:?}", x.pda_seeds, y.pda_seeds));
        }
        if x.expected_address != y.expected_address {
            slot.push(format!(
                "expected address {:?} -> {:?}",
                x.expected_address, y.expected_address
            ));
        }
        if x.optional != y.optional {
            slot.push(format!("optional {} -> {}", x.optional, y.optional));
        }
        if !slot.is_empty() {
            lines.push(format!(
                "{prefix}account #{i} {}: {}",
                y.name,
                slot.join("; ")
            ));
        }
    }
    lines
}

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
    lines.extend(slot_changes("", &a.accounts, &b.accounts));
    // Round 39 (R39-CB-12): an alternative layout is judged exactly like
    // the main one when the transaction's account count selects it.
    if a.account_layouts.len() != b.account_layouts.len() {
        lines.push(format!(
            "account layouts {} -> {} alternative(s), sizes {:?} -> {:?}",
            a.account_layouts.len(),
            b.account_layouts.len(),
            a.account_layouts.iter().map(Vec::len).collect::<Vec<_>>(),
            b.account_layouts.iter().map(Vec::len).collect::<Vec<_>>()
        ));
    }
    for (j, (x, y)) in a
        .account_layouts
        .iter()
        .zip(b.account_layouts.iter())
        .enumerate()
    {
        lines.extend(slot_changes(&format!("account layouts [{j}] "), x, y));
    }
    if a.risk_rules != b.risk_rules {
        lines.push(format!(
            "risk rules {:?} -> {:?}",
            a.risk_rules, b.risk_rules
        ));
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

/// Compare two manifests instruction by instruction.
///
/// Deliberately structural rather than textual: a reviewer needs to see that a
/// discriminator moved or an account became writable, not that a JSON key was
/// reordered. Ordering is by name so the output is stable (P2).
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

/// L8 in the operator's hands: did what Graphite decided actually govern what
/// happened on chain?
///
/// The reconciliation is the point. A chain-status lookup tells the caller
/// something they already know; comparing it against the append-only record
/// tells them whether the gate was obeyed. `BlockedButExecuted` is the outcome
/// worth waking someone for, and nothing inside a verification request can ever
/// detect it, because it happens outside one.
#[cfg(feature = "rpc")]
fn run_execution(
    data_dir: Option<PathBuf>,
    signature: &str,
    keys: crate::verification::ExecutionKeys<'_>,
    rpc_url: Option<String>,
    witness_url: Option<String>,
) -> Result<i32, Box<dyn std::error::Error>> {
    use crate::verification::ExecutionReconciliation;

    // Validated before use, and reported without the URL (Round 12), under
    // the name it came from: an endpoint read from the environment was
    // reported as `--rpc-url:` (audit 2026-10-20).
    let (endpoint, source) = endpoint_from(rpc_url, "--rpc-url", "GRAPHITE_RPC_URL")
        .ok_or("no RPC endpoint: pass --rpc-url or set GRAPHITE_RPC_URL")?;
    crate::rpc_client::validate_endpoint(&endpoint).map_err(|e| format!("{source}: {e}"))?;

    let dir = data_dir_path(data_dir);
    let mut core = GraphiteCore::open_data_dir_read_only(&dir)?;
    core.attach_rpc_client(crate::rpc_client::SolanaRpcClient::new(
        crate::rpc_client::RpcConfig {
            endpoint,
            ..Default::default()
        },
    ));
    if let Some((witness, source)) =
        endpoint_from(witness_url, "--witness-url", "GRAPHITE_RPC_WITNESS_URL")
    {
        crate::rpc_client::validate_endpoint(&witness).map_err(|e| format!("{source}: {e}"))?;
        core.attach_inclusion_witness(crate::rpc_client::SolanaRpcClient::new(
            crate::rpc_client::RpcConfig {
                endpoint: witness,
                ..Default::default()
            },
        ))
        .map_err(|e| format!("{source}: {e}"))?;
    }
    // Round 38 (Round 37, V-3): `GRAPHITE_L8_HIGH_ASSURANCE` was the server's
    // alone, so the same reconciliation read `executed` here on one provider's
    // word where the server would have withheld it. Honoured the same way:
    // a conclusion needs an independent witness that agrees, and with none
    // configured the check refuses to run rather than run at an assurance the
    // operator did not choose.
    if crate::operator_boundary::env_flag(
        "GRAPHITE_L8_HIGH_ASSURANCE",
        std::env::var("GRAPHITE_L8_HIGH_ASSURANCE").ok().as_deref(),
    )? {
        if !core.has_inclusion_witness() {
            return Err("GRAPHITE_L8_HIGH_ASSURANCE=1 needs an independent witness: pass --witness-url or set GRAPHITE_RPC_WITNESS_URL".into());
        }
        core.set_require_independent_witness(true);
    }

    // Read the same audit trail the server writes, so the CLI reconciles
    // against the real record rather than a second source of truth. Read
    // only (Round 30): this runs beside the server, which holds the trail's
    // writer lock, and appends nothing. With the server's keys (Round 38,
    // T-11), so it reads the trail as the server's own readers do.
    let audit = match execution_audit_log(
        &dir,
        std::env::var(crate::durable::AUDIT_KEY_ENV).ok().as_deref(),
        std::env::var(crate::durable::AUDIT_PREVIOUS_KEY_ENV)
            .ok()
            .as_deref(),
    ) {
        Ok(log) => Some(log),
        Err(e) => {
            eprintln!(
                "audit trail {}: {e} — reconciling without a verdict on record",
                crate::durable::audit_path(&dir).display()
            );
            None
        }
    };

    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(core.audit_execution(signature, keys, audit.as_ref()));

    println!("signature   {}", result.signature);
    println!("chain       {:?}", result.chain_status);
    println!("attribution {:?}", result.attribution);
    println!("assurance   {}", result.inclusion_assurance.as_str());
    if let Some(d) = &result.chain_transaction_sha256 {
        println!("chain tx    {d}");
    }
    match result.recorded_approved {
        Some(a) => println!(
            "recorded    approved={a}  audit_trail_id={}  transaction_sha256={}",
            result.recorded_audit_trail_id.as_deref().unwrap_or("-"),
            result.recorded_transaction_sha256.as_deref().unwrap_or("-")
        ),
        None => println!("recorded    (no verification on file for this transaction)"),
    }
    for d in &result.caller_keys_disagree {
        println!("WARNING     {d}");
    }
    if let Some(why) = &result.chain_bytes_rejected {
        println!("REJECTED    {why}");
    }
    if let Some(why) = &result.chain_bytes_unavailable {
        println!("NOTE        {why}");
    }
    if let Some(why) = &result.chain_inconsistent {
        println!("INCONSISTENT {why}");
    }
    match &result.inclusion_witness {
        Some(w) if w.agrees => println!("witness     agrees: {}", w.detail),
        Some(w) => println!("WITNESS     DISAGREES: {}", w.detail),
        None => println!("witness     none attached (one RPC is the only source for inclusion)"),
    }
    println!("verdict     {:?}", result.reconciliation);
    println!();

    match &result.reconciliation {
        ExecutionReconciliation::BlockedButExecuted => {
            println!(
                "DISCREPANCY: Graphite BLOCKED this transaction and it executed anyway. The gate\n\
                 was bypassed rather than obeyed - an integration ignoring the verdict, a key\n\
                 used out of band, or an override. Investigate before trusting the next one."
            );
        }
        ExecutionReconciliation::ApprovedButFailedOnChain { error } => {
            println!(
                "Approved, then failed on chain ({}). Not a security failure - Graphite verifies\n\
                 intent and structure, not that a transaction will succeed - but a pattern of\n\
                 these means the verified shape and the executable shape are drifting apart.",
                error.as_deref().unwrap_or("no error reported")
            );
        }
        ExecutionReconciliation::Unavailable { reason } => {
            println!("Could not reconcile: {reason}");
            println!(
                "An unavailable check reports that it is unavailable; it never reports a pass."
            );
        }
        ExecutionReconciliation::NoVerificationOnRecord => {
            println!(
                "Graphite has no verification on file for this transaction - an execution it\n\
                 never saw. That is not proof of wrongdoing, but it is not coverage either."
            );
        }
        ExecutionReconciliation::RecordedForDifferentBytes {
            recorded_transaction_sha256,
            chain_transaction_sha256,
            ..
        } => {
            // Kept so recorded results still parse; no longer produced (audit
            // 2026-10-20, F5): a cited verdict about other bytes is reported
            // in `caller_keys_disagree`, never as a discrepancy.
            println!(
                "The audit_trail_id you supplied names a verification of DIFFERENT bytes\n\
                 (recorded for {}, the chain's bytes digest to {}). Nothing on the trail\n\
                 covers what actually executed under this signature.",
                recorded_transaction_sha256
                    .as_deref()
                    .unwrap_or("a descriptive verification"),
                chain_transaction_sha256
            );
        }
        _ => {}
    }
    Ok(execution_exit_code(
        &result.reconciliation,
        result.chain_bytes_rejected.is_some(),
        result.chain_inconsistent.is_some(),
        result.inclusion_witness.as_ref().is_some_and(|w| !w.agrees),
    ))
}

/// The trail `graphite execution` reconciles against (Round 38, T-11): read
/// only, with the keys the server is configured with —
/// `GRAPHITE_AUDIT_KEY_FILE` and, during a rotation,
/// `GRAPHITE_AUDIT_PREVIOUS_KEY_FILE` (`key_file`, `previous_key_file`) —
/// so its readers check MACs as the server's do. It read the trail without
/// them, to which a self-hashed forgery claiming a MAC was a verdict. A key
/// that cannot be loaded, a keyed trail with no key configured, or a head
/// under none of the keys refuses the trail; the reconciliation is then
/// unavailable (exit 3), never answered from a trail it cannot check.
#[cfg(any(feature = "rpc", test))]
pub(crate) fn execution_audit_log(
    dir: &Path,
    key_file: Option<&str>,
    previous_key_file: Option<&str>,
) -> Result<crate::durable::AuditLog, String> {
    let options = crate::durable::AuditOptions::default()
        .with_env_values(key_file, None, dir)?
        .with_previous_key_value(previous_key_file, dir)?;
    let keys: Vec<crate::durable::AuditKey> = options
        .key
        .into_iter()
        .chain(options.previous_key)
        .collect();
    crate::durable::AuditLog::open_read_only_keyed(crate::durable::audit_path(dir), keys)
        .map_err(|e| e.to_string())
}

/// `graphite execution`'s exit status: a discrepancy (the gate was bypassed).
pub const EXIT_EXECUTION_DISCREPANCY: i32 = 1;
/// The reconciliation could not be made (no RPC answer, no audit trail, a
/// configuration error), so nothing was checked.
pub const EXIT_EXECUTION_UNAVAILABLE: i32 = 3;
/// The RPC returned transaction bytes not bound to the signature.
pub const EXIT_EXECUTION_CHAIN_BYTES_REJECTED: i32 = 4;
/// The primary RPC gave two accounts of the signature.
pub const EXIT_EXECUTION_RPC_INCONSISTENT: i32 = 5;
/// The inclusion witness disagreed with the primary, or could not be asked.
pub const EXIT_EXECUTION_WITNESS_DISAGREES: i32 = 6;

/// The exit status of `graphite execution` (audit 2026-10-20, L10).
///
/// The command is documented as a monitoring check, and it exited 0 whenever
/// the answer was not a discrepancy — including when nothing could be checked
/// (`Unavailable`), when the RPC handed back bytes that are not the
/// signature's, when the RPC contradicted itself and when the inclusion
/// witness disagreed. A check that cannot run reported the same as a check
/// that passed. Each now has its own code, most severe first, so a monitor
/// can page on the one that matters and tell a hostile RPC from an outage;
/// 1 stays the discrepancy, and 2 is left to argument errors (clap's).
pub fn execution_exit_code(
    reconciliation: &crate::verification::ExecutionReconciliation,
    chain_bytes_rejected: bool,
    chain_inconsistent: bool,
    witness_disagrees: bool,
) -> i32 {
    if reconciliation.is_discrepancy() {
        EXIT_EXECUTION_DISCREPANCY
    } else if chain_bytes_rejected {
        EXIT_EXECUTION_CHAIN_BYTES_REJECTED
    } else if chain_inconsistent {
        EXIT_EXECUTION_RPC_INCONSISTENT
    } else if witness_disagrees {
        EXIT_EXECUTION_WITNESS_DISAGREES
    } else if matches!(
        reconciliation,
        crate::verification::ExecutionReconciliation::Unavailable { .. }
    ) {
        EXIT_EXECUTION_UNAVAILABLE
    } else {
        0
    }
}

/// An endpoint from its flag, else from its environment variable, with the
/// name it came from for error messages.
#[cfg(feature = "rpc")]
fn endpoint_from(
    flag: Option<String>,
    flag_name: &'static str,
    env_name: &'static str,
) -> Option<(String, &'static str)> {
    flag.filter(|u| !u.trim().is_empty())
        .map(|u| (u, flag_name))
        .or_else(|| {
            std::env::var(env_name)
                .ok()
                .filter(|u| !u.trim().is_empty())
                .map(|u| (u, env_name))
        })
}

/// A `--program` that changes the durable graph: a base58 32-byte public key,
/// trimmed (audit 2026-10-20, L9). The server's `/admin/quarantine` refused
/// anything else (Round 19, F-19-15) and this path did not: a typo'd id
/// appended a record that can never match a program the gate verifies and
/// that lives forever.
fn program_id_arg(raw: &str) -> Result<String, String> {
    let program_id = raw.trim();
    if program_id.is_empty() {
        return Err("--program must not be empty".to_string());
    }
    crate::solana_types::Pubkey::from_base58(program_id).map_err(|_| {
        format!("--program {program_id:?} is not a base58-encoded 32-byte public key")
    })?;
    Ok(program_id.to_string())
}

/// The audit trail of the data directory an operator command changes (audit
/// 2026-10-20, L9).
///
/// `quarantine add/lift` and `evidence seed/baseline/promote-shadow` change
/// the durable graph the server loads, and left no row on the append-only
/// trail; the same change through `/admin/quarantine` writes an
/// `OperatorAction` row, and the server refuses a lift it cannot record.
/// Opened BEFORE the change, so a trail that cannot be written refuses the
/// command instead of discovering it afterwards. The command already holds
/// the data directory's lock, so no server is appending beside it. Rotation
/// follows the server's `GRAPHITE_AUDIT_ROTATE_BYTES` /
/// `GRAPHITE_AUDIT_MAX_ARCHIVES`, read as strictly as the server reads them.
struct OperatorTrail {
    log: crate::durable::AuditLog,
}

impl OperatorTrail {
    fn open(dir: &Path) -> Result<Self, String> {
        let get = |k: &str| std::env::var(k).ok();
        let rotate_bytes = boundary::env_number(
            "GRAPHITE_AUDIT_ROTATE_BYTES",
            get("GRAPHITE_AUDIT_ROTATE_BYTES").as_deref(),
            crate::durable::DEFAULT_ROTATE_BYTES,
            "a whole number of bytes (0 disables rotation)",
            |_| true,
        )?;
        let max_archives = boundary::env_number(
            "GRAPHITE_AUDIT_MAX_ARCHIVES",
            get("GRAPHITE_AUDIT_MAX_ARCHIVES").as_deref(),
            0usize,
            "a whole number of archives (0 keeps every archive)",
            |_| true,
        )?;
        let path = crate::durable::audit_path(dir);
        // The server's key and anchor settings (Round 30): a keyed trail
        // refuses to be continued without its key.
        let options = crate::durable::AuditOptions {
            rotate_bytes,
            max_archives,
            ..Default::default()
        }
        .with_env_values(
            get(crate::durable::AUDIT_KEY_ENV).as_deref(),
            get(crate::durable::AUDIT_ANCHOR_ENV).as_deref(),
            dir,
        )?
        .with_previous_key_value(get(crate::durable::AUDIT_PREVIOUS_KEY_ENV).as_deref(), dir)?;
        crate::durable::AuditLog::open_with_options(&path, options)
            .map(|log| Self { log })
            .map_err(|e| {
                format!(
                    "the audit trail {} cannot be opened ({e}); refusing an operator action that could not be recorded",
                    path.display()
                )
            })
    }

    /// Append one `OperatorAction` row about `program_id`. False when the
    /// row did not reach the trail.
    fn record(&self, program_id: &str, detail: String) -> bool {
        use crate::durable::{LifecycleEvent, LifecycleEventRecord};
        self.log.append_lifecycle(&LifecycleEventRecord {
            event_type: LifecycleEvent::OperatorAction,
            timestamp: crate::durable::now_utc_rfc3339(),
            // As `/admin/quarantine` writes it: the program id stands where a
            // transaction's content_hash would.
            content_hash: program_id.to_string(),
            verdict_on_record: None,
            verdict_on_record_key: None,
            transaction_sha256: None,
            audit_trail_id: None,
            transaction_signature: None,
            // The credential here is filesystem access to the data
            // directory; the server names its operator key instead.
            reported_by: Some(
                "graphite CLI (local operator with write access to the data directory)".to_string(),
            ),
            detail: Some(detail),
            observed_by_graphite: true,
            sequence_anomalies: Vec::new(),
        })
    }
}

/// What every graph-changing command prints about a running server. The
/// command took the data directory's lock (Round 19, F-19-12), so no server
/// is running on it: the old text told the operator to restart one that
/// could not exist (audit 2026-10-20).
const NO_SERVER_HOLDS_THIS_DIRECTORY: &str =
    "No server holds this data directory (this command took its lock); the next one started on it loads this change.";

/// `graphite evidence import-census` (Round 40, bootstrap): seed each
/// program's HistoricalVolume from the committed, measured census
/// (`census_import`), recording every import on the audit trail as
/// `evidence seed` does. `--dry-run` reads the data directory without its
/// lock and writes nothing.
fn run_import_census(
    data_dir: Option<PathBuf>,
    census_path: Option<PathBuf>,
    programs: Vec<String>,
    dry_run: bool,
    cluster: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::census_import::{self as ci, Census};

    // Round 40: the census is mainnet-beta's; the operator states the Core's
    // cluster, and the server holds the RPC to it at every start.
    match cluster.as_deref() {
        Some(c) => ci::check_cluster_arg(c)?,
        None => {
            return Err(format!(
                "--cluster is required: the census measures {} only (--cluster {}); the server then refuses to start on an RPC of another cluster",
                ci::CENSUS_CLUSTER,
                ci::CENSUS_CLUSTER
            )
            .into())
        }
    }

    let (census, source) = match &census_path {
        Some(path) => {
            let bytes = std::fs::read(path)
                .map_err(|e| format!("the census file {} cannot be read: {e}", path.display()))?;
            let census = Census::from_file_bytes(&bytes)
                .map_err(|e| format!("refusing the census file {}: {e}", path.display()))?;
            (
                census,
                format!(
                    "file {}, identical to the copy compiled into this build",
                    path.display()
                ),
            )
        }
        None => (
            Census::embedded().map_err(|e| format!("the compiled-in census: {e}"))?,
            "the copy compiled into this build".to_string(),
        ),
    };
    let programs = programs
        .iter()
        .map(|p| program_id_arg(p))
        .collect::<Result<Vec<_>, _>>()?;
    let dir = data_dir_path(data_dir);

    let print_plan = |plan: &ci::ImportPlan| {
        println!(
            "CENSUS  {} sha256={}  ({source})",
            ci::CENSUS_FILE,
            plan.census_sha256
        );
        println!(
            "        {} record(s): {} to import, {} skipped{}",
            census.records().len(),
            plan.imports.len(),
            plan.skipped.len(),
            if plan.not_selected > 0 {
                format!(", {} not selected (--program)", plan.not_selected)
            } else {
                String::new()
            }
        );
        println!();
        for i in &plan.imports {
            println!("IMPORT  {}  ({})", i.program_id, i.name);
            println!(
                "  census       {} successful transactions over {}s, slots {}..{}, measured_at {}",
                i.census_transactions,
                i.window_seconds,
                i.oldest_slot,
                i.newest_slot,
                ci::utc(i.measured_at_unix)
            );
            println!(
                "  evidence     battle_tested {} -> {}   (every other field carried over; no signature asserted)",
                i.previous_volume, i.census_transactions
            );
            println!(
                "  graph tier   {} -> {:?}   (recomputed from that evidence, not set - P7)",
                i.previous_graph_tier
                    .map(|t| format!("{t:?}"))
                    .unwrap_or_else(|| "(no record)".to_string()),
                i.graph_tier
            );
            println!(
                "  verdict      tier {:?} -> {:?}; standalone confidence {:.4} -> {:.4}",
                i.before.verdict_tier,
                i.after.verdict_tier,
                i.before.confidence,
                i.after.confidence
            );
        }
        for s in &plan.skipped {
            println!("SKIP    {}  ({}): {}", s.program_id, s.name, s.reason);
        }
        println!();
    };

    if dry_run {
        let core = GraphiteCore::open_data_dir_read_only(&dir)?;
        let plan = ci::plan(&core, &census, &programs)?;
        print_plan(&plan);
        println!(
            "DRY RUN: nothing was written to {} and nothing was recorded on its audit trail.",
            dir.display()
        );
        print_census_caveat();
        return Ok(());
    }

    let mut core = GraphiteCore::open_data_dir(dir.clone())?;
    // Before any change: a trail that cannot be written refuses the command.
    let trail = OperatorTrail::open(&dir)?;
    let plan = ci::plan(&core, &census, &programs)?;
    print_plan(&plan);
    let mut done: Vec<String> = Vec::new();
    for i in &plan.imports {
        match ci::apply(&mut core, i)? {
            Ok(()) => {}
            Err(e) => {
                return Err(format!(
                    "the evidence for {} did NOT reach the data directory ({e}); it is not in force for a server. \
                     Imported, on disk and recorded before it: [{}]",
                    i.program_id,
                    done.join(", ")
                )
                .into());
            }
        }
        // As `evidence seed`: an append-only graph has no undo, so an import
        // the trail cannot take is a failure with the change in force.
        if !trail.record(&i.program_id, ci::audit_detail(&plan.census_sha256, i)) {
            return Err(format!(
                "the evidence for {} was imported and is in force, but the audit trail did NOT record it. \
                 Imported and recorded before it: [{}]",
                i.program_id,
                done.join(", ")
            )
            .into());
        }
        done.push(i.program_id.clone());
    }
    if done.is_empty() {
        println!("Nothing imported: every selected record was skipped (see above).");
    } else {
        println!(
            "IMPORTED {} program(s) into {}; each is one operator_action row on its audit trail.",
            done.len(),
            dir.display()
        );
    }
    print_census_caveat();
    println!("{NO_SERVER_HOLDS_THIS_DIRECTORY}");
    Ok(())
}

fn print_census_caveat() {
    println!();
    println!(
        "This evidence is CENSUS-MEASURED (read-only mainnet-beta counts in battle_tested_evidence.json),"
    );
    println!(
        "not typed by an operator and not earned by this Core. It raises the HistoricalVolume signal only:"
    );
    println!(
        "no tier rule, ceiling, floor or profile changes; on a fresh Core a manifested program's verdict"
    );
    println!(
        "tier stays OfficialManifest. It describes mainnet-beta code at the time measured; an upgrade the Core"
    );
    println!(
        "observes after that time withdraws it. A server on this data directory refuses to start unless its RPC serves mainnet-beta."
    );
}

/// Seed operator-asserted evidence into the durable semantic graph.
///
/// Deliberately loud about provenance. Evidence seeded here was ASSERTED by an
/// operator, not earned by observation, and it feeds the same confidence
/// signals that RPC-verified history feeds. Anyone reading a later approval has
/// to be able to tell those apart, and the append-only graph plus this
/// command's output are what make that possible.
fn run_evidence(action: EvidenceAction) -> Result<(), Box<dyn std::error::Error>> {
    use crate::semantic_graph_store::{Behavior, BehaviorEvidence};

    match action {
        EvidenceAction::Seed {
            data_dir,
            program_id,
            signed_manifest,
            community_verified,
            battle_tested,
            simulation_matches,
        } => {
            let program_id = program_id_arg(&program_id)?;
            if !signed_manifest
                && community_verified == 0
                && battle_tested == 0
                && simulation_matches == 0
            {
                // Seeding nothing appends a record asserting NO evidence, which
                // recomputes to Unknown — a downgrade the operator did not ask
                // for, arriving through a command named "seed".
                return Err("nothing to seed - supply at least one evidence flag".into());
            }
            let dir = data_dir_path(data_dir);
            let mut core = GraphiteCore::open_data_dir(dir.clone())?;
            let trail = OperatorTrail::open(&dir)?;
            let evidence = BehaviorEvidence {
                has_signed_manifest: signed_manifest,
                community_verified_count: community_verified,
                battle_tested_tx_count: battle_tested,
                simulation_match_count: simulation_matches,
            };
            let name = core
                .registry()
                .get(&program_id)
                .map(|m| m.protocol.name.clone())
                .unwrap_or_else(|| "(no manifest)".to_string());
            let version = core
                .registry()
                .get(&program_id)
                .map(|m| m.version.label.clone())
                .unwrap_or_else(|| "operator-seeded".to_string());
            core.seed_behavior(Behavior {
                program_id: program_id.clone(),
                version,
                expected_state_changes: vec![],
                allowed_cpis: vec![],
                // Ignored: `append` recomputes it from the evidence (P7).
                trust_tier: TrustTier::Unknown,
                evidence,
                quarantined: false,
                quarantine_reason: None,
            })?;

            let earned = core
                .program_behavior(&program_id)
                .map(|b| format!("{:?}", b.trust_tier))
                .unwrap_or_else(|| "Unknown".to_string());
            // Seeded evidence raises trust, and an append-only graph has no
            // undo, so a seed the trail cannot take is reported as a failure
            // with the change in force, never as a success.
            if !trail.record(
                &program_id,
                format!(
                    "evidence seeded for {program_id} (operator-asserted): signed_manifest={signed_manifest} community={community_verified} battle_tested={battle_tested} simulation_matches={simulation_matches}; tier recomputed to {earned}"
                ),
            ) {
                return Err(format!(
                    "the evidence for {program_id} was seeded and is in force, but the audit trail did NOT record it"
                )
                .into());
            }
            println!("SEEDED {program_id}  ({name})");
            println!(
                "  evidence     signed_manifest={signed_manifest} community={community_verified} \
                 battle_tested={battle_tested} simulation_matches={simulation_matches}"
            );
            println!("  trust tier   {earned}   (recomputed from that evidence, not set - P7)");
            println!("  graph        {}", dir.display());
            println!();
            println!(
                "This evidence is OPERATOR-ASSERTED, not earned by observation. It feeds the same"
            );
            println!(
                "confidence signals as RPC-verified history, so seed it only for programs whose"
            );
            println!("history you are restoring or can vouch for. Recorded on the audit trail.");
            println!("{NO_SERVER_HOLDS_THIS_DIRECTORY}");
            Ok(())
        }

        EvidenceAction::ImportCensus {
            data_dir,
            census,
            programs,
            dry_run,
            cluster,
        } => run_import_census(data_dir, census, programs, dry_run, cluster),

        EvidenceAction::Baseline {
            data_dir,
            program_id,
            mean_compute_units,
            std_compute_units,
            samples,
            mean_account_writes,
            mean_cpi_hops,
        } => {
            let program_id = program_id_arg(&program_id)?;
            if samples < crate::simulation_integrity::MIN_SAMPLES {
                // Below MIN_SAMPLES the integrity check is skipped entirely, so
                // a baseline seeded under it silently does nothing while the
                // command still reports success.
                return Err(format!(
                    "--samples must be at least {} or the simulation-integrity check stays \
                     disabled and this baseline would have no effect",
                    crate::simulation_integrity::MIN_SAMPLES
                )
                .into());
            }
            let baseline = crate::simulation_integrity::ComputeBaseline {
                mean_compute_units,
                std_compute_units,
                sample_count: samples,
                mean_account_writes,
                std_account_writes: (mean_account_writes * 0.25).max(0.5),
                mean_cpi_hops,
                std_cpi_hops: (mean_cpi_hops * 0.25).max(0.1),
                ..Default::default()
            };
            // Every field, finite and non-negative, by the store's own rule,
            // before the data directory is touched (audit 2026-10-20, L13:
            // this checked only the compute pair, `< 0.0`, which NaN passes;
            // the store refused the rest only after the lock was taken).
            crate::semantic_graph_store::validate_baseline(&baseline)
                .map_err(|e| format!("invalid baseline: {e}"))?;
            let dir = data_dir_path(data_dir);
            let core = GraphiteCore::open_data_dir(dir.clone())?;
            let trail = OperatorTrail::open(&dir)?;
            core.seed_simulation_baseline(&program_id, baseline)?;
            if !trail.record(
                &program_id,
                format!(
                    "simulation baseline seeded for {program_id}: compute mean {mean_compute_units} sd {std_compute_units} over {samples} sample(s), writes {mean_account_writes}, hops {mean_cpi_hops}"
                ),
            ) {
                return Err(format!(
                    "the baseline for {program_id} was seeded and is in force, but the audit trail did NOT record it"
                )
                .into());
            }
            println!("SEEDED BASELINE {program_id}");
            println!(
                "  compute      mean {mean_compute_units} sd {std_compute_units} over {samples} sample(s)"
            );
            println!("  writes/hops  mean {mean_account_writes} / {mean_cpi_hops}");
            println!("  graph        {}", dir.display());
            println!();
            println!(
                "L3 now judges divergence for this program against these numbers. A baseline that"
            );
            println!(
                "does not match real usage will flag legitimate traffic, so restore an exported"
            );
            println!("baseline rather than inventing one.");
            println!("{NO_SERVER_HOLDS_THIS_DIRECTORY}");
            Ok(())
        }

        EvidenceAction::Show {
            data_dir,
            program_id,
        } => {
            let dir = data_dir_path(data_dir);
            let core = GraphiteCore::open_data_dir_read_only(&dir)?;
            match core.program_behavior(&program_id) {
                Some(b) => {
                    println!("{program_id}");
                    println!(
                        "  trust tier   {:?}   (computed from the evidence below)",
                        b.trust_tier
                    );
                    println!(
                        "  evidence     signed_manifest={} community={} battle_tested={} simulation_matches={}",
                        b.evidence.has_signed_manifest,
                        b.evidence.community_verified_count,
                        b.evidence.battle_tested_tx_count,
                        b.evidence.simulation_match_count
                    );
                    if b.quarantined {
                        println!(
                            "  QUARANTINED  {}",
                            b.quarantine_reason
                                .as_deref()
                                .unwrap_or("no reason recorded")
                        );
                    }
                }
                None => println!("{program_id}\n  no behaviour record - nothing earned or seeded"),
            }
            println!("  graph        {}", dir.display());
            Ok(())
        }
        EvidenceAction::PromoteShadow {
            data_dir,
            program_id,
        } => {
            let program_id = program_id_arg(&program_id)?;
            let dir = data_dir_path(data_dir);
            let core = GraphiteCore::open_data_dir(dir.clone())?;
            let trail = OperatorTrail::open(&dir)?;
            let promoted = core.promote_shadow_baseline(&program_id)?;
            let summary = format!(
                "{} samples, mean {:.0} CU (std {:.1}), {:.1} writes, {:.1} hops",
                promoted.sample_count,
                promoted.mean_compute_units,
                promoted.std_compute_units,
                promoted.mean_account_writes,
                promoted.mean_cpi_hops
            );
            if !trail.record(
                &program_id,
                format!("shadow baseline promoted for {program_id}: {summary}"),
            ) {
                return Err(format!(
                    "the shadow baseline for {program_id} was promoted and is in force, but the audit trail did NOT record it"
                )
                .into());
            }
            println!("PROMOTED {program_id}");
            println!(
                "  baseline     {summary} — the clean executions the frozen baseline had refused"
            );
            println!("  graph        {}", dir.display());
            println!("{NO_SERVER_HOLDS_THIS_DIRECTORY}");
            Ok(())
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
            let program_id = program_id_arg(&program_id)?;
            let dir = data_dir_path(data_dir);
            // Takes the data directory's lock (Round 19, F-19-12): beside a
            // running server this refuses, rather than writing a snapshot the
            // server's next one would overwrite. Use POST /admin/quarantine
            // against a running server.
            let core = GraphiteCore::open_data_dir(dir.clone())?;
            let trail = OperatorTrail::open(&dir)?;
            core.quarantine_program_durably(&program_id, &reason)?
                .map_err(|e| format!("the quarantine was not written to disk: {e}"))?;
            // As at `/admin/quarantine`: a quarantine stays in force when the
            // trail cannot take it (undoing it would fail open), and the
            // command says the record is missing.
            if !trail.record(
                &program_id,
                format!("quarantined {program_id}: {}", reason.trim()),
            ) {
                return Err(format!(
                    "{program_id} is QUARANTINED, but the audit trail did NOT record it"
                )
                .into());
            }
            println!("QUARANTINED {program_id} — {}", reason.trim());
            println!(
                "trust tier forced to Unknown until lifted; graph: {}",
                dir.display()
            );
            println!("{NO_SERVER_HOLDS_THIS_DIRECTORY}");
            Ok(())
        }
        QuarantineAction::Lift {
            data_dir,
            program_id,
        } => {
            let program_id = program_id_arg(&program_id)?;
            let dir = data_dir_path(data_dir);
            let core = GraphiteCore::open_data_dir(dir.clone())?;
            let trail = OperatorTrail::open(&dir)?;
            let reason_before_lift = core
                .quarantined_programs()
                .into_iter()
                .find(|(p, _)| p == &program_id)
                .map(|(_, reason)| reason);
            core.lift_program_quarantine_durably(&program_id)?
                .map_err(|e| format!("the lift was not written to disk: {e}"))?;
            if !trail.record(&program_id, format!("quarantine lifted for {program_id}")) {
                // The server's rule (W21): restoring trust with no record of
                // who restored it is the failing-open direction, so a lift the
                // trail cannot take is undone.
                let restored = core.quarantine_program_durably(
                    &program_id,
                    reason_before_lift
                        .as_deref()
                        .filter(|r| !r.trim().is_empty())
                        .unwrap_or("quarantine restored"),
                );
                return Err(format!(
                    "the audit trail could not record the lift, so it was not applied (quarantine restored: {})",
                    if matches!(restored, Ok(Ok(()))) { "yes" } else { "NO" }
                )
                .into());
            }
            println!("LIFTED {program_id} — tier recomputed from evidence (P7)");
            println!("graph: {}", dir.display());
            println!("{NO_SERVER_HOLDS_THIS_DIRECTORY}");
            Ok(())
        }
        QuarantineAction::List { data_dir } => {
            let dir = data_dir_path(data_dir);
            let core = GraphiteCore::open_data_dir_read_only(&dir)?;
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
        RegistryAction::VerifyRecords { state } => {
            let path = registry_state_path(state);
            let engine = load_registry(&path)?;
            let (mut failed, mut unproven) = (0usize, 0usize);
            for rec in engine.records() {
                let outcome = rec.verify_offline();
                let label = match &outcome {
                    Ok(()) => "verified".to_string(),
                    Err(e) if rec.signing_domain.is_none() || rec.manifest.is_none() => {
                        unproven += 1;
                        format!("UNPROVEN: {e}")
                    }
                    Err(e) => {
                        failed += 1;
                        format!("FAILED: {e}")
                    }
                };
                println!("  {} v{}: {label}", rec.program_id, rec.version_label);
            }
            println!(
                "{} record(s): {failed} failed, {unproven} unproven",
                engine.records().len()
            );
            if failed > 0 {
                std::process::exit(1);
            }
            if unproven > 0 {
                std::process::exit(2);
            }
            Ok(())
        }
        RegistryAction::RegisterReviewer {
            state,
            pubkey,
            reputation,
        } => {
            let path = registry_state_path(state);
            // The same read-modify-write lock `submit` takes (audit
            // 2026-10-20, L12): a registration racing a submission (or
            // another registration) each read the state, and the second
            // write dropped the first's change.
            let _registry_lock = lock_registry(&path)?;
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
                // The decode error is not quoted: it names the offending
                // character and its position, which is key material on a
                // terminal or in a CI log (audit 2026-10-20).
                let bytes = hex::decode(key_hex.trim()).map_err(|_| {
                    "--signer-key must be 64 hex chars (32-byte ed25519 seed); the value given is not hex"
                        .to_string()
                })?;
                let seed: [u8; 32] = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                    "--signer-key must be exactly 32 bytes (64 hex chars)".to_string()
                })?;
                let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
                use ed25519_dalek::Signer;
                // The domain-tagged message (audit 2026-10-20, MR-3), never the
                // bare hash: a key that also signs anything else cannot be
                // replayed into an attestation here.
                let sig = hex::encode(signing.sign(&submission.signing_message()).to_bytes());
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
            let _registry_lock = lock_registry(&state_path)?;
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
                    // A refusal by the replay gate is recorded by the engine
                    // (audit 2026-10-20, MR-2: a refused version is never
                    // retaken), and it only holds if it is saved.
                    save_registry(&engine, &state_path)?;
                    std::process::exit(1);
                }
            }
        }
        RegistryAction::RevokeReviewer {
            state,
            graph_state,
            pubkey,
        } => {
            let state_path = registry_state_path(state);
            let graph_path = graph_state_path(graph_state);
            let _registry_lock = lock_registry(&state_path)?;
            let mut engine = load_registry(&state_path)?;
            let mut store = load_graph(&graph_path)?;
            let affected = engine.revoke_reviewer(&mut store, &pubkey)?;
            save_registry(&engine, &state_path)?;
            save_graph(&store, &graph_path)?;
            println!(
                "revoked reviewer {pubkey}; {affected} program tier(s) recomputed without its attestations (state: {}, graph: {})",
                state_path.display(),
                graph_path.display()
            );
            Ok(())
        }
        RegistryAction::DeprecateFixture {
            state,
            content_hash,
        } => {
            let state_path = registry_state_path(state);
            let _registry_lock = lock_registry(&state_path)?;
            let mut engine = load_registry(&state_path)?;
            if !engine.deprecate_regression_fixture(content_hash.trim()) {
                return Err(format!(
                    "no fixture with content_hash {} in the registry's corpus",
                    content_hash.trim()
                )
                .into());
            }
            save_registry(&engine, &state_path)?;
            println!(
                "fixture {} deprecated: it no longer counts toward the promotion gate (state: {})",
                content_hash.trim(),
                state_path.display()
            );
            Ok(())
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

    // The same check every other endpoint gets before a client is built on
    // it (audit 2026-10-20): an unusable --rpc used to surface as "no
    // fixtures recorded" after every fetch had failed. Reported without the
    // URL, which may carry a provider key.
    crate::rpc_client::validate_endpoint(&rpc_url).map_err(|e| format!("--rpc: {e}"))?;
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

    /// A6-13: the default check passes any 2xx; `--strict` also refuses a
    /// degraded node and a body without the flag.
    #[cfg(feature = "server")]
    #[test]
    fn strict_healthcheck_fails_a_degraded_node() {
        let healthy = serde_json::json!({ "status": "ok", "degraded": false });
        let degraded = serde_json::json!({
            "status": "ok",
            "degraded": true,
            "degraded_reasons": ["audit writes failing"]
        });
        let bare = serde_json::json!({ "status": "ok" });
        assert!(health_verdict(true, Some(&healthy), false).is_ok());
        assert!(health_verdict(true, Some(&degraded), false).is_ok());
        assert!(health_verdict(true, Some(&healthy), true).is_ok());
        let e = health_verdict(true, Some(&degraded), true).unwrap_err();
        assert!(e.contains("audit writes failing"), "{e}");
        assert!(health_verdict(true, Some(&bare), true).is_err());
        assert!(health_verdict(true, None, true).is_err());
        assert!(health_verdict(false, Some(&healthy), false).is_err());
        assert!(health_verdict(false, Some(&healthy), true).is_err());
    }
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
                account_layouts: vec![],
                name: "Deposit".to_string(),
                discriminator: "01".to_string(),
                accounts: vec![AccountRoleDef {
                    name: "vault".to_string(),
                    role: "vault".to_string(),
                    is_writable: false,
                    is_signer: false,
                    pda_seeds: vec![],
                    expected_address: vec![],
                    optional: false,
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

    /// Round 39 (R39-CB-12): the diff compared only an account's name,
    /// signer and writable flags, so a version that dropped a slot's
    /// expected address, changed its PDA seeds or role, made it optional,
    /// or changed an alternative layout or a risk rule read "no
    /// instruction-level changes".
    #[test]
    fn the_diff_surfaces_every_field_the_runtime_judges_an_account_by() {
        type Edit = fn(&mut ProtocolManifest);
        let edits: [(&str, Edit); 8] = [
            ("expected address", |m| {
                m.instructions[0].accounts[0].expected_address =
                    vec!["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()]
            }),
            ("pda seeds", |m| {
                m.instructions[0].accounts[0].pda_seeds = vec!["vault".to_string()]
            }),
            ("role", |m| {
                m.instructions[0].accounts[0].role = "pda".to_string()
            }),
            ("optional", |m| {
                m.instructions[0].accounts[0].optional = true
            }),
            ("account layouts", |m| {
                let alt = m.instructions[0].accounts.clone();
                m.instructions[0].account_layouts = vec![alt]
            }),
            (
                "account layouts [0] account #0 vault: expected address",
                |m| {
                    // Both sides have the alternative; only its slot differs
                    // (the `before` side gets the same layout below).
                    let mut alt = m.instructions[0].accounts.clone();
                    alt[0].expected_address = vec!["{program_id}".to_string()];
                    m.instructions[0].account_layouts = vec![alt]
                },
            ),
            ("risk rules", |m| {
                m.instructions[0].risk_rules = vec!["no_external_destination".to_string()]
            }),
            ("account #0", |m| {
                // Several fields of one slot at once: still one line per slot.
                let a = &mut m.instructions[0].accounts[0];
                a.pda_seeds = vec!["vault".to_string()];
                a.expected_address = vec!["{program_id}".to_string()];
            }),
        ];
        for (what, edit) in edits {
            let mut before = diff_manifest(DIFF_PROGRAM, "1.0");
            if what.starts_with("account layouts [0]") {
                before.instructions[0].account_layouts =
                    vec![before.instructions[0].accounts.clone()];
            }
            let mut after = diff_manifest(DIFF_PROGRAM, "1.0");
            edit(&mut after);
            let out = manifest_diff(&before, &after).join("\n");
            assert!(
                !out.contains("no instruction-level changes"),
                "a change of {what} read as no change: {out}"
            );
            assert!(out.contains(what), "{what} not named: {out}");
            // The reverse direction (a constraint removed) is the one that
            // weakens a verdict; it must show too.
            let back = manifest_diff(&after, &before).join("\n");
            assert!(back.contains(what), "{what} removal not named: {back}");
        }
        // Benign control: an identical manifest still diffs to nothing.
        let a = diff_manifest(DIFF_PROGRAM, "1.0");
        let out = manifest_diff(&a, &a.clone()).join("\n");
        assert!(out.contains("no instruction-level changes"), "{out}");
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

    // ── Audit 2026-10-20: CLI findings ──────────────────────────────────────

    fn transfer_input() -> VerificationInput {
        serde_json::from_value(serde_json::json!({
            "proposed_intent": {
                "intent_type": "transfer",
                "raw_natural_language": "Transfer 1 SOL",
                "confidence_of_parse": 0.95
            },
            "program_id": "11111111111111111111111111111111",
            "instruction_discriminator": "02000000",
            "account_addresses": [
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"
            ],
            "wallet_profile": { "Custom": { "min_confidence": 0.0, "min_trust_tier": "Unknown" } }
        }))
        .unwrap()
    }

    /// L11: `verify`/`explain` judged a weak caller-supplied `Custom`
    /// profile as given, while the server clamps it; and they ignored a
    /// `GRAPHITE_WALLET_PROFILE` pin. Both now go through the server's own
    /// boundary, and a `--profile` stands where a request body's would.
    #[test]
    fn the_cli_applies_the_servers_profile_boundary() {
        use crate::policy_engine::{
            WEAKEST_BUILTIN_MIN_CONFIDENCE, WEAKEST_BUILTIN_MIN_TRUST_TIER,
        };
        let open = boundary::OperatorPolicy::default();

        // A weak Custom in the input is clamped, with the server's note.
        let (input, note) =
            effective_input(transfer_input(), &ProfileArg::default(), &open).expect("valid input");
        assert_eq!(
            input.wallet_profile,
            WalletProfile::Custom {
                min_confidence: WEAKEST_BUILTIN_MIN_CONFIDENCE,
                min_trust_tier: WEAKEST_BUILTIN_MIN_TRUST_TIER,
            }
        );
        assert!(note.unwrap().contains("weaker than any built-in"));

        // So is a weak --profile custom.
        let weak = ProfileArg {
            name: Some("custom".to_string()),
            min_confidence: Some(0.1),
            min_trust_tier: Some("Unknown".to_string()),
        };
        let (input, _) = effective_input(transfer_input(), &weak, &open).unwrap();
        assert!(!input.wallet_profile.is_weaker_than_any_builtin());

        // The opt-out applies it as given, as the server would.
        let permissive = boundary::OperatorPolicy {
            allow_permissive_profiles: true,
            ..Default::default()
        };
        let (input, note) = effective_input(transfer_input(), &weak, &permissive).unwrap();
        assert!(input.wallet_profile.is_weaker_than_any_builtin());
        assert!(note.is_none());

        // A pin beats both the input and --profile, and says so.
        let pinned = boundary::OperatorPolicy {
            pinned_profile: Some(WalletProfile::Treasury),
            ..Default::default()
        };
        let (input, note) = effective_input(transfer_input(), &arg("gaming"), &pinned).unwrap();
        assert_eq!(input.wallet_profile, WalletProfile::Treasury);
        assert!(note.unwrap().contains("pinned"));

        // Out-of-range is refused in every mode.
        let mut bad = transfer_input();
        bad.wallet_profile = WalletProfile::Custom {
            min_confidence: 2.0,
            min_trust_tier: TrustTier::BattleTested,
        };
        assert!(effective_input(bad, &ProfileArg::default(), &permissive).is_err());
    }

    /// L11: the plugins directory and the core switches the server applies
    /// are applied by the CLI's core too, and an unloadable directory is an
    /// error there as it is a startup error at the server.
    #[test]
    fn the_cli_core_carries_the_servers_switches_and_plugins() {
        let policy = boundary::OperatorPolicy::from_lookup(|k| match k {
            "GRAPHITE_ALLOW_DURABLE_NONCE" => Some("1".to_string()),
            "GRAPHITE_QUARANTINE_ON_UPGRADE" => Some("true".to_string()),
            "GRAPHITE_PLUGINS_DIR" => Some("/nonexistent/graphite-plugins".to_string()),
            _ => None,
        })
        .unwrap();
        assert!(policy.allow_durable_nonce && policy.quarantine_on_upgrade);
        let mut core = GraphiteCore::new();
        let e = policy.apply_to_core(&mut core).unwrap_err();
        assert!(e.contains("GRAPHITE_PLUGINS_DIR"), "{e}");
        assert!(core.quarantine_on_upgrade(), "the switch reached the core");

        // Round 32: the relaxations of the production defaults reach the
        // core too, each from its own variable, and are off unless set.
        let mut core = GraphiteCore::new();
        boundary::OperatorPolicy::default()
            .apply_to_core(&mut core)
            .unwrap();
        assert_eq!(core.l4_relaxations(), Default::default());
        assert!(!core.allow_unbounded_withdrawals());
        for (name, check) in [
            (
                "GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS",
                (|c: &GraphiteCore| c.l4_relaxations().unreadable_value_declarations)
                    as fn(&GraphiteCore) -> bool,
            ),
            (
                "GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT",
                |c| c.l4_relaxations().signer_lamports_outside_declared_debit,
            ),
            ("GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS", |c| {
                c.allow_unbounded_withdrawals()
            }),
        ] {
            let policy =
                boundary::OperatorPolicy::from_lookup(|k| (k == name).then(|| "1".to_string()))
                    .unwrap();
            let mut core = GraphiteCore::new();
            policy.apply_to_core(&mut core).unwrap();
            assert!(check(&core), "{name} reached the core");
        }

        let dir = reg_dir();
        let policy = boundary::OperatorPolicy {
            plugins_dir: Some(dir.clone()),
            ..Default::default()
        };
        let summary = policy.apply_to_core(&mut GraphiteCore::new()).unwrap();
        assert_eq!(
            summary.map(|s| s.registered),
            Some(0),
            "an empty directory loads"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// L14: the probe address was hard-coded to 127.0.0.1.
    #[cfg(feature = "server")]
    #[test]
    fn the_healthcheck_probes_the_host_it_is_given() {
        assert_eq!(
            health_url("127.0.0.1", 7331).unwrap(),
            "http://127.0.0.1:7331/health"
        );
        assert_eq!(health_url("::1", 7331).unwrap(), "http://[::1]:7331/health");
        assert_eq!(health_url("[::1]", 80).unwrap(), "http://[::1]:80/health");
        assert_eq!(
            health_url("10.1.2.3", 9000).unwrap(),
            "http://10.1.2.3:9000/health"
        );
        assert_eq!(
            health_url("0.0.0.0", 7331).unwrap(),
            "http://127.0.0.1:7331/health"
        );
        assert_eq!(health_url("::", 7331).unwrap(), "http://[::1]:7331/health");
        assert_eq!(
            health_url("localhost", 7331).unwrap(),
            "http://127.0.0.1:7331/health"
        );
        assert!(health_url("example.com", 7331).is_err());
    }

    /// L10: `graphite execution` exited 0 for every outcome but a
    /// discrepancy, including a check that could not run at all.
    #[test]
    fn every_execution_outcome_that_is_not_clean_exits_non_zero() {
        use crate::verification::ExecutionReconciliation as R;
        let unavailable = R::Unavailable {
            reason: "no RPC".to_string(),
        };
        assert_eq!(
            execution_exit_code(&R::ApprovedAndExecuted, false, false, false),
            0
        );
        assert_eq!(
            execution_exit_code(&R::NoVerificationOnRecord, false, false, false),
            0
        );
        assert_eq!(
            execution_exit_code(&R::BlockedButExecuted, false, false, false),
            EXIT_EXECUTION_DISCREPANCY
        );
        assert_eq!(EXIT_EXECUTION_DISCREPANCY, 1, "1 stays the discrepancy");
        assert_eq!(
            execution_exit_code(&unavailable, false, false, false),
            EXIT_EXECUTION_UNAVAILABLE
        );
        assert_eq!(
            execution_exit_code(&unavailable, true, false, false),
            EXIT_EXECUTION_CHAIN_BYTES_REJECTED
        );
        assert_eq!(
            execution_exit_code(&R::ApprovedAndExecuted, false, true, false),
            EXIT_EXECUTION_RPC_INCONSISTENT
        );
        assert_eq!(
            execution_exit_code(&R::ApprovedAndExecuted, false, false, true),
            EXIT_EXECUTION_WITNESS_DISAGREES
        );
        // A discrepancy outranks every doubt about the RPC.
        assert_eq!(
            execution_exit_code(&R::BlockedButExecuted, true, true, true),
            EXIT_EXECUTION_DISCREPANCY
        );
        let codes = [
            EXIT_EXECUTION_DISCREPANCY,
            EXIT_EXECUTION_UNAVAILABLE,
            EXIT_EXECUTION_CHAIN_BYTES_REJECTED,
            EXIT_EXECUTION_RPC_INCONSISTENT,
            EXIT_EXECUTION_WITNESS_DISAGREES,
        ];
        let distinct: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(distinct.len(), codes.len());
        assert!(!codes.contains(&2), "2 is clap's usage error");
    }

    fn operator_rows(dir: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(crate::durable::audit_path(dir))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["event_type"] == "operator_action")
            .collect()
    }

    /// L9: the CLI's quarantine and evidence commands changed the durable
    /// graph with no row on the audit trail and accepted any string as a
    /// program id. Each writes an `OperatorAction` row now, and a program id
    /// must be a base58 public key.
    #[test]
    fn graph_changing_commands_validate_the_program_and_leave_a_row() {
        const PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        let dir = reg_dir();
        let data = Some(dir.clone());

        let e = run_quarantine(QuarantineAction::Add {
            data_dir: data.clone(),
            program_id: "not-a-program".to_string(),
            reason: "r".to_string(),
        })
        .unwrap_err();
        assert!(e.to_string().contains("base58"), "{e}");
        assert!(
            operator_rows(&dir).is_empty(),
            "a refused command writes nothing"
        );

        run_quarantine(QuarantineAction::Add {
            data_dir: data.clone(),
            program_id: format!("  {PROGRAM} "),
            reason: "GHSA-test".to_string(),
        })
        .unwrap();
        run_quarantine(QuarantineAction::Lift {
            data_dir: data.clone(),
            program_id: PROGRAM.to_string(),
        })
        .unwrap();
        run_evidence(EvidenceAction::Seed {
            data_dir: data.clone(),
            program_id: PROGRAM.to_string(),
            signed_manifest: true,
            community_verified: 0,
            battle_tested: 0,
            simulation_matches: 0,
        })
        .unwrap();
        run_evidence(EvidenceAction::Baseline {
            data_dir: data.clone(),
            program_id: PROGRAM.to_string(),
            mean_compute_units: 1500.0,
            std_compute_units: 10.0,
            samples: crate::simulation_integrity::MIN_SAMPLES,
            mean_account_writes: 2.0,
            mean_cpi_hops: 0.0,
        })
        .unwrap();

        let rows = operator_rows(&dir);
        let details: Vec<&str> = rows.iter().map(|r| r["detail"].as_str().unwrap()).collect();
        assert_eq!(rows.len(), 4, "{details:?}");
        assert!(rows
            .iter()
            .all(|r| r["content_hash"] == PROGRAM && r["observed_by_graphite"] == true));
        assert!(details[0].starts_with("quarantined"), "{details:?}");
        assert!(details[1].starts_with("quarantine lifted"), "{details:?}");
        assert!(details[2].starts_with("evidence seeded"), "{details:?}");
        assert!(
            details[3].starts_with("simulation baseline seeded"),
            "{details:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// L13: `evidence baseline` checked `< 0.0` on the compute pair only, and
    /// NaN passes `< 0.0`. Every field is checked by the store's own rule now,
    /// before the data directory is opened.
    #[test]
    fn a_baseline_that_is_not_finite_is_refused_before_the_data_dir_is_touched() {
        for (field, value) in [
            ("mean_compute_units", f64::NAN),
            ("std_compute_units", f64::INFINITY),
            ("mean_account_writes", f64::NAN),
            ("mean_cpi_hops", -1.0),
        ] {
            let dir = reg_dir().join("data");
            let mut args = [1500.0, 10.0, 2.0, 0.0];
            let i = match field {
                "mean_compute_units" => 0,
                "std_compute_units" => 1,
                "mean_account_writes" => 2,
                _ => 3,
            };
            args[i] = value;
            let e = run_evidence(EvidenceAction::Baseline {
                data_dir: Some(dir.clone()),
                program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
                mean_compute_units: args[0],
                std_compute_units: args[1],
                samples: crate::simulation_integrity::MIN_SAMPLES,
                mean_account_writes: args[2],
                mean_cpi_hops: args[3],
            })
            .unwrap_err();
            assert!(e.to_string().contains("invalid baseline"), "{field}: {e}");
            assert!(!dir.exists(), "{field}: the data directory was opened");
        }
    }

    /// L12: `registry register-reviewer` read, changed and wrote the state
    /// with no lock, so it could drop a concurrent submission's record. It
    /// waits for the registry lock now.
    #[test]
    fn register_reviewer_waits_for_the_registry_lock() {
        let dir = reg_dir();
        let state = dir.join("state.json");
        let held = lock_registry(&state).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let pubkey = bs58::encode(key.verifying_key().to_bytes()).into_string();
        let worker = {
            let state = state.clone();
            std::thread::spawn(move || {
                run_registry(RegistryAction::RegisterReviewer {
                    state: Some(state),
                    pubkey,
                    reputation: 200,
                })
                .map_err(|e| e.to_string())
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(
            !state.exists(),
            "the registration wrote the state while another command held the lock"
        );
        drop(held);
        worker.join().unwrap().unwrap();
        assert_eq!(load_registry(&state).unwrap().reviewers().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn program_ids_are_base58_public_keys() {
        assert_eq!(
            program_id_arg(" 11111111111111111111111111111111 ").unwrap(),
            "11111111111111111111111111111111"
        );
        for bad in [
            "",
            "   ",
            "not-a-program",
            "1111",
            "0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl",
        ] {
            assert!(program_id_arg(bad).is_err(), "{bad:?}");
        }
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
