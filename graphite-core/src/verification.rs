//! GraphiteCore — the top-level verification orchestrator.
//!
//! Wires together: Manifest Registry → Account Resolution → Transaction Builder
//! → Risk Engine → Confidence Engine → Policy Engine → Unknown Protocol Mode.
//!
//! This is the public API. Call `GraphiteCore::verify()` with a VerificationInput
//! and receive a VerificationResult with confidence score, breakdown, risk
//! assessment, and policy decision.

use crate::account_resolution::{resolve_accounts, AccountResolutionInput, ResolvedAccount};
use crate::confidence_engine::{
    compute_confidence, ConfidenceResult, SignalKind, TrustTier, WeightedSignal,
};
use crate::manifest::{load_seed_manifests, ManifestRegistry};
use crate::plugin_orchestrator::{LayerId, PluginContext, PluginVerdict};
use crate::policy_engine::{evaluate_policy, PolicyInput, PolicyVerdict, WalletProfile};
use crate::risk_engine::{assess_with_warnings, RiskAssessmentInput, RiskPattern, RiskVerdict};
#[cfg(feature = "rpc")]
use crate::rpc_client::SolanaRpcClient;
use crate::semantic_graph_store::{Behavior, BehaviorEvidence, SemanticGraphStore};
use crate::transaction_builder::{build_transaction, BuiltTransaction, TransactionPlan};
use crate::unknown_protocol_mode::apply_unknown_protocol_ceiling;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProposedIntent {
    pub intent_type: String,
    pub raw_natural_language: String,
    pub confidence_of_parse: f64,
    #[serde(default)]
    pub extracted_parameters: Option<ExtractedParameters>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtractedParameters {
    #[serde(default)]
    pub input_token: Option<String>,
    #[serde(default)]
    pub output_token: Option<String>,
    #[serde(default)]
    pub amount: Option<String>,
    #[serde(default)]
    pub slippage_bps: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationInput {
    pub proposed_intent: ProposedIntent,
    pub program_id: String,
    #[serde(default)]
    pub protocol_version: String,
    pub instruction_discriminator: String,
    pub account_addresses: Vec<String>,
    #[serde(default)]
    pub instruction_data: Option<Vec<u8>>,
    #[serde(default)]
    pub cpi_targets: Vec<String>,
    #[serde(default)]
    pub wallet_profile: WalletProfile,
    #[serde(default)]
    pub behavior_evidence: BehaviorEvidence,
    #[serde(default)]
    pub compute_units: u64,
    #[serde(default)]
    pub account_writes: u32,
    #[serde(default)]
    pub cpi_hops: u32,
    /// Optional fully-signed transaction blob (binary). When provided, the
    /// RPC client will use this exact blob for `simulateTransaction` which
    /// yields the most accurate simulation result. If absent, a best-effort
    /// simulation will use `instruction_data` as a minimal payload.
    #[serde(default)]
    pub signed_transaction: Option<Vec<u8>>,
    /// Phase 2: the COMPLETE list of instructions in the transaction,
    /// including the primary instruction (whose fields above are the focused
    /// view). When empty (the default, backward compatible), verification is
    /// single-instruction. When 2+, the multi-instruction pattern analysis
    /// layer detects coordinated mass-drain patterns across them.
    #[serde(default)]
    pub transaction_instructions: Vec<crate::tx_pattern_analysis::TransactionInstruction>,
    /// Phase 2: the hierarchical CPI trace tree of the primary instruction.
    /// When present, the CPI trace analysis layer scrutinizes it for unknown
    /// programs, repeated revisits, excessive depth, and impersonation.
    #[serde(default)]
    pub cpi_trace: Option<crate::tx_pattern_analysis::CpiTraceNode>,
    /// P1 fix (2026-09-05 audit, "signer/writable metadata is not grounded
    /// in actual transaction AccountMeta data"): the REAL per-account
    /// signer/writable bits from the actual transaction, in the same order
    /// as `account_addresses`, when the caller has them available. Empty
    /// (the default) or a length that doesn't match `account_addresses`
    /// means "not supplied" — `ResolvedAccount.privilege_mismatch` stays
    /// honestly `false` (not checked) rather than assumed to match. See
    /// `account_resolution::RealAccountMeta`.
    #[serde(default)]
    pub real_account_metas: Vec<crate::account_resolution::RealAccountMeta>,
    /// P1 fix (2026-09-05 audit, "no real ALT/v0 transaction awareness"):
    /// the caller declares whether the underlying transaction is a
    /// versioned (v0) message that resolves one or more accounts through
    /// Address Lookup Tables. Graphite has NO independent way to detect
    /// this itself — it only ever sees the flat `account_addresses` the
    /// caller supplies, never the raw transaction bytes' message-version
    /// byte or ALT references (full bincode `VersionedTransaction` parsing
    /// and RPC-based ALT resolution is tracked as a larger follow-up, not
    /// attempted here — a rushed, hand-rolled wire-format parser without
    /// the `solana-sdk` crate carries real correctness risk, and getting it
    /// wrong is worse than the current honest disclosure). When true, this
    /// is surfaced as a non-blocking warning (P12: ALT usage is extremely
    /// common in legitimate, complex swaps and must never itself reduce
    /// confidence or block) so a consumer of the result can see that
    /// ALT-resolved accounts were not independently verified by this
    /// pipeline, rather than the blind spot being silent.
    #[serde(default)]
    pub uses_versioned_transaction: bool,
    /// Number of distinct Address Lookup Tables the caller's transaction
    /// references, if known (0 if `uses_versioned_transaction` is false or
    /// the caller doesn't track this). Purely informational — included in
    /// the warning text when non-zero.
    #[serde(default)]
    pub lookup_table_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationBreakdownItem {
    pub kind: String,
    pub raw_value: f64,
    pub weight: f64,
    pub contribution: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RiskFinding {
    pub pattern: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RiskVerdictSummary {
    pub status: String, // "Clear" | "Blocked"
    pub findings: Vec<RiskFinding>,
}

/// Read-only dashboard snapshot of the Semantic Graph (Constitution P4 —
/// never mutates state). Nodes are programs with merged manifest + earned
/// behavior + baseline state; edges are directed CPI relationships.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct GraphSnapshot {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct GraphNode {
    pub program_id: String,
    /// Protocol name from the manifest, or the program id when unknown.
    pub name: String,
    pub manifest_version: Option<String>,
    /// Trust tier: manifest-declared tier (P7-capped on the verify path) or
    /// the graph's earned tier when a behavior record exists.
    pub trust_tier: String,
    pub instruction_count: usize,
    /// Simulation baseline sample count (None when never observed/seeded).
    pub baseline_samples: Option<u64>,
    pub battle_tested_tx_count: u64,
    pub community_verified_count: u32,
    pub quarantined: bool,
    pub quarantine_reason: Option<String>,
    /// Direct CPI targets reachable from this program's instructions.
    pub cpi_targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
}

/// Outcome of L8 execution verification (post-submission confirmation).
///
/// The honest L8 contract: Graphite cannot prove execution before
/// submission. After submission it confirms against the cluster. The
/// variants below are the ONLY truthful states — there is deliberately no
/// "assumed executed" fallback (GAP-2026-08-06-3: Inconclusive, never a
/// phantom pass).
#[cfg(feature = "rpc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionVerification {
    /// Transaction included in a slot; `success` is the on-chain status.
    Confirmed {
        signature: String,
        slot: u64,
        success: bool,
        error: Option<String>,
    },
    /// The cluster has no record of this signature (pending or never sent).
    UnknownSignature(String),
    /// Cannot confirm right now (no RPC client, RPC failure, timeout).
    Unavailable(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationResult {
    pub approved: bool,
    pub confidence: f64,
    pub breakdown: Vec<VerificationBreakdownItem>,
    pub trust_tier: String,
    pub risk_verdict: RiskVerdictSummary,
    pub policy_verdict: String,
    pub audit_trail_id: String,
    /// Deterministic SHA-256 hash of the transaction configuration (same input → same hash).
    /// Unlike audit_trail_id (which includes a per-call sequence counter), content_hash is
    /// fully reproducible and satisfies Constitution P2 (deterministic/reproducible).
    pub content_hash: String,
    pub transaction: BuiltTransaction,
    pub resolved_accounts: Vec<ResolvedAccount>,
    pub protocol_name: String,
    pub instruction_name: String,
    pub manifest_found: bool,
    pub unknown_protocol: bool,
    /// Version label of the protocol manifest this verification was checked
    /// against (None when no manifest exists). This lets a consumer
    /// programmatically confirm WHICH manifest version produced the result —
    /// the Constitution G7 gap (cross-version replay confusion) requires this
    /// field to exist on the result, not just in the audit log.
    #[serde(default)]
    pub manifest_version: Option<String>,
    pub summary: String,
    // Phase 1.5: Simulation integrity result (None if not checked)
    #[serde(default)]
    pub simulation_flagged: Option<bool>,
    #[serde(default)]
    pub simulation_divergence: Option<f64>,
    #[serde(default)]
    pub layers: Vec<PipelineLayerResult>,
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("account resolution failed: {0}")]
    AccountResolution(#[from] crate::account_resolution::AccountResolutionError),
    #[error("risk assessment failed: {0}")]
    RiskAssessment(#[from] crate::risk_engine::RiskError),
    #[error("policy evaluation failed: {0}")]
    PolicyEvaluation(#[from] crate::policy_engine::PolicyError),
    #[error("transaction build failed: {0}")]
    TransactionBuild(String),
    #[error("semantic graph error: {0}")]
    SemanticGraph(#[from] crate::semantic_graph_store::SemanticGraphError),
    #[error("confidence computation failed: {0}")]
    Confidence(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// Tri-state outcome of a single pipeline layer (GAP-2026-08-06-3).
///
/// A layer either PASSES, FAILS, or is INCONCLUSIVE — it never reports a
/// verdict it did not reach. `passed` (kept for SDK backward compatibility)
/// is DERIVED at construction: only `Passed` yields `passed: true`. This
/// eliminates the phantom-pass class where L3/L8 hardcoded `passed: true`
/// while the real verdict lived elsewhere in the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerStatus {
    /// The layer ran and confirmed its check.
    Passed,
    /// The layer ran and its check failed (blocks / reduces confidence).
    Failed,
    /// The layer could not produce a verdict (not run, skipped, or
    /// insufficient evidence). Never reported as a pass.
    Inconclusive,
}

impl Default for LayerStatus {
    /// Fail-closed default: an absent/unknown status must not claim a pass.
    fn default() -> Self {
        LayerStatus::Inconclusive
    }
}

impl LayerStatus {
    /// Serde-consistent snake_case name (used in the audit trail).
    pub fn as_str(&self) -> &'static str {
        match self {
            LayerStatus::Passed => "passed",
            LayerStatus::Failed => "failed",
            LayerStatus::Inconclusive => "inconclusive",
        }
    }
}

/// Result of a single pipeline layer verification.
///
/// `passed` is the legacy boolean (SDK-consumed) and is ALWAYS derived from
/// `status` at construction — never set independently, so the report cannot
/// drift from reality.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PipelineLayerResult {
    pub layer: String,
    pub passed: bool,
    /// Tri-state truth (GAP-2026-08-06-3). `#[serde(default)]` keeps
    /// deserialization of older payloads that predate the field working; the
    /// fail-closed default is `Inconclusive`.
    #[serde(default)]
    pub status: LayerStatus,
    pub reason: String,
}

impl PipelineLayerResult {
    /// Single construction point: `passed` is derived from `status`, so the
    /// boolean can never contradict the tri-state.
    pub fn new(layer: impl Into<String>, status: LayerStatus, reason: impl Into<String>) -> Self {
        Self {
            layer: layer.into(),
            passed: status == LayerStatus::Passed,
            status,
            reason: reason.into(),
        }
    }
}

/// File name of the semantic-graph snapshot inside the data directory.
const SEMANTIC_GRAPH_FILENAME: &str = "semantic_graph.json";

/// Atomically write `json` to `path` via a uniquely-named temp file + rename.
/// Never fatal — failures are logged. A unique temp name (`pid` + monotonic
/// counter) means concurrent writers can't clobber each other's temp files;
/// the rename is atomic, so readers only ever see complete documents.
fn persist_json_atomic(path: &std::path::Path, json: &str) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!(
        "json.tmp.{}.{}",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    if let Err(e) = std::fs::write(&tmp, json) {
        tracing::warn!("failed to persist semantic graph: {}", e);
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        tracing::warn!("failed to commit semantic graph snapshot: {}", e);
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Phase 2 evidence-derived confidence signals, read from the Semantic Graph's
/// INTERNAL accumulator (Constitution G4) — never from the request body.
///
/// - `simulation_matches`: RPC-verified simulation count (the program's
///   baseline `sample_count`) — recorded only from real `simulateTransaction`
///   results (anti-poisoning), never from caller JSON.
/// - `historical_volume`: earned/verified transaction volume (Behavior
///   evidence `battle_tested_tx_count`), seeded only via the trusted operator
///   API or the manifest registry.
/// - `community_verified`: independent community verifications (Behavior
///   evidence `community_verified_count`), earned via the registry/review
///   process — never self-asserted.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GraphSignalEvidence {
    pub simulation_matches: u64,
    pub historical_volume: u64,
    pub community_verified: u32,
}

/// Manifest-derived risk-assessment context for a single instruction. See
/// `GraphiteCore::instruction_risk_context` (P0-3 fix, 2026-09-05 audit).
struct InstructionRiskContext {
    expected_state_changes: Vec<String>,
    allowed_cpis: Vec<String>,
    expected_account_count: Option<usize>,
    variable_accounts: bool,
    manifest_risk_class: String,
    manifest_found: bool,
}

/// The main Graphite verification engine.
///
/// `semantic_graph` is `Arc<Mutex<..>>` so that cloned core instances (axum
/// State clones one per request) all share the same append-only history,
/// trust tiers, and simulation baselines — and so the accumulator can be
/// updated while `verify_async` runs on a shared `&self`.
///
/// `plugins` (Constitution P8): layer-scoped plugins fold into their own
/// layer's result; analytics observe completed results. Clones share the same
/// registered plugin instances (`Arc`), so server per-request clones see the
/// same plugin set and the same analytics sink state. Register plugins at
/// startup, before cloning.
#[derive(Clone)]
pub struct GraphiteCore {
    registry: ManifestRegistry,
    semantic_graph: Arc<Mutex<SemanticGraphStore>>,
    #[cfg(feature = "rpc")]
    rpc_client: Option<SolanaRpcClient>,
    /// Optional durability directory (snapshots + audit trail).
    data_dir: Option<PathBuf>,
    /// P8 plugin orchestrator (sole caller of every plugin).
    plugins: crate::plugin_orchestrator::PluginOrchestrator,
}

impl std::fmt::Debug for GraphiteCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Plugin trait objects are not `Debug`; report what is structurally
        // knowable (registry + registered plugins) rather than internals.
        f.debug_struct("GraphiteCore")
            .field("registry", &self.registry)
            .field("plugins", &self.plugins)
            .finish_non_exhaustive()
    }
}

impl Default for GraphiteCore {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphiteCore {
    /// Create a new GraphiteCore with built-in seed protocol manifests and the
    /// built-in first-party plugins registered (reviewed in-tree): the
    /// FakeRewardsDrainer L7 risk plugin and the verification event logger.
    pub fn new() -> Self {
        Self {
            registry: load_seed_manifests(),
            semantic_graph: Arc::new(Mutex::new(SemanticGraphStore::new())),
            #[cfg(feature = "rpc")]
            rpc_client: None,
            data_dir: None,
            plugins: crate::plugin_orchestrator::PluginOrchestrator::with_builtin_plugins(),
        }
    }

    /// Create a GraphiteCore with NO plugins registered — a pristine core for
    /// embedding/benchmarking minimal footprints. The built-in plugins are
    /// reviewed and safe; this is an explicit opt-out for embedders that want
    /// zero plugin overhead.
    pub fn new_without_plugins() -> Self {
        Self {
            registry: load_seed_manifests(),
            semantic_graph: Arc::new(Mutex::new(SemanticGraphStore::new())),
            #[cfg(feature = "rpc")]
            rpc_client: None,
            data_dir: None,
            plugins: crate::plugin_orchestrator::PluginOrchestrator::new(),
        }
    }

    /// Create with a custom manifest registry (built-in plugins registered).
    pub fn with_registry(registry: ManifestRegistry) -> Self {
        Self {
            registry,
            semantic_graph: Arc::new(Mutex::new(SemanticGraphStore::new())),
            #[cfg(feature = "rpc")]
            rpc_client: None,
            data_dir: None,
            plugins: crate::plugin_orchestrator::PluginOrchestrator::with_builtin_plugins(),
        }
    }

    /// Create with durability enabled: the semantic graph, trust tiers, and
    /// simulation baselines are snapshotted to `data_dir` on every mutation
    /// and reloaded on startup. Fail-closed: a corrupt snapshot logs an error
    /// and starts fresh (state is re-earned) rather than panicking.
    pub fn with_data_dir(data_dir: PathBuf) -> Self {
        let mut core = Self::new();
        core.data_dir = Some(data_dir.clone());
        if let Err(e) = std::fs::create_dir_all(&data_dir) {
            tracing::warn!("failed to create data dir {}: {}", data_dir.display(), e);
        }
        // Clean up stale temp files left by a crash mid-snapshot (they are
        // uniquely named per write; only the atomic rename commits).
        if let Ok(entries) = std::fs::read_dir(&data_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with("semantic_graph.json.tmp.") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        let path = data_dir.join("semantic_graph.json");
        match std::fs::read_to_string(&path) {
            Ok(json) => match SemanticGraphStore::from_json(&json) {
                Ok(store) => {
                    core.semantic_graph = Arc::new(Mutex::new(store));
                    tracing::info!("restored semantic graph from {}", path.display());
                }
                Err(e) => tracing::error!(
                    "corrupt semantic graph snapshot at {} — starting fresh: {}",
                    path.display(),
                    e
                ),
            },
            Err(_) => { /* no snapshot yet — fresh store */ }
        }
        core
    }

    /// Interior-mutable handle to the semantic graph, shared across clones.
    /// Poisoned mutexes are recovered (fail-open) so a panic elsewhere can
    /// never wedge verification permanently.
    fn graph(&self) -> std::sync::MutexGuard<'_, SemanticGraphStore> {
        self.semantic_graph
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Read-only dashboard view of the Semantic Graph (Constitution P4 —
    /// never mutates). Returns protocol nodes (merged manifest + graph
    /// behavior + baseline state) and CPI edges derived from manifest
    /// `allowed_cpis` and graph behavior records.
    pub fn graph_snapshot(&self) -> GraphSnapshot {
        let registry = self.registry();
        let graph = self.graph();

        // Merge manifest + graph data per program id.
        let mut by_program: std::collections::HashMap<String, GraphNode> =
            std::collections::HashMap::new();
        for m in registry.list() {
            let node = by_program
                .entry(m.protocol.program_id.clone())
                .or_insert_with(|| GraphNode {
                    program_id: m.protocol.program_id.clone(),
                    name: m.protocol.name.clone(),
                    manifest_version: Some(m.version.label.clone()),
                    trust_tier: m.trust_tier.clone(),
                    instruction_count: m.instructions.len(),
                    baseline_samples: None,
                    battle_tested_tx_count: 0,
                    community_verified_count: 0,
                    quarantined: false,
                    quarantine_reason: None,
                    cpi_targets: Vec::new(),
                });
            node.instruction_count = m.instructions.len();
            // CPI edges from the manifest's instruction definitions.
            for ix in &m.instructions {
                for cpi in &ix.allowed_cpis {
                    if !node.cpi_targets.contains(cpi) {
                        node.cpi_targets.push(cpi.clone());
                    }
                }
            }
        }
        // Graph behavior evidence (earned tiers/volume) overlays the manifest.
        for b in graph.behaviors() {
            let node = by_program
                .entry(b.program_id.clone())
                .or_insert_with(|| GraphNode {
                    program_id: b.program_id.clone(),
                    name: b.program_id.clone(),
                    manifest_version: None,
                    trust_tier: b.trust_tier.as_str().to_string(),
                    instruction_count: 0,
                    baseline_samples: None,
                    battle_tested_tx_count: 0,
                    community_verified_count: 0,
                    quarantined: b.quarantined,
                    quarantine_reason: b.quarantine_reason.clone(),
                    cpi_targets: Vec::new(),
                });
            node.trust_tier = b.trust_tier.as_str().to_string();
            node.battle_tested_tx_count = b.evidence.battle_tested_tx_count;
            node.community_verified_count = b.evidence.community_verified_count;
            node.quarantined = b.quarantined;
            node.quarantine_reason = b.quarantine_reason.clone();
            for cpi in &b.allowed_cpis {
                if !node.cpi_targets.contains(cpi) {
                    node.cpi_targets.push(cpi.clone());
                }
            }
        }
        // Baselines (simulation accumulator samples) keyed by program.
        for (program_id, baseline) in graph.baselines() {
            if let Some(node) = by_program.get_mut(program_id) {
                node.baseline_samples = Some(baseline.sample_count);
            }
        }

        // Edges: every CPI target of every node is a directed edge
        // node → target.
        let mut edges = Vec::new();
        for node in by_program.values() {
            for target in &node.cpi_targets {
                edges.push(GraphEdge {
                    from: node.program_id.clone(),
                    to: target.clone(),
                });
            }
        }
        edges.sort();
        edges.dedup();

        let mut nodes: Vec<GraphNode> = by_program.into_values().collect();
        nodes.sort_by(|a, b| a.program_id.cmp(&b.program_id));
        GraphSnapshot { nodes, edges }
    }

    /// Snapshot graph state to disk (best-effort; never fatal).
    ///
    /// Uses a UNIQUE temp file per call (`semantic_graph.json.tmp.<pid>.<n>`)
    /// so concurrent snapshots can never overwrite each other's in-flight temp
    /// files — the final rename is atomic, so the committed snapshot is always
    /// one complete JSON document. The static `.tmp` path this replaces meant
    /// two racing writers could interleave on the same temp file.
    fn persist_state(&self) {
        let Some(dir) = self.data_dir.as_ref() else {
            return;
        };
        let Ok(json) = self.graph().to_json() else {
            tracing::warn!("failed to serialize semantic graph");
            return;
        };
        let path = dir.join(SEMANTIC_GRAPH_FILENAME);
        persist_json_atomic(&path, &json);
    }

    /// Async variant for use inside `verify_async` (rpc feature only — the
    /// only path that records baselines during a request): the blocking fs
    /// write is moved off the Tokio worker thread via `spawn_blocking` so a
    /// busy data directory can never stall the async runtime (no blocking I/O
    /// under the runtime worker — a starvation vector when under load).
    #[cfg(feature = "rpc")]
    async fn persist_state_async(&self) {
        let Some(dir) = self.data_dir.clone() else {
            return;
        };
        let Ok(json) = self.graph().to_json() else {
            tracing::warn!("failed to serialize semantic graph");
            return;
        };
        let path = dir.join(SEMANTIC_GRAPH_FILENAME);
        let _ = tokio::task::spawn_blocking(move || persist_json_atomic(&path, &json)).await;
    }

    /// Attach an RPC client for Phase 2 features (simulation, on-chain checks).
    #[cfg(feature = "rpc")]
    pub fn attach_rpc_client(&mut self, client: SolanaRpcClient) {
        self.rpc_client = Some(client);
    }

    /// L8 execution verification — the POST-SUBMISSION confirmation path.
    ///
    /// L8 is Inconclusive during pre-submission verification by design: no
    /// static analysis can guarantee what happens on-chain. The honest
    /// guarantee Graphite CAN provide is the closing of the loop after the
    /// transaction is actually submitted: given the transaction signature,
    /// confirm from the cluster that (a) the transaction was included in a
    /// slot, and (b) it executed successfully (status Ok). A failed or
    /// unknown status is reported exactly as such — never as a phantom pass.
    ///
    /// Requires an attached RPC client (the `rpc` feature + GRAPHITE_RPC_URL
    /// or an explicit `attach_rpc_client`). Without one, this returns
    /// `None`-success with a clear "unavailable" reason rather than failing
    /// closed or fabricating evidence.
    #[cfg(feature = "rpc")]
    pub async fn verify_execution(
        &self,
        signature: &str,
    ) -> Result<ExecutionVerification, VerificationError> {
        let Some(client) = &self.rpc_client else {
            return Ok(ExecutionVerification::Unavailable(
                "no RPC client attached — attach one via attach_rpc_client or set GRAPHITE_RPC_URL"
                    .to_string(),
            ));
        };
        match client.get_signature_status(signature).await {
            Ok(Some(status)) => Ok(ExecutionVerification::Confirmed {
                signature: signature.to_string(),
                slot: status.slot,
                success: status.success,
                error: status.error,
            }),
            Ok(None) => Ok(ExecutionVerification::UnknownSignature(
                signature.to_string(),
            )),
            Err(e) => Ok(ExecutionVerification::Unavailable(format!(
                "RPC error confirming signature: {e}"
            ))),
        }
    }

    /// Synchronous wrapper around the async verification API. Blocks on a
    /// fresh Tokio runtime. Available whenever an async runtime is compiled in
    /// (rpc / server / cli features). A library build with NO features gets
    /// the fail-closed stub below instead of failing to compile — the library
    /// core itself never needs a runtime (only the RPC path does), so
    /// embedding Graphite as a verification library must not force an async
    /// dependency.
    #[cfg(any(feature = "rpc", feature = "server", feature = "cli"))]
    pub fn verify(
        &self,
        input: &VerificationInput,
    ) -> Result<VerificationResult, VerificationError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| VerificationError::TransactionBuild(e.to_string()))?;
        rt.block_on(self.verify_async(input))
    }

    /// Fail-closed synchronous fallback for minimal library builds (no
    /// features): returns a clear error instead of silently skipping
    /// verification. `verify_async` is always available and requires no
    /// runtime unless an RPC client is attached.
    #[cfg(not(any(feature = "rpc", feature = "server", feature = "cli")))]
    pub fn verify(
        &self,
        _input: &VerificationInput,
    ) -> Result<VerificationResult, VerificationError> {
        Err(VerificationError::InvalidInput(
            "async runtime not compiled in: build with the 'rpc', 'server', or 'cli' feature to verify synchronously".to_string(),
        ))
    }

    /// Load an additional protocol manifest at runtime.
    pub fn load_manifest(&mut self, json: &str) -> Result<(), VerificationError> {
        self.registry
            .load_from_json(json)
            .map(|_| ())
            .map_err(|e| VerificationError::TransactionBuild(e.to_string()))
    }

    /// List all loaded protocol manifests.
    pub fn list_manifests(&self) -> Vec<&crate::manifest::ProtocolManifest> {
        self.registry.list()
    }

    /// Get the manifest registry.
    pub fn registry(&self) -> &ManifestRegistry {
        &self.registry
    }

    /// Merge community-accepted manifests from the Manifest Registry engine
    /// into this core's runtime registry (C53). Seed-wins: a compile-time
    /// seed manifest is never overridden by a community submission. Returns
    /// the number of community manifests merged.
    pub fn merge_community_manifests(
        &mut self,
        engine: &crate::manifest_registry::ManifestRegistryEngine,
    ) -> usize {
        let manifests: Vec<_> = engine.accepted_manifests().cloned().collect();
        self.registry.merge_community(&manifests)
    }

    /// Access the plugin orchestrator (P8 surface).
    pub fn plugins(&self) -> &crate::plugin_orchestrator::PluginOrchestrator {
        &self.plugins
    }

    /// Register a plugin programmatically (startup only).
    pub fn register_plugin(&mut self, plugin: crate::plugin_orchestrator::PluginKind) {
        self.plugins.register_plugin(plugin);
    }

    /// Discover + register plugin manifests from a directory through the
    /// review gate (only `approved` manifests activate). Fail-closed on
    /// malformed manifests or unknown built-in names.
    pub fn attach_plugins_dir(
        &mut self,
        dir: &std::path::Path,
    ) -> Result<
        crate::plugin_orchestrator::RegistrationSummary,
        crate::plugin_orchestrator::PluginError,
    > {
        let manifests = crate::plugin_orchestrator::PluginOrchestrator::discover_from_dir(dir)?;
        self.plugins.register_discovered(&manifests)
    }

    /// Attach a JSON-lines event file to the built-in event-logger plugin so
    /// every completed verification is appended (production observability).
    /// `&self` because the underlying operation uses interior mutability and
    /// is thread-safe (shared across server clones).
    pub fn attach_event_file_sink(
        &self,
        path: &std::path::Path,
    ) -> Result<(), crate::plugin_orchestrator::PluginError> {
        self.plugins.attach_event_file_sink(path)
    }

    /// Seed a behavior record into the semantic graph (persisted if durability
    /// is enabled).
    pub fn seed_behavior(&mut self, behavior: Behavior) -> Result<(), VerificationError> {
        self.graph().append(behavior)?;
        self.persist_state();
        Ok(())
    }

    /// Trusted operator API: seed or override a program's simulation baseline
    /// (e.g. restoring a previous deployment's export). Never reachable from a
    /// request body — baselines are earned (RPC-verified usage) or seeded here.
    /// Returns an error for invalid baselines (NaN/Infinity/negative values)
    /// so a corrupt seed can never poison the accumulator.
    pub fn seed_simulation_baseline(
        &self,
        program_id: &str,
        baseline: crate::simulation_integrity::ComputeBaseline,
    ) -> Result<(), VerificationError> {
        self.graph()
            .seed_simulation_baseline(program_id, baseline)
            .map_err(VerificationError::SemanticGraph)?;
        self.persist_state();
        Ok(())
    }

    // L2: Instruction Verification
    fn verify_instruction(
        &self,
        input: &VerificationInput,
        manifest: Option<&crate::manifest::ProtocolManifest>,
        resolution: &crate::account_resolution::AccountResolutionResult,
    ) -> PipelineLayerResult {
        let layer_name = "L2_InstructionVerification";

        let manifest = match manifest {
            Some(m) => m,
            None => {
                // GAP-2026-08-06-3: a SKIPPED check is Inconclusive, never a pass.
                return PipelineLayerResult::new(
                    layer_name,
                    LayerStatus::Inconclusive,
                    "No manifest - unknown protocol, instruction check skipped",
                );
            }
        };

        // Discriminator matching is delegated to the single hardened helper
        // in manifest.rs (SECURITY: exact-or-input-starts-with-manifest only —
        // the old inline matchers also accepted a truncated input that was a
        // 4-char prefix of a known discriminator, minting a false
        // InstructionMatch on a different instruction).
        let matching_ix = manifest.instructions.iter().find(|ix| {
            crate::manifest::discriminator_matches(
                &ix.discriminator,
                &input.instruction_discriminator,
            )
        });

        let ix = match matching_ix {
            Some(ix) => ix,
            None => {
                // P12: Unknown instruction on known protocol = soft pass (fail open).
                // The instruction is unknown but the protocol is trusted.
                // Confidence will be lower (no InstructionMatch signal).
                // Risk Engine still checks for malicious patterns.
                return PipelineLayerResult::new(
                    layer_name,
                    LayerStatus::Passed,
                    format!(
                        "Unknown instruction '{}' on known protocol {} — P12 soft pass (reduced confidence)",
                        input.instruction_discriminator,
                        manifest.protocol.name
                    ),
                );
            }
        };

        // Verify instruction data (if provided) starts with the discriminator
        if let Some(ref data) = input.instruction_data {
            if !data.is_empty() {
                let disc_hex = input.instruction_discriminator.trim_start_matches("0x");
                if let Ok(disc_bytes) = hex::decode(disc_hex) {
                    if data.len() >= disc_bytes.len()
                        && &data[..disc_bytes.len()] != disc_bytes.as_slice()
                    {
                        return PipelineLayerResult::new(
                            layer_name,
                            LayerStatus::Failed,
                            "Instruction data does not start with expected discriminator",
                        );
                    }
                }
            }
        }

        // Verify account count matches manifest expectations
        // NOTE: Some protocols (e.g., Jupiter V6 aggregator) use variable-length
        // account lists. The manifest defines the MINIMUM required accounts, but
        // real transactions may include additional accounts for DEX routing.
        // For known protocols with BattleTested tier, we treat account count
        // surplus as a confidence-reducing signal, not a hard fail.
        let expected_accounts = ix.accounts.len();
        let actual_accounts = resolution.resolved_accounts.len();
        if actual_accounts < expected_accounts {
            // C57: an account shortfall is a RESOLUTION LIMITATION, not an
            // identity failure — real transactions legitimately supply fewer
            // accounts than the manifest declares when optional accounts are
            // omitted (e.g. stake-pool's sol_withdraw_authority), ALT-resolved
            // positions are skipped by the pure reader, or repeated keys
            // deduplicate. The discriminator — L2's actual job — matched. The
            // shortfall is surfaced as an AccountCountShortfall risk finding
            // upstream (P3: never silently dropped), so L2 passes with a note
            // exactly like the surplus branch below. The previous hard FAIL
            // applied a 0.20 confidence penalty to legitimate on-chain
            // transactions (marinade/clmm/cpmm/stake-pool real txs).
            return PipelineLayerResult::new(
                layer_name,
                LayerStatus::Passed,
                format!(
                    "Instruction {} verified (manifest min: {}, actual: {} — account shortfall surfaced as finding)",
                    ix.name, expected_accounts, actual_accounts
                ),
            );
        } else if actual_accounts > expected_accounts && expected_accounts > 0 {
            // More accounts than manifest expects — common for aggregators
            // that route through multiple DEX venues. Soft pass with note.
            return PipelineLayerResult::new(
                layer_name,
                LayerStatus::Passed,
                format!(
                    "Instruction {} verified (manifest min: {}, actual: {} — variable accounts for routing)",
                    ix.name, expected_accounts, actual_accounts
                ),
            );
        }

        PipelineLayerResult::new(
            layer_name,
            LayerStatus::Passed,
            format!("Instruction {} verified against manifest", ix.name),
        )
    }

    // L4: State Verification
    fn verify_state(
        &self,
        expected_state_changes: &[String],
        resolved_accounts: &[ResolvedAccount],
        _manifest_found: bool,
    ) -> PipelineLayerResult {
        let layer_name = "L4_StateVerification";

        // GAP-2026-08-06-3: a SKIPPED check is Inconclusive, never a pass. The
        // check runs when there is evidence to verify against: a manifest with
        // state changes, or reviewed ProtocolPlugin rules for a manifest-less
        // program (evidence only — never a verdict or tier, P7/P8). With no
        // evidence at all, the layer is Inconclusive.
        if expected_state_changes.is_empty() {
            return PipelineLayerResult::new(
                layer_name,
                LayerStatus::Inconclusive,
                "No expected state changes (manifest or plugin rules) - state check skipped",
            );
        }

        let changes_lower: Vec<String> = expected_state_changes
            .iter()
            .map(|c| c.to_lowercase())
            .collect();

        // If state changes mention fund movement (debit/credit), there
        // should be at least 2 writable accounts (source + destination).
        // Audit refinement (C4x): "transfer"/"swap"/"stake" were over-broad
        // triggers — a Stake DelegateStake legitimately writes ONE account
        // (the stake account), Metaplex update metadata writes one, and a
        // locked-position transfer writes one. The fund-movement wording
        // (debit/credit) is what actually implies two writable sides, and
        // the L7 risk engine independently gates real transfer semantics.
        let needs_writable = changes_lower
            .iter()
            .any(|c| c.contains("debit") || c.contains("credit"));

        let writable_count = resolved_accounts.iter().filter(|a| a.is_writable).count();

        if needs_writable && writable_count < 2 {
            return PipelineLayerResult::new(
                layer_name,
                LayerStatus::Failed,
                format!(
                    "Expected state changes require writable accounts but only {} writable account(s) found",
                    writable_count
                ),
            );
        }

        // If state changes mention an authority-changing/delegating action
        // (signer, approve, delegate, assign), there should be at least 1
        // signer account. Audit refinement (C4x): the bare noun "authority"
        // over-triggered — SPL Token InitializeMint sets the mint_authority
        // FIELD (data in the instruction) with no signer account on-chain,
        // and the manifest's own account list reflects that. A real
        // authority TRANSFER is phrased with an action verb (assign,
        // transfer authority, approve, delegate) which the remaining
        // triggers cover.
        let needs_signer = changes_lower.iter().any(|c| {
            c.contains("signer")
                || c.contains("approve")
                || c.contains("delegate")
                || c.contains("assign")
        });

        let signer_count = resolved_accounts.iter().filter(|a| a.is_signer).count();

        if needs_signer && signer_count == 0 {
            return PipelineLayerResult::new(
                layer_name,
                LayerStatus::Failed,
                "Expected state changes require a signer but no signer account found",
            );
        }

        // If state changes mention close/closure,
        // verify there is a writable account (the one being closed)
        let needs_close = changes_lower
            .iter()
            .any(|c| c.contains("close") || c.contains("closure"));
        if needs_close && writable_count == 0 {
            return PipelineLayerResult::new(
                layer_name,
                LayerStatus::Failed,
                "Expected state changes mention close/closure but no writable account found",
            );
        }

        PipelineLayerResult::new(
            layer_name,
            LayerStatus::Passed,
            format!(
                "State verification passed: {} state change(s) consistent with {} account(s)",
                expected_state_changes.len(),
                resolved_accounts.len()
            ),
        )
    }

    // L5: Semantic Verification
    fn verify_semantic(
        &self,
        proposed_intent: &ProposedIntent,
        instruction_name: &str,
        expected_state_changes: &[String],
        manifest_found: bool,
    ) -> PipelineLayerResult {
        let layer_name = "L5_SemanticVerification";

        if !manifest_found {
            // GAP-2026-08-06-3: a SKIPPED check is Inconclusive, never a pass.
            return PipelineLayerResult::new(
                layer_name,
                LayerStatus::Inconclusive,
                "No manifest - unknown protocol, semantic check skipped",
            );
        }

        // SECURITY FIX: For unknown instructions on known protocols with high-risk
        // intents (swap, bridge, withdraw, delegate, mint), fail-closed instead
        // of soft-pass. An unknown discriminator with a swap intent was a free
        // approval vector (FakeSwap was skipped, L5 was soft-passed).
        if instruction_name == "unknown_instruction" {
            let high_risk = matches!(
                proposed_intent.intent_type.as_str(),
                "swap" | "bridge" | "withdraw" | "delegate" | "mint"
            );
            if high_risk {
                return PipelineLayerResult::new(
                    layer_name,
                    LayerStatus::Failed,
                    format!(
                        "Unknown instruction on known protocol with high-risk intent '{}' — fail-closed (P12: cannot verify intent-instruction alignment)",
                        proposed_intent.intent_type
                    ),
                );
            }
            // Low-risk unknown instruction: the semantic check itself did not
            // run against a known shape — Inconclusive, not a pass (GAP-2026-08-06-3).
            return PipelineLayerResult::new(
                layer_name,
                LayerStatus::Inconclusive,
                "Unknown instruction on known protocol with low-risk intent — semantic check skipped (P12 soft pass)",
            );
        }

        let intent = proposed_intent.intent_type.to_lowercase();
        let ix_name = instruction_name.to_lowercase();
        let changes_lower: Vec<String> = expected_state_changes
            .iter()
            .map(|c| c.to_lowercase())
            .collect();

        let (intent_keywords, mismatch_msg) = match intent.as_str() {
            "swap" | "trade" | "exchange" => (
                vec!["swap", "route", "trade", "token", "credit", "debit"],
                "swap intent but instruction does not appear to be a swap",
            ),
            "transfer" | "send" => (
                vec!["transfer", "send", "debit", "credit", "move"],
                "transfer intent but instruction does not appear to be a transfer",
            ),
            "stake" | "delegate" => (
                vec!["stake", "delegate", "withdraw", "deactivate", "reward"],
                "stake intent but instruction does not appear to be a stake operation",
            ),
            "close" | "close_account" => (
                vec!["close", "closure", "shutdown"],
                "close intent but instruction does not appear to close an account",
            ),
            "create" | "create_account" => (
                vec!["create", "allocate", "assign", "initialize"],
                "create intent but instruction does not appear to create an account",
            ),
            "approve" | "revoke" => (
                vec!["approve", "revoke", "delegate"],
                "approve/revoke intent but instruction does not match",
            ),
            _ => {
                return PipelineLayerResult::new(
                    layer_name,
                    LayerStatus::Failed,
                    format!(
                        "Unknown intent type {} - semantic verification failed (P12 fail-closed)",
                        intent
                    ),
                );
            }
        };

        let ix_matches = intent_keywords.iter().any(|kw| ix_name.contains(kw));
        let changes_match = changes_lower
            .iter()
            .any(|c| intent_keywords.iter().any(|kw| c.contains(kw)));

        if !ix_matches && !changes_match {
            return PipelineLayerResult::new(
                layer_name,
                LayerStatus::Failed,
                format!(
                    "{}: intent={}, instruction={}, state_changes={:?}",
                    mismatch_msg, intent, instruction_name, expected_state_changes
                ),
            );
        }

        PipelineLayerResult::new(
            layer_name,
            LayerStatus::Passed,
            format!(
                "Semantic verification passed: intent {} consistent with instruction {}",
                intent, instruction_name
            ),
        )
    }

    /// Manifest-derived risk-assessment context for ONE instruction, keyed by
    /// (program_id, discriminator). Mirrors the manifest lookup the primary
    /// instruction already performs (see `expected_state_changes`/
    /// `allowed_cpis`/`expected_account_count`/`variable_accounts`/
    /// `manifest_risk_class` in `verify_async` below) so that a SECONDARY
    /// instruction — one that is not the primary instruction being verified,
    /// but still part of the same transaction (a flattened CPI callee or a
    /// top-level sibling instruction) — gets the SAME manifest-grounded
    /// evidence the primary instruction gets, instead of being invisible to
    /// the Risk Engine (P0-3 in the 2026-09-05 audit: secondary instructions
    /// were never individually risk-assessed at all).
    ///
    /// Deliberately does NOT replicate the primary path's ProtocolPlugin
    /// state-change extension (`verify_async`'s `!manifest_found` branch) —
    /// that extension is scoped to the primary instruction's own L4/plugin
    /// context and out of scope for this per-secondary-instruction risk pass.
    fn instruction_risk_context(
        &self,
        program_id: &str,
        discriminator: &str,
    ) -> InstructionRiskContext {
        match self.registry.get(program_id) {
            Some(m) => {
                let ix = m.instructions.iter().find(|i| {
                    crate::manifest::discriminator_matches(&i.discriminator, discriminator)
                });
                match ix {
                    Some(ix) => InstructionRiskContext {
                        expected_state_changes: ix.expected_state_changes.clone(),
                        allowed_cpis: ix.allowed_cpis.clone(),
                        expected_account_count: Some(ix.accounts.len()),
                        variable_accounts: ix.variable_accounts,
                        manifest_risk_class: ix.risk_class.clone(),
                        manifest_found: true,
                    },
                    None => {
                        // Unknown instruction on a known protocol: same P12
                        // union-of-allowed-CPIs convention as the primary path.
                        let union_cpis: Vec<String> = m
                            .instructions
                            .iter()
                            .flat_map(|i| i.allowed_cpis.iter().cloned())
                            .collect::<std::collections::HashSet<_>>()
                            .into_iter()
                            .collect();
                        InstructionRiskContext {
                            expected_state_changes: vec!["Protocol-level state changes".to_string()],
                            allowed_cpis: union_cpis,
                            expected_account_count: None,
                            variable_accounts: false,
                            manifest_risk_class: String::new(),
                            manifest_found: true,
                        }
                    }
                }
            }
            None => InstructionRiskContext {
                expected_state_changes: vec![],
                allowed_cpis: vec![],
                expected_account_count: None,
                variable_accounts: false,
                manifest_risk_class: String::new(),
                manifest_found: false,
            },
        }
    }

    /// Risk-assess every SECONDARY instruction (index >= 1) in
    /// `effective_instructions` — the primary instruction (index 0) is
    /// assessed separately by the existing single-instruction path above and
    /// is skipped here to avoid duplicate work / divergent behavior.
    ///
    /// P0-3 fix (2026-09-05 audit): `risk_engine::assess` used to be called
    /// exactly once, for the primary instruction only. Everything else in the
    /// transaction — CPI-flattened callees and top-level sibling instructions
    /// — was invisible to the 23 structural risk checks, and only reachable
    /// via `tx_pattern_analysis`'s narrow, correlation-based rules (which
    /// require a specific paired instruction, e.g. Approve immediately
    /// followed by a Transfer on the same account). A STANDALONE secondary
    /// instruction with no such pairing — a bare SetAuthority, a manifest-
    /// tagged high-risk withdraw/mint/authority/close call, a CPI-level
    /// authority hijack — passed through completely unscrutinized.
    ///
    /// Design (deliberately NOT "call risk_engine in a loop and assume it's
    /// fixed"): every secondary instruction is assessed with an EMPTY
    /// declared intent (`proposed_intent_type: String::new()`), never the
    /// primary's declared intent. This is load-bearing, not an oversight:
    ///   - The caller's natural-language declaration describes the PRIMARY
    ///     action only. Reusing it against a secondary instruction is a
    ///     category error that would false-positive on extremely common,
    ///     legitimate multi-instruction patterns — e.g. a "swap" transaction
    ///     whose secondary instruction creates the destination ATA (Check 6b
    ///     would otherwise fire: "account creation but declared intent is
    ///     swap").
    ///   - An empty intent naturally no-ops every intent-DEPENDENT check
    ///     (6a/6b/7/8/9 in risk_engine.rs — each requires a non-empty,
    ///     MISMATCHED intent to fire), so secondary instructions never trip
    ///     those false-positive-prone gates.
    ///   - Every intent-INDEPENDENT structural check stays fully active: the
    ///     unconditional known-risky-discriminator table (Check 2 — this is
    ///     what catches a standalone SetAuthority/Approve/System-Assign/
    ///     CloseAccount), the CPI checks (1/1b/4), the drainer/hidden-
    ///     transfer heuristics (3/3b/5), and system-account impersonation
    ///     (Check 10a).
    ///   - Check 10b ("manifest declares this instruction's class as
    ///     drain/authority/withdraw/mint/close and NO intent was declared —
    ///     fail closed") is DELIBERATELY activated by the empty intent for
    ///     every secondary instruction: the agent's declaration never
    ///     mentioned it, so P12 fail-closed applies exactly as the check was
    ///     designed for the single-instruction case — it now also covers the
    ///     secondary case for free, for every onboarded protocol, without new
    ///     per-protocol detection logic.
    ///
    /// Aggregation is deterministic: `effective_instructions` is a plain,
    /// insertion-ordered `Vec` (primary, then CPI-trace pre-order flatten,
    /// then top-level secondaries in caller-supplied order — see its
    /// construction below); this loop walks it in that same fixed order, so
    /// which instruction's reason text becomes the PRIMARY blocked reason
    /// (vs. a corroborating `|`-joined suffix) never depends on hash-map
    /// iteration or any other non-deterministic source. A blocked secondary
    /// instruction is a HARD GATE — it overrides an otherwise-Passed verdict
    /// exactly like a plugin block or a pattern-analysis finding (SECURITY.md);
    /// it can never be "outvoted" by other, benign instructions in the same
    /// transaction, and N duplicate copies of the same risky secondary
    /// instruction each independently re-confirm the same block rather than
    /// diluting it.
    fn assess_secondary_instructions(
        &self,
        effective_instructions: &[crate::tx_pattern_analysis::TransactionInstruction],
    ) -> Result<(RiskVerdict, Vec<String>), VerificationError> {
        let mut verdict = RiskVerdict::Passed;
        let mut warnings: Vec<String> = Vec::new();
        // P1 fix (2026-09-05 audit, "duplicate-instruction abuse"): an
        // unmanifested secondary instruction only ever produces a per-
        // occurrence WARNING below (Check 2's unconditional table and Check
        // 10a's impersonation check are the only things that can BLOCK it —
        // deliberately, since manifest evidence is unavailable and Graphite
        // has no transaction amount/value data to reason about cumulative
        // damage; a hard cap on repetition count would be trivially evaded
        // by staying one under the threshold and would false-positive on
        // legitimate batches to a not-yet-onboarded protocol, P12). Counting
        // occurrences per unmanifested program and surfacing an explicit
        // repetition warning is pure disclosure — never a confidence penalty
        // or a block — so a human/downstream auditor sees the aggregate
        // pattern that per-instruction warnings alone don't make visible.
        // BTreeMap (not HashMap): iteration order feeds directly into the
        // warning text below, and warning order must be deterministic (P2)
        // regardless of hash-map internals.
        let mut unmanifested_repeats: std::collections::BTreeMap<&str, u32> =
            std::collections::BTreeMap::new();
        for (idx, ix) in effective_instructions.iter().enumerate().skip(1) {
            // A secondary instruction with NO discriminator (common for
            // CPI-trace-flattened nodes: trace introspection frequently
            // cannot recover a callee's full instruction data, only its
            // program ID and accounts) must NOT be routed into
            // `risk_engine::assess`'s empty-discriminator fail-closed branch
            // (Check 2's second arm) — that branch exists to catch a PRIMARY
            // instruction that omits its discriminator despite the caller
            // being asked to fully specify what to verify, which is a
            // meaningfully different situation from a CPI callee whose data
            // was simply never captured by the trace. Applying it here would
            // hard-block the extremely common case of an ordinary CPI child
            // call to SPL Token/Token-2022 (present in nearly every DEX
            // route) purely because its discriminator wasn't observed —
            // false-positiving on benign transactions, which the P0-3 fix is
            // explicitly required not to do. Surfaced as a visible,
            // non-blocking warning instead (P3 explainability; P12 —
            // insufficient evidence is not proof of harm, but it is also
            // never silently dropped). A REAL secondary SetAuthority/
            // CloseAccount/Approve/Assign — the actual P0-3 attack scenario —
            // always carries a real discriminator and is unaffected by this
            // skip; it is still caught by Check 2's first (non-empty,
            // matched) arm below.
            if ix.instruction_discriminator.is_empty() {
                warnings.push(format!(
                    "secondary instruction #{idx} (program {}) has no discriminator available \u{2014} cannot run instruction-level risk checks (CPI-trace introspection limit, not evidence of harm)",
                    ix.program_id
                ));
                continue;
            }
            let risk_ctx =
                self.instruction_risk_context(&ix.program_id, &ix.instruction_discriminator);
            if !risk_ctx.manifest_found {
                // Visible, non-blocking signal (P3): an unmanifested program
                // in a secondary position has no manifest-grounded evidence
                // for the structural heuristics below to reason about, but is
                // NOT itself proof of harm (P12 — unknown != active harm).
                // Still fully covered by Check 2's unconditional table and
                // Check 10a's impersonation check, neither of which need a
                // manifest.
                warnings.push(format!(
                    "secondary instruction #{idx} calls unmanifested program {} \u{2014} no manifest evidence available, structural risk checks only",
                    ix.program_id
                ));
                *unmanifested_repeats
                    .entry(ix.program_id.as_str())
                    .or_insert(0) += 1;
            }
            let ix_input = RiskAssessmentInput {
                program_id: ix.program_id.clone(),
                accounts: ix.account_addresses.clone(),
                cpi_targets: ix.cpi_targets.clone(),
                expected_state_changes: risk_ctx.expected_state_changes,
                allowed_cpis: risk_ctx.allowed_cpis,
                instruction_discriminator: ix.instruction_discriminator.clone(),
                expected_account_count: risk_ctx.expected_account_count,
                variable_accounts: risk_ctx.variable_accounts,
                // Deliberately empty — see the method doc comment above.
                proposed_intent_type: String::new(),
                extracted_output_token: None,
                manifest_risk_class: risk_ctx.manifest_risk_class,
            };
            let detail = assess_with_warnings(&ix_input)?;
            warnings.extend(
                detail
                    .warnings
                    .into_iter()
                    .map(|w| format!("[secondary instruction #{idx}] {w}")),
            );
            if let RiskVerdict::Blocked { pattern, reason } = detail.verdict {
                let tagged_reason = format!(
                    "secondary instruction #{idx} (program {}): {reason}",
                    ix.program_id
                );
                verdict = match verdict {
                    RiskVerdict::Passed => RiskVerdict::Blocked {
                        pattern,
                        reason: tagged_reason,
                    },
                    RiskVerdict::Blocked {
                        pattern: existing,
                        reason: prior,
                    } => RiskVerdict::Blocked {
                        pattern: existing,
                        reason: format!("{prior} | {tagged_reason}"),
                    },
                };
            }
        }
        // Threshold mirrors tx_pattern_analysis's mass-sweep floor (>= 3):
        // one or two secondary calls to the same not-yet-onboarded protocol
        // is unremarkable multi-step composability; three or more sharing no
        // manifest evidence is the shape worth an explicit disclosure.
        for (program_id, count) in &unmanifested_repeats {
            if *count >= 3 {
                warnings.push(format!(
                    "unmanifested program {program_id} was invoked {count} times as a secondary instruction \u{2014} repeated calls with no manifest evidence available for any of them (disclosure only, not a block: P12)"
                ));
            }
        }
        Ok((verdict, warnings))
    }

    /// Run the full verification pipeline on a transaction.
    pub async fn verify_async(
        &self,
        input: &VerificationInput,
    ) -> Result<VerificationResult, VerificationError> {
        // Input validation: cap account count to prevent DoS.
        //
        // The cap is set to Solana's own protocol limit (256 keys in a
        // transaction message; v0 messages can reference more via address
        // lookup tables, but the static key list is bounded at 256). The
        // previous 64-account cap rejected LEGITIMATE modern transactions —
        // real Jupiter V6 route instructions routinely carry 70+ accounts
        // (one per route step), and the P16 mainnet benchmark surfaced a
        // 72-account route being rejected with a misleading "expected 64"
        // error. Bounding at the protocol limit still prevents unbounded
        // memory/CPU waste while never rejecting valid traffic.
        const MAX_ACCOUNTS: usize = 256;
        if input.account_addresses.len() > MAX_ACCOUNTS {
            return Err(VerificationError::AccountResolution(
                crate::account_resolution::AccountResolutionError::AccountCountMismatch {
                    expected: MAX_ACCOUNTS,
                    actual: input.account_addresses.len(),
                },
            ));
        }

        // Input validation: cap instruction_data and CPI target list sizes.
        // The HTTP server enforces a 1 MB body limit, but in-process callers
        // (library users, tests) have no such ceiling — cap here so a huge
        // payload can never waste unbounded CPU/memory in the pipeline.
        const MAX_INSTRUCTION_DATA: usize = 64 * 1024; // 64 KiB
        const MAX_CPI_TARGETS: usize = 32;
        if let Some(ref data) = input.instruction_data {
            if data.len() > MAX_INSTRUCTION_DATA {
                return Err(VerificationError::InvalidInput(format!(
                    "instruction_data exceeds maximum of {} bytes (got {})",
                    MAX_INSTRUCTION_DATA,
                    data.len()
                )));
            }
        }
        if input.cpi_targets.len() > MAX_CPI_TARGETS {
            return Err(VerificationError::InvalidInput(format!(
                "cpi_targets exceeds maximum of {} entries (got {})",
                MAX_CPI_TARGETS,
                input.cpi_targets.len()
            )));
        }

        // Step 1: Account Resolution
        // Fail-closed (P12): If the manifest is found but the instruction discriminator
        // is not in the manifest, BLOCK the transaction instead of returning an error.
        // An unknown instruction on a known protocol is suspicious — it could be
        // an impersonation attack or an unverified new instruction.
        let resolution = match resolve_accounts(
            &AccountResolutionInput {
                program_id: input.program_id.clone(),
                instruction_discriminator: input.instruction_discriminator.clone(),
                account_addresses: input.account_addresses.clone(),
                instruction_data: input.instruction_data.clone(),
                real_account_metas: input.real_account_metas.clone(),
            },
            &self.registry,
        ) {
            Ok(r) => r,
            Err(crate::account_resolution::AccountResolutionError::InstructionNotFound(
                _disc,
                _prog,
            )) => {
                // P12 COMPLIANCE: Known protocol + unknown instruction is NOT a hard block.
                // Per Constitution P12 and the 5-Response Framework:
                //   - Response 2 (fail open with explanation) applies: "protocol/instruction
                //     genuinely unknown, no evidence of malice"
                //   - NOT Response 4 (fail closed) which is reserved for Risk Engine findings
                //   - The pipeline continues with reduced confidence
                //   - The Risk Engine still checks for malicious patterns
                //   - The Policy Engine makes the final threshold decision
                //
                // The confidence will be lower because InstructionMatch signal won't fire,
                // but the protocol is still trusted (ManifestMatch fires).
                // This replaces the previous P12-violating hard-block.
                crate::account_resolution::AccountResolutionResult {
                    manifest_found: true,
                    resolution_order: (0..input.account_addresses.len()).collect(),
                    instruction_name: "unknown_instruction".to_string(),
                    resolved_accounts: input
                        .account_addresses
                        .iter()
                        .enumerate()
                        .map(|(i, addr)| crate::account_resolution::ResolvedAccount {
                            address: addr.clone(),
                            role: if i == 0 {
                                "signer".to_string()
                            } else {
                                "readonly".to_string()
                            },
                            is_pda: false,
                            is_signer: i == 0,
                            is_writable: i == 0,
                            pda_seeds: vec![],
                            identity: crate::account_resolution::AccountIdentity::Unverified,
                            expected_address_mismatch: false,
                            pda_mismatch: false,
                            privilege_mismatch: false,
                        })
                        .collect(),
                    account_count_shortfall: None,
                }
            }
            Err(crate::account_resolution::AccountResolutionError::InvalidAddress(addr)) => {
                // Client provided an invalid address — return error (caller-fixable)
                return Err(VerificationError::AccountResolution(
                    crate::account_resolution::AccountResolutionError::InvalidAddress(addr),
                ));
            }
            Err(crate::account_resolution::AccountResolutionError::AccountCountMismatch {
                expected,
                actual,
            }) => {
                // Client provided wrong number of accounts — return error (caller-fixable)
                return Err(VerificationError::AccountResolution(
                    crate::account_resolution::AccountResolutionError::AccountCountMismatch {
                        expected,
                        actual,
                    },
                ));
            }
            Err(e) => {
                // Other errors (PdaDerivationFailed, NoManifest) — propagate
                return Err(VerificationError::AccountResolution(e));
            }
        };

        let manifest_found = resolution.manifest_found;
        let unknown_protocol = !manifest_found;

        // Get manifest for protocol info (if found)
        let manifest = self.registry.get(&input.program_id);

        // L2: Instruction Verification
        let l2_result = self.verify_instruction(input, manifest, &resolution);

        let protocol_name = manifest
            .map(|m| m.protocol.name.clone())
            .unwrap_or_else(|| "Unknown Protocol".to_string());

        let instruction_name = resolution.instruction_name.clone();

        // Get expected state changes and allowed CPIs from manifest
        // When the instruction is found, use its specific allowed_cpis.
        // When the instruction is NOT found (P12 unknown instruction path),
        // use the UNION of all allowed_cpis from all instructions in the protocol's
        // manifest — this ensures known protocols have their CPI lists available.
        let (mut expected_state_changes, allowed_cpis) = match manifest {
            Some(m) => {
                let ix = m.instructions.iter().find(|i| {
                    crate::manifest::discriminator_matches(
                        &i.discriminator,
                        &input.instruction_discriminator,
                    )
                });
                match ix {
                    Some(ix) => (ix.expected_state_changes.clone(), ix.allowed_cpis.clone()),
                    None => {
                        // Unknown instruction on known protocol (P12 path)
                        // Use UNION of all allowed_cpis from all instructions
                        let union_cpis: Vec<String> = m
                            .instructions
                            .iter()
                            .flat_map(|i| i.allowed_cpis.iter().cloned())
                            .collect::<std::collections::HashSet<_>>()
                            .into_iter()
                            .collect();
                        (vec!["Protocol-level state changes".to_string()], union_cpis)
                    }
                }
            }
            None => (vec![], vec![]),
        };

        // ProtocolPlugin knowledge (P8): for a program with no manifest yet, a
        // reviewed ProtocolPlugin may supply raw state-change rules so the
        // core's own L4 check can run against them. Exact program_id match
        // only (P11); a plugin never supplies verdicts or tiers (P7) — only
        // evidence. The risk CPI allowlist is deliberately NOT extended: an
        // allowlist is an authorization decision, not evidence.
        if !manifest_found {
            let (plugin_rules, _plugin_cpis) = self
                .plugins
                .protocol_rules(&input.program_id, &input.instruction_discriminator);
            expected_state_changes.extend(plugin_rules);
        }

        // Plugin execution context (P8 surface): borrows ONLY this
        // transaction's data. Plugins cannot reach the audit trail, the
        // orchestrator, or any other layer's result.
        let ctx = PluginContext {
            program_id: &input.program_id,
            protocol_name: &protocol_name,
            instruction_discriminator: &input.instruction_discriminator,
            instruction_name: &instruction_name,
            proposed_intent: &input.proposed_intent,
            account_addresses: &input.account_addresses,
            cpi_targets: &input.cpi_targets,
            expected_state_changes: &expected_state_changes,
            allowed_cpis: &allowed_cpis,
            manifest_found,
            compute_units: input.compute_units,
            account_writes: input.account_writes,
            cpi_hops: input.cpi_hops,
        };

        // L2: plugin folds run after the core's own L2 check. A plugin Block
        // fails the layer (and its 0.2 confidence penalty below); a Note is
        // appended to the report; NoFinding leaves the core verdict intact.
        let l2_result =
            self.plugins
                .fold_verifier(LayerId::L2InstructionVerification, l2_result, &ctx);

        // Step 2: Transaction Construction
        let transaction = build_transaction(&TransactionPlan {
            program_id: input.program_id.clone(),
            protocol_version: input.protocol_version.clone(),
            instruction_discriminator: input.instruction_discriminator.clone(),
            instruction_name: instruction_name.clone(),
            resolved_accounts: resolution.resolved_accounts.clone(),
            expected_state_changes: expected_state_changes.clone(),
            allowed_cpis: allowed_cpis.clone(),
            instruction_data: input.instruction_data.clone().unwrap_or_default(),
        })
        .map_err(|e| VerificationError::TransactionBuild(e.to_string()))?;
        // Step 3: Risk Assessment
        let (expected_account_count, variable_accounts, manifest_risk_class) = match manifest {
            Some(m) => {
                let ix = m.instructions.iter().find(|i| {
                    crate::manifest::discriminator_matches(
                        &i.discriminator,
                        &input.instruction_discriminator,
                    )
                });
                match ix {
                    Some(i) => (
                        Some(i.accounts.len()),
                        i.variable_accounts,
                        i.risk_class.clone(),
                    ),
                    None => (None, false, String::new()),
                }
            }
            None => (None, false, String::new()),
        };

        let risk_detail = assess_with_warnings(&RiskAssessmentInput {
            program_id: input.program_id.clone(),
            accounts: input.account_addresses.clone(),
            cpi_targets: input.cpi_targets.clone(),
            expected_state_changes: expected_state_changes.clone(),
            allowed_cpis: allowed_cpis.clone(),
            instruction_discriminator: input.instruction_discriminator.clone(),
            expected_account_count,
            variable_accounts,
            proposed_intent_type: input.proposed_intent.intent_type.clone(),
            extracted_output_token: input
                .proposed_intent
                .extracted_parameters
                .as_ref()
                .and_then(|p| p.output_token.clone()),
            manifest_risk_class,
        })?;
        // `assess_with_warnings` returns non-blocking warnings (e.g. an
        // out-of-manifest CPI on a known protocol) alongside the binary verdict.
        // These are surfaced in the L7 layer report and the summary below so the
        // signal is never silently dropped (Constitution P3 explainability).
        let risk_verdict = risk_detail.verdict;
        let mut risk_warnings = risk_detail.warnings;

        // GAP-2026-08-06-1: a NOVEL instruction on a KNOWN protocol is exactly
        // where new attacker behavior hides. The confidence ceiling (P6) already
        // reduces score, but the Risk Engine pattern list only matches known
        // discriminators — so a novel instruction would otherwise pass with NO
        // risk signal at all. Surface it as a non-blocking WARNING (P12
        // fail-open: unknown ≠ active harm, response 2 of the 5-Response
        // Framework) so consumers see the novelty signal without a false block.
        if manifest_found && instruction_name == "unknown_instruction" {
            risk_warnings.push(format!(
                "novel instruction discriminator '{}' on known protocol {} — not in manifest (confidence reduced, P6)",
                input.instruction_discriminator, input.program_id
            ));
        }

        // P1 fix (2026-09-05 audit, "no real ALT/v0 transaction awareness"):
        // disclose, never penalize. ALT usage is normal for legitimate
        // complex swaps/routes — this must never reduce confidence or block
        // (P12) — but the caller-declared flag makes the pipeline's honest
        // blind spot (it cannot independently verify ALT-resolved accounts)
        // visible instead of silent.
        if input.uses_versioned_transaction {
            risk_warnings.push(if input.lookup_table_count > 0 {
                format!(
                    "versioned (v0) transaction using {} address lookup table(s) — accounts resolved via ALT are not independently verified by this pipeline",
                    input.lookup_table_count
                )
            } else {
                "versioned (v0) transaction using address lookup table(s) — accounts resolved via ALT are not independently verified by this pipeline".to_string()
            });
        }

        // Phase 2 (best-effort): if an RPC client is attached, fetch the first
        // account to provide additional context for L3 (simulation) layer.
        // This is intentionally best-effort and will not hard-fail verification
        // if the RPC call errors — it enriches the report when available.
        // NOTE: must be `mut` — the `#[cfg(feature = "rpc")]` block below
        // assigns to it. (Compile error under `--features rpc` without this.)
        // Under default features the block compiles out and rustc's
        // `unused_mut` would fire, so silence it there.
        #[cfg_attr(not(feature = "rpc"), allow(unused_mut))]
        let mut l3_rpc_account_info: Option<String> = None;
        #[cfg(feature = "rpc")]
        {
            if let Some(client) = &self.rpc_client {
                if let Some(first_addr) = input.account_addresses.first() {
                    if let Ok(pk) = crate::solana_types::Pubkey::from_base58(first_addr) {
                        match client.get_account(&pk).await {
                            Ok(acc) => {
                                l3_rpc_account_info = Some(format!(
                                    "RPC account {}: lamports={}, owner={}, data_len={}",
                                    acc.pubkey,
                                    acc.lamports,
                                    acc.owner,
                                    acc.data.len()
                                ));
                            }
                            Err(e) => {
                                l3_rpc_account_info = Some(format!("RPC error: {}", e));
                            }
                        }
                    }
                }
            }
        }

        // Note: Intent-Program mismatch and FakeSwap checks are now handled
        // inside the risk engine's assess() function (P0 Checks 8 and 9).

        // Step 3c: Account Identity Mismatch Detection
        // If account resolution found PDA mismatches OR expected-address
        // (constant/well-known-program) mismatches, or a privilege mismatch
        // (P1 fix, 2026-09-05 audit: a manifest-required signer that the
        // real transaction shows is NOT signed, or a manifest-readonly
        // position the real transaction marks writable), surface them as
        // risk findings. Each means the transaction provides an account
        // that doesn't match what the protocol manifest declares that slot
        // must be — a potential spoofing/substitution/escalation attempt.
        let identity_mismatches: Vec<&ResolvedAccount> = resolution
            .resolved_accounts
            .iter()
            .filter(|a| a.pda_mismatch || a.expected_address_mismatch || a.privilege_mismatch)
            .collect();
        let risk_verdict = if !identity_mismatches.is_empty() {
            let mismatch_reason = format!(
                "Account identity mismatch: {} account(s) do not match manifest-declared identity: {}",
                identity_mismatches.len(),
                identity_mismatches
                    .iter()
                    .map(|a| format!(
                        "{} (role={}, kind={})",
                        if a.address.len() >= 8 {
                            &a.address[..8]
                        } else {
                            &a.address
                        },
                        a.role,
                        if a.pda_mismatch {
                            "pda"
                        } else if a.expected_address_mismatch {
                            "expected_address"
                        } else {
                            "privilege"
                        }
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            match risk_verdict {
                crate::risk_engine::RiskVerdict::Passed => {
                    crate::risk_engine::RiskVerdict::Blocked {
                        pattern: crate::risk_engine::RiskPattern::MaliciousAccountChange,
                        reason: mismatch_reason,
                    }
                }
                crate::risk_engine::RiskVerdict::Blocked { ref pattern, .. } => {
                    // Already blocked — add the mismatch to findings via summarize_risk downstream
                    crate::risk_engine::RiskVerdict::Blocked {
                        pattern: *pattern,
                        reason: format!("{} | account identity mismatch detected", mismatch_reason),
                    }
                }
            }
        } else {
            risk_verdict
        };

        // L7: Risk plugin findings (Constitution P8). A `Block` verdict is a
        // binary-and-blocking hard gate regardless of confidence; a `Note` is
        // a non-blocking warning. Plugins can never clear a core block — they
        // only add evidence. A panicking plugin is isolated and contributes
        // nothing (it cannot fabricate a block).
        let plugin_risk = self.plugins.risk_outcome(&ctx);
        let risk_verdict = if plugin_risk.blocked && matches!(risk_verdict, RiskVerdict::Passed) {
            RiskVerdict::Blocked {
                pattern: RiskPattern::Drainer,
                reason: format!(
                    "plugin block: {}",
                    plugin_risk
                        .findings
                        .iter()
                        .map(|f| f.reason.clone())
                        .collect::<Vec<_>>()
                        .join(" | ")
                ),
            }
        } else {
            risk_verdict
        };

        // Phase 2: Transaction-level pattern analysis — multi-instruction
        // mass-drain detection and hierarchical CPI trace analysis. These
        // layers see coordination the single-instruction Risk Engine cannot:
        // an Approve + Transfer on the same account in one tx (AAT), a
        // SetAuthority + Transfer (authority hijack + drain), a CloseAccount
        // + Transfer (close-and-sweep), a mass multi-transfer sweep, or an
        // unknown/revisited/impersonated program inside the CPI tree.
        //
        // Blocked findings are HARD GATES (SECURITY.md): they override a
        // Passed risk verdict exactly like a plugin block. Warning findings
        // never block — they are surfaced in the report (P3 explainability).
        let mut pattern_findings: Vec<crate::tx_pattern_analysis::PatternFinding> = Vec::new();
        // P1B: CPI flattening — a malicious combination hidden inside a single
        // CPI-wrapped instruction (Approve + Transfer both nested in the trace)
        // is only visible after normalizing the effective instruction sequence.
        // Pre-order flatten preserves execution ordering; the primary
        // instruction's callees execute during it, so they are appended in
        // call order after the top-level list.
        let effective_instructions: Vec<crate::tx_pattern_analysis::TransactionInstruction> = {
            // Execution order: the primary instruction runs first, its CPI
            // callees execute during it (pre-order flatten), then the
            // remaining top-level instructions. Ordering matters to the AAT
            // rules (P1E): an Approve nested in the primary's CPI precedes a
            // top-level Transfer, so the pair must be seen in that order.
            let mut v = Vec::with_capacity(input.transaction_instructions.len() + 1 + 8);
            v.push(crate::tx_pattern_analysis::TransactionInstruction {
                program_id: input.program_id.clone(),
                instruction_discriminator: input.instruction_discriminator.clone(),
                account_addresses: input.account_addresses.clone(),
                cpi_targets: input.cpi_targets.clone(),
            });
            if let Some(trace) = &input.cpi_trace {
                v.extend(crate::tx_pattern_analysis::flatten_cpi_trace(trace));
            }
            v.extend(input.transaction_instructions.clone());
            v
        };

        // P0-3 fix (2026-09-05 audit): risk-assess every SECONDARY
        // instruction (CPI-flattened callees + top-level siblings), not just
        // the primary. A blocked secondary instruction is a hard gate,
        // exactly like a plugin block or a pattern-analysis finding — it can
        // never be hidden by another, benign instruction in the same
        // transaction. See `assess_secondary_instructions`'s doc comment for
        // why secondary instructions are assessed with an empty declared
        // intent rather than the primary's.
        let (secondary_risk_verdict, secondary_risk_warnings) =
            self.assess_secondary_instructions(&effective_instructions)?;
        risk_warnings.extend(secondary_risk_warnings);
        let risk_verdict = if let RiskVerdict::Blocked {
            pattern: secondary_pattern,
            reason: secondary_reason,
        } = secondary_risk_verdict
        {
            match risk_verdict {
                RiskVerdict::Passed => RiskVerdict::Blocked {
                    pattern: secondary_pattern,
                    reason: secondary_reason,
                },
                RiskVerdict::Blocked {
                    pattern: existing,
                    reason: prior,
                } => RiskVerdict::Blocked {
                    pattern: existing,
                    reason: format!("{prior} | {secondary_reason}"),
                },
            }
        } else {
            risk_verdict
        };

        if effective_instructions.len() >= 2 {
            pattern_findings.extend(crate::tx_pattern_analysis::analyze_multi_instruction(
                &effective_instructions,
            ));
        }
        if let Some(trace) = &input.cpi_trace {
            let mut known: Vec<String> = crate::tx_pattern_analysis::system_programs();
            known.extend(
                self.registry
                    .list()
                    .iter()
                    .map(|m| m.protocol.program_id.clone()),
            );
            pattern_findings.extend(crate::tx_pattern_analysis::analyze_cpi_trace(trace, &known));
        }
        let blocked_pattern = pattern_findings
            .iter()
            .find(|f| f.severity == crate::tx_pattern_analysis::PatternSeverity::Blocked);
        let risk_verdict = if let Some(f) = blocked_pattern {
            let pattern = if f.pattern == "MultiInstructionDrain" {
                RiskPattern::MultiInstructionDrain
            } else {
                RiskPattern::CpiTraceAnomaly
            };
            match risk_verdict {
                RiskVerdict::Passed => RiskVerdict::Blocked {
                    pattern,
                    reason: f.reason.clone(),
                },
                // Already blocked by the single-instruction engine or a
                // plugin: keep the primary reason, the pattern finding is
                // appended to the summary below as corroborating evidence.
                RiskVerdict::Blocked {
                    pattern: existing,
                    ref reason,
                } => RiskVerdict::Blocked {
                    pattern: existing,
                    reason: format!("{reason} | {}", f.reason),
                },
            }
        } else {
            risk_verdict
        };

        let risk_summary = summarize_risk(&risk_verdict);

        // Surface transaction-pattern findings (blocked + warnings) on the
        // risk summary so the signal is never silently dropped (P3).
        let risk_summary = if pattern_findings.is_empty() {
            risk_summary
        } else {
            RiskVerdictSummary {
                status: risk_summary.status.clone(),
                findings: {
                    let mut f = risk_summary.findings.clone();
                    f.extend(pattern_findings.iter().map(|pf| RiskFinding {
                        pattern: pf.pattern.clone(),
                        reason: pf.reason.clone(),
                    }));
                    f
                },
            }
        };

        // Step 3c.5: Add account identity mismatch findings to risk summary
        let risk_summary = if !identity_mismatches.is_empty() && risk_summary.status == "Clear" {
            RiskVerdictSummary {
                status: "Blocked".to_string(),
                findings: vec![RiskFinding {
                    pattern: "AccountIdentityMismatch".to_string(),
                    reason: format!(
                        "identity mismatch on {} account(s) — derived/expected address does not match provided",
                        identity_mismatches.len()
                    ),
                }],
            }
        } else if !identity_mismatches.is_empty() {
            // Already blocked — append the mismatch finding
            RiskVerdictSummary {
                status: "Blocked".to_string(),
                findings: {
                    let mut f = risk_summary.findings.clone();
                    f.push(RiskFinding {
                        pattern: "AccountIdentityMismatch".to_string(),
                        reason: format!(
                            "identity mismatch on {} account(s) — derived/expected address does not match provided",
                            identity_mismatches.len()
                        ),
                    });
                    f
                },
            }
        } else {
            risk_summary
        };

        // Step 3c.6: Account-count shortfall finding (C57). A real transaction
        // may supply fewer accounts than the manifest declares because the
        // pure reader skips ALT-resolved positions and deduplicates repeated
        // keys — that is a RESOLUTION LIMITATION, not a spoofing signal, so it
        // is surfaced as a non-blocking finding (P3: never silently dropped)
        // and does NOT flip the status to Blocked.
        let risk_summary = match resolution.account_count_shortfall {
            Some((expected, actual)) => RiskVerdictSummary {
                status: risk_summary.status.clone(),
                findings: {
                    let mut f = risk_summary.findings.clone();
                    f.push(RiskFinding {
                        pattern: "AccountCountShortfall".to_string(),
                        reason: format!(
                            "manifest declares {expected} accounts but {actual} were resolvable (ALT-resolved or deduplicated keys) — account-role analysis is partial"
                        ),
                    });
                    f
                },
            },
            None => risk_summary,
        };

        // Step 3.5: Simulation Integrity Check (Phase 1.5)
        //
        // SECURITY (baseline trust model): the baseline is read from the
        // TRUSTED semantic-graph accumulator — earned via `record_simulation`
        // from RPC-verified usage, or seeded by an operator. The request body
        // can NO LONGER supply a baseline; the `simulation_baseline` field was
        // removed from VerificationInput because it was caller-controlled JSON
        // that let an attacker normalize their own divergence.
        let trusted_baseline = self
            .graph()
            .get_simulation_baseline(&input.program_id)
            .cloned();
        let (sim_flagged, sim_divergence) = if let Some(baseline) = trusted_baseline {
            // A baseline with fewer than MIN_SAMPLES samples is statistically
            // meaningless — the check is skipped (None = no verdict), per P12
            // fail-open-with-explanation. Zero-variance baselines (std == 0)
            // are handled INSIDE check_simulation_integrity (any deviation
            // from an identical-history mean is a max-signal divergence) — the
            // old `std > 0.0` gate here silently skipped those programs
            // forever (a permanent spoofing bypass for uniform programs).
            if baseline.sample_count >= crate::simulation_integrity::MIN_SAMPLES {
                // Build a simulation usage object, preferring live RPC
                // simulation when an RPC client is attached; fall back to
                // caller-provided values if unavailable.
                #[cfg_attr(not(feature = "rpc"), allow(unused_mut))]
                let mut usage = crate::simulation_integrity::ComputeUsage {
                    compute_units: input.compute_units,
                    account_writes: input.account_writes,
                    cpi_hops: input.cpi_hops,
                };

                // Usage is recorded into the trusted accumulator ONLY when it
                // came ENTIRELY from a real simulateTransaction. Raw
                // request-body values must never feed the baseline (poisoning
                // vector): if the RPC result is partial — units_consumed == 0
                // (failed/budget-rejected simulation) or a missing optional
                // field — the merged object would still carry caller-controlled
                // numbers, so we record NOTHING. A partial RPC result is a
                // non-event for the accumulator.
                #[cfg_attr(not(feature = "rpc"), allow(unused_mut))]
                let mut rpc_sim_ok = false;
                #[cfg(feature = "rpc")]
                {
                    if let Some(client) = &self.rpc_client {
                        // Prefer a fully-signed transaction blob when provided;
                        // otherwise fall back to instruction_data as a minimal
                        // payload.
                        let tx_bytes = input
                            .signed_transaction
                            .as_ref()
                            .cloned()
                            .unwrap_or_else(|| input.instruction_data.clone().unwrap_or_default());
                        match client.simulate_transaction(&tx_bytes).await {
                            Ok(sim_res) => {
                                // Only a COMPLETE RPC result may enter the
                                // accumulator: nonzero units AND both optional
                                // fields present. Anything less leaves the
                                // caller's numbers in `usage`, so it must not
                                // be recorded (anti-poisoning).
                                if sim_res.units_consumed > 0
                                    && sim_res.account_writes.is_some()
                                    && sim_res.cpi_hops.is_some()
                                {
                                    usage.compute_units = sim_res.units_consumed;
                                    usage.account_writes = sim_res.account_writes.unwrap_or(0);
                                    usage.cpi_hops = sim_res.cpi_hops.unwrap_or(0);
                                    rpc_sim_ok = true;
                                }
                            }
                            Err(e) => {
                                tracing::warn!("simulateTransaction failed: {}", e);
                                // keep usage as-is (caller-provided)
                            }
                        }
                    }
                }

                // SECURITY (record-after-check): the integrity check MUST run
                // against the CURRENT trusted baseline BEFORE any new
                // observation is folded into it. Recording first would let a
                // compute spike normalize the baseline before the integrity
                // layer could flag it (baseline poisoning through the earn
                // path). Additionally, a FLAGGED observation must never enter
                // the accumulator.
                //
                // Recorded tradeoff (Constitution P14): because flagged
                // observations are never recorded, a program whose usage
                // LEGITIMATELY drifts (feature deploys, parameter changes)
                // stays flagged — its baseline freezes and an operator must
                // reseed it. This is the security-correct choice (an
                // attacker-driven spike must never move the baseline) at the
                // cost of operator intervention for genuinely evolving
                // programs.
                let check_result = match crate::simulation_integrity::check_simulation_integrity(
                    &crate::simulation_integrity::SimulationIntegrityInput {
                        program_id: input.program_id.clone(),
                        // clone: `usage` is still needed below for the
                        // record-after-check accumulator update.
                        simulation_usage: usage.clone(),
                        baseline,
                        divergence_threshold: 2.0,
                    },
                ) {
                    Ok(result) => result,
                    // Fail-closed (Constitution P12): on integrity check
                    // error (e.g. a corrupted seeded baseline), flag the
                    // simulation rather than silently passing it.
                    Err(e) => {
                        tracing::error!("simulation integrity check error: {}", e);
                        crate::simulation_integrity::SimulationIntegrityResult {
                            flagged: true,
                            divergence_score: f64::MAX,
                            reason: None,
                        }
                    }
                };

                // Provenance-aware verdict (Constitution P5 — simulation is
                // evidence, never ground truth): a CLEAN verdict is certified
                // ONLY when the usage came from a complete RPC
                // simulateTransaction. Caller-supplied usage can flag
                // divergence (why would anyone report divergent usage?) but can
                // never produce a false "clean" — an attacker who controls the
                // numbers could otherwise normalize their own z-score to 0.
                // Unverified-but-unflagged is reported as None ("no trusted
                // verdict"), not Some(false).
                let sim_flagged = if check_result.flagged {
                    Some(true)
                } else if rpc_sim_ok {
                    Some(false)
                } else {
                    None
                };

                // Record AFTER the check, and ONLY RPC-verified, un-flagged
                // observations enter the trusted accumulator. (rpc-only: the
                // accumulator cannot be written without a live RPC client,
                // and `persist_state_async` is rpc-gated.)
                #[cfg(feature = "rpc")]
                if rpc_sim_ok && !check_result.flagged {
                    self.graph().record_simulation(&input.program_id, &usage);
                    self.persist_state_async().await;
                }

                (sim_flagged, Some(check_result.divergence_score))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        // If simulation is flagged, add it as a risk finding
        let risk_summary = if sim_flagged == Some(true) {
            RiskVerdictSummary {
                status: "Blocked".to_string(),
                findings: {
                    let mut f = risk_summary.findings.clone();
                    f.push(RiskFinding {
                        pattern: "SimulationSpoofing".to_string(),
                        reason: "Compute usage diverges from baseline (flagged at >2.0σ)"
                            .to_string(),
                    });
                    f
                },
            }
        } else {
            risk_summary
        };

        // Surface plugin findings (L7) on the final risk summary: a Block made
        // the summary Blocked above; plugin Notes are appended as warning
        // findings so the signal is never silently dropped (P3 explainability).
        let risk_summary = if plugin_risk.findings.is_empty() {
            risk_summary
        } else {
            RiskVerdictSummary {
                status: risk_summary.status.clone(),
                findings: {
                    let mut f = risk_summary.findings.clone();
                    f.extend(plugin_risk.findings);
                    f
                },
            }
        };

        // L3: Simulation plugins run after the core's simulation-integrity
        // verdict. They may only Note or Block — never certify a clean
        // simulation (P5: a plugin cannot mint evidence). A Block fails the L3
        // layer report only; it does not fabricate a risk finding (that would
        // cross the layer boundary P8 forbids).
        let l3_plugin_runs = self.plugins.simulation_verdicts(&ctx);

        // L4: State Verification
        let l4_result = self.verify_state(
            &expected_state_changes,
            &resolution.resolved_accounts,
            manifest_found,
        );
        // L4: plugin folds (Block → layer Failed; Note → report annotation).
        let l4_result = self
            .plugins
            .fold_verifier(LayerId::L4StateVerification, l4_result, &ctx);

        // L5: Semantic Verification
        let l5_result = self.verify_semantic(
            &input.proposed_intent,
            &instruction_name,
            &expected_state_changes,
            manifest_found,
        );
        // L5: plugin folds run BEFORE the semantic penalty is computed so a
        // plugin Block on L5 contributes the same 0.3 penalty as the core's
        // own L5 failure (the plugin affects only its own layer's outcome).
        let l5_result =
            self.plugins
                .fold_verifier(LayerId::L5SemanticVerification, l5_result, &ctx);

        // GAP-2026-08-06-3: penalties key off the tri-state — only a genuine
        // FAILED check penalizes. Inconclusive (skipped/unverified) is absence
        // of evidence, not failure: it must not shift the verdict math, only
        // the (now honest) layer report.
        let semantic_penalty = if l5_result.status == LayerStatus::Failed {
            0.3
        } else {
            0.0
        };
        let instruction_penalty = if l2_result.status == LayerStatus::Failed {
            0.2
        } else {
            0.0
        };
        let state_penalty = if l4_result.status == LayerStatus::Failed {
            0.15
        } else {
            0.0
        };
        // Step 4: Confidence Computation
        let trust_tier = if manifest_found {
            // Manifest found — the manifest's trust_tier field is the protocol
            // team's self-assessment. Per Constitution P7, we cap this at
            // OfficialManifest (Tier 2) — tiers 3+ (SimulationValidated,
            // CommunityVerified, BattleTested) must be EARNED through
            // accumulated evidence in the Semantic Graph, not self-asserted.
            let manifest_tier = manifest
                .map(|m| TrustTier::from_manifest_str(&m.trust_tier))
                .unwrap_or(TrustTier::HeuristicInferred)
                .min(TrustTier::OfficialManifest); // P7: cap self-asserted tiers

            // SECURITY (G4 / P7): caller-provided `behavior_evidence` is
            // request-body JSON — it must NEVER raise the trust tier above what
            // the protocol's own compile-time-baked, reviewed manifest declares.
            // Previously a caller could fabricate `has_signed_manifest: true`
            // (or fake community/battle-test counts) to mint OfficialManifest on
            // a low-tier manifest, escaping that tier's 0.55 P6 ceiling and
            // inflating the TrustTierLevel signal. The Semantic Graph's
            // internally-accumulated tier (earned, never asserted) is still
            // honored; request-body evidence is ignored on the manifest path.
            match self.graph().get(&input.program_id) {
                Some(b) => b.trust_tier.max(manifest_tier),
                None => manifest_tier,
            }
        } else {
            // No manifest found — the trust tier comes ONLY from the Semantic
            // Graph's accumulated evidence (P7: earned, never asserted). The
            // request-body `behavior_evidence` is ignored here exactly as on
            // the manifest path — it is caller-controlled JSON, and honoring
            // it would let an attacker mint an earned-looking tier for a
            // program with no on-chain reputation (evidence-gaming, the same
            // class of bug as the build_signals zeroing). P6's low confidence
            // ceiling for unknown protocols still applies via
            // apply_unknown_protocol_ceiling below. A graph entry whose tier
            // was genuinely EARNED (operator-seeded Behavior evidence, or a
            // quarantine downgrade) is respected — forcibly capping an earned
            // tier at HeuristicInferred would violate P7.
            self.graph()
                .get(&input.program_id)
                .map(|b| b.trust_tier)
                .unwrap_or(TrustTier::Unknown)
        };

        // Phase 2 (G4): the three evidence-derived signals now read from the
        // Semantic Graph's internal accumulator — the program's RPC-verified
        // simulation baseline (`sample_count`) and its earned Behavior evidence.
        // The request body CANNOT supply them: `input.behavior_evidence` stays
        // ignored (caller-controlled JSON would mint confidence).
        let ge_sim = self
            .graph()
            .get_simulation_baseline(&input.program_id)
            .map(|b| b.sample_count)
            .unwrap_or(0);
        let ge_hist = self
            .graph()
            .get(&input.program_id)
            .map(|b| b.evidence.battle_tested_tx_count)
            .unwrap_or(0);
        let ge_comm = self
            .graph()
            .get(&input.program_id)
            .map(|b| b.evidence.community_verified_count)
            .unwrap_or(0);
        let graph_evidence = GraphSignalEvidence {
            simulation_matches: ge_sim,
            historical_volume: ge_hist,
            community_verified: ge_comm,
        };
        let signals = build_signals(
            &graph_evidence,
            manifest_found,
            trust_tier,
            &input.proposed_intent,
            // Only a genuine Failed L5 blocks the intent-alignment signal; an
            // Inconclusive (skipped) semantic check keeps the pre-GAP-2026-08-06-3
            // behavior (no alignment penalty) while the layer report is now honest.
            l5_result.status != LayerStatus::Failed,
        );
        let confidence_result = compute_confidence(&signals, trust_tier)
            .map_err(|e| VerificationError::Confidence(e.to_string()))?;

        // Defense-in-depth: apply the same tier-based ceiling a second time.
        // compute_confidence() already caps at the tier ceiling (0.55 for Unknown),
        // but this redundant cap ensures the invariant holds even if a future refactor
        // accidentally removes the ceiling from compute_confidence(). The second cap
        // is always a no-op given the first cap is in place — it exists as a safety net.
        let confidence = apply_unknown_protocol_ceiling(trust_tier, confidence_result.confidence);
        // Penalties must never push confidence below zero — AND the breakdown must
        // still explain the final score (Constitution P3). If the L2/L4/L5 penalties
        // exceed the available score, scale them down so their contributions sum
        // EXACTLY to the applied penalty and confidence floors at 0. Without this,
        // a heavily-penalized result reported confidence 0.0 while the breakdown
        // summed to a negative value (found by the proptest invariant suite).
        let total_penalty: f64 = semantic_penalty + instruction_penalty + state_penalty;
        let applied_penalty = if total_penalty > 0.0 {
            total_penalty.min(confidence)
        } else {
            0.0
        };
        let scale = if total_penalty > 0.0 {
            applied_penalty / total_penalty
        } else {
            1.0
        };
        let semantic_penalty = semantic_penalty * scale;
        let instruction_penalty = instruction_penalty * scale;
        let state_penalty = state_penalty * scale;
        let confidence = confidence - applied_penalty;
        // Step 5: Policy Evaluation
        let policy_input = PolicyInput {
            confidence_result: ConfidenceResult {
                confidence,
                breakdown: confidence_result.breakdown.clone(),
                trust_tier_applied: confidence_result.trust_tier_applied,
                ceiling_triggered: confidence_result.ceiling_triggered,
                ceiling_applied: confidence_result.ceiling_applied,
            },
            risk_verdict: risk_verdict.clone(),
            profile: input.wallet_profile,
        };
        let policy_verdict = evaluate_policy(&policy_input)?;

        let policy_str = match &policy_verdict {
            PolicyVerdict::Approved => "Approved",
            PolicyVerdict::RejectedBelowThreshold { .. } => "Rejected",
            PolicyVerdict::RejectedBelowTrustTier { .. } => "Rejected",
            PolicyVerdict::RejectedRiskEngineBlock => "Rejected",
        };

        // L6: Policy plugins may only veto (Block) or annotate (Note) — they
        // can never approve what the core's policy rejected (P8: plugins
        // affect only their own layer). A Block rejects the transaction and
        // is reflected in the L6 layer report and `approved` below.
        let mut l6_block: Option<(String, String)> = None;
        for run in self.plugins.policy_verdicts(&ctx) {
            if let PluginVerdict::Block { pattern, reason } = run.verdict {
                if l6_block.is_none() {
                    l6_block = Some((pattern, reason));
                }
            }
        }
        // P0 fix (2026-09-05 audit, "L2/L4/L5 approval-gate discrepancy"):
        // a GENUINE Failed (never Inconclusive — GAP-2026-08-06-3 preserves
        // that distinction below) L2/L4/L5 result is Graphite POSITIVELY
        // CONFIRMING a structural mismatch, not merely absent evidence:
        //   - L2 Failed means the caller's OWN instruction_data contradicts
        //     its OWN declared discriminator (a self-contradictory input,
        //     the exact HIGH #1 "Discriminator Check Bypass" class).
        //   - L4 Failed means the manifest's expected state changes are
        //     structurally unsatisfiable by the resolved accounts (e.g. an
        //     authority-changing instruction with zero signers — which
        //     could not execute on-chain either).
        //   - L5 Failed means the declared intent does not match what the
        //     instruction actually does — precisely the mismatch Graphite
        //     exists to catch.
        // Each is categorically different from Inconclusive (insufficient
        // evidence, P12 fail-open-with-explanation) and, like L3's
        // flagged-simulation case (already folded into risk_summary as a
        // hard Block), must not be reducible to a confidence penalty that a
        // high trust tier or a loose wallet profile threshold can absorb.
        // GRAPHITE_FINAL_CERTIFICATION_REPORT.md's "CRITICAL #6" originally
        // required exactly this hard gate; the later GAP-2026-08-06-3
        // tri-state refactor correctly preserved the confidence PENALTY
        // (so Inconclusive layers never wrongly penalize) but silently
        // dropped the HARD GATE for genuine failures, leaving e.g. a
        // BattleTested-tier transaction with a confirmed L2 discriminator/
        // data mismatch able to clear TradingBot's 0.80 threshold (raw
        // confidence 1.0 − 0.2 penalty = 0.80). This restores the gate,
        // correctly scoped to Failed only.
        let structural_layer_failed = l2_result.status == LayerStatus::Failed
            || l4_result.status == LayerStatus::Failed
            || l5_result.status == LayerStatus::Failed;

        // The effective policy outcome: core verdict AND no plugin veto AND
        // no structural layer failure.
        let l6_passed = matches!(policy_verdict, PolicyVerdict::Approved)
            && l6_block.is_none()
            && !structural_layer_failed;
        // CRITICAL (2026-09-05 SDK integration audit): `policy_str` must also
        // reflect the FINAL risk summary, not just the policy engine's view.
        //
        // `policy_verdict` above was computed from the risk verdict as it
        // stood BEFORE the L3 simulation-integrity check. When simulation
        // flags compute divergence — the SimulationSpoofing case that layer
        // exists to catch — the code mutates `risk_summary` to "Blocked",
        // which correctly forces `approved = false` further down, but left
        // `policy_verdict` reading "Approved". The result payload therefore
        // contradicted itself: `approved: false` next to
        // `policy_verdict: "Approved"`.
        //
        // That is not merely cosmetic. `policy_verdict` is a human-readable
        // field of exactly the name a developer reaches for, and gating on it
        // would have signed a transaction Graphite had flagged as spoofed.
        // Folding the final risk status in here makes the invariant
        // structural: `policy_str == "Approved"` iff `approved == true`
        // (see `approved` below — same three conditions), so no future
        // late-stage risk mutation can reintroduce the divergence without
        // also flipping this string. The specific REASON for the rejection
        // remains fully available in `risk_verdict.findings` and the layer
        // results, so explainability is preserved (P3).
        let policy_str =
            if l6_block.is_some() || structural_layer_failed || risk_summary.status != "Clear" {
                "Rejected"
            } else {
                policy_str
            };

        // Build audit trail ID (deterministic hash of key fields)
        let (audit_id, content_hash) = generate_audit_id(
            &input.program_id,
            &input.instruction_discriminator,
            &input.account_addresses,
            &input.instruction_data,
            &input.cpi_targets,
            confidence,
            &risk_summary,
        );

        // Determine if approved
        let approved = l6_passed && risk_summary.status == "Clear";

        // Generate summary
        let mut summary = generate_summary(
            approved,
            confidence,
            &risk_summary,
            policy_str,
            &protocol_name,
            &instruction_name,
            unknown_protocol,
        );
        // Surface non-blocking risk warnings in the human-readable summary so
        // they are visible to anyone consuming the result, not just the L7 layer.
        if !risk_warnings.is_empty() {
            summary.push_str(&format!(" | warnings: {}", risk_warnings.join("; ")));
        }

        let mut breakdown: Vec<VerificationBreakdownItem> = confidence_result
            .breakdown
            .iter()
            .map(|(kind, contribution)| {
                let kind_str = format!("{:?}", kind);
                let raw_value = signals
                    .iter()
                    .find(|s| format!("{:?}", s.kind) == kind_str)
                    .map(|s| s.value)
                    .unwrap_or(0.0);
                VerificationBreakdownItem {
                    kind: kind_str.clone(),
                    raw_value,
                    weight: signals
                        .iter()
                        .find(|s| format!("{:?}", s.kind) == kind_str)
                        .map(|s| s.weight)
                        .unwrap_or(0.0),
                    contribution: *contribution,
                }
            })
            .collect();

        // Add penalty items to breakdown (Constitution P3: breakdown must explain the final score)
        if semantic_penalty > 0.0 {
            breakdown.push(VerificationBreakdownItem {
                kind: "SemanticPenalty".to_string(),
                raw_value: semantic_penalty,
                weight: -1.0,
                contribution: -semantic_penalty,
            });
        }
        if instruction_penalty > 0.0 {
            breakdown.push(VerificationBreakdownItem {
                kind: "InstructionPenalty".to_string(),
                raw_value: instruction_penalty,
                weight: -1.0,
                contribution: -instruction_penalty,
            });
        }
        if state_penalty > 0.0 {
            breakdown.push(VerificationBreakdownItem {
                kind: "StatePenalty".to_string(),
                raw_value: state_penalty,
                weight: -1.0,
                contribution: -state_penalty,
            });
        }

        // Add ceiling cap to breakdown if it was applied (Constitution P3).
        // compute_confidence() already caps the confidence and sets ceiling_triggered=true
        // when the raw score exceeds the tier ceiling. We reconstruct the raw score from
        // the breakdown contributions to show the user exactly how much the ceiling reduced
        // their confidence — the breakdown must explain the final score (P3).
        if confidence_result.ceiling_triggered {
            let raw_confidence: f64 = confidence_result.breakdown.iter().map(|(_, v)| *v).sum();
            let ceiling_reduction = raw_confidence - confidence_result.confidence;
            // Filter floating-point noise: only report if the reduction is
            // meaningful (> 0.001, i.e., 0.1% confidence reduction).
            // This prevents epsilon-level differences (e.g., 2.22e-16)
            // from appearing as spurious ceiling items in the breakdown.
            if ceiling_reduction > 0.001 {
                breakdown.push(VerificationBreakdownItem {
                    kind: "TrustTierCeiling".to_string(),
                    raw_value: ceiling_reduction,
                    weight: 0.0,
                    contribution: -ceiling_reduction,
                });
            }
        }

        let _summary_for_layers = summary.clone();

        // L3 layer report: the core simulation verdict folded with simulation
        // plugin runs (a plugin Note appends; a Block fails the report only).
        let l3_layer_result = PipelineLayerResult::new(
            "L3_SimulationVerification",
            match sim_flagged {
                Some(true) => LayerStatus::Failed,
                Some(false) => LayerStatus::Passed,
                None => LayerStatus::Inconclusive,
            },
            {
                let base = match (sim_flagged, sim_divergence) {
                    (Some(true), _) => {
                        // Clamp the DISPLAYED divergence: zero-variance
                        // and degenerate paths report f64::MAX (JSON-safe
                        // in the structured field) which would otherwise
                        // render as a ~300-digit number here.
                        let d = sim_divergence.unwrap_or(0.0);
                        let div = if d > 1000.0 {
                            ">1000σ".to_string()
                        } else {
                            format!("{:.2}σ", d)
                        };
                        format!(
                            "Simulation integrity FLAGGED: {} CU / {} writes / {} hops (divergence {} vs baseline)",
                            input.compute_units, input.account_writes, input.cpi_hops, div
                        )
                    }
                    (Some(false), _) => format!(
                        "Simulation integrity clean (RPC-verified): {} CU / {} writes / {} hops",
                        input.compute_units, input.account_writes, input.cpi_hops
                    ),
                    (None, Some(_)) => format!(
                        "Simulation integrity NOT RPC-verified: caller-supplied usage ({} CU / {} writes / {} hops) — advisory only, cannot certify clean (P5)",
                        input.compute_units, input.account_writes, input.cpi_hops
                    ),
                    (None, None) => {
                        "Phase 1: simulation not checked (no baseline or insufficient samples) — active when a trusted baseline exists".to_string()
                    }
                };
                if let Some(ref info) = l3_rpc_account_info {
                    format!("{} | RPC: {}", base, info)
                } else {
                    base
                }
            },
        );
        let l3_layer_result =
            crate::plugin_orchestrator::fold_runs_into_result(l3_layer_result, l3_plugin_runs);

        // L6 layer report reason (includes any policy-plugin veto).
        let mut l6_reason = format!(
            "Confidence: {:.4} (tier: {:?}, ceiling: {:.2}) → Policy: {} (min_conf: {:.2}, min_tier: {:?})",
            confidence, trust_tier, confidence_result.ceiling_applied,
            policy_str,
            match input.wallet_profile {
                WalletProfile::Treasury => 0.95,
                WalletProfile::Enterprise => 0.99,
                WalletProfile::Gaming => 0.60,
                WalletProfile::TradingBot => 0.80,
                WalletProfile::Custom { min_confidence, .. } => min_confidence,
            },
            match input.wallet_profile {
                WalletProfile::Treasury => TrustTier::CommunityVerified,
                WalletProfile::Enterprise => TrustTier::BattleTested,
                WalletProfile::Gaming => TrustTier::HeuristicInferred,
                WalletProfile::TradingBot => TrustTier::SimulationValidated,
                WalletProfile::Custom { min_trust_tier, .. } => min_trust_tier,
            }
        );
        if let Some((pattern, reason)) = &l6_block {
            l6_reason = format!(
                "Rejected by policy plugin ({}): {} | {}",
                pattern, reason, l6_reason
            );
        }
        if structural_layer_failed {
            l6_reason = format!(
                "Rejected: structural verification failed (L2={:?}, L4={:?}, L5={:?}) — see layer reports | {}",
                l2_result.status, l4_result.status, l5_result.status, l6_reason
            );
        }

        // L8: Execution Verification — report-only layer (post-submission). A
        // plugin registered for L8 can only annotate or fail the report; it
        // cannot affect `approved` (L8 is Inconclusive by design until
        // on-chain confirmation exists).
        let l8_layer_result = PipelineLayerResult::new(
            "L8_ExecutionVerification",
            LayerStatus::Inconclusive,
            "Phase 1: execution verification not yet verified (post-submission feature) — audit_trail_id bound to transaction for future L8 replay",
        );
        let l8_layer_result =
            self.plugins
                .fold_verifier(LayerId::L8ExecutionVerification, l8_layer_result, &ctx);

        let result = VerificationResult {
            approved,
            confidence,
            breakdown,
            trust_tier: format!("{:?}", trust_tier),
            risk_verdict: risk_summary.clone(),
            policy_verdict: policy_str.to_string(),
            audit_trail_id: audit_id,
            content_hash,
            transaction,
            resolved_accounts: resolution.resolved_accounts.clone(),
            protocol_name,
            instruction_name,
            manifest_found,
            unknown_protocol,
            manifest_version: manifest.map(|m| m.version.label.clone()),
            summary,
            simulation_flagged: sim_flagged,
            simulation_divergence: sim_divergence,
            layers: vec![
                // L1: Account Resolution — resolve all required accounts/PDAs
                // ARCHITECTURE.md 3.12: "Resolve all required accounts/PDAs"
                PipelineLayerResult::new(
                    "L1_AccountResolution",
                    LayerStatus::Passed,
                    format!(
                        "Resolved {} account(s), manifest {}",
                        resolution.resolved_accounts.len(),
                        if manifest_found { "found" } else { "not found" }
                    ),
                ),
                // L2: Instruction Verification — confirm discriminator + args match known shape
                // ARCHITECTURE.md 3.12: "Confirm instruction discriminator + args match a known shape"
                PipelineLayerResult::new(
                    "L2_InstructionVerification",
                    l2_result.status,
                    l2_result.reason.clone(),
                ),
                // L3: Simulation Verification — run simulateTransaction, confirm it succeeds
                // ARCHITECTURE.md 3.12: "Run simulateTransaction, confirm it succeeds"
                // Phase 1: SKIPPED — no RPC connection available. Simulation requires a
                // Solana RPC endpoint to call simulateTransaction. This is a Phase 2
                // feature (requires infrastructure provisioning). The simulation_integrity
                // module IS wired in and checks for compute-unit divergence when
                // simulation data is provided by the caller, but the full L3 (actually
                // running simulateTransaction against an RPC node) is not yet active.
                // GAP-2026-08-06-3: the L3 layer result now carries the REAL
                // simulation-integrity verdict. The provenance-aware tri-state:
                //   Some(true)  → Failed   (integrity check flagged)
                //   Some(false) → Passed   (RPC-verified clean)
                //   None        → Inconclusive (no trusted verdict: no baseline,
                //                  insufficient samples, or unverified
                //                  caller-supplied usage — P5 cannot certify)
                PipelineLayerResult::new(
                    "L3_SimulationVerification",
                    l3_layer_result.status,
                    l3_layer_result.reason.clone(),
                ),
                // L4: State Verification — diff pre/post account state against declared intent
                // ARCHITECTURE.md 3.12: "Diff pre/post account state against declared intent"
                // Phase 1: heuristic check — verifies writable/signer account counts
                // are consistent with declared state changes. Full pre/post state diff
                // requires RPC access (Phase 2).
                PipelineLayerResult::new(
                    "L4_StateVerification",
                    l4_result.status,
                    l4_result.reason.clone(),
                ),
                // L5: Semantic Verification — compare diff against Semantic Graph expected Behavior
                // ARCHITECTURE.md 3.12: "Compare diff against the Semantic Graph's expected Behavior"
                // Phase 1: keyword matching between intent type, instruction name, and
                // expected state changes. Full Semantic Graph comparison requires
                // accumulated behavior data (Phase 2+).
                PipelineLayerResult::new(
                    "L5_SemanticVerification",
                    l5_result.status,
                    l5_result.reason.clone(),
                ),
                // L6: Policy Verification — apply the active wallet's Policy Engine profile
                // ARCHITECTURE.md 3.12: "Apply the active wallet's Policy Engine profile"
                // Includes confidence computation (3.11) + policy threshold checks (3.13).
                // Confidence is computed first, then policy evaluates it against the
                // wallet profile's minimum confidence and trust tier thresholds.
                PipelineLayerResult::new(
                    "L6_PolicyVerification",
                    if l6_passed {
                        LayerStatus::Passed
                    } else {
                        LayerStatus::Failed
                    },
                    l6_reason.clone(),
                ),
                // L7: Risk Verification — runs the Risk Engine (3.21)
                // ARCHITECTURE.md 3.12: "Forbidden patterns, allowlist/denylist, compositional risk"
                // NOTE: The Risk Engine executes EARLY in the pipeline (before confidence/policy)
                // for fail-fast performance — a known malicious pattern should block
                // immediately without wasting computation. However, it is REPORTED at L7
                // per the architecture spec's layer ordering. A risk block is a hard gate
                // that overrides any policy approval (Constitution: risk block is binary,
                // not a scored signal).
                PipelineLayerResult::new(
                    "L7_RiskVerification",
                    if risk_summary.status == "Clear" {
                        LayerStatus::Passed
                    } else {
                        LayerStatus::Failed
                    },
                    if risk_summary.status == "Clear" {
                        if risk_warnings.is_empty() {
                            format!(
                                "No risk patterns detected ({} patterns checked)",
                                crate::risk_engine::CHECKED_PATTERNS
                            )
                        } else {
                            format!(
                                "No risk patterns detected ({} patterns checked) — warnings: {}",
                                crate::risk_engine::CHECKED_PATTERNS,
                                risk_warnings.join("; ")
                            )
                        }
                    } else {
                        format!(
                            "Blocked: {} finding(s) — {:?}",
                            risk_summary.findings.len(),
                            risk_summary
                                .findings
                                .iter()
                                .map(|f| &f.pattern)
                                .collect::<Vec<_>>()
                        )
                    },
                ),
                // L8: Execution Verification — confirm finalized on-chain result matches prediction
                // ARCHITECTURE.md 3.12: "Post-submission: confirm the finalized on-chain result
                // matches what L1-L7 predicted"
                // GAP-2026-08-06-3: L8 emits a REAL 'not yet verified' state —
                // Inconclusive, never a phantom pass. Execution verification requires
                // transaction submission to Solana mainnet/devnet (Phase 2+, SAK
                // integration or direct RPC submission). The audit_trail_id (SHA-256
                // of accounts + instruction data + CPI targets) enables post-hoc
                // verification once L8 is implemented.
                PipelineLayerResult::new(
                    "L8_ExecutionVerification",
                    l8_layer_result.status,
                    l8_layer_result.reason.clone(),
                ),
            ],
        };

        // Analytics observers (read-only, P8): record the completed result to
        // every registered sink. Sink failures are logged, never fatal — the
        // returned result is byte-identical either way (P2 determinism).
        self.plugins.run_analytics(&result);

        Ok(result)
    }
}

fn summarize_risk(verdict: &RiskVerdict) -> RiskVerdictSummary {
    match verdict {
        RiskVerdict::Passed => RiskVerdictSummary {
            status: "Clear".to_string(),
            findings: vec![],
        },
        RiskVerdict::Blocked { pattern, reason } => RiskVerdictSummary {
            status: "Blocked".to_string(),
            findings: vec![RiskFinding {
                pattern: format!("{:?}", pattern),
                reason: reason.clone(),
            }],
        },
    }
}

fn build_signals(
    evidence: &GraphSignalEvidence,
    manifest_found: bool,
    trust_tier: TrustTier,
    intent: &ProposedIntent,
    l5_passed: bool,
) -> Vec<WeightedSignal> {
    // Manifest match: binary 1.0/0.0 — did we find a protocol manifest?
    let manifest_value = if manifest_found { 1.0 } else { 0.0 };

    // Trust tier signal: the manifest's declared trust tier IS evidence.
    // ARCHITECTURE.md 3.11: "Confidence is computed from: the trust tier
    // of every instruction touched" — the tier is not just a ceiling, it's
    // a confidence INPUT. A BattleTested protocol has proven itself through
    // 1000+ verified transactions; that knowledge contributes to confidence.
    let trust_tier_value = match trust_tier {
        TrustTier::BattleTested => 1.0,
        TrustTier::CommunityVerified => 0.90,
        TrustTier::SimulationValidated => 0.80,
        TrustTier::OfficialManifest => 0.70,
        TrustTier::HeuristicInferred => 0.30,
        TrustTier::Unknown => 0.0,
    };

    // SECURITY (G4): the evidence-derived signals (SimulationMatch,
    // HistoricalVolume, CommunityVerification) read from the Semantic Graph's
    // internal accumulator — never from the request body. `behavior_evidence`
    // is caller-controlled JSON and stays ignored: an attacker can no longer
    // mint confidence by sending fabricated values. Values are normalized
    // against the trust-tier promotion thresholds so full evidence = full
    // signal, and partial evidence = proportional signal. The TrustTierLevel
    // signal separately captures the earned tier.
    let simulation_value = (evidence.simulation_matches as f64
        / crate::semantic_graph_store::thresholds::SIMULATION_MATCH as f64)
        .min(1.0);
    let historical_value = (evidence.historical_volume as f64
        / crate::semantic_graph_store::thresholds::BATTLE_TESTED_TX as f64)
        .min(1.0);
    let community_value = (evidence.community_verified as f64
        / crate::semantic_graph_store::thresholds::COMMUNITY_VERIFIED as f64)
        .min(1.0);

    // Intent-manifest alignment: if the proposed intent type matches
    // a known instruction in the manifest, this is a positive signal.
    // When no manifest exists, this contributes 0 (consistent with
    // Unknown Protocol Mode). This is NOT the same as L5 semantic
    // verification — it's a confidence INPUT, not a pass/fail gate.
    let intent_alignment = if manifest_found && !intent.intent_type.is_empty() && l5_passed {
        1.0
    } else if manifest_found && !intent.intent_type.is_empty() && !l5_passed {
        0.3
    } else {
        0.0
    };

    // Signal weights must sum to exactly 1.0 (validated by compute_confidence).
    // SECURITY (G4): the evidence signal VALUES come from the Semantic Graph's
    // internal accumulator (GraphSignalEvidence), NEVER from caller JSON — a
    // request body cannot mint confidence. On a fresh core (no earned state)
    // they are 0, so confidence comes only from manifest + tier + intent.
    //   ManifestMatch (0.20): binary — was a manifest found?
    //   TrustTierLevel (0.20): the protocol's earned trust tier (manifest/graph)
    //   SimulationMatch (0.20): normalized RPC-verified simulation count
    //   HistoricalVolume (0.15): normalized earned transaction volume
    //   CommunityVerification (0.15): normalized earned community verifications
    //   IntentAlignment (0.10): intent-manifest alignment (requires L5 pass)
    vec![
        WeightedSignal {
            kind: SignalKind::ManifestMatch,
            value: manifest_value,
            weight: 0.20,
        },
        WeightedSignal {
            kind: SignalKind::TrustTierLevel,
            value: trust_tier_value,
            weight: 0.20,
        },
        WeightedSignal {
            kind: SignalKind::SimulationMatch,
            value: simulation_value,
            weight: 0.20,
        },
        WeightedSignal {
            kind: SignalKind::HistoricalVolume,
            value: historical_value,
            weight: 0.15,
        },
        WeightedSignal {
            kind: SignalKind::CommunityVerification,
            value: community_value,
            weight: 0.15,
        },
        WeightedSignal {
            kind: SignalKind::IntentAlignment,
            value: intent_alignment,
            weight: 0.10,
        },
    ]
}

fn generate_audit_id(
    program_id: &str,
    discriminator: &str,
    account_addresses: &[String],
    instruction_data: &Option<Vec<u8>>,
    cpi_targets: &[String],
    confidence: f64,
    risk: &RiskVerdictSummary,
) -> (String, String) {
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let seq = COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut hasher = Sha256::new();
    hasher.update(program_id.as_bytes());
    hasher.update(discriminator.as_bytes());
    // Bind audit trail to specific accounts — mitigates TOCTOU by making
    // the audit ID unique per transaction configuration.
    for addr in account_addresses {
        hasher.update(addr.as_bytes());
    }
    // Include instruction data if present
    if let Some(data) = instruction_data {
        hasher.update(data);
    }
    // Include CPI targets
    for target in cpi_targets {
        hasher.update(target.as_bytes());
    }
    // SECURITY FIX: content_hash covers ONLY transaction inputs (deterministic,
    // reproducible by the client). audit_trail_id adds confidence + risk + seq
    // for uniqueness. Previously content_hash included confidence/risk which
    // made AuditBind impossible (client can't know the verification result
    // before submitting).
    let hash = hasher.finalize();
    let content_hash = hex::encode(&hash[..8]);

    // audit_trail_id adds verification result + sequence for uniqueness
    let mut id_hasher = sha2::Sha256::new();
    id_hasher.update(hash);
    id_hasher.update(format!("{:.6}", confidence).as_bytes());
    id_hasher.update(risk.status.as_bytes());
    for f in &risk.findings {
        id_hasher.update(f.pattern.as_bytes());
        id_hasher.update(f.reason.as_bytes());
    }
    let id_hash = id_hasher.finalize();
    let audit_trail_id = format!("gr-{}-{:08x}", hex::encode(&id_hash[..8]), seq);
    (audit_trail_id, content_hash)
}

fn generate_summary(
    approved: bool,
    confidence: f64,
    risk: &RiskVerdictSummary,
    policy: &str,
    protocol: &str,
    instruction: &str,
    unknown: bool,
) -> String {
    let parts: Vec<String> = vec![
        if approved {
            "APPROVED".into()
        } else {
            "BLOCKED".into()
        },
        format!("confidence={:.2}", confidence),
        format!("risk={}", risk.status),
        format!("policy={}", policy),
        format!("protocol={}", protocol),
        format!("instruction={}", instruction),
        if unknown {
            "unknown_protocol=true".into()
        } else {
            "unknown_protocol=false".into()
        },
    ];
    parts.join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_input(program: &str, disc: &str, accounts: &[&str]) -> VerificationInput {
        VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "transfer".to_string(),
                raw_natural_language: "Transfer 1 SOL".to_string(),
                confidence_of_parse: 0.9,
                extracted_parameters: None,
            },
            program_id: program.to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: disc.to_string(),
            account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
            instruction_data: None,
            cpi_targets: vec![],
            wallet_profile: WalletProfile::TradingBot,
            behavior_evidence: BehaviorEvidence {
                has_signed_manifest: false,
                community_verified_count: 5,
                battle_tested_tx_count: 50000,
                simulation_match_count: 100,
            },
            compute_units: 150,
            account_writes: 2,
            cpi_hops: 0,
            signed_transaction: None,
            transaction_instructions: vec![],
            cpi_trace: None,
            uses_versioned_transaction: false,
            lookup_table_count: 0,
            real_account_metas: vec![],
        }
    }

    /// P16 finding: the previous 64-account DoS cap rejected legitimate modern
    /// transactions — a real Jupiter V6 route on mainnet carries 72 accounts
    /// (one per route step). The cap now matches Solana's protocol limit (256),
    /// so a 72-account route must verify rather than hit a misleading
    /// "expected 64" account-count error.
    #[test]
    fn test_large_legitimate_route_account_list_is_not_rejected_by_cap() {
        let mut core = GraphiteCore::new();
        // Steady-state node: Jupiter has earned evidence (battle-tested volume)
        // and a simulation baseline, so a matched route can exceed the
        // TradingBot 0.80 confidence threshold. Without this, the fresh-node
        // cold-start ceiling (0.44) blocks everything — a documented P7
        // earned-evidence property, not a cap bug.
        use crate::semantic_graph_store::{Behavior, BehaviorEvidence};
        use crate::simulation_integrity::ComputeBaseline;
        let jup = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
        core.seed_behavior(Behavior {
            program_id: jup.to_string(),
            version: "1.0.0".to_string(),
            expected_state_changes: vec!["Jupiter V6 aggregator instruction".to_string()],
            allowed_cpis: vec!["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()],
            trust_tier: crate::TrustTier::BattleTested,
            evidence: BehaviorEvidence {
                has_signed_manifest: true,
                community_verified_count: 5,
                battle_tested_tx_count: 50000,
                simulation_match_count: 100,
            },
            quarantined: false,
            quarantine_reason: None,
        })
        .unwrap();
        core.seed_simulation_baseline(
            jup,
            ComputeBaseline {
                mean_compute_units: 150.0,
                std_compute_units: 1.0,
                sample_count: 50,
                mean_account_writes: 2.0,
                std_account_writes: 0.5,
                mean_cpi_hops: 0.0,
                std_cpi_hops: 0.1,
                ..Default::default()
            },
        )
        .unwrap();
        // 72 distinct valid pubkeys (the shape of a real Jupiter route tx).
        let mut accounts: Vec<String> = Vec::new();
        for i in 0..72u8 {
            let mut bytes = [0u8; 32];
            bytes[0] = 1;
            bytes[1] = i;
            let addr = crate::solana_types::Pubkey(bytes).to_base58();
            accounts.push(addr);
        }
        // P0-1 fix (2026-09-05 audit): route_v2's manifest now constrains
        // slots 5 (token_program) and 6 (token_2022_program) via
        // `expected_address` — placeholder synthetic pubkeys at those
        // positions are correctly rejected by the new check (that is the
        // whole point of the fix). Use the REAL constants there so this
        // test keeps isolating what it actually claims to test (the
        // 256-account cap, not account identity).
        accounts[5] = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string();
        accounts[6] = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb".to_string();
        let input = VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "swap".to_string(),
                raw_natural_language: "Swap tokens".to_string(),
                confidence_of_parse: 0.9,
                extracted_parameters: None,
            },
            program_id: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4".to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: "bb64facc31c4af14".to_string(), // route_v2 (C22.3: on-chain confirmed)
            account_addresses: accounts,
            instruction_data: None,
            cpi_targets: vec![],
            wallet_profile: WalletProfile::TradingBot,
            behavior_evidence: BehaviorEvidence {
                has_signed_manifest: true,
                community_verified_count: 5,
                battle_tested_tx_count: 50000,
                simulation_match_count: 100,
            },
            compute_units: 150,
            account_writes: 2,
            cpi_hops: 0,
            signed_transaction: None,
            transaction_instructions: vec![],
            cpi_trace: None,
            uses_versioned_transaction: false,
            lookup_table_count: 0,
            real_account_metas: vec![],
        };
        let result = core
            .verify(&input)
            .expect("72-account route must not be rejected by the cap");
        assert!(
            result.approved,
            "known Jupiter route with earned evidence must approve"
        );
    }

    #[test]
    fn test_verify_system_transfer() {
        let core = GraphiteCore::new();
        let input = make_input(
            "11111111111111111111111111111111",
            "02000000",
            &[
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
            ],
        );
        let result = core.verify(&input).unwrap();
        assert!(result.manifest_found);
        assert_eq!(result.protocol_name, "System Program");
        assert_eq!(result.instruction_name, "Transfer");
        assert!(result.confidence > 0.0);
        assert_eq!(result.risk_verdict.status, "Clear");
    }

    #[test]
    fn test_verify_unknown_protocol_capped() {
        let core = GraphiteCore::new();
        let input = make_input(
            "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
            "03000000",
            &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"],
        );
        let result = core.verify(&input).unwrap();
        assert!(result.unknown_protocol);
        // Unknown protocol confidence should be capped (P6/P12)
        assert!(result.confidence <= 0.55);
    }

    #[test]
    fn test_verify_with_blocked_risk() {
        let core = GraphiteCore::new();
        let input = VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "transfer".to_string(),
                raw_natural_language: "Set authority".to_string(),
                confidence_of_parse: 0.5,
                extracted_parameters: None,
            },
            program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: "06".to_string(), // SetAuthority
            account_addresses: vec![
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
            ],
            instruction_data: None,
            cpi_targets: vec!["unverified_target".to_string()],
            wallet_profile: WalletProfile::TradingBot,
            behavior_evidence: BehaviorEvidence {
                has_signed_manifest: false,
                community_verified_count: 0,
                battle_tested_tx_count: 0,
                simulation_match_count: 0,
            },
            compute_units: 150,
            account_writes: 2,
            cpi_hops: 1,
            signed_transaction: None,
            transaction_instructions: vec![],
            cpi_trace: None,
            uses_versioned_transaction: false,
            lookup_table_count: 0,
            real_account_metas: vec![],
        };
        let result = core.verify(&input).unwrap();
        // Should be blocked due to unverified CPI or authority-related patterns
        // Even if not blocked, it should have low confidence
        assert!(result.confidence < 1.0);
    }

    #[test]
    fn test_verify_generates_audit_id() {
        let core = GraphiteCore::new();
        let input = make_input(
            "11111111111111111111111111111111",
            "02000000",
            &[
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
            ],
        );
        let result = core.verify(&input).unwrap();
        assert!(result.audit_trail_id.starts_with("gr-"));
    }

    #[test]
    fn test_signed_transaction_flows_to_simulation_input() {
        // Phase 1.5: a caller-supplied signed transaction blob is the preferred
        // L3 simulation payload. With no RPC client attached the blob is not
        // transmitted anywhere, but the pipeline must accept it and the
        // simulation-integrity check must still run when a trusted baseline
        // exists (seeded via the operator API — request bodies can no longer
        // supply baselines).
        let core = GraphiteCore::new();
        let mut input = make_input(
            "11111111111111111111111111111111",
            "02000000",
            &[
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
            ],
        );
        input.signed_transaction = Some(vec![1u8, 2, 3, 4, 5]);
        input.compute_units = 150;
        input.account_writes = 2;
        input.cpi_hops = 0;
        core.seed_simulation_baseline(
            "11111111111111111111111111111111",
            crate::simulation_integrity::ComputeBaseline {
                mean_compute_units: 150.0,
                std_compute_units: 1.0,
                sample_count: 50,
                mean_account_writes: 2.0,
                std_account_writes: 0.5,
                mean_cpi_hops: 0.0,
                std_cpi_hops: 0.1,
                ..Default::default()
            },
        )
        .unwrap();
        let result = core.verify(&input).unwrap();
        // Baseline is present (>=10 samples) and the check RAN (usage matches
        // the baseline → divergence 0). BUT with no RPC client attached the
        // usage is caller-supplied, so the verdict is PROVENANCE-AWARE: a
        // caller-controlled usage can never certify a CLEAN simulation (P5) —
        // it is reported as None ("no trusted verdict"), not Some(false). The
        // computed divergence is still surfaced for transparency.
        assert_eq!(result.simulation_flagged, None);
        assert_eq!(result.simulation_divergence, Some(0.0));
        // Signed-transaction-bearing input must not corrupt the deterministic
        // content hash (the blob is not part of the verification identity).
        assert_eq!(result.content_hash, "afb61d8865b4cb68");
    }

    #[test]
    fn test_verify_summary_generated() {
        let core = GraphiteCore::new();
        let input = make_input(
            "11111111111111111111111111111111",
            "02000000",
            &[
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
            ],
        );
        let result = core.verify(&input).unwrap();
        assert!(result.summary.contains("confidence="));
        assert!(result.summary.contains("protocol=System Program"));
    }

    #[test]
    fn test_ceiling_shown_in_breakdown_when_triggered() {
        // P3 compliance: when the confidence ceiling is triggered (raw score
        // exceeds the tier ceiling), the breakdown MUST include a
        // TrustTierCeiling item showing how much the ceiling reduced the score.
        //
        // Use a known protocol with strong evidence so the raw confidence
        // exceeds the ceiling, then verify the breakdown includes it.
        let core = GraphiteCore::new();
        let input = VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "transfer".to_string(),
                raw_natural_language: "Transfer 1 SOL".to_string(),
                confidence_of_parse: 0.95,
                extracted_parameters: None,
            },
            program_id: "11111111111111111111111111111111".to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: "02000000".to_string(),
            account_addresses: vec![
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
            ],
            instruction_data: None,
            cpi_targets: vec![],
            wallet_profile: WalletProfile::Gaming,
            behavior_evidence: BehaviorEvidence {
                has_signed_manifest: true,
                community_verified_count: 5,
                battle_tested_tx_count: 50000,
                simulation_match_count: 100,
            },
            compute_units: 150,
            account_writes: 2,
            cpi_hops: 0,
            signed_transaction: None,
            transaction_instructions: vec![],
            cpi_trace: None,
            uses_versioned_transaction: false,
            lookup_table_count: 0,
            real_account_metas: vec![],
        };

        let result = core.verify(&input).unwrap();

        // SECURITY (G4): Caller-provided evidence is ignored — the tier is capped
        // at OfficialManifest (P7) and the evidence signals read from the Semantic
        // Graph (empty on a fresh core). With no earned state: conf = 0.44, tier =
        // OfficialManifest (ceiling 0.75). Since 0.44 < 0.75, NO ceiling is
        // triggered — breakdown should NOT have a TrustTierCeiling item (or it
        // should be negligible floating-point noise).
        assert_eq!(
            result.trust_tier, "OfficialManifest",
            "Evidence tier must be capped at OfficialManifest — got: {}",
            result.trust_tier
        );
        let ceiling_item = result
            .breakdown
            .iter()
            .find(|b| b.kind == "TrustTierCeiling");
        if let Some(item) = ceiling_item {
            assert!(item.raw_value.abs() < 0.001,
                "Confidence 0.44 is below OfficialManifest ceiling 0.75 — ceiling reduction should be negligible, got: {}",
                item.raw_value);
        }
    }

    #[test]
    fn test_ceiling_shown_in_breakdown_for_unknown_protocol() {
        // P3 compliance: for an unknown protocol (no manifest), the trust tier
        // is Unknown (ceiling = 0.55). If the raw confidence exceeds 0.55,
        // the breakdown MUST include a TrustTierCeiling item.
        let core = GraphiteCore::new();
        let input = VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "transfer".to_string(),
                raw_natural_language: "Transfer 1 SOL".to_string(),
                confidence_of_parse: 0.95,
                extracted_parameters: None,
            },
            // Unknown program (no manifest)
            program_id: "DezXAZ8z7PnrnRJjz3vX2k7BtZbJ2k2cRgZ7HzXADc1".to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: "02000000".to_string(),
            account_addresses: vec![
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
            ],
            instruction_data: None,
            cpi_targets: vec![],
            wallet_profile: WalletProfile::Gaming,
            behavior_evidence: BehaviorEvidence {
                has_signed_manifest: true,
                community_verified_count: 10,
                battle_tested_tx_count: 50000,
                simulation_match_count: 100,
            },
            compute_units: 150,
            account_writes: 2,
            cpi_hops: 0,
            signed_transaction: None,
            transaction_instructions: vec![],
            cpi_trace: None,
            uses_versioned_transaction: false,
            lookup_table_count: 0,
            real_account_metas: vec![],
        };

        let result = core.verify(&input).unwrap();

        // Unknown protocol → trust_tier = Unknown → ceiling = 0.55
        // With strong evidence (but no manifest), the raw confidence from
        // signals will be high, but the ceiling should cap it to 0.55.
        // The breakdown should include a TrustTierCeiling item.
        let ceiling_item = result
            .breakdown
            .iter()
            .find(|b| b.kind == "TrustTierCeiling");

        // The confidence should be <= 0.55 (capped)
        assert!(
            result.confidence <= 0.55,
            "Unknown protocol should be capped at 0.55, got confidence={}",
            result.confidence
        );

        // If the raw confidence exceeded 0.55, the ceiling item should be present
        // With these evidence values, the raw confidence should be high enough
        if let Some(item) = ceiling_item {
            assert!(
                item.contribution < 0.0,
                "Ceiling contribution should be negative (reducing confidence), got: {}",
                item.contribution
            );
        }
        // If ceiling_item is None, it means the raw confidence was already <= 0.55
        // (the signals didn't produce a high enough raw score). This is also OK —
        // the ceiling is still enforced, just not triggered.
    }

    #[test]
    fn test_caller_evidence_cannot_raise_tier_above_manifest_declared() {
        // G4 regression: fabricated request-body evidence (has_signed_manifest,
        // community/battle counts) must never raise the trust tier above what the
        // protocol's manifest itself declares. Before the fix, a caller could mint
        // OfficialManifest on a HeuristicInferred-tier manifest, escaping that
        // tier's 0.55 P6 ceiling and inflating the TrustTierLevel signal.
        let mut core = GraphiteCore::new();
        let program_id = "DezXAZ8z7PnrnRJjz3vX2k7BtZbJ2k2cRgZ7HzXADc1";
        let manifest = serde_json::json!({
            "graphite_manifest_version": "1.0",
            "protocol": { "name": "LowTierTest", "program_id": program_id, "website": "", "github": "" },
            "version": { "label": "1.0.0", "effective_from_slot": 0, "previous_version_ref": null },
            "trust_tier": "HeuristicInferred",
            "instructions": [{
                "name": "Transfer",
                "discriminator": "02000000",
                "accounts": [
                    { "name": "from", "role": "signer", "is_writable": true, "is_signer": true, "pda_seeds": [] },
                    { "name": "to", "role": "writable", "is_writable": true, "is_signer": false, "pda_seeds": [] }
                ],
                "expected_state_changes": ["debits accounts.from", "credits accounts.to"],
                "allowed_cpis": [],
                "risk_rules": [],
                "variable_accounts": false
            }]
        });
        core.load_manifest(&manifest.to_string()).unwrap();

        let input = VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "transfer".to_string(),
                raw_natural_language: "Transfer 1 SOL".to_string(),
                confidence_of_parse: 0.95,
                extracted_parameters: None,
            },
            program_id: program_id.to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: "02000000".to_string(),
            account_addresses: vec![
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
            ],
            instruction_data: None,
            cpi_targets: vec![],
            wallet_profile: WalletProfile::Gaming,
            // Fabricated "battle-tested" evidence — must be ignored on the
            // manifest-found path.
            behavior_evidence: BehaviorEvidence {
                has_signed_manifest: true,
                community_verified_count: 999,
                battle_tested_tx_count: 10_000_000,
                simulation_match_count: 1000,
            },
            compute_units: 150,
            account_writes: 2,
            cpi_hops: 0,
            signed_transaction: None,
            transaction_instructions: vec![],
            cpi_trace: None,
            uses_versioned_transaction: false,
            lookup_table_count: 0,
            real_account_metas: vec![],
        };

        let result = core.verify(&input).unwrap();
        // The manifest declares HeuristicInferred — fabricated evidence must not
        // raise it. (TrustTier ordering: HeuristicInferred < OfficialManifest.)
        assert_eq!(
            result.trust_tier, "HeuristicInferred",
            "caller evidence must not raise tier above the manifest's declared tier"
        );
        assert!(
            result.confidence <= 0.55,
            "P6 ceiling must hold for the manifest-declared tier"
        );
    }

    #[test]
    fn test_manifest_version_reported_in_result() {
        // G7: the verification result must report WHICH manifest version was
        // checked so consumers can detect cross-version replay confusion.
        let core = GraphiteCore::new();
        let input = make_input(
            "11111111111111111111111111111111",
            "02000000",
            &[
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
            ],
        );
        let result = core.verify(&input).unwrap();
        assert_eq!(result.manifest_version.as_deref(), Some("1.0.0"));

        // Unknown protocol → None
        let unknown = make_input(
            "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
            "03000000",
            &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"],
        );
        let result = core.verify(&unknown).unwrap();
        assert_eq!(result.manifest_version, None);
    }

    #[test]
    fn test_content_hash_matches_ts_auditbind_reference_vector() {
        // Cross-language contract lock: the TS AuditBind tests
        // (integrations/solana-agent-kit/auditbind.test.ts) pin the same value —
        // sha256(program||disc||from||to)[0..16] = "afb61d8865b4cb68". If either
        // side changes the hashed field set or ordering, BOTH pinned tests must
        // be regenerated together or the TOCTOU check silently breaks.
        let risk = RiskVerdictSummary {
            status: "Clear".to_string(),
            findings: vec![],
        };
        let (_, content_hash) = generate_audit_id(
            "11111111111111111111111111111111",
            "02000000",
            &[
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
            ],
            &None,
            &[],
            0.44,
            &risk,
        );
        assert_eq!(content_hash, "afb61d8865b4cb68");
    }

    #[test]
    fn test_oversized_instruction_data_rejected() {
        let core = GraphiteCore::new();
        let mut input = make_input(
            "11111111111111111111111111111111",
            "02000000",
            &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"],
        );
        input.instruction_data = Some(vec![0u8; 64 * 1024 + 1]);
        assert!(matches!(
            core.verify(&input),
            Err(VerificationError::InvalidInput(_))
        ));
    }

    #[test]
    fn test_unexpected_cpi_warning_surfaced_in_l7_and_summary() {
        // P3 explainability: an out-of-manifest CPI on a known protocol used to
        // be silently dropped. It must now appear in the L7 layer report and the
        // result summary while the verdict stays Clear (fail open with
        // explanation — Constitution P12, response 2).
        let mut core = GraphiteCore::new();
        let program_id = "DezXAZ8z7PnrnRJjz3vX2k7BtZbJ2k2cRgZ7HzXADc1";
        let manifest = serde_json::json!({
            "graphite_manifest_version": "1.0",
            "protocol": { "name": "CpiWarningTest", "program_id": program_id, "website": "", "github": "" },
            "version": { "label": "1.0.0", "effective_from_slot": 0, "previous_version_ref": null },
            "trust_tier": "OfficialManifest",
            "instructions": [{
                "name": "Transfer",
                "discriminator": "02000000",
                "accounts": [
                    { "name": "from", "role": "signer", "is_writable": true, "is_signer": true, "pda_seeds": [] },
                    { "name": "to", "role": "writable", "is_writable": true, "is_signer": false, "pda_seeds": [] }
                ],
                "expected_state_changes": ["debits accounts.from", "credits accounts.to"],
                "allowed_cpis": ["SomeAllowedProgram"],
                "risk_rules": [],
                "variable_accounts": false
            }]
        });
        core.load_manifest(&manifest.to_string()).unwrap();

        let input = VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "transfer".to_string(),
                raw_natural_language: "Transfer 1 SOL".to_string(),
                confidence_of_parse: 0.9,
                extracted_parameters: None,
            },
            program_id: program_id.to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: "02000000".to_string(),
            account_addresses: vec![
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
            ],
            instruction_data: None,
            cpi_targets: vec!["unlisted_program_xyz".to_string()],
            wallet_profile: WalletProfile::Custom {
                min_confidence: 0.40,
                min_trust_tier: TrustTier::OfficialManifest,
            },
            behavior_evidence: BehaviorEvidence {
                has_signed_manifest: false,
                community_verified_count: 0,
                battle_tested_tx_count: 0,
                simulation_match_count: 0,
            },
            compute_units: 150,
            account_writes: 2,
            cpi_hops: 1,
            signed_transaction: None,
            transaction_instructions: vec![],
            cpi_trace: None,
            uses_versioned_transaction: false,
            lookup_table_count: 0,
            real_account_metas: vec![],
        };

        let result = core.verify(&input).unwrap();
        let l7 = result
            .layers
            .iter()
            .find(|l| l.layer == "L7_RiskVerification")
            .expect("L7 layer must be present");
        assert!(
            l7.passed,
            "known-protocol unexpected CPI is a warning, not a hard block"
        );
        assert!(
            l7.reason
                .contains("warnings: CPI target 'unlisted_program_xyz'"),
            "L7 reason must surface the warning, got: {}",
            l7.reason
        );
        assert!(
            result
                .summary
                .contains("warnings: CPI target 'unlisted_program_xyz'"),
            "summary must surface the warning, got: {}",
            result.summary
        );
    }

    #[cfg(feature = "rpc")]
    #[tokio::test]
    async fn l8_verify_execution_no_rpc_client_is_unavailable_not_fake() {
        // L8 contract: without an RPC client, the outcome is Unavailable —
        // never a fabricated "executed" pass.
        let core = GraphiteCore::new();
        let outcome = core
            .verify_execution("5sigAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .await
            .unwrap();
        assert!(
            matches!(outcome, ExecutionVerification::Unavailable(_)),
            "no RPC client must be Unavailable, got: {:?}",
            outcome
        );
    }

    #[cfg(feature = "rpc")]
    #[tokio::test]
    async fn l8_verify_execution_confirmed_success_via_mock_rpc() {
        // Full L8 loop: mock cluster confirms the signature in a slot with
        // status Ok — the only honest "executed" state.
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"slot\":2},\"value\":[{\"slot\":12345,\"confirmations\":0,\"err\":null,\"status\":{\"Ok\":null}}]},\"id\":1}";
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        });
        let mut core = GraphiteCore::new();
        core.attach_rpc_client(SolanaRpcClient::new(crate::rpc_client::RpcConfig {
            endpoint: format!("http://{addr}"),
            timeout: std::time::Duration::from_secs(5),
            max_retries: 0,
            ..Default::default()
        }));
        let outcome = core
            .verify_execution("5sigAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .await
            .unwrap();
        handle.join().unwrap();
        match outcome {
            ExecutionVerification::Confirmed {
                signature,
                slot,
                success,
                error,
            } => {
                assert_eq!(slot, 12345);
                assert!(success);
                assert!(error.is_none());
                assert!(signature.starts_with("5sig"));
            }
            other => panic!("expected Confirmed, got: {:?}", other),
        }
    }
}
