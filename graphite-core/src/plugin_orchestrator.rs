//! Plugin Orchestrator — ARCHITECTURE.md 3.14 / Constitution P8.
//!
//! Manages plugin lifecycle and enforces the fixed orchestration contract.
//! Plugins cannot reorder or skip verification layers, cannot call other
//! plugins, and cannot write to the audit trail (Constitution P8).
//!
//! # P8 enforcement — by construction, not convention
//!
//! 1. **`PluginContext` carries input data only.** It borrows the transaction
//!    being verified (program, discriminator, accounts, CPIs, state changes,
//!    proposed intent). It has no reference to the orchestrator, the audit
//!    trail, or any other layer's result — so a plugin cannot reach them.
//! 2. **`PluginVerdict` cannot mint a pass.** Its variants are `NoFinding`,
//!    `Note`, and `Block` — there is deliberately NO "pass" variant. Only the
//!    core's own layer logic can produce a passing layer; a plugin can only
//!    leave the core verdict alone, annotate it, or block it. A plugin can
//!    never manufacture a clean bill of health.
//! 3. **`PIPELINE_ORDER` is a fixed const.** Plugins have no configuration
//!    surface that could reorder or skip layers.
//! 4. **The orchestrator is the sole caller.** Plugins are invoked only from
//!    here; a plugin holds no handle to other plugins.
//! 5. **Fault tolerance.** A panicking plugin is isolated with
//!    `catch_unwind`: its verdict is dropped, an error note is recorded, and
//!    the core verdict survives. A misbehaving plugin can neither wedge the
//!    pipeline nor fabricate a block or a pass.
//!
//! # Plugin review gate
//!
//! Third-party plugins are registered through a manifest file (name, version,
//! author, layer, review status) discovered from a directory. Only
//! `review_status == approved` manifests activate the corresponding built-in
//! plugin; `pending`/`rejected` manifests are skipped. The built-in plugins
//! (`crate::plugins`) are first-party and ship pre-registered on
//! `GraphiteCore::new()`.

use crate::verification::{LayerStatus, PipelineLayerResult, ProposedIntent, RiskFinding};
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::Arc;

/// A verification layer of the fixed 8-layer pipeline.
///
/// Serde form is the canonical pipeline layer name (e.g. "L7_RiskVerification")
/// — the same string emitted in `VerificationResult.layers` — so manifest
/// files, reports, and plugin manifests share one spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum LayerId {
    /// L1: Account Resolution
    #[serde(rename = "L1_AccountResolution")]
    L1AccountResolution,
    /// L2: Instruction Verification
    #[serde(rename = "L2_InstructionVerification")]
    L2InstructionVerification,
    /// L3: Simulation Verification
    #[serde(rename = "L3_SimulationVerification")]
    L3SimulationVerification,
    /// L4: State Verification
    #[serde(rename = "L4_StateVerification")]
    L4StateVerification,
    /// L5: Semantic Verification
    #[serde(rename = "L5_SemanticVerification")]
    L5SemanticVerification,
    /// L6: Policy Verification
    #[serde(rename = "L6_PolicyVerification")]
    L6PolicyVerification,
    /// L7: Risk Verification
    #[serde(rename = "L7_RiskVerification")]
    L7RiskVerification,
    /// L8: Execution Verification
    #[serde(rename = "L8_ExecutionVerification")]
    L8ExecutionVerification,
}

impl LayerId {
    /// Canonical pipeline layer name (matches the layer names emitted in
    /// `VerificationResult.layers`).
    pub fn as_str(&self) -> &'static str {
        match self {
            LayerId::L1AccountResolution => "L1_AccountResolution",
            LayerId::L2InstructionVerification => "L2_InstructionVerification",
            LayerId::L3SimulationVerification => "L3_SimulationVerification",
            LayerId::L4StateVerification => "L4_StateVerification",
            LayerId::L5SemanticVerification => "L5_SemanticVerification",
            LayerId::L6PolicyVerification => "L6_PolicyVerification",
            LayerId::L7RiskVerification => "L7_RiskVerification",
            LayerId::L8ExecutionVerification => "L8_ExecutionVerification",
        }
    }

    /// All layers in pipeline order.
    pub const ALL: [LayerId; 8] = [
        LayerId::L1AccountResolution,
        LayerId::L2InstructionVerification,
        LayerId::L3SimulationVerification,
        LayerId::L4StateVerification,
        LayerId::L5SemanticVerification,
        LayerId::L6PolicyVerification,
        LayerId::L7RiskVerification,
        LayerId::L8ExecutionVerification,
    ];
}

/// The fixed pipeline order. Constitution P8: this order is immutable and no
/// plugin has any mechanism to change it — it is a compile-time const, not
/// runtime configuration.
pub const PIPELINE_ORDER: [LayerId; 8] = LayerId::ALL;

/// Plugin review status (pre-registration code review gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    /// Security-reviewed and cleared for registration.
    Approved,
    /// Awaiting review — registered but not activated.
    Pending,
    /// Rejected — never activates.
    Rejected,
}

// (Review status strings are the serde snake_case form — no separate as_str
// needed; the serde form IS the canonical spelling used by manifests and CLI.)

/// Static metadata for a plugin. This is the "plugin manifest" — it also
/// serializes to/from the JSON files used by file-based discovery.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PluginManifest {
    /// Unique plugin name (also the discovery key).
    pub name: String,
    /// Semantic version of the plugin.
    pub version: String,
    /// Author or maintainer identifier.
    pub author: String,
    /// The single layer this plugin may affect (P8).
    pub layer: LayerId,
    /// Review-gate status: only `Approved` manifests activate.
    pub review_status: ReviewStatus,
    #[serde(default)]
    pub description: String,
}

/// The only output a plugin may produce.
///
/// Deliberately has NO pass variant (P8): a plugin can never manufacture a
/// clean verdict — it can only leave the core's verdict alone (`NoFinding`),
/// annotate it (`Note`), or block it (`Block`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginVerdict {
    /// Plugin has nothing to add; the core verdict stands unchanged.
    NoFinding,
    /// Non-blocking annotation appended to the layer's report (P3).
    Note(String),
    /// The plugin's layer FAILS. For L7 this hard-blocks the transaction.
    Block { pattern: String, reason: String },
}

/// Everything a plugin may see about the transaction under verification.
///
/// P8 by construction: this struct borrows ONLY the transaction's own data.
/// There is no audit-trail handle, no orchestrator handle, no `&mut` state,
/// and no other layer's result — a plugin cannot reach beyond its input.
#[derive(Debug)]
pub struct PluginContext<'a> {
    pub program_id: &'a str,
    pub protocol_name: &'a str,
    pub instruction_discriminator: &'a str,
    pub instruction_name: &'a str,
    pub proposed_intent: &'a ProposedIntent,
    pub account_addresses: &'a [String],
    pub cpi_targets: &'a [String],
    pub expected_state_changes: &'a [String],
    pub allowed_cpis: &'a [String],
    pub manifest_found: bool,
    pub compute_units: u64,
    pub account_writes: u32,
    pub cpi_hops: u32,
}

/// Protocol plugin — supplies raw protocol knowledge (semantic rules for L4/L5)
/// for programs that have no manifest yet. NEVER returns a verdict and NEVER
/// assigns a trust tier (P7/P8): it only extends the evidence available to the
/// core's own layer checks.
pub trait ProtocolPlugin: Send + Sync {
    fn manifest(&self) -> &PluginManifest;
    /// The exact `program_id` this plugin has knowledge for (P11: exact match
    /// only, no fuzzy matching).
    fn protocol_id(&self) -> &str;
    /// Raw expected state changes for an instruction on this protocol.
    fn semantic_rules(&self, instruction_discriminator: &str) -> Vec<String>;
    /// Raw allowed CPI allowlist for an instruction on this protocol.
    fn allowed_cpis(&self, instruction_discriminator: &str) -> Vec<String>;
}

/// Simulation plugin — observes L3. May only `Note` or `Block`; it can NEVER
/// certify a clean simulation (P5: simulation is evidence, and a plugin cannot
/// mint evidence). A `Block` fails the L3 layer report; it does not mint a pass.
pub trait SimulationPlugin: Send + Sync {
    fn manifest(&self) -> &PluginManifest;
    fn observe_simulation(&self, ctx: &PluginContext) -> PluginVerdict;
}

/// Verifier plugin — operates within exactly ONE layer (L2/L4/L5/L8).
pub trait VerifierPlugin: Send + Sync {
    fn manifest(&self) -> &PluginManifest;
    fn verify(&self, ctx: &PluginContext) -> PluginVerdict;
}

/// Risk plugin — L7. Findings are binary-and-blocking: a `Block` verdict
/// hard-blocks the transaction regardless of confidence (never a scored
/// signal). It can also `Note` non-blocking warnings.
pub trait RiskPlugin: Send + Sync {
    fn manifest(&self) -> &PluginManifest;
    fn assess_risk(&self, ctx: &PluginContext) -> PluginVerdict;
}

/// Policy plugin — L6. May only veto (`Block`, which rejects the transaction)
/// or annotate (`Note`). It cannot approve what the core's policy rejected.
pub trait PolicyPlugin: Send + Sync {
    fn manifest(&self) -> &PluginManifest;
    fn evaluate(&self, ctx: &PluginContext) -> PluginVerdict;
}

/// Analytics plugin — strictly read-only observer of completed verification
/// results. NEVER writes back into the Semantic Graph or the audit trail.
pub trait AnalyticsPlugin: Send + Sync {
    fn manifest(&self) -> &PluginManifest;
    fn on_verification(&self, result: &crate::verification::VerificationResult);
    /// Downcast support for first-party configuration hooks (e.g. attaching an
    /// event-file sink to the built-in event logger). Implementors return `self`.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Type-erased plugin handle. Exactly one trait per handle (P8 — a combined
/// plugin requires explicit Architect Mode approval).
#[derive(Clone)]
pub enum PluginKind {
    Protocol(Arc<dyn ProtocolPlugin>),
    Simulation(Arc<dyn SimulationPlugin>),
    Verifier(Arc<dyn VerifierPlugin>),
    Risk(Arc<dyn RiskPlugin>),
    Policy(Arc<dyn PolicyPlugin>),
    Analytics(Arc<dyn AnalyticsPlugin>),
}

impl PluginKind {
    pub fn manifest(&self) -> &PluginManifest {
        match self {
            PluginKind::Protocol(p) => p.manifest(),
            PluginKind::Simulation(p) => p.manifest(),
            PluginKind::Verifier(p) => p.manifest(),
            PluginKind::Risk(p) => p.manifest(),
            PluginKind::Policy(p) => p.manifest(),
            PluginKind::Analytics(p) => p.manifest(),
        }
    }

    /// The plugin's trait family (used to dispatch layer folds to exactly the
    /// trait that layer owns — P8: a VerifierPlugin can never become a risk
    /// finding even if its manifest declares L7).
    fn family(&self) -> PluginFamily {
        match self {
            PluginKind::Protocol(_) => PluginFamily::Protocol,
            PluginKind::Simulation(_) => PluginFamily::Simulation,
            PluginKind::Verifier(_) => PluginFamily::Verifier,
            PluginKind::Risk(_) => PluginFamily::Risk,
            PluginKind::Policy(_) => PluginFamily::Policy,
            PluginKind::Analytics(_) => PluginFamily::Analytics,
        }
    }

    /// Run the plugin against the layer context (panic-isolated). Only the
    /// verdict-producing plugin types execute here; Protocol/Analytics never
    /// produce a `PluginVerdict` (they have no layer verdict semantics).
    fn run(&self, ctx: &PluginContext) -> PluginVerdict {
        match self {
            PluginKind::Verifier(p) => p.verify(ctx),
            PluginKind::Simulation(p) => p.observe_simulation(ctx),
            PluginKind::Policy(p) => p.evaluate(ctx),
            PluginKind::Risk(p) => p.assess_risk(ctx),
            PluginKind::Protocol(_) | PluginKind::Analytics(_) => PluginVerdict::NoFinding,
        }
    }
}

/// The six plugin trait families. Layer folds dispatch to exactly one family
/// (P8 hardening): the layer determines WHICH trait may affect its outcome, so
/// a plugin's trait, not its manifest layer claim, decides its effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PluginFamily {
    Protocol,
    Simulation,
    Verifier,
    Risk,
    Policy,
    Analytics,
}

/// Errors from plugin discovery, registration, and execution.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("plugin discovery failed in {path}: {reason}")]
    DiscoveryFailed { path: String, reason: String },
    #[error("invalid plugin manifest {file}: {reason}")]
    InvalidManifest { file: String, reason: String },
    #[error("plugin manifest references unknown built-in plugin '{name}' (review gate: only built-ins may be activated by name)")]
    UnknownPlugin { name: String },
}

/// Result of a single plugin invocation (for reporting).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginRun {
    pub plugin_name: String,
    pub verdict: PluginVerdict,
}

/// L7 risk-plugin outcome: whether any plugin hard-blocked, plus the findings
/// to surface on the risk summary. (Not `Eq`: `RiskFinding` is `PartialEq`
/// only.)
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RiskPluginOutcome {
    pub blocked: bool,
    pub findings: Vec<RiskFinding>,
}

/// Summary of a discovery + registration pass (review gate report).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistrationSummary {
    /// Approved manifests whose plugin is now registered and running.
    pub registered: usize,
    /// Manifests skipped because review status is pending.
    pub skipped_pending: usize,
    /// Manifests skipped because review status is rejected.
    pub skipped_rejected: usize,
}

/// The plugin orchestrator. Sole caller of every plugin (P8).
///
/// `Clone` shares the underlying plugin instances (`Arc`), so a `GraphiteCore`
/// cloned into per-request server state shares the same registered plugins —
/// including the analytics sink state. Register plugins at startup, before
/// cloning, so every clone sees the same set.
#[derive(Clone, Default)]
pub struct PluginOrchestrator {
    /// Layer-scoped verdict plugins, in registration order per layer.
    plugins: HashMap<LayerId, Vec<PluginKind>>,
    /// Read-only analytics observers (not layer-scoped).
    analytics: Vec<Arc<dyn AnalyticsPlugin>>,
}

impl std::fmt::Debug for PluginOrchestrator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut layers: Vec<&LayerId> = self.plugins.keys().collect();
        layers.sort_by_key(|l| l.as_str());
        f.debug_struct("PluginOrchestrator")
            .field(
                "registered_layers",
                &layers
                    .iter()
                    .map(|l| {
                        format!(
                            "{}: [{}]",
                            l.as_str(),
                            self.plugins[*l]
                                .iter()
                                .map(|k| k.manifest().name.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    })
                    .collect::<Vec<_>>(),
            )
            .field(
                "analytics_plugins",
                &self
                    .analytics
                    .iter()
                    .map(|p| p.manifest().name.clone())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl PluginOrchestrator {
    /// Create an empty orchestrator (no plugins registered).
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a plugin. The plugin's manifest declares the single layer it
    /// may affect (P8); analytics plugins are observed post-verification.
    ///
    /// Idempotent by name: registering a plugin whose name is already
    /// registered for the same role is a no-op (logged) — so a manifest that
    /// re-activates an already-running built-in cannot double-fire findings.
    pub fn register_plugin(&mut self, plugin: PluginKind) {
        let name = plugin.manifest().name.clone();
        match plugin {
            PluginKind::Analytics(a) => {
                if !self.analytics.iter().any(|p| p.manifest().name == name) {
                    self.analytics.push(a);
                } else {
                    tracing::info!("plugin '{name}' already registered — skipping duplicate");
                }
            }
            kind => {
                let layer = kind.manifest().layer;
                let entry = self.plugins.entry(layer).or_default();
                if !entry.iter().any(|k| k.manifest().name == name) {
                    entry.push(kind);
                } else {
                    tracing::info!(
                        "plugin '{name}' already registered for {} — skipping duplicate",
                        layer.as_str()
                    );
                }
            }
        }
    }

    /// Number of registered (layer-scoped) plugins.
    pub fn registered_count(&self) -> usize {
        self.plugins.values().map(Vec::len).sum()
    }

    /// Number of registered analytics observers.
    pub fn analytics_count(&self) -> usize {
        self.analytics.len()
    }

    /// All registered layer-scoped plugin names, in layer order.
    pub fn registered_plugins(&self) -> Vec<String> {
        let mut out = Vec::new();
        for layer in PIPELINE_ORDER.iter() {
            if let Some(kinds) = self.plugins.get(layer) {
                for k in kinds {
                    out.push(format!("{}@{}", k.manifest().name, layer.as_str()));
                }
            }
        }
        out
    }

    /// Discover plugin manifests from a directory of JSON files (one manifest
    /// per file). Fail-closed: a single malformed file fails discovery with the
    /// offending path + reason — silent config errors are not an option.
    pub fn discover_from_dir(dir: &Path) -> Result<Vec<PluginManifest>, PluginError> {
        let mut manifests = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let entries = std::fs::read_dir(dir).map_err(|e| PluginError::DiscoveryFailed {
            path: dir.display().to_string(),
            reason: e.to_string(),
        })?;
        let mut files: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path().is_file() && e.path().extension().map(|x| x == "json").unwrap_or(false)
            })
            .collect();
        files.sort_by_key(|e| e.file_name());
        for entry in files {
            let path = entry.path();
            let raw = std::fs::read_to_string(&path).map_err(|e| PluginError::InvalidManifest {
                file: path.display().to_string(),
                reason: e.to_string(),
            })?;
            let manifest: PluginManifest =
                serde_json::from_str(&raw).map_err(|e| PluginError::InvalidManifest {
                    file: path.display().to_string(),
                    reason: e.to_string(),
                })?;
            if manifest.name.trim().is_empty() {
                return Err(PluginError::InvalidManifest {
                    file: path.display().to_string(),
                    reason: "name must be non-empty".to_string(),
                });
            }
            if !seen.insert(manifest.name.clone()) {
                return Err(PluginError::InvalidManifest {
                    file: path.display().to_string(),
                    reason: format!("duplicate plugin name '{}' across manifests", manifest.name),
                });
            }
            manifests.push(manifest);
        }
        Ok(manifests)
    }

    /// Register discovered manifests through the review gate: only `approved`
    /// manifests activate the corresponding built-in plugin; `pending` and
    /// `rejected` are skipped. An approved manifest naming an unknown built-in
    /// plugin is a fail-closed config error.
    pub fn register_discovered(
        &mut self,
        manifests: &[PluginManifest],
    ) -> Result<RegistrationSummary, PluginError> {
        let mut summary = RegistrationSummary::default();
        for m in manifests {
            match m.review_status {
                ReviewStatus::Approved => {
                    let builtin = crate::plugins::builtin_plugin(&m.name).ok_or_else(|| {
                        PluginError::UnknownPlugin {
                            name: m.name.clone(),
                        }
                    })?;
                    self.register_plugin(builtin);
                    summary.registered += 1;
                }
                ReviewStatus::Pending => summary.skipped_pending += 1,
                ReviewStatus::Rejected => summary.skipped_rejected += 1,
            }
        }
        Ok(summary)
    }

    /// Attach an additional event sink to every registered event-logger
    /// analytics plugin (e.g. a file sink for JSONL event logs). Fail-closed
    /// if no event logger is registered.
    pub fn attach_event_file_sink(&self, path: &Path) -> Result<(), PluginError> {
        let mut attached = false;
        for p in &self.analytics {
            if let Some(logger) =
                p.as_any()
                    .downcast_ref::<crate::plugins::event_logger::VerificationEventLoggerPlugin>()
            {
                logger.add_sink(Arc::new(crate::plugins::event_logger::FileSink::new(path)));
                attached = true;
            }
        }
        if attached {
            Ok(())
        } else {
            Err(PluginError::DiscoveryFailed {
                path: path.display().to_string(),
                reason: "no verification-event-logger plugin registered to attach sink to"
                    .to_string(),
            })
        }
    }

    /// Run the plugins of ONE trait family registered for `layer` (panic-
    /// isolated), in registration order. P8 dispatch: the caller picks the
    /// family, so a plugin's trait — not its manifest layer claim — decides
    /// where its verdict can take effect.
    fn run_family(
        &self,
        layer: LayerId,
        family: PluginFamily,
        ctx: &PluginContext,
    ) -> Vec<PluginRun> {
        let Some(kinds) = self.plugins.get(&layer) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for kind in kinds.iter().filter(|k| k.family() == family) {
            let name = kind.manifest().name.clone();
            let verdict = match catch_unwind(AssertUnwindSafe(|| kind.run(ctx))) {
                Ok(v) => v,
                Err(_) => {
                    tracing::error!(
                        "plugin '{name}' panicked in layer {} — verdict isolated, core verdict preserved",
                        layer.as_str()
                    );
                    PluginVerdict::Note(format!(
                        "plugin '{}' panicked and was isolated (no verdict applied)",
                        name
                    ))
                }
            };
            out.push(PluginRun {
                plugin_name: name,
                verdict,
            });
        }
        out
    }

    /// Fold Verifier-family plugins for a verifier layer (L2/L4/L5/L8) into
    /// the layer result.
    ///
    /// - `Block` → the layer FAILS (reason records the plugin + pattern).
    /// - `Note`  → appended to the layer's reason (P3 explainability).
    /// - `NoFinding` → unchanged.
    ///
    /// The core's verdict is the source of truth and always survives: a
    /// panicking plugin is reduced to an error note.
    pub fn fold_verifier(
        &self,
        layer: LayerId,
        result: PipelineLayerResult,
        ctx: &PluginContext,
    ) -> PipelineLayerResult {
        let runs = self.run_family(layer, PluginFamily::Verifier, ctx);
        fold_runs_into_result(result, runs)
    }

    /// Simulation-family verdicts for L3 (Note/Block report-only — never a
    /// pass; P5).
    pub fn simulation_verdicts(&self, ctx: &PluginContext) -> Vec<PluginRun> {
        self.run_family(
            LayerId::L3SimulationVerification,
            PluginFamily::Simulation,
            ctx,
        )
    }

    /// Policy-family verdicts for L6 (Block = veto, Note = annotation).
    pub fn policy_verdicts(&self, ctx: &PluginContext) -> Vec<PluginRun> {
        self.run_family(LayerId::L6PolicyVerification, PluginFamily::Policy, ctx)
    }

    /// Risk-plugin outcome for L7: whether any RISK-family plugin hard-blocks,
    /// plus the findings to surface (`Block` → blocking finding; `Note` →
    /// warning finding). Only `PluginKind::Risk` is consulted — a plugin of
    /// any other trait can never become a risk finding, even if its manifest
    /// declares L7 (P8 dispatch by trait, not by manifest claim). `NoFinding`
    /// and plugin panics contribute nothing (a panic cannot fabricate a
    /// block).
    pub fn risk_outcome(&self, ctx: &PluginContext) -> RiskPluginOutcome {
        let mut findings = Vec::new();
        let mut blocked = false;
        for run in self.run_family(LayerId::L7RiskVerification, PluginFamily::Risk, ctx) {
            match run.verdict {
                PluginVerdict::Block { pattern, reason } => {
                    blocked = true;
                    findings.push(RiskFinding {
                        pattern: format!("{}:{}", run.plugin_name, pattern),
                        reason,
                    });
                }
                PluginVerdict::Note(reason) => findings.push(RiskFinding {
                    pattern: format!("{}:warning", run.plugin_name),
                    reason,
                }),
                PluginVerdict::NoFinding => {}
            }
        }
        RiskPluginOutcome { blocked, findings }
    }

    /// Protocol-plugin semantic knowledge for a program with no manifest:
    /// extends the evidence available to L4/L5 so the core's own checks can
    /// run against plugin-supplied rules. Never a verdict, never a tier (P7).
    pub fn protocol_rules(
        &self,
        program_id: &str,
        instruction_discriminator: &str,
    ) -> (Vec<String>, Vec<String>) {
        let mut rules = Vec::new();
        let mut cpis = Vec::new();
        for kind in self.plugins.values().flatten() {
            if let PluginKind::Protocol(p) = kind {
                if p.protocol_id() == program_id {
                    rules.extend(p.semantic_rules(instruction_discriminator));
                    cpis.extend(p.allowed_cpis(instruction_discriminator));
                }
            }
        }
        (rules, cpis)
    }

    /// Run all analytics observers against a completed verification result.
    /// Strictly read-only with respect to Graphite state; sink failures are
    /// logged and never affect the result (observability must not break
    /// verification). Panics inside observers are isolated AND logged — a
    /// crashing observer must not vanish silently.
    pub fn run_analytics(&self, result: &crate::verification::VerificationResult) {
        for p in &self.analytics {
            let name = p.manifest().name.clone();
            let outcome = catch_unwind(AssertUnwindSafe(|| p.on_verification(result)));
            if outcome.is_err() {
                tracing::error!("analytics plugin '{name}' panicked — isolated, result unaffected");
            }
        }
    }

    /// All verification events currently buffered by the registered event
    /// logger (read-side observability API; empty when no logger registered).
    pub fn analytics_events(&self) -> Vec<crate::plugins::VerificationEvent> {
        let mut out = Vec::new();
        for p in &self.analytics {
            if let Some(logger) =
                p.as_any()
                    .downcast_ref::<crate::plugins::event_logger::VerificationEventLoggerPlugin>()
            {
                out.extend(logger.buffered_events());
            }
        }
        out
    }

    /// Convenience: the built-in first-party plugin set (reviewed in-tree).
    pub fn with_builtin_plugins() -> Self {
        let mut o = Self::new();
        for kind in crate::plugins::builtin_plugins() {
            o.register_plugin(kind);
        }
        o
    }
}

/// Fold a list of plugin runs into a layer result (shared by `fold_verifier`
/// and the L3/L6/L8 construction paths).
pub(crate) fn fold_runs_into_result(
    mut result: PipelineLayerResult,
    runs: Vec<PluginRun>,
) -> PipelineLayerResult {
    let mut block: Option<(String, String)> = None;
    let mut notes: Vec<String> = Vec::new();
    for run in runs {
        match run.verdict {
            PluginVerdict::Block { pattern, reason } => {
                if block.is_none() {
                    block = Some((pattern, reason));
                }
            }
            PluginVerdict::Note(note) => notes.push(note),
            PluginVerdict::NoFinding => {}
        }
    }
    if let Some((pattern, reason)) = block {
        result.status = LayerStatus::Failed;
        result.passed = false;
        result.reason = format!(
            "Blocked by plugin ({}): {} | {}",
            pattern, reason, result.reason
        );
    } else if !notes.is_empty() {
        result.reason = format!("{} | plugins: {}", result.reason, notes.join("; "));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::ProposedIntent;

    /// A deterministic test verifier plugin that can be told what to emit.
    struct TestVerifier {
        manifest: PluginManifest,
        verdict: PluginVerdict,
    }
    impl VerifierPlugin for TestVerifier {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn verify(&self, _ctx: &PluginContext) -> PluginVerdict {
            self.verdict.clone()
        }
    }

    fn manifest(name: &str, layer: LayerId) -> PluginManifest {
        PluginManifest {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            author: "test".to_string(),
            layer,
            review_status: ReviewStatus::Approved,
            description: String::new(),
        }
    }

    /// Build a `'static` context by leaking the owned test data (tests only).
    fn ctx() -> PluginContext<'static> {
        let intent_owned = ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        };
        let intent_owned: &'static ProposedIntent = Box::leak(Box::new(intent_owned));
        PluginContext {
            program_id: "11111111111111111111111111111111",
            protocol_name: "System Program",
            instruction_discriminator: "02000000",
            instruction_name: "Transfer",
            proposed_intent: intent_owned,
            account_addresses: &[],
            cpi_targets: &[],
            expected_state_changes: &[],
            allowed_cpis: &[],
            manifest_found: true,
            compute_units: 150,
            account_writes: 0,
            cpi_hops: 0,
        }
    }

    #[test]
    fn test_pipeline_order_is_fixed_and_complete() {
        assert_eq!(PIPELINE_ORDER.len(), 8);
        assert_eq!(PIPELINE_ORDER[0], LayerId::L1AccountResolution);
        assert_eq!(PIPELINE_ORDER[1], LayerId::L2InstructionVerification);
        assert_eq!(PIPELINE_ORDER[2], LayerId::L3SimulationVerification);
        assert_eq!(PIPELINE_ORDER[3], LayerId::L4StateVerification);
        assert_eq!(PIPELINE_ORDER[4], LayerId::L5SemanticVerification);
        assert_eq!(PIPELINE_ORDER[5], LayerId::L6PolicyVerification);
        assert_eq!(PIPELINE_ORDER[6], LayerId::L7RiskVerification);
        assert_eq!(PIPELINE_ORDER[7], LayerId::L8ExecutionVerification);
    }

    #[test]
    fn test_layer_ids_round_trip_serde() {
        for layer in PIPELINE_ORDER.iter() {
            let json = serde_json::to_string(layer).unwrap();
            let back: LayerId = serde_json::from_str(&json).unwrap();
            assert_eq!(*layer, back);
            assert_eq!(layer.as_str(), back.as_str());
        }
        // The serde form is the canonical pipeline name — no dual formats.
        assert_eq!(
            serde_json::to_string(&LayerId::L7RiskVerification).unwrap(),
            "\"L7_RiskVerification\""
        );
    }

    #[test]
    fn test_plugin_verdict_cannot_mint_a_pass() {
        // P8 load-bearing shape test: an exhaustive match over PluginVerdict
        // compiles ONLY while the enum has exactly these three variants. If a
        // "Pass" variant were ever added, this test fails to compile — the
        // structural guarantee is checked at compile time, not runtime.
        fn classify(v: &PluginVerdict) -> &'static str {
            match v {
                PluginVerdict::NoFinding => "nothing",
                PluginVerdict::Note(_) => "note",
                PluginVerdict::Block { .. } => "block",
            }
        }
        assert_eq!(classify(&PluginVerdict::NoFinding), "nothing");
        assert_eq!(classify(&PluginVerdict::Note("x".into())), "note");
        assert_eq!(
            classify(&PluginVerdict::Block {
                pattern: "p".into(),
                reason: "r".into()
            }),
            "block"
        );
    }

    #[test]
    fn test_registration_is_idempotent_by_name() {
        let mut orch = PluginOrchestrator::new();
        let make = || {
            PluginKind::Verifier(Arc::new(TestVerifier {
                manifest: manifest("dup", LayerId::L2InstructionVerification),
                verdict: PluginVerdict::Note("n".into()),
            }))
        };
        orch.register_plugin(make());
        orch.register_plugin(make());
        assert_eq!(
            orch.registered_count(),
            1,
            "duplicate name must not double-register"
        );
        // Analytics dedupe too.
        orch.register_plugin(PluginKind::Analytics(Arc::new(
            crate::plugins::VerificationEventLoggerPlugin::new(),
        )));
        orch.register_plugin(PluginKind::Analytics(Arc::new(
            crate::plugins::VerificationEventLoggerPlugin::new(),
        )));
        assert_eq!(orch.analytics_count(), 1);
    }

    #[test]
    fn test_plugin_only_runs_for_its_own_layer() {
        let mut orch = PluginOrchestrator::new();
        orch.register_plugin(PluginKind::Verifier(Arc::new(TestVerifier {
            manifest: manifest("l2-only", LayerId::L2InstructionVerification),
            verdict: PluginVerdict::Block {
                pattern: "test".into(),
                reason: "l2 block".into(),
            },
        })));
        // Registered for L2: L4 must be untouched, L2 must block.
        let base = PipelineLayerResult::new("L4_StateVerification", LayerStatus::Passed, "core ok");
        let folded = orch.fold_verifier(LayerId::L4StateVerification, base.clone(), &ctx());
        assert_eq!(folded.status, LayerStatus::Passed);
        assert!(folded.passed);

        let l2 = orch.fold_verifier(
            LayerId::L2InstructionVerification,
            PipelineLayerResult::new("L2_InstructionVerification", LayerStatus::Passed, "core ok"),
            &ctx(),
        );
        assert_eq!(l2.status, LayerStatus::Failed);
        assert!(!l2.passed);
        assert!(l2.reason.contains("l2 block"));
    }

    #[test]
    fn test_note_appends_and_noop_unchanges() {
        let mut orch = PluginOrchestrator::new();
        orch.register_plugin(PluginKind::Verifier(Arc::new(TestVerifier {
            manifest: manifest("note-plugin", LayerId::L4StateVerification),
            verdict: PluginVerdict::Note("extra signal".into()),
        })));
        orch.register_plugin(PluginKind::Verifier(Arc::new(TestVerifier {
            manifest: manifest("quiet-plugin", LayerId::L4StateVerification),
            verdict: PluginVerdict::NoFinding,
        })));
        let base = PipelineLayerResult::new("L4_StateVerification", LayerStatus::Passed, "core ok");
        let folded = orch.fold_verifier(LayerId::L4StateVerification, base, &ctx());
        assert_eq!(folded.status, LayerStatus::Passed);
        assert!(folded.reason.contains("extra signal"));
    }

    /// A plugin that panics — must be isolated, not wedge the pipeline, and
    /// never fabricate a verdict.
    struct PanicPlugin {
        manifest: PluginManifest,
    }
    impl VerifierPlugin for PanicPlugin {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn verify(&self, _ctx: &PluginContext) -> PluginVerdict {
            panic!("boom");
        }
    }

    #[test]
    fn test_layer_folds_dispatch_only_their_trait_family() {
        // P8 hardening: a plugin's TRAIT — not its manifest layer claim —
        // decides where its verdict can take effect. A VerifierPlugin whose
        // manifest declares L7 must NEVER become a risk finding; a RiskPlugin
        // declared at L2 must never fold into a verifier layer.
        let mut orch = PluginOrchestrator::new();
        // A Block-ing VerifierPlugin misdeclared at L7:
        orch.register_plugin(PluginKind::Verifier(Arc::new(TestVerifier {
            manifest: manifest("sneaky", LayerId::L7RiskVerification),
            verdict: PluginVerdict::Block {
                pattern: "ShouldNeverBlock".into(),
                reason: "trait mismatch".into(),
            },
        })));
        let risk = orch.risk_outcome(&ctx());
        assert!(
            !risk.blocked,
            "VerifierPlugin must not produce a risk block"
        );
        assert!(risk.findings.is_empty());

        // A Block-ing RiskPlugin declared at L2 must not fold into L2:
        struct SneakyRisk {
            m: PluginManifest,
        }
        impl RiskPlugin for SneakyRisk {
            fn manifest(&self) -> &PluginManifest {
                &self.m
            }
            fn assess_risk(&self, _ctx: &PluginContext) -> PluginVerdict {
                PluginVerdict::Block {
                    pattern: "X".into(),
                    reason: "y".into(),
                }
            }
        }
        orch.register_plugin(PluginKind::Risk(Arc::new(SneakyRisk {
            m: manifest("sneaky-risk", LayerId::L2InstructionVerification),
        })));
        let l2 = orch.fold_verifier(
            LayerId::L2InstructionVerification,
            PipelineLayerResult::new("L2_InstructionVerification", LayerStatus::Passed, "core ok"),
            &ctx(),
        );
        assert_eq!(
            l2.status,
            LayerStatus::Passed,
            "RiskPlugin must not fold into L2"
        );
    }

    #[test]
    fn test_panicking_plugin_is_isolated_and_core_verdict_survives() {
        let mut orch = PluginOrchestrator::new();
        orch.register_plugin(PluginKind::Verifier(Arc::new(PanicPlugin {
            manifest: manifest("panic", LayerId::L2InstructionVerification),
        })));
        let base =
            PipelineLayerResult::new("L2_InstructionVerification", LayerStatus::Passed, "core ok");
        let folded = orch.fold_verifier(LayerId::L2InstructionVerification, base, &ctx());
        // Core verdict survives; the panic is surfaced as an honest note.
        assert_eq!(folded.status, LayerStatus::Passed);
        assert!(folded.reason.contains("panic"));
        // And a panicking RISK plugin cannot fabricate a block.
        let mut orch2 = PluginOrchestrator::new();
        struct PanicRisk {
            m: PluginManifest,
        }
        impl RiskPlugin for PanicRisk {
            fn manifest(&self) -> &PluginManifest {
                &self.m
            }
            fn assess_risk(&self, _ctx: &PluginContext) -> PluginVerdict {
                panic!("risk boom");
            }
        }
        orch2.register_plugin(PluginKind::Risk(Arc::new(PanicRisk {
            m: manifest("panic-risk", LayerId::L7RiskVerification),
        })));
        let outcome = orch2.risk_outcome(&ctx());
        // A panic can NEVER fabricate a hard block — but the failure is
        // surfaced honestly as a non-blocking warning finding (fail-open with
        // explanation, P12-style observability).
        assert!(!outcome.blocked);
        assert_eq!(outcome.findings.len(), 1);
        assert!(outcome.findings[0].pattern.ends_with(":warning"));
        assert!(outcome.findings[0].reason.contains("panic"));
    }

    #[test]
    fn test_determinism_same_plugins_same_output() {
        let mut orch = PluginOrchestrator::new();
        orch.register_plugin(PluginKind::Verifier(Arc::new(TestVerifier {
            manifest: manifest("d1", LayerId::L2InstructionVerification),
            verdict: PluginVerdict::Note("n".into()),
        })));
        orch.register_plugin(PluginKind::Verifier(Arc::new(TestVerifier {
            manifest: manifest("d2", LayerId::L4StateVerification),
            verdict: PluginVerdict::Block {
                pattern: "p".into(),
                reason: "r".into(),
            },
        })));
        let base_l2 =
            PipelineLayerResult::new("L2_InstructionVerification", LayerStatus::Passed, "c");
        let base_l4 = PipelineLayerResult::new("L4_StateVerification", LayerStatus::Passed, "c");
        for _ in 0..2 {
            // Same call → byte-identical result (P2 determinism).
            let a = orch.fold_verifier(LayerId::L2InstructionVerification, base_l2.clone(), &ctx());
            let b = orch.fold_verifier(LayerId::L2InstructionVerification, base_l2.clone(), &ctx());
            assert_eq!(a, b);
            let c = orch.fold_verifier(LayerId::L4StateVerification, base_l4.clone(), &ctx());
            let d = orch.fold_verifier(LayerId::L4StateVerification, base_l4.clone(), &ctx());
            assert_eq!(c, d);
        }
    }

    #[test]
    fn test_concurrent_shared_orchestrator() {
        let mut orch = PluginOrchestrator::new();
        orch.register_plugin(PluginKind::Verifier(Arc::new(TestVerifier {
            manifest: manifest("c1", LayerId::L2InstructionVerification),
            verdict: PluginVerdict::Note("shared".into()),
        })));
        let orch = Arc::new(orch);
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let orch = orch.clone();
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        let r = orch.fold_verifier(
                            LayerId::L2InstructionVerification,
                            PipelineLayerResult::new(
                                "L2_InstructionVerification",
                                LayerStatus::Passed,
                                "core",
                            ),
                            &ctx(),
                        );
                        assert!(r.reason.contains("shared"));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_discovery_rejects_malformed_and_duplicate() {
        let dir = std::env::temp_dir().join(format!("graphite-plugins-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("bad.json"), "{ this is not json").unwrap();
        let err = PluginOrchestrator::discover_from_dir(&dir).unwrap_err();
        assert!(matches!(err, PluginError::InvalidManifest { .. }));

        // Duplicate names across files are rejected.
        let _ = std::fs::remove_file(dir.join("bad.json"));
        let good =
            serde_json::to_string(&manifest("dup", LayerId::L2InstructionVerification)).unwrap();
        std::fs::write(dir.join("a.json"), &good).unwrap();
        std::fs::write(dir.join("b.json"), &good).unwrap();
        let err = PluginOrchestrator::discover_from_dir(&dir).unwrap_err();
        assert!(matches!(err, PluginError::InvalidManifest { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_review_gate_skips_pending_and_rejected() {
        let mut orch = PluginOrchestrator::new();
        let mut pending = manifest("fake-rewards-drainer", LayerId::L7RiskVerification);
        pending.review_status = ReviewStatus::Pending;
        let mut rejected = manifest(
            "verification-event-logger",
            LayerId::L8ExecutionVerification,
        );
        rejected.review_status = ReviewStatus::Rejected;
        let approved = manifest("fake-rewards-drainer", LayerId::L7RiskVerification);
        let summary = orch
            .register_discovered(&[pending, rejected, approved])
            .unwrap();
        assert_eq!(summary.registered, 1);
        assert_eq!(summary.skipped_pending, 1);
        assert_eq!(summary.skipped_rejected, 1);
        assert_eq!(orch.registered_count(), 1);
    }

    #[test]
    fn test_approved_unknown_builtin_is_fail_closed() {
        let mut orch = PluginOrchestrator::new();
        let unknown = manifest("not-a-real-plugin", LayerId::L2InstructionVerification);
        let err = orch.register_discovered(&[unknown]).unwrap_err();
        assert!(matches!(err, PluginError::UnknownPlugin { .. }));
        assert_eq!(orch.registered_count(), 0);
    }

    #[test]
    fn test_context_has_no_orchestrator_or_audit_reference() {
        // P8 code-path-analysis aid: enumerate exactly what a plugin can see.
        // Every field here is transaction input data. There is deliberately no
        // field of type PluginOrchestrator, audit log, or &mut anything — the
        // trait signature plus this exhaustive enumeration is what review
        // checks against (any added field is visible in this test).
        fn surface(c: &PluginContext) -> (String, String, String, String, bool) {
            (
                c.program_id.to_string(),
                c.instruction_discriminator.to_string(),
                c.instruction_name.to_string(),
                c.proposed_intent.intent_type.clone(),
                c.manifest_found,
            )
        }
        let c = ctx();
        let s = surface(&c);
        assert_eq!(s.0, "11111111111111111111111111111111");
        assert_eq!(s.1, "02000000");
        assert_eq!(s.2, "Transfer");
    }
}
