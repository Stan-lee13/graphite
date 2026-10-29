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
//! 5. **Fault tolerance, fail-closed.** A panicking plugin is isolated with
//!    `catch_unwind`, so it can never wedge the pipeline or fabricate a
//!    pass. Since Round 40 each run has a deadline ([`PLUGIN_DEADLINE`]) on
//!    a thread of its own, and a run past it is a panicking run. What its panic MEANS depends on what its verdict could have
//!    done: a Risk or Verifier plugin — one that can block — becomes a
//!    block attributed to the plugin by name (Round 17, F-16-07: reducing
//!    it to a note was the fail-open direction, an input that crashed the
//!    plugin lost its block), and so does a Policy plugin, whose Block is a
//!    veto, and (Round 39) a Simulation plugin, whose Block fails L3 and so
//!    refuses the verdict (F11). Protocol and Analytics plugins return no
//!    verdict: a panic loses their knowledge or their observation, never a
//!    block.
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
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How long one plugin run may take (Round 40; core-decision P3 "No
/// per-plugin timeout").
///
/// Plugins ran synchronously on the request's worker, so a slow one held the
/// verdict for as long as it took — bounded only by the server's 10 s
/// request timeout, which answers no verdict at all. Each run now has this
/// deadline. A plugin past it is treated exactly as a plugin that panicked
/// (R39-CORE-DECISION-3): a family whose verdict can block refuses, any
/// other family's run is a Note; a protocol plugin's knowledge is lost and
/// the program is judged as declaring no effects; an analytics observer is
/// logged. Every shipped plugin answers in microseconds; 250 ms leaves room
/// for a loaded host without letting one plugin spend a request's budget.
/// A constant, not a setting: the deadline is part of what a plugin is
/// reviewed against.
pub const PLUGIN_DEADLINE: Duration = Duration::from_millis(250);

/// How many plugin runs past their deadline may still be running (Round 40).
///
/// A run past its deadline cannot be stopped — a thread cannot be killed,
/// and the Core may not spawn a process (`tests/ai_layer_isolation.rs`) — so
/// it is left to finish on its own thread and counted here until it does.
/// At the bound, no further plugin is started: its run is refused as one
/// that could not reach a verdict. So a plugin that hangs on every input
/// costs at most this many threads, plus the runs started concurrently with
/// the check that reached the bound, and then every request that would run
/// it is refused, never approved without it. Analytics observers have a
/// gate of their own (`ANALYTICS_GATE`).
pub const MAX_OVERRUN_PLUGIN_RUNS: usize = 16;

/// Why a plugin run produced no verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PluginFailure {
    /// It panicked (caught on its thread).
    Panicked,
    /// It was still running at [`PLUGIN_DEADLINE`].
    TimedOut,
    /// It was not started: [`MAX_OVERRUN_PLUGIN_RUNS`] runs are still
    /// running past their deadline, or no thread could be spawned.
    Saturated,
}

impl PluginFailure {
    /// The suffix of the pattern a blocking plugin's failure is recorded
    /// under (`<name>:panicked` since Round 17).
    fn tag(self) -> &'static str {
        match self {
            PluginFailure::Panicked => "panicked",
            PluginFailure::TimedOut => "timed-out",
            PluginFailure::Saturated => "not-run",
        }
    }

    fn what(self) -> String {
        match self {
            PluginFailure::Panicked => "panicked".to_string(),
            PluginFailure::TimedOut => format!(
                "did not answer within its {} ms deadline",
                PLUGIN_DEADLINE.as_millis()
            ),
            PluginFailure::Saturated => format!(
                "was not run: {MAX_OVERRUN_PLUGIN_RUNS} plugin runs are still running past their deadline"
            ),
        }
    }

    fn log_phrase(self) -> String {
        format!("{} ", self.what())
    }
}

/// The count of runs past their deadline that a gate allows.
struct OverrunGate {
    overrunning: AtomicUsize,
    max: usize,
}

impl OverrunGate {
    const fn new(max: usize) -> Self {
        Self {
            overrunning: AtomicUsize::new(0),
            max,
        }
    }
}

/// The gate of verdict and protocol plugins.
static VERDICT_GATE: OverrunGate = OverrunGate::new(MAX_OVERRUN_PLUGIN_RUNS);
/// The gate of analytics observers, so a slow event sink never stops a
/// verdict plugin from running.
static ANALYTICS_GATE: OverrunGate = OverrunGate::new(MAX_OVERRUN_PLUGIN_RUNS);

const RUN_RUNNING: u8 = 0;
const RUN_DONE: u8 = 1;
const RUN_ABANDONED: u8 = 2;

/// Run `work` on a thread of its own and wait for it until `deadline`
/// (Round 40). A panic is caught on that thread. Past the deadline the run
/// is abandoned — it finishes, unobserved, and leaves the gate's count when
/// it does — and the caller has its answer: `TimedOut`.
fn run_bounded<T: Send + 'static>(
    gate: &'static OverrunGate,
    deadline: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, PluginFailure> {
    if gate.overrunning.load(Ordering::SeqCst) >= gate.max {
        return Err(PluginFailure::Saturated);
    }
    let state = Arc::new(AtomicU8::new(RUN_RUNNING));
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let on_thread = Arc::clone(&state);
    let spawned = std::thread::Builder::new()
        .name("graphite-plugin".to_string())
        .spawn(move || {
            let outcome = catch_unwind(AssertUnwindSafe(work));
            let _ = tx.send(outcome);
            if on_thread
                .compare_exchange(RUN_RUNNING, RUN_DONE, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                // Abandoned at the deadline: no longer overrunning.
                gate.overrunning.fetch_sub(1, Ordering::SeqCst);
            }
        });
    if spawned.is_err() {
        return Err(PluginFailure::Saturated);
    }
    match rx.recv_timeout(deadline) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(_)) => Err(PluginFailure::Panicked),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            // Counted before it is marked abandoned, so the thread's
            // decrement can never come first.
            gate.overrunning.fetch_add(1, Ordering::SeqCst);
            if state
                .compare_exchange(
                    RUN_RUNNING,
                    RUN_ABANDONED,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
            {
                return Err(PluginFailure::TimedOut);
            }
            // It finished between the deadline and the mark: it sent first.
            gate.overrunning.fetch_sub(1, Ordering::SeqCst);
            match rx.try_recv() {
                Ok(Ok(v)) => Ok(v),
                _ => Err(PluginFailure::Panicked),
            }
        }
        // The thread ended without sending: only a panic does that.
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(PluginFailure::Panicked),
    }
}

/// The verdict of a run that reached none.
///
/// Round 17 (F-16-07): a panic in a plugin whose verdict can BLOCK is
/// fail-closed. Reducing it to a Note meant an input that crashed a Risk or
/// Verifier plugin lost that plugin's block and the layer passed on the
/// core's verdict alone — the one direction a security plugin must not fail
/// in. A Policy plugin's Block is a veto, so it is in the same set.
///
/// Round 39 (R39-CORE-DECISION-3): so is a Simulation plugin's. Since F11
/// its Block fails L3 and refuses the verdict, but a panic was still reduced
/// to a Note on the grounds that its verdicts were report-only — so an input
/// that crashed it lost its veto, and an honest-looking swap it would have
/// refused was `executable_approved`. Every family whose verdict can block
/// now blocks when it cannot reach one; only Protocol and Analytics plugins,
/// which have no verdict, would take the Note.
///
/// Round 40: a run past its deadline, or one not started because too many
/// overran, is the same case — a plugin that cannot reach a verdict — and
/// goes the same way.
fn failed_plugin_verdict(
    family: PluginFamily,
    name: &str,
    layer: LayerId,
    failure: PluginFailure,
) -> PluginVerdict {
    let what = failure.what();
    if matches!(
        family,
        PluginFamily::Risk
            | PluginFamily::Verifier
            | PluginFamily::Policy
            | PluginFamily::Simulation
    ) {
        tracing::error!(
            "plugin '{name}' {what} in layer {} — a blocking plugin that cannot run is a block (fail-closed)",
            layer.as_str()
        );
        let reason = match failure {
            PluginFailure::Panicked => format!(
                "plugin '{name}' panicked while assessing this request; a security plugin that cannot reach a verdict refuses rather than abstains (P12 fail-closed)"
            ),
            _ => format!(
                "plugin '{name}' {what} while assessing this request; a security plugin that cannot reach a verdict refuses rather than abstains (P12 fail-closed)"
            ),
        };
        PluginVerdict::Block {
            pattern: format!("{name}:{}", failure.tag()),
            reason,
        }
    } else {
        tracing::error!(
            "plugin '{name}' {what} in layer {} — verdict isolated, core verdict preserved",
            layer.as_str()
        );
        PluginVerdict::Note(match failure {
            PluginFailure::Panicked => {
                format!("plugin '{name}' panicked and was isolated (no verdict applied)")
            }
            _ => format!("plugin '{name}' {what} and was isolated (no verdict applied)"),
        })
    }
}

/// An owned copy of a [`PluginContext`] (Round 40): what a plugin's thread
/// borrows from, so a run past its deadline never outlives the request's
/// data.
struct OwnedPluginContext {
    program_id: String,
    protocol_name: String,
    instruction_discriminator: String,
    instruction_name: String,
    proposed_intent: ProposedIntent,
    account_addresses: Vec<String>,
    cpi_targets: Vec<String>,
    expected_state_changes: Vec<String>,
    allowed_cpis: Vec<String>,
    manifest_found: bool,
    compute_units: u64,
    account_writes: u32,
    cpi_hops: u32,
}

impl OwnedPluginContext {
    fn of(ctx: &PluginContext) -> Self {
        Self {
            program_id: ctx.program_id.to_string(),
            protocol_name: ctx.protocol_name.to_string(),
            instruction_discriminator: ctx.instruction_discriminator.to_string(),
            instruction_name: ctx.instruction_name.to_string(),
            proposed_intent: ctx.proposed_intent.clone(),
            account_addresses: ctx.account_addresses.to_vec(),
            cpi_targets: ctx.cpi_targets.to_vec(),
            expected_state_changes: ctx.expected_state_changes.to_vec(),
            allowed_cpis: ctx.allowed_cpis.to_vec(),
            manifest_found: ctx.manifest_found,
            compute_units: ctx.compute_units,
            account_writes: ctx.account_writes,
            cpi_hops: ctx.cpi_hops,
        }
    }

    fn view(&self) -> PluginContext<'_> {
        PluginContext {
            program_id: &self.program_id,
            protocol_name: &self.protocol_name,
            instruction_discriminator: &self.instruction_discriminator,
            instruction_name: &self.instruction_name,
            proposed_intent: &self.proposed_intent,
            account_addresses: &self.account_addresses,
            cpi_targets: &self.cpi_targets,
            expected_state_changes: &self.expected_state_changes,
            allowed_cpis: &self.allowed_cpis,
            manifest_found: self.manifest_found,
            compute_units: self.compute_units,
            account_writes: self.account_writes,
            cpi_hops: self.cpi_hops,
        }
    }
}

/// A verification layer of the fixed 8-layer pipeline.
///
/// Serde form is the canonical pipeline layer name (e.g. "L7_RiskVerification")
/// — the same string emitted in `VerificationResult.layers` — so manifest
/// files, reports, and plugin manifests share one spelling.
///
/// Ordered by declaration, which is the pipeline order (L1 first): the
/// orchestrator keys its plugins by layer in that order (Round 34, C-5).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
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
    /// Approved manifests naming a plugin already registered under that name:
    /// nothing new runs for them (W15, external review: they were counted as
    /// registered).
    pub already_registered: usize,
}

/// The plugin orchestrator. Sole caller of every plugin (P8).
///
/// `Clone` shares the underlying plugin instances (`Arc`), so a `GraphiteCore`
/// cloned into per-request server state shares the same registered plugins —
/// including the analytics sink state. Register plugins at startup, before
/// cloning, so every clone sees the same set.
#[derive(Clone, Default)]
pub struct PluginOrchestrator {
    /// Layer-scoped verdict plugins, in registration order per layer, the
    /// layers in pipeline order. Round 34 (C-5): a `HashMap` here iterated
    /// its layers in a per-process random order, so `protocol_rules` — which
    /// walks every layer — returned two Protocol plugins' rules in a different
    /// order from one run to the next (P2: same input, same output).
    plugins: BTreeMap<LayerId, Vec<PluginKind>>,
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
    ///
    /// Returns whether the plugin is now registered. `false` means a plugin of
    /// that name was already there and this one will NOT run; that is a
    /// warning, because an operator's plugin that shares a built-in's name was
    /// otherwise dropped without a word (W15, external review).
    pub fn register_plugin(&mut self, plugin: PluginKind) -> bool {
        let name = plugin.manifest().name.clone();
        match plugin {
            PluginKind::Analytics(a) => {
                if !self.analytics.iter().any(|p| p.manifest().name == name) {
                    self.analytics.push(a);
                    true
                } else {
                    tracing::warn!("plugin '{name}' is already registered; this one will not run");
                    false
                }
            }
            kind => {
                let layer = kind.manifest().layer;
                let entry = self.plugins.entry(layer).or_default();
                if !entry.iter().any(|k| k.manifest().name == name) {
                    entry.push(kind);
                    true
                } else {
                    tracing::warn!(
                        "plugin '{name}' is already registered for {}; this one will not run",
                        layer.as_str()
                    );
                    false
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
                    if self.register_plugin(builtin) {
                        summary.registered += 1;
                    } else {
                        summary.already_registered += 1;
                    }
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
        // One owned copy of the context for every plugin of the family: a
        // plugin runs on its own thread, which may outlive this call
        // (Round 40, `run_bounded`).
        let mut owned: Option<Arc<OwnedPluginContext>> = None;
        for kind in kinds.iter().filter(|k| k.family() == family) {
            let name = kind.manifest().name.clone();
            let shared =
                Arc::clone(owned.get_or_insert_with(|| Arc::new(OwnedPluginContext::of(ctx))));
            let plugin = kind.clone();
            let verdict = match run_bounded(&VERDICT_GATE, PLUGIN_DEADLINE, move || {
                plugin.run(&shared.view())
            }) {
                Ok(v) => v,
                Err(failure) => failed_plugin_verdict(family, &name, layer, failure),
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

    /// Simulation-family verdicts for L3 (Note or Block, never a pass; P5).
    /// A Block fails L3, which refuses the verdict (F11); a panic is a Block.
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
    /// contributes nothing; a plugin that panics is a block (`run_family`: a
    /// security plugin that cannot reach a verdict refuses).
    pub fn risk_outcome(&self, ctx: &PluginContext) -> RiskPluginOutcome {
        let mut findings = Vec::new();
        let mut blocked = false;
        for run in self.run_family(LayerId::L7RiskVerification, PluginFamily::Risk, ctx) {
            match run.verdict {
                PluginVerdict::Block { pattern, reason } => {
                    blocked = true;
                    // A block is never shaped like a note (W15, external
                    // review): `name:warning` is how a Note is recorded, and
                    // the shadow-baseline filter reads that suffix as
                    // non-blocking, so a Block named "warning" let a refused
                    // request feed the shadow accumulator.
                    let pattern = if pattern == "warning" || pattern.ends_with(":warning") {
                        format!("{pattern}-block")
                    } else {
                        pattern
                    };
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
                // Isolated like every other plugin call (Round 19, F-19-25).
                // A panicking protocol plugin used to unwind through the
                // request: no verdict, no audit row. Its knowledge is lost
                // instead, and the program is judged as declaring no effects
                // — the strict reading — rather than with no rules at all.
                // Round 40: so is one that overruns its deadline, or that
                // cannot be run because too many overran.
                let p = Arc::clone(p);
                let (program, discriminator) = (
                    program_id.to_string(),
                    instruction_discriminator.to_string(),
                );
                let outcome = run_bounded(&VERDICT_GATE, PLUGIN_DEADLINE, move || {
                    if p.protocol_id() == program {
                        Some((
                            p.semantic_rules(&discriminator),
                            p.allowed_cpis(&discriminator),
                        ))
                    } else {
                        None
                    }
                });
                match outcome {
                    Ok(Some((r, c))) => {
                        rules.extend(r);
                        cpis.extend(c);
                    }
                    Ok(None) => {}
                    Err(failure) => {
                        tracing::error!(
                            "protocol plugin {}while describing {program_id}; judging it as declaring no effects",
                            failure.log_phrase()
                        );
                        rules.push(crate::state_diff::UNDESCRIBED_INSTRUCTION_EFFECTS.to_string());
                    }
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
    ///
    /// Round 40: each observer runs under the plugin deadline, on a gate of
    /// its own — a slow sink (the event logger's file) delays the response
    /// by at most the deadline, and observers that overran can never take
    /// the verdict plugins' places. One that overruns, or cannot run, is
    /// logged; the result is unaffected either way.
    pub fn run_analytics(&self, result: &crate::verification::VerificationResult) {
        if self.analytics.is_empty() {
            return;
        }
        let shared = Arc::new(result.clone());
        for p in &self.analytics {
            let name = p.manifest().name.clone();
            let (p, r) = (Arc::clone(p), Arc::clone(&shared));
            let outcome = run_bounded(&ANALYTICS_GATE, PLUGIN_DEADLINE, move || {
                p.on_verification(&r)
            });
            if let Err(failure) = outcome {
                tracing::error!(
                    "analytics plugin '{name}' {}— isolated, result unaffected",
                    failure.log_phrase()
                );
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

    /// Round 17 (F-16-07): a panicking BLOCKING plugin fails closed. The
    /// previous assertion — "core verdict survives, panic is a note" — was
    /// the fail-open direction: an input that crashed a Verifier or Risk
    /// plugin lost that plugin's block. The pipeline is not wedged (the
    /// panic is caught), and the block is attributed to the plugin by name.
    /// Round 39: every family that can block, Simulation included.
    #[test]
    fn test_panicking_blocking_plugin_fails_closed() {
        let mut orch = PluginOrchestrator::new();
        orch.register_plugin(PluginKind::Verifier(Arc::new(PanicPlugin {
            manifest: manifest("panic", LayerId::L2InstructionVerification),
        })));
        let base =
            PipelineLayerResult::new("L2_InstructionVerification", LayerStatus::Passed, "core ok");
        let folded = orch.fold_verifier(LayerId::L2InstructionVerification, base, &ctx());
        assert_eq!(folded.status, LayerStatus::Failed);
        assert!(!folded.passed);
        // Round 40: a crash is reported as `panicked`, or as `timed-out`
        // when unwinding (and the panic hook's backtrace, with
        // RUST_BACKTRACE set, on a loaded machine) outlasts the 250 ms
        // deadline. Both refuse; the label is diagnostic, the refusal and the
        // plugin's name are what this test holds.
        assert!(
            folded.reason.contains("panic:panicked") || folded.reason.contains("panic:timed-out"),
            "{}",
            folded.reason
        );
        // A panicking RISK plugin is a block, named as the plugin's failure.
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
        assert!(outcome.blocked);
        assert_eq!(outcome.findings.len(), 1);
        assert!(
            outcome.findings[0].pattern.ends_with("panic-risk:panicked")
                || outcome.findings[0]
                    .pattern
                    .ends_with("panic-risk:timed-out"),
            "{}",
            outcome.findings[0].pattern
        );
        assert!(outcome.findings[0].reason.contains("panic"));
        // Re-pinned in Round 39 (R39-CORE-DECISION-3): this asserted that a
        // panicking Simulation plugin keeps a Note, "its verdict never
        // blocked anyway". Since F11 its Block fails L3 and refuses the
        // verdict, so the Note lost a veto; a crash is now a Block, like the
        // other families that can block.
        struct PanicSim {
            m: PluginManifest,
        }
        impl SimulationPlugin for PanicSim {
            fn manifest(&self) -> &PluginManifest {
                &self.m
            }
            fn observe_simulation(&self, _ctx: &PluginContext) -> PluginVerdict {
                panic!("sim boom");
            }
        }
        let mut orch3 = PluginOrchestrator::new();
        orch3.register_plugin(PluginKind::Simulation(Arc::new(PanicSim {
            m: manifest("panic-sim", LayerId::L3SimulationVerification),
        })));
        let runs = orch3.simulation_verdicts(&ctx());
        assert_eq!(runs.len(), 1);
        assert!(
            matches!(&runs[0].verdict, PluginVerdict::Block { pattern, .. } if pattern == "panic-sim:panicked" || pattern == "panic-sim:timed-out"),
            "{:?}",
            runs[0].verdict
        );
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

    /// A Protocol plugin that contributes one rule, named for itself.
    struct RuleProtocol {
        manifest: PluginManifest,
    }
    impl ProtocolPlugin for RuleProtocol {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn protocol_id(&self) -> &str {
            "RuLeProtoco1111111111111111111111111111111"
        }
        fn semantic_rules(&self, _d: &str) -> Vec<String> {
            vec![format!("rule of {}", self.manifest.name)]
        }
        fn allowed_cpis(&self, _d: &str) -> Vec<String> {
            vec![self.manifest.name.clone()]
        }
    }

    /// Round 34 (C-5): two Protocol plugins for one program, on different
    /// layers, give their rules in one order — the pipeline's — in every
    /// orchestrator, whatever order they were registered in. The plugins sat
    /// in a `HashMap` keyed by layer, whose iteration order is randomised per
    /// map: built 64 times, the order differed between builds.
    #[test]
    fn protocol_rules_come_in_one_order_in_every_orchestrator() {
        let program = "RuLeProtoco1111111111111111111111111111111";
        for round in 0..64 {
            let mut orch = PluginOrchestrator::new();
            let l5 = PluginKind::Protocol(Arc::new(RuleProtocol {
                manifest: manifest("on-l5", LayerId::L5SemanticVerification),
            }));
            let l4 = PluginKind::Protocol(Arc::new(RuleProtocol {
                manifest: manifest("on-l4", LayerId::L4StateVerification),
            }));
            if round % 2 == 0 {
                orch.register_plugin(l5);
                orch.register_plugin(l4);
            } else {
                orch.register_plugin(l4);
                orch.register_plugin(l5);
            }
            let (rules, cpis) = orch.protocol_rules(program, "00");
            assert_eq!(
                rules,
                vec!["rule of on-l4".to_string(), "rule of on-l5".to_string()],
                "round {round}"
            );
            assert_eq!(cpis, vec!["on-l4".to_string(), "on-l5".to_string()]);
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

    /// W15 (external review): a Block a plugin names "warning" is still
    /// recorded as a block, never with the suffix a Note carries.
    #[test]
    fn test_a_block_named_warning_is_not_recorded_as_a_note() {
        struct WarningBlock {
            m: PluginManifest,
        }
        impl RiskPlugin for WarningBlock {
            fn manifest(&self) -> &PluginManifest {
                &self.m
            }
            fn assess_risk(&self, _ctx: &PluginContext) -> PluginVerdict {
                PluginVerdict::Block {
                    pattern: "warning".into(),
                    reason: "blocks".into(),
                }
            }
        }
        let mut orch = PluginOrchestrator::new();
        orch.register_plugin(PluginKind::Risk(Arc::new(WarningBlock {
            m: manifest("warning-block", LayerId::L7RiskVerification),
        })));
        let outcome = orch.risk_outcome(&ctx());
        assert!(outcome.blocked);
        assert_eq!(outcome.findings.len(), 1);
        assert!(
            !outcome.findings[0].pattern.ends_with(":warning"),
            "{}",
            outcome.findings[0].pattern
        );
    }

    /// W15 (external review): a manifest naming a plugin that is already
    /// registered runs nothing new; it used to be counted as registered.
    #[test]
    fn test_a_duplicate_registration_is_reported_not_counted() {
        let mut orch = PluginOrchestrator::new();
        let approved = manifest("fake-rewards-drainer", LayerId::L7RiskVerification);
        let summary = orch
            .register_discovered(&[approved.clone(), approved])
            .unwrap();
        assert_eq!(summary.registered, 1);
        assert_eq!(summary.already_registered, 1);
        assert_eq!(orch.registered_count(), 1);
        assert!(
            !orch.register_plugin(crate::plugins::builtin_plugin("fake-rewards-drainer").unwrap())
        );
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

    /// Round 40: a plugin past its deadline is a plugin that cannot reach a
    /// verdict — the R39-CORE-DECISION-3 path. A family that can block
    /// refuses, naming the plugin and why; any other family's run is a Note.
    /// (No verdict family is non-blocking since Round 39, so the Note is
    /// reached only through this function; Protocol and Analytics plugins
    /// have their own fallbacks, `protocol_rules` and `run_analytics`.)
    #[test]
    fn a_plugin_that_cannot_reach_a_verdict_blocks_or_notes_by_family() {
        let layer = LayerId::L7RiskVerification;
        for family in [
            PluginFamily::Risk,
            PluginFamily::Verifier,
            PluginFamily::Policy,
            PluginFamily::Simulation,
        ] {
            for (failure, tag) in [
                (PluginFailure::Panicked, "panicked"),
                (PluginFailure::TimedOut, "timed-out"),
                (PluginFailure::Saturated, "not-run"),
            ] {
                match failed_plugin_verdict(family, "p", layer, failure) {
                    PluginVerdict::Block { pattern, reason } => {
                        assert_eq!(pattern, format!("p:{tag}"));
                        assert!(reason.contains("refuses rather than abstains"), "{reason}");
                    }
                    v => panic!("{family:?} {failure:?}: {v:?}"),
                }
            }
        }
        for family in [PluginFamily::Protocol, PluginFamily::Analytics] {
            match failed_plugin_verdict(family, "p", layer, PluginFailure::TimedOut) {
                PluginVerdict::Note(n) => {
                    assert!(
                        n.contains("250 ms deadline") && n.contains("isolated"),
                        "{n}"
                    )
                }
                v => panic!("{family:?}: {v:?}"),
            }
        }
    }

    /// Round 40: a slow Risk plugin is refused at the deadline, not after it
    /// finishes; a fast one is untouched.
    #[test]
    fn a_risk_plugin_past_its_deadline_is_a_block_at_the_deadline() {
        struct Slow {
            m: PluginManifest,
            sleep: Duration,
        }
        impl RiskPlugin for Slow {
            fn manifest(&self) -> &PluginManifest {
                &self.m
            }
            fn assess_risk(&self, _ctx: &PluginContext) -> PluginVerdict {
                std::thread::sleep(self.sleep);
                PluginVerdict::NoFinding
            }
        }
        let mut orch = PluginOrchestrator::new();
        orch.register_plugin(PluginKind::Risk(Arc::new(Slow {
            m: manifest("hang", LayerId::L7RiskVerification),
            sleep: Duration::from_secs(3),
        })));
        let started = std::time::Instant::now();
        let outcome = orch.risk_outcome(&ctx());
        let took = started.elapsed();
        assert!(outcome.blocked);
        assert!(
            outcome.findings[0].pattern.ends_with("hang:timed-out"),
            "{}",
            outcome.findings[0].pattern
        );
        assert!(
            took >= PLUGIN_DEADLINE && took < Duration::from_secs(2),
            "answered after {took:?}"
        );
        let mut fast = PluginOrchestrator::new();
        fast.register_plugin(PluginKind::Risk(Arc::new(Slow {
            m: manifest("quick", LayerId::L7RiskVerification),
            sleep: Duration::from_millis(1),
        })));
        assert_eq!(fast.risk_outcome(&ctx()), RiskPluginOutcome::default());
    }

    /// Round 40: runs past their deadline are bounded. At the bound nothing
    /// more is started (`Saturated`), and each abandoned run leaves the
    /// count when it finishes, so the gate reopens. A gate of its own: the
    /// shared one serves the other tests running beside this one.
    #[test]
    fn abandoned_runs_are_bounded_and_released() {
        static GATE: OverrunGate = OverrunGate::new(2);
        let (release, held) = std::sync::mpsc::channel::<()>();
        let held = Arc::new(std::sync::Mutex::new(held));
        let hang = || {
            let held = Arc::clone(&held);
            move || {
                let _ = held.lock().unwrap().recv();
            }
        };
        let deadline = Duration::from_millis(20);
        assert_eq!(
            run_bounded(&GATE, deadline, hang()),
            Err(PluginFailure::TimedOut)
        );
        assert_eq!(
            run_bounded(&GATE, deadline, hang()),
            Err(PluginFailure::TimedOut)
        );
        assert_eq!(GATE.overrunning.load(Ordering::SeqCst), 2);
        // At the bound: refused without being started.
        let started = Arc::new(AtomicUsize::new(0));
        let s = Arc::clone(&started);
        assert_eq!(
            run_bounded(&GATE, deadline, move || s.fetch_add(1, Ordering::SeqCst)),
            Err(PluginFailure::Saturated)
        );
        assert_eq!(started.load(Ordering::SeqCst), 0, "not started");
        // Released, both finish and leave the count.
        release.send(()).unwrap();
        release.send(()).unwrap();
        let until = std::time::Instant::now() + Duration::from_secs(10);
        while GATE.overrunning.load(Ordering::SeqCst) != 0 {
            assert!(std::time::Instant::now() < until, "the gate never reopened");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(run_bounded(&GATE, deadline, || 7), Ok(7));
        // A panic is caught on the plugin's thread (the panic hook may take
        // longer than 20 ms to print it, so this one gets longer).
        assert_eq!(
            run_bounded(&GATE, Duration::from_secs(5), || -> u8 { panic!("boom") }),
            Err(PluginFailure::Panicked)
        );
        assert_eq!(GATE.overrunning.load(Ordering::SeqCst), 0);
    }
}
