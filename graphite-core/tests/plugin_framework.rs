//! Plugin framework integration tests (Constitution P8) — end-to-end through
//! the real `GraphiteCore::verify` pipeline, plus structural enforcement,
//! fault tolerance, concurrency, discovery, and soak coverage.
//!
//! These tests exercise the production framework with real plugins and a real
//! pipeline; the few custom plugin structs here are TEST doubles that probe
//! the framework interface (registered via the public API), not production
//! code.

use graphite_core::plugin_orchestrator::{
    LayerId, PluginContext, PluginKind, PluginManifest, PluginVerdict, ProtocolPlugin,
    ReviewStatus, RiskPlugin, VerifierPlugin,
};
use graphite_core::plugins::builtin_plugin;
use graphite_core::verification::{GraphiteCore, LayerStatus, ProposedIntent, VerificationInput};
use graphite_core::{BehaviorEvidence, WalletProfile};
use std::path::Path;
use std::sync::{Arc, Mutex};

// ─── Test helpers ────────────────────────────────────────────────────────────

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
// Valid base58 account addresses (no 0/O/I/l), matching the exploit suite's.
const SIGNER: &str = "7vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const RECIPIENT: &str = "6bSsP4p6wXqFJdD2TkYgNcVmLzHfWq7pRyA8tCzE5nBj";
const UNKNOWN_PROGRAM: &str = "GdP9U5aYx7f2kQzVwNmT8jRcL4hB6eX3sDnWqA1uMoH";
const MEMO_PROGRAM: &str = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo";

fn input(
    intent: &str,
    raw_nl: &str,
    program: &str,
    disc: &str,
    accounts: &[&str],
) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: intent.to_string(),
            raw_natural_language: raw_nl.to_string(),
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
            min_trust_tier: graphite_core::TrustTier::OfficialManifest,
        },
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
    }
}

fn plain_transfer() -> VerificationInput {
    input(
        "transfer",
        "Send 0.5 SOL to Alice",
        SYSTEM_PROGRAM,
        "02000000",
        &[SIGNER, RECIPIENT],
    )
}

fn transfer_with_claim_nl() -> VerificationInput {
    input(
        "transfer",
        "Claim airdrop rewards — click to verify eligibility",
        SYSTEM_PROGRAM,
        "02000000",
        &[SIGNER, RECIPIENT],
    )
}

/// A test VerifierPlugin that emits a fixed verdict.
struct TestVerifier {
    manifest: PluginManifest,
    verdict: Mutex<PluginVerdict>,
}
impl TestVerifier {
    fn new(name: &str, layer: LayerId, verdict: PluginVerdict) -> Self {
        Self {
            manifest: PluginManifest {
                name: name.to_string(),
                version: "1.0.0".to_string(),
                author: "test".to_string(),
                layer,
                review_status: ReviewStatus::Approved,
                description: String::new(),
            },
            verdict: Mutex::new(verdict),
        }
    }
}
impl VerifierPlugin for TestVerifier {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
    fn verify(&self, _ctx: &PluginContext) -> PluginVerdict {
        self.verdict.lock().unwrap().clone()
    }
}

/// A test RiskPlugin that emits a fixed verdict.
struct TestRisk {
    manifest: PluginManifest,
    verdict: Mutex<PluginVerdict>,
}
impl TestRisk {
    fn new(name: &str, verdict: PluginVerdict) -> Self {
        Self {
            manifest: PluginManifest {
                name: name.to_string(),
                version: "1.0.0".to_string(),
                author: "test".to_string(),
                layer: LayerId::L7RiskVerification,
                review_status: ReviewStatus::Approved,
                description: String::new(),
            },
            verdict: Mutex::new(verdict),
        }
    }
}
impl RiskPlugin for TestRisk {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
    fn assess_risk(&self, _ctx: &PluginContext) -> PluginVerdict {
        self.verdict.lock().unwrap().clone()
    }
}

/// A test SimulationPlugin that emits a fixed verdict.
struct TestSimulation {
    manifest: PluginManifest,
    verdict: Mutex<PluginVerdict>,
}
impl TestSimulation {
    fn new(name: &str, verdict: PluginVerdict) -> Self {
        Self {
            manifest: PluginManifest {
                name: name.to_string(),
                version: "1.0.0".to_string(),
                author: "test".to_string(),
                layer: LayerId::L3SimulationVerification,
                review_status: ReviewStatus::Approved,
                description: String::new(),
            },
            verdict: Mutex::new(verdict),
        }
    }
}
impl graphite_core::plugin_orchestrator::SimulationPlugin for TestSimulation {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
    fn observe_simulation(&self, _ctx: &PluginContext) -> PluginVerdict {
        self.verdict.lock().unwrap().clone()
    }
}

/// A test PolicyPlugin that emits a fixed verdict.
struct TestPolicy {
    manifest: PluginManifest,
    verdict: Mutex<PluginVerdict>,
}
impl TestPolicy {
    fn new(name: &str, verdict: PluginVerdict) -> Self {
        Self {
            manifest: PluginManifest {
                name: name.to_string(),
                version: "1.0.0".to_string(),
                author: "test".to_string(),
                layer: LayerId::L6PolicyVerification,
                review_status: ReviewStatus::Approved,
                description: String::new(),
            },
            verdict: Mutex::new(verdict),
        }
    }
}
impl graphite_core::plugin_orchestrator::PolicyPlugin for TestPolicy {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
    fn evaluate(&self, _ctx: &PluginContext) -> PluginVerdict {
        self.verdict.lock().unwrap().clone()
    }
}

/// A test ProtocolPlugin supplying rules for an unknown program.
struct TestProtocol {
    manifest: PluginManifest,
}
impl TestProtocol {
    fn new() -> Self {
        Self {
            manifest: PluginManifest {
                name: "test-protocol".to_string(),
                version: "1.0.0".to_string(),
                author: "test".to_string(),
                layer: LayerId::L4StateVerification,
                review_status: ReviewStatus::Approved,
                description: String::new(),
            },
        }
    }
}
impl ProtocolPlugin for TestProtocol {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
    fn protocol_id(&self) -> &str {
        UNKNOWN_PROGRAM
    }
    fn semantic_rules(&self, _discriminator: &str) -> Vec<String> {
        vec!["creates a new escrow account".to_string()]
    }
    fn allowed_cpis(&self, _discriminator: &str) -> Vec<String> {
        vec![]
    }
}

/// A panicking plugin — must never wedge the real pipeline.
struct PanicVerifier {
    manifest: PluginManifest,
}
impl VerifierPlugin for PanicVerifier {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
    fn verify(&self, _ctx: &PluginContext) -> PluginVerdict {
        panic!("plugin exploded");
    }
}

// ─── P8 structural enforcement ───────────────────────────────────────────────

#[test]
fn test_pipeline_order_is_immutable() {
    // Constitution P8: 8 layers, fixed order, no plugin mechanism can change it.
    assert_eq!(graphite_core::PIPELINE_ORDER.len(), 8);
    assert_eq!(
        graphite_core::PIPELINE_ORDER[0],
        LayerId::L1AccountResolution
    );
    assert_eq!(
        graphite_core::PIPELINE_ORDER[7],
        LayerId::L8ExecutionVerification
    );
    // Layer names match the pipeline report strings (one canonical spelling).
    assert_eq!(LayerId::L7RiskVerification.as_str(), "L7_RiskVerification");
    let j = serde_json::to_string(&LayerId::L3SimulationVerification).unwrap();
    assert_eq!(j, "\"L3_SimulationVerification\"");
}

#[test]
fn test_plugin_cannot_reach_audit_or_orchestrator() {
    // P8 code-path analysis: PluginContext exposes ONLY transaction input data
    // — no audit trail, no orchestrator, no &mut state. This compiles against
    // the public surface and documents every field a plugin can see.
    let core = GraphiteCore::new();
    let ctx = PluginContext {
        program_id: SYSTEM_PROGRAM,
        protocol_name: "x",
        instruction_discriminator: "02000000",
        instruction_name: "Transfer",
        proposed_intent: &ProposedIntent {
            intent_type: "transfer".into(),
            raw_natural_language: "".into(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        account_addresses: &[],
        cpi_targets: &[],
        expected_state_changes: &[],
        allowed_cpis: &[],
        manifest_found: true,
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
    };
    // The context carries no reference to the core's internals — plugins only
    // ever see the transaction itself. (Structural guarantee is the trait
    // signature; this asserts the reachable surface compiles as input-only.)
    // Default core: 1 layer-scoped plugin (FakeRewardsDrainer) + 1 analytics
    // observer (event logger).
    assert!(core.plugins().registered_count() >= 1);
    assert!(core.plugins().analytics_count() >= 1);
    assert_eq!(ctx.program_id, SYSTEM_PROGRAM);
}

// ─── End-to-end: built-in FakeRewardsDrainer (default-on) ───────────────────

#[test]
fn test_plain_transfer_is_approved_with_default_plugins() {
    let core = GraphiteCore::new();
    let r = core.verify(&plain_transfer()).expect("verify ok");
    assert!(r.approved, "plain transfer must pass: {}", r.summary);
    assert_eq!(r.risk_verdict.status, "Clear");
}

#[test]
fn test_fake_rewards_claim_transfer_is_blocked_end_to_end() {
    let core = GraphiteCore::new();
    let r = core.verify(&transfer_with_claim_nl()).expect("verify ok");
    // The default FakeRewardsDrainer plugin hard-blocks the semantic
    // inversion: rewards-shaped request + debiting state changes.
    assert!(!r.approved, "claim-shaped transfer must be blocked");
    assert_eq!(r.risk_verdict.status, "Blocked");
    let has_plugin_finding = r
        .risk_verdict
        .findings
        .iter()
        .any(|f| f.pattern.contains("FakeRewardsDrainer"));
    assert!(
        has_plugin_finding,
        "plugin finding must be surfaced: {:?}",
        r.risk_verdict.findings
    );
    let l7 = r
        .layers
        .iter()
        .find(|l| l.layer == "L7_RiskVerification")
        .expect("L7 layer present");
    assert_eq!(l7.status, LayerStatus::Failed);
    // The same transaction WITHOUT the plugin is approved (isolates the
    // plugin as the differentiator, not the core pipeline).
    let bare = GraphiteCore::new_without_plugins();
    let r_bare = bare.verify(&transfer_with_claim_nl()).expect("verify ok");
    assert!(
        r_bare.approved,
        "control: without the risk plugin the transfer must pass: {}",
        r_bare.summary
    );
}

#[test]
fn test_no_false_positive_when_no_debit_signal() {
    // A rewards-shaped request against an instruction that does NOT move money
    // out of the user's account (Memo has no debit/deduct state changes) must
    // not fire the plugin — the plugin keys off the semantic inversion
    // (rewards request + money leaving), not the rewards words alone.
    let core = GraphiteCore::new();
    let r = core
        .verify(&input(
            "claim",
            "Claim my staking rewards",
            MEMO_PROGRAM,
            "",
            &[SIGNER],
        ))
        .expect("verify ok");
    assert!(
        r.risk_verdict
            .findings
            .iter()
            .all(|f| !f.pattern.contains("FakeRewardsDrainer")),
        "no plugin finding on a non-debit claim: {:?}",
        r.risk_verdict.findings
    );
    // The core rejects the unknown intent type itself (L5) — the plugin adds
    // nothing on top for the non-debit case.
    assert!(!r.approved);
}

// ─── End-to-end: custom plugins through the public API ──────────────────────

#[test]
fn test_custom_risk_plugin_blocks_and_l7_fails() {
    let mut core = GraphiteCore::new_without_plugins();
    core.register_plugin(PluginKind::Risk(Arc::new(TestRisk::new(
        "wallet-guard",
        PluginVerdict::Block {
            pattern: "HoneypotDeposit".into(),
            reason: "recipient flagged by wallet-guard".into(),
        },
    ))));
    let r = core.verify(&plain_transfer()).expect("verify ok");
    assert!(!r.approved);
    assert!(r
        .risk_verdict
        .findings
        .iter()
        .any(|f| f.pattern.contains("wallet-guard:HoneypotDeposit")));
    let l7 = r
        .layers
        .iter()
        .find(|l| l.layer == "L7_RiskVerification")
        .unwrap();
    assert_eq!(l7.status, LayerStatus::Failed);
}

#[test]
fn test_verifier_note_annotates_layer_without_blocking() {
    let mut core = GraphiteCore::new_without_plugins();
    core.register_plugin(PluginKind::Verifier(Arc::new(TestVerifier::new(
        "l4-annotator",
        LayerId::L4StateVerification,
        PluginVerdict::Note("extra context signal".into()),
    ))));
    let r = core.verify(&plain_transfer()).expect("verify ok");
    assert!(r.approved, "note must not block");
    let l4 = r
        .layers
        .iter()
        .find(|l| l.layer == "L4_StateVerification")
        .unwrap();
    assert!(l4.reason.contains("extra context signal"));
}

#[test]
fn test_verifier_block_on_l5_rejects_with_penalty() {
    let mut core = GraphiteCore::new_without_plugins();
    core.register_plugin(PluginKind::Verifier(Arc::new(TestVerifier::new(
        "l5-veto",
        LayerId::L5SemanticVerification,
        PluginVerdict::Block {
            pattern: "SemanticVeto".into(),
            reason: "intent-instruction alignment rejected by operator policy".into(),
        },
    ))));
    let r = core.verify(&plain_transfer()).expect("verify ok");
    assert!(!r.approved, "L5 block must reject");
    let l5 = r
        .layers
        .iter()
        .find(|l| l.layer == "L5_SemanticVerification")
        .unwrap();
    assert_eq!(l5.status, LayerStatus::Failed);
    assert!(l5.reason.contains("SemanticVeto"));
    // The 0.3 semantic penalty must appear in the breakdown (P3 explainability).
    assert!(r.breakdown.iter().any(|b| b.kind == "SemanticPenalty"));
}

#[test]
fn test_policy_plugin_veto_rejects_transaction() {
    let mut core = GraphiteCore::new_without_plugins();
    core.register_plugin(PluginKind::Policy(Arc::new(TestPolicy::new(
        "compliance-gate",
        PluginVerdict::Block {
            pattern: "ComplianceHold".into(),
            reason: "jurisdiction blocklist".into(),
        },
    ))));
    let r = core.verify(&plain_transfer()).expect("verify ok");
    assert!(!r.approved, "policy plugin veto must reject");
    assert_eq!(r.policy_verdict, "Rejected");
    let l6 = r
        .layers
        .iter()
        .find(|l| l.layer == "L6_PolicyVerification")
        .unwrap();
    assert_eq!(l6.status, LayerStatus::Failed);
    assert!(l6.reason.contains("ComplianceHold"));
}

#[test]
fn test_simulation_plugin_block_fails_l3_report_only() {
    // A simulation plugin can note/block the L3 report but never mint a pass
    // and never fabricate an L7 risk finding (P8 layer boundary, P5).
    let mut core = GraphiteCore::new_without_plugins();
    core.register_plugin(PluginKind::Simulation(Arc::new(TestSimulation::new(
        "sim-obs",
        PluginVerdict::Block {
            pattern: "RpcSuspicious".into(),
            reason: "simulation endpoint deviation".into(),
        },
    ))));
    let r = core.verify(&plain_transfer()).expect("verify ok");
    // L3 is report-only: the layer fails, the transaction is unaffected.
    let l3 = r
        .layers
        .iter()
        .find(|l| l.layer == "L3_SimulationVerification")
        .unwrap();
    assert_eq!(l3.status, LayerStatus::Failed);
    assert!(l3.reason.contains("RpcSuspicious"));
    assert!(r.approved, "L3 report block must not hard-block the tx");
}

#[test]
fn test_plugin_cannot_clear_a_core_block() {
    // Known malicious discriminator (SPL Token SetAuthority → AuthorityHijack).
    // A registered NoFinding plugin must NOT rescue the transaction.
    let mut core = GraphiteCore::new_without_plugins();
    core.register_plugin(PluginKind::Risk(Arc::new(TestRisk::new(
        "no-op",
        PluginVerdict::NoFinding,
    ))));
    let r = core
        .verify(&input(
            "transfer",
            "Approve the token account",
            TOKEN_PROGRAM,
            "06",
            &[SIGNER, RECIPIENT],
        ))
        .expect("verify ok");
    assert!(!r.approved, "core block must stand");
    assert_eq!(r.risk_verdict.status, "Blocked");
}

// ─── ProtocolPlugin extension (L4 evidence for manifest-less programs) ──────

#[test]
fn test_protocol_plugin_enables_l4_for_unknown_program() {
    // Without the plugin: L4 is Inconclusive (no manifest, no rules).
    let bare = GraphiteCore::new_without_plugins();
    let r_bare = bare
        .verify(&input(
            "transfer",
            "Fund the escrow",
            UNKNOWN_PROGRAM,
            "01",
            &[SIGNER, RECIPIENT],
        ))
        .expect("verify ok");
    let l4_bare = r_bare
        .layers
        .iter()
        .find(|l| l.layer == "L4_StateVerification")
        .unwrap();
    assert_eq!(l4_bare.status, LayerStatus::Inconclusive);

    // With a reviewed ProtocolPlugin supplying rules: L4 now runs against
    // plugin-supplied evidence (never a verdict, never a tier — P7/P8).
    let mut core = GraphiteCore::new_without_plugins();
    core.register_plugin(PluginKind::Protocol(Arc::new(TestProtocol::new())));
    let r = core
        .verify(&input(
            "transfer",
            "Fund the escrow",
            UNKNOWN_PROGRAM,
            "01",
            &[SIGNER, RECIPIENT],
        ))
        .expect("verify ok");
    let l4 = r
        .layers
        .iter()
        .find(|l| l.layer == "L4_StateVerification")
        .unwrap();
    assert_eq!(
        l4.status,
        LayerStatus::Passed,
        "L4 must run on plugin rules"
    );
    assert!(l4.reason.contains("state change"));
}

// ─── Fault tolerance ─────────────────────────────────────────────────────────

#[test]
fn test_panicking_plugin_never_wedges_verification() {
    let mut core = GraphiteCore::new_without_plugins();
    core.register_plugin(PluginKind::Verifier(Arc::new(PanicVerifier {
        manifest: PluginManifest {
            name: "bomb".into(),
            version: "1.0.0".into(),
            author: "test".into(),
            layer: LayerId::L4StateVerification,
            review_status: ReviewStatus::Approved,
            description: String::new(),
        },
    })));
    // verify() completes, the core's L4 verdict survives, and the panic is
    // surfaced as an honest note — the pipeline is never wedged.
    let r = core
        .verify(&plain_transfer())
        .expect("verify must not propagate plugin panic");
    assert!(r.approved);
    let l4 = r
        .layers
        .iter()
        .find(|l| l.layer == "L4_StateVerification")
        .unwrap();
    assert_eq!(l4.status, LayerStatus::Passed);
    assert!(
        l4.reason.contains("panic"),
        "panic must be reported: {}",
        l4.reason
    );
}

#[test]
fn test_invalid_input_still_errors_cleanly_with_plugins() {
    let core = GraphiteCore::new();
    let bad = VerificationInput {
        account_addresses: vec!["@@not-base58@@".to_string()],
        ..plain_transfer()
    };
    let err = core.verify(&bad);
    assert!(err.is_err(), "invalid address must error, not panic");
}

// ─── Determinism (P2) ────────────────────────────────────────────────────────

#[test]
fn test_verify_is_deterministic_with_plugins() {
    let core = GraphiteCore::new();
    let a = core.verify(&plain_transfer()).unwrap();
    let b = core.verify(&plain_transfer()).unwrap();
    assert_eq!(a.approved, b.approved);
    assert_eq!(a.confidence, b.confidence);
    // content_hash is the P2-deterministic identity (audit_trail_id carries a
    // per-call sequence counter by design and is NOT asserted equal).
    assert_eq!(a.content_hash, b.content_hash);
    assert_eq!(a.layers, b.layers);
    // Plugin-blocked inputs are deterministic too.
    let ca = core.verify(&transfer_with_claim_nl()).unwrap();
    let cb = core.verify(&transfer_with_claim_nl()).unwrap();
    assert_eq!(ca.content_hash, cb.content_hash);
    assert_eq!(ca.risk_verdict, cb.risk_verdict);
}

#[test]
fn test_analytics_do_not_change_the_result() {
    let with = GraphiteCore::new().verify(&plain_transfer()).unwrap();
    let without = GraphiteCore::new_without_plugins()
        .verify(&plain_transfer())
        .unwrap();
    assert_eq!(with.approved, without.approved);
    assert_eq!(with.confidence, without.confidence);
    assert_eq!(with.content_hash, without.content_hash);
    assert_eq!(with.layers, without.layers);
}

// ─── Analytics end-to-end ────────────────────────────────────────────────────

#[test]
fn test_event_logger_records_each_verification() {
    let core = GraphiteCore::new();
    let _ = core.verify(&plain_transfer()).unwrap();
    let _ = core.verify(&transfer_with_claim_nl()).unwrap();
    let events = core.plugins().analytics_events();
    assert_eq!(events.len(), 2);
    assert!(events[0].approved);
    assert!(!events[1].approved);
    assert!(events[1].risk_status.contains("Blocked"));
}

#[test]
fn test_event_file_sink_appends_jsonl_end_to_end() {
    let dir = std::env::temp_dir().join(format!(
        "graphite-events-e2e-{}-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        line!(),
        std::thread::current().name().unwrap_or("t")
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.jsonl");
    let core = GraphiteCore::new();
    core.attach_event_file_sink(&path).expect("sink attaches");
    let _ = core.verify(&plain_transfer()).unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    assert_eq!(content.lines().count(), 1);
    let v: serde_json::Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
    assert_eq!(v["approved"], serde_json::Value::Bool(true));
    assert_eq!(v["program_id"], SYSTEM_PROGRAM);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_attach_sink_fails_closed_without_logger() {
    let core = GraphiteCore::new_without_plugins();
    let err = core.attach_event_file_sink(Path::new("x.jsonl"));
    assert!(err.is_err(), "no event logger → fail closed");
}

// ─── Discovery + review gate end-to-end ──────────────────────────────────────

/// Unique temp dir per CALL (tests run in parallel in one process, so pid is
/// not unique — a shared dir would let tests clobber each other's manifests).
fn temp_manifest_dir() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("graphite-plugins-e2e-{}-{}", std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_manifest(dir: &Path, file: &str, name: &str, status: ReviewStatus) {
    let m = PluginManifest {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        author: "third-party".to_string(),
        layer: LayerId::L7RiskVerification,
        review_status: status,
        description: String::new(),
    };
    std::fs::write(dir.join(file), serde_json::to_string_pretty(&m).unwrap()).unwrap();
}

#[test]
fn test_review_gate_end_to_end() {
    let dir = temp_manifest_dir();
    write_manifest(
        &dir,
        "drainer.json",
        "fake-rewards-drainer",
        ReviewStatus::Approved,
    );
    write_manifest(
        &dir,
        "logger.json",
        "verification-event-logger",
        ReviewStatus::Pending,
    );
    // A rejected manifest is skipped BEFORE the built-in lookup, so its name
    // need not (and must not, discovery enforces unique names) collide.
    write_manifest(
        &dir,
        "rejected.json",
        "rejected-plugin-x",
        ReviewStatus::Rejected,
    );
    let mut core = GraphiteCore::new_without_plugins();
    let summary = core.attach_plugins_dir(&dir).expect("discovery ok");
    // Approved activates the built-in; pending/rejected are skipped. The
    // rejected duplicate of an already-approved name is skipped too.
    assert_eq!(summary.registered, 1);
    assert_eq!(summary.skipped_pending, 1);
    assert_eq!(summary.skipped_rejected, 1);
    assert_eq!(core.plugins().registered_count(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_unknown_builtin_name_fails_closed() {
    let dir = temp_manifest_dir();
    write_manifest(
        &dir,
        "evil.json",
        "not-a-real-plugin",
        ReviewStatus::Approved,
    );
    let mut core = GraphiteCore::new_without_plugins();
    let err = core.attach_plugins_dir(&dir).unwrap_err();
    assert!(err.to_string().contains("unknown built-in"), "{}", err);
    assert_eq!(core.plugins().registered_count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_malformed_manifest_fails_closed() {
    let dir = temp_manifest_dir();
    std::fs::write(dir.join("bad.json"), "{ not json").unwrap();
    let mut core = GraphiteCore::new_without_plugins();
    let err = core.attach_plugins_dir(&dir).unwrap_err();
    assert!(
        err.to_string().contains("invalid plugin manifest"),
        "{}",
        err
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ─── Concurrency ─────────────────────────────────────────────────────────────

#[test]
fn test_concurrent_verifications_shared_core() {
    let core = Arc::new(GraphiteCore::new());
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let core = core.clone();
            std::thread::spawn(move || {
                let mut last_hash = String::new();
                for _ in 0..100 {
                    let r = core.verify(&plain_transfer()).unwrap();
                    assert!(r.approved);
                    if last_hash.is_empty() {
                        last_hash = r.content_hash;
                    } else {
                        assert_eq!(r.content_hash, last_hash, "deterministic under concurrency");
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    // The ring buffer is bounded: 800 verifications → at most capacity events.
    assert!(core.plugins().analytics_events().len() <= 1024);
}

// ─── Soak / resource bounds ──────────────────────────────────────────────────

#[test]
fn test_soak_ring_buffer_stays_bounded() {
    let core = GraphiteCore::new();
    for _ in 0..2000 {
        let _ = core.verify(&plain_transfer()).unwrap();
    }
    let events = core.plugins().analytics_events();
    assert!(
        events.len() <= 1024,
        "ring buffer must evict oldest: {}",
        events.len()
    );
    // A pristine core produces byte-identical output to one that has recorded
    // 2000 events — recording never mutates the result path.
    let pristine = GraphiteCore::new().verify(&plain_transfer()).unwrap();
    let after_soak = core.verify(&plain_transfer()).unwrap();
    assert_eq!(pristine.content_hash, after_soak.content_hash);
}

// ─── Builtin registry sanity ─────────────────────────────────────────────────

#[test]
fn test_builtin_plugins_are_registered_on_default_core() {
    let core = GraphiteCore::new();
    let names = core.plugins().registered_plugins();
    assert!(
        names
            .iter()
            .any(|n| n.starts_with("fake-rewards-drainer@L7")),
        "{:?}",
        names
    );
    assert_eq!(core.plugins().analytics_count(), 1);
}

#[test]
fn test_builtin_resolution_returns_kind() {
    assert!(builtin_plugin("fake-rewards-drainer").is_some());
    assert!(builtin_plugin("verification-event-logger").is_some());
    assert!(builtin_plugin("nope").is_none());
}
