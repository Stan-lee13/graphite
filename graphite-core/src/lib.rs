#![allow(clippy::too_many_arguments)]
//! Graphite Core — Transaction verification for Solana AI agents.
//!
//! Phase 1 MVP: Account Resolution + Transaction Construction + Verification Engine
//! + Risk Engine + Confidence Engine + Unknown Protocol Mode + Protocol Manifests.
//!
//! Public API: `GraphiteCore::verify()` takes a `VerificationInput` and returns
//! a `VerificationResult` with confidence score, risk assessment, and policy decision.

pub mod account_resolution;
pub mod confidence_engine;
pub mod durable;
pub mod live_corpus;
pub mod manifest;
pub mod manifest_registry;
pub mod plugin_orchestrator;
pub mod plugins;
pub mod policy_engine;
pub mod regression_engine;
pub mod risk_engine;
#[cfg(feature = "rpc")]
pub mod rpc_client;
pub mod semantic_graph_store;
pub mod simulation_integrity;
pub mod solana_types;
pub mod transaction_builder;
pub mod tx_pattern_analysis;
pub mod unknown_protocol_mode;
pub mod verification;

// Re-export core API
pub use account_resolution::{
    resolve_accounts, AccountResolutionInput, AccountResolutionResult, ResolvedAccount,
};
pub use confidence_engine::{
    compute_confidence, ConfidenceResult, SignalKind, TrustTier, WeightedSignal,
};
pub use manifest::{load_seed_manifests, ManifestRegistry, ProtocolManifest};
pub use manifest_registry::{
    ManifestRegistryEngine, ManifestSubmission, RegistryDecision, RegistryError, RegistryRecord,
    RegistryReviewer, ReviewerAttestation, MIN_REVIEWER_REPUTATION,
};
pub use plugin_orchestrator::{
    AnalyticsPlugin, LayerId, PluginContext, PluginError, PluginKind, PluginManifest,
    PluginOrchestrator, PluginRun, PluginVerdict, PolicyPlugin, ProtocolPlugin,
    RegistrationSummary, ReviewStatus, RiskPlugin, RiskPluginOutcome, SimulationPlugin,
    VerifierPlugin, PIPELINE_ORDER,
};
pub use plugins::{
    builtin_plugin, builtin_plugins, EventSink, FakeRewardsDrainerRiskPlugin, FileSink,
    RingBufferSink, VerificationEvent, VerificationEventLoggerPlugin,
};
pub use policy_engine::{evaluate_policy, PolicyInput, PolicyVerdict, WalletProfile};
pub use regression_engine::{
    decide_promotion, record_fixture, replay_corpus, seed_corpus_from_benchmark, PromotionDecision,
    RegressionCorpus, RegressionFixture, RegressionRun,
};
pub use risk_engine::{
    assess, assess_with_warnings, RiskAssessmentDetail, RiskAssessmentInput, RiskPattern,
    RiskVerdict,
};
pub use tx_pattern_analysis::{
    analyze_cpi_trace, analyze_multi_instruction, CpiTraceNode, PatternFinding,
    PatternSeverity, TransactionInstruction,
};
pub use semantic_graph_store::{Behavior, BehaviorEvidence, SemanticGraphStore};
pub use solana_types::{find_program_address, is_on_curve, AccountMeta, Instruction, Pubkey};
pub use transaction_builder::{build_transaction, BuiltTransaction, TransactionPlan};
pub use verification::{
    GraphiteCore, ProposedIntent, VerificationError, VerificationInput, VerificationResult,
};

#[cfg(feature = "server")]
pub mod server;

pub mod benchmark;
#[cfg(feature = "cli")]
pub mod cli;
