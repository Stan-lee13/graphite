//! Graphite Core — Transaction verification for Solana AI agents.
//!
//! Phase 1 MVP: Account Resolution + Transaction Construction + Verification Engine
//! + Risk Engine + Confidence Engine + Unknown Protocol Mode + Protocol Manifests.
//!
//! Public API: `GraphiteCore::verify()` takes a `VerificationInput` and returns
//! a `VerificationResult` with confidence score, risk assessment, and policy decision.

pub mod solana_types;
pub mod manifest;
pub mod account_resolution;
pub mod confidence_engine;
pub mod risk_engine;
pub mod policy_engine;
pub mod cpi_chain;
pub mod simulation_integrity;
pub mod semantic_graph_store;
pub mod self_healing;
pub mod regression_engine;
pub mod plugin_orchestrator;
pub mod transaction_builder;
pub mod unknown_protocol_mode;
pub mod verification;

// Re-export core API
pub use verification::{GraphiteCore, VerificationInput, VerificationResult, VerificationError, ProposedIntent};
pub use account_resolution::{resolve_accounts, AccountResolutionInput, AccountResolutionResult, ResolvedAccount};
pub use confidence_engine::{compute_confidence, ConfidenceResult, SignalKind, TrustTier, WeightedSignal};
pub use policy_engine::{evaluate_policy, PolicyInput, PolicyVerdict, WalletProfile};
pub use risk_engine::{assess, RiskAssessmentInput, RiskPattern, RiskVerdict};
pub use semantic_graph_store::{Behavior, BehaviorEvidence, SemanticGraphStore};
pub use transaction_builder::{build_transaction, BuiltTransaction, TransactionPlan};
pub use manifest::{ManifestRegistry, ProtocolManifest, load_seed_manifests};
pub use solana_types::{Pubkey, AccountMeta, Instruction, find_program_address, is_on_curve};

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "cli")]
pub mod cli;
pub mod benchmark;
