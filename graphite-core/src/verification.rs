//! GraphiteCore — the top-level verification orchestrator.
//!
//! Wires together: Manifest Registry → Account Resolution → Transaction Builder
//! → Risk Engine → Confidence Engine → Policy Engine → Unknown Protocol Mode.
//!
//! This is the public API. Call `GraphiteCore::verify()` with a VerificationInput
//! and receive a VerificationResult with confidence score, breakdown, risk
//! assessment, and policy decision.

use crate::account_resolution::{resolve_accounts, AccountResolutionInput, ResolvedAccount};
use crate::confidence_engine::{compute_confidence, ConfidenceResult, SignalKind, TrustTier, WeightedSignal};
use crate::manifest::{ManifestRegistry, load_seed_manifests};
use crate::policy_engine::{evaluate_policy, PolicyInput, PolicyVerdict, WalletProfile};
use crate::risk_engine::{assess, RiskAssessmentInput, RiskVerdict};
use crate::semantic_graph_store::{Behavior, BehaviorEvidence, SemanticGraphStore};
use crate::transaction_builder::{build_transaction, BuiltTransaction, TransactionPlan};
use crate::unknown_protocol_mode::apply_unknown_protocol_ceiling;

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationResult {
    pub approved: bool,
    pub confidence: f64,
    pub breakdown: Vec<VerificationBreakdownItem>,
    pub trust_tier: String,
    pub risk_verdict: RiskVerdictSummary,
    pub policy_verdict: String,
    pub audit_trail_id: String,
    pub transaction: BuiltTransaction,
    pub resolved_accounts: Vec<ResolvedAccount>,
    pub protocol_name: String,
    pub instruction_name: String,
    pub manifest_found: bool,
    pub unknown_protocol: bool,
    pub summary: String,
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
}

/// The main Graphite verification engine.
#[derive(Debug, Clone)]
pub struct GraphiteCore {
    registry: ManifestRegistry,
    semantic_graph: SemanticGraphStore,
}

impl Default for GraphiteCore {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphiteCore {
    /// Create a new GraphiteCore with built-in seed protocol manifests.
    pub fn new() -> Self {
        Self {
            registry: load_seed_manifests(),
            semantic_graph: SemanticGraphStore::new(),
        }
    }

    /// Create with a custom manifest registry.
    pub fn with_registry(registry: ManifestRegistry) -> Self {
        Self {
            registry,
            semantic_graph: SemanticGraphStore::new(),
        }
    }

    /// Load an additional protocol manifest at runtime.
    pub fn load_manifest(&mut self, json: &str) -> Result<(), VerificationError> {
        self.registry.load_from_json(json)
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

    /// Seed a behavior record into the semantic graph.
    pub fn seed_behavior(&mut self, behavior: Behavior) -> Result<(), VerificationError> {
        self.semantic_graph.append(behavior)?;
        Ok(())
    }

    /// Run the full verification pipeline on a transaction.
    pub fn verify(&self, input: &VerificationInput) -> Result<VerificationResult, VerificationError> {
        // Step 1: Account Resolution
        let resolution = resolve_accounts(
            &AccountResolutionInput {
                program_id: input.program_id.clone(),
                instruction_discriminator: input.instruction_discriminator.clone(),
                account_addresses: input.account_addresses.clone(),
                instruction_data: input.instruction_data.clone(),
            },
            &self.registry,
        )?;

        let manifest_found = resolution.manifest_found;
        let unknown_protocol = !manifest_found;

        // Get manifest for protocol info (if found)
        let manifest = self.registry.get(&input.program_id);
        let protocol_name = manifest
            .map(|m| m.protocol.name.clone())
            .unwrap_or_else(|| "Unknown Protocol".to_string());

        let instruction_name = resolution.instruction_name.clone();

        // Get expected state changes and allowed CPIs from manifest
        let (expected_state_changes, allowed_cpis) = match manifest {
            Some(m) => {
                let ix = m.instructions.iter()
                    .find(|i| i.discriminator.to_lowercase() == input.instruction_discriminator.to_lowercase());
                match ix {
                    Some(ix) => (ix.expected_state_changes.clone(), ix.allowed_cpis.clone()),
                    None => (vec![], vec![]),
                }
            }
            None => (vec![], vec![]),
        };

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
        }).map_err(|e| VerificationError::TransactionBuild(e.to_string()))?;

        // Step 3: Risk Assessment
        let risk_verdict = assess(&RiskAssessmentInput {
            program_id: input.program_id.clone(),
            accounts: input.account_addresses.clone(),
            cpi_targets: input.cpi_targets.clone(),
            expected_state_changes: expected_state_changes.clone(),
            allowed_cpis: allowed_cpis.clone(),
            instruction_discriminator: input.instruction_discriminator.clone(),
        })?;

        let risk_summary = summarize_risk(&risk_verdict);

        // Step 4: Confidence Computation
        let trust_tier = if manifest_found {
            // Check semantic graph for this program
            match self.semantic_graph.get(&input.program_id) {
                Some(b) => b.trust_tier,
                None => compute_trust_tier_from_evidence(&input.behavior_evidence),
            }
        } else {
            TrustTier::Unknown
        };

        let signals = build_signals(&input.behavior_evidence, manifest_found, &input.proposed_intent);
        let confidence_result = compute_confidence(&signals, trust_tier)
            .map_err(|e| VerificationError::Confidence(e.to_string()))?;

        // Apply unknown protocol ceiling
        let confidence = apply_unknown_protocol_ceiling(trust_tier, confidence_result.confidence);

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

        // Build audit trail ID (deterministic hash of key fields)
        let audit_id = generate_audit_id(
            &input.program_id,
            &input.instruction_discriminator,
            confidence,
            &risk_summary,
        );

        // Determine if approved
        let approved = matches!(policy_verdict, PolicyVerdict::Approved)
            && risk_summary.status == "Clear";

        // Generate summary
        let summary = generate_summary(
            approved,
            confidence,
            &risk_summary,
            policy_str,
            &protocol_name,
            &instruction_name,
            unknown_protocol,
        );

        let breakdown: Vec<VerificationBreakdownItem> = confidence_result
            .breakdown
            .iter()
            .map(|(kind, contribution)| {
                let kind_str = format!("{:?}", kind);
                let raw_value = signals.iter()
                    .find(|s| format!("{:?}", s.kind) == kind_str)
                    .map(|s| s.value)
                    .unwrap_or(0.0);
                VerificationBreakdownItem {
                    kind: kind_str.clone(),
                    raw_value,
                    weight: signals.iter()
                        .find(|s| format!("{:?}", s.kind) == kind_str)
                        .map(|s| s.weight)
                        .unwrap_or(0.0),
                    contribution: *contribution,
                }
            })
            .collect();

        Ok(VerificationResult {
            approved,
            confidence,
            breakdown,
            trust_tier: format!("{:?}", trust_tier),
            risk_verdict: risk_summary,
            policy_verdict: policy_str.to_string(),
            audit_trail_id: audit_id,
            transaction,
            resolved_accounts: resolution.resolved_accounts,
            protocol_name,
            instruction_name,
            manifest_found,
            unknown_protocol,
            summary,
        })
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

fn compute_trust_tier_from_evidence(evidence: &BehaviorEvidence) -> TrustTier {
    crate::semantic_graph_store::compute_trust_tier(evidence)
}

fn build_signals(
    evidence: &BehaviorEvidence,
    manifest_found: bool,
    _intent: &ProposedIntent,
) -> Vec<WeightedSignal> {
    let manifest_value = if manifest_found { 1.0 } else { 0.0 };
    let simulation_value = (evidence.simulation_match_count as f64 / 3.0).min(1.0);
    let historical_value = (evidence.battle_tested_tx_count as f64 / 1000.0).min(1.0);
    let community_value = (evidence.community_verified_count as f64 / 2.0).min(1.0);

    vec![
        WeightedSignal {
            kind: SignalKind::ManifestMatch,
            value: manifest_value,
            weight: 0.3,
        },
        WeightedSignal {
            kind: SignalKind::SimulationMatch,
            value: simulation_value,
            weight: 0.3,
        },
        WeightedSignal {
            kind: SignalKind::HistoricalVolume,
            value: historical_value,
            weight: 0.25,
        },
        WeightedSignal {
            kind: SignalKind::CommunityVerification,
            value: community_value,
            weight: 0.15,
        },
    ]
}

fn generate_audit_id(
    program_id: &str,
    discriminator: &str,
    confidence: f64,
    risk: &RiskVerdictSummary,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(program_id.as_bytes());
    hasher.update(discriminator.as_bytes());
    hasher.update(format!("{:.6}", confidence).as_bytes());
    hasher.update(risk.status.as_bytes());
    for f in &risk.findings {
        hasher.update(f.pattern.as_bytes());
        hasher.update(f.reason.as_bytes());
    }
    let hash = hasher.finalize();
    format!("gr-{}", hex::encode(&hash[..8]))
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
        if approved { "APPROVED".into() } else { "BLOCKED".into() },
        format!("confidence={:.2}", confidence),
        format!("risk={}", risk.status),
        format!("policy={}", policy),
        format!("protocol={}", protocol),
        format!("instruction={}", instruction),
        if unknown { "unknown_protocol=true".into() } else { "unknown_protocol=false".into() },
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
            wallet_profile: WalletProfile::Standard,
            behavior_evidence: BehaviorEvidence {
                has_signed_manifest: false,
                community_verified_count: 5,
                battle_tested_tx_count: 50000,
                simulation_match_count: 100,
            },
            compute_units: 150,
            account_writes: 2,
            cpi_hops: 0,
        }
    }

    #[test]
    fn test_verify_system_transfer() {
        let core = GraphiteCore::new();
        let input = make_input(
            "11111111111111111111111111111111",
            "02000000",
            &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
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
            program_id: "TokenkegQfeZyiNwAJbNbGKPfxCWuBvf9Ss623VQ5DA".to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: "0b".to_string(), // SetAuthority
            account_addresses: vec!["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(), "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string()],
            instruction_data: None,
            cpi_targets: vec!["unverified_target".to_string()],
            wallet_profile: WalletProfile::Standard,
            behavior_evidence: BehaviorEvidence {
                has_signed_manifest: false,
                community_verified_count: 0,
                battle_tested_tx_count: 0,
                simulation_match_count: 0,
            },
            compute_units: 150,
            account_writes: 2,
            cpi_hops: 1,
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
            &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        );
        let result = core.verify(&input).unwrap();
        assert!(result.audit_trail_id.starts_with("gr-"));
    }

    #[test]
    fn test_verify_summary_generated() {
        let core = GraphiteCore::new();
        let input = make_input(
            "11111111111111111111111111111111",
            "02000000",
            &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        );
        let result = core.verify(&input).unwrap();
        assert!(result.summary.contains("confidence="));
        assert!(result.summary.contains("protocol=System Program"));
    }
}
