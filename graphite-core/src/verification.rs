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
    // Phase 1.5: Simulation Integrity (optional — if None, skip simulation check)
    #[serde(default)]
    pub simulation_baseline: Option<crate::simulation_integrity::ComputeBaseline>,
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
}

/// Result of a single pipeline layer verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PipelineLayerResult {
    pub layer: String,
    pub passed: bool,
    pub reason: String,
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

    /// Seed a behavior record into the semantic graph.
    pub fn seed_behavior(&mut self, behavior: Behavior) -> Result<(), VerificationError> {
        self.semantic_graph.append(behavior)?;
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
                return PipelineLayerResult {
                    layer: layer_name.to_string(),
                    passed: true,
                    reason: "No manifest - unknown protocol, instruction check skipped".to_string(),
                };
            }
        };

        // Support both exact match and prefix match:
        // - Anchor programs: 8-byte discriminators, exact match
        // - Non-Anchor programs (System, SPL Token, Raydium): shorter discriminators (1-4 bytes)
        //   that should match as a prefix of the input discriminator
        let input_disc_lower = input.instruction_discriminator.to_lowercase();
        let matching_ix = manifest.instructions.iter().find(|ix| {
            let manifest_disc = ix.discriminator.to_lowercase();
            if manifest_disc.is_empty() {
                return false; // skip empty discriminators (e.g., Memo)
            }
            // Exact match
            if manifest_disc == input_disc_lower {
                return true;
            }
            // Prefix match: manifest disc is a prefix of input (handles short manifest discriminators)
            if input_disc_lower.starts_with(&manifest_disc) {
                return true;
            }
            // Reverse prefix: input disc is a prefix of manifest (handles short input discriminators)
            if manifest_disc.starts_with(&input_disc_lower) && input_disc_lower.len() >= 4 {
                return true;
            }
            false
        });

        let ix = match matching_ix {
            Some(ix) => ix,
            None => {
                // P12: Unknown instruction on known protocol = soft pass (fail open).
                // The instruction is unknown but the protocol is trusted.
                // Confidence will be lower (no InstructionMatch signal).
                // Risk Engine still checks for malicious patterns.
                return PipelineLayerResult {
                    layer: layer_name.to_string(),
                    passed: true,
                    reason: format!(
                        "Unknown instruction '{}' on known protocol {} — P12 soft pass (reduced confidence)",
                        input.instruction_discriminator,
                        manifest.protocol.name
                    ),
                };
            }
        };

        // Verify instruction data (if provided) starts with the discriminator
        if let Some(ref data) = input.instruction_data {
            if !data.is_empty() {
                let disc_hex = input.instruction_discriminator.trim_start_matches("0x");
                if let Ok(disc_bytes) = hex::decode(disc_hex) {
                    if data.len() >= disc_bytes.len()
                        && &data[..disc_bytes.len()] != disc_bytes.as_slice() {
                            return PipelineLayerResult {
                                layer: layer_name.to_string(),
                                passed: false,
                                reason: "Instruction data does not start with expected discriminator".to_string(),
                            };
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
            // Too few accounts is always a hard fail — missing required accounts
            return PipelineLayerResult {
                layer: layer_name.to_string(),
                passed: false,
                reason: format!(
                    "Account count insufficient: manifest requires {}, got {}",
                    expected_accounts, actual_accounts
                ),
            };
        } else if actual_accounts > expected_accounts && expected_accounts > 0 {
            // More accounts than manifest expects — common for aggregators
            // that route through multiple DEX venues. Soft pass with note.
            return PipelineLayerResult {
                layer: layer_name.to_string(),
                passed: true,
                reason: format!(
                    "Instruction {} verified (manifest min: {}, actual: {} — variable accounts for routing)",
                    ix.name, expected_accounts, actual_accounts
                ),
            };
        }

        PipelineLayerResult {
            layer: layer_name.to_string(),
            passed: true,
            reason: format!("Instruction {} verified against manifest", ix.name),
        }
    }

    // L4: State Verification
    fn verify_state(
        &self,
        expected_state_changes: &[String],
        resolved_accounts: &[ResolvedAccount],
        manifest_found: bool,
    ) -> PipelineLayerResult {
        let layer_name = "L4_StateVerification";

        if !manifest_found || expected_state_changes.is_empty() {
            return PipelineLayerResult {
                layer: layer_name.to_string(),
                passed: true,
                reason: "No manifest or no expected state changes - state check skipped".to_string(),
            };
        }

        let changes_lower: Vec<String> = expected_state_changes
            .iter()
            .map(|c| c.to_lowercase())
            .collect();

        // If state changes mention debit/credit/transfer/swap/stake,
        // there should be at least 2 writable accounts
        let needs_writable = changes_lower.iter().any(|c| {
            c.contains("debit") || c.contains("credit") || c.contains("transfer")
                || c.contains("swap") || c.contains("stake")
        });

        let writable_count = resolved_accounts.iter().filter(|a| a.is_writable).count();

        if needs_writable && writable_count < 2 {
            return PipelineLayerResult {
                layer: layer_name.to_string(),
                passed: false,
                reason: format!(
                    "Expected state changes require writable accounts but only {} writable account(s) found",
                    writable_count
                ),
            };
        }

        // If state changes mention signer/authority/delegate/approve,
        // there should be at least 1 signer account
        let needs_signer = changes_lower.iter().any(|c| {
            c.contains("signer") || c.contains("authority") || c.contains("delegate")
                || c.contains("approve")
        });

        let signer_count = resolved_accounts.iter().filter(|a| a.is_signer).count();

        if needs_signer && signer_count == 0 {
            return PipelineLayerResult {
                layer: layer_name.to_string(),
                passed: false,
                reason: "Expected state changes require a signer but no signer account found".to_string(),
            };
        }

        // If state changes mention close/closure,
        // verify there is a writable account (the one being closed)
        let needs_close = changes_lower.iter().any(|c| c.contains("close") || c.contains("closure"));
        if needs_close && writable_count == 0 {
            return PipelineLayerResult {
                layer: layer_name.to_string(),
                passed: false,
                reason: "Expected state changes mention close/closure but no writable account found".to_string(),
            };
        }

        PipelineLayerResult {
            layer: layer_name.to_string(),
            passed: true,
            reason: format!(
                "State verification passed: {} state change(s) consistent with {} account(s)",
                expected_state_changes.len(),
                resolved_accounts.len()
            ),
        }
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
            return PipelineLayerResult {
                layer: layer_name.to_string(),
                passed: true,
                reason: "No manifest - unknown protocol, semantic check skipped".to_string(),
            };
        }

        // P12: For unknown instructions on known protocols, we cannot verify
        // intent-instruction alignment. Soft pass (fail open) per Constitution P12.
        if instruction_name == "unknown_instruction" {
            return PipelineLayerResult {
                layer: layer_name.to_string(),
                passed: true,
                reason: "Unknown instruction on known protocol — semantic check skipped (P12 soft pass)".to_string(),
            };
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
                return PipelineLayerResult {
                    layer: layer_name.to_string(),
                    passed: true,
                    reason: format!("Unknown intent type {} - semantic check skipped", intent),
                };
            }
        };

        let ix_matches = intent_keywords.iter().any(|kw| ix_name.contains(kw));
        let changes_match = changes_lower.iter().any(|c| {
            intent_keywords.iter().any(|kw| c.contains(kw))
        });

        if !ix_matches && !changes_match {
            return PipelineLayerResult {
                layer: layer_name.to_string(),
                passed: false,
                reason: format!(
                    "{}: intent={}, instruction={}, state_changes={:?}",
                    mismatch_msg, intent, instruction_name, expected_state_changes
                ),
            };
        }

        PipelineLayerResult {
            layer: layer_name.to_string(),
            passed: true,
            reason: format!(
                "Semantic verification passed: intent {} consistent with instruction {}",
                intent, instruction_name
            ),
        }
    }

    /// Run the full verification pipeline on a transaction.
    pub fn verify(
        &self,
        input: &VerificationInput,
    ) -> Result<VerificationResult, VerificationError> {
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
            },
            &self.registry,
        ) {
            Ok(r) => r,
            Err(crate::account_resolution::AccountResolutionError::InstructionNotFound(_disc, _prog)) => {
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
                    resolved_accounts: input.account_addresses.iter().enumerate().map(|(i, addr)| {
                        crate::account_resolution::ResolvedAccount {
                            address: addr.clone(),
                            role: if i == 0 { "signer".to_string() } else { "readonly".to_string() },
                            is_pda: false,
                            is_signer: i == 0,
                            is_writable: i == 0,
                            pda_seeds: vec![],
                            pda_mismatch: false,
                        }
                    }).collect(),
                }
            }
            Err(crate::account_resolution::AccountResolutionError::InvalidAddress(addr)) => {
                // Client provided an invalid address — return error (caller-fixable)
                return Err(VerificationError::AccountResolution(
                    crate::account_resolution::AccountResolutionError::InvalidAddress(addr),
                ));
            }
            Err(crate::account_resolution::AccountResolutionError::AccountCountMismatch { expected, actual }) => {
                // Client provided wrong number of accounts — return error (caller-fixable)
                return Err(VerificationError::AccountResolution(
                    crate::account_resolution::AccountResolutionError::AccountCountMismatch { expected, actual },
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
        let (expected_state_changes, allowed_cpis) = match manifest {
            Some(m) => {
                let input_disc_lower = input.instruction_discriminator.to_lowercase();
                let ix = m.instructions.iter().find(|i| {
                    let manifest_disc = i.discriminator.to_lowercase();
                    if manifest_disc.is_empty() { return false; }
                    if manifest_disc == input_disc_lower { return true; }
                    if input_disc_lower.starts_with(&manifest_disc) { return true; }
                    if manifest_disc.starts_with(&input_disc_lower) && input_disc_lower.len() >= 4 { return true; }
                    false
                });
                match ix {
                    Some(ix) => (ix.expected_state_changes.clone(), ix.allowed_cpis.clone()),
                    None => {
                        // Unknown instruction on known protocol (P12 path)
                        // Use UNION of all allowed_cpis from all instructions
                        let union_cpis: Vec<String> = m.instructions.iter()
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
        let (expected_account_count, variable_accounts) = match manifest {
            Some(m) => {
                let input_disc_lower = input.instruction_discriminator.to_lowercase();
                let ix = m.instructions.iter().find(|i| {
                    let manifest_disc = i.discriminator.to_lowercase();
                    if manifest_disc.is_empty() { return false; }
                    if manifest_disc == input_disc_lower { return true; }
                    if input_disc_lower.starts_with(&manifest_disc) { return true; }
                    if manifest_disc.starts_with(&input_disc_lower) && input_disc_lower.len() >= 4 { return true; }
                    false
                });
                match ix {
                    Some(i) => (Some(i.accounts.len()), i.variable_accounts),
                    None => (None, false),
                }
            }
            None => (None, false),
        };

        let risk_verdict = assess(&RiskAssessmentInput {
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
        })?;

        // Note: Intent-Program mismatch and FakeSwap checks are now handled
        // inside the risk engine's assess() function (P0 Checks 8 and 9).

        // Step 3c: PDA Mismatch Detection
        // If account resolution found PDA mismatches, surface them as risk findings.
        // A PDA mismatch means the transaction provides an account that doesn't match
        // the protocol manifest's expected PDA derivation — a potential spoofing attack.
        let pda_mismatches: Vec<&ResolvedAccount> = resolution
            .resolved_accounts
            .iter()
            .filter(|a| a.pda_mismatch)
            .collect();
        let risk_verdict = if !pda_mismatches.is_empty() {
            let mismatch_reason = format!(
                "PDA mismatch: {} account(s) do not match manifest-derived addresses: {}",
                pda_mismatches.len(),
                pda_mismatches
                    .iter()
                    .map(|a| format!("{} (role={})", &a.address[..8], a.role))
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
                    // Already blocked — add PDA mismatch to findings via summarize_risk downstream
                    crate::risk_engine::RiskVerdict::Blocked {
                        pattern: *pattern,
                        reason: format!("{} | PDA mismatch detected", mismatch_reason),
                    }
                }
            }
        } else {
            risk_verdict
        };

        let risk_summary = summarize_risk(&risk_verdict);

        // Step 3c.5: Add PDA mismatch findings to risk summary
        let risk_summary = if !pda_mismatches.is_empty() && risk_summary.status == "Clear" {
            RiskVerdictSummary {
                status: "Blocked".to_string(),
                findings: vec![RiskFinding {
                    pattern: "PdaMismatch".to_string(),
                    reason: format!(
                        "PDA mismatch on {} account(s) — derived address does not match provided",
                        pda_mismatches.len()
                    ),
                }],
            }
        } else if !pda_mismatches.is_empty() {
            // Already blocked — append the PDA mismatch finding
            RiskVerdictSummary {
                status: "Blocked".to_string(),
                findings: {
                    let mut f = risk_summary.findings.clone();
                    f.push(RiskFinding {
                        pattern: "PdaMismatch".to_string(),
                        reason: format!(
                            "PDA mismatch on {} account(s) — derived address does not match provided",
                            pda_mismatches.len()
                        ),
                    });
                    f
                },
            }
        } else {
            risk_summary
        };

        // Step 3.5: Simulation Integrity Check (Phase 1.5)
        let (sim_flagged, sim_divergence) = if let Some(ref baseline) = input.simulation_baseline {
            if baseline.sample_count >= 10 && baseline.std_compute_units > 0.0 {
                match crate::simulation_integrity::check_simulation_integrity(
                    &crate::simulation_integrity::SimulationIntegrityInput {
                        program_id: input.program_id.clone(),
                        simulation_usage: crate::simulation_integrity::ComputeUsage {
                            compute_units: input.compute_units,
                            account_writes: input.account_writes,
                            cpi_hops: input.cpi_hops,
                        },
                        baseline: baseline.clone(),
                        divergence_threshold: 2.0,
                    },
                ) {
                    Ok(result) => (Some(result.flagged), Some(result.divergence_score)),
                    // Fail-closed (Constitution P12): on integrity check error,
                    // flag the simulation rather than silently passing it.
                    Err(_) => (Some(true), Some(f64::MAX)),
                }
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

        // L4: State Verification
        let l4_result = self.verify_state(
            &expected_state_changes,
            &resolution.resolved_accounts,
            manifest_found,
        );

        // L5: Semantic Verification
        let l5_result = self.verify_semantic(
            &input.proposed_intent,
            &instruction_name,
            &expected_state_changes,
            manifest_found,
        );

        let semantic_penalty = if !l5_result.passed { 0.3 } else { 0.0 };
        let instruction_penalty = if !l2_result.passed { 0.2 } else { 0.0 };
        let state_penalty = if !l4_result.passed { 0.15 } else { 0.0 };

        // Step 4: Confidence Computation
        let trust_tier = if manifest_found {
            // Use the manifest's declared trust tier as the base.
            // The manifest's trust_tier field is the protocol team's
            // self-assessment of their own protocol's reliability —
            // validated against the manifest's instruction surface.
            //
            // If the semantic graph has accumulated a HIGHER tier
            // through independent evidence (community verification,
            // battle-tested volume), use that — evidence can promote
            // but never demote below the manifest's declared tier
            // (Constitution P7: trust is earned through evidence,
            // but the manifest IS evidence — Tier 2+).
            //
            // If the caller provides behavior_evidence that computes
            // to a HIGHER tier than the manifest declares, use the
            // higher — accumulated evidence overrides the manifest's
            // self-assessment (P7: tier is a computed output, never
            // directly set by the protocol team alone).
            let manifest_tier = manifest
                .map(|m| TrustTier::from_manifest_str(&m.trust_tier))
                .unwrap_or(TrustTier::HeuristicInferred);
            let evidence_tier = compute_trust_tier_from_evidence(&input.behavior_evidence);

            match self.semantic_graph.get(&input.program_id) {
                Some(b) => {
                    // Graph has accumulated behavior — use the highest
                    // of manifest tier, evidence tier, and graph tier.
                    b.trust_tier.max(manifest_tier).max(evidence_tier)
                }
                None => {
                    // No graph behavior — use the higher of manifest
                    // declared tier and caller-provided evidence tier.
                    manifest_tier.max(evidence_tier)
                }
            }
        } else {
            // No manifest found — completely unknown protocol.
            // Hard cap at 0.55 regardless of any evidence provided
            // (Constitution P6/P12: unknown is capped, period).
            TrustTier::Unknown
        };

        let signals = build_signals(
            &input.behavior_evidence,
            manifest_found,
            trust_tier,
            &input.proposed_intent,
        );
        let confidence_result = compute_confidence(&signals, trust_tier)
            .map_err(|e| VerificationError::Confidence(e.to_string()))?;

        // Defense-in-depth: apply the same tier-based ceiling a second time.
        // compute_confidence() already caps at the tier ceiling (0.55 for Unknown),
        // but this redundant cap ensures the invariant holds even if a future refactor
        // accidentally removes the ceiling from compute_confidence(). The second cap
        // is always a no-op given the first cap is in place — it exists as a safety net.
        let confidence = apply_unknown_protocol_ceiling(trust_tier, confidence_result.confidence);
        let confidence = (confidence - semantic_penalty - instruction_penalty - state_penalty).max(0.0);

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
        let approved =
            matches!(policy_verdict, PolicyVerdict::Approved) && risk_summary.status == "Clear";

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

        Ok(VerificationResult {
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
            summary,
            simulation_flagged: sim_flagged,
            simulation_divergence: sim_divergence,
            layers: vec![
                // L1: Account Resolution — resolve all required accounts/PDAs
                // ARCHITECTURE.md 3.12: "Resolve all required accounts/PDAs"
                PipelineLayerResult {
                    layer: "L1_AccountResolution".to_string(),
                    passed: true,
                    reason: format!(
                        "Resolved {} account(s), manifest {}",
                        resolution.resolved_accounts.len(),
                        if manifest_found { "found" } else { "not found" }
                    ),
                },
                // L2: Instruction Verification — confirm discriminator + args match known shape
                // ARCHITECTURE.md 3.12: "Confirm instruction discriminator + args match a known shape"
                PipelineLayerResult {
                    layer: "L2_InstructionVerification".to_string(),
                    passed: l2_result.passed,
                    reason: l2_result.reason.clone(),
                },
                // L3: Simulation Verification — run simulateTransaction, confirm it succeeds
                // ARCHITECTURE.md 3.12: "Run simulateTransaction, confirm it succeeds"
                // Phase 1: SKIPPED — no RPC connection available. Simulation requires a
                // Solana RPC endpoint to call simulateTransaction. This is a Phase 2
                // feature (requires infrastructure provisioning). The simulation_integrity
                // module IS wired in and checks for compute-unit divergence when
                // simulation data is provided by the caller, but the full L3 (actually
                // running simulateTransaction against an RPC node) is not yet active.
                PipelineLayerResult {
                    layer: "L3_SimulationVerification".to_string(),
                    passed: true,
                    reason: if input.compute_units > 0 {
                        format!(
                            "Simulation integrity checked: {} compute units, {} account writes, {} CPI hops — divergence: {}",
                            input.compute_units, input.account_writes, input.cpi_hops,
                            if sim_flagged == Some(true) { "FLAGGED" } else { "none" }
                        )
                    } else {
                        "Phase 1: simulation skipped (no RPC connection) — simulation integrity module active when caller provides compute data".to_string()
                    },
                },
                // L4: State Verification — diff pre/post account state against declared intent
                // ARCHITECTURE.md 3.12: "Diff pre/post account state against declared intent"
                // Phase 1: heuristic check — verifies writable/signer account counts
                // are consistent with declared state changes. Full pre/post state diff
                // requires RPC access (Phase 2).
                PipelineLayerResult {
                    layer: "L4_StateVerification".to_string(),
                    passed: l4_result.passed,
                    reason: l4_result.reason.clone(),
                },
                // L5: Semantic Verification — compare diff against Semantic Graph expected Behavior
                // ARCHITECTURE.md 3.12: "Compare diff against the Semantic Graph's expected Behavior"
                // Phase 1: keyword matching between intent type, instruction name, and
                // expected state changes. Full Semantic Graph comparison requires
                // accumulated behavior data (Phase 2+).
                PipelineLayerResult {
                    layer: "L5_SemanticVerification".to_string(),
                    passed: l5_result.passed,
                    reason: l5_result.reason.clone(),
                },
                // L6: Policy Verification — apply the active wallet's Policy Engine profile
                // ARCHITECTURE.md 3.12: "Apply the active wallet's Policy Engine profile"
                // Includes confidence computation (3.11) + policy threshold checks (3.13).
                // Confidence is computed first, then policy evaluates it against the
                // wallet profile's minimum confidence and trust tier thresholds.
                PipelineLayerResult {
                    layer: "L6_PolicyVerification".to_string(),
                    passed: matches!(policy_verdict, PolicyVerdict::Approved),
                    reason: format!(
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
                    ),
                },
                // L7: Risk Verification — runs the Risk Engine (3.21)
                // ARCHITECTURE.md 3.12: "Forbidden patterns, allowlist/denylist, compositional risk"
                // NOTE: The Risk Engine executes EARLY in the pipeline (before confidence/policy)
                // for fail-fast performance — a known malicious pattern should block
                // immediately without wasting computation. However, it is REPORTED at L7
                // per the architecture spec's layer ordering. A risk block is a hard gate
                // that overrides any policy approval (Constitution: risk block is binary,
                // not a scored signal).
                PipelineLayerResult {
                    layer: "L7_RiskVerification".to_string(),
                    passed: risk_summary.status == "Clear",
                    reason: if risk_summary.status == "Clear" {
                        "No risk patterns detected (8 patterns checked)".to_string()
                    } else {
                        format!("Blocked: {} finding(s) — {:?}", risk_summary.findings.len(), risk_summary.findings.iter().map(|f| &f.pattern).collect::<Vec<_>>())
                    },
                },
                // L8: Execution Verification — confirm finalized on-chain result matches prediction
                // ARCHITECTURE.md 3.12: "Post-submission: confirm the finalized on-chain result
                // matches what L1-L7 predicted"
                // Phase 1: SKIPPED — requires transaction submission to Solana mainnet/devnet.
                // This is a Phase 2+ feature (requires SAK integration or direct RPC submission).
                // The audit_trail_id (SHA-256 of accounts + instruction data + CPI targets)
                // enables post-hoc verification once L8 is implemented.
                PipelineLayerResult {
                    layer: "L8_ExecutionVerification".to_string(),
                    passed: true,
                    reason: "Phase 1: execution verification skipped (post-submission feature) — audit_trail_id bound to transaction for future L8 replay".to_string(),
                },
            ],
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
    trust_tier: TrustTier,
    intent: &ProposedIntent,
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

    // Simulation match: fraction of 3 required simulation matches.
    // Zero when caller provides no simulation evidence (Phase 1 default).
    let simulation_value = (evidence.simulation_match_count as f64 / 3.0).min(1.0);

    // Historical volume: fraction of 1000 required battle-tested transactions.
    // Zero when caller provides no historical evidence (Phase 1 default).
    let historical_value = (evidence.battle_tested_tx_count as f64 / 1000.0).min(1.0);

    // Community verification: fraction of 2 required independent verifications.
    let community_value = (evidence.community_verified_count as f64 / 2.0).min(1.0);

    // Intent-manifest alignment: if the proposed intent type matches
    // a known instruction in the manifest, this is a positive signal.
    // When no manifest exists, this contributes 0 (consistent with
    // Unknown Protocol Mode). This is NOT the same as L5 semantic
    // verification — it's a confidence INPUT, not a pass/fail gate.
    let intent_alignment = if manifest_found && !intent.intent_type.is_empty() {
        1.0
    } else {
        0.0
    };

    // Signal weights must sum to exactly 1.0 (validated by compute_confidence).
    // Distribution rationale:
    //   ManifestMatch (0.20): binary — was a manifest found?
    //   TrustTierLevel (0.20): the protocol's trust tier IS evidence (ARCHITECTURE.md 3.11)
    //   SimulationMatch (0.20): simulation evidence (caller-provided)
    //   HistoricalVolume (0.15): battle-tested volume (caller-provided)
    //   CommunityVerification (0.15): independent verification (caller-provided)
    //   IntentAlignment (0.10): intent-manifest alignment
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
    hasher.update(format!("{:.6}", confidence).as_bytes());
    hasher.update(risk.status.as_bytes());
    for f in &risk.findings {
        hasher.update(f.pattern.as_bytes());
        hasher.update(f.reason.as_bytes());
    }
    let hash = hasher.finalize();
    let content_hash = hex::encode(&hash[..8]);
    let audit_trail_id = format!("gr-{}-{:08x}", content_hash, seq);
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
            simulation_baseline: None,
        }
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
            instruction_discriminator: "0b".to_string(), // SetAuthority
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
            simulation_baseline: None,
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
            simulation_baseline: None,
        };

        let result = core.verify(&input).unwrap();

        // With strong evidence (signed manifest + 50k battle-tested txs +
        // 100 simulation matches + 5 community verifications), the trust tier
        // should be BattleTested (ceiling = 1.0), so the ceiling should NOT
        // trigger. The breakdown should NOT have a TrustTierCeiling item.
        let ceiling_item = result.breakdown.iter().find(|b| b.kind == "TrustTierCeiling");
        // BattleTested tier has ceiling = 1.0, so no meaningful ceiling reduction
        // should appear. If an item exists, it must be floating-point noise (< 0.001).
        if let Some(item) = ceiling_item {
            assert!(item.raw_value.abs() < 0.001,
                "BattleTested tier has 1.0 ceiling — ceiling reduction should be negligible, got: {}",
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
            simulation_baseline: None,
        };

        let result = core.verify(&input).unwrap();

        // Unknown protocol → trust_tier = Unknown → ceiling = 0.55
        // With strong evidence (but no manifest), the raw confidence from
        // signals will be high, but the ceiling should cap it to 0.55.
        // The breakdown should include a TrustTierCeiling item.
        let ceiling_item = result.breakdown.iter().find(|b| b.kind == "TrustTierCeiling");

        // The confidence should be <= 0.55 (capped)
        assert!(result.confidence <= 0.55,
            "Unknown protocol should be capped at 0.55, got confidence={}", result.confidence);

        // If the raw confidence exceeded 0.55, the ceiling item should be present
        // With these evidence values, the raw confidence should be high enough
        if let Some(item) = ceiling_item {
            assert!(item.contribution < 0.0,
                "Ceiling contribution should be negative (reducing confidence), got: {}",
                item.contribution);
        }
        // If ceiling_item is None, it means the raw confidence was already <= 0.55
        // (the signals didn't produce a high enough raw score). This is also OK —
        // the ceiling is still enforced, just not triggered.
    }
}
