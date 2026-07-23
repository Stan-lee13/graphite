//! Policy Engine — ARCHITECTURE.md 3.13
//!
//! Evaluates whether a transaction meets wallet policy requirements (confidence
//! thresholds, trust tier minimums, risk engine blocks). Risk Engine findings
//! are checked FIRST, unconditionally — no wallet profile can disable risk checks
//! (SECURITY.md).
//!
//! This reference implementation demonstrates the policy evaluation SHAPE,
//! including the structural guarantee that Risk Engine blocks override confidence
//! thresholds (the G4 mitigation).

use thiserror::Error;

use crate::confidence_engine::{ConfidenceResult, TrustTier};
use crate::risk_engine::RiskVerdict;

/// Error cases for policy evaluation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("invalid policy configuration: {reason}")]
    InvalidConfiguration { reason: String },
}

/// Wallet profile defining policy requirements.
///
/// `Eq` is deliberately NOT derived here (only `PartialEq`): the `Custom`
/// variant holds an `f64` (`min_confidence`), and `f64` cannot implement
/// `Eq` (NaN != NaN). This was a real compile error found by actually
/// running `cargo test` during the 2026-07-06 production-readiness sweep —
/// deriving `Eq` on an enum containing a float field doesn't compile at
/// all, so this bug could never have shipped a working build.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq)]
#[derive(Default)]
pub enum WalletProfile {
    /// Conservative profile: high confidence, high trust tier required
    Conservative,
    /// Standard profile: moderate requirements
    #[default]
    Standard,
    /// Permissive profile: lower requirements for testing/dev
    Permissive,
    /// Enterprise profile: 99%+ confidence, Tier 5 required
    Enterprise,
    /// Custom profile with explicit thresholds
    Custom { min_confidence: f64, min_trust_tier: TrustTier },
}

/// Verdict from policy evaluation.
///
/// `Eq` is deliberately NOT derived here (only `PartialEq`) for the same
/// reason as `WalletProfile` above: `RejectedBelowThreshold` holds `f64`
/// fields, which cannot implement `Eq`.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyVerdict {
    /// Transaction approved
    Approved,
    /// Rejected due to confidence below threshold
    RejectedBelowThreshold { required: f64, actual: f64 },
    /// Rejected due to trust tier below minimum
    RejectedBelowTrustTier { required: TrustTier, actual: TrustTier },
    /// Rejected due to Risk Engine block (hard gate, cannot be overridden)
    RejectedRiskEngineBlock,
}

/// Input for policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyInput {
    /// Confidence result from Confidence Engine
    pub confidence_result: ConfidenceResult,
    /// Risk verdict from Risk Engine
    pub risk_verdict: RiskVerdict,
    /// Wallet profile to evaluate against
    pub profile: WalletProfile,
}

/// Evaluate policy requirements for a transaction.
///
/// This is a pure, deterministic function (Constitution P2). The evaluation
/// follows a strict order: Risk Engine check FIRST, then confidence threshold,
/// then trust tier minimum. This ordering is the structural G4 mitigation.
pub fn evaluate_policy(input: &PolicyInput) -> Result<PolicyVerdict, PolicyError> {
    // STEP 1: Risk Engine check FIRST, unconditionally (G4 mitigation)
    // This cannot be overridden by any wallet profile
    if input.risk_verdict != RiskVerdict::Passed {
        return Ok(PolicyVerdict::RejectedRiskEngineBlock);
    }
    
    // STEP 2: Get profile thresholds
    let (min_confidence, min_trust_tier) = match input.profile {
        WalletProfile::Conservative => (0.85, TrustTier::SimulationValidated),
        WalletProfile::Standard => (0.70, TrustTier::OfficialManifest),
        WalletProfile::Permissive => (0.50, TrustTier::HeuristicInferred),
        WalletProfile::Enterprise => (0.99, TrustTier::BattleTested),
        WalletProfile::Custom { min_confidence, min_trust_tier } => {
            (min_confidence, min_trust_tier)
        }
    };
    
    // STEP 3: Check confidence threshold
    let actual_confidence = input.confidence_result.confidence;
    if actual_confidence < min_confidence {
        return Ok(PolicyVerdict::RejectedBelowThreshold {
            required: min_confidence,
            actual: actual_confidence,
        });
    }
    
    // STEP 4: Check trust tier minimum
    let actual_tier = input.confidence_result.trust_tier_applied;
    if actual_tier < min_trust_tier {
        return Ok(PolicyVerdict::RejectedBelowTrustTier {
            required: min_trust_tier,
            actual: actual_tier,
        });
    }
    
    // All checks passed
    Ok(PolicyVerdict::Approved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_engine_block_overrides_perfect_confidence_on_most_permissive_profile() {
        // Load-bearing security test: Risk Engine block cannot be overridden
        let confidence_result = ConfidenceResult {
            confidence: 1.0,
            breakdown: vec![],
            trust_tier_applied: TrustTier::BattleTested,
            ceiling_triggered: false,
            ceiling_applied: 1.0,
        };
        
        let input = PolicyInput {
            confidence_result,
            risk_verdict: RiskVerdict::Blocked {
                pattern: crate::risk_engine::RiskPattern::Drainer,
                reason: "test".to_string(),
            },
            profile: WalletProfile::Permissive, // Most permissive profile
        };
        
        let result = evaluate_policy(&input).unwrap();
        assert_eq!(result, PolicyVerdict::RejectedRiskEngineBlock);
    }

    #[test]
    fn test_confidence_threshold_enforced() {
        let confidence_result = ConfidenceResult {
            confidence: 0.60, // Below Conservative threshold
            breakdown: vec![],
            trust_tier_applied: TrustTier::BattleTested,
            ceiling_triggered: false,
            ceiling_applied: 1.0,
        };
        
        let input = PolicyInput {
            confidence_result,
            risk_verdict: RiskVerdict::Passed,
            profile: WalletProfile::Conservative,
        };
        
        let result = evaluate_policy(&input).unwrap();
        assert!(matches!(result, PolicyVerdict::RejectedBelowThreshold { .. }));
    }

    #[test]
    fn test_trust_tier_minimum_enforced() {
        // Bug fixed 2026-07-06 (found by actually running `cargo test`):
        // this test set `confidence: 0.90` while testing Enterprise profile
        // (`min_confidence: 0.99`), so `evaluate_policy`'s STEP 3 confidence
        // check correctly rejected with `RejectedBelowThreshold` BEFORE ever
        // reaching STEP 4's trust tier check — the test asserted the wrong
        // verdict variant, not a bug in `evaluate_policy` itself (the
        // Risk -> Confidence -> TrustTier ordering is exactly what the
        // function's own doc comment specifies). Fixed by raising confidence
        // to 1.0 so ONLY the trust tier check can be the deciding factor,
        // correctly isolating what this test claims to verify.
        let confidence_result = ConfidenceResult {
            confidence: 1.0,
            breakdown: vec![],
            trust_tier_applied: TrustTier::OfficialManifest, // Below Enterprise's BattleTested requirement
            ceiling_triggered: false,
            ceiling_applied: 1.0,
        };
        
        let input = PolicyInput {
            confidence_result,
            risk_verdict: RiskVerdict::Passed,
            profile: WalletProfile::Enterprise,
        };
        
        let result = evaluate_policy(&input).unwrap();
        assert!(matches!(result, PolicyVerdict::RejectedBelowTrustTier { .. }));
    }

    #[test]
    fn test_deterministic_same_input_same_output() {
        let confidence_result = ConfidenceResult {
            confidence: 0.80,
            breakdown: vec![],
            trust_tier_applied: TrustTier::SimulationValidated,
            ceiling_triggered: false,
            ceiling_applied: 1.0,
        };
        
        let input = PolicyInput {
            confidence_result: confidence_result.clone(),
            risk_verdict: RiskVerdict::Passed,
            profile: WalletProfile::Standard,
        };
        
        let result1 = evaluate_policy(&input).unwrap();
        let result2 = evaluate_policy(&input).unwrap();
        
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_custom_profile_thresholds_applied() {
        let confidence_result = ConfidenceResult {
            confidence: 0.75,
            breakdown: vec![],
            trust_tier_applied: TrustTier::OfficialManifest,
            ceiling_triggered: false,
            ceiling_applied: 1.0,
        };
        
        let input = PolicyInput {
            confidence_result,
            risk_verdict: RiskVerdict::Passed,
            profile: WalletProfile::Custom {
                min_confidence: 0.80,
                min_trust_tier: TrustTier::SimulationValidated,
            },
        };
        
        let result = evaluate_policy(&input).unwrap();
        assert!(matches!(result, PolicyVerdict::RejectedBelowThreshold { .. }));
    }
}

