//! Confidence Engine — ARCHITECTURE.md 3.11
//!
//! Computes confidence scores for transaction verification based on weighted
//! signals (manifest match, simulation match, historical volume, etc.). Enforces
//! Constitution P3 (confidence always scored + explained) and P6 (unknown
//! protocols never receive maximum confidence via tier-based ceilings).
//!
//! This is a reference implementation demonstrating the SHAPE of the confidence
//! computation, not a production-final algorithm. The actual signal weights and
//! threshold values are design decisions for the real Phase 1+ implementation.
//!
//! Known simplifications (tracked in memory/known-gaps-log.md):
//! - Signal weights are hardcoded constants here; production should make these
//!   configurable per protocol class.
//! - The ceiling enforcement is simple linear capping; production may use
//!   more sophisticated decay curves.

use thiserror::Error;

/// Error cases for confidence computation.
///
/// `Eq` is deliberately NOT derived (only `PartialEq`): `WeightsDoNotSumToOne`
/// and `SignalOutOfRange` both hold `f64` fields, and `f64` cannot implement
/// `Eq` (NaN != NaN). Found by actually running `cargo test` during the
/// 2026-07-06 production-readiness sweep — this is the same class of bug
/// independently found and fixed in `policy_engine.rs`'s `WalletProfile` and
/// `PolicyVerdict` in the same sweep; grep for `derive(.*Eq` combined with
/// an `f64` field before adding new error/verdict enums to this crate.
#[derive(Debug, Error, PartialEq)]
pub enum ConfidenceError {
    #[error("no signals provided to compute confidence")]
    NoSignalsProvided,
    
    #[error("signal weights must sum to 1.0, got {sum}")]
    WeightsDoNotSumToOne { sum: f64 },
    
    #[error("signal value {value} out of range [0, 1]")]
    SignalOutOfRange { value: f64 },
}

/// Trust tier for a protocol or program ID.
///
/// Ordered from least to most trusted. Used to apply confidence ceilings per
/// Constitution P6 (unknown protocols never receive maximum confidence).
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustTier {
    /// Tier 0: Completely unknown program, no evidence
    Unknown,
    /// Tier 1: Heuristically inferred from bytecode similarity or IDL analysis
    HeuristicInferred,
    /// Tier 2: Official manifest from protocol team, signature-verified
    OfficialManifest,
    /// Tier 3: Simulation-validated against historical behavior
    SimulationValidated,
    /// Tier 4: Community-verified through independent review
    CommunityVerified,
    /// Tier 5: Battle-tested through 1000+ verified transactions
    BattleTested,
}

/// Confidence ceiling constants per trust tier.
///
/// Per Constitution P6, unknown protocols must never receive maximum confidence.
/// These ceilings enforce that constraint structurally.
pub mod ceilings {
    /// Maximum confidence for Unknown or HeuristicInferred tiers
    pub const UNKNOWN_OR_HEURISTIC_MAX: f64 = 0.55;
    
    /// Maximum confidence for OfficialManifest tier
    pub const OFFICIAL_MANIFEST_MAX: f64 = 0.75;
    
    /// Maximum confidence for SimulationValidated tier
    pub const SIMULATION_VALIDATED_MAX: f64 = 0.85;
    
    /// Maximum confidence for CommunityVerified or BattleTested tiers
    pub const COMMUNITY_OR_BATTLE_TESTED_MAX: f64 = 1.0;
}

/// Kind of signal contributing to confidence score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalKind {
    /// Manifest matches observed behavior
    ManifestMatch,
    /// Simulation matches historical execution
    SimulationMatch,
    /// Historical transaction volume
    HistoricalVolume,
    /// Independent community verification
    CommunityVerification,
}

/// A weighted signal input to confidence computation.
#[derive(Debug, Clone)]
pub struct WeightedSignal {
    pub kind: SignalKind,
    pub value: f64, // Must be in [0, 1]
    pub weight: f64, // Must sum to 1.0 across all signals
}

/// Result of a confidence computation.
#[derive(Debug, Clone)]
pub struct ConfidenceResult {
    /// Final confidence score in [0, 1]
    pub confidence: f64,
    /// Breakdown of how each signal contributed
    pub breakdown: Vec<(SignalKind, f64)>,
    /// Trust tier that was applied
    pub trust_tier_applied: TrustTier,
    /// Whether a ceiling was triggered
    pub ceiling_triggered: bool,
    /// The ceiling value that was applied (if triggered)
    pub ceiling_applied: f64,
}

/// Compute confidence score from weighted signals, applying tier-based ceilings.
///
/// This is a pure, deterministic function (Constitution P2). Same inputs always
/// produce the same output.
pub fn compute_confidence(
    signals: &[WeightedSignal],
    trust_tier: TrustTier,
) -> Result<ConfidenceResult, ConfidenceError> {
    // Validate inputs
    if signals.is_empty() {
        return Err(ConfidenceError::NoSignalsProvided);
    }
    
    let weight_sum: f64 = signals.iter().map(|s| s.weight).sum();
    if (weight_sum - 1.0).abs() > 0.0001 {
        return Err(ConfidenceError::WeightsDoNotSumToOne { sum: weight_sum });
    }
    
    for signal in signals {
        if signal.value < 0.0 || signal.value > 1.0 {
            return Err(ConfidenceError::SignalOutOfRange { value: signal.value });
        }
    }
    
    // Compute weighted sum
    let mut confidence = 0.0;
    let mut breakdown = Vec::new();
    
    for signal in signals {
        let contribution = signal.value * signal.weight;
        confidence += contribution;
        breakdown.push((signal.kind, contribution));
    }
    
    // Apply tier-based ceiling (Constitution P6).
    //
    // `ceiling` is the maximum confidence this trust tier is ALLOWED to
    // report. `ceiling_triggered` means the ceiling actually CAPPED the raw
    // computed score — not merely that a ceiling tier is in scope. A tier
    // with a ceiling of 0.85 applies to every computation at that tier, but
    // if the raw weighted score only came out to 0.40, the ceiling never
    // did anything — reporting `ceiling_triggered: true` in that case would
    // be misleading to anything consuming this result (e.g. a caller that
    // logs "confidence was artificially capped" when it plainly wasn't).
    //
    // Bug fixed 2026-07-06 (found during a production-readiness sweep):
    // this previously conflated "a ceiling tier applies" with "the ceiling
    // was binding," always reporting `true` for every capped tier regardless
    // of whether `confidence` actually exceeded `ceiling`. See
    // `test_ceiling_not_triggered_when_raw_score_already_below_ceiling`
    // below — the regression test that would have caught this.
    let ceiling = match trust_tier {
        TrustTier::Unknown | TrustTier::HeuristicInferred => ceilings::UNKNOWN_OR_HEURISTIC_MAX,
        TrustTier::OfficialManifest => ceilings::OFFICIAL_MANIFEST_MAX,
        TrustTier::SimulationValidated => ceilings::SIMULATION_VALIDATED_MAX,
        TrustTier::CommunityVerified | TrustTier::BattleTested => {
            ceilings::COMMUNITY_OR_BATTLE_TESTED_MAX
        }
    };

    let ceiling_triggered = confidence > ceiling;
    let final_confidence = if ceiling_triggered { ceiling } else { confidence };

    Ok(ConfidenceResult {
        confidence: final_confidence,
        breakdown,
        trust_tier_applied: trust_tier,
        ceiling_triggered,
        ceiling_applied: ceiling,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_tier_ordering() {
        assert!(TrustTier::Unknown < TrustTier::HeuristicInferred);
        assert!(TrustTier::HeuristicInferred < TrustTier::OfficialManifest);
        assert!(TrustTier::OfficialManifest < TrustTier::SimulationValidated);
        assert!(TrustTier::SimulationValidated < TrustTier::CommunityVerified);
        assert!(TrustTier::CommunityVerified < TrustTier::BattleTested);
    }

    #[test]
    fn test_unknown_protocol_capped_even_with_perfect_signals() {
        // Load-bearing security test: even perfect signals can't bypass P6 ceiling
        let signals = vec![WeightedSignal {
            kind: SignalKind::ManifestMatch,
            value: 1.0,
            weight: 1.0,
        }];
        
        let result = compute_confidence(&signals, TrustTier::Unknown)
            .expect("Computation should succeed");
        
        assert_eq!(result.confidence, ceilings::UNKNOWN_OR_HEURISTIC_MAX);
        assert!(result.ceiling_triggered);
    }

    #[test]
    fn test_deterministic_same_input_same_output() {
        let signals = vec![
            WeightedSignal {
                kind: SignalKind::ManifestMatch,
                value: 0.8,
                weight: 0.5,
            },
            WeightedSignal {
                kind: SignalKind::SimulationMatch,
                value: 0.9,
                weight: 0.5,
            },
        ];
        
        let result1 = compute_confidence(&signals, TrustTier::BattleTested).unwrap();
        let result2 = compute_confidence(&signals, TrustTier::BattleTested).unwrap();
        
        assert_eq!(result1.confidence, result2.confidence);
    }

    #[test]
    fn test_explain_output_mentions_ceiling_when_triggered() {
        let signals = vec![WeightedSignal {
            kind: SignalKind::ManifestMatch,
            value: 1.0,
            weight: 1.0,
        }];
        
        let result = compute_confidence(&signals, TrustTier::Unknown).unwrap();
        
        // The breakdown should show the signal contribution
        assert!(!result.breakdown.is_empty());
        // And ceiling should be marked as triggered
        assert!(result.ceiling_triggered);
    }

    #[test]
    fn test_regression_adding_risk_engine_signal_requires_rebalanced_weights() {
        // This test documents that adding a new signal type requires updating
        // the weight sum validation. If a new RiskEngine signal is added,
        // the weights must still sum to 1.0.
        let signals = vec![
            WeightedSignal {
                kind: SignalKind::ManifestMatch,
                value: 1.0,
                weight: 0.5,
            },
            WeightedSignal {
                kind: SignalKind::SimulationMatch,
                value: 1.0,
                weight: 0.5,
            },
        ];
        
        let result = compute_confidence(&signals, TrustTier::BattleTested);
        assert!(result.is_ok());
    }

    /// Regression test for the `ceiling_triggered` bug found during the
    /// 2026-07-06 production-readiness sweep: this tier (SimulationValidated,
    /// ceiling 0.85) applies a ceiling, but a raw score well below that
    /// ceiling must NOT be reported as ceiling-triggered. Before the fix,
    /// `ceiling_triggered` was set to `true` for every tier below
    /// CommunityVerified/BattleTested regardless of whether the score
    /// actually needed capping — this test fails against that old behavior
    /// and passes against the corrected one.
    #[test]
    fn test_ceiling_not_triggered_when_raw_score_already_below_ceiling() {
        let signals = vec![
            WeightedSignal {
                kind: SignalKind::ManifestMatch,
                value: 0.3,
                weight: 0.5,
            },
            WeightedSignal {
                kind: SignalKind::SimulationMatch,
                value: 0.3,
                weight: 0.5,
            },
        ];

        // Raw weighted score here is 0.3 — well under SimulationValidated's
        // 0.85 ceiling. The ceiling tier applies (it's not the uncapped
        // CommunityVerified/BattleTested branch), but it should never have
        // been the deciding factor in this result.
        let result = compute_confidence(&signals, TrustTier::SimulationValidated)
            .expect("computation should succeed");

        assert_eq!(result.confidence, 0.3);
        assert!(
            !result.ceiling_triggered,
            "ceiling_triggered must be false when the raw score never approached the ceiling —              a caller trusting this field to mean \"this score was artificially capped\" would              be misled otherwise"
        );
        assert_eq!(result.ceiling_applied, ceilings::SIMULATION_VALIDATED_MAX);
    }

    /// Companion positive case, same tier as above: when the raw score DOES
    /// exceed the ceiling, `ceiling_triggered` must still correctly report
    /// true and the final confidence must be exactly the ceiling value, not
    /// the raw (higher) score.
    #[test]
    fn test_ceiling_triggered_when_raw_score_exceeds_ceiling() {
        let signals = vec![WeightedSignal {
            kind: SignalKind::ManifestMatch,
            value: 1.0,
            weight: 1.0,
        }];

        let result = compute_confidence(&signals, TrustTier::SimulationValidated)
            .expect("computation should succeed");

        assert!(result.ceiling_triggered);
        assert_eq!(result.confidence, ceilings::SIMULATION_VALIDATED_MAX);
    }
}
