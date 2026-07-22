//! Confidence Engine Tests
//!
//! Comprehensive test suite for the reference confidence engine.
//! Tests P3 (confidence always scored + explained) and P6 (trust tier ceilings).

use graphite_core::confidence_engine::*;

// ============================================
// Basic Construction Tests
// ============================================

#[test]
fn test_trust_tier_ordering() {
    // Trust tiers must be ordered from least to most trusted
    assert!(TrustTier::Unknown < TrustTier::HeuristicInferred);
    assert!(TrustTier::HeuristicInferred < TrustTier::OfficialManifest);
    assert!(TrustTier::OfficialManifest < TrustTier::SimulationValidated);
    assert!(TrustTier::SimulationValidated < TrustTier::CommunityVerified);
    assert!(TrustTier::CommunityVerified < TrustTier::BattleTested);
}

// clippy's `assertions_on_constants` lint suggests moving these into a
// `const { assert!(..) }` block, which would fail at compile time instead.
// That's deliberately not done here: keeping these as ordinary `#[test]`
// functions means a violation surfaces as a clearly named, standard
// `cargo test` failure (e.g. "test_ceiling_constants ... FAILED") in CI
// output, which is friendlier to skim than a compile error nested inside a
// const block's macro expansion — these ARE compile-time-knowable
// invariants, but the discoverability trade-off favors a named test here.
#[test]
#[allow(clippy::assertions_on_constants)]
fn test_ceiling_constants() {
    // Ceilings must increase with trust tier
    assert!(ceilings::UNKNOWN_OR_HEURISTIC_MAX < ceilings::OFFICIAL_MANIFEST_MAX);
    assert!(ceilings::OFFICIAL_MANIFEST_MAX < ceilings::SIMULATION_VALIDATED_MAX);
    assert!(ceilings::SIMULATION_VALIDATED_MAX <= ceilings::COMMUNITY_OR_BATTLE_TESTED_MAX);
    
    // Unknown/heuristic ceiling must be <= 0.55 (P6)
    assert!(ceilings::UNKNOWN_OR_HEURISTIC_MAX <= 0.55);
}

// ============================================
// Confidence Computation Tests
// ============================================

#[test]
fn test_compute_confidence_no_signals_fails() {
    let signals: Vec<WeightedSignal> = vec![];
    let result = compute_confidence(&signals, TrustTier::OfficialManifest);
    
    assert!(matches!(result, Err(ConfidenceError::NoSignalsProvided)));
}

#[test]
fn test_compute_confidence_weights_must_sum_to_one() {
    let signals = vec![
        WeightedSignal {
            kind: SignalKind::ManifestMatch,
            value: 1.0,
            weight: 0.5, // Only 0.5, not 1.0
        },
    ];
    
    let result = compute_confidence(&signals, TrustTier::OfficialManifest);
    assert!(matches!(result, Err(ConfidenceError::WeightsDoNotSumToOne { .. })));
}

#[test]
fn test_compute_confidence_signal_out_of_range_fails() {
    let signals = vec![
        WeightedSignal {
            kind: SignalKind::ManifestMatch,
            value: 1.5, // Out of range [0, 1]
            weight: 1.0,
        },
    ];
    
    let result = compute_confidence(&signals, TrustTier::OfficialManifest);
    assert!(matches!(result, Err(ConfidenceError::SignalOutOfRange { .. })));
}

#[test]
fn test_compute_confidence_basic_computation() {
    let signals = vec![
        WeightedSignal {
            kind: SignalKind::ManifestMatch,
            value: 1.0,
            weight: 0.5,
        },
        WeightedSignal {
            kind: SignalKind::SimulationMatch,
            value: 0.9,
            weight: 0.5,
        },
    ];
    
    let result = compute_confidence(&signals, TrustTier::BattleTested)
        .expect("Valid computation should succeed");
    
    // Expected: (1.0 * 0.5) + (0.9 * 0.5) = 0.5 + 0.45 = 0.95
    assert!((result.confidence - 0.95).abs() < 0.0001);
    assert_eq!(result.breakdown.len(), 2);
    assert_eq!(result.trust_tier_applied, TrustTier::BattleTested);
    assert!(!result.ceiling_triggered); // BattleTested has no ceiling
}

// ============================================
// P6: Trust Tier Ceiling Tests
// ============================================

#[test]
fn test_unknown_tier_ceiling_enforced() {
    let signals = vec![
        WeightedSignal {
            kind: SignalKind::ManifestMatch,
            value: 1.0, // Perfect signal
            weight: 1.0,
        },
    ];
    
    // Even with perfect signals, Unknown tier caps at 0.55
    let result = compute_confidence(&signals, TrustTier::Unknown)
        .expect("Computation should succeed");
    
    assert_eq!(result.confidence, ceilings::UNKNOWN_OR_HEURISTIC_MAX);
    assert!(result.ceiling_triggered);
    assert_eq!(result.ceiling_applied, ceilings::UNKNOWN_OR_HEURISTIC_MAX);
}

#[test]
fn test_heuristic_tier_ceiling_enforced() {
    let signals = vec![
        WeightedSignal {
            kind: SignalKind::ManifestMatch,
            value: 1.0,
            weight: 1.0,
        },
    ];
    
    let result = compute_confidence(&signals, TrustTier::HeuristicInferred)
        .expect("Computation should succeed");
    
    assert_eq!(result.confidence, ceilings::UNKNOWN_OR_HEURISTIC_MAX);
    assert!(result.ceiling_triggered);
}

#[test]
fn test_official_manifest_ceiling_enforced() {
    let signals = vec![
        WeightedSignal {
            kind: SignalKind::ManifestMatch,
            value: 1.0,
            weight: 1.0,
        },
    ];
    
    let result = compute_confidence(&signals, TrustTier::OfficialManifest)
        .expect("Computation should succeed");
    
    assert_eq!(result.confidence, ceilings::OFFICIAL_MANIFEST_MAX);
    assert!(result.ceiling_triggered);
}

#[test]
fn test_simulation_validated_ceiling_enforced() {
    let signals = vec![
        WeightedSignal {
            kind: SignalKind::ManifestMatch,
            value: 1.0,
            weight: 1.0,
        },
    ];
    
    let result = compute_confidence(&signals, TrustTier::SimulationValidated)
        .expect("Computation should succeed");
    
    assert_eq!(result.confidence, ceilings::SIMULATION_VALIDATED_MAX);
    assert!(result.ceiling_triggered);
}

#[test]
fn test_community_and_battle_tested_no_ceiling() {
    let signals = vec![
        WeightedSignal {
            kind: SignalKind::ManifestMatch,
            value: 1.0,
            weight: 1.0,
        },
    ];
    
    // CommunityVerified and BattleTested have no ceiling
    let result_community = compute_confidence(&signals, TrustTier::CommunityVerified)
        .expect("Computation should succeed");
    assert!(!result_community.ceiling_triggered);
    assert_eq!(result_community.confidence, 1.0);
    
    let result_battle = compute_confidence(&signals, TrustTier::BattleTested)
        .expect("Computation should succeed");
    assert!(!result_battle.ceiling_triggered);
    assert_eq!(result_battle.confidence, 1.0);
}

// ============================================
// Property-Based Tests (Optional - proptest)
// ============================================

#[cfg(test)]
mod property_tests {
    use super::*;

    /// Confidence must always be in [0, 1] regardless of inputs
    #[test]
    fn confidence_always_in_range() {
        // This is a simplified property test
        // In production, use proptest for exhaustive coverage
        let signals = vec![
            WeightedSignal {
                kind: SignalKind::ManifestMatch,
                value: 0.5,
                weight: 1.0,
            },
        ];
        
        let result = compute_confidence(&signals, TrustTier::BattleTested)
            .expect("Should succeed");
        
        assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
    }

    /// Higher tier never has lower ceiling than lower tier
    ///
    /// See `test_ceiling_constants` above for why this stays a named
    /// `#[test]` rather than a `const { assert!(..) }` block despite
    /// clippy's `assertions_on_constants` suggestion.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn ceiling_monotonicity() {
        assert!(ceilings::UNKNOWN_OR_HEURISTIC_MAX <= ceilings::OFFICIAL_MANIFEST_MAX);
        assert!(ceilings::OFFICIAL_MANIFEST_MAX <= ceilings::SIMULATION_VALIDATED_MAX);
        assert!(ceilings::SIMULATION_VALIDATED_MAX <= ceilings::COMMUNITY_OR_BATTLE_TESTED_MAX);
    }
}
