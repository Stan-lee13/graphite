//! Unknown Protocol Mode (Constitution P6/P12): a program Graphite has no
//! earned or declared trust in never receives more than its tier's confidence
//! ceiling.
//!
//! The tier -> ceiling table lives in ONE place,
//! [`TrustTier::confidence_ceiling`] in `confidence_engine.rs`, which
//! `compute_confidence` applies as well (audit 2026-10-20: this module kept
//! its own copy of the table, and two copies of a security constant are one
//! edit away from disagreeing). The functions here are the pipeline's second,
//! defence-in-depth application of that same ceiling.

use crate::confidence_engine::TrustTier;

/// The confidence ceiling for `tier` — [`TrustTier::confidence_ceiling`].
pub fn unknown_protocol_confidence_ceiling(tier: TrustTier) -> f64 {
    tier.confidence_ceiling()
}

/// `confidence`, capped at `tier`'s ceiling.
pub fn apply_unknown_protocol_ceiling(tier: TrustTier, confidence: f64) -> f64 {
    confidence.min(tier.confidence_ceiling())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidence_engine::ceilings;

    /// One table: this module and `compute_confidence` read the same
    /// ceilings, so the two caps cannot drift apart.
    #[test]
    fn the_ceiling_is_the_confidence_engines_ceiling() {
        for tier in [
            TrustTier::Unknown,
            TrustTier::HeuristicInferred,
            TrustTier::OfficialManifest,
            TrustTier::SimulationValidated,
            TrustTier::CommunityVerified,
            TrustTier::BattleTested,
        ] {
            assert_eq!(
                unknown_protocol_confidence_ceiling(tier),
                tier.confidence_ceiling()
            );
            assert_eq!(
                apply_unknown_protocol_ceiling(tier, 1.0),
                tier.confidence_ceiling()
            );
        }
        assert_eq!(
            unknown_protocol_confidence_ceiling(TrustTier::Unknown),
            ceilings::UNKNOWN_OR_HEURISTIC_MAX
        );
        assert_eq!(
            apply_unknown_protocol_ceiling(TrustTier::BattleTested, 0.3),
            0.3
        );
    }
}
