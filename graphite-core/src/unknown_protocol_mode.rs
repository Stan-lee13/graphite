use crate::confidence_engine::{ceilings, TrustTier};

pub fn is_unknown_protocol(tier: TrustTier) -> bool {
    matches!(tier, TrustTier::Unknown | TrustTier::HeuristicInferred)
}

pub fn unknown_protocol_confidence_ceiling(tier: TrustTier) -> f64 {
    match tier {
        TrustTier::Unknown | TrustTier::HeuristicInferred => ceilings::UNKNOWN_OR_HEURISTIC_MAX,
        TrustTier::OfficialManifest => ceilings::OFFICIAL_MANIFEST_MAX,
        TrustTier::SimulationValidated => ceilings::SIMULATION_VALIDATED_MAX,
        TrustTier::CommunityVerified | TrustTier::BattleTested => ceilings::COMMUNITY_OR_BATTLE_TESTED_MAX,
    }
}

pub fn apply_unknown_protocol_ceiling(tier: TrustTier, confidence: f64) -> f64 {
    confidence.min(unknown_protocol_confidence_ceiling(tier))
}
