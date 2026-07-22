//! Integration test: self_healing → semantic_graph_store.
//!
//! Restored 2026-07-06 during a production-readiness sweep. History: this
//! test previously existed as `reference/self_healing_integration_test.rs`
//! (flat layout, using `#[path]` module inlining since `reference/` wasn't
//! yet a real Cargo crate). When `reference/` was restructured into a real
//! crate (`src/` + `tests/`), this file was deleted and never recreated —
//! and worse, the restructuring ALSO silently dropped the `quarantine()`
//! method from `semantic_graph_store.rs` and the wiring that would let
//! `self_healing::detect_anomaly`'s result actually reach it. Both were
//! restored in this same sweep (see `semantic_graph_store.rs`'s `quarantine`
//! method and `self_healing.rs`'s `to_quarantine_status` function) — this
//! file is the proof the restoration actually composes end-to-end, not just
//! that each half compiles in isolation.
//!
//! This is a proper Cargo integration test (`tests/` directory), exercising
//! the crate only through its public API (`graphite_core::*`), not
//! `#[path]` module inlining — the crate restructuring made that workaround
//! unnecessary.

use graphite_core::self_healing::{
    detect_anomaly, to_quarantine_status, AnomalyDetectionInput, AnomalyDimension, Baseline,
    QuarantineStatus,
};
use graphite_core::semantic_graph_store::{
    Behavior, BehaviorEvidence, SemanticGraphStore, TrustTier,
};

fn stable_baseline() -> Baseline {
    Baseline {
        mean: 50_000.0,
        std_dev: 2_000.0,
        sample_count: 500,
    }
}

fn seeded_battle_tested_behavior(program_id: &str) -> Behavior {
    Behavior {
        program_id: program_id.to_string(),
        version: "1.0".to_string(),
        expected_state_changes: vec!["debits input mint, credits output mint".to_string()],
        allowed_cpis: vec!["JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB".to_string()],
        trust_tier: TrustTier::Unknown, // ignored by append — always recomputed from evidence
        evidence: BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 3,
            battle_tested_tx_count: 2000,
            simulation_match_count: 20,
        },
        quarantined: false,
        quarantine_reason: None,
    }
}

/// The full, real end-to-end flow: an anomalous execution is observed
/// against a stable baseline, `detect_anomaly` flags it, `to_quarantine_status`
/// converts that into an actionable status with a reason, and the store's
/// `quarantine()` call makes that durable — with the resulting trust tier
/// correctly reflecting the quarantine on the very next read.
#[test]
fn anomaly_detection_triggers_quarantine_which_the_store_correctly_reflects() {
    let program_id = "battle-tested-but-now-suspicious";
    let mut store = SemanticGraphStore::new();
    store.append(seeded_battle_tested_behavior(program_id)).unwrap();

    // Before any anomaly: this protocol legitimately reaches BattleTested.
    let pre_quarantine = store.get(program_id).unwrap();
    assert_eq!(pre_quarantine.trust_tier, TrustTier::BattleTested);

    // Self-Healing observes a wildly anomalous execution (e.g. a compromised
    // upgrade) against an otherwise-stable baseline.
    let input = AnomalyDetectionInput {
        baseline: stable_baseline(),
        observed: vec![(AnomalyDimension::ComputeUnits, 500_000.0)], // ~225 stddevs from the mean
        z_threshold: 3.0,
    };
    let detection = detect_anomaly(&input).expect("detection should succeed with sufficient history");
    assert!(detection.should_quarantine);

    let status = to_quarantine_status(&detection);
    let reason = match status {
        QuarantineStatus::Quarantined { reason } => reason,
        QuarantineStatus::NotQuarantined => panic!("expected Quarantined given the anomalous observation"),
    };
    assert!(reason.contains("ComputeUnits"));

    // The calling orchestrator (not either module itself — each module's own
    // doc comments are explicit about this separation of "decide" vs.
    // "durably record") reacts to a `Quarantined` status by actually
    // quarantining the record.
    store.quarantine(program_id, reason).unwrap();

    // After quarantine: trust tier correctly drops to Unknown, even though
    // the underlying evidence fields (battle_tested_tx_count,
    // has_signed_manifest, community_verified_count) are UNCHANGED — this is
    // the concrete proof that P4/P7's guarantees compose correctly across
    // the module boundary, not just within each module's own unit tests.
    let post_quarantine = store.get(program_id).unwrap();
    assert!(post_quarantine.quarantined);
    assert_eq!(post_quarantine.trust_tier, TrustTier::Unknown);
    assert!(post_quarantine.quarantine_reason.as_ref().unwrap().contains("ComputeUnits"));

    // And per P4, the PRE-quarantine version stays queryable and still
    // correctly reports its original tier — quarantine is a new append,
    // never an erasure of history.
    let versions = store.get_all_versions(program_id);
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].trust_tier, TrustTier::BattleTested);
    assert!(!versions[0].quarantined);
}

/// The negative case: a normal observation must NOT trigger any quarantine
/// action anywhere along the chain, and the tier must remain unaffected.
/// Guards against an overly-eager integration accidentally quarantining
/// regardless of the detection result.
#[test]
fn normal_observation_never_triggers_quarantine() {
    let program_id = "stable-protocol";
    let mut store = SemanticGraphStore::new();
    store.append(seeded_battle_tested_behavior(program_id)).unwrap();

    let input = AnomalyDetectionInput {
        baseline: stable_baseline(),
        observed: vec![(AnomalyDimension::ComputeUnits, 51_200.0)], // 0.6 stddevs — normal
        z_threshold: 3.0,
    };
    let detection = detect_anomaly(&input).unwrap();
    assert!(!detection.should_quarantine);
    assert_eq!(to_quarantine_status(&detection), QuarantineStatus::NotQuarantined);

    // No `quarantine()` call should ever be made for a `NotQuarantined`
    // status — confirmed here by simply never calling it and checking the
    // record is untouched, mirroring what the real calling orchestrator
    // logic would (correctly) do.
    let record = store.get(program_id).unwrap();
    assert!(!record.quarantined);
    assert_eq!(record.trust_tier, TrustTier::BattleTested);
}

/// A multi-dimension anomaly (e.g. both compute units AND CPI hop count
/// spike together — a stronger signal of a compromised upgrade than either
/// alone) must still flow through cleanly to a single quarantine action
/// with both dimensions named in the reason.
#[test]
fn multi_dimension_anomaly_quarantines_with_combined_reason() {
    let program_id = "multi-signal-anomaly-protocol";
    let mut store = SemanticGraphStore::new();
    store.append(seeded_battle_tested_behavior(program_id)).unwrap();

    let input = AnomalyDetectionInput {
        baseline: stable_baseline(),
        observed: vec![
            (AnomalyDimension::ComputeUnits, 500_000.0),
            (AnomalyDimension::CpiHopCount, 400.0),
        ],
        z_threshold: 3.0,
    };
    let detection = detect_anomaly(&input).unwrap();
    assert_eq!(detection.anomalies.len(), 2, "both dimensions should be flagged, not just the first");

    let reason = match to_quarantine_status(&detection) {
        QuarantineStatus::Quarantined { reason } => reason,
        QuarantineStatus::NotQuarantined => panic!("expected Quarantined"),
    };
    assert!(reason.contains("ComputeUnits"));
    assert!(reason.contains("CpiHopCount"));

    store.quarantine(program_id, reason.clone()).unwrap();
    let post = store.get(program_id).unwrap();
    assert!(post.quarantined);
    assert_eq!(post.quarantine_reason.as_deref(), Some(reason.as_str()));
}
