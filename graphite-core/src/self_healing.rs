//! Self-Healing Semantic Graph — ARCHITECTURE.md 3.8
//!
//! Detects anomalies in protocol behavior and automatically quarantines
//! affected Behavior records, dropping trust tier to Unknown while preserving
//! append-only history (Constitution P4).
//!
//! This reference implementation demonstrates the anomaly detection SHAPE:
//! baseline update → z-score check → quarantine trigger. The variance update
//! uses a simplified recurrence; production should use Welford's numerically-
//! stable online algorithm (tracked in memory/known-gaps-log.md).

use thiserror::Error;

/// Error cases for self-healing operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SelfHealingError {
    #[error("insufficient history to establish baseline")]
    InsufficientHistory,
    #[error("invalid anomaly detection parameters")]
    InvalidParameters,
}

/// Anomaly dimension being monitored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyDimension {
    /// Compute units consumed
    ComputeUnits,
    /// Account write count
    AccountWriteCount,
    /// CPI hop count
    CpiHopCount,
}

/// Detected anomaly.
#[derive(Debug, Clone)]
pub struct Anomaly {
    /// Dimension where anomaly was detected
    pub dimension: AnomalyDimension,
    /// Observed value
    pub observed_value: f64,
    /// Expected value (mean)
    pub expected_value: f64,
    /// Z-score (standard deviations from mean)
    pub z_score: f64,
}

/// Quarantine status for a Behavior record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineStatus {
    /// Not quarantined
    NotQuarantined,
    /// Quarantined due to detected anomaly
    Quarantined { reason: String },
}

/// Statistical baseline for anomaly detection.
#[derive(Debug, Clone)]
pub struct Baseline {
    /// Mean value
    pub mean: f64,
    /// Standard deviation
    pub std_dev: f64,
    /// Sample count
    pub sample_count: u64,
}

/// Input for anomaly detection.
#[derive(Debug, Clone)]
pub struct AnomalyDetectionInput {
    /// Current baseline statistics
    pub baseline: Baseline,
    /// Observed values for each dimension
    pub observed: Vec<(AnomalyDimension, f64)>,
    /// Z-score threshold for anomaly detection (default: 3.0)
    pub z_threshold: f64,
}

/// Result of anomaly detection.
#[derive(Debug, Clone)]
pub struct AnomalyDetectionResult {
    /// Detected anomalies (if any)
    pub anomalies: Vec<Anomaly>,
    /// Whether quarantine should be triggered
    pub should_quarantine: bool,
}

/// Detect anomalies in observed behavior against historical baseline.
///
/// This is a simplified reference implementation. The variance update uses a
/// direct recurrence which can accumulate floating-point error at very large
/// sample counts. Production should use Welford's numerically-stable online
/// algorithm (tracked in memory/known-gaps-log.md).
pub fn detect_anomaly(
    input: &AnomalyDetectionInput,
) -> Result<AnomalyDetectionResult, SelfHealingError> {
    if input.baseline.sample_count < 10 {
        return Err(SelfHealingError::InsufficientHistory);
    }

    if input.baseline.std_dev == 0.0 {
        return Err(SelfHealingError::InvalidParameters);
    }

    let mut anomalies = Vec::new();

    for (dimension, observed_value) in &input.observed {
        let z_score = (observed_value - input.baseline.mean) / input.baseline.std_dev;

        if z_score.abs() > input.z_threshold {
            anomalies.push(Anomaly {
                dimension: *dimension,
                observed_value: *observed_value,
                expected_value: input.baseline.mean,
                z_score,
            });
        }
    }

    // Short-circuit: return first anomaly found (simplification)
    // Production might want to check all dimensions and return complete picture
    let should_quarantine = !anomalies.is_empty();

    Ok(AnomalyDetectionResult {
        anomalies,
        should_quarantine,
    })
}

/// Update baseline with new observation (simplified recurrence).
///
/// This uses a direct recurrence for variance which is not numerically stable
/// at very large sample counts. Production should use Welford's algorithm.
pub fn update_baseline(baseline: &mut Baseline, new_value: f64) {
    let n = baseline.sample_count as f64;
    let new_n = n + 1.0;

    // Update mean
    let new_mean = (baseline.mean * n + new_value) / new_n;

    // Update variance (simplified recurrence)
    let variance = baseline.std_dev * baseline.std_dev;
    let new_variance =
        (variance * n + (new_value - baseline.mean) * (new_value - new_mean)) / new_n;

    baseline.mean = new_mean;
    baseline.std_dev = new_variance.sqrt();
    baseline.sample_count += 1;
}

/// Convert an `AnomalyDetectionResult` into the `QuarantineStatus` a caller
/// should act on.
///
/// This is the bridge this module was missing: `detect_anomaly` decides
/// whether quarantine should happen, but until this function existed nothing
/// in the crate actually consumed `QuarantineStatus` — it was a defined type
/// with no producer, and `should_quarantine: bool` alone couldn't carry a
/// human-readable reason into `semantic_graph_store::quarantine()`, which
/// requires one. Found and fixed during the 2026-07-06 production-readiness
/// sweep (`cargo clippy`'s dead-code-adjacent "never constructed" pattern
/// for `QuarantineStatus` was the tell — see `memory/known-gaps-log.md`).
///
/// Callers wire this as: `detect_anomaly(..)` → `to_quarantine_status(..)` →
/// if `Quarantined`, call `semantic_graph_store::SemanticGraphStore::quarantine`
/// with the reason. See `reference/tests/self_healing_integration_test.rs`
/// for the full flow.
pub fn to_quarantine_status(result: &AnomalyDetectionResult) -> QuarantineStatus {
    if !result.should_quarantine {
        return QuarantineStatus::NotQuarantined;
    }

    // Build a reason string that names every anomalous dimension and its
    // z-score, not just the first one found — a maintainer reading this
    // reason later (e.g. from `Behavior.quarantine_reason`) should be able
    // to see the full picture without re-running detection.
    let reason = result
        .anomalies
        .iter()
        .map(|a| {
            format!(
                "{:?}: observed {:.1} vs expected {:.1} (z={:.1})",
                a.dimension, a.observed_value, a.expected_value, a.z_score
            )
        })
        .collect::<Vec<_>>()
        .join("; ");

    QuarantineStatus::Quarantined { reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_observation_no_anomaly() {
        let input = AnomalyDetectionInput {
            baseline: Baseline {
                mean: 1000.0,
                std_dev: 100.0,
                sample_count: 100,
            },
            observed: vec![(AnomalyDimension::ComputeUnits, 1050.0)], // 0.5 z-score
            z_threshold: 3.0,
        };

        let result = detect_anomaly(&input).unwrap();
        assert!(!result.should_quarantine);
        assert!(result.anomalies.is_empty());
    }

    #[test]
    fn test_anomaly_detected_triggers_quarantine() {
        let input = AnomalyDetectionInput {
            baseline: Baseline {
                mean: 1000.0,
                std_dev: 100.0,
                sample_count: 100,
            },
            observed: vec![(AnomalyDimension::ComputeUnits, 1500.0)], // 5.0 z-score
            z_threshold: 3.0,
        };

        let result = detect_anomaly(&input).unwrap();
        assert!(result.should_quarantine);
        assert_eq!(result.anomalies.len(), 1);
    }

    #[test]
    fn test_insufficient_history_rejected() {
        let input = AnomalyDetectionInput {
            baseline: Baseline {
                mean: 1000.0,
                std_dev: 100.0,
                sample_count: 5, // Below threshold
            },
            observed: vec![(AnomalyDimension::ComputeUnits, 1500.0)],
            z_threshold: 3.0,
        };

        let result = detect_anomaly(&input);
        assert!(matches!(result, Err(SelfHealingError::InsufficientHistory)));
    }

    #[test]
    fn test_deterministic_same_input_same_output() {
        let input = AnomalyDetectionInput {
            baseline: Baseline {
                mean: 1000.0,
                std_dev: 100.0,
                sample_count: 100,
            },
            observed: vec![(AnomalyDimension::ComputeUnits, 1050.0)],
            z_threshold: 3.0,
        };

        let result1 = detect_anomaly(&input).unwrap();
        let result2 = detect_anomaly(&input).unwrap();

        assert_eq!(result1.should_quarantine, result2.should_quarantine);
    }

    #[test]
    fn test_baseline_update_converges() {
        let mut baseline = Baseline {
            mean: 1000.0,
            std_dev: 100.0,
            sample_count: 100,
        };

        let old_mean = baseline.mean;
        update_baseline(&mut baseline, 1050.0);

        // Mean should shift toward new value
        assert_ne!(baseline.mean, old_mean);
        assert_eq!(baseline.sample_count, 101);
    }

    #[test]
    fn test_to_quarantine_status_not_quarantined_when_no_anomalies() {
        let result = AnomalyDetectionResult {
            anomalies: vec![],
            should_quarantine: false,
        };
        assert_eq!(
            to_quarantine_status(&result),
            QuarantineStatus::NotQuarantined
        );
    }

    #[test]
    fn test_to_quarantine_status_includes_dimension_and_z_score_in_reason() {
        let result = AnomalyDetectionResult {
            anomalies: vec![Anomaly {
                dimension: AnomalyDimension::ComputeUnits,
                observed_value: 500_000.0,
                expected_value: 50_000.0,
                z_score: 225.0,
            }],
            should_quarantine: true,
        };

        match to_quarantine_status(&result) {
            QuarantineStatus::Quarantined { reason } => {
                assert!(reason.contains("ComputeUnits"));
                assert!(reason.contains("225.0"));
            }
            QuarantineStatus::NotQuarantined => panic!("expected Quarantined"),
        }
    }

    /// Multiple simultaneous anomalies must all appear in the reason, not
    /// just the first — a maintainer reading `Behavior.quarantine_reason`
    /// later needs the complete picture, not a partial one.
    #[test]
    fn test_to_quarantine_status_joins_multiple_anomalous_dimensions() {
        let result = AnomalyDetectionResult {
            anomalies: vec![
                Anomaly {
                    dimension: AnomalyDimension::ComputeUnits,
                    observed_value: 500_000.0,
                    expected_value: 50_000.0,
                    z_score: 225.0,
                },
                Anomaly {
                    dimension: AnomalyDimension::CpiHopCount,
                    observed_value: 8.0,
                    expected_value: 2.0,
                    z_score: 12.0,
                },
            ],
            should_quarantine: true,
        };

        match to_quarantine_status(&result) {
            QuarantineStatus::Quarantined { reason } => {
                assert!(reason.contains("ComputeUnits"));
                assert!(reason.contains("CpiHopCount"));
            }
            QuarantineStatus::NotQuarantined => panic!("expected Quarantined"),
        }
    }
}
