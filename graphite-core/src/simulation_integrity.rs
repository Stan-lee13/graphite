//! Simulation Integrity Layer — ARCHITECTURE.md 3.17
//!
//! Detects Simulation Spoofing attacks by comparing simulation behavior against
//! historical execution baselines. A malicious program can detect whether it's
//! being invoked inside `simulateTransaction` versus real execution and behave
//! differently — clean in simulation, malicious in reality.
//!
//! Checks three signals:
//! 1. Compute units (z-score vs baseline)
//! 2. Account write count (z-score vs baseline)
//! 3. CPI hop count (z-score vs baseline)
//!
//! Any signal exceeding the threshold flags the simulation.

use thiserror::Error;

/// Minimum baseline samples before the z-score check is statistically
/// meaningful. Below this the check is SKIPPED (no verdict), per P12
/// fail-open-with-explanation — never faked, never fail-closed.
pub const MIN_SAMPLES: u64 = 10;

/// Tolerance for zero-variance divergence: usage counts are integers, so any
/// deviation larger than this from an identical-history mean is a real signal.
const ZERO_VARIANCE_EPSILON: f64 = 1e-6;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SimulationIntegrityError {
    #[error("no baseline available for program {program_id}")]
    NoBaseline { program_id: String },
    #[error("invalid simulation data: {reason}")]
    InvalidData { reason: String },
}

/// Compute usage statistics for a program.
#[derive(Debug, Clone)]
pub struct ComputeUsage {
    pub compute_units: u64,
    pub account_writes: u32,
    pub cpi_hops: u32,
}

/// Historical baseline for a program — now tracks all three signals.
///
/// `Default` is the empty baseline (sample_count = 0) used when a program's
/// accumulator starts; `update_baseline` grows it from there.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Default)]
pub struct ComputeBaseline {
    pub mean_compute_units: f64,
    pub std_compute_units: f64,
    pub sample_count: u64,
    /// Mean account write count (Phase 1.5 addition)
    #[serde(default)]
    pub mean_account_writes: f64,
    /// Std dev of account writes
    #[serde(default)]
    pub std_account_writes: f64,
    /// Mean CPI hop count
    #[serde(default)]
    pub mean_cpi_hops: f64,
    /// Std dev of CPI hops
    #[serde(default)]
    pub std_cpi_hops: f64,
}

/// Input for simulation integrity check.
#[derive(Debug, Clone)]
pub struct SimulationIntegrityInput {
    pub program_id: String,
    pub simulation_usage: ComputeUsage,
    pub baseline: ComputeBaseline,
    pub divergence_threshold: f64,
}

/// Result of simulation integrity check. Serialized so downstream reports can
/// embed the verdict; divergence_score is always finite (JSON-safe).
#[derive(Debug, Clone, serde::Serialize)]
pub struct SimulationIntegrityResult {
    pub flagged: bool,
    pub divergence_score: f64,
    pub reason: Option<String>,
}

/// Reject NaN/Infinity anywhere in the baseline (Red Team L6/L6b). A
/// non-finite baseline would produce non-finite z-scores for every signal.
fn baseline_is_finite(baseline: &ComputeBaseline) -> bool {
    [
        baseline.mean_compute_units,
        baseline.std_compute_units,
        baseline.mean_account_writes,
        baseline.std_account_writes,
        baseline.mean_cpi_hops,
        baseline.std_cpi_hops,
    ]
    .iter()
    .all(|v| v.is_finite())
}

/// Check simulation integrity against historical baseline.
///
/// Checks all three signals: compute units, account writes, CPI hops.
/// Any signal exceeding the threshold flags the simulation.
///
/// Zero-variance handling: a baseline whose historical samples were IDENTICAL
/// (std == 0) is NOT a reason to skip the check (that was a permanent bypass
/// for uniform-behavior programs). Any deviation beyond float noise is a
/// maximum-signal divergence; an identical usage is perfectly consistent.
/// A fully degenerate baseline (mean == 0 AND std == 0) is rejected
/// fail-closed — there are no meaningful statistics at all.
pub fn check_simulation_integrity(
    input: &SimulationIntegrityInput,
) -> Result<SimulationIntegrityResult, SimulationIntegrityError> {
    if input.baseline.sample_count < MIN_SAMPLES {
        return Err(SimulationIntegrityError::NoBaseline {
            program_id: input.program_id.clone(),
        });
    }

    if !baseline_is_finite(&input.baseline) {
        return Err(SimulationIntegrityError::InvalidData {
            reason: "baseline contains NaN or Infinity values".to_string(),
        });
    }

    // Signal 1: Compute units z-score (zero-variance aware).
    let compute_z = if input.baseline.std_compute_units == 0.0 {
        if input.baseline.mean_compute_units == 0.0 {
            return Err(SimulationIntegrityError::InvalidData {
                reason: "baseline has zero mean AND zero variance — degenerate".to_string(),
            });
        }
        let delta =
            (input.simulation_usage.compute_units as f64 - input.baseline.mean_compute_units).abs();
        if delta > ZERO_VARIANCE_EPSILON {
            return Ok(SimulationIntegrityResult {
                flagged: true,
                // f64::MAX (NOT Infinity): divergence_score is serialized into
                // JSON responses, and serde_json cannot encode Infinity.
                divergence_score: f64::MAX,
                reason: Some(format!(
                    "Compute usage diverges from zero-variance baseline: {} CU vs mean {} (delta {})",
                    input.simulation_usage.compute_units,
                    input.baseline.mean_compute_units,
                    delta
                )),
            });
        }
        0.0
    } else {
        (input.simulation_usage.compute_units as f64 - input.baseline.mean_compute_units)
            / input.baseline.std_compute_units
    };

    if compute_z.is_nan() || compute_z.is_infinite() {
        return Ok(SimulationIntegrityResult {
            flagged: true,
            divergence_score: f64::MAX,
            reason: Some("Compute z-score produced NaN/Infinity — corrupted baseline".to_string()),
        });
    }

    if compute_z.abs() > input.divergence_threshold {
        return Ok(SimulationIntegrityResult {
            flagged: true,
            divergence_score: compute_z,
            reason: Some(format!(
                "Compute usage divergence: {:.2}σ from baseline (threshold: {:.2}σ)",
                compute_z, input.divergence_threshold
            )),
        });
    }

    // Signal 2: Account writes z-score. Zero-variance handling applies when
    // the signal has data (mean > 0); a mean==0 && std==0 signal means it was
    // never observed and is skipped (identical to the pre-existing gate).
    if !input.baseline.mean_account_writes.is_nan()
        && !(input.baseline.std_account_writes == 0.0 && input.baseline.mean_account_writes == 0.0)
    {
        let writes_z = if input.baseline.std_account_writes == 0.0 {
            let delta = (input.simulation_usage.account_writes as f64
                - input.baseline.mean_account_writes)
                .abs();
            if delta > ZERO_VARIANCE_EPSILON {
                return Ok(SimulationIntegrityResult {
                    flagged: true,
                    divergence_score: f64::MAX,
                    reason: Some(format!(
                        "Account write divergence from zero-variance baseline: {} writes vs mean {}",
                        input.simulation_usage.account_writes,
                        input.baseline.mean_account_writes
                    )),
                });
            }
            0.0
        } else {
            (input.simulation_usage.account_writes as f64 - input.baseline.mean_account_writes)
                / input.baseline.std_account_writes
        };

        if !writes_z.is_nan()
            && !writes_z.is_infinite()
            && writes_z.abs() > input.divergence_threshold
        {
            return Ok(SimulationIntegrityResult {
                flagged: true,
                divergence_score: writes_z,
                reason: Some(format!(
                    "Account write divergence: {:.2}σ from baseline ({} writes vs mean {:.1})",
                    writes_z,
                    input.simulation_usage.account_writes,
                    input.baseline.mean_account_writes
                )),
            });
        }
    }

    // Signal 3: CPI hops z-score (same zero-variance rules).
    if !input.baseline.mean_cpi_hops.is_nan()
        && !(input.baseline.std_cpi_hops == 0.0 && input.baseline.mean_cpi_hops == 0.0)
    {
        let hops_z = if input.baseline.std_cpi_hops == 0.0 {
            let delta =
                (input.simulation_usage.cpi_hops as f64 - input.baseline.mean_cpi_hops).abs();
            if delta > ZERO_VARIANCE_EPSILON {
                return Ok(SimulationIntegrityResult {
                    flagged: true,
                    divergence_score: f64::MAX,
                    reason: Some(format!(
                        "CPI hop divergence from zero-variance baseline: {} hops vs mean {}",
                        input.simulation_usage.cpi_hops, input.baseline.mean_cpi_hops
                    )),
                });
            }
            0.0
        } else {
            (input.simulation_usage.cpi_hops as f64 - input.baseline.mean_cpi_hops)
                / input.baseline.std_cpi_hops
        };

        if !hops_z.is_nan() && !hops_z.is_infinite() && hops_z.abs() > input.divergence_threshold {
            return Ok(SimulationIntegrityResult {
                flagged: true,
                divergence_score: hops_z,
                reason: Some(format!(
                    "CPI hop divergence: {:.2}σ from baseline ({} hops vs mean {:.1})",
                    hops_z, input.simulation_usage.cpi_hops, input.baseline.mean_cpi_hops
                )),
            });
        }
    }

    Ok(SimulationIntegrityResult {
        flagged: false,
        divergence_score: compute_z,
        reason: None,
    })
}

/// Update baseline with new execution data.
///
/// Updates all three tracked signals: compute units, account writes, and CPI hops.
/// Uses Welford's online algorithm for numerically stable mean/variance updates.
pub fn update_baseline(
    baseline: &mut ComputeBaseline,
    new_compute_units: u64,
    new_account_writes: u32,
    new_cpi_hops: u32,
) {
    let n = baseline.sample_count as f64;
    let new_n = n + 1.0;

    // Signal 1: Compute units (Welford's algorithm)
    let delta_cu = new_compute_units as f64 - baseline.mean_compute_units;
    let new_mean_cu = baseline.mean_compute_units + delta_cu / new_n;
    let new_var_cu = (baseline.std_compute_units * baseline.std_compute_units * n
        + delta_cu * (new_compute_units as f64 - new_mean_cu))
        / new_n;
    baseline.mean_compute_units = new_mean_cu;
    baseline.std_compute_units = new_var_cu.max(0.0).sqrt();

    // Signal 2: Account writes (Welford's algorithm)
    let delta_aw = new_account_writes as f64 - baseline.mean_account_writes;
    let new_mean_aw = baseline.mean_account_writes + delta_aw / new_n;
    let new_var_aw = (baseline.std_account_writes * baseline.std_account_writes * n
        + delta_aw * (new_account_writes as f64 - new_mean_aw))
        / new_n;
    baseline.mean_account_writes = new_mean_aw;
    baseline.std_account_writes = new_var_aw.max(0.0).sqrt();

    // Signal 3: CPI hops (Welford's algorithm)
    let delta_ch = new_cpi_hops as f64 - baseline.mean_cpi_hops;
    let new_mean_ch = baseline.mean_cpi_hops + delta_ch / new_n;
    let new_var_ch = (baseline.std_cpi_hops * baseline.std_cpi_hops * n
        + delta_ch * (new_cpi_hops as f64 - new_mean_ch))
        / new_n;
    baseline.mean_cpi_hops = new_mean_ch;
    baseline.std_cpi_hops = new_var_ch.max(0.0).sqrt();

    baseline.sample_count += 1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_large_compute_divergence_flagged() {
        let input = SimulationIntegrityInput {
            program_id: "test_program".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 5000,
                account_writes: 10,
                cpi_hops: 2,
            },
            baseline: ComputeBaseline {
                mean_compute_units: 1000.0,
                std_compute_units: 1000.0,
                sample_count: 100,
                mean_account_writes: 10.0,
                std_account_writes: 2.0,
                mean_cpi_hops: 2.0,
                std_cpi_hops: 1.0,
            },
            divergence_threshold: 2.0,
        };
        let result = check_simulation_integrity(&input).unwrap();
        assert!(result.flagged);
    }

    #[test]
    fn test_normal_compute_usage_not_flagged() {
        let input = SimulationIntegrityInput {
            program_id: "test_program".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 1100,
                account_writes: 10,
                cpi_hops: 2,
            },
            baseline: ComputeBaseline {
                mean_compute_units: 1000.0,
                std_compute_units: 100.0,
                sample_count: 100,
                mean_account_writes: 10.0,
                std_account_writes: 2.0,
                mean_cpi_hops: 2.0,
                std_cpi_hops: 1.0,
            },
            divergence_threshold: 2.0,
        };
        let result = check_simulation_integrity(&input).unwrap();
        assert!(!result.flagged);
    }

    #[test]
    fn test_account_write_divergence_flagged() {
        // Compute is fine but account writes are way off
        let input = SimulationIntegrityInput {
            program_id: "test_program".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 1000,
                account_writes: 50, // Way above baseline of 10
                cpi_hops: 2,
            },
            baseline: ComputeBaseline {
                mean_compute_units: 1000.0,
                std_compute_units: 100.0,
                sample_count: 100,
                mean_account_writes: 10.0,
                std_account_writes: 2.0,
                mean_cpi_hops: 2.0,
                std_cpi_hops: 1.0,
            },
            divergence_threshold: 2.0,
        };
        let result = check_simulation_integrity(&input).unwrap();
        assert!(result.flagged);
        assert!(result.reason.as_ref().unwrap().contains("Account write"));
    }

    #[test]
    fn test_cpi_hop_divergence_flagged() {
        let input = SimulationIntegrityInput {
            program_id: "test_program".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 1000,
                account_writes: 10,
                cpi_hops: 15, // Way above baseline of 2
            },
            baseline: ComputeBaseline {
                mean_compute_units: 1000.0,
                std_compute_units: 100.0,
                sample_count: 100,
                mean_account_writes: 10.0,
                std_account_writes: 2.0,
                mean_cpi_hops: 2.0,
                std_cpi_hops: 1.0,
            },
            divergence_threshold: 2.0,
        };
        let result = check_simulation_integrity(&input).unwrap();
        assert!(result.flagged);
        assert!(result.reason.as_ref().unwrap().contains("CPI hop"));
    }

    #[test]
    fn test_no_baseline_rejected() {
        let input = SimulationIntegrityInput {
            program_id: "test_program".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 1000,
                account_writes: 10,
                cpi_hops: 2,
            },
            baseline: ComputeBaseline {
                mean_compute_units: 1000.0,
                std_compute_units: 100.0,
                sample_count: 5,
                mean_account_writes: 10.0,
                std_account_writes: 2.0,
                mean_cpi_hops: 2.0,
                std_cpi_hops: 1.0,
            },
            divergence_threshold: 2.0,
        };
        let result = check_simulation_integrity(&input);
        assert!(matches!(
            result,
            Err(SimulationIntegrityError::NoBaseline { .. })
        ));
    }

    #[test]
    fn test_deterministic_same_input_same_output() {
        let input = SimulationIntegrityInput {
            program_id: "test_program".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 1100,
                account_writes: 10,
                cpi_hops: 2,
            },
            baseline: ComputeBaseline {
                mean_compute_units: 1000.0,
                std_compute_units: 100.0,
                sample_count: 100,
                mean_account_writes: 10.0,
                std_account_writes: 2.0,
                mean_cpi_hops: 2.0,
                std_cpi_hops: 1.0,
            },
            divergence_threshold: 2.0,
        };
        let result1 = check_simulation_integrity(&input).unwrap();
        let result2 = check_simulation_integrity(&input).unwrap();
        assert_eq!(result1.flagged, result2.flagged);
        assert_eq!(result1.divergence_score, result2.divergence_score);
    }

    #[test]
    fn test_baseline_update_converges() {
        let mut baseline = ComputeBaseline {
            mean_compute_units: 1000.0,
            std_compute_units: 100.0,
            sample_count: 100,
            mean_account_writes: 10.0,
            std_account_writes: 2.0,
            mean_cpi_hops: 2.0,
            std_cpi_hops: 1.0,
        };
        let old_mean = baseline.mean_compute_units;
        update_baseline(&mut baseline, 1100, 10, 2);
        assert_ne!(baseline.mean_compute_units, old_mean);
        assert_eq!(baseline.sample_count, 101);
    }

    #[test]
    fn test_zero_variance_baseline_no_longer_skips_check() {
        // SECURITY regression (zero-variance bypass): a baseline with std == 0
        // used to make the check return an error and the pipeline gate skipped
        // it PERMANENTLY — a spoofed tx could hide behind a uniform-history
        // baseline. Now: any deviation flags, an identical usage passes.
        let mut baseline = ComputeBaseline {
            mean_compute_units: 1000.0,
            std_compute_units: 0.0,
            sample_count: 100,
            mean_account_writes: 0.0,
            std_account_writes: 0.0,
            mean_cpi_hops: 0.0,
            std_cpi_hops: 0.0,
        };
        for _ in 0..100 {
            update_baseline(&mut baseline, 1000, 0, 0);
        }
        baseline.sample_count = 100;
        assert_eq!(baseline.std_compute_units, 0.0);

        // Deviating usage → flagged (max divergence, finite for JSON).
        let deviating = SimulationIntegrityInput {
            program_id: "test".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 5000,
                account_writes: 0,
                cpi_hops: 0,
            },
            baseline: baseline.clone(),
            divergence_threshold: 2.0,
        };
        let r = check_simulation_integrity(&deviating).unwrap();
        assert!(r.flagged);
        assert!(
            r.divergence_score.is_finite(),
            "divergence must be JSON-serializable"
        );

        // Identical usage → not flagged.
        let identical = SimulationIntegrityInput {
            program_id: "test".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 1000,
                account_writes: 0,
                cpi_hops: 0,
            },
            baseline,
            divergence_threshold: 2.0,
        };
        assert!(!check_simulation_integrity(&identical).unwrap().flagged);
    }

    #[test]
    fn test_degenerate_zero_baseline_is_fail_closed() {
        let input = SimulationIntegrityInput {
            program_id: "test".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 1000,
                account_writes: 0,
                cpi_hops: 0,
            },
            baseline: ComputeBaseline {
                mean_compute_units: 0.0,
                std_compute_units: 0.0,
                sample_count: 100,
                ..Default::default()
            },
            divergence_threshold: 2.0,
        };
        assert!(
            check_simulation_integrity(&input).is_err(),
            "degenerate baseline must fail-closed"
        );
    }

    #[test]
    fn test_zero_variance_writes_flagged_when_data_exists() {
        // Writes mean=5, std=0 (all historical txs wrote exactly 5 accounts)
        // → a tx writing 12 accounts is a max-signal divergence.
        let input = SimulationIntegrityInput {
            program_id: "test".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 1000,
                account_writes: 12,
                cpi_hops: 0,
            },
            baseline: ComputeBaseline {
                mean_compute_units: 1000.0,
                std_compute_units: 10.0,
                sample_count: 100,
                mean_account_writes: 5.0,
                std_account_writes: 0.0,
                mean_cpi_hops: 0.0,
                std_cpi_hops: 0.0,
            },
            divergence_threshold: 2.0,
        };
        let r = check_simulation_integrity(&input).unwrap();
        assert!(r.flagged);
    }

    #[test]
    fn test_unobserved_writes_signal_skipped_not_flagged() {
        // Writes mean=0, std=0 means the signal was never observed — it must
        // NOT flag every transaction (that would be a false-positive storm).
        let input = SimulationIntegrityInput {
            program_id: "test".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 1000,
                account_writes: 2,
                cpi_hops: 1,
            },
            baseline: ComputeBaseline {
                mean_compute_units: 1000.0,
                std_compute_units: 10.0,
                sample_count: 100,
                mean_account_writes: 0.0,
                std_account_writes: 0.0,
                mean_cpi_hops: 0.0,
                std_cpi_hops: 0.0,
            },
            divergence_threshold: 2.0,
        };
        let r = check_simulation_integrity(&input).unwrap();
        assert!(!r.flagged);
    }

    #[test]
    fn test_nan_in_writes_stats_rejected() {
        // Red Team L6 extended to the write/hop signals.
        let input = SimulationIntegrityInput {
            program_id: "test".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 1000,
                account_writes: 10,
                cpi_hops: 2,
            },
            baseline: ComputeBaseline {
                mean_compute_units: 1000.0,
                std_compute_units: 100.0,
                sample_count: 100,
                mean_account_writes: f64::NAN,
                std_account_writes: 2.0,
                mean_cpi_hops: 0.0,
                std_cpi_hops: 1.0,
            },
            divergence_threshold: 2.0,
        };
        assert!(check_simulation_integrity(&input).is_err());
    }

    #[test]
    fn test_divergence_always_json_serializable() {
        // Every path that produces a divergence_score must yield a finite,
        // JSON-serializable value (the score is returned in the HTTP body).
        let scores = [0.0_f64, f64::MAX, 3.5];
        for s in scores {
            let v = serde_json::to_value(SimulationIntegrityResult {
                flagged: true,
                divergence_score: s,
                reason: None,
            })
            .unwrap();
            assert!(v
                .get("divergence_score")
                .unwrap()
                .as_f64()
                .unwrap()
                .is_finite());
        }
    }
}
