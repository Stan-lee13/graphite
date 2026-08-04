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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
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

/// Result of simulation integrity check.
#[derive(Debug, Clone)]
pub struct SimulationIntegrityResult {
    pub flagged: bool,
    pub divergence_score: f64,
    pub reason: Option<String>,
}

/// Check simulation integrity against historical baseline.
///
/// Checks all three signals: compute units, account writes, CPI hops.
/// Any signal exceeding the threshold flags the simulation.
pub fn check_simulation_integrity(
    input: &SimulationIntegrityInput,
) -> Result<SimulationIntegrityResult, SimulationIntegrityError> {
    if input.baseline.sample_count < 10 {
        return Err(SimulationIntegrityError::NoBaseline {
            program_id: input.program_id.clone(),
        });
    }

    if input.baseline.std_compute_units == 0.0 {
        return Err(SimulationIntegrityError::InvalidData {
            reason: "baseline std_dev is zero".to_string(),
        });
    }

    // Reject NaN and Infinity in baseline (Red Team fix L6/L6b)
    if input.baseline.mean_compute_units.is_nan()
        || input.baseline.mean_compute_units.is_infinite()
        || input.baseline.std_compute_units.is_nan()
        || input.baseline.std_compute_units.is_infinite()
    {
        return Err(SimulationIntegrityError::InvalidData {
            reason: "baseline contains NaN or Infinity values".to_string(),
        });
    }

    // Signal 1: Compute units z-score
    let compute_z = (input.simulation_usage.compute_units as f64
        - input.baseline.mean_compute_units)
        / input.baseline.std_compute_units;

    if compute_z.is_nan() || compute_z.is_infinite() {
        return Ok(SimulationIntegrityResult {
            flagged: true,
            divergence_score: f64::INFINITY,
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

    // Signal 2: Account writes z-score (if baseline has data)
    if input.baseline.std_account_writes > 0.0 && !input.baseline.mean_account_writes.is_nan() {
        let writes_z = (input.simulation_usage.account_writes as f64
            - input.baseline.mean_account_writes)
            / input.baseline.std_account_writes;

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

    // Signal 3: CPI hops z-score (if baseline has data)
    if input.baseline.std_cpi_hops > 0.0 && !input.baseline.mean_cpi_hops.is_nan() {
        let hops_z = (input.simulation_usage.cpi_hops as f64 - input.baseline.mean_cpi_hops)
            / input.baseline.std_cpi_hops;

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
}
