//! Simulation Integrity Layer — ARCHITECTURE.md 3.17
//!
//! Detects Simulation Spoofing attacks by comparing simulation behavior against
//! historical execution baselines. A malicious program can detect whether it's
//! being invoked inside `simulateTransaction` versus real execution and behave
//! differently — clean in simulation, malicious in reality.
//!
//! This reference implementation demonstrates the divergence detection SHAPE.
//! The actual baseline management and threshold tuning are design decisions for
//! Phase 1+.

use thiserror::Error;

/// Error cases for simulation integrity checking.
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
    /// Compute units consumed
    pub compute_units: u64,
    /// Account write count
    pub account_writes: u32,
    /// CPI hop count
    pub cpi_hops: u32,
}

/// Historical baseline for a program.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ComputeBaseline {
    /// Mean compute units
    pub mean_compute_units: f64,
    /// Standard deviation of compute units
    pub std_compute_units: f64,
    /// Sample count
    pub sample_count: u64,
}

/// Input for simulation integrity check.
#[derive(Debug, Clone)]
pub struct SimulationIntegrityInput {
    /// Program ID being checked
    pub program_id: String,
    /// Compute usage from simulation
    pub simulation_usage: ComputeUsage,
    /// Historical baseline
    pub baseline: ComputeBaseline,
    /// Divergence threshold (default: 2.0 standard deviations)
    pub divergence_threshold: f64,
}

/// Result of simulation integrity check.
#[derive(Debug, Clone)]
pub struct SimulationIntegrityResult {
    /// Whether simulation is flagged as potentially spoofed
    pub flagged: bool,
    /// Divergence score (standard deviations from baseline)
    pub divergence_score: f64,
    /// Reason for flag (if flagged)
    pub reason: Option<String>,
}

/// Check simulation integrity against historical baseline.
///
/// This detects Simulation Spoofing by comparing compute usage against
/// historical execution. A large divergence suggests the program is behaving
/// differently in simulation than in real execution.
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
    
    // Red Team fix L6/L6b: Reject NaN and Infinity in baseline values.
    // NaN mean → NaN z-score → NaN.abs() > threshold is false → bypasses detection.
    // Infinity std → z-score = 0.0 → bypasses detection.
    if input.baseline.mean_compute_units.is_nan() 
        || input.baseline.mean_compute_units.is_infinite()
        || input.baseline.std_compute_units.is_nan()
        || input.baseline.std_compute_units.is_infinite() {
        return Err(SimulationIntegrityError::InvalidData {
            reason: "baseline contains NaN or Infinity values".to_string(),
        });
    }
    
    // Compute z-score for compute units
    let z_score = (input.simulation_usage.compute_units as f64 - input.baseline.mean_compute_units)
        / input.baseline.std_compute_units;
    
    // Sanity check: z-score must not be NaN (Constitution P3)
    if z_score.is_nan() || z_score.is_infinite() {
        return Ok(SimulationIntegrityResult {
            flagged: true, // Fail-safe: flag as suspicious (P12)
            divergence_score: f64::INFINITY,
            reason: Some("Z-score computation produced NaN/Infinity — baseline may be corrupted".to_string()),
        });
    }
    
    let flagged = z_score.abs() > input.divergence_threshold;
    
    let reason = if flagged {
        Some(format!(
            "Compute usage divergence: {:.2}σ from baseline (threshold: {:.2}σ)",
            z_score, input.divergence_threshold
        ))
    } else {
        None
    };
    
    Ok(SimulationIntegrityResult {
        flagged,
        divergence_score: z_score,
        reason,
    })
}

/// Update baseline with new execution data (simplified).
pub fn update_baseline(baseline: &mut ComputeBaseline, new_compute_units: u64) {
    let n = baseline.sample_count as f64;
    let new_n = n + 1.0;
    
    // Update mean
    let new_mean = (baseline.mean_compute_units * n + new_compute_units as f64) / new_n;
    
    // Update variance (simplified recurrence)
    let variance = baseline.std_compute_units * baseline.std_compute_units;
    let new_variance = (variance * n
        + (new_compute_units as f64 - baseline.mean_compute_units) * (new_compute_units as f64 - new_mean))
        / new_n;
    
    baseline.mean_compute_units = new_mean;
    baseline.std_compute_units = new_variance.sqrt();
    baseline.sample_count += 1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_large_compute_divergence_flagged() {
        // Load-bearing security test: large divergence flagged as potential spoofing
        let input = SimulationIntegrityInput {
            program_id: "test_program".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 5000, // Far from baseline
                account_writes: 10,
                cpi_hops: 2,
            },
            baseline: ComputeBaseline {
                mean_compute_units: 1000.0,
                std_compute_units: 1000.0,
                sample_count: 100,
            },
            divergence_threshold: 2.0,
        };
        
        let result = check_simulation_integrity(&input).unwrap();
        assert!(result.flagged);
        assert!(result.divergence_score > 2.0);
    }

    #[test]
    fn test_normal_compute_usage_not_flagged() {
        let input = SimulationIntegrityInput {
            program_id: "test_program".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 1100, // Close to baseline
                account_writes: 10,
                cpi_hops: 2,
            },
            baseline: ComputeBaseline {
                mean_compute_units: 1000.0,
                std_compute_units: 100.0,
                sample_count: 100,
            },
            divergence_threshold: 2.0,
        };
        
        let result = check_simulation_integrity(&input).unwrap();
        assert!(!result.flagged);
        assert!(result.divergence_score < 2.0);
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
                sample_count: 5, // Below threshold
            },
            divergence_threshold: 2.0,
        };
        
        let result = check_simulation_integrity(&input);
        assert!(matches!(result, Err(SimulationIntegrityError::NoBaseline { .. })));
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
        };
        
        let old_mean = baseline.mean_compute_units;
        update_baseline(&mut baseline, 1100);
        
        // Mean should shift toward new value
        assert_ne!(baseline.mean_compute_units, old_mean);
        assert_eq!(baseline.sample_count, 101);
    }
}
