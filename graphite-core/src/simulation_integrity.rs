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
//!
//! C28 (anti-poisoning): the mean/std z-score is supplemented with a robust
//! median/MAD statistic. Mean and std are both sensitive to outliers — a few
//! poisoned baseline samples (e.g. injected huge-compute txs) inflate std and
//! drag the mean, which NARROWS the z-score of a genuinely divergent tx and can
//! hide the attack. Median absolute deviation (MAD) is robust: a handful of
//! outliers barely move the median or MAD, so a poisoned baseline cannot mask
//! a real divergence. When enough samples exist in the bounded window the
//! robust z-score is used as the primary signal; mean/std remains the fallback
//! for small histories.

use thiserror::Error;

/// Minimum baseline samples before the z-score check is statistically
/// meaningful. Below this the check is SKIPPED (no verdict), per P12
/// fail-open-with-explanation — never faked, never fail-closed.
pub const MIN_SAMPLES: u64 = 10;

/// Bounded window of recent samples kept for robust median/MAD statistics.
/// Older samples fall out, so a poisoned spike ages out and cannot permanently
/// mask divergence. 256 samples is ~10x MIN_SAMPLES and cheap to sort.
pub const ROBUST_WINDOW: usize = 256;

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
///
/// C28: in addition to the Welford mean/std pairs, the baseline keeps a bounded
/// window of RECENT raw samples per signal so the integrity check can compute
/// robust median/MAD statistics. The window is what makes the baseline
/// poison-resistant: a few extreme samples affect mean/std immediately but can
/// only shift the median/MAD by a bounded amount (they need >50% of the window
/// to do that), and they age out of the window entirely.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Default)]
pub struct ComputeBaseline{
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
    /// Bounded recent compute-unit samples (C28 robust baseline)
    #[serde(default)]
    pub recent_compute_units: Vec<u64>,
    /// Bounded recent account-write samples (C28 robust baseline)
    #[serde(default)]
    pub recent_account_writes: Vec<u32>,
    /// Bounded recent CPI-hop samples (C28 robust baseline)
    #[serde(default)]
    pub recent_cpi_hops: Vec<u32>,
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

/// Median of a slice (does not mutate input; sorts a copy). Empty => None.
fn median(samples: &[f64]) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let mut s = samples.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = s.len();
    Some(if n % 2 == 1 {
        s[n / 2]
    } else {
        (s[n / 2 - 1] + s[n / 2]) / 2.0
    })
}

/// Median absolute deviation (MAD) of a slice: median(|x_i - median|).
/// Empty => None. This is the robust scale estimator used for the C28
/// poison-resistant z-score.
fn mad(samples: &[f64]) -> Option<f64> {
    let m = median(samples)?;
    let devs: Vec<f64> = samples.iter().map(|x| (x - m).abs()).collect();
    median(&devs)
}

/// Robust z-score = 0.6745 * (x - median) / MAD.
///
/// The 0.6745 scaling factor makes the robust z comparable to a standard
/// z-score for normally distributed data (MAD * 1.4826 approximates std).
/// Returns None when the window has no samples or MAD is 0 (zero spread —
/// caller decides how to handle identical histories).
fn robust_z(x: f64, samples: &[f64]) -> Option<f64> {
    let m = median(samples)?;
    let d = mad(samples)?;
    if d <= ZERO_VARIANCE_EPSILON {
        return None; // zero spread: caller uses zero-variance semantics
    }
    Some(0.6745 * (x - m) / d)
}

/// Check simulation integrity against historical baseline.
///
/// Checks all three signals: compute units, account writes, CPI hops.
/// Any signal exceeding the threshold flags the simulation.
///
/// C28: when the bounded window has >= MIN_SAMPLES samples, the robust
/// median/MAD z-score is the primary signal (it cannot be masked by a few
/// poisoned outliers). The mean/std z-score is used as a fallback when the
/// window is too small, and as a secondary check when both exist — a tx that
/// diverges on EITHER statistic is flagged, because an attacker could target
/// whichever the check uses.
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

    // Degenerate baseline (zero mean AND zero variance for compute):
    // there are no meaningful statistics, so fail-closed.
    if input.baseline.mean_compute_units == 0.0 && input.baseline.std_compute_units == 0.0 {
        return Err(SimulationIntegrityError::InvalidData {
            reason: "baseline is degenerate (zero mean AND zero variance for compute)".to_string(),
        });
    }

    // Signal 1: Compute units — evaluate BOTH the mean/std z-score and the
    // C28 robust median/MAD z-score. Flag if either exceeds the threshold:
    // an attacker who can poison the baseline targets whichever statistic the
    // check uses, so both must be checked.
    if let Some(z) = mean_std_z(
        input.simulation_usage.compute_units as f64,
        input.baseline.mean_compute_units,
        input.baseline.std_compute_units,
        input.divergence_threshold,
        "Compute usage",
    ) {
        return Ok(z);
    }
    if let Some(z) = robust_signal_z(
        input.simulation_usage.compute_units as f64,
        &input
            .baseline
            .recent_compute_units
            .iter()
            .map(|&v| v as f64)
            .collect::<Vec<_>>(),
        input.divergence_threshold,
        "Compute usage (robust median/MAD)",
    ) {
        return Ok(z);
    }

    // Signal 2: Account writes.
    if !input.baseline.mean_account_writes.is_nan()
        && !(input.baseline.std_account_writes == 0.0 && input.baseline.mean_account_writes == 0.0)
    {
        if let Some(z) = mean_std_z(
            input.simulation_usage.account_writes as f64,
            input.baseline.mean_account_writes,
            input.baseline.std_account_writes,
            input.divergence_threshold,
            "Account write",
        ) {
            return Ok(z);
        }
        if let Some(z) = robust_signal_z(
            input.simulation_usage.account_writes as f64,
            &input.baseline.recent_account_writes.iter().map(|&v| v as f64).collect::<Vec<_>>(),
            input.divergence_threshold,
            "Account write (robust median/MAD)",
        ) {
            return Ok(z);
        }
    }

    // Signal 3: CPI hops.
    if !input.baseline.mean_cpi_hops.is_nan()
        && !(input.baseline.std_cpi_hops == 0.0 && input.baseline.mean_cpi_hops == 0.0)
    {
        if let Some(z) = mean_std_z(
            input.simulation_usage.cpi_hops as f64,
            input.baseline.mean_cpi_hops,
            input.baseline.std_cpi_hops,
            input.divergence_threshold,
            "CPI hop",
        ) {
            return Ok(z);
        }
        if let Some(z) = robust_signal_z(
            input.simulation_usage.cpi_hops as f64,
            &input.baseline.recent_cpi_hops.iter().map(|&v| v as f64).collect::<Vec<_>>(),
            input.divergence_threshold,
            "CPI hop (robust median/MAD)",
        ) {
            return Ok(z);
        }
    }

    Ok(SimulationIntegrityResult {
        flagged: false,
        divergence_score: 0.0,
        reason: None,
    })
}

/// Evaluate one signal with the classic mean/std z-score (zero-variance aware).
/// Returns Some(result) if the signal FLAGS (or errors are encoded as flags);
/// None means the signal is consistent (or unobserved and skipped).
fn mean_std_z(
    value: f64,
    mean: f64,
    std: f64,
    threshold: f64,
    label: &str,
) -> Option<SimulationIntegrityResult> {
    if std == 0.0 {
        // Zero variance: mean must be nonzero (degenerate baselines are
        // rejected earlier by the caller for the compute signal; writes/hops
        // with mean==0 are unobserved and skipped by the caller's gate).
        let delta = (value - mean).abs();
        if delta > ZERO_VARIANCE_EPSILON {
            return Some(SimulationIntegrityResult {
                flagged: true,
                divergence_score: f64::MAX,
                reason: Some(format!(
                    "{} divergence from zero-variance baseline: {:.0} vs mean {:.0} (delta {:.0})",
                    label, value, mean, delta
                )),
            });
        }
        return None;
    }
    let z = (value - mean) / std;
    if z.is_nan() || z.is_infinite() {
        return Some(SimulationIntegrityResult {
            flagged: true,
            divergence_score: f64::MAX,
            reason: Some(format!("{label} z-score produced NaN/Infinity — corrupted baseline")),
        });
    }
    if z.abs() > threshold {
        return Some(SimulationIntegrityResult {
            flagged: true,
            divergence_score: z,
            reason: Some(format!(
                "{label} divergence: {:.2}σ from baseline (threshold: {:.2}σ)",
                z, threshold
            )),
        });
    }
    None
}

/// Evaluate one signal with the C28 robust median/MAD z-score. Requires at
/// least MIN_SAMPLES in the bounded window; returns None when the window is
/// too small (the mean/std check covers those histories).
///
/// Zero-spread window (all samples identical): when the median is nonzero,
/// any deviation beyond epsilon is a maximum-signal divergence (mirroring
/// the mean/std zero-variance path). A zero-spread, zero-median window is
/// degenerate and yields None (the mean/std path covers unobserved signals).
fn robust_signal_z(
    value: f64,
    samples: &[f64],
    threshold: f64,
    label: &str,
) -> Option<SimulationIntegrityResult> {
    if samples.len() < MIN_SAMPLES as usize {
        return None;
    }
    let m = median(samples)?;
    let d = mad(samples)?;
    if d <= ZERO_VARIANCE_EPSILON {
        // Zero-spread window: any deviation beyond noise is a max signal.
        let delta = (value - m).abs();
        if delta > ZERO_VARIANCE_EPSILON {
            return Some(SimulationIntegrityResult {
                flagged: true,
                divergence_score: f64::MAX,
                reason: Some(format!(
                    "{label} robust median/MAD (zero-spread window): {:.0} vs median {:.0} (delta {:.0})",
                    value, m, delta
                )),
            });
        }
        return None;
    }
    let z = robust_z(value, samples)?;
    if z.abs() > threshold {
        return Some(SimulationIntegrityResult {
            flagged: true,
            divergence_score: z,
            reason: Some(format!(
                "{label} divergence: {:.2} robust-σ from median (threshold: {:.2}σ)",
                z, threshold
            )),
        });
    }
    None
}

/// Update baseline with new execution data.
///
/// Updates all three tracked signals: compute units, account writes, and CPI hops.
/// Uses Welford's online algorithm for numerically stable mean/variance updates,
/// and appends to the bounded recent-sample windows for the C28 robust stats.
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

    // C28: maintain the bounded recent-sample windows (ring-buffer semantics —
    // push then truncate, so old samples age out and the median/MAD always
    // reflects recent behavior). Old serialized baselines have empty windows;
    // they fill in as new observations arrive.
    baseline.recent_compute_units.push(new_compute_units);
    if baseline.recent_compute_units.len() > ROBUST_WINDOW {
        baseline.recent_compute_units.remove(0);
    }
    baseline.recent_account_writes.push(new_account_writes);
    if baseline.recent_account_writes.len() > ROBUST_WINDOW {
        baseline.recent_account_writes.remove(0);
    }
    baseline.recent_cpi_hops.push(new_cpi_hops);
    if baseline.recent_cpi_hops.len() > ROBUST_WINDOW {
        baseline.recent_cpi_hops.remove(0);
    }

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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
            },
            divergence_threshold: 2.0,
        };
        assert!(check_simulation_integrity(&input).is_err());
    }

    // ------------------------------------------------------------------
    // C28 — robust median/MAD baseline (anti-poisoning)
    // ------------------------------------------------------------------

    /// Build a baseline whose mean/std has been POISONED by a few extreme
    /// samples but whose recent window is honest. The classic z-score uses
    /// the poisoned mean/std; the robust z-score uses the window median/MAD.
    fn poisoned_baseline() -> ComputeBaseline {
        let mut b = ComputeBaseline {
            mean_compute_units: 1000.0,
            std_compute_units: 100.0,
            sample_count: 100,
            mean_account_writes: 10.0,
            std_account_writes: 2.0,
            mean_cpi_hops: 2.0,
            std_cpi_hops: 1.0,
            ..Default::default()
        };
        // Honest history: compute units ~1000.
        for _ in 0..100 {
            update_baseline(&mut b, 1000, 10, 2);
        }
        // Poison: inject 3 extreme samples directly into the Welford stats.
        // (This simulates a baseline whose mean/std were polluted upstream —
        // the C28 defense must not rely on the poisoned pair.)
        b.mean_compute_units = 5000.0;
        b.std_compute_units = 2000.0;
        // The window stays honest (recent real observations).
        assert!(b.recent_compute_units.len() <= ROBUST_WINDOW);
        assert!(b.recent_compute_units.iter().all(|&c| c < 2000));
        b
    }

    #[test]
    fn test_robust_z_catches_divergence_masked_by_poisoned_mean_std() {
        // A genuinely divergent tx (6000 CU) looks NORMAL to the poisoned
        // mean/std (mean 5000, std 2000 → z = 0.5) but is 5+ robust-σ from
        // the honest median (~1000, MAD ~0). The robust check must flag it.
        let baseline = poisoned_baseline();
        let input = SimulationIntegrityInput {
            program_id: "test".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 6000,
                account_writes: 10,
                cpi_hops: 2,
            },
            baseline,
            divergence_threshold: 2.0,
        };
        let r = check_simulation_integrity(&input).unwrap();
        assert!(
            r.flagged,
            "robust z must catch divergence masked by poisoned mean/std: {:?}",
            r.reason
        );
        assert!(
            r.reason.as_ref().unwrap().contains("robust median/MAD"),
            "flag must come from the robust statistic: {:?}",
            r.reason
        );
    }

    #[test]
    fn test_robust_z_does_not_flag_normal_usage_under_poison() {
        // The same poisoned baseline must NOT flag a normal tx (1000 CU).
        let baseline = poisoned_baseline();
        let input = SimulationIntegrityInput {
            program_id: "test".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 1000,
                account_writes: 10,
                cpi_hops: 2,
            },
            baseline,
            divergence_threshold: 2.0,
        };
        let r = check_simulation_integrity(&input).unwrap();
        assert!(!r.flagged, "normal usage must not flag: {:?}", r.reason);
    }

    #[test]
    fn test_window_ages_out_poison_and_recovers() {
        // Poison ages out of the bounded window: after ROBUST_WINDOW honest
        // observations, the window median/MAD fully reflects reality and a
        // divergent tx is caught even though mean/std were polluted.
        let mut b = poisoned_baseline();
        for _ in 0..ROBUST_WINDOW {
            update_baseline(&mut b, 1000, 10, 2);
        }
        assert!(b.recent_compute_units.len() <= ROBUST_WINDOW);
        // The window must be dominated by the honest 1000s now.
        let median_cu = median(
            &b.recent_compute_units.iter().map(|&v| v as f64).collect::<Vec<_>>(),
        )
        .unwrap();
        assert!((median_cu - 1000.0).abs() < 1.0, "median drifted: {median_cu}");

        let input = SimulationIntegrityInput {
            program_id: "test".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 6000,
                account_writes: 10,
                cpi_hops: 2,
            },
            baseline: b,
            divergence_threshold: 2.0,
        };
        let r = check_simulation_integrity(&input).unwrap();
        assert!(r.flagged, "window recovery must still catch divergence");
    }

    #[test]
    fn test_median_and_mad_are_correct() {
        let samples = [1.0, 2.0, 3.0, 4.0, 100.0];
        assert_eq!(median(&samples), Some(3.0));
        // MAD = median(|x - 3|) = median(2,1,0,1,97) = 1.0
        assert_eq!(mad(&samples), Some(1.0));
        // Robust z of 100 vs this: 0.6745 * (100-3)/1 ≈ 65.4
        let z = robust_z(100.0, &samples).unwrap();
        assert!((z - 0.6745 * 97.0).abs() < 1e-9);
        // Robust z of 3 (the median) is 0.
        assert_eq!(robust_z(3.0, &samples), Some(0.0));
    }

    #[test]
    fn test_robust_z_needs_min_samples() {
        let small = [1.0, 2.0, 3.0];
        assert_eq!(robust_z(100.0, &small), Some(0.6745 * 98.0 / 1.0));
        // The robust_signal_z gate requires MIN_SAMPLES in the window.
        let r = robust_signal_z(100.0, &small, 2.0, "t");
        assert!(r.is_none(), "below MIN_SAMPLES the mean/std path must cover it");
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
