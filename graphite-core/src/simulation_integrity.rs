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

/// Round 17 (F-16-02): the smallest spread a baseline is allowed to claim,
/// as a fraction of its centre. Ten identical early samples used to make
/// `std == 0`, after which EVERY other value was a ">1000σ" divergence and the
/// program's honest traffic was refused as `SimulationSpoofing` until an
/// operator reseeded — a freeze any caller could cause with ten requests. A
/// history that has only ever seen one value is treated as a band of
/// ±25% around it rather than a point: with the 2σ threshold, a deviation
/// beyond 50% of the centre still flags, a variation within it does not.
///
/// THE DETECTION FLOOR this sets (Round 29, audit 2026-10-20, S2), stated
/// exactly: a signal is flagged only when
/// `|value − centre| > threshold × max(measured spread, 0.25 × |centre|, 1)`,
/// for the mean/std statistic and the median/MAD one alike. With the
/// pipeline's threshold of 2.0 (`verification.rs`), NO deviation of 50% of
/// the centre or less is ever flagged, however tight the program's history
/// is: a program centred on 100,000 CU is flagged above 150,000 or below
/// 50,000 and not between. Deliberate: the figure judged is the whole
/// transaction's compute, and even one instruction in one composition
/// varies with its accounts and arguments (a swap's route, a loop's length);
/// a tighter floor flagged honest traffic as spoofing. Since Round 30 the
/// centre is the instruction's own (`SemanticGraphStore::shape_key`), with
/// the program's as the fallback while that is immature, and the band can
/// no longer drift past where it was anchored (`BaselineAnchor`). A
/// simulation-aware program that stays within the band is not caught by this
/// layer; the state diff (L4) judges what it does, not how much it costs.
pub const MIN_RELATIVE_SPREAD: f64 = 0.25;
/// Absolute floor on the spread, for the small integer signals (writes,
/// hops) whose centre may be 1 or 2: one write more or fewer than an
/// identical history is a 1σ event, not a maximal one.
pub const MIN_ABSOLUTE_SPREAD: f64 = 1.0;

/// The spread a signal is judged against: the measured one, or the floor.
fn effective_spread(centre: f64, measured: f64) -> f64 {
    measured
        .max(centre.abs() * MIN_RELATIVE_SPREAD)
        .max(MIN_ABSOLUTE_SPREAD)
}

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
/// window of RECENT samples per signal (each winsorized against the window's
/// own median once it holds `MIN_SAMPLES`, Round 29 S1 — see
/// `update_baseline`) so the integrity check can compute
/// robust median/MAD statistics. The window is what makes the baseline
/// poison-resistant: a few extreme samples affect mean/std immediately but can
/// only shift the median/MAD by a bounded amount (they need >50% of the window
/// to do that), and they age out of the window entirely.
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
    /// Bounded recent compute-unit samples (C28 robust baseline)
    #[serde(default)]
    pub recent_compute_units: Vec<u64>,
    /// Bounded recent account-write samples (C28 robust baseline)
    #[serde(default)]
    pub recent_account_writes: Vec<u32>,
    /// Bounded recent CPI-hop samples (C28 robust baseline)
    #[serde(default)]
    pub recent_cpi_hops: Vec<u32>,
    // Which observations this baseline has already counted is not kept here
    // any more. Round 17 kept the last `ROBUST_WINDOW` artifact digests on the
    // baseline itself, so an identity counted 257 observations ago counted
    // again (Round 19, F-19-03); the exact, non-aging memory now lives beside
    // the baseline in `SemanticGraphStore` (`ObservationMemory`). A snapshot
    // written by an older build still loads: serde ignores the retired
    // `recent_observation_keys` field.
    /// The band this baseline was first judged by (Round 30, G-03): fixed
    /// when it reached `MIN_SAMPLES`, or when an operator seeded or promoted
    /// it, and never moved by what it learns afterwards. See
    /// [`BaselineAnchor`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<BaselineAnchor>,
}

/// The centre and spread a baseline had when it first became able to judge
/// (Round 30, G-03).
///
/// Every observation a mature baseline learns is winsorized to one spread of
/// its centre (A2-06, S1), which bounds how far one observation moves it but
/// not how far many do: observations fed one after another at the edge of an
/// adaptive band walk the band with them — the mean by one spread / n per
/// step, the 256-sample window by up to one spread per window — and an
/// attacker patient enough to drip them in, or a program that really drifts,
/// ends up judged against a band nobody ever reviewed. The anchor does not
/// adapt. `check_simulation_integrity` judges every simulation against the
/// anchor as well as against the adaptive statistics, so whatever the
/// baseline has learned, a value more than `threshold` anchor spreads from
/// the anchor's centre is flagged — and a flagged observation is never
/// learned. Total drift is bounded by the anchored band. A program that
/// genuinely moved past it reaches its shadow accumulator, and an operator
/// promoting that shadow sets a new anchor.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct BaselineAnchor {
    pub compute_units: f64,
    pub compute_units_spread: f64,
    pub account_writes: f64,
    pub account_writes_spread: f64,
    pub cpi_hops: f64,
    pub cpi_hops_spread: f64,
}

/// The anchor a baseline is fixed to: its centres, and the effective spreads
/// (`MIN_RELATIVE_SPREAD` and `MIN_ABSOLUTE_SPREAD` floors included) those
/// centres are judged with, as they stand now.
pub fn anchor_of(baseline: &ComputeBaseline) -> BaselineAnchor {
    BaselineAnchor {
        compute_units: baseline.mean_compute_units,
        compute_units_spread: effective_spread(
            baseline.mean_compute_units,
            baseline.std_compute_units,
        ),
        account_writes: baseline.mean_account_writes,
        account_writes_spread: effective_spread(
            baseline.mean_account_writes,
            baseline.std_account_writes,
        ),
        cpi_hops: baseline.mean_cpi_hops,
        cpi_hops_spread: effective_spread(baseline.mean_cpi_hops, baseline.std_cpi_hops),
    }
}

/// Whether an anchor's numbers can judge anything: finite, and every spread
/// positive. A snapshot carrying one that cannot is dropped like any other
/// invalid baseline.
pub fn anchor_is_valid(anchor: &BaselineAnchor) -> bool {
    [
        anchor.compute_units,
        anchor.account_writes,
        anchor.cpi_hops,
    ]
    .iter()
    .all(|v| v.is_finite() && *v >= 0.0)
        && [
            anchor.compute_units_spread,
            anchor.account_writes_spread,
            anchor.cpi_hops_spread,
        ]
        .iter()
        .all(|v| v.is_finite() && *v > 0.0)
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

/// A window sample: compute units are `u64`, writes and hops `u32`.
trait WindowSample: Copy {
    fn as_f64(self) -> f64;
}
impl WindowSample for u64 {
    fn as_f64(self) -> f64 {
        self as f64
    }
}
impl WindowSample for u32 {
    fn as_f64(self) -> f64 {
        f64::from(self)
    }
}

/// The most recent `ROBUST_WINDOW` samples of a window, as `f64` (S5).
fn recent_window<T: WindowSample>(samples: &[T]) -> Vec<f64> {
    samples[samples.len().saturating_sub(ROBUST_WINDOW)..]
        .iter()
        .map(|&v| v.as_f64())
        .collect()
}

/// Drop the oldest samples until at most `ROBUST_WINDOW` remain (S5). One
/// element per update used to come off, so a window persisted longer than
/// the bound never shrank back to it.
fn trim_window<T>(samples: &mut Vec<T>) {
    let excess = samples.len().saturating_sub(ROBUST_WINDOW);
    if excess > 0 {
        samples.drain(..excess);
    }
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
///
/// Round 29 (audit 2026-10-20, S4): the threshold must be finite and
/// positive. A NaN compared false with every z-score, so it could never flag;
/// a negative or zero one flagged everything. Both are a misconfiguration,
/// and an `Err` here is a FLAG at the caller (verification.rs maps any error
/// to `flagged: true`), so a broken threshold fails closed.
///
/// S5: only the last `ROBUST_WINDOW` samples of each window are judged. A
/// persisted baseline can carry a longer one (written by hand, or by a build
/// that trimmed one element per update); it is not trusted to be recent.
pub fn check_simulation_integrity(
    input: &SimulationIntegrityInput,
) -> Result<SimulationIntegrityResult, SimulationIntegrityError> {
    if !input.divergence_threshold.is_finite() || input.divergence_threshold <= 0.0 {
        return Err(SimulationIntegrityError::InvalidData {
            reason: format!(
                "divergence threshold {} is not a finite positive number",
                input.divergence_threshold
            ),
        });
    }
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

    // Round 30 (G-03): the anchor first. Whatever the adaptive statistics
    // below have learned since, a value outside the band the baseline was
    // anchored to is a divergence. A signal the baseline has not observed (a
    // legacy baseline's unpopulated counter) is not judged here either.
    if let Some(anchor) = &input.baseline.anchor {
        if !anchor_is_valid(anchor) {
            return Err(SimulationIntegrityError::InvalidData {
                reason: "baseline anchor is not finite and positive".to_string(),
            });
        }
        let signals = [
            (
                input.simulation_usage.compute_units as f64,
                anchor.compute_units,
                anchor.compute_units_spread,
                true,
                "Compute usage",
            ),
            (
                f64::from(input.simulation_usage.account_writes),
                anchor.account_writes,
                anchor.account_writes_spread,
                signal_is_observed(
                    input.baseline.mean_account_writes,
                    input.baseline.std_account_writes,
                    recent_window(&input.baseline.recent_account_writes).len(),
                ),
                "Account write",
            ),
            (
                f64::from(input.simulation_usage.cpi_hops),
                anchor.cpi_hops,
                anchor.cpi_hops_spread,
                signal_is_observed(
                    input.baseline.mean_cpi_hops,
                    input.baseline.std_cpi_hops,
                    recent_window(&input.baseline.recent_cpi_hops).len(),
                ),
                "CPI hop",
            ),
        ];
        for (value, centre, spread, observed, label) in signals {
            if !observed {
                continue;
            }
            let z = (value - centre) / spread;
            if z.abs() > input.divergence_threshold {
                return Ok(SimulationIntegrityResult {
                    flagged: true,
                    divergence_score: z,
                    reason: Some(format!(
                        "{label} divergence: {z:.2}σ from the baseline's anchored band (threshold: {:.2}σ) — outside the band it was first judged by, whatever it has learned since",
                        input.divergence_threshold
                    )),
                });
            }
        }
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
        &recent_window(&input.baseline.recent_compute_units),
        input.divergence_threshold,
        "Compute usage (robust median/MAD)",
    ) {
        return Ok(z);
    }

    // Signal 2: Account writes.
    if signal_is_observed(
        input.baseline.mean_account_writes,
        input.baseline.std_account_writes,
        recent_window(&input.baseline.recent_account_writes).len(),
    ) {
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
            &recent_window(&input.baseline.recent_account_writes),
            input.divergence_threshold,
            "Account write (robust median/MAD)",
        ) {
            return Ok(z);
        }
    }

    // Signal 3: CPI hops.
    if signal_is_observed(
        input.baseline.mean_cpi_hops,
        input.baseline.std_cpi_hops,
        recent_window(&input.baseline.recent_cpi_hops).len(),
    ) {
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
            &recent_window(&input.baseline.recent_cpi_hops),
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
    // Round 17 (F-16-02): a zero or near-zero measured spread is judged
    // against the floor, not treated as a point. The zero-variance BYPASS
    // (skipping the check when std == 0) stays closed — the check still
    // runs, with a spread that cannot be made arbitrarily small.
    let std = effective_spread(mean, std);
    let z = (value - mean) / std;
    if z.is_nan() || z.is_infinite() {
        return Some(SimulationIntegrityResult {
            flagged: true,
            divergence_score: f64::MAX,
            reason: Some(format!(
                "{label} z-score produced NaN/Infinity — corrupted baseline"
            )),
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
    // Round 17 (F-16-02): the robust path gets the same floor as the
    // mean/std path — a zero-spread window is a ±25% band, not a point.
    let z = if d * 1.4826 < effective_spread(m, 0.0) {
        (value - m) / effective_spread(m, 0.0)
    } else {
        robust_z(value, samples)?
    };
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

/// Solana's hard per-transaction compute ceiling (`MAX_COMPUTE_UNIT_LIMIT`).
///
/// No execution can report more, so a larger figure did not come from one.
///
/// This matters because the baseline is DURABLE and governs every future
/// verification of that program. Folding one impossible sample into the
/// accumulator drags the mean and standard deviation up by orders of magnitude,
/// after which no real compute spike can ever reach the z-score threshold
/// again: a single response permanently disables L3 for that program.
///
/// `record_simulation` already restricted the accumulator to RPC-measured
/// usage, on the reasoning that the caller must not be able to normalize their
/// own divergence. That was the right rule aimed at the wrong party — it
/// assumed the RPC was honest. Found 2026-09-08 attacking the RPC trust
/// boundary. `seed_simulation_baseline` validates what an operator supplies;
/// this is the equivalent gate on what the network supplies.
pub const MAX_TRANSACTION_COMPUTE_UNITS: u64 = 1_400_000;

/// Whether a baseline signal carries enough information to judge against.
///
/// Two states mean "no verdict available", and they are different: a NaN mean
/// is a corrupted baseline, and a mean and standard deviation that are both
/// exactly zero mean the signal was never observed — every recorded sample was
/// zero, which is what an unpopulated counter looks like. Judging against
/// either would manufacture a divergence out of an absent measurement.
///
/// Written as an early return rather than a compound boolean because the two
/// cases have nothing to do with each other and reading them as one expression
/// obscures that.
///
/// Round 19 (F-19-21): "every sample was zero" is NOT the same as "never
/// measured" any more. Every observation the accumulator records carries a
/// measured write count and a measured CPI-hop count (`rpc_sim_ok` requires
/// both), and each is pushed onto the robust window. So a program whose
/// history holds MIN_SAMPLES samples of zero CPI hops has been OBSERVED to
/// make no CPIs — and a simulation of it that suddenly makes three is the
/// divergence this layer exists to see. Treating that history as unobserved
/// skipped the signal entirely. The mean/std-only test still applies to a
/// baseline with an empty window: one written by a build that predates the
/// window, whose zeros really are unpopulated counters.
fn signal_is_observed(mean: f64, std: f64, window_samples: usize) -> bool {
    if mean.is_nan() {
        return false;
    }
    if window_samples >= MIN_SAMPLES as usize {
        return true;
    }
    !(std == 0.0 && mean == 0.0)
}

/// Update baseline with new execution data.
///
/// Updates all three tracked signals: compute units, account writes, and CPI hops.
/// Uses Welford's online algorithm for numerically stable mean/variance updates,
/// and appends to the bounded recent-sample windows for the C28 robust stats.
///
/// THE BOOTSTRAP (Round 29, audit 2026-10-20, S3), stated exactly: while the
/// baseline holds fewer than `MIN_SAMPLES` (10) samples there is no verdict
/// (`check_simulation_integrity` returns `NoBaseline`) and nothing to hold an
/// observation to, so each of the first 10 recorded observations is learned
/// exactly as measured — into the mean/std AND the windows — with no clamp.
/// Those 10 set the centre and the spread every later observation is
/// winsorized against and every later simulation is judged against. Whoever
/// supplies a new program's first 10 RPC-verified, error-free simulations
/// therefore chooses its initial band (bounded only by the 1,400,000 CU
/// ceiling, the trace limits and the RPC being the one measuring); from the
/// 11th on, one observation can move the centre by at most one spread / n.
/// An operator who needs a different start seeds the baseline instead.
pub fn update_baseline(
    baseline: &mut ComputeBaseline,
    new_compute_units: u64,
    new_account_writes: u32,
    new_cpi_hops: u32,
) {
    // S1: the robust windows are winsorized too, against their OWN centre
    // and spread (median ± one effective MAD-spread) — computed before this
    // observation is added, from the same window the check reads.
    let window_learned = |samples: Vec<f64>, v: f64| -> f64 {
        if samples.len() < MIN_SAMPLES as usize {
            return v;
        }
        match (median(&samples), mad(&samples)) {
            (Some(m), Some(d)) => {
                let s = effective_spread(m, d * 1.4826);
                let (lo, hi) = ((m - s).max(0.0), m + s);
                if lo <= hi {
                    v.clamp(lo, hi)
                } else {
                    v
                }
            }
            _ => v,
        }
    };
    let window_cu = window_learned(
        recent_window(&baseline.recent_compute_units),
        new_compute_units as f64,
    )
    .round() as u64;
    let window_aw = window_learned(
        recent_window(&baseline.recent_account_writes),
        f64::from(new_account_writes),
    )
    .round() as u32;
    let window_ch = window_learned(
        recent_window(&baseline.recent_cpi_hops),
        f64::from(new_cpi_hops),
    )
    .round() as u32;

    let n = baseline.sample_count as f64;
    let new_n = n + 1.0;

    // A2-06 (2026-09-29 audit): a mature baseline learns from an observation
    // no further than one effective spread from its centre. Every recorded
    // observation had passed the check, but the check accepts up to 2 spreads
    // out, and recording one at that edge WIDENS the spread it is judged by:
    // 600 distinct edge observations, alternating direction, took a program
    // centred on 100k CU from a band ending near 150k to one ending near
    // 800k — L3 disabled for every caller of the program by one party, at no
    // fee. Winsorized at one spread, an edge observation still counts, its
    // pull on the centre is bounded, and it can no longer grow the spread
    // past what honest variation has shown. The bootstrap (fewer than
    // MIN_SAMPLES) has no centre to hold to and records as observed.
    let (learned_cu, learned_aw, learned_ch) = if baseline.sample_count >= MIN_SAMPLES {
        let clamp = |v: f64, mean: f64, std: f64| {
            let s = effective_spread(mean, std);
            let (lo, hi) = ((mean - s).max(0.0), mean + s);
            // `f64::clamp` panics on NaN or inverted bounds; a baseline that
            // produces them (a corrupted persisted one) learns the value as
            // observed rather than crashing the verifier (review F5).
            if lo <= hi {
                v.clamp(lo, hi)
            } else {
                v
            }
        };
        (
            clamp(
                new_compute_units as f64,
                baseline.mean_compute_units,
                baseline.std_compute_units,
            )
            .round() as u64,
            clamp(
                f64::from(new_account_writes),
                baseline.mean_account_writes,
                baseline.std_account_writes,
            )
            .round() as u32,
            clamp(
                f64::from(new_cpi_hops),
                baseline.mean_cpi_hops,
                baseline.std_cpi_hops,
            )
            .round() as u32,
        )
    } else {
        (new_compute_units, new_account_writes, new_cpi_hops)
    };

    // Signal 1: Compute units (Welford's algorithm)
    let delta_cu = learned_cu as f64 - baseline.mean_compute_units;
    let new_mean_cu = baseline.mean_compute_units + delta_cu / new_n;
    let new_var_cu = (baseline.std_compute_units * baseline.std_compute_units * n
        + delta_cu * (learned_cu as f64 - new_mean_cu))
        / new_n;
    baseline.mean_compute_units = new_mean_cu;
    baseline.std_compute_units = new_var_cu.max(0.0).sqrt();

    // Signal 2: Account writes (Welford's algorithm)
    let delta_aw = learned_aw as f64 - baseline.mean_account_writes;
    let new_mean_aw = baseline.mean_account_writes + delta_aw / new_n;
    let new_var_aw = (baseline.std_account_writes * baseline.std_account_writes * n
        + delta_aw * (learned_aw as f64 - new_mean_aw))
        / new_n;
    baseline.mean_account_writes = new_mean_aw;
    baseline.std_account_writes = new_var_aw.max(0.0).sqrt();

    // Signal 3: CPI hops (Welford's algorithm)
    let delta_ch = learned_ch as f64 - baseline.mean_cpi_hops;
    let new_mean_ch = baseline.mean_cpi_hops + delta_ch / new_n;
    let new_var_ch = (baseline.std_cpi_hops * baseline.std_cpi_hops * n
        + delta_ch * (learned_ch as f64 - new_mean_ch))
        / new_n;
    baseline.mean_cpi_hops = new_mean_ch;
    baseline.std_cpi_hops = new_var_ch.max(0.0).sqrt();

    // C28: maintain the bounded recent-sample windows (ring-buffer semantics —
    // push then truncate, so old samples age out and the median/MAD always
    // reflects recent behavior). Old serialized baselines have empty windows;
    // they fill in as new observations arrive.
    //
    // Round 29 (audit 2026-10-20, S1): what is pushed is the WINSORIZED value.
    // The raw one used to be, so A2-06's bound on how far one observation
    // pulls the baseline held for the mean/std and not for the median/MAD:
    // 129 one-sided observations at the edge of the band — each accepted by
    // the check — made the edge the window's median outright, a jump of two
    // spreads in one window's time. Clamped to one spread of the window's own
    // median, the same drift moves the median at most one spread per window,
    // the rate the Welford centre is held to. The window is clamped against
    // itself, not against the mean/std, so it stays the independent check
    // C28 made it: a poisoned mean/std cannot drag the window with it. A
    // sustained, one-sided drift is still learned — slowly, as every adaptive
    // baseline must learn a program that really changes.
    baseline.recent_compute_units.push(window_cu);
    trim_window(&mut baseline.recent_compute_units);
    baseline.recent_account_writes.push(window_aw);
    trim_window(&mut baseline.recent_account_writes);
    baseline.recent_cpi_hops.push(window_ch);
    trim_window(&mut baseline.recent_cpi_hops);

    baseline.sample_count += 1;

    // Round 30 (G-03): the band the bootstrap establishes is the one the
    // baseline is held to from now on.
    if baseline.anchor.is_none() && baseline.sample_count >= MIN_SAMPLES {
        baseline.anchor = Some(anchor_of(baseline));
    }
}

#[cfg(test)]
mod tests {
    /// Round 19 (F-19-21): a history of MIN_SAMPLES observed zero-hop
    /// executions judges a simulation that suddenly makes three CPI hops.
    #[test]
    fn an_observed_zero_is_judged_not_skipped() {
        let mut baseline = ComputeBaseline::default();
        for _ in 0..MIN_SAMPLES {
            update_baseline(&mut baseline, 5_000, 2, 0);
        }
        let judged = |hops: u32| {
            check_simulation_integrity(&SimulationIntegrityInput {
                program_id: "P".to_string(),
                simulation_usage: ComputeUsage {
                    compute_units: 5_000,
                    account_writes: 2,
                    cpi_hops: hops,
                },
                baseline: baseline.clone(),
                divergence_threshold: 2.0,
            })
            .unwrap()
        };
        assert!(!judged(0).flagged, "the same shape is consistent");
        let r = judged(3);
        assert!(
            r.flagged,
            "three CPI hops from a program never seen to make one"
        );
        assert!(r.reason.unwrap().contains("CPI hop"));
        // A baseline written before the window existed: its zeros are
        // unpopulated counters, and the signal is still not judged.
        let mut legacy = baseline.clone();
        legacy.recent_cpi_hops.clear();
        legacy.recent_account_writes.clear();
        legacy.recent_compute_units.clear();
        assert!(
            !check_simulation_integrity(&SimulationIntegrityInput {
                program_id: "P".to_string(),
                simulation_usage: ComputeUsage {
                    compute_units: 5_000,
                    account_writes: 2,
                    cpi_hops: 3,
                },
                baseline: legacy,
                divergence_threshold: 2.0,
            })
            .unwrap()
            .flagged
        );
    }

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

    /// Round 17 (F-16-02): a one-value history is a band, not a point.
    #[test]
    fn test_zero_variance_baseline_is_a_band_not_a_point() {
        let mut baseline = ComputeBaseline::default();
        for _ in 0..(MIN_SAMPLES as usize) {
            update_baseline(&mut baseline, 450, 2, 0);
        }
        assert_eq!(baseline.std_compute_units, 0.0);
        let check = |cu: u64| {
            check_simulation_integrity(&SimulationIntegrityInput {
                program_id: "p".to_string(),
                simulation_usage: ComputeUsage {
                    compute_units: cu,
                    account_writes: 2,
                    cpi_hops: 0,
                },
                baseline: baseline.clone(),
                divergence_threshold: 2.0,
            })
            .unwrap()
        };
        assert!(!check(450).flagged);
        assert!(
            !check(451).flagged,
            "one unit off a uniform history is not a divergence"
        );
        assert!(
            !check(600).flagged,
            "a third more is within the ±25% band at 2σ"
        );
        assert!(check(1200).flagged, "a real divergence still flags");
        assert!(check(100).flagged);
        // The small integer signals get the absolute floor: one write more
        // or fewer than a uniform history is a 1σ event.
        let writes = |w: u32| {
            check_simulation_integrity(&SimulationIntegrityInput {
                program_id: "p".to_string(),
                simulation_usage: ComputeUsage {
                    compute_units: 450,
                    account_writes: w,
                    cpi_hops: 0,
                },
                baseline: baseline.clone(),
                divergence_threshold: 2.0,
            })
            .unwrap()
        };
        assert!(!writes(3).flagged);
        assert!(writes(6).flagged);
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

    /// F5: a baseline whose bounds come out NaN or inverted is updated, not
    /// a panic.
    #[test]
    fn a_broken_baseline_does_not_panic_the_update() {
        for mean in [f64::NAN, -1.0e9] {
            let mut b = ComputeBaseline {
                sample_count: MIN_SAMPLES,
                mean_compute_units: mean,
                ..Default::default()
            };
            update_baseline(&mut b, 1_000, 2, 0);
            assert_eq!(b.sample_count, MIN_SAMPLES + 1);
        }
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
            &b.recent_compute_units
                .iter()
                .map(|&v| v as f64)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(
            (median_cu - 1000.0).abs() < 1.0,
            "median drifted: {median_cu}"
        );

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
        assert!(
            r.is_none(),
            "below MIN_SAMPLES the mean/std path must cover it"
        );
    }

    fn judge(baseline: &ComputeBaseline, cu: u64, threshold: f64) -> SimulationIntegrityResult {
        check_simulation_integrity(&SimulationIntegrityInput {
            program_id: "P".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: cu,
                account_writes: 2,
                cpi_hops: 1,
            },
            baseline: baseline.clone(),
            divergence_threshold: threshold,
        })
        .unwrap()
    }

    /// Round 29 (S1): one-sided drift at the edge of the band. Every
    /// observation passes the check, so the pipeline records every one; the
    /// window used to keep them raw, and 129 of them made the edge its
    /// median. Winsorized, the robust centre moves at most one spread.
    #[test]
    fn one_sided_edge_drift_moves_the_robust_centre_at_most_one_spread() {
        let mut b = ComputeBaseline::default();
        for i in 0..ROBUST_WINDOW as u64 {
            update_baseline(&mut b, 99_500 + (i % 11) * 100, 2, 1);
        }
        let centre = median(&recent_window(&b.recent_compute_units)).unwrap();
        assert!((centre - 100_000.0).abs() <= 500.0, "{centre}");
        for _ in 0..(ROBUST_WINDOW / 2 + 1) {
            let edge = 149_000;
            assert!(
                !judge(&b, edge, 2.0).flagged,
                "the edge observation passes the check, so it is recorded"
            );
            update_baseline(&mut b, edge, 2, 1);
        }
        let drifted = median(&recent_window(&b.recent_compute_units)).unwrap();
        assert!(
            drifted <= centre + 25_000.0 + 1.0,
            "the window's median moved from {centre} to {drifted}: more than one spread (25,000) in one window of one-sided edge traffic"
        );
        assert!(
            b.recent_compute_units.iter().all(|&v| v < 149_000),
            "no window sample sits further from its window's centre than one spread"
        );
    }

    /// S1: the window is winsorized against ITSELF, so a poisoned mean/std
    /// does not drag it (the C28 independence the window exists for).
    #[test]
    fn the_window_is_not_winsorized_against_a_poisoned_mean() {
        let mut b = poisoned_baseline();
        update_baseline(&mut b, 1000, 10, 2);
        assert_eq!(b.recent_compute_units.last(), Some(&1000));
    }

    /// Round 29 (S4): a threshold that is not a finite positive number is an
    /// error, and the pipeline maps an error to a flag.
    #[test]
    fn a_non_finite_or_non_positive_threshold_is_refused() {
        let mut b = ComputeBaseline::default();
        for _ in 0..MIN_SAMPLES {
            update_baseline(&mut b, 1_000, 2, 1);
        }
        for threshold in [f64::NAN, f64::INFINITY, -1.0, 0.0] {
            let r = check_simulation_integrity(&SimulationIntegrityInput {
                program_id: "P".to_string(),
                simulation_usage: ComputeUsage {
                    compute_units: 1_000_000,
                    account_writes: 2,
                    cpi_hops: 1,
                },
                baseline: b.clone(),
                divergence_threshold: threshold,
            });
            assert!(
                matches!(r, Err(SimulationIntegrityError::InvalidData { .. })),
                "threshold {threshold}: {r:?}"
            );
        }
        assert!(judge(&b, 1_000_000, 2.0).flagged);
    }

    /// Round 29 (S5): a persisted window longer than `ROBUST_WINDOW` is
    /// judged on its newest samples and trimmed to the bound in one update.
    #[test]
    fn an_overlong_window_is_judged_recent_and_trimmed_at_once() {
        let mut b = ComputeBaseline {
            mean_compute_units: 1_000.0,
            std_compute_units: 10.0,
            sample_count: 1_000,
            mean_account_writes: 2.0,
            mean_cpi_hops: 1.0,
            ..Default::default()
        };
        b.recent_compute_units = vec![50_000; 300];
        b.recent_compute_units.extend(vec![1_000; ROBUST_WINDOW]);
        b.recent_account_writes = vec![2; 300 + ROBUST_WINDOW];
        b.recent_cpi_hops = vec![1; 300 + ROBUST_WINDOW];
        assert!(
            !judge(&b, 1_000, 2.0).flagged,
            "only the newest {ROBUST_WINDOW} samples describe the program now"
        );
        update_baseline(&mut b, 1_000, 2, 1);
        assert_eq!(b.recent_compute_units.len(), ROBUST_WINDOW);
        assert_eq!(b.recent_account_writes.len(), ROBUST_WINDOW);
        assert_eq!(b.recent_cpi_hops.len(), ROBUST_WINDOW);
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

    // ─── Round 30 (G-03): the anchored band ────────────────────────────────

    /// Feed `steps` observations, each the largest compute figure the check
    /// accepts at that moment (found by bisection), and return the largest
    /// figure that was accepted and learned. `anchored` false strips the
    /// anchor first: the pre-Round-30 adaptive-only baseline.
    fn drip(steps: usize, anchored: bool, alternate: bool) -> u64 {
        let mut b = ComputeBaseline::default();
        for _ in 0..MIN_SAMPLES {
            update_baseline(&mut b, 100_000, 2, 1);
        }
        if !anchored {
            b.anchor = None;
        }
        let flags = |b: &ComputeBaseline, cu: u64| {
            check_simulation_integrity(&SimulationIntegrityInput {
                program_id: "P".to_string(),
                simulation_usage: ComputeUsage {
                    compute_units: cu,
                    account_writes: 2,
                    cpi_hops: 1,
                },
                baseline: b.clone(),
                divergence_threshold: 2.0,
            })
            .map(|r| r.flagged)
            .unwrap_or(true)
        };
        let mut highest = 0u64;
        for i in 0..steps {
            let up = !alternate || i % 2 == 0;
            // The accepted region is an interval around the centre; bisect
            // for its edge in the direction of travel.
            let centre = b.mean_compute_units.round() as u64;
            let (mut ok, mut bad) = if up {
                (centre, 1_400_000u64)
            } else {
                (centre, 0u64)
            };
            if flags(&b, ok) {
                break;
            }
            while ok.abs_diff(bad) > 1 {
                let mid = (ok + bad) / 2;
                if flags(&b, mid) {
                    bad = mid;
                } else {
                    ok = mid;
                }
            }
            highest = highest.max(ok);
            update_baseline(&mut b, ok, 2, 1);
        }
        highest
    }

    /// A slow drip: 3,000 observations, each at the very edge of what the
    /// check accepts. The adaptive-only baseline walks: the band its first
    /// ten samples set ended at 150,000 CU; the drip gets well past it. The
    /// anchored one never accepts a figure beyond that first band.
    #[test]
    fn a_slow_drip_cannot_walk_an_anchored_baseline() {
        let unanchored = drip(3_000, false, false);
        assert!(
            unanchored > 200_000,
            "the attack must work on the adaptive-only baseline for this test to mean anything: {unanchored}"
        );
        let anchored = drip(3_000, true, false);
        assert!(
            anchored <= 150_000,
            "the anchored baseline accepted {anchored} CU, beyond its first band"
        );
    }

    /// Alternating edge observations try to widen the spread instead of
    /// moving the centre. The anchored band does not widen.
    #[test]
    fn alternating_outliers_cannot_widen_an_anchored_band() {
        let anchored = drip(2_000, true, true);
        assert!(anchored <= 150_000, "{anchored}");
    }

    /// The anchor is set by the bootstrap, kept through later learning, and
    /// a corrupt one is an error (a flag at the caller), not a pass.
    #[test]
    fn the_anchor_is_fixed_at_maturity_and_validated() {
        let mut b = ComputeBaseline::default();
        for _ in 0..MIN_SAMPLES - 1 {
            update_baseline(&mut b, 10_000, 1, 0);
        }
        assert!(b.anchor.is_none(), "no anchor before MIN_SAMPLES");
        update_baseline(&mut b, 10_000, 1, 0);
        let anchor = b.anchor.clone().expect("anchored at MIN_SAMPLES");
        assert_eq!(anchor.compute_units, 10_000.0);
        assert_eq!(anchor.compute_units_spread, 2_500.0);
        for _ in 0..50 {
            update_baseline(&mut b, 12_000, 1, 0);
        }
        assert_eq!(b.anchor.as_ref(), Some(&anchor), "learning never moves it");
        b.anchor.as_mut().unwrap().compute_units_spread = f64::NAN;
        assert!(check_simulation_integrity(&SimulationIntegrityInput {
            program_id: "P".to_string(),
            simulation_usage: ComputeUsage {
                compute_units: 10_000,
                account_writes: 1,
                cpi_hops: 0,
            },
            baseline: b,
            divergence_threshold: 2.0,
        })
        .is_err());
    }
}
