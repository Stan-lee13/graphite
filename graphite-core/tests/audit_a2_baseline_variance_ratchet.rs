//! A2-06 (2026-09-29 audit): a mature L3 baseline cannot be widened by the
//! observations its own integrity check accepts.
//!
//! The pipeline records every un-flagged, RPC-clean simulation into the
//! program's trusted baseline, and the check accepts values up to two
//! effective spreads from the centre. Welford updates took each such sample at
//! full weight, so a stream of edge observations, alternating direction,
//! widened the spread they were judged by: about 600 distinct transactions
//! took a program centred on 100,000 CU from a band ending near 150,000 to one
//! ending near 800,000, and a 7x compute divergence no longer flagged. One
//! party could switch L3 off for every caller of the program.
//!
//! The fix is in `simulation_integrity`: once a baseline has `MIN_SAMPLES`,
//! each observation is winsorized to one effective spread from the current
//! centre before it updates the baseline. An edge observation still counts,
//! but it cannot grow the spread past what honest variation has shown. The
//! bootstrap below `MIN_SAMPLES` records as observed.
//!
//! The test builds an honest history, checks the controls (honest variation
//! accepted, a 7x divergence flagged), feeds 600 accepted edge observations,
//! and pins that 700,000 CU still flags afterwards.

use graphite_core::simulation_integrity::{
    check_simulation_integrity, update_baseline, ComputeBaseline, ComputeUsage,
    SimulationIntegrityInput,
};

fn flagged(b: &ComputeBaseline, cu: u64) -> bool {
    check_simulation_integrity(&SimulationIntegrityInput {
        program_id: "Prog".to_string(),
        simulation_usage: ComputeUsage {
            compute_units: cu,
            account_writes: 3,
            cpi_hops: 1,
        },
        baseline: b.clone(),
        divergence_threshold: 2.0, // what the pipeline passes
    })
    .map(|r| r.flagged)
    .unwrap_or(true)
}

/// Largest (or smallest) compute figure the current baseline accepts.
fn extreme_unflagged(b: &ComputeBaseline, upward: bool) -> u64 {
    let (mut ok, mut bad) = if upward {
        (b.mean_compute_units as u64, 1_400_000u64)
    } else {
        (b.mean_compute_units as u64, 0u64)
    };
    while ok.abs_diff(bad) > 1 {
        let mid = (ok + bad) / 2;
        if flagged(b, mid) {
            bad = mid;
        } else {
            ok = mid;
        }
    }
    ok
}

#[test]
fn accepted_observations_cannot_widen_the_band_eightfold() {
    let mut b = ComputeBaseline::default();
    // Honest history: 20 transactions at 100,000 CU +/- 1,000.
    for i in 0..20u64 {
        update_baseline(&mut b, 99_000 + (i * 97) % 2_000, 3, 1);
    }
    assert!(
        !flagged(&b, 120_000),
        "control: honest variation is accepted"
    );
    assert!(
        flagged(&b, 700_000),
        "control: 7x divergence flags on the honest baseline"
    );

    // The attacker: 600 distinct transactions, each at the edge of what the
    // current baseline accepts, alternating direction. Each is un-flagged, so
    // the pipeline records each one.
    let mut upward = true;
    for _ in 0..600 {
        let cu = extreme_unflagged(&b, upward);
        assert!(!flagged(&b, cu));
        update_baseline(&mut b, cu, 3, 1);
        upward = !upward;
    }

    assert!(
        flagged(&b, 700_000),
        "after 600 accepted observations the baseline (mean {:.0}, std {:.0}) no longer flags a \
         7x compute divergence",
        b.mean_compute_units,
        b.std_compute_units
    );
}
