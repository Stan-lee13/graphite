//! OMEGA RED TEAM — Regression Tests (Post-Fix)
//!
//! These tests verify that the vulnerabilities found by the Red Team
//! have been fixed. Each test asserts that the previous exploit
//! no longer works.

use graphite_core::confidence_engine::{compute_confidence, SignalKind, TrustTier, WeightedSignal};
use graphite_core::risk_engine::{assess, RiskAssessmentInput, RiskPattern, RiskVerdict};
use graphite_core::simulation_integrity::{
    check_simulation_integrity, ComputeBaseline, ComputeUsage, SimulationIntegrityInput,
};

// R-L1: Drainer with 5 accounts should now be BLOCKED (>=5, not >5)
#[test]
fn regression_l1_drainer_5_accounts_now_blocked() {
    let input = RiskAssessmentInput {
        program_id: "MaliciousDrainerProgram1111111111111".to_string(),
        accounts: vec![
            "victim_wallet".into(),
            "att1".into(),
            "att2".into(),
            "att3".into(),
            "att4".into(),
        ],
        cpi_targets: vec![],
        expected_state_changes: vec![],
        allowed_cpis: vec![],
        instruction_discriminator: String::new(),
            expected_account_count: None,
    };
    let result = assess(&input).unwrap();
    assert!(
        matches!(
            result,
            RiskVerdict::Blocked {
                pattern: RiskPattern::Drainer,
                ..
            }
        ),
        "L1 FIXED: 5 accounts now correctly blocked as drainer (>=5)"
    );
}

// R-L2: Hidden transfer with 12 accounts should now be BLOCKED (>=12, not >12)
#[test]
fn regression_l2_hidden_transfer_12_accounts_now_blocked() {
    let accounts: Vec<String> = (0..12).map(|i| format!("account_{}", i)).collect();
    let input = RiskAssessmentInput {
        program_id: "SomeProgram111111111111111111111111111".to_string(),
        accounts,
        cpi_targets: vec![],
        expected_state_changes: vec!["accounts.0.transfer".into()],
        allowed_cpis: vec![],
        instruction_discriminator: String::new(),
            expected_account_count: None,
    };
    let result = assess(&input).unwrap();
    assert!(
        matches!(
            result,
            RiskVerdict::Blocked {
                pattern: RiskPattern::HiddenTransfer,
                ..
            }
        ),
        "L2 FIXED: 12 accounts now correctly blocked as hidden transfer (>=12)"
    );
}

// R-L3: 4 repeated CPI targets should now be BLOCKED (>=3, not >4)
#[test]
fn regression_l3_compositional_drain_4_targets_now_blocked() {
    let drainer = "DrainerProgram111111111111111111111111111";
    let input = RiskAssessmentInput {
        program_id: "aggregator".to_string(),
        accounts: vec!["wallet".into()],
        cpi_targets: vec![
            drainer.into(),
            drainer.into(),
            drainer.into(),
            drainer.into(),
        ],
        expected_state_changes: vec![],
        allowed_cpis: vec![drainer.into()],
        instruction_discriminator: String::new(),
            expected_account_count: None,
    };
    let result = assess(&input).unwrap();
    assert!(
        matches!(
            result,
            RiskVerdict::Blocked {
                pattern: RiskPattern::CompositionalDrainPattern,
                ..
            }
        ),
        "L3 FIXED: 4 repeated CPI targets now blocked (>=3)"
    );
}

// R-L4: Token-2022 SetAuthority should now be BLOCKED with correct program ID
#[test]
fn regression_l4_token2022_setauthority_now_blocked() {
    let real_token2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
    let input = RiskAssessmentInput {
        program_id: real_token2022.to_string(),
        accounts: vec!["token_account".into(), "new_authority".into()],
        cpi_targets: vec![],
        expected_state_changes: vec!["changes authority".into()],
        allowed_cpis: vec![],
        instruction_discriminator: "0b".to_string(),
            expected_account_count: None,
    };
    let result = assess(&input).unwrap();
    assert!(
        matches!(
            result,
            RiskVerdict::Blocked {
                pattern: RiskPattern::AuthorityHijack,
                ..
            }
        ),
        "L4 FIXED: SetAuthority on real Token-2022 ({}) now blocked",
        real_token2022
    );
}

// R-L4b: SPL Token SetAuthority should now be BLOCKED with correct program ID
#[test]
fn regression_l4b_spl_token_setauthority_now_blocked() {
    let real_spl_token = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    let input = RiskAssessmentInput {
        program_id: real_spl_token.to_string(),
        accounts: vec!["token_account".into(), "new_authority".into()],
        cpi_targets: vec![],
        expected_state_changes: vec!["changes authority".into()],
        allowed_cpis: vec![],
        instruction_discriminator: "0b".to_string(),
            expected_account_count: None,
    };
    let result = assess(&input).unwrap();
    assert!(
        matches!(
            result,
            RiskVerdict::Blocked {
                pattern: RiskPattern::AuthorityHijack,
                ..
            }
        ),
        "L4b FIXED: SetAuthority on real SPL Token ({}) now blocked",
        real_spl_token
    );
}

// R-L6: NaN baseline should now be REJECTED
#[test]
fn regression_l6_nan_baseline_now_rejected() {
    let input = SimulationIntegrityInput {
        program_id: "test".to_string(),
        simulation_usage: ComputeUsage {
            compute_units: 999999,
            account_writes: 100,
            cpi_hops: 50,
        },
        baseline: ComputeBaseline {
            mean_compute_units: f64::NAN,
            std_compute_units: 100.0,
            sample_count: 100,
        },
        divergence_threshold: 2.0,
    };
    let result = check_simulation_integrity(&input);
    assert!(
        result.is_err(),
        "L6 FIXED: NaN baseline mean now rejected (no longer bypasses detection)"
    );
}

// R-L6b: Infinity std should now be REJECTED
#[test]
fn regression_l6b_infinity_std_now_rejected() {
    let input = SimulationIntegrityInput {
        program_id: "test".to_string(),
        simulation_usage: ComputeUsage {
            compute_units: 999999,
            account_writes: 100,
            cpi_hops: 50,
        },
        baseline: ComputeBaseline {
            mean_compute_units: 100.0,
            std_compute_units: f64::INFINITY,
            sample_count: 100,
        },
        divergence_threshold: 2.0,
    };
    let result = check_simulation_integrity(&input);
    assert!(result.is_err(), "L6b FIXED: Infinity std now rejected");
}

// R-L8: Empty discriminator on SPL Token should now be BLOCKED
#[test]
fn regression_l8_empty_discriminator_spl_token_now_blocked() {
    let input = RiskAssessmentInput {
        program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
        accounts: vec!["account1".into(), "account2".into()],
        cpi_targets: vec![],
        expected_state_changes: vec!["transfer".into()],
        allowed_cpis: vec![],
        instruction_discriminator: String::new(),
            expected_account_count: None,
    };
    let result = assess(&input).unwrap();
    assert!(
        matches!(result, RiskVerdict::Blocked { .. }),
        "L8 FIXED: Empty discriminator on SPL Token now blocked (P12 fail-closed)"
    );
}

// R-L11: NaN signal value should now be REJECTED by confidence engine
#[test]
fn regression_l11_nan_signal_now_rejected() {
    let signals = vec![
        WeightedSignal {
            kind: SignalKind::ManifestMatch,
            value: f64::NAN,
            weight: 0.3,
        },
        WeightedSignal {
            kind: SignalKind::SimulationMatch,
            value: 1.0,
            weight: 0.3,
        },
        WeightedSignal {
            kind: SignalKind::HistoricalVolume,
            value: 1.0,
            weight: 0.25,
        },
        WeightedSignal {
            kind: SignalKind::CommunityVerification,
            value: 1.0,
            weight: 0.15,
        },
    ];
    let result = compute_confidence(&signals, TrustTier::BattleTested);
    assert!(
        result.is_err(),
        "L11 FIXED: NaN signal value now rejected (no longer produces NaN confidence)"
    );
}

// R-L12: 6 copies of same account should NOT trigger drainer (deduplication)
#[test]
fn regression_l12_dedup_prevents_false_positive() {
    let input = RiskAssessmentInput {
        program_id: "legit_program".to_string(),
        accounts: vec!["same_account".into(); 6],
        cpi_targets: vec![],
        expected_state_changes: vec![],
        allowed_cpis: vec![],
        instruction_discriminator: String::new(),
            expected_account_count: None,
    };
    let result = assess(&input).unwrap();
    // After dedup, only 1 unique account → should NOT be flagged as drainer
    assert_eq!(
        result,
        RiskVerdict::Passed,
        "L12 FIXED: 6 copies of same account no longer triggers drainer (deduplication works)"
    );
}

// R-L18: 100 accounts with 1 "transfer" should now be BLOCKED (ratio-based)
#[test]
fn regression_l18_100_accounts_1_change_now_blocked() {
    let accounts: Vec<String> = (0..100).map(|i| format!("account_{}", i)).collect();
    let input = RiskAssessmentInput {
        program_id: "SomeProgram111111111111111111111111".to_string(),
        accounts,
        cpi_targets: vec![],
        expected_state_changes: vec!["transfer".to_string()],
        allowed_cpis: vec![],
        instruction_discriminator: String::new(),
            expected_account_count: None,
    };
    let result = assess(&input).unwrap();
    assert!(
        matches!(
            result,
            RiskVerdict::Blocked {
                pattern: RiskPattern::Drainer,
                ..
            }
        ),
        "L18 FIXED: 100 accounts with 1 transfer now blocked (ratio-based drainer detection)"
    );
}
