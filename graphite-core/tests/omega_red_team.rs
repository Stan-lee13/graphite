//! OMEGA RED TEAM — Exploit Suite
//!
//! Mission: Find and exploit vulnerabilities in Graphite.
//! Every exploit in this file was written to trigger a real failure.
//! If it compiles and the test panics/fails, the vulnerability is real.

#![allow(dead_code)]
#![allow(clippy::all)]
use graphite_core::confidence_engine::{compute_confidence, SignalKind, TrustTier, WeightedSignal};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::risk_engine::{
    assess, assess_with_warnings, RiskAssessmentInput, RiskPattern, RiskVerdict,
};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::simulation_integrity::{
    check_simulation_integrity, ComputeBaseline, ComputeUsage, SimulationIntegrityInput,
};
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

fn max_evidence() -> BehaviorEvidence {
    BehaviorEvidence {
        has_signed_manifest: true,
        simulation_match_count: 3,
        battle_tested_tx_count: 1000,
        community_verified_count: 2,
    }
}

// L1: Drainer with exactly 5 accounts bypasses (threshold is >5, not >=5)
#[test]
fn exploit_l1_drainer_threshold_bypass_5_accounts() {
    let input = RiskAssessmentInput {
        program_id: "MaliciousDrainerProgram1111111111111".to_string(),
        accounts: vec![
            "victim_wallet".to_string(),
            "attacker_wallet_1".to_string(),
            "attacker_wallet_2".to_string(),
            "attacker_wallet_3".to_string(),
            "attacker_wallet_4".to_string(),
        ],
        cpi_targets: vec![],
        expected_state_changes: vec![],
        allowed_cpis: vec![],
        instruction_discriminator: String::new(),
        expected_account_count: None,
        proposed_intent_type: String::new(),
        variable_accounts: false,
        extracted_output_token: None,
        manifest_risk_class: String::new(),
    };
    let result = assess(&input).unwrap();
    assert!(
        matches!(result, RiskVerdict::Blocked { .. }),
        "L1 FIXED: Drainer with exactly 5 accounts now blocked (>=5)."
    );
}

// L2: Hidden transfer with exactly 12 accounts bypasses (threshold is >12, not >=12)
#[test]
fn exploit_l2_hidden_transfer_threshold_bypass_12_accounts() {
    let accounts: Vec<String> = (0..12).map(|i| format!("account_{}", i)).collect();
    let input = RiskAssessmentInput {
        program_id: "SomeProgram111111111111111111111111111".to_string(),
        accounts,
        cpi_targets: vec![],
        expected_state_changes: vec!["accounts.0.transfer".to_string()],
        allowed_cpis: vec![],
        instruction_discriminator: String::new(),
        expected_account_count: None,
        proposed_intent_type: String::new(),
        variable_accounts: false,
        extracted_output_token: None,
        manifest_risk_class: String::new(),
    };
    let result = assess(&input).unwrap();
    assert!(
        matches!(result, RiskVerdict::Blocked { .. }),
        "L2 FIXED: Hidden transfer with exactly 12 accounts now blocked (>=12)."
    );
}

// L3: Compositional drain with exactly 4 repeated CPI targets bypasses (>4, not >=4)
#[test]
fn exploit_l3_compositional_drain_bypass_4_targets() {
    let drainer = "DrainerProgram111111111111111111111111111";
    let input = RiskAssessmentInput {
        program_id: "aggregator".to_string(),
        accounts: vec!["wallet".to_string()],
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
        proposed_intent_type: String::new(),
        variable_accounts: false,
        extracted_output_token: None,
        manifest_risk_class: String::new(),
    };
    let result = assess(&input).unwrap();
    assert!(
        matches!(result, RiskVerdict::Blocked { .. }),
        "L3 FIXED: 4 repeated CPI targets now blocked (>=3)."
    );
}

// L4: Token-2022 SetAuthority — fixed with correct program ID
#[test]
fn exploit_l4_token2022_setauthority_bypass() {
    let real_token2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
    let input = RiskAssessmentInput {
        program_id: real_token2022.to_string(),
        accounts: vec!["token_account".into(), "new_authority".into()],
        cpi_targets: vec![],
        expected_state_changes: vec!["changes authority".into()],
        allowed_cpis: vec![],
        instruction_discriminator: "06".to_string(),
        expected_account_count: None,
        proposed_intent_type: String::new(),
        variable_accounts: false,
        extracted_output_token: None,
        manifest_risk_class: String::new(),
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
        "L4 FIXED: SetAuthority on real Token-2022 now blocked."
    );
}

// L6: NaN in baseline mean bypasses simulation spoofing detection
#[test]
fn exploit_l6_nan_baseline_bypasses_simulation_check() {
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
            mean_account_writes: 0.0,
            std_account_writes: 0.0,
            mean_cpi_hops: 0.0,
            std_cpi_hops: 0.0,
            ..Default::default()
        },
        divergence_threshold: 2.0,
    };
    let result = check_simulation_integrity(&input);
    assert!(result.is_err(), "L6 FIXED: NaN baseline mean now rejected.");
}

// L6b: Infinity std bypasses simulation check
#[test]
fn exploit_l6b_infinity_std_bypasses_simulation_check() {
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
            mean_account_writes: 0.0,
            std_account_writes: 0.0,
            mean_cpi_hops: 0.0,
            std_cpi_hops: 0.0,
            ..Default::default()
        },
        divergence_threshold: 2.0,
    };
    let result = check_simulation_integrity(&input);
    assert!(result.is_err(), "L6b FIXED: Infinity std now rejected.");
}

// L8: Empty discriminator bypasses SetAuthority detection
#[test]
fn exploit_l8_empty_discriminator_bypasses_setauthority() {
    let input = RiskAssessmentInput {
        program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
        accounts: vec!["account1".into(), "account2".into()],
        cpi_targets: vec![],
        expected_state_changes: vec!["transfer".into()],
        allowed_cpis: vec![],
        instruction_discriminator: String::new(),
        expected_account_count: None,
        proposed_intent_type: String::new(),
        variable_accounts: false,
        extracted_output_token: None,
        manifest_risk_class: String::new(),
    };
    let result = assess(&input).unwrap();
    assert!(
        matches!(result, RiskVerdict::Blocked { .. }),
        "L8 FIXED: Empty discriminator on SPL Token now blocked."
    );
}

// L11: NaN signal value passes confidence range check
#[test]
fn exploit_l11_nan_confidence_bypass() {
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
    match result {
        Ok(_) => {
            panic!("L11 FIXED CHECK FAILED: NaN signal should be rejected but produced confidence")
        }
        Err(_) => {} // FIXED — NaN is now rejected
    }
}

// L12: 6 copies of SAME account with NO changes = false positive drainer
#[test]
fn exploit_l12_account_duplication_false_positive() {
    let input = RiskAssessmentInput {
        program_id: "legit_program".to_string(),
        accounts: vec!["same_account".into(); 6],
        cpi_targets: vec![],
        expected_state_changes: vec![],
        allowed_cpis: vec![],
        instruction_discriminator: String::new(),
        expected_account_count: None,
        proposed_intent_type: String::new(),
        variable_accounts: false,
        extracted_output_token: None,
        manifest_risk_class: String::new(),
    };
    let result = assess(&input).unwrap();
    assert_eq!(
        result,
        RiskVerdict::Passed,
        "L12 FIXED: 6 copies of same account no longer triggers drainer (dedup)."
    );
}

// L14: Unknown instruction on System Program passes
#[test]
fn exploit_l14_unknown_system_instruction_passes() {
    let input = RiskAssessmentInput {
        program_id: "11111111111111111111111111111111".to_string(),
        accounts: vec!["account".into()],
        cpi_targets: vec![],
        expected_state_changes: vec!["some_change".into()],
        allowed_cpis: vec![],
        instruction_discriminator: "ff00ff".to_string(),
        expected_account_count: None,
        proposed_intent_type: String::new(),
        variable_accounts: false,
        extracted_output_token: None,
        manifest_risk_class: String::new(),
    };
    let result = assess(&input).unwrap();
    assert_eq!(
        result,
        RiskVerdict::Passed,
        "L14 EXPLOIT: Unknown discriminator on System Program passes. Only Assign is flagged. \
         P12 concern: unknown instructions should reduce confidence."
    );
}

// L15: Infinity signal value — verify it's rejected
#[test]
fn exploit_l15_infinity_signal_rejected() {
    let signals = vec![
        WeightedSignal {
            kind: SignalKind::ManifestMatch,
            value: f64::INFINITY,
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
        "L15 VERIFIED: Infinity correctly rejected by confidence engine."
    );
}

// L18: 100 accounts with 1 meaningful state change bypasses drainer AND hidden transfer
#[test]
fn exploit_l18_drainer_with_single_meaningful_change_bypass() {
    let accounts: Vec<String> = (0..100).map(|i| format!("account_{}", i)).collect();
    let input = RiskAssessmentInput {
        program_id: "SomeProgram111111111111111111111111".to_string(),
        accounts,
        cpi_targets: vec![],
        expected_state_changes: vec!["transfer".to_string()],
        allowed_cpis: vec![],
        instruction_discriminator: String::new(),
        expected_account_count: None,
        proposed_intent_type: String::new(),
        variable_accounts: false,
        extracted_output_token: None,
        manifest_risk_class: String::new(),
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
        "L18 FIXED: 100 accounts with 1 transfer now blocked (ratio-based)."
    );
}

// L19: Full pipeline test — unknown protocol with Gaming profile
#[test]
fn exploit_l19_unknown_protocol_permissive_bypass() {
    let core = GraphiteCore::new();
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Transfer 1 SOL".to_string(),
            confidence_of_parse: 1.0,
            extracted_parameters: None,
        },
        program_id: "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec!["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string()],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: max_evidence(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
    };
    let result = core.verify(&input).unwrap();
    // Unknown tier capped at 0.55. Gaming threshold is 0.50.
    // But Gaming requires TrustTier::HeuristicInferred minimum.
    // Unknown < HeuristicInferred → should be rejected.
    assert!(
        !result.approved,
        "L19 VERIFIED: Unknown protocol correctly rejected by trust tier minimum."
    );
}

// L20: CPI allowed list injection — malicious program self-allowed
#[test]
fn exploit_l20_cpi_self_allowing() {
    let malicious = "MaliciousDrainerProgram111111111111111";
    let input = RiskAssessmentInput {
        program_id: "legit_program".to_string(),
        accounts: vec!["wallet".into()],
        cpi_targets: vec![malicious.into()],
        expected_state_changes: vec!["transfer".into()],
        allowed_cpis: vec![malicious.into()],
        instruction_discriminator: String::new(),
        expected_account_count: None,
        proposed_intent_type: String::new(),
        variable_accounts: false,
        extracted_output_token: None,
        manifest_risk_class: String::new(),
    };
    let result = assess(&input).unwrap();
    assert_eq!(
        result,
        RiskVerdict::Passed,
        "L20 EXPLOIT: Malicious program in allowed_cpis passes CPI check. \
         No whitelist validation on allowed_cpis."
    );
}

// L21: Negative compute_units (u64 underflow via i64 conversion)
// Compute units is u64 — can't be negative. But what about account_writes/cpi_hops (u32)?
// These are u32, so they can't be negative either. This is safe.

// L22: Simulation baseline with sample_count < 10 — check skipped entirely
#[test]
fn exploit_l22_low_sample_count_skips_simulation_check() {
    // In the verification pipeline, if baseline.sample_count < 10, sim check is skipped
    // This means an attacker can provide a baseline with sample_count = 9
    // to bypass simulation spoofing detection entirely
    let core = GraphiteCore::new();
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Transfer 1 SOL".to_string(),
            confidence_of_parse: 1.0,
            extracted_parameters: None,
        },
        program_id: "11111111111111111111111111111111".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
        ],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::TradingBot,
        behavior_evidence: max_evidence(),
        compute_units: 999999, // Massive compute — should be flagged
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
    };
    // SECURITY (baseline trust model): baselines are trusted state seeded via
    // the operator API — an attacker can no longer supply a low-sample-count
    // baseline from the request body to skip the check. This test pins the
    // (intentional) behavior that a baseline with sample_count < 10 skips the
    // statistical check for lack of significance.
    core.seed_simulation_baseline(
        "11111111111111111111111111111111",
        ComputeBaseline {
            mean_compute_units: 150.0,
            std_compute_units: 20.0,
            sample_count: 9, // Below MIN_SAMPLES — check skipped!
            mean_account_writes: 0.0,
            std_account_writes: 0.0,
            mean_cpi_hops: 0.0,
            std_cpi_hops: 0.0,
            ..Default::default()
        },
    )
    .unwrap();
    let result = core.verify(&input).unwrap();
    // PINNED (P5/P12): with the trusted-baseline model the caller can no
    // longer supply a low-sample baseline at all (seed_simulation_baseline is
    // operator-only). A baseline below MIN_SAMPLES yields NO statistical
    // verdict — `simulation_flagged` must be exactly None, never a false
    // Some(false) "clean" (and never Some(true): insufficient data is not
    // evidence of divergence — it is absence of evidence, per the 5-Response
    // Framework's response 2/1, not response 4). The old assertion
    // `is_none() || !unwrap()` was weakened by the second branch.
    assert_eq!(
        result.simulation_flagged, None,
        "<MIN_SAMPLES baseline must produce no simulation verdict (None), got {:?}",
        result.simulation_flagged
    );
}

// ═══════════════════════════════════════════════════════════
// PROTOCOL EXPANSION (Phase 2 Month 1) — TRUSTED DEX ROOT COVERAGE
//
// Pump.fun and Jupiter DCA were added to DEX_PROGRAMS and TRUSTED_CPI_ROOTS
// (2026-08-07). These tests prove the relaxations cannot mask a real drainer
// and pin the intended trusted-root behavior, so a future edit to those
// allowlists can't silently widen the bypass surface.
// ═══════════════════════════════════════════════════════════

const PUMP_FUN: &str = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
const JUPITER_DCA: &str = "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M";
const WORMHOLE: &str = "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth";
const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

// DX1/DX2: repeated-program CPI chains must STILL be blocked on both new
// trusted roots — the DEX_PROGRAMS/TRUSTED_CPI_ROOTS relaxations apply to the
// drainer heuristic and the token-CPI whitelist, NOT to compositional drains.
#[test]
fn dx1_pumpfun_repeated_cpi_drain_still_blocked() {
    let input = RiskAssessmentInput {
        program_id: PUMP_FUN.to_string(),
        accounts: vec!["curve".to_string(), "user".to_string()],
        cpi_targets: vec!["evil_drainer_program".to_string(); 4],
        expected_state_changes: vec!["credits accounts.curve".to_string()],
        allowed_cpis: vec![SPL_TOKEN.to_string()],
        instruction_discriminator: "66063d1201daebea".to_string(),
        expected_account_count: None,
        proposed_intent_type: "swap".to_string(),
        variable_accounts: false,
        extracted_output_token: None,
        manifest_risk_class: String::new(),
    };
    assert!(
        matches!(
            assess(&input).unwrap(),
            RiskVerdict::Blocked {
                pattern: RiskPattern::CompositionalDrainPattern,
                ..
            }
        ),
        "DX1 FIXED: repeated-program CPI chain on pump.fun root must still be blocked"
    );
}

#[test]
fn dx2_dca_repeated_cpi_drain_still_blocked() {
    let input = RiskAssessmentInput {
        program_id: JUPITER_DCA.to_string(),
        accounts: vec!["user".to_string(), "escrow".to_string()],
        cpi_targets: vec!["evil_drainer_program".to_string(); 4],
        expected_state_changes: vec!["debits accounts.escrow".to_string()],
        allowed_cpis: vec![SPL_TOKEN.to_string()],
        instruction_discriminator: "16072162a8b722f3".to_string(),
        expected_account_count: None,
        proposed_intent_type: "close".to_string(),
        variable_accounts: false,
        extracted_output_token: None,
        manifest_risk_class: String::new(),
    };
    assert!(
        matches!(
            assess(&input).unwrap(),
            RiskVerdict::Blocked {
                pattern: RiskPattern::CompositionalDrainPattern,
                ..
            }
        ),
        "DX2 FIXED: repeated-program CPI chain on Jupiter DCA root must still be blocked"
    );
}

// DX3: SPL Token CPI from a TRUSTED_CPI_ROOT is legitimate (curve transfers,
// DCA escrow) — must NOT be flagged as AuthorityHijack.
#[test]
fn dx3_pumpfun_and_dca_token_cpi_from_trusted_root_is_allowed() {
    for (program, disc, intent) in [
        (PUMP_FUN, "66063d1201daebea", "swap"),
        (JUPITER_DCA, "16072162a8b722f3", "close"),
    ] {
        let input = RiskAssessmentInput {
            program_id: program.to_string(),
            accounts: vec!["user".to_string(), "curve_or_escrow".to_string()],
            cpi_targets: vec![SPL_TOKEN.to_string()],
            expected_state_changes: vec![
                "debits accounts.user".to_string(),
                "credits accounts.curve_or_escrow".to_string(),
            ],
            allowed_cpis: vec![SPL_TOKEN.to_string()],
            instruction_discriminator: disc.to_string(),
            expected_account_count: None,
            proposed_intent_type: intent.to_string(),
            variable_accounts: false,
            extracted_output_token: None,
            manifest_risk_class: String::new(),
        };
        assert_eq!(
            assess(&input).unwrap(),
            RiskVerdict::Passed,
            "DX3 FIXED: {} is a TRUSTED_CPI_ROOT — SPL Token CPI must not be flagged as AuthorityHijack",
            program
        );
    }
}

// DX4: P12/P3 — an out-of-manifest CPI on a known trusted root is a WARNING,
// not a silent pass and not a hard block. The warning must be surfaced by
// assess_with_warnings, never dropped.
#[test]
fn dx4_pumpfun_unlisted_cpi_warning_surfaced_not_silent() {
    let input = RiskAssessmentInput {
        program_id: PUMP_FUN.to_string(),
        accounts: vec!["curve".to_string(), "user".to_string()],
        cpi_targets: vec!["some_unlisted_program".to_string()],
        expected_state_changes: vec!["credits accounts.curve".to_string()],
        allowed_cpis: vec![SPL_TOKEN.to_string()],
        instruction_discriminator: "66063d1201daebea".to_string(),
        expected_account_count: None,
        proposed_intent_type: "swap".to_string(),
        variable_accounts: false,
        extracted_output_token: None,
        manifest_risk_class: String::new(),
    };
    let detail = assess_with_warnings(&input).unwrap();
    assert_eq!(
        detail.verdict,
        RiskVerdict::Passed,
        "DX4 VERIFIED: P12 — unlisted CPI on known protocol is a warning, not a block"
    );
    assert!(
        !detail.warnings.is_empty(),
        "DX4 FIXED: P3 — out-of-manifest CPI warning must be surfaced, never silently dropped"
    );
}

// DX5: the drainer relaxation is PROGRAM-SCOPED. Wormhole Core and Metaplex
// were added this cycle but are NOT in DEX_PROGRAMS — a drainer-shaped
// transaction on Wormhole must still be blocked.
#[test]
fn dx5_non_dex_expansion_roots_do_not_get_drainer_relaxation() {
    let input = RiskAssessmentInput {
        program_id: WORMHOLE.to_string(),
        accounts: vec![
            "a1".to_string(),
            "a2".to_string(),
            "a3".to_string(),
            "a4".to_string(),
            "a5".to_string(),
            "a6".to_string(),
        ],
        cpi_targets: vec![],
        expected_state_changes: vec![],
        allowed_cpis: vec![],
        instruction_discriminator: "01".to_string(),
        expected_account_count: None,
        proposed_intent_type: String::new(),
        variable_accounts: false,
        extracted_output_token: None,
        manifest_risk_class: String::new(),
    };
    assert!(
        matches!(
            assess(&input).unwrap(),
            RiskVerdict::Blocked {
                pattern: RiskPattern::Drainer,
                ..
            }
        ),
        "DX5 VERIFIED: Wormhole must NOT inherit the DEX_PROGRAMS drainer relaxation"
    );
}
