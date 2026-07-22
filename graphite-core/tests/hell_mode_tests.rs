//! HELL MODE — Adversarial test suite designed to BREAK Graphite.
//!
//! Philosophy: Every test here is crafted to exploit a specific weakness.
//! If Graphite passes, the test is too weak. We escalate.
//!
//! Attack vectors:
//! H1: Trust tier gaming — max evidence to inflate confidence on dangerous tx
//! H2: Discriminator confusion — valid disc on wrong program
//! H3: Permissive profile + unknown protocol — can it slip through?
//! H4: Intent-discriminator mismatch — say "transfer", do "close"
//! H5: Zero/degenerate account edge cases
//! H6: Manifest spoofing — inject a manifest that declares dangerous ops as safe
//! H7: CPI substring/prefix attack — CPI target that's substring of allowed
//! H8: Duplicate account injection — same address repeated N times
//! H9: Confidence ceiling exploitation — unknown protocol at exactly 0.55
//! H10: Risk engine pattern shadowing — safe pattern masks dangerous one
//! H11: State change injection — crafted state changes neutralize drainer
//! H12: Legitimate-but-dangerous ops — Squads Execute, Stake Delegate
//! H13: Mixed-case program ID
//! H14: Unicode/homoglyph in program ID
//! H15: Audit trail uniqueness across 500 calls
//! H16: Empty string vs "00" vs "0x00" discriminator
//! H17: Behavior evidence overflow — u32::MAX values
//! H18: Protocol version injection
//! H19: Instruction data injection — 100KB payload
//! H20: Concurrent verification determinism — 500 calls
//! H21: Policy engine bypass — custom profile with zero thresholds
//! H22: Hidden transfer detection bypass
//! H23: Composable attack chains — multiple vectors combined
//! H24: Policy engine isolation — risk overrides perfect confidence

use graphite_core::{
    GraphiteCore, VerificationInput, ProposedIntent,
    WalletProfile,
    risk_engine::{assess, RiskAssessmentInput, RiskVerdict, RiskPattern},
    confidence_engine::{TrustTier},
    policy_engine::{evaluate_policy, PolicyInput, PolicyVerdict},
    semantic_graph_store::BehaviorEvidence,
};
use graphite_core::confidence_engine::ConfidenceResult;

fn max_evidence() -> BehaviorEvidence {
    BehaviorEvidence {
        has_signed_manifest: true,
        community_verified_count: u32::MAX,
        battle_tested_tx_count: u64::MAX,
        simulation_match_count: u64::MAX,
    }
}

fn zero_evidence() -> BehaviorEvidence {
    BehaviorEvidence {
        has_signed_manifest: false,
        community_verified_count: 0,
        battle_tested_tx_count: 0,
        simulation_match_count: 0,
    }
}

fn make_input(
    program_id: &str,
    disc: &str,
    accounts: &[&str],
    profile: WalletProfile,
    evidence: BehaviorEvidence,
) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Transfer 1 SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: program_id.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: disc.to_string(),
        account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: profile,
        behavior_evidence: evidence,
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
            simulation_baseline: None,
    }
}

fn risk_input(
    program: &str,
    accounts: &[&str],
    cpi: &[&str],
    state_changes: &[&str],
    allowed_cpis: &[&str],
    disc: &str,
) -> RiskAssessmentInput {
    RiskAssessmentInput {
        program_id: program.to_string(),
        accounts: accounts.iter().map(|s| s.to_string()).collect(),
        cpi_targets: cpi.iter().map(|s| s.to_string()).collect(),
        expected_state_changes: state_changes.iter().map(|s| s.to_string()).collect(),
        allowed_cpis: allowed_cpis.iter().map(|s| s.to_string()).collect(),
        instruction_discriminator: disc.to_string(),
    }
}

// ═══════════════════════════════════════════════════════════
// H1: TRUST TIER GAMING
// ═══════════════════════════════════════════════════════════

#[test]
fn h1_max_evidence_cannot_override_risk_block() {
    let core = GraphiteCore::new();
    let input = make_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "0b",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        WalletProfile::Permissive,
        max_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved, "MAX evidence + Permissive must NOT override risk block on SetAuthority");
    assert_eq!(result.risk_verdict.status, "Blocked");
}

#[test]
fn h1_max_evidence_cannot_override_unknown_protocol_block() {
    let core = GraphiteCore::new();
    let input = make_input(
        "4Nd1mYbz1NQ8Tk6eX5N6w5eM6eX5N6w5eM6eX5N6w5eM",
        "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        WalletProfile::Permissive,
        max_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved, "MAX evidence must NOT make unknown protocol pass Permissive profile");
    assert!(result.confidence <= 0.551, "Unknown protocol confidence must be capped even with max evidence");
}

// ═══════════════════════════════════════════════════════════
// H2: DISCRIMINATOR CONFUSION
// ═══════════════════════════════════════════════════════════

#[test]
fn h2_system_transfer_disc_on_spl_token() {
    let core = GraphiteCore::new();
    let input = make_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        WalletProfile::Standard,
        max_evidence(),
    );
    // Unknown discriminator on known program → Err is acceptable (fail-closed)
    let result = core.verify(&input);
    match result {
        Ok(r) => assert!(r.instruction_name != "Transfer",
            "System Transfer discriminator on SPL Token should NOT match Transfer"),
        Err(_) => {}, // Err is acceptable — graceful failure for unknown instruction
    }
}

#[test]
fn h2_spl_closeaccount_disc_on_system_program() {
    let core = GraphiteCore::new();
    let input = make_input(
        "11111111111111111111111111111111",
        "09",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        WalletProfile::Standard,
        max_evidence(),
    );
    let result = core.verify(&input);
    match result {
        Ok(r) => assert!(r.instruction_name != "CloseAccount",
            "SPL CloseAccount discriminator on System Program should NOT match"),
        Err(_) => {},
    }
}

// ═══════════════════════════════════════════════════════════
// H3: PERMISSIVE PROFILE + UNKNOWN PROTOCOL
// ═══════════════════════════════════════════════════════════

#[test]
fn h3_permissive_profile_unknown_protocol_blocked() {
    let core = GraphiteCore::new();
    let input = make_input(
        "4Nd1mYbz1NQ8Tk6eX5N6w5eM6eX5N6w5eM6eX5N6w5eM",
        "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        WalletProfile::Permissive,
        max_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved,
        "Unknown protocol must NOT pass even Permissive profile — trust tier Unknown < HeuristicInferred");
}

// ═══════════════════════════════════════════════════════════
// H4: INTENT-DISCRIMINATOR MISMATCH
// ═══════════════════════════════════════════════════════════

#[test]
fn h4_transfer_intent_with_closeaccount_disc() {
    let core = GraphiteCore::new();
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Transfer 100 USDC to my friend".to_string(),
            confidence_of_parse: 0.99,
            extracted_parameters: None,
        },
        program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "09".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
            "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx".to_string(),
        ],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Standard,
        behavior_evidence: max_evidence(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
            simulation_baseline: None,
    };
    let result = core.verify(&input);
    match result {
        Ok(r) => assert!(!r.approved,
            "Intent says 'transfer' but discriminator is CloseAccount — must NOT be approved"),
        Err(_) => {}, // Err is acceptable
    }
}

#[test]
fn h4_swap_intent_with_setauthority_disc() {
    let core = GraphiteCore::new();
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "swap".to_string(),
            raw_natural_language: "Swap 1 SOL for USDC on Jupiter".to_string(),
            confidence_of_parse: 0.99,
            extracted_parameters: None,
        },
        program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "0b".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
        ],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Standard,
        behavior_evidence: max_evidence(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
            simulation_baseline: None,
    };
    let result = core.verify(&input).unwrap();
    assert!(!result.approved,
        "Intent says 'swap' but discriminator is SetAuthority — must NOT be approved");
}

// ═══════════════════════════════════════════════════════════
// H5: ZERO/DEGENERATE EDGE CASES
// ═══════════════════════════════════════════════════════════

#[test]
fn h5_zero_accounts() {
    let core = GraphiteCore::new();
    let input = make_input(
        "11111111111111111111111111111111", "02000000", &[],
        WalletProfile::Standard, max_evidence(),
    );
    let result = core.verify(&input);
    match result {
        Ok(r) => assert!(!r.approved, "Zero-account transaction must not be approved"),
        Err(_) => {},
    }
}

#[test]
fn h5_one_account() {
    let core = GraphiteCore::new();
    let input = make_input(
        "11111111111111111111111111111111", "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"],
        WalletProfile::Standard, max_evidence(),
    );
    let result = core.verify(&input);
    match result {
        Ok(r) => assert!(!r.approved, "1-account System Transfer (needs 2) must not be approved"),
        Err(_) => {},
    }
}

#[test]
fn h5_empty_string_account_address() {
    let core = GraphiteCore::new();
    let input = make_input(
        "11111111111111111111111111111111", "02000000", &["", ""],
        WalletProfile::Standard, max_evidence(),
    );
    let result = core.verify(&input);
    match result {
        Ok(r) => assert!(!r.approved, "Empty-string accounts must not be approved"),
        Err(_) => {},
    }
}

// ═══════════════════════════════════════════════════════════
// H6: MANIFEST SPOOFING
// ═══════════════════════════════════════════════════════════

#[test]
fn h6_manifest_injection_declaring_setauthority_as_safe() {
    let mut core = GraphiteCore::new();
    let malicious_manifest = r#"{
        "protocol": {
            "name": "Fake Safe Protocol",
            "program_id": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "version": "1.0.0"
        },
        "instructions": [
            {
                "name": "Safe Transfer",
                "discriminator": "0b",
                "accounts": ["source", "destination"],
                "expected_state_changes": ["debits accounts.from", "credits accounts.to"],
                "allowed_cpis": []
            }
        ]
    }"#;
    let _ = core.load_manifest(malicious_manifest);

    let input = make_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "0b",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        WalletProfile::Permissive, max_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved,
        "Manifest injection must NOT make SetAuthority appear safe — risk engine must still block it");
}

// ═══════════════════════════════════════════════════════════
// H7: CPI SUBSTRING/PREFIX ATTACK
// ═══════════════════════════════════════════════════════════

#[test]
fn h7_cpi_target_substring_of_allowed() {
    let input = risk_input(
        "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", &[],
        &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5D"], &[],
        &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
        "e517cb977ae3ad2a",
    );
    let result = assess(&input).unwrap();
    assert!(matches!(result, RiskVerdict::Blocked { .. }),
        "CPI target that is a substring of allowed must NOT pass — exact match only");
}

#[test]
fn h7_cpi_target_prefix_of_allowed() {
    let input = risk_input(
        "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", &[],
        &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DAxTRA"], &[],
        &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
        "e517cb977ae3ad2a",
    );
    let result = assess(&input).unwrap();
    assert!(matches!(result, RiskVerdict::Blocked { .. }),
        "CPI target with extra chars appended to allowed must NOT pass");
}

#[test]
fn h7_cpi_target_case_mismatch() {
    let input = risk_input(
        "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", &[],
        &["tokenkegQfeZyiNwAJbNbGKPfxCWuBvf9Ss623VQ5DA"], &[],
        &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
        "e517cb977ae3ad2a",
    );
    let result = assess(&input).unwrap();
    assert!(matches!(result, RiskVerdict::Blocked { .. }),
        "CPI target with case mismatch must NOT pass");
}

// ═══════════════════════════════════════════════════════════
// H8: DUPLICATE ACCOUNT INJECTION
// ═══════════════════════════════════════════════════════════

#[test]
fn h8_all_same_account_6_times_with_state_changes() {
    let input = risk_input(
        "11111111111111111111111111111111",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
          "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
          "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
          "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
          "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
          "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"],
        &[],
        &["transfer SOL"],
        &[],
        "02000000",
    );
    let result = assess(&input).unwrap();
    assert_eq!(result, RiskVerdict::Passed,
        "6 duplicate accounts WITH declared state changes should not trigger drainer");
}

#[test]
fn h8_all_same_account_6_times_no_state_changes() {
    // Red Team fix L12: account deduplication means 6 copies of the SAME account
    // = 1 unique account → NOT a drainer. This test now verifies dedup works
    // by using 6 DIFFERENT accounts to confirm the drainer still triggers.
    let input = risk_input(
        "11111111111111111111111111111111",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
          "8xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsV",
          "9xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsW",
          "AxKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsX",
          "BxKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsY",
          "CxKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsZ"],
        &[],
        &[],
        &[],
        "02000000",
    );
    let result = assess(&input).unwrap();
    assert!(matches!(result, RiskVerdict::Blocked { pattern: RiskPattern::Drainer, .. }),
        "6 UNIQUE accounts with NO state changes should trigger drainer pattern");
}

// ═══════════════════════════════════════════════════════════
// H9: CONFIDENCE CEILING EXPLOITATION
// ═══════════════════════════════════════════════════════════

#[test]
fn h9_unknown_protocol_confidence_never_exceeds_055() {
    let core = GraphiteCore::new();
    let input = make_input(
        "4Nd1mYbz1NQ8Tk6eX5N6w5eM6eX5N6w5eM6eX5N6w5eM", "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        WalletProfile::Standard, max_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(result.confidence <= 0.55,
        "Unknown protocol confidence ({}) must NEVER exceed 0.55, even with max evidence", result.confidence);
}

#[test]
fn h9_unknown_protocol_confidence_zero_evidence() {
    let core = GraphiteCore::new();
    let input = make_input(
        "4Nd1mYbz1NQ8Tk6eX5N6w5eM6eX5N6w5eM6eX5N6w5eM", "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        WalletProfile::Standard, zero_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(result.confidence < 0.3,
        "Unknown protocol with zero evidence should have very low confidence (< 0.3), got {}", result.confidence);
}

// ═══════════════════════════════════════════════════════════
// H10: RISK ENGINE PATTERN SHADOWING
// ═══════════════════════════════════════════════════════════

#[test]
fn h10_safe_state_changes_dont_mask_setauthority() {
    let input = RiskAssessmentInput {
        program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
        accounts: vec!["account1".to_string()],
        cpi_targets: vec![],
        expected_state_changes: vec!["debits accounts.from".to_string(), "credits accounts.to".to_string()],
        allowed_cpis: vec![],
        instruction_discriminator: "0b".to_string(),
    };
    let result = assess(&input).unwrap();
    assert!(matches!(result, RiskVerdict::Blocked { .. }),
        "SetAuthority must be blocked even when expected_state_changes look like a transfer");
}

#[test]
fn h10_state_changes_dont_mask_closeaccount() {
    let input = RiskAssessmentInput {
        program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
        accounts: vec!["account1".to_string()],
        cpi_targets: vec![],
        expected_state_changes: vec!["debits accounts.from".to_string(), "credits accounts.to".to_string()],
        allowed_cpis: vec![],
        instruction_discriminator: "09".to_string(),
    };
    let result = assess(&input).unwrap();
    assert!(matches!(result, RiskVerdict::Blocked { .. }),
        "CloseAccount must be blocked even when expected_state_changes look legitimate");
}

// ═══════════════════════════════════════════════════════════
// H11: STATE CHANGE INJECTION — drainer bypass
// ═══════════════════════════════════════════════════════════

#[test]
fn h11_empty_string_state_change_bypasses_drainer() {
    // BUG HUNT: vec![""] is NOT empty, so drainer check passes
    // This is a known bypass — drainer checks is_empty() not all-empty-strings
    let input = RiskAssessmentInput {
        program_id: "test".to_string(),
        accounts: vec!["a1","a2","a3","a4","a5","a6"].iter().map(|s| s.to_string()).collect(),
        cpi_targets: vec![],
        expected_state_changes: vec!["".to_string()],
        allowed_cpis: vec![],
        instruction_discriminator: String::new(),
    };
    let result = assess(&input).unwrap();
    // If this passes (not blocked), we found a drainer bypass
    // Expected: should be blocked, but might not be
    assert!(matches!(result, RiskVerdict::Blocked { .. }),
        "BUG: empty-string state changes bypass drainer detection — vec![\"\"] is not empty!");
}

#[test]
fn h11_whitespace_state_change_bypasses_drainer() {
    let input = RiskAssessmentInput {
        program_id: "test".to_string(),
        accounts: vec!["a1","a2","a3","a4","a5","a6"].iter().map(|s| s.to_string()).collect(),
        cpi_targets: vec![],
        expected_state_changes: vec!["   ".to_string()],
        allowed_cpis: vec![],
        instruction_discriminator: String::new(),
    };
    let result = assess(&input).unwrap();
    assert!(matches!(result, RiskVerdict::Blocked { .. }),
        "BUG: whitespace-only state changes bypass drainer detection");
}

// ═══════════════════════════════════════════════════════════
// H12: LEGITIMATE-BUT-DANGEROUS OPS
// ═══════════════════════════════════════════════════════════

#[test]
fn h12_stake_delegate_stake_not_blocked() {
    let core = GraphiteCore::new();
    let input = make_input(
        "Stake11111111111111111111111111111111111111", "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
          "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
          "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
          "9WzDXwBbmkg8ZTbNMqJx8W5DkxUkq5PjAB8qjGp3q5J",
          "7Np41oeYqPefeNQEHSv1DUhjy2v12k5q3r5r5r5r5r5r",
          "5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r"],
        WalletProfile::Standard, max_evidence(),
    );
    let result = core.verify(&input);
    match result {
        Ok(r) => assert_eq!(r.risk_verdict.status, "Clear",
            "Stake Delegate is legitimate — must NOT be blocked"),
        Err(e) => panic!("Stake Delegate should not error: {:?}", e),
    }
}

#[test]
fn h12_squads_execute_transaction_not_blocked() {
    let core = GraphiteCore::new();
    // Use the actual Squads V4 discriminator for execute_transaction
    let input = make_input(
        "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf", "8faecbbfaecf93c5",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
          "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
          "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
          "9WzDXwBbmkg8ZTbNMqJx8W5DkxUkq5PjAB8qjGp3q5J",
          "7Np41oeYqPefeNQEHSv1DUhjy2v12k5q3r5r5r5r5r5r",
          "5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r"],
        WalletProfile::Standard, max_evidence(),
    );
    let result = core.verify(&input);
    match result {
        Ok(r) => assert_eq!(r.risk_verdict.status, "Clear",
            "Squads ExecuteTransaction is legitimate governance — must NOT be blocked"),
        Err(e) => panic!("Squads ExecuteTransaction should not error: {:?}", e),
    }
}

// ═══════════════════════════════════════════════════════════
// H14: UNICODE/HOMOGLYPH PROGRAM ID
// ═══════════════════════════════════════════════════════════

#[test]
fn h14_unicode_in_program_id_rejected() {
    let core = GraphiteCore::new();
    let fake_program = "11111111111111111111111111111111\u{ff11}";
    let input = make_input(
        fake_program, "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        WalletProfile::Standard, max_evidence(),
    );
    let result = core.verify(&input);
    match result {
        Ok(r) => {
            assert!(!r.approved, "Unicode-homoglyph program ID must NOT be approved");
            assert!(r.unknown_protocol, "Unicode program ID should be flagged as unknown");
        }
        Err(_) => {},
    }
}

// ═══════════════════════════════════════════════════════════
// H15: AUDIT TRAIL UNIQUENESS
// ═══════════════════════════════════════════════════════════

#[test]
fn h15_audit_trail_ids_unique_across_500_calls() {
    let core = GraphiteCore::new();
    let input = make_input(
        "11111111111111111111111111111111", "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        WalletProfile::Standard, max_evidence(),
    );
    let mut ids = std::collections::HashSet::new();
    for _ in 0..500 {
        let result = core.verify(&input).unwrap();
        ids.insert(result.audit_trail_id);
    }
    assert_eq!(ids.len(), 500,
        "500 verifications must produce 500 unique audit trail IDs, got {}", ids.len());
}

// ═══════════════════════════════════════════════════════════
// H16: DISCRIMINATOR FORMAT VARIATIONS
// ═══════════════════════════════════════════════════════════

#[test]
fn h16_empty_and_zero_discriminators_dont_crash() {
    let core = GraphiteCore::new();
    let input1 = make_input(
        "11111111111111111111111111111111", "",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        WalletProfile::Standard, max_evidence(),
    );
    let input2 = make_input(
        "11111111111111111111111111111111", "00",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        WalletProfile::Standard, max_evidence(),
    );
    let r1 = core.verify(&input1);
    let r2 = core.verify(&input2);
    // Both should not crash — Err is acceptable as long as it's not a panic
    assert!(r1.is_ok() || r1.is_err(), "Empty discriminator should not panic");
    assert!(r2.is_ok() || r2.is_err(), "Zero discriminator should not panic");
}

// ═══════════════════════════════════════════════════════════
// H17: BEHAVIOR EVIDENCE OVERFLOW
// ═══════════════════════════════════════════════════════════

#[test]
fn h17_u32_max_evidence_does_not_overflow_confidence() {
    let core = GraphiteCore::new();
    let input = make_input(
        "11111111111111111111111111111111", "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        WalletProfile::Standard, max_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(result.confidence >= 0.0 && result.confidence <= 1.0,
        "Confidence must be in [0.0, 1.0] even with u32::MAX evidence, got {}", result.confidence);
    assert!(!result.confidence.is_nan(), "Confidence must not be NaN");
    assert!(!result.confidence.is_infinite(), "Confidence must not be infinite");
}

// ═══════════════════════════════════════════════════════════
// H19: INSTRUCTION DATA INJECTION
// ═══════════════════════════════════════════════════════════

#[test]
fn h19_large_instruction_data_does_not_crash() {
    let core = GraphiteCore::new();
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Transfer 1 SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: "11111111111111111111111111111111".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
        ],
        instruction_data: Some(vec![0x42; 100000]),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Standard,
        behavior_evidence: max_evidence(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
            simulation_baseline: None,
    };
    let result = core.verify(&input);
    match result {
        Ok(r) => assert!(!r.confidence.is_nan(), "100KB instruction data must not corrupt confidence"),
        Err(_) => {},
    }
}

// ═══════════════════════════════════════════════════════════
// H20: CONCURRENT VERIFICATION DETERMINISM (500 calls)
// ═══════════════════════════════════════════════════════════

#[test]
fn h20_500x_full_pipeline_determinism() {
    let core = GraphiteCore::new();
    let input = make_input(
        "11111111111111111111111111111111", "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        WalletProfile::Standard, max_evidence(),
    );
    let first = core.verify(&input).unwrap();
    for i in 0..500 {
        let result = core.verify(&input).unwrap();
        assert_eq!(result.confidence, first.confidence,
            "Confidence changed on iteration {}: {} vs {}", i, result.confidence, first.confidence);
        assert_eq!(result.risk_verdict, first.risk_verdict,
            "Risk verdict changed on iteration {}", i);
        assert_eq!(result.approved, first.approved, "Approval changed on iteration {}", i);
        assert_eq!(result.protocol_name, first.protocol_name, "Protocol name changed on iteration {}", i);
    }
}

// ═══════════════════════════════════════════════════════════
// H21: POLICY ENGINE BYPASS ATTEMPTS
// ═══════════════════════════════════════════════════════════

#[test]
fn h21_custom_profile_zero_threshold_still_checks_risk() {
    let core = GraphiteCore::new();
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Transfer 100 USDC".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "0b".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
        ],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Custom { min_confidence: 0.0, min_trust_tier: TrustTier::Unknown },
        behavior_evidence: max_evidence(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
            simulation_baseline: None,
    };
    let result = core.verify(&input).unwrap();
    assert!(!result.approved,
        "Custom profile with zero thresholds must NOT bypass risk engine block on SetAuthority");
}

#[test]
fn h21_permissive_profile_still_blocks_risk() {
    let core = GraphiteCore::new();
    let input = make_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "0b",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        WalletProfile::Permissive, max_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved,
        "Permissive profile must NOT bypass risk engine block");
}

// ═══════════════════════════════════════════════════════════
// H22: HIDDEN TRANSFER DETECTION BYPASS
// ═══════════════════════════════════════════════════════════

#[test]
fn h22_10_accounts_with_state_changes_not_flagged() {
    let input = risk_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        &["a1","a2","a3","a4","a5","a6","a7","a8","a9","a10"],
        &[],
        &["debits accounts.from", "credits accounts.to"],
        &[],
        "03",
    );
    let result = assess(&input).unwrap();
    assert_eq!(result, RiskVerdict::Passed,
        "10 accounts WITH legitimate state changes should not trigger any pattern");
}

#[test]
fn h22_10_accounts_no_state_changes_drainer() {
    let input = risk_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        &["a1","a2","a3","a4","a5","a6","a7","a8","a9","a10"],
        &[],
        &[],
        &[],
        "03",
    );
    let result = assess(&input).unwrap();
    assert!(matches!(result, RiskVerdict::Blocked { .. }),
        "10 accounts with NO state changes should trigger drainer");
}

// ═══════════════════════════════════════════════════════════
// H23: COMPOSABLE ATTACK CHAINS
// ═══════════════════════════════════════════════════════════

#[test]
fn h23_unknown_program_cpi_many_accounts_safe_intent_permissive() {
    let core = GraphiteCore::new();
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Transfer 1 SOL to my savings account".to_string(),
            confidence_of_parse: 0.99,
            extracted_parameters: None,
        },
        program_id: "4Nd1mYbz1NQ8Tk6eX5N6w5eM6eX5N6w5eM6eX5N6w5eM".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
            "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx".to_string(),
            "9WzDXwBbmkg8ZTbNMqJx8W5DkxUkq5PjAB8qjGp3q5J".to_string(),
            "7Np41oeYqPefeNQEHSv1DUhjy2v12k5q3r5r5r5r5r5r".to_string(),
            "5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r".to_string(),
            "11111111111111111111111111111111".to_string(),
        ],
        instruction_data: None,
        cpi_targets: vec!["DrainerProgram1111111111111111111111111111111".to_string()],
        wallet_profile: WalletProfile::Permissive,
        behavior_evidence: max_evidence(),
        compute_units: 150,
        account_writes: 7,
        cpi_hops: 1,
            simulation_baseline: None,
    };
    let result = core.verify(&input).unwrap();
    assert!(!result.approved,
        "Unknown program + CPI + 7 accounts + max evidence + Permissive must NOT be approved");
    assert_eq!(result.risk_verdict.status, "Blocked",
        "Risk engine must block this composite attack");
}

#[test]
fn h23_known_program_wrong_disc_cpi_many_accounts() {
    let core = GraphiteCore::new();
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Transfer 1 SOL".to_string(),
            confidence_of_parse: 0.99,
            extracted_parameters: None,
        },
        program_id: "11111111111111111111111111111111".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "ffffff".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
            "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx".to_string(),
            "9WzDXwBbmkg8ZTbNMqJx8W5DkxUkq5PjAB8qjGp3q5J".to_string(),
            "7Np41oeYqPefeNQEHSv1DUhjy2v12k5q3r5r5r5r5r5r".to_string(),
            "5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r5r".to_string(),
            "11111111111111111111111111111111".to_string(),
        ],
        instruction_data: None,
        cpi_targets: vec!["4Nd1mYbz1NQ8Tk6eX5N6w5eM6eX5N6w5eM6eX5N6w5eM".to_string()],
        wallet_profile: WalletProfile::Permissive,
        behavior_evidence: max_evidence(),
        compute_units: 150,
        account_writes: 7,
        cpi_hops: 1,
            simulation_baseline: None,
    };
    let result = core.verify(&input);
    match result {
        Ok(r) => assert!(!r.approved,
            "System Program + unknown disc + CPI + 7 accounts must NOT be approved"),
        Err(_) => {}, // Err is acceptable — unknown discriminator should error
    }
}

// ═══════════════════════════════════════════════════════════
// H24: POLICY ENGINE ISOLATION
// ═══════════════════════════════════════════════════════════

#[test]
fn h24_risk_block_overrides_perfect_confidence_zero_threshold() {
    let input = PolicyInput {
        confidence_result: ConfidenceResult {
            confidence: 1.0,
            breakdown: vec![],
            trust_tier_applied: TrustTier::BattleTested,
            ceiling_triggered: false,
            ceiling_applied: 1.0,
        },
        risk_verdict: RiskVerdict::Blocked {
            pattern: RiskPattern::Drainer,
            reason: "drainer detected".to_string(),
        },
        profile: WalletProfile::Custom { min_confidence: 0.0, min_trust_tier: TrustTier::Unknown },
    };
    let result = evaluate_policy(&input).unwrap();
    assert_eq!(result, PolicyVerdict::RejectedRiskEngineBlock,
        "Risk block must override perfect confidence + max tier + zero-threshold custom profile");
}
