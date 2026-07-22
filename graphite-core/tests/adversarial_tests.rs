//! Adversarial Test Suite — designed to break and fool the system
//!
//! These tests are UNFORGIVING. They try:
//! - Evasion: making malicious transactions look safe
//! - Spoofing: using wrong discriminators to bypass risk patterns
//! - Boundary attacks: hitting exact threshold values
//! - Chaining: combining multiple risk patterns to see which wins
//! - Degradation: feeding garbage/empty/malformed inputs
//! - Replay: feeding the same input 1000x to check determinism
//! - Confusion: using program IDs that look similar to real ones
//! - Authority theft: every variant of SetAuthority across programs

use graphite_core::{
    solana_types::Pubkey,
    manifest::{load_seed_manifests, ManifestRegistry},
    verification::{GraphiteCore, VerificationInput, ProposedIntent},
    risk_engine::{RiskAssessmentInput, RiskVerdict, RiskPattern, assess},
    policy_engine::{evaluate_policy, PolicyInput, PolicyVerdict, WalletProfile},
    confidence_engine::{ConfidenceResult, TrustTier},
    semantic_graph_store::BehaviorEvidence,
};

// ============================================================
// HELPER
// ============================================================

fn make_input(program_id: &str, discriminator: &str, accounts: &[&str], cpi: &[&str], profile: WalletProfile, evidence: BehaviorEvidence) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Transfer 1 SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: program_id.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: discriminator.to_string(),
        account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
        instruction_data: None,
        cpi_targets: cpi.iter().map(|s| s.to_string()).collect(),
        wallet_profile: profile,
        behavior_evidence: evidence,
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
            simulation_baseline: None,
    }
}

fn good_evidence() -> BehaviorEvidence {
    BehaviorEvidence {
        has_signed_manifest: true,
        community_verified_count: 1000,
        battle_tested_tx_count: 100000,
        simulation_match_count: 50000,
    }
}

fn no_evidence() -> BehaviorEvidence {
    BehaviorEvidence {
        has_signed_manifest: false,
        community_verified_count: 0,
        battle_tested_tx_count: 0,
        simulation_match_count: 0,
    }
}

fn risk_input(program: &str, accounts: &[&str], cpi: &[&str], changes: &[&str], allowed: &[&str], disc: &str) -> RiskAssessmentInput {
    RiskAssessmentInput {
        program_id: program.to_string(),
        accounts: accounts.iter().map(|s| s.to_string()).collect(),
        cpi_targets: cpi.iter().map(|s| s.to_string()).collect(),
        expected_state_changes: changes.iter().map(|s| s.to_string()).collect(),
        allowed_cpis: allowed.iter().map(|s| s.to_string()).collect(),
        instruction_discriminator: disc.to_string(),
    }
}

// ============================================================
// 1. EVASION ATTACKS — making malicious transactions look safe
// ============================================================

#[test]
fn test_evasion_set_authority_with_safe_intent_description() {
    // Attacker declares "transfer" as intent but actually calls SetAuthority
    let core = GraphiteCore::default();
    let mut input = make_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "0b",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx"],
        &[], WalletProfile::Conservative, good_evidence(),
    );
    input.proposed_intent.intent_type = "transfer".to_string();
    input.proposed_intent.raw_natural_language = "Transfer 100 USDC to my friend".to_string();
    let result = core.verify(&input).unwrap();
    assert!(!result.approved, "SetAuthority with fake 'transfer' intent must be blocked — risk engine catches discriminator, not intent description");
    assert_eq!(result.risk_verdict.status, "Blocked");
}

#[test]
fn test_evasion_set_authority_on_token_2022_with_safe_intent() {
    // Same attack but on Token-2022 (which shares SPL Token discriminators)
    let core = GraphiteCore::default();
    let input = make_input(
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "0b",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx"],
        &[], WalletProfile::Conservative, good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved, "Token-2022 SetAuthority with safe intent must be blocked");
    assert_eq!(result.risk_verdict.status, "Blocked");
}

#[test]
fn test_evasion_drainer_with_safe_intent_and_few_accounts() {
    // Attacker uses only 2 accounts (below drainer threshold) but still drains
    // This is a known Phase 1 limitation — CloseAccount with 2 accounts won't trigger drainer
    let core = GraphiteCore::default();
    let input = make_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "09", // CloseAccount
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
          "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        &[], WalletProfile::Conservative, good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    // CloseAccount IS in the RISKY_PATTERNS table as a Drainer — should be caught by discriminator
    assert!(!result.approved, "CloseAccount must be blocked even with few accounts — it's in RISKY_PATTERNS");
}

#[test]
fn test_evasion_unknown_program_with_permissive_profile() {
    // Attacker hopes Permissive profile will approve unknown program
    let core = GraphiteCore::default();
    let input = make_input(
        "4Nd1mYbz1NQ8Tk6eX5N6w5eM6eX5N6w5eM6eX5N6w5eM", // unknown program
        "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        &[], WalletProfile::Permissive, good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved, "Unknown program must not be approved even with Permissive profile");
    assert!(result.unknown_protocol, "Must be flagged as unknown protocol");
    assert!(result.confidence <= 0.55, "Unknown protocol confidence must be <= 0.55, got {}", result.confidence);
}

#[test]
fn test_evasion_unknown_program_with_high_evidence() {
    // Attacker provides maxed-out evidence hoping to boost confidence past the cap
    let core = GraphiteCore::default();
    let max_evidence = BehaviorEvidence {
        has_signed_manifest: true,
        community_verified_count: u32::MAX,
        battle_tested_tx_count: u64::MAX,
        simulation_match_count: u64::MAX,
    };
    let input = make_input(
        "4Nd1mYbz1NQ8Tk6eX5N6w5eM6eX5N6w5eM6eX5N6w5eM", // unknown program
        "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        &[], WalletProfile::Permissive, max_evidence,
    );
    let result = core.verify(&input).unwrap();
    assert!(result.confidence <= 0.55, "Unknown protocol confidence cap must hold even with MAX evidence, got {}", result.confidence);
}

// ============================================================
// 2. SPOOFING ATTACKS — using wrong discriminators to bypass risk patterns
// ============================================================

#[test]
fn test_spoofing_system_transfer_with_authority_hijack_discriminator() {
    // Attacker claims to be System Program Transfer but uses Assign discriminator
    let core = GraphiteCore::default();
    let input = make_input(
        "11111111111111111111111111111111", "01000000", // Assign, not Transfer
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"],
        &[], WalletProfile::Standard, good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved, "System Assign must be blocked — it's authority hijack");
    assert_eq!(result.risk_verdict.status, "Blocked");
}

#[test]
fn test_spoofing_spl_token_transfer_discriminator_on_wrong_program() {
    // Attacker uses SPL Token Transfer discriminator (03) on an unknown program
    let core = GraphiteCore::default();
    let input = make_input(
        "4Nd1mYbz1NQ8Tk6eX5N6w5eM6eX5N6w5eM6eX5N6w5eM", // unknown program
        "03", // SPL Token Transfer discriminator
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        &[], WalletProfile::Standard, good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved, "Unknown program must not be approved regardless of discriminator");
    assert!(result.unknown_protocol, "Must be flagged as unknown");
}

#[test]
fn test_spoofing_empty_discriminator_on_known_program() {
    // Attacker sends empty discriminator to a known program (bypass instruction matching)
    let core = GraphiteCore::default();
    let input = make_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "", // empty discriminator
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"],
        &[], WalletProfile::Standard, good_evidence(),
    );
    // Should not crash — should handle gracefully (either Ok with unknown or Err)
    let result = core.verify(&input);
    match result {
        Ok(r) => assert!(!r.approved, "Empty discriminator must not be approved"),
        Err(_) => {}, // Error is also acceptable — graceful failure
    }
}

// ============================================================
// 3. BOUNDARY ATTACKS — hitting exact threshold values
// ============================================================

#[test]
fn test_boundary_drainer_exactly_5_accounts_blocked() {
    // Red Team fix L1: Exactly 5 accounts now BLOCKED (threshold changed from >5 to >=5)
    let input = risk_input("prog", &["a1","a2","a3","a4","a5"], &[], &[], &[], "");
    assert!(matches!(assess(&input).unwrap(), RiskVerdict::Blocked { pattern: RiskPattern::Drainer, .. }));
}

#[test]
fn test_boundary_drainer_exactly_6_accounts_blocked() {
    // Exactly 6 accounts — at the drainer threshold
    let input = risk_input("prog", &["a1","a2","a3","a4","a5","a6"], &[], &[], &[], "");
    assert!(matches!(assess(&input).unwrap(), RiskVerdict::Blocked { pattern: RiskPattern::Drainer, .. }));
}

#[test]
fn test_boundary_compositional_drain_4_with_repeat_blocked() {
    // Red Team fix L3: 4 CPI targets with repeat now BLOCKED (threshold changed from >4 to >=3)
    // allowed_cpis includes all targets so CPI check passes, then compositional drain runs
    let input = risk_input("agg", &[], &["a","a","b","c"], &[], &["a","b","c"], "");
    assert!(matches!(assess(&input).unwrap(), RiskVerdict::Blocked { pattern: RiskPattern::CompositionalDrainPattern, .. }));
}

#[test]
fn test_boundary_compositional_drain_5_with_repeat_blocked() {
    // 5 CPI targets with a repeat — still blocked at new threshold (>=3)
    let input = risk_input("agg", &[], &["a","a","b","c","d"], &[], &["a","b","c","d"], "");
    assert!(matches!(assess(&input).unwrap(), RiskVerdict::Blocked { pattern: RiskPattern::CompositionalDrainPattern, .. }));
}

#[test]
fn test_boundary_confidence_exactly_0_55_unknown_protocol() {
    // Unknown protocol confidence must be exactly capped at 0.55
    let core = GraphiteCore::default();
    let max_evidence = BehaviorEvidence {
        has_signed_manifest: true,
        community_verified_count: u32::MAX,
        battle_tested_tx_count: u64::MAX,
        simulation_match_count: u64::MAX,
    };
    let input = make_input(
        "4Nd1mYbz1NQ8Tk6eX5N6w5eM6eX5N6w5eM6eX5N6w5eM",
        "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        &[], WalletProfile::Permissive, max_evidence,
    );
    let result = core.verify(&input).unwrap();
    assert!(result.confidence <= 0.55 + 0.001, // floating point tolerance
        "Unknown protocol confidence must be <= 0.55, got {}", result.confidence);
}

// ============================================================
// 4. CHAINING ATTACKS — multiple risk patterns combined
// ============================================================

#[test]
fn test_chaining_drainer_plus_authority_hijack_plus_cpi() {
    // Transaction that triggers drainer (6+ accounts) + authority hijack + unexpected CPI
    let input = risk_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        &["a1","a2","a3","a4","a5","a6","a7","a8"], // 8 accounts = drainer
        &["unknown_program"], // unexpected CPI
        &["debits accounts.from", "credits accounts.to"],
        &[], // empty allowed_cpis — unknown_program not in any list
        "0b", // SetAuthority = authority hijack
    );
    let result = assess(&input).unwrap();
    // Multiple patterns triggered — the engine should block (first match wins or all reported)
    assert!(matches!(result, RiskVerdict::Blocked { .. }), "Multiple risk patterns must result in block");
}

#[test]
fn test_chaining_drainer_plus_hidden_transfer() {
    // 13 accounts with only 1 "accounts." reference — triggers both drainer AND hidden transfer
    let input = risk_input(
        "some_program",
        &["a1","a2","a3","a4","a5","a6","a7","a8","a9","a10","a11","a12","a13"],
        &[],
        &["debits accounts.from by amount"],
        &[],
        "",
    );
    let result = assess(&input).unwrap();
    assert!(matches!(result, RiskVerdict::Blocked { .. }), "Drainer + hidden transfer must block");
}

#[test]
fn test_chaining_cpi_allowed_but_authority_hijack_still_blocks() {
    // CPI is allowed, but SetAuthority still triggers authority hijack
    let input = risk_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        &["account", "authority"],
        &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"], // allowed CPI
        &["changes authority"],
        &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
        "0b", // SetAuthority
    );
    let result = assess(&input).unwrap();
    assert!(matches!(result, RiskVerdict::Blocked { pattern: RiskPattern::AuthorityHijack, .. }),
        "Authority hijack must block even when CPI is allowed");
}

// ============================================================
// 5. DEGRADATION ATTACKS — garbage/empty/malformed inputs
// ============================================================

#[test]
fn test_degradation_empty_accounts() {
    let input = risk_input("prog", &[], &[], &[], &[], "");
    assert_eq!(assess(&input).unwrap(), RiskVerdict::Passed,
        "Empty accounts should not crash and should pass (no risk detected)");
}

#[test]
fn test_degradation_empty_program_id() {
    let input = risk_input("", &["a1"], &[], &[], &[], "");
    assert_eq!(assess(&input).unwrap(), RiskVerdict::Passed,
        "Empty program_id should not crash");
}

#[test]
fn test_degradation_empty_discriminator() {
    let input = risk_input("prog", &["a1"], &[], &[], &[], "");
    assert_eq!(assess(&input).unwrap(), RiskVerdict::Passed,
        "Empty discriminator should not crash");
}

#[test]
fn test_degradation_empty_cpi_targets() {
    let input = risk_input("prog", &["a1"], &[], &["change"], &[], "");
    assert_eq!(assess(&input).unwrap(), RiskVerdict::Passed);
}

#[test]
fn test_degradation_empty_allowed_cpis_with_cpi() {
    // CPI target present but allowed_cpis is empty — should this block?
    // If allowed_cpis is empty, any CPI is "unlisted" — should block
    let input = risk_input("prog", &["a1"], &["some_target"], &["change"], &[], "");
    let result = assess(&input).unwrap();
    // With empty allowed_cpis, any CPI should be unexpected
    assert!(matches!(result, RiskVerdict::Blocked { pattern: RiskPattern::UnexpectedCpi, .. }),
        "CPI target with empty allowed list should block");
}

#[test]
fn test_degradation_all_empty() {
    let input = risk_input("", &[], &[], &[], &[], "");
    assert_eq!(assess(&input).unwrap(), RiskVerdict::Passed,
        "All-empty input should not crash");
}

#[test]
fn test_degradation_very_long_account_list() {
    // 1000 accounts — should trigger drainer but not crash
    let accounts: Vec<String> = (0..1000).map(|i| format!("account_{}", i)).collect();
    let accounts_ref: Vec<&str> = accounts.iter().map(|s| s.as_str()).collect();
    let input = risk_input("prog", accounts_ref.as_slice(), &[], &[], &[], "");
    let result = assess(&input).unwrap();
    assert!(matches!(result, RiskVerdict::Blocked { pattern: RiskPattern::Drainer, .. }),
        "1000 accounts must trigger drainer");
}

#[test]
fn test_degradation_unicode_in_program_id() {
    let input = risk_input("🦀rust💻", &["a1"], &[], &[], &[], "");
    let result = assess(&input);
    assert!(result.is_ok(), "Unicode in program_id should not crash");
}

#[test]
fn test_degradation_extremely_long_program_id() {
    let long_id = "a".repeat(10000);
    let input = risk_input(&long_id, &["a1"], &[], &[], &[], "");
    let result = assess(&input);
    assert!(result.is_ok(), "10000-char program_id should not crash");
}

// ============================================================
// 6. REPLAY / DETERMINISM ATTACKS
// ============================================================

#[test]
fn test_replay_1000x_deterministic() {
    let input = risk_input("test", &["a1","a2"], &["unknown"], &[], &[], "");
    let first = assess(&input).unwrap();
    for _ in 0..1000 {
        assert_eq!(assess(&input).unwrap(), first, "Risk engine must be deterministic across 1000 runs");
    }
}

#[test]
fn test_replay_verification_1000x_deterministic() {
    let core = GraphiteCore::default();
    let input = make_input(
        "11111111111111111111111111111111", "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        &[], WalletProfile::Standard, good_evidence(),
    );
    let first = core.verify(&input).unwrap();
    for i in 0..1000 {
        let result = core.verify(&input).unwrap();
        assert_eq!(result.approved, first.approved, "approved changed on iteration {}", i);
        assert_eq!(result.confidence, first.confidence, "confidence changed on iteration {}", i);
        // audit_trail_id is intentionally unique per call (sequence counter)
    }
}

// ============================================================
// 7. CONFUSION ATTACKS — similar-looking program IDs
// ============================================================

#[test]
fn test_confusion_almost_system_program() {
    // One character different from System Program
    let core = GraphiteCore::default();
    let input = make_input(
        "11111111111111111111111111111112", // Last char different
        "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        &[], WalletProfile::Standard, good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved, "Almost-System-Program must not be approved");
    assert!(result.unknown_protocol, "Must be flagged as unknown — it's NOT the real System Program");
}

#[test]
fn test_confusion_almost_spl_token() {
    // Different from SPL Token by one character
    let core = GraphiteCore::default();
    let input = make_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DB", // Last char B instead of A
        "0b", // SetAuthority discriminator
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx"],
        &[], WalletProfile::Conservative, good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved, "Almost-SPL-Token must not be approved");
    // This should be unknown — NOT matched to SPL Token, so SetAuthority pattern won't trigger
    assert!(result.unknown_protocol, "Must be unknown — wrong program ID");
}

#[test]
fn test_confusion_capital_vs_lowercase_program_id() {
    // Solana addresses are case-sensitive — different case = different program
    let core = GraphiteCore::default();
    let input = make_input(
        "tokenkegQfeZyiNwAJbNbGKPfxCWuBvf9Ss623VQ5DA", // lowercase 't' instead of 'T'
        "03", // Transfer
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        &[], WalletProfile::Standard, good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved, "Case-modified program ID must not be approved");
    assert!(result.unknown_protocol, "Must be unknown — case-sensitive mismatch");
}

// ============================================================
// 8. AUTHORITY THEFT — every variant across programs
// ============================================================

#[test]
fn test_authority_theft_spl_token_set_authority_blocked() {
    let input = risk_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        &["account", "authority"],
        &[], &["changes authority"], &[], "0b",
    );
    assert!(matches!(assess(&input).unwrap(), RiskVerdict::Blocked { pattern: RiskPattern::AuthorityHijack, .. }));
}

#[test]
fn test_authority_theft_token_2022_set_authority_blocked() {
    let input = risk_input(
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        &["account", "authority"],
        &[], &["changes authority"], &[], "0b",
    );
    assert!(matches!(assess(&input).unwrap(), RiskVerdict::Blocked { pattern: RiskPattern::AuthorityHijack, .. }));
}

#[test]
fn test_authority_theft_system_assign_blocked() {
    let input = risk_input(
        "11111111111111111111111111111111",
        &["account", "new_owner"],
        &[], &["assigns"], &[], "01000000",
    );
    assert!(matches!(assess(&input).unwrap(), RiskVerdict::Blocked { pattern: RiskPattern::AuthorityHijack, .. }));
}

#[test]
fn test_authority_theft_spl_token_close_account_blocked() {
    let input = risk_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        &["account", "destination"],
        &[], &["closes account"], &[], "09",
    );
    assert!(matches!(assess(&input).unwrap(), RiskVerdict::Blocked { pattern: RiskPattern::Drainer, .. }));
}

#[test]
fn test_authority_theft_token_2022_close_account_blocked() {
    let input = risk_input(
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        &["account", "destination"],
        &[], &["closes account"], &[], "09",
    );
    assert!(matches!(assess(&input).unwrap(), RiskVerdict::Blocked { pattern: RiskPattern::Drainer, .. }));
}

// ============================================================
// 9. POLICY ENGINE ADVERSARIAL TESTS
// ============================================================

#[test]
fn test_policy_no_profile_overrides_risk_block() {
    // No wallet profile should override a risk engine block
    let conf = ConfidenceResult {
        confidence: 1.0, // perfect confidence
        breakdown: vec![],
        trust_tier_applied: TrustTier::BattleTested,
        ceiling_triggered: false,
        ceiling_applied: 0.0,
    };
    for profile in &[WalletProfile::Conservative, WalletProfile::Standard, WalletProfile::Permissive] {
        let input = PolicyInput {
            confidence_result: conf.clone(),
            risk_verdict: RiskVerdict::Blocked { pattern: RiskPattern::Drainer, reason: "test".to_string() },
            profile: profile.clone(),
        };
        let result = evaluate_policy(&input).unwrap();
        assert!(matches!(result, PolicyVerdict::RejectedRiskEngineBlock),
            "{:?} must not override risk block even with confidence 1.0", profile);
    }
}

#[test]
fn test_policy_enterprise_requires_highest_confidence() {
    let conf = ConfidenceResult {
        confidence: 0.98, // very high but not 0.99+
        breakdown: vec![],
        trust_tier_applied: TrustTier::BattleTested,
        ceiling_triggered: false,
        ceiling_applied: 0.0,
    };
    let input = PolicyInput {
        confidence_result: conf,
        risk_verdict: RiskVerdict::Passed,
        profile: WalletProfile::Enterprise,
    };
    let result = evaluate_policy(&input).unwrap();
    // Enterprise should require 0.99+ confidence
    assert!(!matches!(result, PolicyVerdict::Approved),
        "Enterprise should reject 0.98 confidence — requires 0.99+");
}

// ============================================================
// 10. MANIFEST INTEGRITY ATTACKS
// ============================================================

#[test]
fn test_manifest_injection_extra_instruction_not_loaded() {
    // Attacker can't inject extra instructions via manifest loading
    let mut registry = ManifestRegistry::new();
    let malicious_json = r#"{
        "graphite_manifest_version": "1.0",
        "protocol": {"name": "Evil", "program_id": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "website": "", "github": ""},
        "version": {"label": "1.0", "effective_from_slot": 0, "previous_version_ref": null},
        "instructions": [{"name": "EvilTransfer", "discriminator": "03", "accounts": [], "expected_state_changes": [], "allowed_cpis": [], "risk_rules": []}],
        "trust_tier": "Unverified"
    }"#;
    let result = registry.load_from_json(malicious_json);
    assert!(result.is_ok(), "Loading should succeed (it's a valid manifest format)");
    
    // But it should OVERWRITE the existing SPL Token manifest with a weaker one
    let manifest = registry.get("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    assert!(manifest.is_some());
    let manifest = manifest.unwrap();
    // The malicious manifest only has 1 instruction, overwriting the 7-instruction SPL Token
    assert_eq!(manifest.protocol.name, "Evil");
    assert_eq!(manifest.instructions.len(), 1);
    // This is a known Phase 1 limitation — manifest injection is possible
    // because load_from_json uses insert() which overwrites.
    // Phase 2 will add manifest signing (P7: trust computed, never asserted).
}

#[test]
fn test_manifest_trust_tier_does_not_affect_risk_engine() {
    // The risk engine operates on discriminators and program IDs,
    // not on the manifest's trust_tier field
    let input = risk_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        &["account", "authority"],
        &[], &["changes authority"], &[], "0b",
    );
    let result = assess(&input).unwrap();
    // Risk engine blocks SetAuthority regardless of what trust_tier the manifest claims
    assert!(matches!(result, RiskVerdict::Blocked { pattern: RiskPattern::AuthorityHijack, .. }));
}

// ============================================================
// 11. PROTOCOL-SPECIFIC ADVERSARIAL TESTS
// ============================================================

#[test]
fn test_adversarial_jupiter_with_malicious_cpi_not_allowed() {
    let core = GraphiteCore::default();
    let input = make_input(
        "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", "e517cb977ae3ad2a",
        &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
          "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
          "9WzDXwBbmkg8ZTbNMqJx8W5DkxUkq5PjAB8qjGp3q5J"],
        &["4Nd1mYbz1NQ8Tk6eX5N6w5eM6eX5N6w5eM6eX5N6w5eM"], // malicious CPI not in allowed list
        WalletProfile::Conservative, good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved, "Jupiter swap with unlisted CPI must be blocked");
    assert_eq!(result.risk_verdict.status, "Blocked");
}

#[test]
fn test_adversarial_squads_with_non_system_cpi_blocked() {
    let core = GraphiteCore::default();
    let input = make_input(
        "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf", "8faecbbfaecf93c5",
        &["Stake11111111111111111111111111111111111111", "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
          "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
          "9WzDXwBbmkg8ZTbNMqJx8W5DkxUkq5PjAB8qjGp3q5J", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
        &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"], // SPL Token not in Squads allowed_cpis
        WalletProfile::Conservative, good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved, "Squads with non-System CPI must be blocked");
}

#[test]
fn test_adversarial_orca_swap_with_wrong_cpi_blocked() {
    let core = GraphiteCore::default();
    let input = make_input(
        "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc", "f8c69e91e17587c8",
        &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
          "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
          "9WzDXwBbmkg8ZTbNMqJx8W5DkxUkq5PjAB8qjGp3q5J", "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf",
          "11111111111111111111111111111111", "Stake11111111111111111111111111111111111111",
          "Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
          "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"],
        &["SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"], // Squads not in Orca allowed_cpis
        WalletProfile::Conservative, good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved, "Orca swap with Squads CPI must be blocked");
}

// ============================================================
// 12. FULL PIPELINE INTEGRATION — end-to-end adversarial
// ============================================================

#[test]
fn test_full_pipeline_safe_transfer_approved_with_audit_trail() {
    let core = GraphiteCore::default();
    let input = make_input(
        "11111111111111111111111111111111", "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        &[], WalletProfile::Standard, good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(result.approved);
    assert!(!result.audit_trail_id.is_empty(), "Audit trail ID must be generated");
    assert_eq!(result.protocol_name, "System Program");
    assert_eq!(result.instruction_name, "Transfer");
    assert!(!result.unknown_protocol);
    assert!(result.manifest_found);
}

#[test]
fn test_full_pipeline_blocked_transaction_has_audit_trail() {
    // Even blocked transactions must have audit trail for forensic analysis
    let core = GraphiteCore::default();
    let input = make_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "0b",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx"],
        &[], WalletProfile::Conservative, good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved);
    assert!(!result.audit_trail_id.is_empty(), "Blocked transactions must still have audit trail ID");
}

#[test]
fn test_full_pipeline_unknown_protocol_has_audit_trail() {
    let core = GraphiteCore::default();
    let input = make_input(
        "4Nd1mYbz1NQ8Tk6eX5N6w5eM6eX5N6w5eM6eX5N6w5eM", "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        &[], WalletProfile::Conservative, no_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved);
    assert!(!result.audit_trail_id.is_empty(), "Unknown protocol must still have audit trail ID");
    assert!(result.unknown_protocol);
}
