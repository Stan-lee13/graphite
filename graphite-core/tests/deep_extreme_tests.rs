//! Deep Extreme Tests — edge cases, boundary conditions, adversarial inputs
//!
//! These tests stress-test every surface:
//! - Manifest validation edge cases
//! - Risk engine boundary conditions
//! - Confidence engine limits
//! - Verification pipeline edge cases
//! - Policy engine profiles
//! - Determinism across runs
//! - Pubkey round-trips

use graphite_core::{
    confidence_engine::{
        compute_confidence, ConfidenceResult, SignalKind, TrustTier, WeightedSignal,
    },
    manifest::{load_seed_manifests, ManifestError, ManifestRegistry},
    policy_engine::{evaluate_policy, PolicyInput, PolicyVerdict, WalletProfile},
    risk_engine::{assess, RiskAssessmentInput, RiskPattern, RiskVerdict},
    semantic_graph_store::BehaviorEvidence,
    solana_types::Pubkey,
    verification::{GraphiteCore, ProposedIntent, VerificationInput, VerificationResult},
};

fn make_input(
    program_id: &str,
    discriminator: &str,
    accounts: &[&str],
    cpi: &[&str],
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

// ============================================================
// 1. MANIFEST EDGE CASES
// ============================================================

#[test]
fn test_all_10_manifests_load_with_valid_pubkeys() {
    let registry = load_seed_manifests();
    let manifests = registry.list();
    assert_eq!(manifests.len(), 10, "expected exactly 10 seed manifests");

    for m in &manifests {
        let pubkey = Pubkey::from_base58(&m.protocol.program_id);
        assert!(
            pubkey.is_ok(),
            "program_id '{}' for '{}' is not a valid Pubkey",
            m.protocol.program_id,
            m.protocol.name
        );
    }
}

#[test]
fn test_no_duplicate_program_ids() {
    let registry = load_seed_manifests();
    let manifests = registry.list();
    let mut ids: Vec<&str> = manifests
        .iter()
        .map(|m| m.protocol.program_id.as_str())
        .collect();
    ids.sort();
    for i in 1..ids.len() {
        assert_ne!(ids[i - 1], ids[i], "duplicate program_id: {}", ids[i]);
    }
}

#[test]
fn test_every_instruction_has_accounts() {
    let registry = load_seed_manifests();
    for m in registry.list() {
        for ix in &m.instructions {
            assert!(
                !ix.accounts.is_empty(),
                "instruction '{}' in '{}' has no accounts",
                ix.name,
                m.protocol.name
            );
        }
    }
}

#[test]
fn test_every_instruction_has_expected_state_changes() {
    let registry = load_seed_manifests();
    for m in registry.list() {
        for ix in &m.instructions {
            assert!(
                !ix.expected_state_changes.is_empty(),
                "instruction '{}' in '{}' has no expected_state_changes",
                ix.name,
                m.protocol.name
            );
        }
    }
}

#[test]
fn test_memo_program_loaded_with_empty_discriminator() {
    let registry = load_seed_manifests();
    let memo = registry.get("Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH");
    assert!(memo.is_some(), "Memo program should be loaded");
    let memo = memo.unwrap();
    assert_eq!(memo.instructions.len(), 1);
    assert!(
        memo.instructions[0].discriminator.is_empty(),
        "Memo instruction should have empty discriminator"
    );
}

#[test]
fn test_invalid_manifest_rejected_empty_program_id() {
    let mut registry = ManifestRegistry::new();
    let bad_json = r#"{
        "graphite_manifest_version": "1.0",
        "protocol": {"name": "Bad", "program_id": "", "website": "", "github": ""},
        "version": {"label": "1.0", "effective_from_slot": 0, "previous_version_ref": null},
        "instructions": [{"name": "Test", "discriminator": "01", "accounts": [], "expected_state_changes": [], "allowed_cpis": [], "risk_rules": []}],
        "trust_tier": "Unverified"
    }"#;
    let result = registry.load_from_json(bad_json);
    assert!(result.is_err());
}

#[test]
fn test_invalid_manifest_rejected_no_instructions() {
    let mut registry = ManifestRegistry::new();
    let bad_json = r#"{
        "graphite_manifest_version": "1.0",
        "protocol": {"name": "Bad", "program_id": "11111111111111111111111111111111", "website": "", "github": ""},
        "version": {"label": "1.0", "effective_from_slot": 0, "previous_version_ref": null},
        "instructions": [],
        "trust_tier": "Unverified"
    }"#;
    let result = registry.load_from_json(bad_json);
    assert!(result.is_err());
}

#[test]
fn test_invalid_manifest_rejected_bad_hex_discriminator() {
    let mut registry = ManifestRegistry::new();
    let bad_json = r#"{
        "graphite_manifest_version": "1.0",
        "protocol": {"name": "Bad", "program_id": "11111111111111111111111111111111", "website": "", "github": ""},
        "version": {"label": "1.0", "effective_from_slot": 0, "previous_version_ref": null},
        "instructions": [{"name": "Test", "discriminator": "ZZ", "accounts": [], "expected_state_changes": [], "allowed_cpis": [], "risk_rules": []}],
        "trust_tier": "Unverified"
    }"#;
    let result = registry.load_from_json(bad_json);
    assert!(result.is_err());
}

// ============================================================
// 2. RISK ENGINE EDGE CASES
// ============================================================

fn risk_input(
    program: &str,
    accounts: &[&str],
    cpi: &[&str],
    changes: &[&str],
    allowed: &[&str],
    disc: &str,
) -> RiskAssessmentInput {
    RiskAssessmentInput {
        program_id: program.to_string(),
        accounts: accounts.iter().map(|s| s.to_string()).collect(),
        cpi_targets: cpi.iter().map(|s| s.to_string()).collect(),
        expected_state_changes: changes.iter().map(|s| s.to_string()).collect(),
        allowed_cpis: allowed.iter().map(|s| s.to_string()).collect(),
        instruction_discriminator: disc.to_string(),
            expected_account_count: None,
    }
}

#[test]
fn test_empty_accounts_not_flagged_as_drainer() {
    let input = risk_input("program", &[], &[], &[], &[], "");
    assert_eq!(assess(&input).unwrap(), RiskVerdict::Passed);
}

#[test]
fn test_single_account_not_flagged_as_drainer() {
    let input = risk_input("program", &["a1"], &[], &[], &[], "");
    assert_eq!(assess(&input).unwrap(), RiskVerdict::Passed);
}

#[test]
fn test_exactly_5_accounts_flagged_as_drainer() {
    // Red Team fix L1: threshold changed from >5 to >=5
    let input = risk_input(
        "program",
        &["a1", "a2", "a3", "a4", "a5"],
        &[],
        &[],
        &[],
        "",
    );
    assert!(
        matches!(
            assess(&input).unwrap(),
            RiskVerdict::Blocked {
                pattern: RiskPattern::Drainer,
                ..
            }
        ),
        "Red Team L1: exactly 5 accounts now flagged as drainer (>=5)"
    );
}

#[test]
fn test_exactly_6_accounts_flagged_as_drainer() {
    let input = risk_input(
        "program",
        &["a1", "a2", "a3", "a4", "a5", "a6"],
        &[],
        &[],
        &[],
        "",
    );
    assert!(matches!(
        assess(&input).unwrap(),
        RiskVerdict::Blocked {
            pattern: RiskPattern::Drainer,
            ..
        }
    ));
}

#[test]
fn test_cpi_allowed_list_blocks_unlisted_target() {
    let input = risk_input(
        "program",
        &["a1"],
        &["unknown"],
        &["change"],
        &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
        "",
    );
    assert!(matches!(
        assess(&input).unwrap(),
        RiskVerdict::Blocked {
            pattern: RiskPattern::UnexpectedCpi,
            ..
        }
    ));
}

#[test]
fn test_cpi_allowed_list_accepts_listed_target() {
    let input = risk_input(
        "program",
        &["a1"],
        &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
        &["change"],
        &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
        "",
    );
    assert_eq!(assess(&input).unwrap(), RiskVerdict::Passed);
}

#[test]
fn test_risk_engine_deterministic_1000_runs() {
    let input = risk_input("test", &["a1", "a2"], &["unverified"], &[], &[], "");
    let first = assess(&input).unwrap();
    for _ in 0..1000 {
        assert_eq!(
            assess(&input).unwrap(),
            first,
            "risk engine is not deterministic"
        );
    }
}

#[test]
fn test_set_authority_discriminator_blocked_on_spl_token() {
    let input = risk_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        &["account", "authority"],
        &[],
        &["changes authority"],
        &[],
        "0b",
    );
    assert!(matches!(
        assess(&input).unwrap(),
        RiskVerdict::Blocked {
            pattern: RiskPattern::AuthorityHijack,
            ..
        }
    ));
}

#[test]
fn test_system_assign_blocked() {
    let input = risk_input(
        "11111111111111111111111111111111",
        &["account", "new_owner"],
        &[],
        &["assigns"],
        &[],
        "01000000",
    );
    assert!(matches!(
        assess(&input).unwrap(),
        RiskVerdict::Blocked {
            pattern: RiskPattern::AuthorityHijack,
            ..
        }
    ));
}

#[test]
fn test_compositional_drain_4_with_repeat_flagged() {
    // Red Team fix L3: threshold changed from >4 to >=3
    let input = risk_input("agg", &[], &["a", "a", "b", "c"], &[], &["a", "b", "c"], "");
    assert!(
        matches!(
            assess(&input).unwrap(),
            RiskVerdict::Blocked {
                pattern: RiskPattern::CompositionalDrainPattern,
                ..
            }
        ),
        "Red Team L3: 4 CPI targets with repeat now flagged (>=3)"
    );
}

#[test]
fn test_compositional_drain_5_distinct_not_flagged() {
    let input = risk_input(
        "agg",
        &[],
        &["a", "b", "c", "d", "e"],
        &[],
        &["a", "b", "c", "d", "e"],
        "",
    );
    assert_eq!(assess(&input).unwrap(), RiskVerdict::Passed);
}

#[test]
fn test_compositional_drain_5_with_repeat_flagged() {
    let input = risk_input(
        "agg",
        &[],
        &["a", "a", "b", "c", "d"],
        &[],
        &["a", "b", "c", "d"],
        "",
    );
    assert!(matches!(
        assess(&input).unwrap(),
        RiskVerdict::Blocked {
            pattern: RiskPattern::CompositionalDrainPattern,
            ..
        }
    ));
}

// ============================================================
// 3. VERIFICATION PIPELINE EDGE CASES
// ============================================================

#[test]
fn test_verify_unknown_program_blocked() {
    let core = GraphiteCore::default();
    let input = make_input(
        "4Nd1mYbz1NQ8Tk6eX5N6w5eM6eX5N6w5eM6eX5N6w5eM",
        "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"],
        &[],
        WalletProfile::Conservative,
        no_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved, "unknown program should not be approved");
    assert!(
        result.confidence <= 0.55,
        "unknown program confidence should be <= 0.55, got {}",
        result.confidence
    );
    assert!(
        result.unknown_protocol,
        "should be flagged as unknown protocol"
    );
}

#[test]
fn test_verify_safe_system_transfer_approved() {
    let core = GraphiteCore::default();
    let input = make_input(
        "11111111111111111111111111111111",
        "02000000",
        &[
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
        ],
        &[],
        WalletProfile::Standard,
        good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(result.approved, "safe system transfer should be approved");
    assert!(
        result.confidence > 0.5,
        "safe transfer should have confidence > 0.5, got {}",
        result.confidence
    );
}

#[test]
fn test_verify_set_authority_blocked() {
    let core = GraphiteCore::default();
    let input = make_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "0b",
        &[
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
        ],
        &[],
        WalletProfile::Conservative,
        good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(!result.approved, "SetAuthority should be blocked");
    assert_eq!(result.risk_verdict.status, "Blocked");
}

#[test]
fn test_verify_jupiter_swap_with_allowed_cpi_passes_risk() {
    let core = GraphiteCore::default();
    let input = make_input(
        "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
        "e517cb977ae3ad2a",
        &[
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
            "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
            "9WzDXwBbmkg8ZTbNMqJx8W5DkxUkq5PjAB8qjGp3q5J",
        ],
        &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
        WalletProfile::Standard,
        good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert_eq!(
        result.risk_verdict.status, "Clear",
        "Jupiter swap with allowed CPI should pass risk engine, got: {:?}",
        result.risk_verdict
    );
}

#[test]
fn test_verify_jupiter_swap_with_unlisted_cpi_blocked() {
    let core = GraphiteCore::default();
    let input = make_input(
        "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
        "e517cb977ae3ad2a",
        &[
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
            "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
            "9WzDXwBbmkg8ZTbNMqJx8W5DkxUkq5PjAB8qjGp3q5J",
        ],
        &["MaliciousDrainerProgram1111111111111111111111"],
        WalletProfile::Conservative,
        good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(
        !result.approved,
        "Jupiter swap with unlisted CPI should be blocked"
    );
    assert_eq!(result.risk_verdict.status, "Blocked");
}

#[test]
fn test_verify_squads_multisig_create() {
    let core = GraphiteCore::default();
    let input = make_input(
        "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf",
        "8faecbbfaecf93c5",
        &[
            "Stake11111111111111111111111111111111111111",
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
            "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
            "9WzDXwBbmkg8ZTbNMqJx8W5DkxUkq5PjAB8qjGp3q5J",
            "4Nd1mYbz1NQ8Tk6eX5N6g5eM6eX5N6g5eM6eX5N6g5eM",
        ],
        &["11111111111111111111111111111111"],
        WalletProfile::Standard,
        good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert_eq!(
        result.risk_verdict.status, "Clear",
        "Squads create with allowed System CPI should pass, got: {:?}",
        result.risk_verdict
    );
}

#[test]
fn test_verify_orca_swap_passes_risk() {
    let core = GraphiteCore::default();
    let input = make_input(
        "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
        "f8c69e91e17587c8",
        &[
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
            "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
            "9WzDXwBbmkg8ZTbNMqJx8W5DkxUkq5PjAB8qjGp3q5J",
            "4Nd1mYbz1NQ8Tk6eX5N6g5eM6eX5N6g5eM6eX5N6g5eM",
            "11111111111111111111111111111111",
            "Stake11111111111111111111111111111111111111",
            "Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
        ],
        &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
        WalletProfile::Standard,
        good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert_eq!(result.risk_verdict.status, "Clear");
}

#[test]
fn test_verify_meteora_swap_passes_risk() {
    let core = GraphiteCore::default();
    let accounts_15: Vec<&str> = vec![
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
        "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
        "9WzDXwBbmkg8ZTbNMqJx8W5DkxUkq5PjAB8qjGp3q5J",
        "4Nd1mYbz1NQ8Tk6eX5N6g5eM6eX5N6g5eM6eX5N6g5eM",
        "11111111111111111111111111111111",
        "Stake11111111111111111111111111111111111111",
        "Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH",
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
        "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",
        "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf",
        "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
        "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo",
    ];
    let input = make_input(
        "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo",
        "f8c69e91e17587c8",
        &accounts_15,
        &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
        WalletProfile::Standard,
        good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert_eq!(result.risk_verdict.status, "Clear");
}

#[test]
fn test_verify_stake_delegate_passes_risk() {
    let core = GraphiteCore::default();
    let input = make_input(
        "Stake11111111111111111111111111111111111111",
        "02000000",
        &[
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
            "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
            "9WzDXwBbmkg8ZTbNMqJx8W5DkxUkq5PjAB8qjGp3q5J",
            "4Nd1mYbz1NQ8Tk6eX5N6g5eM6eX5N6g5eM6eX5N6g5eM",
            "11111111111111111111111111111111",
        ],
        &[],
        WalletProfile::Standard,
        good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert_eq!(result.risk_verdict.status, "Clear");
}

#[test]
fn test_verify_token_2022_transfer_passes_risk() {
    let core = GraphiteCore::default();
    let input = make_input(
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        "03",
        &[
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
            "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
        ],
        &[],
        WalletProfile::Standard,
        good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert_eq!(result.risk_verdict.status, "Clear");
}

#[test]
fn test_verify_token_2022_set_authority_blocked() {
    let core = GraphiteCore::default();
    let input = make_input(
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        "0b",
        &[
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
        ],
        &[],
        WalletProfile::Conservative,
        good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    // Token-2022 SetAuthority should be blocked by risk engine
    // (Token-2022 has same instruction discriminators as SPL Token for base instructions)
    assert!(
        !result.approved,
        "Token-2022 SetAuthority should be blocked"
    );
}

// ============================================================
// 4. POLICY ENGINE EDGE CASES
// ============================================================

#[test]
fn test_conservative_profile_requires_high_confidence() {
    // Conservative should require higher confidence than Standard
    let low_conf = make_confidence_result(0.6, TrustTier::SimulationValidated);
    let policy_input = PolicyInput {
        confidence_result: low_conf,
        risk_verdict: RiskVerdict::Passed,
        profile: WalletProfile::Conservative,
    };
    let result = evaluate_policy(&policy_input).unwrap();
    assert!(
        matches!(result, PolicyVerdict::RejectedBelowThreshold { .. }),
        "Conservative should reject at 0.6 confidence, got {:?}",
        result
    );
}

#[test]
fn test_standard_profile_approves_moderate_confidence() {
    let med_conf = make_confidence_result(0.75, TrustTier::SimulationValidated);
    let policy_input = PolicyInput {
        confidence_result: med_conf,
        risk_verdict: RiskVerdict::Passed,
        profile: WalletProfile::Standard,
    };
    let result = evaluate_policy(&policy_input).unwrap();
    assert!(
        matches!(result, PolicyVerdict::Approved),
        "Standard should approve at 0.75 confidence, got {:?}",
        result
    );
}

#[test]
fn test_all_profiles_block_when_risk_detected() {
    for profile in &[
        WalletProfile::Conservative,
        WalletProfile::Standard,
        WalletProfile::Permissive,
    ] {
        let high_conf = make_confidence_result(0.99, TrustTier::BattleTested);
        let policy_input = PolicyInput {
            confidence_result: high_conf,
            risk_verdict: RiskVerdict::Blocked {
                pattern: RiskPattern::Drainer,
                reason: "test".to_string(),
            },
            profile: profile.clone(),
        };
        let result = evaluate_policy(&policy_input).unwrap();
        assert!(
            matches!(result, PolicyVerdict::RejectedRiskEngineBlock),
            "{:?} profile should block when risk detected, got {:?}",
            profile,
            result
        );
    }
}

fn make_confidence_result(score: f64, tier: TrustTier) -> ConfidenceResult {
    ConfidenceResult {
        confidence: score,
        breakdown: vec![],
        trust_tier_applied: tier,
        ceiling_triggered: false,
        ceiling_applied: 0.0,
    }
}

// ============================================================
// 5. DETERMINISM TESTS
// ============================================================

#[test]
fn test_verification_deterministic_100_runs() {
    let core = GraphiteCore::default();
    let input = make_input(
        "11111111111111111111111111111111",
        "02000000",
        &[
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
        ],
        &[],
        WalletProfile::Standard,
        good_evidence(),
    );
    let first = core.verify(&input).unwrap();
    for _ in 0..100 {
        let result = core.verify(&input).unwrap();
        assert_eq!(
            result.approved, first.approved,
            "verification is not deterministic"
        );
        assert_eq!(
            result.confidence, first.confidence,
            "confidence is not deterministic"
        );
        // audit_trail_id is intentionally unique per call (sequence counter)
    }
}

#[test]
fn test_audit_trail_id_is_content_addressed() {
    let core = GraphiteCore::default();
    let input = make_input(
        "11111111111111111111111111111111",
        "02000000",
        &[
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
        ],
        &[],
        WalletProfile::Standard,
        good_evidence(),
    );
    let result1 = core.verify(&input).unwrap();
    let result2 = core.verify(&input).unwrap();
    // Audit trail IDs are now unique per call (sequence counter appended to deterministic hash)
    // The hash PREFIX is content-addressed; the full ID is unique
    let prefix1 = &result1.audit_trail_id.split('-').nth(1).unwrap();
    let prefix2 = &result2.audit_trail_id.split('-').nth(1).unwrap();
    assert_eq!(
        prefix1, prefix2,
        "same input must produce same hash prefix (content-addressed)"
    );
    assert_ne!(
        result1.audit_trail_id, result2.audit_trail_id,
        "full audit_trail_id must be unique per call"
    );
    assert!(
        !result1.audit_trail_id.is_empty(),
        "audit_trail_id must not be empty"
    );
}

// ============================================================
// 6. PUBKEY EDGE CASES
// ============================================================

#[test]
fn test_pubkey_from_base58_all_zeros() {
    let pk = Pubkey::from_base58("11111111111111111111111111111111").unwrap();
    assert_eq!(pk.0, [0u8; 32]);
}

#[test]
fn test_pubkey_to_base58_round_trip() {
    let original = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    let pk = Pubkey::from_base58(original).unwrap();
    let encoded = pk.to_base58();
    assert_eq!(encoded, original, "Pubkey base58 round-trip failed");
}

#[test]
fn test_pubkey_from_base58_invalid_too_short() {
    let result = Pubkey::from_base58("short");
    assert!(result.is_err(), "short base58 should be rejected");
}

#[test]
fn test_all_10_program_ids_round_trip() {
    let registry = load_seed_manifests();
    for m in registry.list() {
        let pk = Pubkey::from_base58(&m.protocol.program_id).unwrap();
        let encoded = pk.to_base58();
        assert_eq!(
            encoded, m.protocol.program_id,
            "program_id round-trip failed for {}",
            m.protocol.name
        );
    }
}

#[test]
fn test_pda_derivation_deterministic() {
    use graphite_core::solana_types::find_program_address;
    let program_id = Pubkey::from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let seeds: Vec<Vec<u8>> = vec![b"vault".to_vec()];
    let seeds_ref: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
    let (pda1, bump1) = find_program_address(&seeds_ref, &program_id).unwrap();
    let (pda2, bump2) = find_program_address(&seeds_ref, &program_id).unwrap();
    assert_eq!(pda1, pda2, "PDA derivation should be deterministic");
    assert_eq!(bump1, bump2, "bump seed should be deterministic");
}

// ============================================================
// 7. PROTOCOL COVERAGE TESTS
// ============================================================

#[test]
fn test_all_protocols_verifiable() {
    // Every seed protocol should be recognized by the verification engine
    let core = GraphiteCore::default();
    let registry = load_seed_manifests();

    // Generate enough dummy accounts for each protocol
    let dummy = "11111111111111111111111111111111";
    let dummy_accounts: Vec<&str> = vec![dummy; 20];

    for m in registry.list() {
        let ix = &m.instructions[0];
        let n_accounts = ix.accounts.len();
        let accounts = &dummy_accounts[..n_accounts];
        let input = make_input(
            &m.protocol.program_id,
            &ix.discriminator,
            accounts,
            &[],
            WalletProfile::Standard,
            good_evidence(),
        );
        let result = core.verify(&input);
        assert!(
            result.is_ok(),
            "verification failed for {} ({}) with discriminator '{}': {:?}",
            m.protocol.name,
            m.protocol.program_id,
            ix.discriminator,
            result.err()
        );
        let result = result.unwrap();
        assert!(
            result.manifest_found,
            "manifest not found for {} ({})",
            m.protocol.name, m.protocol.program_id
        );
    }
}

#[test]
fn test_protocol_category_diversity() {
    // Verify we have native, token, DEX, and multisig categories
    let registry = load_seed_manifests();
    let names: Vec<&str> = registry
        .list()
        .iter()
        .map(|m| m.protocol.name.as_str())
        .collect();

    // Native
    assert!(
        names.iter().any(|n| n.contains("System")),
        "missing System Program"
    );
    assert!(
        names.iter().any(|n| n.contains("Stake")),
        "missing Stake Program"
    );

    // Token
    assert!(
        names.iter().any(|n| n.contains("SPL Token")),
        "missing SPL Token"
    );
    assert!(
        names.iter().any(|n| n.contains("Token-2022")),
        "missing Token-2022"
    );

    // DEX
    assert!(
        names.iter().any(|n| n.contains("Raydium")),
        "missing Raydium"
    );
    assert!(
        names.iter().any(|n| n.contains("Jupiter")),
        "missing Jupiter"
    );
    assert!(names.iter().any(|n| n.contains("Orca")), "missing Orca");
    assert!(
        names.iter().any(|n| n.contains("Meteora")),
        "missing Meteora"
    );

    // Multisig
    assert!(names.iter().any(|n| n.contains("Squads")), "missing Squads");

    // Utility
    assert!(names.iter().any(|n| n.contains("Memo")), "missing Memo");
}
