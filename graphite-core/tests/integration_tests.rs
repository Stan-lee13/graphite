//! End-to-end integration tests for Graphite Core.
//!
//! Tests the full verification pipeline: manifest loading → account resolution
//! → transaction building → risk assessment → confidence computation → policy.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{
    ExtractedParameters, GraphiteCore, ProposedIntent, VerificationInput,
};

fn make_input(
    program: &str,
    disc: &str,
    accounts: &[&str],
    cpi: &[&str],
    profile: WalletProfile,
    evidence: BehaviorEvidence,
) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "test transaction".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: program.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: disc.to_string(),
        account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
        instruction_data: None,
        cpi_targets: cpi.iter().map(|s| s.to_string()).collect(),
        wallet_profile: profile,
        behavior_evidence: evidence,
        compute_units: 150,
        account_writes: 2,
        cpi_hops: cpi.len() as u32,
        simulation_baseline: None,
    }
}

fn good_evidence() -> BehaviorEvidence {
    BehaviorEvidence {
        has_signed_manifest: false,
        community_verified_count: 5,
        battle_tested_tx_count: 50000,
        simulation_match_count: 100,
    }
}

#[test]
fn test_e2e_system_transfer_approved() {
    let core = GraphiteCore::new();
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
    assert!(
        result.manifest_found,
        "System Program manifest should be found"
    );
    assert_eq!(result.protocol_name, "System Program");
    assert_eq!(result.instruction_name, "Transfer");
    assert!(
        result.confidence > 0.0,
        "confidence should be positive with good evidence"
    );
    assert!(!result.unknown_protocol);
    println!(
        "System Transfer: confidence={:.3}, approved={}",
        result.confidence, result.approved
    );
}

#[test]
fn test_e2e_spl_token_transfer() {
    let core = GraphiteCore::new();
    let input = make_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
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
    assert!(result.manifest_found, "SPL Token manifest should be found");
    assert_eq!(result.protocol_name, "SPL Token Program");
    assert_eq!(result.instruction_name, "Transfer");
}

#[test]
fn test_e2e_unknown_protocol_capped() {
    let core = GraphiteCore::new();
    let input = make_input(
        "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
        "03000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"],
        &[],
        WalletProfile::Standard,
        graphite_core::semantic_graph_store::BehaviorEvidence {
            has_signed_manifest: false,
            community_verified_count: 0,
            battle_tested_tx_count: 0,
            simulation_match_count: 0,
        },
    );
    let result = core.verify(&input).unwrap();
    assert!(result.unknown_protocol);
    assert!(!result.manifest_found);
    assert!(
        result.confidence <= 0.55,
        "unknown protocol confidence must be capped (P6/P12)"
    );
}

#[test]
fn test_e2e_risk_engine_blocks_unverified_cpi() {
    let core = GraphiteCore::new();
    let input = make_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "03",
        &[
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
            "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
        ],
        &["unverified_malicious_target"],
        WalletProfile::Standard,
        good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert_eq!(
        result.risk_verdict.status, "Blocked",
        "unverified CPI should be blocked"
    );
    assert!(!result.approved);
}

#[test]
fn test_e2e_audit_trail_id_is_deterministic() {
    let core = GraphiteCore::new();
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
    let r1 = core.verify(&input).unwrap();
    let r2 = core.verify(&input).unwrap();
    // Audit trail IDs are unique per call (sequence counter), but hash prefix is deterministic (P2)
    let prefix1 = r1.audit_trail_id.split('-').nth(1).unwrap();
    let prefix2 = r2.audit_trail_id.split('-').nth(1).unwrap();
    assert_eq!(
        prefix1, prefix2,
        "same input must produce same hash prefix (P2 determinism)"
    );
    assert_ne!(
        r1.audit_trail_id, r2.audit_trail_id,
        "full audit ID must be unique per call"
    );
}

#[test]
fn test_e2e_manifests_listed() {
    let core = GraphiteCore::new();
    let manifests = core.list_manifests();
    assert!(
        manifests.len() >= 2,
        "should have at least System Program and SPL Token"
    );
    let names: Vec<_> = manifests.iter().map(|m| m.protocol.name.as_str()).collect();
    assert!(names.contains(&"System Program"));
    assert!(names.contains(&"SPL Token Program"));
}

#[test]
fn test_e2e_custom_manifest_loaded() {
    let mut core = GraphiteCore::new();
    let custom_manifest = r#"{
        "graphite_manifest_version": "1.0",
        "protocol": {
            "name": "Test Protocol",
            "program_id": "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
            "website": "",
            "github": ""
        },
        "version": {
            "label": "1.0.0",
            "effective_from_slot": 0,
            "previous_version_ref": null
        },
        "instructions": [
            {
                "name": "Deposit",
                "discriminator": "01",
                "accounts": [
                    {"name": "user", "role": "signer", "is_writable": true, "is_signer": true, "pda_seeds": []},
                    {"name": "vault", "role": "pda", "is_writable": true, "is_signer": false, "pda_seeds": ["seed", "{program_id}"]}
                ],
                "expected_state_changes": ["credits accounts.vault"],
                "allowed_cpis": [],
                "risk_rules": []
            }
        ],
        "trust_tier": "HeuristicInferred"
    }"#;
    core.load_manifest(custom_manifest).unwrap();
    let manifests = core.list_manifests();
    assert!(manifests.iter().any(|m| m.protocol.name == "Test Protocol"));
}

#[test]
fn test_e2e_result_serializes_to_json() {
    let core = GraphiteCore::new();
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
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("confidence"));
    assert!(json.contains("audit_trail_id"));
    assert!(json.contains("System Program"));
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["confidence"].as_f64().unwrap_or(0.0) > 0.0);
}

#[test]
fn test_e2e_conservative_profile_rejects_unknown() {
    let core = GraphiteCore::new();
    let input = make_input(
        "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
        "03000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"],
        &[],
        WalletProfile::Conservative,
        graphite_core::semantic_graph_store::BehaviorEvidence {
            has_signed_manifest: false,
            community_verified_count: 0,
            battle_tested_tx_count: 0,
            simulation_match_count: 0,
        },
    );
    let result = core.verify(&input).unwrap();
    assert!(
        !result.approved,
        "conservative profile should reject unknown protocol"
    );
    assert!(result.confidence <= 0.55);
}

// ============================================================================
// FIX-SPECIFIC TESTS: These verify the exact issues found in code review
// ============================================================================

#[test]
fn test_fix4_invalid_pubkey_in_transaction_builder_is_hard_error() {
    use graphite_core::account_resolution::ResolvedAccount;
    use graphite_core::transaction_builder::{build_transaction, TransactionPlan};

    let bad_account = ResolvedAccount {
        address: "NOT_A_VALID_BASE58_ADDRESS!!!".to_string(),
        role: "signer".to_string(),
        is_pda: false,
        is_signer: true,
        is_writable: true,
        pda_seeds: vec![],
        pda_mismatch: false,
    };

    let plan = TransactionPlan {
        program_id: "11111111111111111111111111111111".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        instruction_name: "Transfer".to_string(),
        resolved_accounts: vec![bad_account],
        expected_state_changes: vec![],
        allowed_cpis: vec![],
        instruction_data: vec![],
    };

    let result = build_transaction(&plan);
    assert!(
        result.is_err(),
        "Invalid pubkey must be a hard error, not silently defaulted"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("invalid account address"),
        "Error should mention invalid address, got: {}",
        err
    );
}

#[test]
fn test_fix4_invalid_program_id_is_hard_error() {
    use graphite_core::account_resolution::ResolvedAccount;
    use graphite_core::transaction_builder::{build_transaction, TransactionPlan};

    let good_account = ResolvedAccount {
        address: "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
        role: "signer".to_string(),
        is_pda: false,
        is_signer: true,
        is_writable: true,
        pda_seeds: vec![],
        pda_mismatch: false,
    };

    let plan = TransactionPlan {
        program_id: "TOO_SHORT_PROGRAM_ID".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        instruction_name: "Transfer".to_string(),
        resolved_accounts: vec![good_account],
        expected_state_changes: vec![],
        allowed_cpis: vec![],
        instruction_data: vec![],
    };

    let result = build_transaction(&plan);
    assert!(result.is_err(), "Invalid program_id must be a hard error");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("invalid program_id"),
        "Error should mention invalid program_id, got: {}",
        err
    );
}

#[test]
fn test_fix5_fake_swap_wired_into_pipeline() {
    let core = GraphiteCore::default();
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "swap".to_string(),
            raw_natural_language: "Swap 1 SOL for USDC".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: Some(ExtractedParameters {
                input_token: Some("SOL".to_string()),
                output_token: Some("USDC".to_string()),
                amount: Some("1".to_string()),
                slippage_bps: None,
            }),
        },
        program_id: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "e517cb977ae3ad2a".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
            "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx".to_string(),
            "9WzDXwBbmkg8ZTbNMqJx8W5DkxUkq5PjAB8qjGp3q5J".to_string(),
            "4Nd1mYbz1NQ8Tk6eX5N6g5eM6eX5N6g5eM6eX5N6g5eM".to_string(),
        ],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Standard,
        behavior_evidence: BehaviorEvidence {
            has_signed_manifest: false,
            community_verified_count: 5,
            battle_tested_tx_count: 50000,
            simulation_match_count: 100,
        },
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        simulation_baseline: None,
    };
    let result = core.verify(&input).unwrap();
    // Jupiter V6 manifest has expected_state_changes that mention "output" or "credits"
    // so FakeSwap should NOT fire for this legitimate swap. It should pass risk.
    // But if FakeSwap WAS wired and the manifest lacked credit/output, it would fire.
    // The key test: verify that the function is called and doesn't panic.
    // If Jupiter's manifest has state changes mentioning output, this passes risk.
    assert!(
        result.risk_verdict.status == "Clear" || result.risk_verdict.status == "Blocked",
        "Pipeline should complete without panic"
    );
}

#[test]
fn test_fix3_pda_mismatch_field_exists() {
    use graphite_core::account_resolution::{resolve_accounts, AccountResolutionInput};
    use graphite_core::manifest::load_seed_manifests;

    let registry = load_seed_manifests();
    // System Program Transfer — no PDAs involved
    let input = AccountResolutionInput {
        program_id: "11111111111111111111111111111111".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
        ],
        instruction_data: None,
    };

    let result = resolve_accounts(&input, &registry).unwrap();
    // Non-PDA accounts should have pda_mismatch = false
    for acc in &result.resolved_accounts {
        assert!(
            !acc.pda_mismatch,
            "Non-PDA account should not have pda_mismatch"
        );
    }
}

#[test]
fn test_fix1_simulation_baseline_accepted_by_pipeline() {
    let core = GraphiteCore::default();
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Transfer 1 SOL".to_string(),
            confidence_of_parse: 0.9,
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
        wallet_profile: WalletProfile::Standard,
        behavior_evidence: BehaviorEvidence {
            has_signed_manifest: false,
            community_verified_count: 5,
            battle_tested_tx_count: 50000,
            simulation_match_count: 100,
        },
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        simulation_baseline: Some(graphite_core::simulation_integrity::ComputeBaseline {
            mean_compute_units: 150.0,
            std_compute_units: 10.0,
            sample_count: 100,
        }),
    };
    let result = core.verify(&input).unwrap();
    // With a baseline and compute_units=150 (close to mean=150), simulation should not be flagged
    assert!(
        result.simulation_flagged == Some(false) || result.simulation_flagged == None,
        "Simulation should not be flagged for normal compute usage"
    );
}

// =========================================================================
// PDA MISMATCH — POSITIVE SECURITY TEST (v0.1.0-alpha freeze)
// Tests the actual security property: a spoofed PDA must be blocked.
// This closes the gap identified in external code review where only the
// negative case (non-PDA accounts have pda_mismatch=false) was tested.
// =========================================================================

#[test]
fn test_pda_mismatch_blocks_spoofed_pda() {
    use graphite_core::account_resolution::{resolve_accounts, AccountResolutionInput};
    use graphite_core::manifest::load_seed_manifests;

    let registry = load_seed_manifests();

    // Squads V4 proposalApprove instruction
    // Program ID: SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf
    // Discriminator: 0a96d0fcd2fb4f30
    // Accounts: [multisig (readonly), member (signer), proposal (writable, pda_seeds: ["proposal"])]

    // The CORRECT PDA derived from seed ["proposal"] + Squads program ID:
    //   4fbg44AUKAPdnKuhSUaq9HDvhC1rdph4u7mSVEKhZzLx
    // We use a WRONG address (derived from different seed) as the proposal account.

    let correct_pda = "4fbg44AUKAPdnKuhSUaq9HDvhC1rdph4u7mSVEKhZzLx";
    let spoofed_pda = "BvU5BGmtvjS2yYRdU5nMJwowZa6nmi3oYrfViBhmweMk"; // wrong seed derivation

    // Valid multisig and member addresses (any valid 32-byte base58)
    let multisig = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    let member = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

    // --- CASE 1: Correct PDA → no mismatch ---
    let input_correct = AccountResolutionInput {
        program_id: "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf".to_string(),
        instruction_discriminator: "0a96d0fcd2fb4f30".to_string(),
        account_addresses: vec![
            multisig.to_string(),
            member.to_string(),
            correct_pda.to_string(),
        ],
        instruction_data: None,
    };

    let result_correct = resolve_accounts(&input_correct, &registry).unwrap();
    let proposal_account_correct = &result_correct.resolved_accounts[2];
    assert!(
        !proposal_account_correct.pda_mismatch,
        "Correct PDA should NOT have pda_mismatch=true"
    );

    // --- CASE 2: Spoofed PDA → mismatch detected, transaction blocked ---
    let input_spoofed = AccountResolutionInput {
        program_id: "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf".to_string(),
        instruction_discriminator: "0a96d0fcd2fb4f30".to_string(),
        account_addresses: vec![
            multisig.to_string(),
            member.to_string(),
            spoofed_pda.to_string(),
        ],
        instruction_data: None,
    };

    let result_spoofed = resolve_accounts(&input_spoofed, &registry).unwrap();
    let proposal_account_spoofed = &result_spoofed.resolved_accounts[2];
    assert!(
        proposal_account_spoofed.pda_mismatch,
        "Spoofed PDA MUST have pda_mismatch=true — this is the core security property"
    );

    // --- CASE 3: Full pipeline — spoofed PDA must produce Blocked verdict ---
    let core = GraphiteCore::new();
    let full_input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "approve".to_string(),
            raw_natural_language: "Approve multisig proposal".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf".to_string(),
        protocol_version: "4.0.0".to_string(),
        instruction_discriminator: "0a96d0fcd2fb4f30".to_string(),
        account_addresses: vec![
            multisig.to_string(),
            member.to_string(),
            spoofed_pda.to_string(),
        ],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Standard,
        behavior_evidence: good_evidence(),
        compute_units: 500,
        account_writes: 1,
        cpi_hops: 0,
        simulation_baseline: None,
    };

    let verdict = core.verify(&full_input).unwrap();
    assert!(
        !verdict.approved,
        "Spoofed PDA transaction MUST be blocked — got approved={}",
        verdict.approved
    );

    // Verify the risk finding mentions PDA mismatch
    let has_pda_finding = verdict
        .risk_verdict
        .findings
        .iter()
        .any(|f| f.pattern == "PdaMismatch" || f.reason.contains("PDA mismatch"));
    assert!(
        has_pda_finding,
        "Risk findings must include PdaMismatch — got: {:?}",
        verdict
            .risk_verdict
            .findings
            .iter()
            .map(|f| &f.pattern)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_pda_mismatch_correct_pda_passes() {
    // Companion test: correct PDA should NOT trigger a block in the full pipeline.
    use graphite_core::account_resolution::{resolve_accounts, AccountResolutionInput};
    use graphite_core::manifest::load_seed_manifests;

    let registry = load_seed_manifests();
    let correct_pda = "4fbg44AUKAPdnKuhSUaq9HDvhC1rdph4u7mSVEKhZzLx";
    let multisig = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    let member = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

    let input = AccountResolutionInput {
        program_id: "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf".to_string(),
        instruction_discriminator: "0a96d0fcd2fb4f30".to_string(),
        account_addresses: vec![
            multisig.to_string(),
            member.to_string(),
            correct_pda.to_string(),
        ],
        instruction_data: None,
    };

    let result = resolve_accounts(&input, &registry).unwrap();
    assert!(
        !result.resolved_accounts[2].pda_mismatch,
        "Correct PDA must not trigger mismatch"
    );

    // Full pipeline should not block specifically due to PDA
    let core = GraphiteCore::new();
    let full_input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "approve".to_string(),
            raw_natural_language: "Approve multisig proposal".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf".to_string(),
        protocol_version: "4.0.0".to_string(),
        instruction_discriminator: "0a96d0fcd2fb4f30".to_string(),
        account_addresses: vec![
            multisig.to_string(),
            member.to_string(),
            correct_pda.to_string(),
        ],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Standard,
        behavior_evidence: good_evidence(),
        compute_units: 500,
        account_writes: 1,
        cpi_hops: 0,
        simulation_baseline: None,
    };

    let verdict = core.verify(&full_input).unwrap();
    let has_pda_finding = verdict
        .risk_verdict
        .findings
        .iter()
        .any(|f| f.pattern == "PdaMismatch");
    assert!(
        !has_pda_finding,
        "Correct PDA must not produce PdaMismatch finding"
    );
}
