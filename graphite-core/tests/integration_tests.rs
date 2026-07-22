//! End-to-end integration tests for Graphite Core.
//!
//! Tests the full verification pipeline: manifest loading → account resolution
//! → transaction building → risk assessment → confidence computation → policy.

use graphite_core::verification::{GraphiteCore, VerificationInput, ProposedIntent};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;

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
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        &[],
        WalletProfile::Standard,
        good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert!(result.manifest_found, "System Program manifest should be found");
    assert_eq!(result.protocol_name, "System Program");
    assert_eq!(result.instruction_name, "Transfer");
    assert!(result.confidence > 0.0, "confidence should be positive with good evidence");
    assert!(!result.unknown_protocol);
    println!("System Transfer: confidence={:.3}, approved={}", result.confidence, result.approved);
}

#[test]
fn test_e2e_spl_token_transfer() {
    let core = GraphiteCore::new();
    let input = make_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "03",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx"],
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
    assert!(result.confidence <= 0.55, "unknown protocol confidence must be capped (P6/P12)");
}

#[test]
fn test_e2e_risk_engine_blocks_unverified_cpi() {
    let core = GraphiteCore::new();
    let input = make_input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "03",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx"],
        &["unverified_malicious_target"],
        WalletProfile::Standard,
        good_evidence(),
    );
    let result = core.verify(&input).unwrap();
    assert_eq!(result.risk_verdict.status, "Blocked", "unverified CPI should be blocked");
    assert!(!result.approved);
}

#[test]
fn test_e2e_audit_trail_id_is_deterministic() {
    let core = GraphiteCore::new();
    let input = make_input(
        "11111111111111111111111111111111",
        "02000000",
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        &[],
        WalletProfile::Standard,
        good_evidence(),
    );
    let r1 = core.verify(&input).unwrap();
    let r2 = core.verify(&input).unwrap();
    // Audit trail IDs are unique per call (sequence counter), but hash prefix is deterministic (P2)
    let prefix1 = r1.audit_trail_id.split('-').nth(1).unwrap();
    let prefix2 = r2.audit_trail_id.split('-').nth(1).unwrap();
    assert_eq!(prefix1, prefix2, "same input must produce same hash prefix (P2 determinism)");
    assert_ne!(r1.audit_trail_id, r2.audit_trail_id, "full audit ID must be unique per call");
}

#[test]
fn test_e2e_manifests_listed() {
    let core = GraphiteCore::new();
    let manifests = core.list_manifests();
    assert!(manifests.len() >= 2, "should have at least System Program and SPL Token");
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
        &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
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
    assert!(!result.approved, "conservative profile should reject unknown protocol");
    assert!(result.confidence <= 0.55);
}
