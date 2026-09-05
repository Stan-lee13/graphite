#[test]
fn verify_manifest_trust_tier_used() {
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::semantic_graph_store::BehaviorEvidence;
    use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

    let core = GraphiteCore::new();

    // SPL Token has a manifest with trust_tier="BattleTested"
    // P7 fix: manifest self-asserted tiers are capped at OfficialManifest (Tier 2)
    // BattleTested must be earned through evidence in the Semantic Graph
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Transfer SPL tokens".to_string(),
            confidence_of_parse: 1.0,
            extracted_parameters: None,
        },
        program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "03".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
            "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7".to_string(),
        ],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::TradingBot,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 200,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    };

    let result = core.verify(&input).unwrap();

    // The trust tier in the result should be BattleTested, NOT HeuristicInferred
    println!("Trust tier: {}", result.trust_tier);
    println!("Confidence: {}", result.confidence);
    println!("Manifest found: {}", result.manifest_found);
    println!("Unknown protocol: {}", result.unknown_protocol);

    assert_eq!(
        result.trust_tier, "OfficialManifest",
        "P7 fix: manifest self-asserted BattleTested must be capped to OfficialManifest"
    );
    assert!(result.confidence > 0.3,
        "With OfficialManifest tier + manifest found + intent alignment, confidence should be > 0.3, got {}",
        result.confidence);
    assert!(
        !result.unknown_protocol,
        "SPL Token has a manifest — should not be marked as unknown protocol"
    );
}

#[test]
fn verify_unknown_protocol_still_capped() {
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::semantic_graph_store::BehaviorEvidence;
    use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

    let core = GraphiteCore::new();

    // Unknown program ID — no manifest exists
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "swap".to_string(),
            raw_natural_language: "Swap tokens".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: "DezXAZ8z7PnrnRJjy3xLZkf7Jj4t1VhR3Q6ojGwFRrP".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "ff".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
        ],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::TradingBot,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    };

    let result = core.verify(&input).unwrap();

    println!("Unknown protocol trust tier: {}", result.trust_tier);
    println!("Unknown protocol confidence: {}", result.confidence);

    assert_eq!(
        result.trust_tier, "Unknown",
        "Unknown program must get Unknown trust tier (Constitution P6)"
    );
    assert!(
        result.confidence <= 0.55,
        "Unknown protocol confidence must be capped at 0.55, got {}",
        result.confidence
    );
    assert!(
        result.unknown_protocol,
        "Unknown program must be marked as unknown protocol"
    );
}
