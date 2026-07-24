#![allow(dead_code)]
#![allow(clippy::all)]
#[test]
fn verify_8_layers_tracked() {
    use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};
    use graphite_core::semantic_graph_store::BehaviorEvidence;
    use graphite_core::policy_engine::WalletProfile;
    
    let core = GraphiteCore::new();
    let input = VerificationInput {
        program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
        instruction_discriminator: "03".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
            "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7".to_string(),
        ],
        instruction_data: None,
        cpi_targets: vec![],
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Transfer tokens".to_string(),
            confidence_of_parse: 1.0,
            extracted_parameters: None,
        },
        behavior_evidence: BehaviorEvidence::default(),
        wallet_profile: WalletProfile::TradingBot,
        protocol_version: "".to_string(),
        simulation_baseline: None,
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
    };
    
    let result = core.verify(&input).unwrap();
    println!("Layer count: {}", result.layers.len());
    for layer in &result.layers {
        println!("  {} - passed: {} - {}", layer.layer, layer.passed, layer.reason);
    }
    assert_eq!(result.layers.len(), 8, "Must have exactly 8 layers matching architecture spec");
    
    // Verify layer names match the actual execution pipeline
    assert_eq!(result.layers[0].layer, "L1_AccountResolution");
    assert_eq!(result.layers[1].layer, "L2_InstructionVerification");
    assert_eq!(result.layers[2].layer, "L3_RiskEngine");
    assert_eq!(result.layers[3].layer, "L4_StateVerification");
    assert_eq!(result.layers[4].layer, "L5_SemanticVerification");
    assert_eq!(result.layers[5].layer, "L6_ConfidenceEngine");
    assert_eq!(result.layers[6].layer, "L7_PolicyEngine");
    assert_eq!(result.layers[7].layer, "L8_EmitVerdict");
}
