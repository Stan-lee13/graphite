#![allow(dead_code)]
#![allow(clippy::all)]
#[test]
fn verify_8_layers_tracked() {
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::semantic_graph_store::BehaviorEvidence;
    use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

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
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
    };

    let result = core.verify(&input).unwrap();
    println!("Layer count: {}", result.layers.len());
    for layer in &result.layers {
        println!(
            "  {} - passed: {} - {}",
            layer.layer, layer.passed, layer.reason
        );
    }
    assert_eq!(
        result.layers.len(),
        8,
        "Must have exactly 8 layers matching ARCHITECTURE.md 3.12 spec"
    );

    // Layer names must match the Engineering Skill's ARCHITECTURE.md section 3.12 exactly:
    // L1 — Account Resolution
    // L2 — Instruction Verification
    // L3 — Simulation Verification
    // L4 — State Verification
    // L5 — Semantic Verification
    // L6 — Policy Verification
    // L7 — Risk Verification (Risk Engine 3.21)
    // L8 — Execution Verification
    assert_eq!(result.layers[0].layer, "L1_AccountResolution");
    assert_eq!(result.layers[1].layer, "L2_InstructionVerification");
    assert_eq!(result.layers[2].layer, "L3_SimulationVerification");
    assert_eq!(result.layers[3].layer, "L4_StateVerification");
    assert_eq!(result.layers[4].layer, "L5_SemanticVerification");
    assert_eq!(result.layers[5].layer, "L6_PolicyVerification");
    assert_eq!(result.layers[6].layer, "L7_RiskVerification");
    assert_eq!(result.layers[7].layer, "L8_ExecutionVerification");
}

/// GAP-2026-08-06-3: L3 must reflect the real simulation-integrity verdict —
/// never a phantom `passed: true`. A flagged simulation is a FAILED layer.
#[test]
fn l3_reflects_flagged_simulation_as_failed() {
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::semantic_graph_store::BehaviorEvidence;
    use graphite_core::simulation_integrity::ComputeBaseline;
    use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

    let core = GraphiteCore::new();
    // Operator-seeded trusted baseline (mean 150 CU, std 10, 100 samples).
    core.seed_simulation_baseline(
        "11111111111111111111111111111111",
        ComputeBaseline {
            mean_compute_units: 150.0,
            std_compute_units: 10.0,
            sample_count: 100,
            mean_account_writes: 0.0,
            std_account_writes: 0.0,
            mean_cpi_hops: 0.0,
            std_cpi_hops: 0.0,
            ..Default::default()},
    )
    .unwrap();

    let input = VerificationInput {
        program_id: "11111111111111111111111111111111".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
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
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        compute_units: 999999, // 100kσ from baseline — must flag
        account_writes: 2,
        cpi_hops: 0,
    };

    let result = core.verify(&input).unwrap();
    assert_eq!(
        result.simulation_flagged,
        Some(true),
        "divergent usage must flag the simulation"
    );
    let l3 = result
        .layers
        .iter()
        .find(|l| l.layer == "L3_SimulationVerification");
    let l3 = l3.expect("L3 layer must be present");
    assert!(
        !l3.passed,
        "L3 must NOT report passed when simulation integrity is flagged — got passed={}",
        l3.passed
    );
    assert_eq!(
        l3.status,
        graphite_core::verification::LayerStatus::Failed,
        "L3 status must be Failed when simulation is flagged"
    );
    assert!(
        l3.reason.contains("FLAGGED"),
        "L3 reason must surface the flag, got: {}",
        l3.reason
    );
}

/// GAP-2026-08-06-3: with no trusted baseline the simulation was never
/// verified — the layer must be INCONCLUSIVE (never a phantom pass, and never
/// a false failure).
#[test]
fn l3_is_inconclusive_without_trusted_verdict() {
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::semantic_graph_store::BehaviorEvidence;
    use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

    let core = GraphiteCore::new(); // no baseline, no RPC client
    let input = VerificationInput {
        program_id: "11111111111111111111111111111111".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
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
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
    };

    let result = core.verify(&input).unwrap();
    let l3 = result
        .layers
        .iter()
        .find(|l| l.layer == "L3_SimulationVerification");
    let l3 = l3.expect("L3 layer must be present");
    assert_eq!(
        l3.status,
        graphite_core::verification::LayerStatus::Inconclusive,
        "L3 with no trusted verdict must be Inconclusive, got {:?}",
        l3.status
    );
    assert!(
        !l3.passed,
        "L3 must not report passed when the simulation was never verified"
    );
}

/// GAP-2026-08-06-1: a NOVEL instruction discriminator on a KNOWN protocol
/// must surface a non-blocking risk warning (P12 fail-open, response 2) — it
/// must not pass with zero risk signal. The confidence ceiling (P6) reduces
/// score, but consumers must SEE the novelty.
#[test]
fn l7_surfaces_novel_instruction_warning_on_known_protocol() {
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::semantic_graph_store::BehaviorEvidence;
    use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

    let core = GraphiteCore::new();
    // SPL Token (known protocol) with a discriminator that is NOT in its
    // manifest — a novel/unknown instruction on a known program.
    let input = VerificationInput {
        program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
        instruction_discriminator: "deadbeef".to_string(), // not a real SPL Token disc
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
            "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx".to_string(),
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
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
    };

    let result = core.verify(&input).unwrap();
    assert!(result.manifest_found, "SPL Token manifest must be found");
    let l7 = result
        .layers
        .iter()
        .find(|l| l.layer == "L7_RiskVerification");
    let l7 = l7.expect("L7 layer must be present");
    assert!(
        l7.reason.contains("novel instruction"),
        "L7 must surface the novel-instruction warning, got: {}",
        l7.reason
    );
    assert!(
        result.summary.contains("novel instruction"),
        "summary must surface the novel-instruction warning, got: {}",
        result.summary
    );
}

/// GAP-2026-08-06-3: L8 execution verification is a post-submission feature —
/// it must emit a real 'not yet verified' state, never a phantom pass.
#[test]
fn l8_reports_not_yet_verified() {
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::semantic_graph_store::BehaviorEvidence;
    use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

    let core = GraphiteCore::new();
    let input = VerificationInput {
        program_id: "11111111111111111111111111111111".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
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
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
    };

    let result = core.verify(&input).unwrap();
    let l8 = result
        .layers
        .iter()
        .find(|l| l.layer == "L8_ExecutionVerification");
    let l8 = l8.expect("L8 layer must be present");
    assert_eq!(
        l8.status,
        graphite_core::verification::LayerStatus::Inconclusive,
        "L8 must be Inconclusive (not yet verified), got {:?}",
        l8.status
    );
    assert!(
        !l8.passed,
        "L8 must not report passed — execution verification has not run yet"
    );
    assert!(
        l8.reason.contains("not yet verified"),
        "L8 reason must say 'not yet verified', got: {}",
        l8.reason
    );
}
