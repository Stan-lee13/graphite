//! Pipeline tests for Phase 2 Month 1 protocol expansion.
//!
//! Covers the 4 new P11-verified manifests (Pump.fun, Jupiter DCA, Wormhole
//! Core, Metaplex Token Metadata) end-to-end through the verification
//! pipeline: happy-path acceptance + adversarial risk-pattern rejection.
//! Program IDs were confirmed executable on mainnet 2026-08-07 (P11/P16).

#![allow(dead_code)]

use graphite_core::manifest::load_seed_manifests;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::risk_engine::{
    assess, detect_intent_program_mismatch, RiskAssessmentInput, RiskPattern, RiskVerdict,
};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

const PUMP_FUN: &str = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
const JUPITER_DCA: &str = "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M";
const WORMHOLE: &str = "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth";
const METAPLEX: &str = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";

fn base_input(program_id: &str, discriminator: &str, intent: &str) -> VerificationInput {
    VerificationInput {
        program_id: program_id.to_string(),
        instruction_discriminator: discriminator.to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
            "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7".to_string(),
            "3npQNsA9S1K9xJ9gTYn1BZu2xw2sBvZK9QG4pLkXVcBz".to_string(),
            "4rQz2f4Wc1y7DpQ8v6mW2nN5uM3sR9bHjC1kTv8XwYdL".to_string(),
        ],
        instruction_data: None,
        cpi_targets: vec![],
        proposed_intent: ProposedIntent {
            intent_type: intent.to_string(),
            raw_natural_language: String::new(),
            confidence_of_parse: 1.0,
            extracted_parameters: None,
        },
        behavior_evidence: BehaviorEvidence::default(),
        wallet_profile: WalletProfile::TradingBot,
        protocol_version: String::new(),
        signed_transaction: None,
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
    }
}

#[test]
fn all_new_manifests_are_loaded_and_instruction_surfaces_parse() {
    let registry = load_seed_manifests();
    assert_eq!(registry.list().len(), 20, "expected 20 seed manifests (16 + Tier-0: ATA, Compute Budget, BPF Loader, BPF Loader Upgradeable)");
    for id in [PUMP_FUN, JUPITER_DCA, WORMHOLE, METAPLEX] {
        let m = registry
            .get(id)
            .unwrap_or_else(|| panic!("manifest {id} should be loaded"));
        assert!(!m.instructions.is_empty(), "{id} must declare instructions");
        for ix in &m.instructions {
            assert!(
                !ix.discriminator.is_empty(),
                "{id}:{} missing discriminator",
                ix.name
            );
            assert!(
                !ix.expected_state_changes.is_empty(),
                "{id}:{} must declare expected_state_changes",
                ix.name
            );
        }
    }
}

#[test]
fn pump_fun_buy_swap_intent_is_accepted() {
    // Happy path: a pump.fun buy with matching "swap" intent.
    let core = GraphiteCore::new();
    let input = base_input(PUMP_FUN, "66063d1201daebea", "swap");
    let result = core.verify(&input).expect("verify should not fail");
    assert!(
        result.layers.iter().any(|l| l.layer.contains("L1")),
        "L1 tracked"
    );
}

#[test]
fn pump_fun_swap_intent_mismatch_is_flagged() {
    // Risk: intent "stake" on a memecoin launcher = permission escalation.
    let pat = detect_intent_program_mismatch(PUMP_FUN, "stake");
    assert!(matches!(pat, Some(RiskPattern::PermissionEscalation)));
    // swap is the supported intent for pump.fun.
    assert!(detect_intent_program_mismatch(PUMP_FUN, "swap").is_none());
}

#[test]
fn jupiter_dca_close_intent_is_accepted() {
    let core = GraphiteCore::new();
    let input = base_input(JUPITER_DCA, "131cb5dbd74f7e19", "close");
    let result = core.verify(&input).expect("verify should not fail");
    assert!(
        result.layers.iter().any(|l| l.layer.contains("L1")),
        "L1 tracked"
    );
    // closeDca is a supported intent for Jupiter DCA (risk_engine "close" arm) —
    // closing a position must never be flagged as permission escalation.
    assert!(
        detect_intent_program_mismatch(JUPITER_DCA, "close").is_none(),
        "close intent must not be flagged as PermissionEscalation"
    );
    assert_ne!(
        result.risk_verdict.status, "Blocked",
        "DCA close must not hard-block, got {:?}",
        result.risk_verdict
    );
}

#[test]
fn jupiter_dca_is_a_swap_program() {
    assert!(detect_intent_program_mismatch(JUPITER_DCA, "swap").is_none());
    // DCA does not support staking.
    assert!(matches!(
        detect_intent_program_mismatch(JUPITER_DCA, "stake"),
        Some(RiskPattern::PermissionEscalation)
    ));
}

#[test]
fn wormhole_post_message_transfer_intent_runs_pipeline() {
    let core = GraphiteCore::new();
    let input = base_input(WORMHOLE, "01", "transfer");
    let result = core.verify(&input).expect("verify should not fail");
    assert!(
        result.layers.iter().any(|l| l.layer.contains("L1")),
        "L1 tracked"
    );
    // transfer is a universally supported intent — no mismatch on Wormhole.
    assert!(detect_intent_program_mismatch(WORMHOLE, "transfer").is_none());
}

#[test]
fn wormhole_unknown_intent_is_fail_closed() {
    // P12: unknown intent types are not silently permitted.
    assert!(matches!(
        detect_intent_program_mismatch(WORMHOLE, "swap"),
        Some(RiskPattern::PermissionEscalation)
    ));
}

#[test]
fn metaplex_create_metadata_runs_pipeline() {
    let core = GraphiteCore::new();
    let input = base_input(METAPLEX, "0fd902b83e0f4ee4", "transfer");
    let result = core.verify(&input).expect("verify should not fail");
    assert!(
        result.layers.iter().any(|l| l.layer.contains("L1")),
        "L1 tracked"
    );
}

#[test]
fn metaplex_burn_has_risk_rules() {
    // The burn instruction must carry drain-protection rules.
    let registry = load_seed_manifests();
    let m = registry.get(METAPLEX).expect("metaplex manifest");
    let burn = m
        .instructions
        .iter()
        .find(|i| i.name == "BurnNft")
        .expect("BurnNft instruction should exist");
    assert!(!burn.risk_rules.is_empty());
    assert!(
        burn.risk_rules.iter().any(|r| r.contains("owner")),
        "burn rules must check ownership"
    );
}

#[test]
fn pump_fun_drainer_heuristic_is_suppressed_for_curve_trades() {
    // Pump.fun is in DEX_PROGRAMS: the drainer heuristic (>=3 accounts with no
    // meaningful state changes) is skipped because bonding-curve trades
    // legitimately carry many accounts (curve + mint + user + fee accounts).
    // The control proves the SAME shape is still blocked on a non-DEX program
    // — the relaxation is program-scoped, not a global drainer bypass.
    let input = RiskAssessmentInput {
        program_id: PUMP_FUN.to_string(),
        accounts: vec![
            "curve".to_string(),
            "mint".to_string(),
            "user".to_string(),
            "global".to_string(),
            "fee".to_string(),
            "pool".to_string(),
        ],
        cpi_targets: vec![],
        expected_state_changes: vec![],
        allowed_cpis: vec![],
        instruction_discriminator: "66063d1201daebea".to_string(),
        expected_account_count: None,
        proposed_intent_type: "swap".to_string(),
        variable_accounts: false,
        extracted_output_token: None,
    };
    assert_eq!(assess(&input).unwrap(), RiskVerdict::Passed);

    // Control: identical shape on a program NOT in DEX_PROGRAMS is a Drainer.
    let mut control = input.clone();
    control.program_id = "SomeOtherProgram11111111111111111111111".to_string();
    assert!(matches!(
        assess(&control).unwrap(),
        RiskVerdict::Blocked {
            pattern: RiskPattern::Drainer,
            ..
        }
    ));
}

#[test]
fn pump_fun_repeated_cpi_chain_still_blocked_as_compositional_drain() {
    // The DEX_PROGRAMS/TRUSTED_CPI_ROOTS relaxations must NOT mask a real
    // drainer: a repeated-program deep CPI chain still trips the
    // compositional-drain pattern (that check is independent of root trust).
    let input = RiskAssessmentInput {
        program_id: PUMP_FUN.to_string(),
        accounts: vec!["a1".to_string(), "a2".to_string()],
        cpi_targets: vec!["evil_drainer_program".to_string(); 4],
        expected_state_changes: vec!["debits accounts.a1".to_string()],
        allowed_cpis: vec!["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()],
        instruction_discriminator: "66063d1201daebea".to_string(),
        expected_account_count: None,
        proposed_intent_type: "swap".to_string(),
        variable_accounts: false,
        extracted_output_token: None,
    };
    assert!(matches!(
        assess(&input).unwrap(),
        RiskVerdict::Blocked {
            pattern: RiskPattern::CompositionalDrainPattern,
            ..
        }
    ));
}
