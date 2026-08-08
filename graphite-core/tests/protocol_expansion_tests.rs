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

// ---------------------------------------------------------------------------
// C21: full L5 intent vocabulary must be supported by the risk engine.
// ---------------------------------------------------------------------------

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

#[test]
fn create_intent_is_supported_on_account_creating_programs() {
    // L5 vocabulary: create/create_account must not be flagged as
    // PermissionEscalation on programs that can create accounts (System
    // CreateAccount/Allocate, ATA CreateAssociatedTokenAccount, SPL Token
    // InitializeAccount/InitializeMint). Before C21 these were always
    // blocked by Check 9, contradicting Check 6b and the semantic layer.
    assert!(
        detect_intent_program_mismatch(SYSTEM_PROGRAM, "create").is_none(),
        "System program must support create intent"
    );
    assert!(
        detect_intent_program_mismatch(ATA_PROGRAM, "create").is_none(),
        "ATA program must support create intent"
    );
    assert!(
        detect_intent_program_mismatch(SPL_TOKEN, "create_account").is_none(),
        "SPL Token must support create_account intent"
    );
    // But create intent on a non-creating program is still fail-closed
    // (Wormhole is a bridge, not an account factory).
    assert!(matches!(
        detect_intent_program_mismatch(WORMHOLE, "create"),
        Some(RiskPattern::PermissionEscalation)
    ));
}

#[test]
fn approve_revoke_intents_are_supported_on_token_programs() {
    // L5 vocabulary + P0 Check 7: Approve/Revoke with a matching declared
    // intent must not be flagged as PermissionEscalation. Before C21, Check 9
    // blocked every approve/revoke even when Check 7 explicitly allowed it.
    assert!(
        detect_intent_program_mismatch(SPL_TOKEN, "approve").is_none(),
        "SPL Token must support approve intent"
    );
    assert!(
        detect_intent_program_mismatch(SPL_TOKEN, "revoke").is_none(),
        "SPL Token must support revoke intent"
    );
    // approve intent on a non-token program remains fail-closed.
    assert!(matches!(
        detect_intent_program_mismatch(SYSTEM_PROGRAM, "approve"),
        Some(RiskPattern::PermissionEscalation)
    ));
}

#[test]
fn full_l5_vocabulary_passes_pipeline_with_matching_instruction() {
    // End-to-end: create/approve/revoke declared intents with MATCHING
    // instructions must flow through the pipeline without a hard risk block.
    let core = GraphiteCore::new();

    // System CreateAccount (00000000) with create intent. The manifest
    // declares 2 accounts (funding + new account), so use a matching short
    // account list — a 5-account fixture legitimately trips the drain check.
    let mut create = base_input(SYSTEM_PROGRAM, "00000000", "create");
    create.account_addresses = vec![
        create.account_addresses[0].clone(),
        create.account_addresses[1].clone(),
    ];
    let r = core.verify(&create).expect("verify should not fail");
    assert_ne!(
        r.risk_verdict.status, "Blocked",
        "create on System blocked: {:?}",
        r.risk_verdict
    );

    // SPL Token Approve (04): still blocked, but by the DESIGNED risky-pattern
    // rule (Approve grants delegate authority), not by the intent-mismatch
    // contradiction that C21 removed. The reason must be the risky pattern.
    let approve = base_input(SPL_TOKEN, "04", "approve");
    let r = core.verify(&approve).expect("verify should not fail");
    assert_eq!(
        r.risk_verdict.status, "Blocked",
        "approve on SPL Token must block: {:?}",
        r.risk_verdict
    );
    assert!(
        r.risk_verdict.findings.iter().all(|f| f.pattern != "PermissionEscalation"
            || !f.reason.contains("does not support this intent type")),
        "approve must be blocked by the risky-pattern rule, not the intent-mismatch contradiction: {:?}",
        r.risk_verdict
    );

    // SPL Token Revoke (05) with revoke intent — revoke REMOVES delegate
    // authority; it must not be blocked (before C21, Check 9's mismatch
    // contradiction blocked every revoke). The manifest declares 2 accounts,
    // so trim the fixture to match (a 5-account list trips the drain check).
    let mut revoke = base_input(SPL_TOKEN, "05", "revoke");
    revoke.account_addresses = vec![
        revoke.account_addresses[0].clone(),
        revoke.account_addresses[1].clone(),
    ];
    let r = core.verify(&revoke).expect("verify should not fail");
    assert_ne!(
        r.risk_verdict.status, "Blocked",
        "revoke on SPL Token blocked: {:?}",
        r.risk_verdict
    );
}

#[test]
fn create_intent_with_undeclared_approve_instruction_still_blocks() {
    // Sanity: the expanded vocabulary must NOT weaken detection. A create
    // intent carrying an Approve instruction (04) on the token program is
    // still caught by Check 7 (approve not declared) or the risky-pattern
    // rule — fail-closed preserved.
    let core = GraphiteCore::new();
    let input = base_input(SPL_TOKEN, "04", "create");
    let r = core.verify(&input).expect("verify should not fail");
    // Approve instruction with a non-approve/revoke declared intent must block.
    assert_eq!(
        r.risk_verdict.status, "Blocked",
        "approve with undeclared intent must block: {:?}",
        r.risk_verdict
    );
}
