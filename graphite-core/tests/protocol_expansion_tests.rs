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

// C56: the five newly onboarded protocols (verified executable on mainnet
// 2026-08-12; see scripts/build_new_manifests.py).
const RAYDIUM_CLMM: &str = "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK";
const RAYDIUM_CPMM: &str = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C";
const MARINADE: &str = "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD";
const SPL_STAKE_POOL: &str = "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy";
const ORCA_TS_V2: &str = "9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP";

fn dca_input(discriminator: &str, intent: &str) -> VerificationInput {
    // Jupiter DCA layouts carry 12-15 accounts per the official IDL (C52).
    let mut input = base_input(JUPITER_DCA, discriminator, intent);
    while input.account_addresses.len() < 15 {
        input
            .account_addresses
            .push("4rQz2f4Wc1y7DpQ8v6mW2nN5uM3sR9bHjC1kTv8XwYdL".to_string());
    }
    input
}

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
        transaction_instructions: vec![],
        cpi_trace: None,
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
    }
}

#[test]
fn all_new_manifests_are_loaded_and_instruction_surfaces_parse() {
    let registry = load_seed_manifests();
    assert_eq!(registry.list().len(), 33, "expected 33 seed manifests (22 + Phoenix, OpenBook V2, Switchboard, Jupiter Limit, Solend, Marginfi + C56: Raydium CLMM/CPMM, Marinade, SPL Stake Pool, Orca TokenSwap V2)");
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
    let input = dca_input("16072162a8b722f3", "close");
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
fn c56_new_protocols_accept_their_native_intents() {
    // Marinade + SPL Stake Pool serve the "stake" intent (liquid staking).
    assert!(
        detect_intent_program_mismatch(MARINADE, "stake").is_none(),
        "Marinade must accept the stake intent"
    );
    assert!(
        detect_intent_program_mismatch(SPL_STAKE_POOL, "stake").is_none(),
        "SPL Stake Pool must accept the stake intent"
    );
    // Staking programs are not swap programs.
    assert!(matches!(
        detect_intent_program_mismatch(MARINADE, "swap"),
        Some(RiskPattern::PermissionEscalation)
    ));
    // The three new DEXes serve the swap intent.
    for id in [RAYDIUM_CLMM, RAYDIUM_CPMM, ORCA_TS_V2] {
        assert!(
            detect_intent_program_mismatch(id, "swap").is_none(),
            "{id} must accept the swap intent"
        );
        // ... and none of them is a staking program.
        assert!(matches!(
            detect_intent_program_mismatch(id, "stake"),
            Some(RiskPattern::PermissionEscalation)
        ));
    }
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
    // C24: Metaplex is Shank-derived — CreateMetadataAccountV3 = u8 33 = "21"
    // (the previous 8-byte value was never observed on-chain).
    let input = base_input(METAPLEX, "21", "transfer");
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
        manifest_risk_class: String::new(),
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
        manifest_risk_class: String::new(),
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

/// C22.3 — Jupiter V6 on-chain discriminator re-verification (2026-08-09).
///
/// Corrected methodology: instruction data in `getTransaction` JSON encoding is
/// base58 (not base64). Under that decoding, route_v2 = bb64facc31c4af14 is
/// CONFIRMED on-chain (pinned fixture sig 57TAjPZXt49F9rSVZNEu… slot
/// 438012579, SUCCESS; live txs the same day). The real bug found was the
/// C18 camelCase disease: 16 old-era entries carried
/// sha256("global:" + camelCaseName) hashes that never matched the deployed
/// program; they now carry the program's snake_case convention, with
/// sharedAccountsRoute = c1209b3341d69c81, setTokenLedger = e455b9704e4f4d02,
/// routeWithTokenLedger = 96564774a75d0e68 verified on-chain. These pins make
/// the bug class fail loudly on recurrence.
#[test]
fn jupiter_discriminators_pin_onchain_verified_values() {
    let registry = load_seed_manifests();
    let jup = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
    let m = registry
        .get(jup)
        .unwrap_or_else(|| panic!("jupiter manifest must load"));
    // route_v2: on-chain confirmed (fixture + live txs).
    let route_v2 = m
        .instructions
        .iter()
        .find(|ix| ix.name == "route_v2")
        .expect("route_v2 must exist");
    assert_eq!(route_v2.discriminator, "bb64facc31c4af14");
    // Old-era entries whose snake_case values were verified on-chain.
    for (name, want) in [
        ("sharedAccountsRoute", "c1209b3341d69c81"),
        ("setTokenLedger", "e455b9704e4f4d02"),
        ("routeWithTokenLedger", "96564774a75d0e68"),
    ] {
        let ix = m
            .instructions
            .iter()
            .find(|ix| ix.name == name)
            .unwrap_or_else(|| panic!("{name} must exist"));
        assert_eq!(ix.discriminator, want, "{name} (C22.3 on-chain verified)");
    }
    // The old camelCase-hashed values must NOT resolve to any active entry.
    for (name, camel) in [
        ("sharedAccountsRoute", "5703feb8e7573909"),
        ("setTokenLedger", "a015bd07dd7f35e4"),
        ("routeWithTokenLedger", "34650f14745e8de8"),
    ] {
        assert!(
            registry.find_instruction(jup, camel).is_none(),
            "camelCase hash of {name} must not resolve (C22.3)"
        );
    }
    // A verified value resolves and passes the pipeline as a swap (route_v2 is
    // variable-accounted, so the 5-account base input satisfies it).
    let core = GraphiteCore::new();
    let r = core
        .verify(&base_input(jup, "bb64facc31c4af14", "swap"))
        .expect("verify must not fail");
    assert_eq!(
        r.risk_verdict.status, "Clear",
        "known Jupiter route with swap intent must pass risk: {:?}",
        r.risk_verdict
    );
}

/// The pinned real-mainnet Jupiter fixture's actual instruction discriminator
/// (base58-decoded — the JSON RPC encoding is base58, not base64) must resolve
/// in the manifest, i.e. corpus ingestion of a REAL Jupiter transaction hits
/// the known-instruction path, not unknown-protocol mode.
#[test]
fn jupiter_pinned_fixture_discriminator_resolves_in_manifest() {
    let raw = std::fs::read_to_string("tests/fixtures/real_mainnet_jup.json")
        .expect("pinned jup fixture must exist");
    let tx: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let msg = tx["transaction"]["message"].clone();
    let keys: Vec<String> = msg["accountKeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| {
            k.as_str()
                .map(|s| s.to_string())
                .unwrap_or_else(|| k["pubkey"].as_str().unwrap().to_string())
        })
        .collect();
    let jup = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
    let mut fixture_disc = None;
    for ix in msg["instructions"].as_array().unwrap() {
        let pid_idx = ix["programIdIndex"].as_u64().unwrap() as usize;
        if keys[pid_idx] == jup {
            let data_b58 = ix["data"].as_str().unwrap_or("");
            let bytes = graphite_core::solana_types::base58_decode(data_b58)
                .expect("fixture instruction data must be base58");
            fixture_disc = Some(hex::encode(&bytes[..bytes.len().min(8)]));
        }
    }
    let disc = fixture_disc.expect("fixture must contain a Jupiter instruction");
    assert_eq!(
        disc, "bb64facc31c4af14",
        "pinned fixture must carry route_v2 (C22.3 base58 decode)"
    );
    let registry = load_seed_manifests();
    let resolved = registry.find_instruction(jup, &disc);
    assert!(
        resolved.is_some(),
        "real fixture discriminator {disc} must resolve in the manifest"
    );
}

/// C22.4 — Jupiter DCA discriminator re-verification (2026-08-09).
///
/// The previous DCA table (ee26b3c8…, 459dd6dd…, 131cb5db…, …) was never
/// observed on-chain: it was produced by base64-decoding base58 instruction
/// data (the same decode artifact class as the Jupiter V6 C22.3 finding). An
/// on-chain census of real DCA txs (base58-correct decode) shows the deployed
/// program is STANDARD ANCHOR: initiate_flash_fill = 8fcd03bfa2d7f531,
/// fulfill_flash_fill = 7340e24e21d369a2, transfer = a334c8e78c0345ba all
/// observed live; the rest follow sha256("global:" + snake_case)[:8]. The three
/// fill-path instructions were previously MISSING entirely — dominant live DCA
/// traffic (keeper fills) was falling to unknown-protocol mode. These pins make
/// the corruption fail loudly on recurrence.
#[test]
fn jupiter_dca_discriminators_pin_onchain_verified_values() {
    let registry = load_seed_manifests();
    let m = registry
        .get(JUPITER_DCA)
        .unwrap_or_else(|| panic!("jupiter dca manifest must load"));
    let get = |name: &str| -> String {
        m.instructions
            .iter()
            .find(|ix| ix.name == name)
            .unwrap_or_else(|| panic!("{name} must exist"))
            .discriminator
            .clone()
    };
    // Observed live on-chain (base58-correct decode of real fill txs).
    assert_eq!(get("initiateFlashFill"), "8fcd03bfa2d7f531");
    assert_eq!(get("fulfillFlashFill"), "7340e24e21d369a2");
    assert_eq!(get("transfer"), "a334c8e78c0345ba");
    // Snake_case Anchor convention for the rest (deployed program is standard
    // Anchor; the old camelCase/corrupted values were never observed).
    assert_eq!(get("openDca"), "2441b93601d264a3");
    assert_eq!(get("openDcaV2"), "8e772b6da2340bb1");
    assert_eq!(get("closeDca"), "16072162a8b722f3");
    assert_eq!(get("deposit"), "f223c68952e1f2b6");
    assert_eq!(get("withdraw"), "b712469c946da122");
    assert_eq!(get("withdrawFees"), "c6d4ab6d90d7ae59");
    assert_eq!(get("endAndClose"), "537da645f7fc6785");
    // The OLD corrupted values must NOT resolve to any active entry.
    for stale in [
        "ee26b3c80e7dc30b",
        "459dd6ddd29d32ea",
        "131cb5dbd74f7e19",
        "478de837bcb934f6",
        "1444d06d0075b0ab",
        "2a54d7277fa6589b",
        "f4eba28483c2ce7d",
    ] {
        assert!(
            registry.find_instruction(JUPITER_DCA, stale).is_none(),
            "stale discriminator {stale} must not resolve (C22.4)"
        );
    }
    // A corrected value resolves and passes the pipeline as a close.
    let core = GraphiteCore::new();
    let r = core
        .verify(&dca_input("16072162a8b722f3", "close"))
        .expect("verify must not fail");
    assert_ne!(
        r.risk_verdict.status, "Blocked",
        "known DCA close must not hard-block: {:?}",
        r.risk_verdict
    );
    // The dominant live traffic (keeper fills) now resolves as known protocol.
    for fill in ["8fcd03bfa2d7f531", "7340e24e21d369a2", "a334c8e78c0345ba"] {
        assert!(
            registry.find_instruction(JUPITER_DCA, fill).is_some(),
            "live fill discriminator {fill} must resolve (C22.4)"
        );
    }
}

/// C24/C25 — Orca Whirlpools discriminator ground truth (2026-08-09).
///
/// C24 corrected 23 camelCase-hashed values to the deployed program's Anchor
/// snake_case convention. C25 then rebuilt the manifest against the deployed
/// program's OFFICIAL IDL (npm @orca-so/whirlpools, program v0.9.0): the 6
/// remaining "legacy" entries (updateFeeRate, transferPositionDelegate,
/// applyDelta, syncTickArray, closeAccount, closeConfigExtension) were
/// FABRICATED — they appear in neither the 2022-era deployed IDL (v0.1.0,
/// 25 instructions) nor the current deployed IDL (66 instructions), and the
/// orca-so/whirlpools git history has zero occurrences. The manifest now
/// covers the full 66-instruction deployed surface with the IDL's explicit
/// discriminator byte arrays.
#[test]
fn orca_discriminators_pin_onchain_verified_values() {
    let registry = load_seed_manifests();
    let orca = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";
    let m = registry
        .get(orca)
        .unwrap_or_else(|| panic!("orca manifest must load"));
    let get = |name: &str| -> String {
        m.instructions
            .iter()
            .find(|ix| ix.name == name)
            .unwrap_or_else(|| panic!("{name} must exist"))
            .discriminator
            .clone()
    };
    // C25: the manifest covers the FULL deployed surface (66 instructions).
    assert_eq!(
        m.instructions.len(),
        66,
        "Orca manifest must cover all 66 deployed instructions"
    );
    // Directly observed on-chain (base58-correct decode).
    assert_eq!(get("swap"), "f8c69e91e17587c8");
    assert_eq!(get("swapV2"), "2b04ed0b1ac91e62");
    assert_eq!(get("increaseLiquidityByTokenAmountsV2"), "effb097cd2c6352b");
    // Represent the confirmed Anchor convention from the deployed IDL.
    assert_eq!(get("increaseLiquidity"), "2e9cf3760dcdfbb2");
    assert_eq!(get("collectFees"), "a498cf631eba13b6");
    assert_eq!(get("openPosition"), "87802f4d0f98f031");
    // C25: the 6 fabricated instructions must be gone — they were never part
    // of the deployed program at any version.
    for fabricated in [
        "updateFeeRate",
        "transferPositionDelegate",
        "applyDelta",
        "syncTickArray",
        "closeAccount",
        "closeConfigExtension",
    ] {
        assert!(
            !m.instructions.iter().any(|ix| ix.name == fabricated),
            "fabricated instruction {fabricated} must not exist (C25)"
        );
    }
    // Every discriminator is a real deployed-IDL value (8-byte, snake_case
    // Anchor hash). The systemic camelCase guard covers hash convention; here
    // we additionally assert the previously-fabricated stale values are absent.
    for stale in [
        "07fd4e278db4d5f4", // increaseLiquidity (camelCase hash)
        "5f4d179a1629512c", // initializePool
        "72712de2b3ef6ae1", // swapV2
        "b179ad7e886ca3f0", // decreaseLiquidity
    ] {
        assert!(
            !m.instructions.iter().any(|ix| ix.discriminator == stale),
            "camelCase hash {stale} must not be stored (C24)"
        );
    }
    // A verified swap value passes the pipeline as a swap. Orca swap declares
    // 11 accounts (variable_accounts=true), so pad the fixture accordingly.
    let mut input = base_input(orca, "f8c69e91e17587c8", "swap");
    // Pad to the declared 11-account minimum with valid base58 pubkeys.
    for extra in [
        "9RGFwSryu7FvDaqHWFLrnvQHge7hc5chawhcSH7m8FVU",
        "DuFgLf6zzf2N9v3iT4NrkdTPDSD2xK52CCnx6Ag2ckTP",
        "12TcEygMYKNaXhPL7pNM9pB8xVq5ynpqURG7rXXJ8ULy",
        "Coxid3BVrSNeMjBNuR2h1JCXBUKvERNMpuDrBk6J1ksw",
        "BfQo77gHmKxUmbMXbZ9avLJuNQXDtUQ7DAf53SZFATeZ",
        "2dYfyhfoSoEApQL3iNqhHQso6waZjfH2rNtb9SiYS2FW",
    ] {
        input.account_addresses.push(extra.to_string());
    }
    let core = GraphiteCore::new();
    let r = core.verify(&input).expect("verify must not fail");
    assert_eq!(
        r.risk_verdict.status, "Clear",
        "known Orca swap with swap intent must pass risk: {:?}",
        r.risk_verdict
    );
}

/// C24 — Metaplex Token Metadata is Shank-derived, NOT Anchor (2026-08-09).
///
/// The previous 8-byte values (0fd902b83e0f4ee4, …) were never observed
/// on-chain — the old verification note claiming live observation was the same
/// fabricated-evidence class as C22.4/DCA. On-chain census (base58-correct)
/// observed instruction data starting 0x21 (=33, CreateMetadataAccountV3) and
/// 0x0f (=15, UpdateMetadataAccountV2). Per the Shank enum order in
/// mpl-token-metadata program/src/instruction/mod.rs: SignMetadata=7,
/// VerifyCollection=18, BurnNft=29. Discriminators are 1-byte hex; the
/// registry matches by prefix, so real "21…" data resolves to "21".
#[test]
fn metaplex_discriminators_are_shank_u8_values() {
    let registry = load_seed_manifests();
    let m = registry
        .get(METAPLEX)
        .unwrap_or_else(|| panic!("metaplex manifest must load"));
    let get = |name: &str| -> String {
        m.instructions
            .iter()
            .find(|ix| ix.name == name)
            .unwrap_or_else(|| panic!("{name} must exist"))
            .discriminator
            .clone()
    };
    // Shank u8 discriminators (enum order, 2 of 5 directly observed on-chain).
    assert_eq!(get("CreateMetadataAccountV3"), "21"); // 33, observed 0x21
    assert_eq!(get("UpdateMetadataAccountV2"), "0f"); // 15, observed 0x0f
    assert_eq!(get("SignMetadata"), "07"); // 7
    assert_eq!(get("VerifyCollection"), "12"); // 18
    assert_eq!(get("BurnNft"), "1d"); // 29
                                      // The old fabricated 8-byte values must NOT be stored in the manifest
                                      // table (checked directly — find_instruction is prefix-based, so
                                      // "0fd902b83e0f4ee4" legitimately prefix-matches the "0f" entry).
    for stale in [
        "0fd902b83e0f4ee4",
        "1ec413bd20e86291",
        "2eb5af436b292665",
        "941686a3459e71c9",
        "8fa1f495a95dbfae",
    ] {
        assert!(
            !m.instructions.iter().any(|ix| ix.discriminator == stale),
            "fabricated 8-byte discriminator {stale} must not be stored (C24)"
        );
    }
    // Real instruction data (u8 discriminator prefix) resolves via prefix match.
    assert!(registry
        .find_instruction(METAPLEX, "2112000000575954")
        .is_some());
    assert!(registry
        .find_instruction(METAPLEX, "0f00010000000000")
        .is_some());
}

/// C24 — systemic guard: NO manifest may carry a camelCase-hashed discriminator.
///
/// The C18 disease (sha256("global:" + camelCaseName) stored for an instruction
/// whose NAME is camelCase) recurred in Squads (C18), Jupiter V6 (C22.3), DCA
/// (C22.4), and Orca (C24) because each fix was scoped to one manifest. This
/// test scans every loaded manifest and fails on ANY camelCase-named
/// instruction whose discriminator equals the camelCase hash — the bug class
/// can no longer silently re-enter any manifest.
#[test]
fn no_manifest_discriminator_is_a_camelcase_anchor_hash() {
    use sha2::{Digest, Sha256};

    let registry = load_seed_manifests();
    for manifest in registry.list() {
        for ix in &manifest.instructions {
            // Only camelCase names can carry the disease (snake_case names have
            // identical camel/snake hashes). u8/u32-tagged programs use short
            // discriminators that never equal a 16-char hash.
            if ix.name == ix.name.to_lowercase() {
                continue;
            }
            let camel_hash = hex::encode(&Sha256::digest(format!("global:{}", ix.name))[..8]);
            assert_ne!(
                ix.discriminator, camel_hash,
                "C18 camelCase disease: {}:{} stores sha256(global:+camelCase)={} \
                 — an Anchor program hashes the SNAKE_CASE name, so this never \
                 matches the deployed program (C24 systemic guard)",
                manifest.protocol.name, ix.name, camel_hash
            );
        }
    }
}
