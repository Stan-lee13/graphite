//! A3-02 (2026-09-29 audit): a declared sibling that hands over an authority
//! is refused as the primary would be.
//!
//! Siblings are assessed with an empty intent (`assess_secondary_instructions`),
//! so the intent checks are off by design, and an authority change could hit
//! only Check 2's table and Check 10 ("the manifest declares a high-risk class
//! and no intent was declared"). Check 10 read `risk_class` from the manifest,
//! which was empty on, among others, loader `SetAuthority`,
//! `SetAuthorityChecked`, `Upgrade` and `Close`, Squads v4
//! `multisigSetConfigAuthority` and System `AssignWithSeed`; eight more
//! carried a class outside Check 10's vocabulary, which the loader accepted.
//!
//! The fix judges siblings through the same `security_class()` as primaries,
//! so the two cannot disagree: the extended `RISKY_PATTERNS` and Check 2b's
//! derived `authority_change` class apply to both. Manifest validation now
//! refuses a `risk_class` outside `RISK_CLASSES`, and the seed manifests
//! carrying out-of-vocabulary classes were retagged (the lint is in
//! `audit_a3_manifest_lint.rs`).
//!
//! The controls pin that an SPL `SetAuthority` sibling and a Stake `Authorize`
//! sibling are Blocked. The attacks pin that loader `SetAuthority`,
//! `SetAuthorityChecked` and Squads `multisigSetConfigAuthority` siblings
//! beside a 0.001 SOL transfer are Blocked.
//! `every_sibling_authority_selector_needs_a_high_risk_class` checks over the
//! loaded registry that every instruction whose name says it changes an
//! authority is judged by a class the Risk Engine acts on.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::simulation_integrity::ComputeBaseline;
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

const SYSTEM: &str = "11111111111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const LOADER_V3: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const SQUADS: &str = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";

const VICTIM: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const FRIEND: &str = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7";
const PROGRAM_DATA: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const MULTISIG: &str = "3npQNsA9S1K9xJ9gTYn1BZu2xw2sBvZK9QG4pLkXVcBz";
const ATTACKER: &str = "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx";

/// A benign 0.001 SOL System transfer, the primary the agent asked for.
fn transfer_with_sibling(sibling: TransactionInstruction) -> VerificationInput {
    let mut data = vec![2u8, 0, 0, 0];
    data.extend_from_slice(&1_000_000u64.to_le_bytes());
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send 0.001 SOL to my friend".to_string(),
            confidence_of_parse: 1.0,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: String::new(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![VICTIM.to_string(), FRIEND.to_string()],
        instruction_data: Some(data),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![sibling],
        cpi_trace: None,
        real_account_metas: vec![],
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        state_diff: None,
    }
}

fn sibling(program: &str, disc: &str, accounts: &[&str]) -> TransactionInstruction {
    TransactionInstruction {
        program_id: program.to_string(),
        instruction_discriminator: disc.to_string(),
        account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
        cpi_targets: vec![],
    }
}

fn core_with_system_samples() -> GraphiteCore {
    let core = GraphiteCore::new();
    core.seed_simulation_baseline(
        SYSTEM,
        ComputeBaseline {
            mean_compute_units: 450.0,
            std_compute_units: 50.0,
            sample_count: 3,
            ..Default::default()
        },
    )
    .unwrap();
    core
}

#[test]
fn control_an_spl_set_authority_sibling_is_blocked() {
    let core = GraphiteCore::new();
    let mut disc = String::from("0602");
    disc.push_str("01");
    let r = core
        .verify(&transfer_with_sibling(sibling(
            TOKEN,
            &disc,
            &[PROGRAM_DATA, VICTIM],
        )))
        .unwrap();
    assert_eq!(r.risk_verdict.status, "Blocked", "{:?}", r.risk_verdict);
}

#[test]
fn control_a_stake_authorize_sibling_is_blocked_by_check_10() {
    // Stake Authorize is tagged risk_class "authority" (Check 10), and is in
    // RISKY_PATTERNS since the A3-01 fix (Check 2).
    let core = GraphiteCore::new();
    let r = core
        .verify(&transfer_with_sibling(sibling(
            "Stake11111111111111111111111111111111111111",
            "01000000",
            &[
                PROGRAM_DATA,
                "SysvarC1ock11111111111111111111111111111111",
                VICTIM,
            ],
        )))
        .unwrap();
    assert_eq!(r.risk_verdict.status, "Blocked", "{:?}", r.risk_verdict);
}

#[test]
fn attack_loader_set_authority_sibling_is_blocked() {
    let core = core_with_system_samples();
    let r = core
        .verify(&transfer_with_sibling(sibling(
            LOADER_V3,
            "04000000",
            &[PROGRAM_DATA, VICTIM, ATTACKER],
        )))
        .unwrap();
    assert_eq!(
        r.risk_verdict.status, "Blocked",
        "a sibling BPF-Upgradeable SetAuthority (upgrade authority -> attacker) beside a 0.001 SOL \
         transfer must be refused; got risk={:?} approved={} conf={:.3}",
        r.risk_verdict,
        r.approved,
        r.confidence
    );
    assert!(!r.approved);
}

#[test]
fn attack_loader_set_authority_checked_sibling_is_blocked() {
    let core = GraphiteCore::new();
    let r = core
        .verify(&transfer_with_sibling(sibling(
            LOADER_V3,
            "07000000",
            &[PROGRAM_DATA, VICTIM, ATTACKER],
        )))
        .unwrap();
    assert_eq!(r.risk_verdict.status, "Blocked", "{:?}", r.risk_verdict);
}

#[test]
fn attack_squads_set_config_authority_sibling_is_blocked() {
    // multisigSetConfigAuthority: [multisig(w), configAuthority(s), rentPayer(s,w), systemProgram]
    let core = GraphiteCore::new();
    let r = core
        .verify(&transfer_with_sibling(sibling(
            SQUADS,
            "8f5dc78f5ca9c1e8",
            &[MULTISIG, VICTIM, VICTIM, SYSTEM],
        )))
        .unwrap();
    assert_eq!(
        r.risk_verdict.status, "Blocked",
        "a sibling Squads multisigSetConfigAuthority must be refused; got {:?}",
        r.risk_verdict
    );
}

#[test]
fn every_sibling_authority_selector_needs_a_high_risk_class() {
    // The structural root cause, stated as a manifest invariant over the
    // loaded registry: every instruction whose NAME says it changes an
    // authority/admin/owner must carry a class Check 10 acts on.
    let reg = graphite_core::load_seed_manifests();
    let high = ["drain", "authority", "withdraw", "mint", "close"];
    let mut missing = Vec::new();
    for m in reg.list() {
        for ix in &m.instructions {
            let n = ix.name.to_lowercase();
            let names_authority = n.contains("setauthority")
                || n.contains("set_authority")
                || n.contains("setconfigauthority")
                || n.contains("updateadmin")
                || n.contains("update_admin")
                || n.contains("transfer_owner")
                || n.contains("assignwithseed")
                || n.contains("setdelegatedfeeauthority");
            // The class the Risk Engine judges by: the manifest's tag, raised
            // to `authority_change` when the name says so (A3-02 fix).
            let class = ix.security_class();
            if names_authority
                && !high.contains(&class)
                && class != graphite_core::manifest::AUTHORITY_CHANGE_CLASS
            {
                missing.push(format!(
                    "{}:{} ({:?})",
                    m.protocol.name, ix.name, ix.risk_class
                ));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "authority-changing instructions Check 10 cannot see: {missing:#?}"
    );
}
