//! R30 (G-05): the thirteen manifests that name fewer than 90% of the
//! instructions their program runs on mainnet (`docs/protocol-coverage.md`,
//! the "Named" column) must never pass an instruction they do not describe as
//! described coverage.
//!
//! What an undescribed instruction gets, from the code (verification.rs):
//! as the primary it takes the `Unknown` trust tier (A3-04), which the P6
//! ceiling caps and no built-in profile's tier floor admits; as a declared
//! sibling it is a Risk Engine block (external review R3). These tests hold
//! both for each of the thirteen programs, under every built-in profile, with
//! the program's evidence EARNED — so the refusal is the undescribed
//! instruction's, not an engine that approves nothing. A described instruction
//! of the same program, under the same engine, is the control.

use graphite_core::manifest::load_seed_manifests;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::{Behavior, BehaviorEvidence, TrustTier};
use graphite_core::simulation_integrity::ComputeBaseline;
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

/// `docs/protocol-coverage.md`, every row whose Named share is below 90%
/// (rendered from `scripts/out/inventory_census.json` and the evidence file).
const LOW_DECODE: &[(&str, &str)] = &[
    ("Zeta", "ZETAxsqBRek56DhiGXrn75yj2NHU3aYUnxvHXpkf3aD"),
    ("Pump Fees", "pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ"),
    ("Main", "CWgkFB7ngUc9cGD1LryyhP7h6xYWtwrAjhSKKCoR1gkz"),
    ("Oridion", "ord1qJZ3DB52s9NoG8nuoacW85aCyNvECa5kAqcBVBu"),
    ("Ocr2", "cjg3oHmg9uuPsP8D6g29NWvhySJkdYdAo9D25PRbKXJ"),
    ("Bubblegum", "BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY"),
    ("Coinflow", "FD1amxhTsDpwzoVX41dxp2ygAESURV2zdUACzxM1Dfw9"),
    ("Doorcash", "67g5HhrzQ2eqqEDJTEogHGBjAfwRD8evD3wg6LTDV8GK"),
    (
        "Account Compression",
        "compr6CUsB5m2jS4Y3831ztGSTnDpnKJTKS95d64XVq",
    ),
    ("Rush", "RUsHe5Kt19Koe2stiQuTRS4wkev5QjY5AyatokniGeY"),
    (
        "Merkle Distributor",
        "MErKy6nZVoVAkryxAejJz2juifQ4ArgLgHmaJCQkU7N",
    ),
    ("Timelock", "strmRqUCoQUgGUan5YhzUZa6KqdzwX5L6FpUxfmKg5m"),
    (
        "Light System Program",
        "SySTEM1eSU2p4BGQfQpimFEWWSC1XDFeun3Nqzz3rT7",
    ),
];

const SYSTEM: &str = "11111111111111111111111111111111";
const A: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const B: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const C: &str = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7";

const PROFILES: [WalletProfile; 4] = [
    WalletProfile::Gaming,
    WalletProfile::TradingBot,
    WalletProfile::Treasury,
    WalletProfile::Enterprise,
];

/// Eight bytes no instruction of `program` is described by: no manifest
/// discriminator is a prefix of them (and they are no prefix of one).
fn undescribed_selector(program: &str) -> Vec<u8> {
    let reg = load_seed_manifests();
    let m = reg.get(program).expect("a seed manifest");
    for first in (0u8..=255).rev() {
        let candidate = [first, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88];
        let hex = hex::encode(candidate);
        if m.instructions.iter().all(|ix| {
            let d = ix.discriminator.to_lowercase();
            d.is_empty() || !(hex.starts_with(&d) || d.starts_with(&hex))
        }) {
            return candidate.to_vec();
        }
    }
    panic!("{program}: no free selector");
}

/// Earned evidence for `program` — operator seeding, never request input.
fn earned_core(programs: &[&str]) -> GraphiteCore {
    let mut core = GraphiteCore::new();
    for program in programs {
        core.seed_simulation_baseline(
            program,
            ComputeBaseline {
                mean_compute_units: 150.0,
                std_compute_units: 1.0,
                sample_count: 50,
                mean_account_writes: 2.0,
                std_account_writes: 0.5,
                mean_cpi_hops: 0.0,
                std_cpi_hops: 0.1,
                ..Default::default()
            },
        )
        .unwrap();
        core.seed_behavior(Behavior {
            program_id: program.to_string(),
            version: "1.0.0".to_string(),
            expected_state_changes: vec!["debits accounts.from by amount".to_string()],
            allowed_cpis: vec![],
            trust_tier: TrustTier::Unknown, // recomputed by append (P7)
            evidence: BehaviorEvidence {
                has_signed_manifest: true,
                community_verified_count: 2,
                battle_tested_tx_count: 1000,
                simulation_match_count: 100,
            },
            quarantined: false,
            quarantine_reason: None,
            first_manifest_unvalidated: false,
        })
        .unwrap();
    }
    core
}

fn input(
    program: &str,
    intent: &str,
    data: Vec<u8>,
    accounts: Vec<String>,
    profile: WalletProfile,
) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: intent.to_string(),
            raw_natural_language: String::new(),
            confidence_of_parse: 1.0,
            extracted_parameters: None,
        },
        program_id: program.to_string(),
        protocol_version: String::new(),
        instruction_discriminator: hex::encode(&data[..data.len().min(8)]),
        account_addresses: accounts,
        instruction_data: Some(data),
        cpi_targets: vec![],
        wallet_profile: profile,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        real_account_metas: vec![],
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        state_diff: None,
    }
}

fn three_accounts() -> Vec<String> {
    vec![A.to_string(), B.to_string(), C.to_string()]
}

/// The list itself is what the coverage page says it is: thirteen programs,
/// each a shipped manifest whose tier the evidence file lowered.
#[test]
fn the_thirteen_are_shipped_manifests() {
    let reg = load_seed_manifests();
    assert_eq!(LOW_DECODE.len(), 13);
    for (name, program) in LOW_DECODE {
        let m = reg
            .get(program)
            .unwrap_or_else(|| panic!("{name} {program} has no seed manifest"));
        assert_ne!(
            m.trust_tier, "BattleTested",
            "{name}: a manifest naming under 90% of observed instructions must not load as BattleTested"
        );
    }
}

/// As the primary: refused under every built-in profile, with the tier the
/// undescribed instruction earns (Unknown) as the cause.
#[test]
fn an_undescribed_primary_of_a_low_decode_manifest_is_never_approved() {
    for (name, program) in LOW_DECODE {
        let core = earned_core(&[program]);
        let mut data = undescribed_selector(program);
        data.extend_from_slice(&[0u8; 16]);
        for profile in PROFILES {
            let r = core
                .verify(&input(
                    program,
                    "transfer",
                    data.clone(),
                    three_accounts(),
                    profile,
                ))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(r.manifest_found, "{name}");
            assert_eq!(r.instruction_name, "unknown_instruction", "{name}");
            assert!(
                !r.approved,
                "{name} {profile:?}: an instruction the manifest does not describe was approved: {}",
                r.summary
            );
            assert_eq!(
                r.trust_tier, "Unknown",
                "{name} {profile:?}: the undescribed instruction must take the Unknown tier"
            );
            assert!(
                r.confidence <= 0.55,
                "{name}: the P6 ceiling applies, got {}",
                r.confidence
            );
        }
    }
}

/// As a declared sibling of an approvable System transfer: a Risk Engine
/// block that names the undescribed instruction.
#[test]
fn an_undescribed_sibling_of_a_low_decode_manifest_is_blocked() {
    for (name, program) in LOW_DECODE {
        let core = earned_core(&[SYSTEM, program]);
        let mut transfer = 2u32.to_le_bytes().to_vec();
        transfer.extend_from_slice(&1_000u64.to_le_bytes());
        let primary = || {
            input(
                SYSTEM,
                "transfer",
                transfer.clone(),
                vec![A.to_string(), B.to_string()],
                WalletProfile::Gaming,
            )
        };
        // Control: the primary alone is approved by this engine.
        let alone = core.verify(&primary()).unwrap();
        assert!(alone.approved, "control: {}", alone.summary);

        let mut with_sibling = primary();
        with_sibling.transaction_instructions = vec![
            TransactionInstruction {
                program_id: SYSTEM.to_string(),
                instruction_discriminator: hex::encode(&transfer[..8]),
                account_addresses: vec![A.to_string(), B.to_string()],
                cpi_targets: vec![],
            },
            TransactionInstruction {
                program_id: program.to_string(),
                instruction_discriminator: hex::encode(undescribed_selector(program)),
                account_addresses: three_accounts(),
                cpi_targets: vec![],
            },
        ];
        let r = core.verify(&with_sibling).unwrap();
        assert!(!r.approved, "{name}: {}", r.summary);
        assert!(
            r.risk_verdict.findings.iter().any(|f| f
                .reason
                .contains("is not described by the program's manifest")),
            "{name}: the block must name the undescribed sibling: {:?}",
            r.risk_verdict.findings
        );
    }
}
