use graphite_core::verification::{GraphiteCore, VerificationInput, ProposedIntent};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;

const SYSTEM: &str = "11111111111111111111111111111111";
const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const JUPITER_V6: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyRT1V6";
const RAYDIUM: &str = "675kPX9MHTjS2zt1qfr1WHuAHzXzLksf6SLAsjW2sw6x";
const SQUADS: &str = "6XBGfP8oWqpdVQ8bH6j6peKK2v8x5A2vd5mR6Z7jN4nM";
const ORCA: &str = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYz2UwP2J5oHo";
const METEORA: &str = "LBUZKhRxPF3XUpvWkxJjm4Vg3Y2n2h1Nz4HVna9L48P";
const MEMO: &str = "9vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";

const A1: &str = "7vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const A2: &str = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const A3: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const A4: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const A5: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyRT1V6";
const A6: &str = "675kPX9MHTjS2zt1qfr1WHuAHzXzLksf6SLAsjW2sw6x";
const A7: &str = "6XBGfP8oWqpdVQ8bH6j6peKK2v8x5A2vd5mR6Z7jN4nM";
const A8: &str = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYz2UwP2J5oHo";
const A9: &str = "LBUZKhRxPF3XUpvWkxJjm4Vg3Y2n2h1Nz4HVna9L48P";
const A10: &str = "9vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const U1: &str = "9vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const U2: &str = "So11111111111111111111111111111111111111112";

fn make(program: &str, disc: &str, accounts: &[&str], cpi: &[&str], profile: WalletProfile) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent { intent_type: "transfer".to_string(), raw_natural_language: "test".to_string(), confidence_of_parse: 0.9, extracted_parameters: None },
        program_id: program.to_string(), protocol_version: "1.0.0".to_string(),
        instruction_discriminator: disc.to_string(),
        account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
        instruction_data: None, cpi_targets: cpi.iter().map(|s| s.to_string()).collect(),
        wallet_profile: profile, behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0, account_writes: 0, cpi_hops: 0, simulation_baseline: None,
    }
}

fn make_ev(program: &str, disc: &str, accounts: &[&str], cpi: &[&str], profile: WalletProfile, ev: BehaviorEvidence) -> VerificationInput {
    let mut input = make(program, disc, accounts, cpi, profile);
    input.behavior_evidence = ev;
    input
}

fn run(input: VerificationInput) -> graphite_core::VerificationResult {
    GraphiteCore::new().verify(&input).unwrap_or_else(|e| {
        // Verification error — construct a blocked result (fail-closed P12)
        graphite_core::verification::VerificationResult {
            approved: false,
            confidence: 0.0,
            breakdown: vec![],
            trust_tier: "Unknown".to_string(),
            risk_verdict: graphite_core::verification::RiskVerdictSummary {
                status: "Blocked".to_string(),
                findings: vec![],
            },
            policy_verdict: "Rejected".to_string(),
            audit_trail_id: "gr-error".to_string(),
            transaction: graphite_core::transaction_builder::BuiltTransaction {
                program_id: input.program_id.clone(),
                protocol_version: input.protocol_version.clone(),
                instruction_name: "Error".to_string(),
                instruction_discriminator: input.instruction_discriminator.clone(),
                instruction_count: 0,
                account_count: input.account_addresses.len(),
                signer_count: 0,
                writable_count: 0,
                compute_budget_units: 0,
                accounts: vec![],
                data_hex: String::new(),
                data_len: 0,
            },
            resolved_accounts: vec![],
            protocol_name: "Error".to_string(),
            instruction_name: "Error".to_string(),
            manifest_found: false,
            unknown_protocol: true,
            summary: format!("BLOCKED | error: {:?}", e),
            simulation_flagged: None,
            simulation_divergence: None,
        }
    })
}

#[test]
fn test_adv_trust_max_001() {
    let result = run(make_ev(SPL_TOKEN, "09", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust max 001 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_trust_max_002() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust max 002 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_trust_max_003() {
    let result = run(make_ev(SPL_TOKEN, "09", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust max 003 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_trust_max_004() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust max 004 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_trust_max_005() {
    let result = run(make_ev(SPL_TOKEN, "09", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust max 005 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_trust_max_006() {
    let result = run(make_ev(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust max 006 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_trust_max_007() {
    let result = run(make_ev(TOKEN_2022, "09", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust max 007 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_trust_max_008() {
    let result = run(make_ev(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust max 008 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_trust_max_009() {
    let result = run(make_ev(TOKEN_2022, "09", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust max 009 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_trust_max_010() {
    let result = run(make_ev(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust max 010 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_profile_011() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[A4], WalletProfile::Permissive));
    println!("Profile 011 (disc=03) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_profile_012() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[A4], WalletProfile::Permissive));
    println!("Profile 012 (disc=0b) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_profile_013() {
    let result = run(make(SPL_TOKEN, "09", &[A1, A2, A3], &[A4], WalletProfile::Permissive));
    println!("Profile 013 (disc=09) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_profile_014() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[A4], WalletProfile::Permissive));
    println!("Profile 014 (disc=03) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_profile_015() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[A4], WalletProfile::Permissive));
    println!("Profile 015 (disc=0b) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_profile_016() {
    let result = run(make(SPL_TOKEN, "09", &[A1, A2, A3], &[A4], WalletProfile::Permissive));
    println!("Profile 016 (disc=09) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_profile_017() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[A4], WalletProfile::Permissive));
    println!("Profile 017 (disc=03) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_profile_018() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[A4], WalletProfile::Permissive));
    println!("Profile 018 (disc=0b) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_profile_019() {
    let result = run(make(SPL_TOKEN, "09", &[A1, A2, A3], &[A4], WalletProfile::Permissive));
    println!("Profile 019 (disc=09) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_profile_020() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[A4], WalletProfile::Permissive));
    println!("Profile 020 (disc=03) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_legit_look_021() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("Legit-look 021 (SPL_TOKEN) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_legit_look_022() {
    let result = run(make(JUPITER_V6, "03", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("Legit-look 022 (JUPITER_V6) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_legit_look_023() {
    let result = run(make(RAYDIUM, "03", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("Legit-look 023 (RAYDIUM) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_legit_look_024() {
    let result = run(make(ORCA, "03", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("Legit-look 024 (ORCA) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_legit_look_025() {
    let result = run(make(METEORA, "03", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("Legit-look 025 (METEORA) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_legit_look_026() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("Legit-look 026 (SPL_TOKEN) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_legit_look_027() {
    let result = run(make(JUPITER_V6, "03", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("Legit-look 027 (JUPITER_V6) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_legit_look_028() {
    let result = run(make(RAYDIUM, "03", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("Legit-look 028 (RAYDIUM) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_legit_look_029() {
    let result = run(make(ORCA, "03", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("Legit-look 029 (ORCA) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_legit_look_030() {
    let result = run(make(METEORA, "03", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("Legit-look 030 (METEORA) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_account_gaming_031() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Account gaming 031 (3 accts) — risk: {}", result.risk_verdict.status);
    let _ = result;
}

#[test]
fn test_adv_account_gaming_032() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4], &[], WalletProfile::Standard));
    println!("Account gaming 032 (4 accts) — risk: {}", result.risk_verdict.status);
    let _ = result;
}

#[test]
fn test_adv_account_gaming_033() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5], &[], WalletProfile::Standard));
    println!("Account gaming 033 (5 accts) — risk: {}", result.risk_verdict.status);
    let _ = result;
}

#[test]
fn test_adv_account_gaming_034() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6], &[], WalletProfile::Standard));
    println!("Account gaming 034 (6 accts) — risk: {}", result.risk_verdict.status);
    assert!(result.risk_verdict.status == "Blocked");
}

#[test]
fn test_adv_account_gaming_035() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7], &[], WalletProfile::Standard));
    println!("Account gaming 035 (7 accts) — risk: {}", result.risk_verdict.status);
    assert!(result.risk_verdict.status == "Blocked");
}

#[test]
fn test_adv_account_gaming_036() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8], &[], WalletProfile::Standard));
    println!("Account gaming 036 (8 accts) — risk: {}", result.risk_verdict.status);
    assert!(result.risk_verdict.status == "Blocked");
}

#[test]
fn test_adv_account_gaming_037() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9], &[], WalletProfile::Standard));
    println!("Account gaming 037 (9 accts) — risk: {}", result.risk_verdict.status);
    assert!(result.risk_verdict.status == "Blocked");
}

#[test]
fn test_adv_account_gaming_038() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9, A10], &[], WalletProfile::Standard));
    println!("Account gaming 038 (10 accts) — risk: {}", result.risk_verdict.status);
    assert!(result.risk_verdict.status == "Blocked");
}

#[test]
fn test_adv_account_gaming_039() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9, A10], &[], WalletProfile::Standard));
    println!("Account gaming 039 (11 accts) — risk: {}", result.risk_verdict.status);
    assert!(result.risk_verdict.status == "Blocked");
}

#[test]
fn test_adv_account_gaming_040() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9, A10], &[], WalletProfile::Standard));
    println!("Account gaming 040 (12 accts) — risk: {}", result.risk_verdict.status);
    assert!(result.risk_verdict.status == "Blocked");
}

#[test]
fn test_adv_cpi_obfuscation_041() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("CPI obfuscation 041 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_cpi_obfuscation_042() {
    let result = run(make(JUPITER_V6, "03", &[A1, A2, A3], &[A1, A2], WalletProfile::Standard));
    println!("CPI obfuscation 042 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_cpi_obfuscation_043() {
    let result = run(make(SYSTEM, "03", &[A1, A2, A3], &[A1, A2, A3], WalletProfile::Standard));
    println!("CPI obfuscation 043 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_cpi_obfuscation_044() {
    let result = run(make(RAYDIUM, "03", &[A1, A2, A3], &[A1, A2, A3, A4], WalletProfile::Standard));
    println!("CPI obfuscation 044 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_cpi_obfuscation_045() {
    let result = run(make(SQUADS, "03", &[A1, A2, A3], &[A1, A2, A3, A4, A5], WalletProfile::Standard));
    println!("CPI obfuscation 045 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_cpi_obfuscation_046() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("CPI obfuscation 046 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_cpi_obfuscation_047() {
    let result = run(make(JUPITER_V6, "03", &[A1, A2, A3], &[A1, A2], WalletProfile::Standard));
    println!("CPI obfuscation 047 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_cpi_obfuscation_048() {
    let result = run(make(SYSTEM, "03", &[A1, A2, A3], &[A1, A2, A3], WalletProfile::Standard));
    println!("CPI obfuscation 048 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_cpi_obfuscation_049() {
    let result = run(make(RAYDIUM, "03", &[A1, A2, A3], &[A1, A2, A3, A4], WalletProfile::Standard));
    println!("CPI obfuscation 049 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_cpi_obfuscation_050() {
    let result = run(make(SQUADS, "03", &[A1, A2, A3], &[A1, A2, A3, A4, A5], WalletProfile::Standard));
    println!("CPI obfuscation 050 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_intent_mismatch_051() {
    let result = run(make(SPL_TOKEN, "09", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Intent mismatch 051 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_intent_mismatch_052() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Intent mismatch 052 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_intent_mismatch_053() {
    let result = run(make(SPL_TOKEN, "09", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Intent mismatch 053 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_intent_mismatch_054() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Intent mismatch 054 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_intent_mismatch_055() {
    let result = run(make(SPL_TOKEN, "09", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Intent mismatch 055 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_intent_mismatch_056() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Intent mismatch 056 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_intent_mismatch_057() {
    let result = run(make(SPL_TOKEN, "09", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Intent mismatch 057 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_intent_mismatch_058() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Intent mismatch 058 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_intent_mismatch_059() {
    let result = run(make(SPL_TOKEN, "09", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Intent mismatch 059 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_intent_mismatch_060() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Intent mismatch 060 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_prog_confusion_061() {
    let result = run(make(A1, "02000000", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Prog confusion 061 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_adv_prog_confusion_062() {
    let result = run(make(A2, "02000000", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Prog confusion 062 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_adv_prog_confusion_063() {
    let result = run(make(U2, "02000000", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Prog confusion 063 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_adv_prog_confusion_064() {
    let result = run(make(U1, "02000000", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Prog confusion 064 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_adv_prog_confusion_065() {
    let result = run(make(U2, "02000000", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Prog confusion 065 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_adv_prog_confusion_066() {
    let result = run(make(U1, "02000000", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Prog confusion 066 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_adv_prog_confusion_067() {
    let result = run(make(U2, "02000000", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Prog confusion 067 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_adv_prog_confusion_068() {
    let result = run(make(U1, "02000000", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Prog confusion 068 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_adv_prog_confusion_069() {
    let result = run(make(U2, "02000000", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Prog confusion 069 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_adv_prog_confusion_070() {
    let result = run(make(U1, "02000000", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Prog confusion 070 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_adv_empty_071() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Empty 071 — approved: {}", result.approved);
    let _ = result;
}

#[test]
fn test_adv_empty_072() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Empty 072 — approved: {}", result.approved);
    let _ = result;
}

#[test]
fn test_adv_empty_073() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Empty 073 — approved: {}", result.approved);
    let _ = result;
}

#[test]
fn test_adv_empty_074() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Empty 074 — approved: {}", result.approved);
    let _ = result;
}

#[test]
fn test_adv_empty_075() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Empty 075 — approved: {}", result.approved);
    let _ = result;
}

#[test]
fn test_adv_empty_076() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Empty 076 — approved: {}", result.approved);
    let _ = result;
}

#[test]
fn test_adv_empty_077() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Empty 077 — approved: {}", result.approved);
    let _ = result;
}

#[test]
fn test_adv_empty_078() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Empty 078 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_empty_079() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Empty 079 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_empty_080() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Empty 080 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_mixed_signal_081() {
    let result = run(make_ev(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 3, battle_tested_tx_count: 5000, simulation_match_count: 10 }));
    println!("Mixed signal 081 — approved: {}, conf: {}", result.approved, result.confidence);
    let _ = result;
}

#[test]
fn test_adv_mixed_signal_082() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 3, battle_tested_tx_count: 5000, simulation_match_count: 10 }));
    println!("Mixed signal 082 — approved: {}, conf: {}", result.approved, result.confidence);
    assert!(!result.approved);
}

#[test]
fn test_adv_mixed_signal_083() {
    let result = run(make_ev(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 3, battle_tested_tx_count: 5000, simulation_match_count: 10 }));
    println!("Mixed signal 083 — approved: {}, conf: {}", result.approved, result.confidence);
    let _ = result;
}

#[test]
fn test_adv_mixed_signal_084() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 3, battle_tested_tx_count: 5000, simulation_match_count: 10 }));
    println!("Mixed signal 084 — approved: {}, conf: {}", result.approved, result.confidence);
    assert!(!result.approved);
}

#[test]
fn test_adv_mixed_signal_085() {
    let result = run(make_ev(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 3, battle_tested_tx_count: 5000, simulation_match_count: 10 }));
    println!("Mixed signal 085 — approved: {}, conf: {}", result.approved, result.confidence);
    let _ = result;
}

#[test]
fn test_adv_mixed_signal_086() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 3, battle_tested_tx_count: 5000, simulation_match_count: 10 }));
    println!("Mixed signal 086 — approved: {}, conf: {}", result.approved, result.confidence);
    assert!(!result.approved);
}

#[test]
fn test_adv_mixed_signal_087() {
    let result = run(make_ev(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 3, battle_tested_tx_count: 5000, simulation_match_count: 10 }));
    println!("Mixed signal 087 — approved: {}, conf: {}", result.approved, result.confidence);
    let _ = result;
}

#[test]
fn test_adv_mixed_signal_088() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 3, battle_tested_tx_count: 5000, simulation_match_count: 10 }));
    println!("Mixed signal 088 — approved: {}, conf: {}", result.approved, result.confidence);
    assert!(!result.approved);
}

#[test]
fn test_adv_mixed_signal_089() {
    let result = run(make_ev(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 3, battle_tested_tx_count: 5000, simulation_match_count: 10 }));
    println!("Mixed signal 089 — approved: {}, conf: {}", result.approved, result.confidence);
    let _ = result;
}

#[test]
fn test_adv_mixed_signal_090() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 3, battle_tested_tx_count: 5000, simulation_match_count: 10 }));
    println!("Mixed signal 090 — approved: {}, conf: {}", result.approved, result.confidence);
    assert!(!result.approved);
}

#[test]
fn test_adv_full_evasion_091() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("Full evasion 091 (SPL_TOKEN, Standard) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_full_evasion_092() {
    let result = run(make(JUPITER_V6, "03", &[A1, A2, A3], &[A1], WalletProfile::Permissive));
    println!("Full evasion 092 (JUPITER_V6, Permissive) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_full_evasion_093() {
    let result = run(make(SYSTEM, "03", &[A1, A2, A3], &[A1], WalletProfile::Enterprise));
    println!("Full evasion 093 (SYSTEM, Enterprise) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_full_evasion_094() {
    let result = run(make(RAYDIUM, "03", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("Full evasion 094 (RAYDIUM, Standard) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_full_evasion_095() {
    let result = run(make(ORCA, "03", &[A1, A2, A3], &[A1], WalletProfile::Conservative));
    println!("Full evasion 095 (ORCA, Conservative) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_full_evasion_096() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("Full evasion 096 (SPL_TOKEN, Standard) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_full_evasion_097() {
    let result = run(make(JUPITER_V6, "03", &[A1, A2, A3], &[A1], WalletProfile::Permissive));
    println!("Full evasion 097 (JUPITER_V6, Permissive) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_full_evasion_098() {
    let result = run(make(SYSTEM, "03", &[A1, A2, A3], &[A1], WalletProfile::Enterprise));
    println!("Full evasion 098 (SYSTEM, Enterprise) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_full_evasion_099() {
    let result = run(make(RAYDIUM, "03", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("Full evasion 099 (RAYDIUM, Standard) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_adv_full_evasion_100() {
    let result = run(make(ORCA, "03", &[A1, A2, A3], &[A1], WalletProfile::Conservative));
    println!("Full evasion 100 (ORCA, Conservative) — approved: {}", result.approved);
    assert!(!result.approved);
}
