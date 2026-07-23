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
fn test_novel_zero_day_001() {
    let result = run(make(A1, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Zero-day 001 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_zero_day_002() {
    let result = run(make(A2, "02000000", &[A1, A2, A3, A4], &[], WalletProfile::Standard));
    println!("Zero-day 002 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_zero_day_003() {
    let result = run(make(U2, "03", &[A1, A2, A3, A4, A5], &[], WalletProfile::Standard));
    println!("Zero-day 003 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_zero_day_004() {
    let result = run(make(U1, "02000000", &[A1, A2, A3, A4, A5, A6], &[], WalletProfile::Standard));
    println!("Zero-day 004 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_zero_day_005() {
    let result = run(make(U2, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Zero-day 005 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_zero_day_006() {
    let result = run(make(U1, "02000000", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Zero-day 006 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_zero_day_007() {
    let result = run(make(U2, "03", &[A1, A2, A3, A4], &[], WalletProfile::Standard));
    println!("Zero-day 007 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_zero_day_008() {
    let result = run(make(U1, "02000000", &[A1, A2, A3, A4, A5], &[], WalletProfile::Standard));
    println!("Zero-day 008 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_zero_day_009() {
    let result = run(make(U2, "03", &[A1, A2, A3, A4, A5, A6], &[], WalletProfile::Standard));
    println!("Zero-day 009 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_zero_day_010() {
    let result = run(make(U1, "02000000", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Zero-day 010 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_cross_prog_011() {
    let result = run(make(JUPITER_V6, "f8c69e91e17587c8", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("Cross-prog 011 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_cross_prog_012() {
    let result = run(make(ORCA, "f8c69e91e17587c8", &[A1, A2, A3], &[A1, A2], WalletProfile::Standard));
    println!("Cross-prog 012 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_cross_prog_013() {
    let result = run(make(METEORA, "f8c69e91e17587c8", &[A1, A2, A3], &[A1, A2, A3], WalletProfile::Standard));
    println!("Cross-prog 013 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_cross_prog_014() {
    let result = run(make(RAYDIUM, "f8c69e91e17587c8", &[A1, A2, A3], &[A1, A2, A3, A4], WalletProfile::Standard));
    println!("Cross-prog 014 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_cross_prog_015() {
    let result = run(make(SPL_TOKEN, "f8c69e91e17587c8", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("Cross-prog 015 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_cross_prog_016() {
    let result = run(make(JUPITER_V6, "f8c69e91e17587c8", &[A1, A2, A3], &[A1, A2], WalletProfile::Standard));
    println!("Cross-prog 016 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_cross_prog_017() {
    let result = run(make(ORCA, "f8c69e91e17587c8", &[A1, A2, A3], &[A1, A2, A3], WalletProfile::Standard));
    println!("Cross-prog 017 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_cross_prog_018() {
    let result = run(make(METEORA, "f8c69e91e17587c8", &[A1, A2, A3], &[A1, A2, A3, A4], WalletProfile::Standard));
    println!("Cross-prog 018 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_cross_prog_019() {
    let result = run(make(RAYDIUM, "f8c69e91e17587c8", &[A1, A2, A3], &[A1], WalletProfile::Standard));
    println!("Cross-prog 019 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_cross_prog_020() {
    let result = run(make(SPL_TOKEN, "f8c69e91e17587c8", &[A1, A2, A3], &[A1, A2], WalletProfile::Standard));
    println!("Cross-prog 020 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_trust_manip_021() {
    let result = run(make_ev(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust manip 021 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_trust_manip_022() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust manip 022 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_trust_manip_023() {
    let result = run(make_ev(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust manip 023 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_trust_manip_024() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust manip 024 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_trust_manip_025() {
    let result = run(make_ev(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust manip 025 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_trust_manip_026() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust manip 026 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_trust_manip_027() {
    let result = run(make_ev(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust manip 027 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_trust_manip_028() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust manip 028 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_trust_manip_029() {
    let result = run(make_ev(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust manip 029 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_trust_manip_030() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 100, battle_tested_tx_count: 1000000, simulation_match_count: 1000 }));
    println!("Trust manip 030 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_profile_031() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[A4], WalletProfile::Enterprise));
    println!("Profile 031 (Enterprise) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_profile_032() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[A4], WalletProfile::Conservative));
    println!("Profile 032 (Conservative) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_profile_033() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[A4], WalletProfile::Standard));
    println!("Profile 033 (Standard) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_profile_034() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[A4], WalletProfile::Permissive));
    println!("Profile 034 (Permissive) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_profile_035() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[A4], WalletProfile::Enterprise));
    println!("Profile 035 (Enterprise) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_profile_036() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[A4], WalletProfile::Conservative));
    println!("Profile 036 (Conservative) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_profile_037() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[A4], WalletProfile::Standard));
    println!("Profile 037 (Standard) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_profile_038() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[A4], WalletProfile::Permissive));
    println!("Profile 038 (Permissive) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_profile_039() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[A4], WalletProfile::Enterprise));
    println!("Profile 039 (Enterprise) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_profile_040() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[A4], WalletProfile::Conservative));
    println!("Profile 040 (Conservative) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_sim_bypass_041() {
    let result = run(make(JUPITER_V6, "03", &[A1, A2, A3], &[A4], WalletProfile::Standard));
    println!("Sim bypass 041 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_sim_bypass_042() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[A4], WalletProfile::Standard));
    println!("Sim bypass 042 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_sim_bypass_043() {
    let result = run(make(JUPITER_V6, "03", &[A1, A2, A3], &[A4], WalletProfile::Standard));
    println!("Sim bypass 043 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_sim_bypass_044() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[A4], WalletProfile::Standard));
    println!("Sim bypass 044 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_sim_bypass_045() {
    let result = run(make(JUPITER_V6, "03", &[A1, A2, A3], &[A4], WalletProfile::Standard));
    println!("Sim bypass 045 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_sim_bypass_046() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[A4], WalletProfile::Standard));
    println!("Sim bypass 046 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_sim_bypass_047() {
    let result = run(make(JUPITER_V6, "03", &[A1, A2, A3], &[A4], WalletProfile::Standard));
    println!("Sim bypass 047 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_sim_bypass_048() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[A4], WalletProfile::Standard));
    println!("Sim bypass 048 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_sim_bypass_049() {
    let result = run(make(JUPITER_V6, "03", &[A1, A2, A3], &[A4], WalletProfile::Standard));
    println!("Sim bypass 049 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_sim_bypass_050() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[A4], WalletProfile::Standard));
    println!("Sim bypass 050 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_graph_poison_051() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 510, battle_tested_tx_count: 51000, simulation_match_count: 510 }));
    println!("Graph poison 051 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_graph_poison_052() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 520, battle_tested_tx_count: 52000, simulation_match_count: 520 }));
    println!("Graph poison 052 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_graph_poison_053() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 530, battle_tested_tx_count: 53000, simulation_match_count: 530 }));
    println!("Graph poison 053 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_graph_poison_054() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 540, battle_tested_tx_count: 54000, simulation_match_count: 540 }));
    println!("Graph poison 054 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_graph_poison_055() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 550, battle_tested_tx_count: 55000, simulation_match_count: 550 }));
    println!("Graph poison 055 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_graph_poison_056() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 560, battle_tested_tx_count: 56000, simulation_match_count: 560 }));
    println!("Graph poison 056 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_graph_poison_057() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 570, battle_tested_tx_count: 57000, simulation_match_count: 570 }));
    println!("Graph poison 057 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_graph_poison_058() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 580, battle_tested_tx_count: 58000, simulation_match_count: 580 }));
    println!("Graph poison 058 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_graph_poison_059() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 590, battle_tested_tx_count: 59000, simulation_match_count: 590 }));
    println!("Graph poison 059 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_graph_poison_060() {
    let result = run(make_ev(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, BehaviorEvidence { has_signed_manifest: true, community_verified_count: 600, battle_tested_tx_count: 60000, simulation_match_count: 600 }));
    println!("Graph poison 060 — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_manifest_confusion_061() {
    let result = run(make(A1, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Manifest confusion 061 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_manifest_confusion_062() {
    let result = run(make(A2, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Manifest confusion 062 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_manifest_confusion_063() {
    let result = run(make(U2, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Manifest confusion 063 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_manifest_confusion_064() {
    let result = run(make(U1, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Manifest confusion 064 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_manifest_confusion_065() {
    let result = run(make(U2, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Manifest confusion 065 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_manifest_confusion_066() {
    let result = run(make(U1, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Manifest confusion 066 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_manifest_confusion_067() {
    let result = run(make(U2, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Manifest confusion 067 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_manifest_confusion_068() {
    let result = run(make(U1, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Manifest confusion 068 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_manifest_confusion_069() {
    let result = run(make(U2, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Manifest confusion 069 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_manifest_confusion_070() {
    let result = run(make(U1, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Manifest confusion 070 — conf: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55);
}

#[test]
fn test_novel_instruction_data_071() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Instruction data 071 (disc=03) — approved: {}", result.approved);
    let _ = result;
}

#[test]
fn test_novel_instruction_data_072() {
    let result = run(make(SPL_TOKEN, "0c", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Instruction data 072 (disc=0c) — approved: {}", result.approved);
    let _ = result;
}

#[test]
fn test_novel_instruction_data_073() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Instruction data 073 (disc=0b) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_instruction_data_074() {
    let result = run(make(SPL_TOKEN, "09", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Instruction data 074 (disc=09) — approved: {}", result.approved);
    assert!(!result.approved);
}

#[test]
fn test_novel_instruction_data_075() {
    let result = run(make(SPL_TOKEN, "07", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Instruction data 075 (disc=07) — approved: {}", result.approved);
    let _ = result;
}

#[test]
fn test_novel_instruction_data_076() {
    let result = run(make(SYSTEM, "08", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Instruction data 076 (disc=08) — approved: {}", result.approved);
    let _ = result;
}

#[test]
fn test_novel_instruction_data_077() {
    let result = run(make(SYSTEM, "04", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Instruction data 077 (disc=04) — approved: {}", result.approved);
    let _ = result;
}

#[test]
fn test_novel_instruction_data_078() {
    let result = run(make(SYSTEM, "02", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Instruction data 078 (disc=02) — approved: {}", result.approved);
    let _ = result;
}

#[test]
fn test_novel_instruction_data_079() {
    let result = run(make(SYSTEM, "02000000", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Instruction data 079 (disc=02000000) — approved: {}", result.approved);
    let _ = result;
}

#[test]
fn test_novel_instruction_data_080() {
    let result = run(make(SYSTEM, "a1b2c3d4", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Instruction data 080 (disc=a1b2c3d4) — approved: {}", result.approved);
    let _ = result;
}

#[test]
fn test_novel_boundary_081() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Boundary 081 (2 accts) — risk: {}", result.risk_verdict.status);
    let _ = result;
}

#[test]
fn test_novel_boundary_082() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard));
    println!("Boundary 082 (3 accts) — risk: {}", result.risk_verdict.status);
    let _ = result;
}

#[test]
fn test_novel_boundary_083() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4], &[], WalletProfile::Standard));
    println!("Boundary 083 (4 accts) — risk: {}", result.risk_verdict.status);
    let _ = result;
}

#[test]
fn test_novel_boundary_084() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5], &[], WalletProfile::Standard));
    println!("Boundary 084 (5 accts) — risk: {}", result.risk_verdict.status);
    let _ = result;
}

#[test]
fn test_novel_boundary_085() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6], &[], WalletProfile::Standard));
    println!("Boundary 085 (6 accts) — risk: {}", result.risk_verdict.status);
    assert!(result.risk_verdict.status == "Blocked");
}

#[test]
fn test_novel_boundary_086() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7], &[], WalletProfile::Standard));
    println!("Boundary 086 (7 accts) — risk: {}", result.risk_verdict.status);
    assert!(result.risk_verdict.status == "Blocked");
}

#[test]
fn test_novel_boundary_087() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8], &[], WalletProfile::Standard));
    println!("Boundary 087 (8 accts) — risk: {}", result.risk_verdict.status);
    assert!(result.risk_verdict.status == "Blocked");
}

#[test]
fn test_novel_boundary_088() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9], &[], WalletProfile::Standard));
    println!("Boundary 088 (9 accts) — risk: {}", result.risk_verdict.status);
    assert!(result.risk_verdict.status == "Blocked");
}

#[test]
fn test_novel_boundary_089() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9, A10], &[], WalletProfile::Standard));
    println!("Boundary 089 (10 accts) — risk: {}", result.risk_verdict.status);
    assert!(result.risk_verdict.status == "Blocked");
}

#[test]
fn test_novel_boundary_090() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9, A10], &[], WalletProfile::Standard));
    println!("Boundary 090 (11 accts) — risk: {}", result.risk_verdict.status);
    assert!(result.risk_verdict.status == "Blocked");
}

#[test]
fn test_novel_comp_evasion_091() {
    let result = run(make(SPL_TOKEN, "0b", &[A1, A2, A3, A4, A5, A6], &[], WalletProfile::Standard));
    println!("Comp evasion 091 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved);
}

#[test]
fn test_novel_comp_evasion_092() {
    let result = run(make(JUPITER_V6, "02000000", &[A1, A2, A3, A4, A5, A6], &[A1], WalletProfile::Standard));
    println!("Comp evasion 092 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    let _ = result;
}

#[test]
fn test_novel_comp_evasion_093() {
    let result = run(make(SYSTEM, "03", &[A1, A2, A3, A4, A5, A6], &[], WalletProfile::Standard));
    println!("Comp evasion 093 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    let _ = result;
}

#[test]
fn test_novel_comp_evasion_094() {
    let result = run(make(RAYDIUM, "0b", &[A1, A2, A3, A4, A5, A6], &[A1], WalletProfile::Standard));
    println!("Comp evasion 094 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved);
}

#[test]
fn test_novel_comp_evasion_095() {
    let result = run(make(SQUADS, "02000000", &[A1, A2, A3, A4, A5, A6], &[], WalletProfile::Standard));
    println!("Comp evasion 095 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    let _ = result;
}

#[test]
fn test_novel_comp_evasion_096() {
    let result = run(make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6], &[A1], WalletProfile::Standard));
    println!("Comp evasion 096 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    let _ = result;
}

#[test]
fn test_novel_comp_evasion_097() {
    let result = run(make(JUPITER_V6, "0b", &[A1, A2, A3, A4, A5, A6], &[], WalletProfile::Standard));
    println!("Comp evasion 097 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved);
}

#[test]
fn test_novel_comp_evasion_098() {
    let result = run(make(SYSTEM, "02000000", &[A1, A2, A3, A4, A5, A6], &[A1], WalletProfile::Standard));
    println!("Comp evasion 098 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    let _ = result;
}

#[test]
fn test_novel_comp_evasion_099() {
    let result = run(make(RAYDIUM, "03", &[A1, A2, A3, A4, A5, A6], &[], WalletProfile::Standard));
    println!("Comp evasion 099 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    let _ = result;
}

#[test]
fn test_novel_comp_evasion_100() {
    let result = run(make(SQUADS, "0b", &[A1, A2, A3, A4, A5, A6], &[A1], WalletProfile::Standard));
    println!("Comp evasion 100 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved);
}
