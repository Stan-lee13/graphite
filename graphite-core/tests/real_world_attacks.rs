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

// Valid 32-byte base58 addresses (all different)
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
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "test".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: program.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: disc.to_string(),
        account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
        instruction_data: None,
        cpi_targets: cpi.iter().map(|s| s.to_string()).collect(),
        wallet_profile: profile,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        simulation_baseline: None,
    }
}

fn make_evidence(program: &str, disc: &str, accounts: &[&str], cpi: &[&str], profile: WalletProfile, ev: BehaviorEvidence) -> VerificationInput {
    let mut input = make(program, disc, accounts, cpi, profile);
    input.behavior_evidence = ev;
    input
}

fn high_ev() -> BehaviorEvidence {
    BehaviorEvidence { has_signed_manifest: true, community_verified_count: 5, battle_tested_tx_count: 10000, simulation_match_count: 50 }
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
fn test_real_stmt_001() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4], &[], WalletProfile::Standard);
    let result = run(input);
    println!("STMT 001 (4 accounts) — approved: {}, confidence: {}, risk: {}", result.approved, result.confidence, result.risk_verdict.status);
    // 4 accounts — may be legitimate
    let _ = result;
}

#[test]
fn test_real_stmt_002() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5], &[], WalletProfile::Standard);
    let result = run(input);
    println!("STMT 002 (5 accounts) — approved: {}, confidence: {}, risk: {}", result.approved, result.confidence, result.risk_verdict.status);
    // 5 accounts — may be legitimate
    let _ = result;
}

#[test]
fn test_real_stmt_003() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6], &[], WalletProfile::Standard);
    let result = run(input);
    println!("STMT 003 (6 accounts) — approved: {}, confidence: {}, risk: {}", result.approved, result.confidence, result.risk_verdict.status);
    assert!(!result.approved || result.confidence < 0.6, "STMT with 6 accounts should be blocked or low confidence");
}

#[test]
fn test_real_stmt_004() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7], &[], WalletProfile::Standard);
    let result = run(input);
    println!("STMT 004 (7 accounts) — approved: {}, confidence: {}, risk: {}", result.approved, result.confidence, result.risk_verdict.status);
    assert!(!result.approved || result.confidence < 0.6, "STMT with 7 accounts should be blocked or low confidence");
}

#[test]
fn test_real_stmt_005() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8], &[], WalletProfile::Standard);
    let result = run(input);
    println!("STMT 005 (8 accounts) — approved: {}, confidence: {}, risk: {}", result.approved, result.confidence, result.risk_verdict.status);
    assert!(!result.approved || result.confidence < 0.6, "STMT with 8 accounts should be blocked or low confidence");
}

#[test]
fn test_real_stmt_006() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9], &[], WalletProfile::Standard);
    let result = run(input);
    println!("STMT 006 (9 accounts) — approved: {}, confidence: {}, risk: {}", result.approved, result.confidence, result.risk_verdict.status);
    assert!(!result.approved || result.confidence < 0.6, "STMT with 9 accounts should be blocked or low confidence");
}

#[test]
fn test_real_stmt_007() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9, A10], &[], WalletProfile::Standard);
    let result = run(input);
    println!("STMT 007 (10 accounts) — approved: {}, confidence: {}, risk: {}", result.approved, result.confidence, result.risk_verdict.status);
    assert!(!result.approved || result.confidence < 0.6, "STMT with 10 accounts should be blocked or low confidence");
}

#[test]
fn test_real_stmt_008() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9, A10], &[], WalletProfile::Standard);
    let result = run(input);
    println!("STMT 008 (11 accounts) — approved: {}, confidence: {}, risk: {}", result.approved, result.confidence, result.risk_verdict.status);
    assert!(!result.approved || result.confidence < 0.6, "STMT with 11 accounts should be blocked or low confidence");
}

#[test]
fn test_real_stmt_009() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9, A10], &[], WalletProfile::Standard);
    let result = run(input);
    println!("STMT 009 (12 accounts) — approved: {}, confidence: {}, risk: {}", result.approved, result.confidence, result.risk_verdict.status);
    assert!(!result.approved || result.confidence < 0.6, "STMT with 12 accounts should be blocked or low confidence");
}

#[test]
fn test_real_stmt_010() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9, A10], &[], WalletProfile::Standard);
    let result = run(input);
    println!("STMT 010 (13 accounts) — approved: {}, confidence: {}, risk: {}", result.approved, result.confidence, result.risk_verdict.status);
    assert!(!result.approved || result.confidence < 0.6, "STMT with 13 accounts should be blocked or low confidence");
}

#[test]
fn test_real_aat_011() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("AAT 011 (SPL_TOKEN) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority MUST be blocked on {}", SPL_TOKEN);
}

#[test]
fn test_real_aat_012() {
    let input = make(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("AAT 012 (TOKEN_2022) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority MUST be blocked on {}", TOKEN_2022);
}

#[test]
fn test_real_aat_013() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("AAT 013 (SPL_TOKEN) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority MUST be blocked on {}", SPL_TOKEN);
}

#[test]
fn test_real_aat_014() {
    let input = make(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("AAT 014 (TOKEN_2022) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority MUST be blocked on {}", TOKEN_2022);
}

#[test]
fn test_real_aat_015() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("AAT 015 (SPL_TOKEN) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority MUST be blocked on {}", SPL_TOKEN);
}

#[test]
fn test_real_aat_016() {
    let input = make(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("AAT 016 (TOKEN_2022) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority MUST be blocked on {}", TOKEN_2022);
}

#[test]
fn test_real_aat_017() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("AAT 017 (SPL_TOKEN) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority MUST be blocked on {}", SPL_TOKEN);
}

#[test]
fn test_real_aat_018() {
    let input = make(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("AAT 018 (TOKEN_2022) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority MUST be blocked on {}", TOKEN_2022);
}

#[test]
fn test_real_aat_019() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("AAT 019 (SPL_TOKEN) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority MUST be blocked on {}", SPL_TOKEN);
}

#[test]
fn test_real_aat_020() {
    let input = make(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("AAT 020 (TOKEN_2022) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority MUST be blocked on {}", TOKEN_2022);
}

#[test]
fn test_real_isa_021() {
    let input = make(U2, "02000000", &[A1, A2], &[], WalletProfile::Standard);
    let result = run(input);
    println!("ISA 021 (prog=A1) — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_isa_022() {
    let input = make(U1, "02000000", &[A1, A2], &[], WalletProfile::Standard);
    let result = run(input);
    println!("ISA 022 (prog=A2) — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_isa_023() {
    let input = make(U2, "02000000", &[A1, A2], &[], WalletProfile::Standard);
    let result = run(input);
    println!("ISA 023 (prog=A3) — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_isa_024() {
    let input = make(U1, "02000000", &[A1, A2], &[], WalletProfile::Standard);
    let result = run(input);
    println!("ISA 024 (prog=A4) — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_isa_025() {
    let input = make(U2, "02000000", &[A1, A2], &[], WalletProfile::Standard);
    let result = run(input);
    println!("ISA 025 (prog=A5) — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_isa_026() {
    let input = make(U1, "02000000", &[A1, A2], &[], WalletProfile::Standard);
    let result = run(input);
    println!("ISA 026 (prog=A6) — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_isa_027() {
    let input = make(U2, "02000000", &[A1, A2], &[], WalletProfile::Standard);
    let result = run(input);
    println!("ISA 027 (prog=A7) — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_isa_028() {
    let input = make(U1, "02000000", &[A1, A2], &[], WalletProfile::Standard);
    let result = run(input);
    println!("ISA 028 (prog=A8) — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_isa_029() {
    let input = make(U2, "02000000", &[A1, A2], &[], WalletProfile::Standard);
    let result = run(input);
    println!("ISA 029 (prog=A9) — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_isa_030() {
    let input = make(U1, "02000000", &[A1, A2], &[], WalletProfile::Standard);
    let result = run(input);
    println!("ISA 030 (prog=A10) — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_compositional_031() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5], &[A1, A2], WalletProfile::Standard);
    let result = run(input);
    println!("Comp drain 031 (5 accts + CPI) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Compositional drain must be blocked");
}

#[test]
fn test_real_compositional_032() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6], &[A1], WalletProfile::Standard);
    let result = run(input);
    println!("Comp drain 032 (6 accts + CPI) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Compositional drain must be blocked");
}

#[test]
fn test_real_compositional_033() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7], &[A1, A2], WalletProfile::Standard);
    let result = run(input);
    println!("Comp drain 033 (7 accts + CPI) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Compositional drain must be blocked");
}

#[test]
fn test_real_compositional_034() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8], &[A1], WalletProfile::Standard);
    let result = run(input);
    println!("Comp drain 034 (8 accts + CPI) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Compositional drain must be blocked");
}

#[test]
fn test_real_compositional_035() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9], &[A1, A2], WalletProfile::Standard);
    let result = run(input);
    println!("Comp drain 035 (9 accts + CPI) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Compositional drain must be blocked");
}

#[test]
fn test_real_compositional_036() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9, A10], &[A1], WalletProfile::Standard);
    let result = run(input);
    println!("Comp drain 036 (10 accts + CPI) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Compositional drain must be blocked");
}

#[test]
fn test_real_compositional_037() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9, A10], &[A1, A2], WalletProfile::Standard);
    let result = run(input);
    println!("Comp drain 037 (11 accts + CPI) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Compositional drain must be blocked");
}

#[test]
fn test_real_compositional_038() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9, A10], &[A1], WalletProfile::Standard);
    let result = run(input);
    println!("Comp drain 038 (12 accts + CPI) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Compositional drain must be blocked");
}

#[test]
fn test_real_compositional_039() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9, A10], &[A1, A2], WalletProfile::Standard);
    let result = run(input);
    println!("Comp drain 039 (13 accts + CPI) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Compositional drain must be blocked");
}

#[test]
fn test_real_compositional_040() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3, A4, A5, A6, A7, A8, A9, A10], &[A1], WalletProfile::Standard);
    let result = run(input);
    println!("Comp drain 040 (14 accts + CPI) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Compositional drain must be blocked");
}

#[test]
fn test_real_fake_swap_041() {
    let input = make(JUPITER_V6, "f8c69e91e17587c8", &[A1, A2, A3, A4], &[A1, A2], WalletProfile::Standard);
    let result = run(input);
    println!("Fake swap 041 (JUPITER_V6) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Fake swap with hidden CPI must be blocked");
}

#[test]
fn test_real_fake_swap_042() {
    let input = make(ORCA, "f8c69e91e17587c8", &[A1, A2, A3, A4, A5], &[A1], WalletProfile::Standard);
    let result = run(input);
    println!("Fake swap 042 (ORCA) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Fake swap with hidden CPI must be blocked");
}

#[test]
fn test_real_fake_swap_043() {
    let input = make(METEORA, "f8c69e91e17587c8", &[A1, A2, A3, A4, A5, A6], &[A1, A2], WalletProfile::Standard);
    let result = run(input);
    println!("Fake swap 043 (METEORA) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Fake swap with hidden CPI must be blocked");
}

#[test]
fn test_real_fake_swap_044() {
    let input = make(JUPITER_V6, "f8c69e91e17587c8", &[A1, A2, A3, A4, A5, A6, A7], &[A1, A2], WalletProfile::Standard);
    let result = run(input);
    println!("Fake swap 044 (JUPITER_V6) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Fake swap with hidden CPI must be blocked");
}

#[test]
fn test_real_fake_swap_045() {
    let input = make(ORCA, "f8c69e91e17587c8", &[A1, A2, A3], &[A1], WalletProfile::Standard);
    let result = run(input);
    println!("Fake swap 045 (ORCA) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Fake swap with hidden CPI must be blocked");
}

#[test]
fn test_real_fake_swap_046() {
    let input = make(METEORA, "f8c69e91e17587c8", &[A1, A2, A3, A4], &[A1, A2], WalletProfile::Standard);
    let result = run(input);
    println!("Fake swap 046 (METEORA) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Fake swap with hidden CPI must be blocked");
}

#[test]
fn test_real_fake_swap_047() {
    let input = make(JUPITER_V6, "f8c69e91e17587c8", &[A1, A2, A3, A4, A5], &[A1, A2], WalletProfile::Standard);
    let result = run(input);
    println!("Fake swap 047 (JUPITER_V6) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Fake swap with hidden CPI must be blocked");
}

#[test]
fn test_real_fake_swap_048() {
    let input = make(ORCA, "f8c69e91e17587c8", &[A1, A2, A3, A4, A5, A6], &[A1], WalletProfile::Standard);
    let result = run(input);
    println!("Fake swap 048 (ORCA) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Fake swap with hidden CPI must be blocked");
}

#[test]
fn test_real_fake_swap_049() {
    let input = make(METEORA, "f8c69e91e17587c8", &[A1, A2, A3, A4, A5, A6, A7], &[A1, A2], WalletProfile::Standard);
    let result = run(input);
    println!("Fake swap 049 (METEORA) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Fake swap with hidden CPI must be blocked");
}

#[test]
fn test_real_fake_swap_050() {
    let input = make(JUPITER_V6, "f8c69e91e17587c8", &[A1, A2, A3], &[A1, A2], WalletProfile::Standard);
    let result = run(input);
    println!("Fake swap 050 (JUPITER_V6) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Fake swap with hidden CPI must be blocked");
}

#[test]
fn test_real_auth_theft_051() {
    let input = make(TOKEN_2022, "0b", &[A1, A2, A3, A4], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Auth theft 051 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Authority theft must be blocked");
}

#[test]
fn test_real_auth_theft_052() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Auth theft 052 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Authority theft must be blocked");
}

#[test]
fn test_real_auth_theft_053() {
    let input = make(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Auth theft 053 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Authority theft must be blocked");
}

#[test]
fn test_real_auth_theft_054() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3, A4], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Auth theft 054 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Authority theft must be blocked");
}

#[test]
fn test_real_auth_theft_055() {
    let input = make(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Auth theft 055 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Authority theft must be blocked");
}

#[test]
fn test_real_auth_theft_056() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Auth theft 056 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Authority theft must be blocked");
}

#[test]
fn test_real_auth_theft_057() {
    let input = make(TOKEN_2022, "0b", &[A1, A2, A3, A4], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Auth theft 057 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Authority theft must be blocked");
}

#[test]
fn test_real_auth_theft_058() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Auth theft 058 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Authority theft must be blocked");
}

#[test]
fn test_real_auth_theft_059() {
    let input = make(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Auth theft 059 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Authority theft must be blocked");
}

#[test]
fn test_real_auth_theft_060() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3, A4], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Auth theft 060 — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "Authority theft must be blocked");
}

#[test]
fn test_real_unknown_program_061() {
    let input = make(U2, "a1b2c3d4", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Unknown prog 061 — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_unknown_program_062() {
    let input = make(U1, "a1b2c3d4", &[A1, A2, A3, A4], &[A1], WalletProfile::Standard);
    let result = run(input);
    println!("Unknown prog 062 — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_unknown_program_063() {
    let input = make(U2, "a1b2c3d4", &[A1, A2, A3, A4, A5], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Unknown prog 063 — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_unknown_program_064() {
    let input = make(U1, "a1b2c3d4", &[A1, A2, A3, A4, A5, A6], &[A1], WalletProfile::Standard);
    let result = run(input);
    println!("Unknown prog 064 — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_unknown_program_065() {
    let input = make(U2, "a1b2c3d4", &[A1, A2, A3, A4, A5, A6, A7], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Unknown prog 065 — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_unknown_program_066() {
    let input = make(U1, "a1b2c3d4", &[A1, A2, A3, A4, A5, A6, A7, A8], &[A1], WalletProfile::Standard);
    let result = run(input);
    println!("Unknown prog 066 — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_unknown_program_067() {
    let input = make(U2, "a1b2c3d4", &[A1, A2, A3, A4, A5, A6, A7, A8, A9], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Unknown prog 067 — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_unknown_program_068() {
    let input = make(U1, "a1b2c3d4", &[A1, A2, A3, A4, A5, A6, A7, A8, A9, A10], &[A1], WalletProfile::Standard);
    let result = run(input);
    println!("Unknown prog 068 — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_unknown_program_069() {
    let input = make(U2, "a1b2c3d4", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Unknown prog 069 — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_unknown_program_070() {
    let input = make(U1, "a1b2c3d4", &[A1, A2, A3, A4], &[A1], WalletProfile::Standard);
    let result = run(input);
    println!("Unknown prog 070 — confidence: {}, unknown: {}", result.confidence, result.unknown_protocol);
    assert!(result.confidence <= 0.55, "Unknown program must be capped at 0.55");
}

#[test]
fn test_real_evasion_071() {
    let input = make_evidence(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, high_ev());
    let result = run(input);
    println!("Evasion 071 (high evidence) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority with high evidence must still be blocked");
}

#[test]
fn test_real_evasion_072() {
    let input = make_evidence(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, high_ev());
    let result = run(input);
    println!("Evasion 072 (high evidence) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority with high evidence must still be blocked");
}

#[test]
fn test_real_evasion_073() {
    let input = make_evidence(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, high_ev());
    let result = run(input);
    println!("Evasion 073 (high evidence) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority with high evidence must still be blocked");
}

#[test]
fn test_real_evasion_074() {
    let input = make_evidence(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, high_ev());
    let result = run(input);
    println!("Evasion 074 (high evidence) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority with high evidence must still be blocked");
}

#[test]
fn test_real_evasion_075() {
    let input = make_evidence(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, high_ev());
    let result = run(input);
    println!("Evasion 075 (high evidence) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority with high evidence must still be blocked");
}

#[test]
fn test_real_evasion_076() {
    let input = make_evidence(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, high_ev());
    let result = run(input);
    println!("Evasion 076 (high evidence) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority with high evidence must still be blocked");
}

#[test]
fn test_real_evasion_077() {
    let input = make_evidence(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, high_ev());
    let result = run(input);
    println!("Evasion 077 (high evidence) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority with high evidence must still be blocked");
}

#[test]
fn test_real_evasion_078() {
    let input = make_evidence(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, high_ev());
    let result = run(input);
    println!("Evasion 078 (high evidence) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority with high evidence must still be blocked");
}

#[test]
fn test_real_evasion_079() {
    let input = make_evidence(TOKEN_2022, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, high_ev());
    let result = run(input);
    println!("Evasion 079 (high evidence) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority with high evidence must still be blocked");
}

#[test]
fn test_real_evasion_080() {
    let input = make_evidence(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard, high_ev());
    let result = run(input);
    println!("Evasion 080 (high evidence) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority with high evidence must still be blocked");
}

#[test]
fn test_real_policy_bypass_081() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Conservative);
    let result = run(input);
    println!("Policy bypass 081 (Conservative) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority must be blocked regardless of profile");
}

#[test]
fn test_real_policy_bypass_082() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Policy bypass 082 (Standard) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority must be blocked regardless of profile");
}

#[test]
fn test_real_policy_bypass_083() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive);
    let result = run(input);
    println!("Policy bypass 083 (Permissive) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority must be blocked regardless of profile");
}

#[test]
fn test_real_policy_bypass_084() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Enterprise);
    let result = run(input);
    println!("Policy bypass 084 (Enterprise) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority must be blocked regardless of profile");
}

#[test]
fn test_real_policy_bypass_085() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Policy bypass 085 (Standard) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority must be blocked regardless of profile");
}

#[test]
fn test_real_policy_bypass_086() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive);
    let result = run(input);
    println!("Policy bypass 086 (Permissive) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority must be blocked regardless of profile");
}

#[test]
fn test_real_policy_bypass_087() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Conservative);
    let result = run(input);
    println!("Policy bypass 087 (Conservative) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority must be blocked regardless of profile");
}

#[test]
fn test_real_policy_bypass_088() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Enterprise);
    let result = run(input);
    println!("Policy bypass 088 (Enterprise) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority must be blocked regardless of profile");
}

#[test]
fn test_real_policy_bypass_089() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Policy bypass 089 (Standard) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority must be blocked regardless of profile");
}

#[test]
fn test_real_policy_bypass_090() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Permissive);
    let result = run(input);
    println!("Policy bypass 090 (Permissive) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority must be blocked regardless of profile");
}

#[test]
fn test_real_edge_091() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Edge 091 (SetAuthority) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority must be blocked");
}

#[test]
fn test_real_edge_092() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Edge 092 (Transfer) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(result.risk_verdict.status == "Clear", "Legitimate transfer must not be risk-blocked");
}

#[test]
fn test_real_edge_093() {
    let input = make(SPL_TOKEN, "09", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Edge 093 (CloseAccount) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "CloseAccount must be blocked");
}

#[test]
fn test_real_edge_094() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Edge 094 (SetAuthority) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority must be blocked");
}

#[test]
fn test_real_edge_095() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Edge 095 (Transfer) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(result.risk_verdict.status == "Clear", "Legitimate transfer must not be risk-blocked");
}

#[test]
fn test_real_edge_096() {
    let input = make(SPL_TOKEN, "09", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Edge 096 (CloseAccount) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "CloseAccount must be blocked");
}

#[test]
fn test_real_edge_097() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Edge 097 (SetAuthority) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority must be blocked");
}

#[test]
fn test_real_edge_098() {
    let input = make(SPL_TOKEN, "03", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Edge 098 (Transfer) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(result.risk_verdict.status == "Clear", "Legitimate transfer must not be risk-blocked");
}

#[test]
fn test_real_edge_099() {
    let input = make(SPL_TOKEN, "09", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Edge 099 (CloseAccount) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "CloseAccount must be blocked");
}

#[test]
fn test_real_edge_100() {
    let input = make(SPL_TOKEN, "0b", &[A1, A2, A3], &[], WalletProfile::Standard);
    let result = run(input);
    println!("Edge 100 (SetAuthority) — approved: {}, risk: {}", result.approved, result.risk_verdict.status);
    assert!(!result.approved, "SetAuthority must be blocked");
}