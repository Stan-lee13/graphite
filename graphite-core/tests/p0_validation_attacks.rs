//! P0 validation attacks — attempt to re-break each fixed vulnerability with
//! adversarial variants that differ from the original regression fixtures.
//!
//! Each test here represents an ATTACK on a fix, not a re-run of it. If any
//! of these pass when they should block (or block when they should pass),
//! the fix is overfit to its regression fixture.

use graphite_core::risk_engine::{assess, RiskAssessmentInput, RiskPattern, RiskVerdict};
use graphite_core::tx_pattern_analysis::TOKEN_PROGRAM;

fn risk_input(
    program: &str,
    accounts: &[&str],
    cpi: &[&str],
    changes: &[&str],
    allowed: &[&str],
    disc: &str,
    intent: &str,
) -> RiskAssessmentInput {
    RiskAssessmentInput {
        program_id: program.to_string(),
        accounts: accounts.iter().map(|s| s.to_string()).collect(),
        cpi_targets: cpi.iter().map(|s| s.to_string()).collect(),
        expected_state_changes: changes.iter().map(|s| s.to_string()).collect(),
        allowed_cpis: allowed.iter().map(|s| s.to_string()).collect(),
        instruction_discriminator: disc.to_string(),
        expected_account_count: None,
        proposed_intent_type: intent.to_string(),
        variable_accounts: false,
        extracted_output_token: None,
        manifest_risk_class: String::new(),
    }
}

const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const SYSTEM: &str = "11111111111111111111111111111111";

fn is_blocked_with(v: &RiskVerdict, pattern: RiskPattern) -> bool {
    matches!(
        v,
        RiskVerdict::Blocked {
            pattern: p,
            ..
        } if *p == pattern
    )
}

// ── P0 #1: discriminator-width consistency ─────────────────────────────────

#[test]
fn attack_p0_1_close_account_every_hex_width() {
    // The C33 fix unified prefix matching. Attack: enumerate every
    // representation width of CloseAccount's 0x09 selector — 1, 2, 4 and 8
    // bytes — all with a non-close intent. Every width must block.
    for disc in [
        "09",
        "0900",
        "09000000",
        "0900000000000000",
        "09000000000000000000000000000000", // over-padded 16 bytes
    ] {
        let input = risk_input(
            SPL_TOKEN,
            &["a1", "a2"],
            &[],
            &["debits accounts.a1"],
            &[],
            disc,
            "transfer", // fake intent — CloseAccount not declared
        );
        let v = assess(&input).unwrap();
        assert!(
            matches!(v, RiskVerdict::Blocked { .. }),
            "CloseAccount width {} with fake transfer intent evaded: {:?}",
            disc,
            v
        );
    }
}

#[test]
fn attack_p0_1_similar_prefix_does_not_false_positive() {
    // 0x05 (MintTo) and 0x06 (SetAuthority) share no prefix, but an attacker
    // could try near-misses: "05" must NOT trip the SetAuthority/CloseAccount
    // gates. Verifies prefix matching doesn't become substring matching.
    let input = risk_input(
        SPL_TOKEN,
        &["a1", "a2"],
        &[],
        &["debits accounts.a1"],
        &[],
        "05", // MintTo, NOT CloseAccount/SetAuthority
        "transfer",
    );
    // MintTo with transfer intent is odd but NOT the authority/close gates —
    // the fail-closed CPI/unknown paths are what should guard it, not a
    // wrong-prefix match.
    let v = assess(&input).unwrap();
    assert!(
        !is_blocked_with(&v, RiskPattern::MaliciousAccountChange)
            && !is_blocked_with(&v, RiskPattern::PermissionEscalation),
        "near-miss discriminator 05 tripped an unrelated gate: {:?}",
        v
    );
}

#[test]
fn attack_p0_1_empty_discriminator_fails_closed() {
    // Empty selector on a token program is unverifiable — must fail closed
    // (blocked by the empty-discriminator-on-risky-program rule), not pass.
    let input = risk_input(SPL_TOKEN, &["a1", "a2"], &[], &[], &[], "", "");
    let v = assess(&input).unwrap();
    assert!(
        matches!(v, RiskVerdict::Blocked { .. }),
        "empty discriminator on SPL Token must fail closed, got {:?}",
        v
    );
}

#[test]
fn attack_p0_1_unknown_selector_full_pipeline_not_approved() {
    // SPL Token's real instruction set ends at 0x11 (SyncNative); 0x12 is
    // unknown to BOTH the manifest and the actual program. Through the FULL
    // pipeline (not the risk engine in isolation), P12 Response 2 reduces
    // confidence — the transaction must not be approved end-to-end.
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::verification::{ProposedIntent, VerificationInput};
    use graphite_core::GraphiteCore;
    let core = GraphiteCore::default();
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send tokens".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: SPL_TOKEN.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "12".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
        ],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Treasury,
        behavior_evidence: Default::default(),
        compute_units: 100,
        account_writes: 1,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
    };
    let result = core.verify(&input).unwrap();
    assert!(
        !result.approved,
        "unknown selector 0x12 on SPL Token was approved end-to-end"
    );
}

// ── P0 #2: TransferChecked destination extraction ──────────────────────────

#[test]
fn attack_p0_2_transfer_checked_shared_mint_sweep() {
    // Attack: 3+ TransferChecked transfers, ALL sharing one mint, each to a
    // distinct destination. Pre-fix code read accounts[1] (the mint) as the
    // destination, so all destinations collapsed to one and the sweep slid
    // under the >=3-destination floor. This exercises the multi-instruction
    // analyzer through the risk-adjacent path with real-shaped layouts.
    use graphite_core::tx_pattern_analysis::{
        analyze_multi_instruction, PatternSeverity, TransactionInstruction,
    };
    let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let mk = |src: &str, dst: &str| TransactionInstruction {
        program_id: SPL_TOKEN.to_string(),
        instruction_discriminator: "0c".to_string(), // TransferChecked
        account_addresses: vec![
            src.to_string(),
            mint.to_string(),
            dst.to_string(),
            "owner".to_string(),
        ],
        cpi_targets: vec![],
    };
    let txs = vec![
        mk("a1", "b1"),
        mk("a2", "b2"),
        mk("a3", "b3"),
        mk("a4", "b4"),
    ];
    let findings = analyze_multi_instruction(&txs);
    assert!(
        findings
            .iter()
            .any(|f| f.severity == PatternSeverity::Blocked && f.pattern == "MultiInstructionDrain"),
        "TransferChecked shared-mint 4-destination sweep evaded mass-sweep: {:?}",
        findings
    );
}

#[test]
fn attack_p0_2_transfer_checked_token_2022_variants() {
    use graphite_core::tx_pattern_analysis::{
        analyze_multi_instruction, PatternSeverity, TransactionInstruction,
    };
    let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let mk = |prog: &str, src: &str, dst: &str| TransactionInstruction {
        program_id: prog.to_string(),
        instruction_discriminator: "0c".to_string(),
        account_addresses: vec![
            src.to_string(),
            mint.to_string(),
            dst.to_string(),
            "owner".to_string(),
        ],
        cpi_targets: vec![],
    };
    // Mixed SPL + Token-2022, 3 distinct destinations, shared mint.
    let txs = vec![
        mk(SPL_TOKEN, "a1", "b1"),
        mk(TOKEN_2022, "a2", "b2"),
        mk(TOKEN_2022, "a3", "b3"),
    ];
    let findings = analyze_multi_instruction(&txs);
    assert!(
        findings
            .iter()
            .any(|f| f.severity == PatternSeverity::Blocked && f.pattern == "MultiInstructionDrain"),
        "mixed SPL/Token-2022 TransferChecked sweep evaded: {:?}",
        findings
    );
}

#[test]
fn attack_p0_2_transfer_checked_malformed_and_extra_accounts() {
    use graphite_core::tx_pattern_analysis::{analyze_multi_instruction, TransactionInstruction};
    // Extra trailing accounts must not shift the destination extraction.
    let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let mk = |src: &str, dst: &str, extra: usize| TransactionInstruction {
        program_id: SPL_TOKEN.to_string(),
        instruction_discriminator: "0c".to_string(),
        account_addresses: {
            let mut v = vec![
                src.to_string(),
                mint.to_string(),
                dst.to_string(),
                "owner".to_string(),
            ];
            for i in 0..extra {
                v.push(format!("extra{i}"));
            }
            v
        },
        cpi_targets: vec![],
    };
    let txs = vec![mk("a1", "b1", 2), mk("a2", "b2", 5), mk("a3", "b3", 0)];
    let findings = analyze_multi_instruction(&txs);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern == "MultiInstructionDrain"),
        "extra accounts confused destination extraction: {:?}",
        findings
    );
}

// ── P0 #3: CPI path traversal ──────────────────────────────────────────────

#[test]
fn attack_p0_3_root_through_alternating_programs() {
    use graphite_core::tx_pattern_analysis::{analyze_cpi_trace, CpiTraceNode};
    let node = |p: &str, d: u32, c: Vec<CpiTraceNode>| CpiTraceNode {
        program_id: p.to_string(),
        instruction_discriminator: String::new(),
        depth: d,
        account_addresses: vec![],
        children: c,
    };
    // Root IS the repeated program: A -> B -> C -> A -> A. Old counter saw
    // only 2 from the deepest A node and missed the root occurrence.
    let trace = node(
        "prog_a",
        0,
        vec![node(
            "prog_b",
            1,
            vec![node(
                "prog_c",
                2,
                vec![node("prog_a", 3, vec![node("prog_a", 4, vec![])])],
            )],
        )],
    );
    let known: Vec<String> = vec!["prog_a".into(), "prog_b".into(), "prog_c".into()];
    let findings = analyze_cpi_trace(&trace, &known);
    assert!(
        findings
            .iter()
            .any(|f| f.reason.contains("re-enters program prog_a 3 times")),
        "root-level repetition evaded after fix: {:?}",
        findings
    );
}

#[test]
fn attack_p0_3_zigzag_sibling_paths() {
    use graphite_core::tx_pattern_analysis::{analyze_cpi_trace, CpiTraceNode};
    let node = |p: &str, d: u32, c: Vec<CpiTraceNode>| CpiTraceNode {
        program_id: p.to_string(),
        instruction_discriminator: String::new(),
        depth: d,
        account_addresses: vec![],
        children: c,
    };
    // Two deep branches, each repeating program X three times, plus a short
    // branch — max-over-paths must find 3 in EITHER branch.
    let branch = |prefix: &str, d: u32| {
        node(
            prefix,
            d,
            vec![node(
                "prog_x",
                d + 1,
                vec![node(
                    "prog_y",
                    d + 2,
                    vec![node("prog_x", d + 3, vec![node("prog_x", d + 4, vec![])])],
                )],
            )],
        )
    };
    let trace = node(TOKEN_PROGRAM, 0, vec![branch("w1", 1), branch("w2", 1)]);
    let known: Vec<String> = vec![
        TOKEN_PROGRAM.into(),
        "w1".into(),
        "w2".into(),
        "prog_x".into(),
        "prog_y".into(),
    ];
    let findings = analyze_cpi_trace(&trace, &known);
    assert!(
        findings
            .iter()
            .any(|f| f.reason.contains("re-enters program prog_x 3 times")),
        "zigzag sibling branches evaded repeated-revisit: {:?}",
        findings
    );
}

// ── P0 #4: compositional drain infra separation ────────────────────────────

#[test]
fn attack_p0_4_multi_hop_swap_with_token_cpis_clean() {
    // The full legitimate shape: trusted DEX root, MANY repeated SPL Token /
    // Token-2022 / System CPI calls across hops. Must stay clean.
    let input = risk_input(
        "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
        &["pool_in", "pool_out"],
        &[
            SPL_TOKEN, SPL_TOKEN, TOKEN_2022, SPL_TOKEN, SYSTEM, TOKEN_2022, TOKEN_2022,
        ],
        &["debits accounts.input", "credits accounts.output"],
        &[SPL_TOKEN, TOKEN_2022, SYSTEM],
        "",
        "swap",
    );
    let v = assess(&input).unwrap();
    assert!(
        !is_blocked_with(&v, RiskPattern::CompositionalDrainPattern),
        "7-CPI multi-hop swap with repeated infra calls flagged as drain: {:?}",
        v
    );
}

#[test]
fn attack_p0_4_infra_repeats_plus_single_custom_visit_clean() {
    // Repeated infra + ONE visit to a custom program is NOT a drain (the
    // custom program appears once — no revisit). Checks we didn't trade
    // false positives for new false negatives at the boundary.
    let input = risk_input(
        "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
        &["a"],
        &[SPL_TOKEN, SPL_TOKEN, SPL_TOKEN, "custom_router"],
        &["debits accounts.a"],
        &[SPL_TOKEN, "custom_router"],
        "",
        "swap",
    );
    let v = assess(&input).unwrap();
    assert!(
        !is_blocked_with(&v, RiskPattern::CompositionalDrainPattern),
        "single custom visit with repeated infra flagged as drain: {:?}",
        v
    );
}

// ── Check 10: manifest-declared high-risk class (risk-engine expansion) ───

#[test]
fn attack_check10_stake_withdraw_no_intent_is_blocked() {
    // The stake-program manifest tags Withdraw (04000000) as "withdraw". An
    // agent submitting a stake withdrawal WITHOUT declaring intent must be
    // fail-closed by the manifest-declared class — no per-protocol code.
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::verification::{ProposedIntent, VerificationInput};
    use graphite_core::GraphiteCore;
    let core = GraphiteCore::default();
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: String::new(), // NO declared intent
            raw_natural_language: String::new(),
            confidence_of_parse: 0.0,
            extracted_parameters: None,
        },
        program_id: "Stake11111111111111111111111111111111111111".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "04000000".to_string(), // Stake Withdraw
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(), // stake
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),  // withdrawer
            "SysvarC1ock11111111111111111111111111111111".to_string(),  // clock
            "SysvarStakeHistory1111111111111111111111111".to_string(),  // stake history
            "9RGFwSryu7FvDaqHWFLrnvQHge7hc5chawhcSH7m8FVU".to_string(), // to
        ],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Treasury,
        behavior_evidence: Default::default(),
        compute_units: 100,
        account_writes: 1,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
    };
    let result = core.verify(&input).unwrap();
    assert!(
        !result.approved,
        "Stake Withdraw with no declared intent must be blocked by its manifest risk_class"
    );
}

#[test]
fn attack_check10_stake_withdraw_with_declared_intent_not_check10_blocked() {
    // Declared "stake" intent takes it out of Check 10; the block (if any)
    // must NOT be the Check 10 MaliciousAccountChange reason.
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::verification::{ProposedIntent, VerificationInput};
    use graphite_core::GraphiteCore;
    let core = GraphiteCore::default();
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "stake".to_string(),
            raw_natural_language: "withdraw staked SOL".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: "Stake11111111111111111111111111111111111111".to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "04000000".to_string(), // Stake Withdraw
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(), // stake
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),  // withdrawer
            "SysvarC1ock11111111111111111111111111111111".to_string(),  // clock
            "SysvarStakeHistory1111111111111111111111111".to_string(),  // stake history
            "9RGFwSryu7FvDaqHWFLrnvQHge7hc5chawhcSH7m8FVU".to_string(), // to
        ],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Treasury,
        behavior_evidence: Default::default(),
        compute_units: 100,
        account_writes: 1,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
    };
    let result = core.verify(&input).unwrap();
    assert!(
        !result
            .risk_verdict
            .findings
            .iter()
            .any(|f| f.reason.contains("no intent was declared")),
        "declared intent must not trip the Check 10 empty-intent gate: {:?}",
        result.risk_verdict.findings
    );
}

// ── P1C: hidden-transfer description robustness ────────────────────────────

#[test]
fn attack_p1c_natural_language_description_still_flags_hidden_transfer() {
    // Old detector required the literal "accounts." string — a manifest that
    // describes changes in plain language silently disabled the gate. 14
    // accounts with a description naming only one account must still block.
    let mut accounts: Vec<String> = (0..14).map(|i| format!("acc{i}")).collect();
    accounts[0] = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string();
    // 3 meaningful changes keep the account:change ratio under the Drainer
    // gate's 6:1 so HiddenTransfer is the gate under test.
    let input = risk_input(
        SPL_TOKEN,
        &accounts.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        &[],
        &[
            "debits the source token balance by the amount", // no "accounts." notation
            "credits the destination token balance",
            "signer authority is verified",
        ],
        &[],
        "03",
        "transfer",
    );
    let v = assess(&input).unwrap();
    assert!(
        is_blocked_with(&v, RiskPattern::HiddenTransfer),
        "natural-language description disabled hidden-transfer gate: {:?}",
        v
    );
}

#[test]
fn attack_p1c_prompt_injected_description_cannot_inflate_threshold() {
    // Prompt-injected description padded with many repeated "accounts.x"
    // mentions must NOT inflate the referenced count (distinct identities
    // only) — otherwise the threshold rises and a real drain slips through.
    let mut accounts: Vec<String> = (0..16).map(|i| format!("acc{i}")).collect();
    accounts[0] = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string();
    let input = risk_input(
        SPL_TOKEN,
        &accounts.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        &[],
        &[
            "debits accounts.source".to_string(),
            "debits accounts.source again".to_string(),
            "debits accounts.source third time".to_string(),
            "debits accounts.source fourth".to_string(),
            "debits accounts.source fifth".to_string(),
            "debits accounts.source sixth".to_string(),
        ]
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>(),
        &[],
        "03",
        "transfer",
    );
    // One distinct identity -> threshold 12 -> 16 accounts block.
    let v = assess(&input).unwrap();
    assert!(
        is_blocked_with(&v, RiskPattern::HiddenTransfer),
        "inflated description padded the threshold: {:?}",
        v
    );
}

#[test]
fn attack_p1c_equivalent_description_variants_still_flag() {
    // Rephrased variants of the same transfer description. Each is paired
    // with 2 additional meaningful but role-FREE changes so the ratio stays
    // under Drainer's 6:1 AND the role vocabulary (not padding) drives the
    // HiddenTransfer threshold.
    for desc in [
        "credits the destination token balance",
        "moves value from the source to the destination",
        "sends tokens from the sender's account to the recipient",
        "updates accounts.to with the transferred amount",
    ] {
        let mut accounts: Vec<String> = (0..14).map(|i| format!("acc{i}")).collect();
        accounts[0] = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string();
        let input = risk_input(
            SPL_TOKEN,
            &accounts.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            &[],
            &[desc, "the transfer amount is recorded", "fees are logged"],
            &[],
            "03",
            "transfer",
        );
        let v = assess(&input).unwrap();
        assert!(
            is_blocked_with(&v, RiskPattern::HiddenTransfer),
            "variant '{desc}' disabled hidden-transfer gate: {:?}",
            v
        );
    }
}

#[test]
fn attack_p1c_legitimate_multi_account_description_not_flagged() {
    // A genuinely multi-account instruction description (3 identities) with a
    // modest account list must NOT hard-block via hidden transfer.
    let input = risk_input(
        SPL_TOKEN,
        &[
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
            "9RGFwSryu7FvDaqHWFLrnvQHge7hc5chawhcSH7m8FVU",
        ],
        &[],
        &[
            "debits accounts.source token balance by data.amount",
            "credits accounts.destination token balance by data.amount",
            "authority signer verified",
        ],
        &[],
        "03",
        "transfer",
    );
    let v = assess(&input).unwrap();
    assert!(
        !is_blocked_with(&v, RiskPattern::HiddenTransfer),
        "legitimate multi-account transfer flagged as hidden: {:?}",
        v
    );
}

#[test]
fn attack_p0_4_system_program_repeats_not_drain() {
    // System-program lamport routing repeated (e.g. fee splits) is infra.
    let input = risk_input(
        "some_protocol",
        &["a1", "a2", "a3"],
        &[SYSTEM, SYSTEM, SYSTEM, SYSTEM],
        &["debits accounts.a1"],
        &[SYSTEM],
        "",
        "",
    );
    let v = assess(&input).unwrap();
    assert!(
        !is_blocked_with(&v, RiskPattern::CompositionalDrainPattern),
        "repeated System CPIs flagged as drain: {:?}",
        v
    );
}
