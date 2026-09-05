//! Certification revalidation — a SECOND, independent adversarial pass.
//!
//! Every attack here is a VARIATION the original `p0_validation_attacks.rs`
//! suite did not use: different widths, different layouts, different tree
//! shapes, different protocol contexts. If any of these regress, the fix is
//! overfit to its original fixture.

use graphite_core::risk_engine::{assess, RiskAssessmentInput, RiskPattern, RiskVerdict};
use graphite_core::tx_pattern_analysis::TOKEN_PROGRAM;

#[allow(clippy::too_many_arguments)]
fn risk_input(
    program: &str,
    accounts: &[&str],
    cpi: &[&str],
    changes: &[&str],
    allowed: &[&str],
    disc: &str,
    intent: &str,
    risk_class: &str,
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
        manifest_risk_class: risk_class.to_string(),
    }
}

fn is_blocked(v: &RiskVerdict) -> bool {
    matches!(v, RiskVerdict::Blocked { .. })
}

// ── P0-1: discriminator width — fresh variants ─────────────────────────────

#[test]
fn cert_p0_1_close_account_0x_prefixed_and_uppercase_forms() {
    // Attack: alternative textual encodings of the same selector — "0x09",
    // "0X09", "09", "09" + trailing zeros, uppercase hex. All must block.
    for disc in [
        "0x09",
        "0X09",
        "09",
        "0900",
        "090000",
        "0900000000000000",
        "09000000000000000000000000000000",
        "09".to_uppercase().as_str(),
    ] {
        let input = risk_input(
            TOKEN_PROGRAM,
            &["a1", "a2"],
            &[],
            &["debits accounts.a1"],
            &[],
            disc,
            "transfer", // fake intent — CloseAccount not declared
            "",
        );
        let v = assess(&input).unwrap();
        assert!(
            is_blocked(&v),
            "CloseAccount form '{disc}' with fake transfer intent evaded: {:?}",
            v
        );
    }
}

#[test]
fn cert_p0_1_set_authority_4byte_selector_form() {
    // The 4-byte padded SetAuthority (06000000) — the form a serialized
    // instruction actually carries on chain — must trip the intent gate.
    let input = risk_input(
        TOKEN_PROGRAM,
        &["a1", "a2"],
        &[],
        &["debits accounts.a1"],
        &[],
        "06000000",
        "transfer",
        "",
    );
    let v = assess(&input).unwrap();
    assert!(
        is_blocked(&v),
        "4-byte SetAuthority with transfer intent evaded: {:?}",
        v
    );
}

#[test]
fn cert_p0_1_approve_16byte_overpadded_form() {
    let input = risk_input(
        TOKEN_PROGRAM,
        &["a1", "a2", "a3"],
        &[],
        &["debits accounts.a1"],
        &[],
        "04000000000000000000000000000000",
        "transfer",
        "",
    );
    let v = assess(&input).unwrap();
    assert!(
        is_blocked(&v),
        "16-byte Approve with fake intent evaded: {:?}",
        v
    );
}

#[test]
fn cert_p0_1_whitespace_padded_discriminator_fails_safely() {
    // Trailing whitespace must not silently resolve to a legitimate
    // instruction through the FULL pipeline — malformed input must take the
    // unknown-instruction path (reduced confidence, not approved).
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::verification::{ProposedIntent, VerificationInput};
    use graphite_core::GraphiteCore;
    let core = GraphiteCore::default();
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: TOKEN_PROGRAM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "03 ".to_string(), // malformed
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
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    };
    // Fail-closed: the malformed discriminator must be rejected — either a
    // hard error (invalid hex) or a non-approval. Approval is the only
    // unacceptable outcome.
    match core.verify(&input) {
        Ok(result) => assert!(
            !result.approved,
            "whitespace-padded discriminator must not be approved end-to-end"
        ),
        Err(_) => { /* fail-closed rejection — acceptable */ }
    }
}

// ── P0-2: TransferChecked — fresh layouts ──────────────────────────────────

#[test]
fn cert_p0_2_transfer_checked_distinct_mints_distinct_destinations() {
    // 4 destinations with 4 DIFFERENT mints — the mint/destination confusion
    // would have collapsed this to 1 destination under the old code; the
    // sweep must still fire on the real destinations.
    use graphite_core::tx_pattern_analysis::{
        analyze_multi_instruction, PatternSeverity, TransactionInstruction,
    };
    let mk = |src: &str, mint: &str, dst: &str| TransactionInstruction {
        program_id: TOKEN_PROGRAM.to_string(),
        instruction_discriminator: "0c".to_string(),
        account_addresses: vec![
            src.to_string(),
            mint.to_string(),
            dst.to_string(),
            "owner".to_string(),
        ],
        cpi_targets: vec![],
    };
    let txs = vec![
        mk("s1", "m1", "d1"),
        mk("s2", "m2", "d2"),
        mk("s3", "m3", "d3"),
        mk("s4", "m4", "d4"),
    ];
    let findings = analyze_multi_instruction(&txs);
    assert!(
        findings
            .iter()
            .any(|f| f.severity == PatternSeverity::Blocked && f.pattern == "MultiInstructionDrain"),
        "4-destination distinct-mint TransferChecked sweep evaded: {:?}",
        findings
    );
}

#[test]
fn cert_p0_2_transfer_checked_different_authorities_still_correlate() {
    // Sweep where each transfer uses a DIFFERENT authority account — the
    // drain signal is the destination, not the signer.
    use graphite_core::tx_pattern_analysis::{
        analyze_multi_instruction, PatternSeverity, TransactionInstruction,
    };
    let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let mk = |src: &str, dst: &str, auth: &str| TransactionInstruction {
        program_id: TOKEN_PROGRAM.to_string(),
        instruction_discriminator: "0c".to_string(),
        account_addresses: vec![
            src.to_string(),
            mint.to_string(),
            dst.to_string(),
            auth.to_string(),
        ],
        cpi_targets: vec![],
    };
    let txs = vec![
        mk("s1", "d1", "auth_a"),
        mk("s2", "d2", "auth_b"),
        mk("s3", "d3", "auth_c"),
    ];
    let findings = analyze_multi_instruction(&txs);
    assert!(
        findings
            .iter()
            .any(|f| f.severity == PatternSeverity::Blocked && f.pattern == "MultiInstructionDrain"),
        "multi-authority TransferChecked sweep evaded: {:?}",
        findings
    );
}

#[test]
fn cert_p0_2_transfer_checked_authority_only_extra_account() {
    // Extra accounts beyond the canonical 4 (e.g. Token-2022 extensions add
    // accounts) must not shift the destination index.
    use graphite_core::tx_pattern_analysis::{
        analyze_multi_instruction, PatternSeverity, TransactionInstruction,
    };
    let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let mk = |src: &str, dst: &str, extras: &[&str]| TransactionInstruction {
        program_id: TOKEN_PROGRAM.to_string(),
        instruction_discriminator: "0c".to_string(),
        account_addresses: {
            let mut v = vec![
                src.to_string(),
                mint.to_string(),
                dst.to_string(),
                "owner".to_string(),
            ];
            v.extend(extras.iter().map(|s| s.to_string()));
            v
        },
        cpi_targets: vec![],
    };
    let txs = vec![
        mk("s1", "d1", &["ext1", "ext2"]),
        mk("s2", "d2", &["ext1"]),
        mk("s3", "d3", &[]),
    ];
    let findings = analyze_multi_instruction(&txs);
    assert!(
        findings
            .iter()
            .any(|f| f.severity == PatternSeverity::Blocked && f.pattern == "MultiInstructionDrain"),
        "extension-account TransferChecked sweep evaded: {:?}",
        findings
    );
}

#[test]
fn cert_p0_2_transfer_checked_missing_authority_does_not_panic_or_fire() {
    // Canonical layout requires 4 accounts; a truncated list has no
    // destination — must be clean (no panic, no fabricated finding).
    use graphite_core::tx_pattern_analysis::{analyze_multi_instruction, TransactionInstruction};
    let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let mk = |src: &str| TransactionInstruction {
        program_id: TOKEN_PROGRAM.to_string(),
        instruction_discriminator: "0c".to_string(),
        account_addresses: vec![src.to_string(), mint.to_string()],
        cpi_targets: vec![],
    };
    let txs = vec![mk("s1"), mk("s2"), mk("s3")];
    assert!(analyze_multi_instruction(&txs).is_empty());
}

// ── P0-3: CPI traversal — fresh tree shapes ────────────────────────────────

#[test]
fn cert_p0_3_alternating_ababa_is_two_revisits_not_drain() {
    use graphite_core::tx_pattern_analysis::{analyze_cpi_trace, CpiTraceNode};
    let node = |p: &str, d: u32, c: Vec<CpiTraceNode>| CpiTraceNode {
        program_id: p.to_string(),
        instruction_discriminator: String::new(),
        depth: d,
        account_addresses: vec![],
        children: c,
    };
    // A -> B -> A -> B -> A: A appears 3 times along the path. Root is NOT A.
    let trace = node(
        "root_prog",
        0,
        vec![node(
            "prog_a",
            1,
            vec![node(
                "prog_b",
                2,
                vec![node(
                    "prog_a",
                    3,
                    vec![node("prog_b", 4, vec![node("prog_a", 5, vec![])])],
                )],
            )],
        )],
    );
    let known: Vec<String> = vec!["root_prog".into(), "prog_a".into(), "prog_b".into()];
    let findings = analyze_cpi_trace(&trace, &known);
    assert!(
        findings
            .iter()
            .any(|f| f.reason.contains("re-enters program prog_a 3 times")),
        "A->B->A->B->A must count 3 A visits: {:?}",
        findings
    );
    // prog_b appears twice only — must NOT fire.
    assert!(
        !findings
            .iter()
            .any(|f| f.reason.contains("re-enters program prog_b")),
        "prog_b only has 2 visits, must not fire: {:?}",
        findings
    );
}

#[test]
fn cert_p0_3_root_program_self_chain_is_drain() {
    use graphite_core::tx_pattern_analysis::{analyze_cpi_trace, CpiTraceNode};
    let node = |p: &str, d: u32, c: Vec<CpiTraceNode>| CpiTraceNode {
        program_id: p.to_string(),
        instruction_discriminator: String::new(),
        depth: d,
        account_addresses: vec![],
        children: c,
    };
    // Root IS the repeated program and the chain is pure self-calls.
    let trace = node(
        "prog_x",
        0,
        vec![node(
            "prog_x",
            1,
            vec![node("prog_x", 2, vec![node("prog_x", 3, vec![])])],
        )],
    );
    let known: Vec<String> = vec!["prog_x".into()];
    let findings = analyze_cpi_trace(&trace, &known);
    assert!(
        findings
            .iter()
            .any(|f| f.reason.contains("re-enters program prog_x 4 times")),
        "root self-chain X->X->X->X must count 4: {:?}",
        findings
    );
}

#[test]
fn cert_p0_3_two_branches_one_repeat_one_clean() {
    use graphite_core::tx_pattern_analysis::{analyze_cpi_trace, CpiTraceNode};
    let node = |p: &str, d: u32, c: Vec<CpiTraceNode>| CpiTraceNode {
        program_id: p.to_string(),
        instruction_discriminator: String::new(),
        depth: d,
        account_addresses: vec![],
        children: c,
    };
    // Branch 1 repeats Y three times; branch 2 is clean. The max over paths
    // must come from branch 1.
    let trace = node(
        TOKEN_PROGRAM,
        0,
        vec![
            node("y", 1, vec![node("y", 2, vec![node("y", 3, vec![])])]),
            node("z", 1, vec![node("z", 2, vec![])]),
        ],
    );
    let known: Vec<String> = vec![TOKEN_PROGRAM.into(), "y".into(), "z".into()];
    let findings = analyze_cpi_trace(&trace, &known);
    assert!(
        findings
            .iter()
            .any(|f| f.reason.contains("re-enters program y 3 times")),
        "branch-1 repetition must fire: {:?}",
        findings
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.reason.contains("re-enters program z")),
        "clean branch must not fire: {:?}",
        findings
    );
}

// ── P0-4: compositional drain — fresh legitimate contexts ──────────────────

#[test]
fn cert_p0_4_lending_operation_token_cpis_clean() {
    // Lending collateral move: repeated Token/Token-2022 CPIs from a lending
    // protocol (Kamino-style) must stay clean.
    let input = risk_input(
        "KAMINO",
        &["collateral", "reserve"],
        &[
            TOKEN_PROGRAM,
            TOKEN_PROGRAM,
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            TOKEN_PROGRAM,
        ],
        &["debits accounts.collateral", "credits accounts.reserve"],
        &[TOKEN_PROGRAM, "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"],
        "",
        "",
        "",
    );
    let v = assess(&input).unwrap();
    assert!(
        !matches!(
            v,
            RiskVerdict::Blocked {
                pattern: RiskPattern::CompositionalDrainPattern,
                ..
            }
        ),
        "lending collateral moves flagged as drain: {:?}",
        v
    );
}

#[test]
fn cert_p0_4_staking_operation_token_cpis_clean() {
    // Staking flow: Stake program CPI + repeated Token calls (rewards) —
    // universal infrastructure, must stay clean.
    let input = risk_input(
        "Stake11111111111111111111111111111111111111",
        &["stake_acct", "authority"],
        &[
            TOKEN_PROGRAM,
            TOKEN_PROGRAM,
            "11111111111111111111111111111111",
        ],
        &["debits accounts.stake_acct"],
        &[TOKEN_PROGRAM, "11111111111111111111111111111111"],
        "",
        "stake",
        "authority",
    );
    let v = assess(&input).unwrap();
    assert!(
        !matches!(
            v,
            RiskVerdict::Blocked {
                pattern: RiskPattern::CompositionalDrainPattern,
                ..
            }
        ),
        "staking flow flagged as drain: {:?}",
        v
    );
}

#[test]
fn cert_p0_4_bridge_operation_repeated_token_cpis_clean() {
    // Bridge flow: repeated Token CPIs (lock + mint wrapped) must be clean.
    let input = risk_input(
        "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth",
        &["bridge", "token_account"],
        &[
            TOKEN_PROGRAM,
            TOKEN_PROGRAM,
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        ],
        &["debits accounts.bridge"],
        &[TOKEN_PROGRAM, "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"],
        "",
        "",
        "",
    );
    let v = assess(&input).unwrap();
    assert!(
        !matches!(
            v,
            RiskVerdict::Blocked {
                pattern: RiskPattern::CompositionalDrainPattern,
                ..
            }
        ),
        "bridge flow flagged as drain: {:?}",
        v
    );
}

// ── Universal-CPI routing audit: can infrastructure hide a malicious caller?

#[test]
fn cert_p0_4_untrusted_root_calling_token_still_blocked() {
    // An attacker contract CPIing to SPL Token must STILL be blocked by
    // Check 1b (AuthorityHijack) — the universal-CPI whitelist must not make
    // untrusted roots safe.
    let input = risk_input(
        "attacker_contract_xyz",
        &["victim_acct"],
        &[TOKEN_PROGRAM],
        &[],
        &[], // no allowed CPIs — unknown protocol
        "",
        "",
        "",
    );
    let v = assess(&input).unwrap();
    assert!(
        is_blocked(&v),
        "untrusted root CPIing to SPL Token must fail closed: {:?}",
        v
    );
}

#[test]
fn cert_p0_4_manifest_declared_token_cpi_from_known_protocol_approved() {
    // Check 1b manifest-aware refinement: a manifest-BACKED known protocol
    // (Kamino lending, non-trusted root) whose manifest declares the Token
    // CPI in allowed_cpis is authorized — the seed manifest is the curated
    // trust anchor, and the CPI is the protocol's verified surface. Before
    // the fix, EVERY Kamino/Drift/ATA/Metaplex token CPI was hard-blocked as
    // "untrusted root" — a systematic false-positive class.
    let input = risk_input(
        "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD", // Kamino Lending
        &["obligation", "reserve", "liquidity"],
        &[TOKEN_PROGRAM],
        &["debits accounts.liquidity"],
        &[
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        ],
        "",
        "transfer",
        "withdraw",
    );
    let v = assess(&input).unwrap();
    assert!(
        !is_blocked(&v),
        "manifest-declared Token CPI from Kamino must not hard-block: {:?}",
        v
    );
}

#[test]
fn cert_p0_4_ata_create_with_declared_token_cpi_approved() {
    // ATA CreateAssociatedTokenAccount CPIs to System + Token to fund and
    // initialize the associated account — the most basic legitimate
    // operation in Solana. Its manifest declares both CPIs; it must approve.
    let input = risk_input(
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", // ATA
        &["wallet", "mint", "ata", "rent"],
        &["11111111111111111111111111111111", TOKEN_PROGRAM],
        &["creates associated token account"],
        &[
            "11111111111111111111111111111111",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        ],
        "",
        "create",
        "create",
    );
    let v = assess(&input).unwrap();
    assert!(
        !is_blocked(&v),
        "ATA create with manifest-declared Token CPI must not hard-block: {:?}",
        v
    );
}

#[test]
fn cert_p0_4_out_of_manifest_token_cpi_from_known_root_still_blocked() {
    // The manifest-aware refinement must NOT become a bypass: a token CPI
    // that the manifest does NOT declare, from a non-trusted root, is
    // exactly the SetAuthority/CloseAccount smuggling vector — still
    // fail-closed even when the root program itself is manifest-backed.
    let input = risk_input(
        "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD", // Kamino — known
        &["obligation"],
        &[TOKEN_PROGRAM],
        &["debits accounts.obligation"],
        &[], // manifest does NOT declare this CPI
        "",
        "transfer",
        "",
    );
    let v = assess(&input).unwrap();
    assert!(
        matches!(
            v,
            RiskVerdict::Blocked {
                pattern: RiskPattern::AuthorityHijack,
                ..
            }
        ),
        "out-of-manifest Token CPI from known non-trusted root must block: {:?}",
        v
    );
}

#[test]
fn cert_p0_4_malicious_repeats_behind_trusted_root_still_caught() {
    // Even behind a TRUSTED DEX root, repeated visits to a SECURITY-RELEVANT
    // custom program must fire (infrastructure exclusion is per-TARGET, not
    // per-ROOT). The trusted root only shields its own CPI, not the target.
    let input = risk_input(
        "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
        &["a"],
        &["custom_drainer", "custom_drainer", "custom_drainer"],
        &["debits accounts.a"],
        &["custom_drainer"],
        "",
        "swap",
        "",
    );
    let v = assess(&input).unwrap();
    assert!(
        matches!(
            v,
            RiskVerdict::Blocked {
                pattern: RiskPattern::CompositionalDrainPattern,
                ..
            }
        ),
        "repeated custom-program CPI behind trusted root must fire: {:?}",
        v
    );
}

#[test]
fn cert_universal_cpi_audit_single_malicious_call_among_infra_repeats() {
    // Universal-CPI audit (mandate 13): "Can an attacker route malicious
    // behavior through an infrastructure program to hide the real malicious
    // program?" The infrastructure EXCLUSION is per-target and covers only
    // fixed substrate programs that cannot run attacker logic. The residual
    // shape — a SINGLE visit to the attacker's program buried among many
    // SPL Token repeats — must still be blocked by the layered gates:
    //   - compositional-drain Pattern 1 does NOT fire (one custom visit),
    //   - so the block must come from Check 1b (token CPI from an untrusted
    //     root with no manifest-declared allowlist) or the CPI-trace
    //     unknown-program rule when a trace is present.
    //
    // Risk-engine level: the untrusted root's Token CPI is undeclared
    // (empty allowed_cpis ⇒ no manifest authorization) → hard-blocked.
    let input = risk_input(
        "attacker_contract",
        &["a1", "a2"],
        &[
            "attacker_contract",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        ],
        &["debits accounts.a1"],
        &[],
        "",
        "",
        "",
    );
    let v = assess(&input).unwrap();
    assert!(
        is_blocked(&v),
        "attacker hiding among infra repeats must still be blocked: {:?}",
        v
    );

    // Same shape but WITH a manifest-declared Token allowlist (a known
    // non-trusted protocol): compositional-drain must now fire for the
    // repeated attacker visits — the infra exclusion never shields the
    // attacker's own program. (Self-referencing CPI to the root program is
    // the repeat that must trip Pattern 1.)
    let input2 = risk_input(
        "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD",
        &["a1", "a2"],
        &[
            "attacker_contract",
            "attacker_contract",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        ],
        &["debits accounts.a1"],
        &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
        "",
        "",
        "",
    );
    let v2 = assess(&input2).unwrap();
    assert!(
        is_blocked(&v2),
        "repeated attacker visits must trip compositional drain even with declared Token CPI: {:?}",
        v2
    );
}
