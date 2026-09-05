//! CRITICAL regression suite — Milestone 4 red-team pass (2026-09-05).
//!
//! Two independently-confirmed gate bypasses, each verified end-to-end against
//! a live server BEFORE being fixed. Chained together they produced a total
//! compromise: a hidden account-draining instruction approved with a Clear
//! risk verdict.
//!
//! ## Bypass 1 — the empty discriminator
//!
//! `assess_secondary_instructions` skipped every structural risk check for any
//! instruction with an empty discriminator. That carve-out was correct for
//! CPI-TRACE nodes (trace introspection often cannot recover a callee's
//! instruction data, so blocking there would false-positive on nearly every
//! real DEX route) — but it was applied to caller-DECLARED
//! `transaction_instructions` too. A caller declaring an instruction has no
//! excuse to omit the one field every check keys on. Attack: declare a real
//! CloseAccount/SetAuthority/Approve with `instruction_discriminator: ""` and
//! it sails past Check 2's table, the AAT correlation rules, and everything
//! else, returning `risk: Clear`.
//!
//! ## Bypass 2 — the caller-chosen policy profile
//!
//! `wallet_profile` arrives in the SAME request body as `proposed_intent` and
//! `program_id` — supplied by the very agent that may be prompt-injected.
//! Sending `{"Custom":{"min_confidence":0.0,"min_trust_tier":"Unknown"}}`
//! approved a transaction to a completely unmanifested program at confidence
//! 0.0. P6's ceiling still computed correctly; it simply stopped gating
//! anything, because the threshold it was compared against was attacker-chosen.
//!
//! These tests assert the FIXES hold. The server-boundary half of bypass 2
//! (profile pinning/clamping) is covered by the unit tests in `server.rs`,
//! since it is deliberately enforced at the network boundary rather than in
//! the core — a library embedder is its own operator and may legitimately
//! choose any profile.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::tx_pattern_analysis::{CpiTraceNode, TransactionInstruction};
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

const SYSTEM: &str = "11111111111111111111111111111111";
const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const VICTIM: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const ATTACKER: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

/// A benign-looking primary transfer, so any block is attributable to the
/// secondary instruction under test rather than to the primary.
fn benign_primary() -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send a little SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![VICTIM.to_string(), ATTACKER.to_string()],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
    }
}

/// THE attack: a caller-declared instruction that hides what it does by
/// omitting its discriminator. Before the fix this returned `risk: Clear`.
#[test]
fn declared_secondary_with_empty_discriminator_is_blocked() {
    let core = GraphiteCore::new();
    let mut input = benign_primary();
    input.transaction_instructions = vec![TransactionInstruction {
        program_id: SPL_TOKEN.to_string(),
        // The real on-chain bytes are 0x09 (CloseAccount) sweeping the victim.
        instruction_discriminator: String::new(),
        account_addresses: vec![VICTIM.to_string(), ATTACKER.to_string()],
        cpi_targets: vec![],
    }];

    let result = core.verify(&input).unwrap();

    assert_eq!(
        result.risk_verdict.status, "Blocked",
        "a caller-DECLARED instruction that omits its discriminator must fail closed — \
         it cannot be verified and there is no observability excuse for omitting it. \
         findings={:?}",
        result.risk_verdict.findings
    );
    assert!(!result.approved);
}

/// The carve-out must SURVIVE for its legitimate case: a CPI-trace node
/// genuinely may not know its own discriminator. Blocking here would
/// false-positive on nearly every real DEX route, so this must stay a
/// non-blocking warning. This is the test that keeps the fix honest — it is
/// what stops "fix the bypass" from becoming "block everything".
#[test]
fn cpi_trace_node_with_empty_discriminator_is_still_only_warned() {
    let core = GraphiteCore::new();
    let mut input = benign_primary();
    input.cpi_trace = Some(CpiTraceNode {
        program_id: SYSTEM.to_string(),
        instruction_discriminator: String::new(),
        depth: 0,
        account_addresses: vec![],
        children: vec![CpiTraceNode {
            program_id: SPL_TOKEN.to_string(),
            instruction_discriminator: String::new(),
            depth: 1,
            account_addresses: vec![VICTIM.to_string(), ATTACKER.to_string()],
            children: vec![],
        }],
    });

    let result = core.verify(&input).unwrap();

    assert_eq!(
        result.risk_verdict.status, "Clear",
        "a CPI-trace node with no recoverable discriminator must NOT block — \
         that would false-positive on ordinary DEX routes. findings={:?}",
        result.risk_verdict.findings
    );
    assert!(
        result.summary.contains("no discriminator available"),
        "the observability limit must still be disclosed: {}",
        result.summary
    );
}

/// The distinction is specifically about ORIGIN, not position: the same
/// empty-discriminator instruction must block when declared and warn when
/// traced. Asserting both in one test pins the boundary itself.
#[test]
fn origin_decides_whether_an_empty_discriminator_blocks() {
    let core = GraphiteCore::new();

    let mut declared = benign_primary();
    declared.transaction_instructions = vec![TransactionInstruction {
        program_id: SPL_TOKEN.to_string(),
        instruction_discriminator: String::new(),
        account_addresses: vec![VICTIM.to_string(), ATTACKER.to_string()],
        cpi_targets: vec![],
    }];

    let mut traced = benign_primary();
    traced.cpi_trace = Some(CpiTraceNode {
        program_id: SYSTEM.to_string(),
        instruction_discriminator: String::new(),
        depth: 0,
        account_addresses: vec![],
        children: vec![CpiTraceNode {
            program_id: SPL_TOKEN.to_string(),
            instruction_discriminator: String::new(),
            depth: 1,
            account_addresses: vec![VICTIM.to_string(), ATTACKER.to_string()],
            children: vec![],
        }],
    });

    assert_eq!(
        core.verify(&declared).unwrap().risk_verdict.status,
        "Blocked"
    );
    assert_eq!(core.verify(&traced).unwrap().risk_verdict.status, "Clear");
}

/// Multiple declared instructions each omitting their discriminator must all
/// be caught — the block cannot be diluted by volume.
#[test]
fn several_declared_empty_discriminator_instructions_all_block() {
    let core = GraphiteCore::new();
    let mut input = benign_primary();
    input.transaction_instructions = (0..4)
        .map(|_| TransactionInstruction {
            program_id: SPL_TOKEN.to_string(),
            instruction_discriminator: String::new(),
            account_addresses: vec![VICTIM.to_string(), ATTACKER.to_string()],
            cpi_targets: vec![],
        })
        .collect();

    let result = core.verify(&input).unwrap();
    assert_eq!(result.risk_verdict.status, "Blocked");
    assert!(!result.approved);
}

/// A declared instruction that DOES carry its discriminator keeps working
/// exactly as before — the fix must not have turned ordinary multi-instruction
/// transactions into blocks.
#[test]
fn declared_secondary_with_a_real_discriminator_is_unaffected() {
    let core = GraphiteCore::new();
    let mut input = benign_primary();
    input.transaction_instructions = vec![TransactionInstruction {
        program_id: SPL_TOKEN.to_string(),
        instruction_discriminator: "03".to_string(), // an ordinary transfer
        account_addresses: vec![VICTIM.to_string(), ATTACKER.to_string()],
        cpi_targets: vec![],
    }];

    let result = core.verify(&input).unwrap();
    assert_eq!(
        result.risk_verdict.status, "Clear",
        "an ordinary declared transfer must not be blocked: {:?}",
        result.risk_verdict.findings
    );
}

/// Determinism (P2) across the new origin-sensitive path.
#[test]
fn empty_discriminator_handling_is_deterministic() {
    let core = GraphiteCore::new();
    let mut input = benign_primary();
    input.transaction_instructions = vec![TransactionInstruction {
        program_id: SPL_TOKEN.to_string(),
        instruction_discriminator: String::new(),
        account_addresses: vec![VICTIM.to_string(), ATTACKER.to_string()],
        cpi_targets: vec![],
    }];
    let a = core.verify(&input).unwrap();
    let b = core.verify(&input).unwrap();
    assert_eq!(a.approved, b.approved);
    assert_eq!(a.risk_verdict, b.risk_verdict);
    assert_eq!(a.content_hash, b.content_hash);
}
