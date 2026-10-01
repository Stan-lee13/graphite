//! A3-03 (2026-09-29 audit): an operator quarantine blocks every transaction
//! that reaches the quarantined program, not only one whose primary it is.
//!
//! `verification.rs` treats a quarantined program as a hard block (the
//! operator asserting evidence of a problem), and
//! `semantic_graph_store::quarantine` documents pre-emptive quarantine of a
//! never-seen program, in reaction to an advisory, as the normal case. The
//! check looked up `input.program_id` only: a declared sibling, a declared CPI
//! trace node or an observed CPI callee was never looked up, so the same
//! program one position down the transaction was judged as if nothing had
//! been said about it.
//!
//! The fix: `invoked_programs` collects every program the transaction reaches
//! (the primary, the declared siblings and their CPI targets, the declared
//! trace, the artifact's top-level instructions, and the observed CPI callees
//! and tree), and the quarantine gate blocks on any of them with the pattern
//! `ProgramQuarantined`.
//!
//! The controls pin that a quarantined primary is blocked and that the
//! transfer alone is approved on Gaming, so the harness does not refuse
//! everything. The attacks pin a Block for the quarantined program as an
//! unmanifested sibling, as a manifested sibling (Jupiter V6) and as a node in
//! the declared CPI trace.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::simulation_integrity::ComputeBaseline;
use graphite_core::tx_pattern_analysis::{CpiTraceNode, TransactionInstruction};
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

const SYSTEM: &str = "11111111111111111111111111111111";
const JUPITER: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
/// The program named in the advisory (no manifest).
const DRAINER: &str = "4rQz2f4Wc1y7DpQ8v6mW2nN5uM3sR9bHjC1kTv8XwYdL";
const VICTIM: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const FRIEND: &str = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7";
const ATTACKER: &str = "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx";

fn transfer(
    siblings: Vec<TransactionInstruction>,
    trace: Option<CpiTraceNode>,
) -> VerificationInput {
    let mut data = vec![2u8, 0, 0, 0];
    data.extend_from_slice(&1_000_000u64.to_le_bytes());
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: String::new(),
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
        transaction_instructions: siblings,
        cpi_trace: trace,
        real_account_metas: vec![],
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        state_diff: None,
    }
}

fn call(program: &str, disc: &str, accounts: &[&str]) -> TransactionInstruction {
    TransactionInstruction {
        program_id: program.to_string(),
        instruction_discriminator: disc.to_string(),
        account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
        cpi_targets: vec![],
    }
}

fn core_with_quarantine(program: &str) -> GraphiteCore {
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
    core.quarantine_program(program, "advisory: drainer contract")
        .unwrap();
    core
}

#[test]
fn control_a_quarantined_primary_is_blocked() {
    let core = core_with_quarantine(DRAINER);
    let mut input = transfer(vec![], None);
    input.program_id = DRAINER.to_string();
    input.instruction_discriminator = "01".to_string();
    input.instruction_data = Some(vec![1]);
    let r = core.verify(&input).unwrap();
    assert!(!r.approved);
    assert!(
        r.risk_verdict
            .findings
            .iter()
            .any(|f| f.pattern == "ProgramQuarantined"),
        "{:?}",
        r.risk_verdict
    );
}

#[test]
fn control_the_transfer_alone_is_approved_on_gaming() {
    // Anti-vacuity: the approval below is not an artefact of the harness
    // refusing everything.
    let core = core_with_quarantine(DRAINER);
    let r = core.verify(&transfer(vec![], None)).unwrap();
    assert!(
        r.approved,
        "conf {:.3} risk {:?}",
        r.confidence, r.risk_verdict
    );
}

#[test]
fn attack_a_quarantined_program_as_a_sibling_is_blocked() {
    let core = core_with_quarantine(DRAINER);
    let r = core
        .verify(&transfer(
            vec![call(DRAINER, "01", &[VICTIM, ATTACKER])],
            None,
        ))
        .unwrap();
    assert!(
        !r.approved && r.risk_verdict.status == "Blocked",
        "a transaction invoking the quarantined program as its second instruction was approved={} \
         risk={:?}",
        r.approved,
        r.risk_verdict
    );
}

#[test]
fn attack_a_quarantined_manifested_program_as_a_sibling_is_blocked() {
    // The operator withdraws Jupiter V6 after an incident; a Jupiter route
    // beside a transfer is blocked by the quarantine, not judged only by the
    // ordinary sibling rules.
    let core = core_with_quarantine(JUPITER);
    let accounts: Vec<&str> = vec![VICTIM, ATTACKER, FRIEND, ATTACKER, VICTIM, FRIEND, ATTACKER];
    let r = core
        .verify(&transfer(
            vec![call(JUPITER, "e517cb977ae3ad2a", &accounts)],
            None,
        ))
        .unwrap();
    assert_eq!(r.risk_verdict.status, "Blocked", "{:?}", r.risk_verdict);
}

#[test]
fn attack_a_quarantined_program_in_the_cpi_trace_is_blocked() {
    // A manifested primary whose declared trace calls the quarantined program.
    let core = core_with_quarantine(JUPITER);
    let trace = CpiTraceNode {
        program_id: SYSTEM.to_string(),
        instruction_discriminator: "02000000".to_string(),
        depth: 0,
        account_addresses: vec![],
        children: vec![CpiTraceNode {
            program_id: JUPITER.to_string(),
            instruction_discriminator: "e517cb977ae3ad2a".to_string(),
            depth: 1,
            account_addresses: vec![],
            children: vec![],
        }],
    };
    let r = core.verify(&transfer(vec![], Some(trace))).unwrap();
    assert_eq!(r.risk_verdict.status, "Blocked", "{:?}", r.risk_verdict);
}
