//! Quarantine, exercised as a control rather than as a primitive.
//!
//! `SemanticGraphStore::quarantine` has existed and been unit-tested since
//! Phase 1, and until 2026-09-05 nothing in the system ever called it. A
//! capability the dashboard displays, the graph API reports, and no code path
//! can reach is a claim the gate does not honour.
//!
//! So these tests go through `GraphiteCore` and assert on `verify`: does
//! withdrawing a program from trust actually change what the gate decides, does
//! it survive a restart, and can the program undo it by itself?

use graphite_core::semantic_graph_store::{Behavior, BehaviorEvidence, TrustTier};
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};
use graphite_core::WalletProfile;

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const SIGNER: &str = "7vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const RECIPIENT: &str = "6bSsP4p6wXqFJdD2TkYgNcVmLzHfWq7pRyA8tCzE5nBj";

fn battle_tested_evidence() -> BehaviorEvidence {
    BehaviorEvidence {
        has_signed_manifest: true,
        community_verified_count: 2,
        battle_tested_tx_count: 1000,
        simulation_match_count: 100,
    }
}

fn behavior(version: &str) -> Behavior {
    Behavior {
        program_id: SYSTEM_PROGRAM.to_string(),
        version: version.to_string(),
        expected_state_changes: vec!["debits accounts.from by amount".to_string()],
        allowed_cpis: vec![],
        trust_tier: TrustTier::Unknown, // recomputed by append (P7)
        evidence: battle_tested_evidence(),
        quarantined: false,
        quarantine_reason: None,
    }
}

/// A transfer that requires a real trust tier to clear, so a forced downgrade
/// to Unknown is what decides it.
fn transfer() -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Send 0.000001 SOL to Alice".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: SYSTEM_PROGRAM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![SIGNER.to_string(), RECIPIENT.to_string()],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Custom {
            min_confidence: 0.40,
            min_trust_tier: TrustTier::OfficialManifest,
        },
        behavior_evidence: battle_tested_evidence(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

fn trusted_core() -> GraphiteCore {
    let mut core = GraphiteCore::new();
    core.seed_behavior(behavior("1.0.0")).expect("seed");
    core
}

#[test]
fn a_trusted_program_is_approved_before_any_quarantine() {
    // Anti-vacuity: every assertion below compares against this baseline, so
    // if the fixture did not approve on its own they would prove nothing.
    let result = trusted_core().verify(&transfer()).unwrap();
    assert!(result.approved, "{}", result.summary);
}

#[test]
fn quarantining_a_program_blocks_it_at_the_gate() {
    let core = trusted_core();
    core.quarantine_program(SYSTEM_PROGRAM, "upstream advisory: authority takeover")
        .expect("quarantine");

    let result = core.verify(&transfer()).unwrap();
    assert!(
        !result.approved,
        "a withdrawn program must not clear the gate: {}",
        result.summary
    );
    assert_eq!(
        result.trust_tier, "Unknown",
        "quarantine forces the tier to Unknown (P7), got {}",
        result.trust_tier
    );
}

#[test]
fn lifting_a_quarantine_restores_the_tier_the_evidence_earns() {
    let core = trusted_core();
    core.quarantine_program(SYSTEM_PROGRAM, "incident").unwrap();
    assert!(!core.verify(&transfer()).unwrap().approved);

    core.lift_program_quarantine(SYSTEM_PROGRAM)
        .expect("lift must succeed on an active quarantine");
    let result = core.verify(&transfer()).unwrap();
    assert!(
        result.approved,
        "a lifted program must be usable again: {}",
        result.summary
    );
}

#[test]
fn a_new_behavior_record_cannot_lift_a_quarantine() {
    // The path that mattered: `manifest_registry::submit` appends a behavior
    // record for every accepted submission, and a resubmission at the same tier
    // is not a promotion, so it is not P10-gated either. If an append cleared
    // quarantine, publishing any new version would be a self-service restore
    // available to the actor whose program had just been withdrawn.
    let mut core = trusted_core();
    core.quarantine_program(SYSTEM_PROGRAM, "incident").unwrap();

    core.seed_behavior(behavior("2.0.0"))
        .expect("the upgrade is still recorded");

    let result = core.verify(&transfer()).unwrap();
    assert!(
        !result.approved,
        "shipping a new version must not restore a withdrawn program: {}",
        result.summary
    );
    assert_eq!(result.trust_tier, "Unknown");
}

#[test]
fn quarantine_requires_a_reason() {
    // An unexplained withdrawal of trust is not an auditable one (P9), and the
    // operator reading the listing six months later is the one who pays.
    let core = trusted_core();
    assert!(core.quarantine_program(SYSTEM_PROGRAM, "   ").is_err());
    assert!(core.quarantine_program(SYSTEM_PROGRAM, "").is_err());
    assert!(
        core.verify(&transfer()).unwrap().approved,
        "a rejected quarantine must not half-apply"
    );
}

#[test]
fn lifting_something_that_is_not_quarantined_is_an_error() {
    let core = trusted_core();
    assert!(core.lift_program_quarantine(SYSTEM_PROGRAM).is_err());
    assert!(core.lift_program_quarantine("never-seen-program").is_err());
}

#[test]
fn quarantine_survives_a_restart() {
    // Quarantine that evaporates on the next deploy is not a control. This is
    // the durability path the CLI and the server both rely on.
    let dir = std::env::temp_dir().join(format!(
        "graphite-quarantine-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();

    {
        let mut core = GraphiteCore::with_data_dir(dir.clone());
        core.seed_behavior(behavior("1.0.0")).unwrap();
        assert!(
            core.verify(&transfer()).unwrap().approved,
            "baseline must approve before the quarantine"
        );
        core.quarantine_program(SYSTEM_PROGRAM, "incident").unwrap();
    }

    let reloaded = GraphiteCore::with_data_dir(dir.clone());
    assert_eq!(
        reloaded.quarantined_programs(),
        vec![(SYSTEM_PROGRAM.to_string(), "incident".to_string())]
    );
    assert!(
        !reloaded.verify(&transfer()).unwrap().approved,
        "a quarantine must outlive the process that set it"
    );

    // And a lift persists too, or recovery would need a hand-edited snapshot.
    reloaded.lift_program_quarantine(SYSTEM_PROGRAM).unwrap();
    let after_lift = GraphiteCore::with_data_dir(dir.clone());
    assert!(after_lift.quarantined_programs().is_empty());
    assert!(after_lift.verify(&transfer()).unwrap().approved);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_listing_reports_only_currently_active_quarantines() {
    let core = trusted_core();
    assert!(core.quarantined_programs().is_empty());

    core.quarantine_program(SYSTEM_PROGRAM, "incident").unwrap();
    assert_eq!(
        core.quarantined_programs(),
        vec![(SYSTEM_PROGRAM.to_string(), "incident".to_string())]
    );

    core.lift_program_quarantine(SYSTEM_PROGRAM).unwrap();
    assert!(
        core.quarantined_programs().is_empty(),
        "a lifted quarantine must leave the listing, even though P4 keeps it in history"
    );
}
