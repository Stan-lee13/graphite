//! A2-04 (2026-09-29 audit): a caller-supplied state diff is additive
//! evidence. It may fail L4; it never displaces the structural check.
//!
//! With no observed diff, L4 used the caller's `state_diff` in place of the
//! structural check. Attaching `state_diff: {deltas: []}` to a request the
//! structural check fails turned L4 from Failed into Inconclusive ("no
//! observable change") and lifted the rejection a Failed L4 carries.
//!
//! The fix matches on `(observed_diff, caller_diff)`. With a caller diff and
//! no observed one, both the diff check and the structural check run, and a
//! structural Failed stands.
//!
//! The test takes a System transfer described with only its `from` account,
//! which the structural check fails (the control), and pins that the same
//! request with an empty caller diff still has L4 Failed and is not approved.

use graphite_core::semantic_graph_store::{BehaviorEvidence, TrustTier};
use graphite_core::state_diff::{DiffProvenance, StateDiff, SYSTEM_PROGRAM};
use graphite_core::verification::{GraphiteCore, LayerStatus, ProposedIntent, VerificationInput};
use graphite_core::WalletProfile;

const SIGNER: &str = "7vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";

/// A System Transfer described with only its `from` account: the manifest's
/// "debits ... / credits ..." needs two writable accounts and the request
/// resolves one, so the structural L4 check fails.
fn short_transfer(diff: Option<StateDiff>) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "Send 0.000001 SOL".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: SYSTEM_PROGRAM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![SIGNER.to_string()],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Custom {
            min_confidence: 0.0,
            min_trust_tier: TrustTier::Unknown,
        },
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 150,
        account_writes: 1,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: diff,
    }
}

fn empty_caller_diff() -> StateDiff {
    StateDiff {
        deltas: vec![],
        provenance: DiffProvenance::CallerSupplied,
        fee_lamports: 0,
        covers_all_writable: false,
        artifact_balance_writes: None,
        artifact_account_universe: None,
        artifact_accounts_undescribed: None,
        transfer_fee_mints: Default::default(),
        token2022_executed: None,
        fee_epoch: None,
        token2022_mints: Default::default(),
        transaction_accounts: None,
        transaction_privileges: None,
    }
}

fn l4(r: &graphite_core::verification::VerificationResult) -> (LayerStatus, String) {
    let l = r
        .layers
        .iter()
        .find(|l| l.layer == "L4_StateVerification")
        .expect("L4 reported");
    (l.status, l.reason.clone())
}

#[test]
fn an_empty_caller_diff_does_not_lift_a_structural_l4_failure() {
    let core = GraphiteCore::new();

    // Control: the structural check fails this request.
    let without = core.verify(&short_transfer(None)).expect("verifies");
    let (status, reason) = l4(&without);
    assert_eq!(status, LayerStatus::Failed, "control: {reason}");
    assert!(!without.approved);

    // Same request, plus a diff the caller wrote with nothing in it.
    let with = core
        .verify(&short_transfer(Some(empty_caller_diff())))
        .expect("verifies");
    let (status, reason) = l4(&with);
    assert_eq!(
        status,
        LayerStatus::Failed,
        "a caller-supplied (unverifiable) diff displaced the structural check: {reason}"
    );
    assert!(!with.approved, "{}", with.summary);
}
