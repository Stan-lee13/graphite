//! L4 real state diffing, exercised end to end through `verify`.
//!
//! `state_diff.rs` has its own unit tests for the decoders and the finding
//! rules. These tests exist to answer a different question: is any of that
//! actually WIRED IN? A diff engine that computes perfect findings which the
//! pipeline never reads is worse than none — it reports a capability the gate
//! does not have.
//!
//! So every test here goes through `GraphiteCore::verify` and asserts on the
//! layer report and the final verdict, never on `check_state_diff` directly.
//!
//! Anti-vacuity: `a_clean_transfer_with_no_diff_is_approved` establishes that
//! the fixture APPROVES without a diff. Every blocking test below reuses that
//! same fixture and changes only the diff, so a passing block assertion cannot
//! be an artefact of the fixture failing for some unrelated reason.

use graphite_core::semantic_graph_store::{Behavior, BehaviorEvidence, TrustTier};
use graphite_core::state_diff::{
    AccountDelta, AccountSnapshot, DiffProvenance, StateDiff, SPL_TOKEN_PROGRAM, SYSTEM_PROGRAM,
};
use graphite_core::verification::{GraphiteCore, LayerStatus, ProposedIntent, VerificationInput};
use graphite_core::WalletProfile;

const SIGNER: &str = "7vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const RECIPIENT: &str = "6bSsP4p6wXqFJdD2TkYgNcVmLzHfWq7pRyA8tCzE5nBj";
const ATTACKER_PROGRAM: &str = "GdP9U5aYx7f2kQzVwNmT8jRcL4hB6eX3sDnWqA1uMoH";

fn battle_tested_evidence() -> BehaviorEvidence {
    BehaviorEvidence {
        has_signed_manifest: true,
        community_verified_count: 2,
        battle_tested_tx_count: 1000,
        simulation_match_count: 100,
    }
}

/// A plain System transfer at BattleTested tier — the most permissive starting
/// point there is, so anything that blocks below blocks on the diff alone.
fn transfer(diff: Option<StateDiff>) -> VerificationInput {
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
        state_diff: diff,
    }
}

fn core() -> GraphiteCore {
    let mut core = GraphiteCore::new();
    core.seed_behavior(Behavior {
        program_id: SYSTEM_PROGRAM.to_string(),
        version: "1.0.0".to_string(),
        expected_state_changes: vec!["debits accounts.from by amount".to_string()],
        allowed_cpis: vec![],
        trust_tier: TrustTier::Unknown, // recomputed by append (P7)
        evidence: battle_tested_evidence(),
        quarantined: false,
        quarantine_reason: None,
    })
    .expect("behavior seed");
    core
}

fn lamports(pubkey: &str, n: u64) -> AccountSnapshot {
    AccountSnapshot {
        pubkey: pubkey.to_string(),
        lamports: n,
        owner: SYSTEM_PROGRAM.to_string(),
        data_len: 0,
        token: None,
        mint: None,
    }
}

/// The 165-byte SPL token account layout, built directly so the pipeline runs
/// the real decoder rather than a hand-assembled view.
fn token_account(amount: u64, delegate: Option<[u8; 32]>) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(&[7u8; 32]); // mint
    d[32..64].copy_from_slice(&[9u8; 32]); // owner
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    if let Some(del) = delegate {
        d[72..76].copy_from_slice(&1u32.to_le_bytes());
        d[76..108].copy_from_slice(&del);
    }
    d[108] = 1; // initialized
    d
}

fn diff(deltas: Vec<AccountDelta>) -> StateDiff {
    StateDiff {
        deltas,
        provenance: DiffProvenance::CallerSupplied,
        fee_lamports: 5_000,
        covers_all_writable: false,
    }
}

fn l4(result: &graphite_core::verification::VerificationResult) -> (LayerStatus, String) {
    let layer = result
        .layers
        .iter()
        .find(|l| l.layer == "L4_StateVerification")
        .expect("L4 must always be reported");
    (layer.status, layer.reason.clone())
}

// ── Anti-vacuity baseline ───────────────────────────────────────────────────

#[test]
fn a_clean_transfer_with_no_diff_is_approved() {
    let result = core().verify(&transfer(None)).unwrap();
    assert!(
        result.approved,
        "the shared fixture must approve without a diff, or every block below \
         proves nothing. reason: {}",
        result.summary
    );
}

// ── The diff actually reaches the layer ─────────────────────────────────────

#[test]
fn an_owner_reassignment_in_the_diff_fails_l4_and_blocks_the_transaction() {
    // The takeover: the instruction says "transfer", the diff shows the
    // signer's account handed to another program. Nothing else about the
    // request changes from the approved baseline.
    let mut after = lamports(SIGNER, 10_000_000);
    after.owner = ATTACKER_PROGRAM.to_string();
    let result = core()
        .verify(&transfer(Some(diff(vec![AccountDelta {
            pubkey: SIGNER.to_string(),
            before: Some(lamports(SIGNER, 10_000_000)),
            after: Some(after),
        }]))))
        .unwrap();

    let (status, reason) = l4(&result);
    assert_eq!(status, LayerStatus::Failed, "L4 reason: {reason}");
    assert!(
        reason.contains("UndeclaredOwnerReassignment"),
        "the layer must name what it found (P3): {reason}"
    );
    assert!(
        !result.approved,
        "a failed L4 is a hard gate; verdict was {} / {}",
        result.policy_verdict, result.summary
    );
}

#[test]
fn a_delegate_granted_in_the_diff_blocks_the_transaction() {
    // The approval-drain: the transfer succeeds and quietly leaves a third
    // party standing permission to move the tokens afterwards.
    let before = AccountSnapshot::from_raw(
        RECIPIENT,
        2_039_280,
        SPL_TOKEN_PROGRAM,
        &token_account(1_000, None),
    );
    let after = AccountSnapshot::from_raw(
        RECIPIENT,
        2_039_280,
        SPL_TOKEN_PROGRAM,
        &token_account(1_000, Some([66u8; 32])),
    );
    assert!(
        before.token.is_some() && after.token.is_some(),
        "fixture must decode"
    );

    let result = core()
        .verify(&transfer(Some(diff(vec![AccountDelta {
            pubkey: RECIPIENT.to_string(),
            before: Some(before),
            after: Some(after),
        }]))))
        .unwrap();

    let (status, reason) = l4(&result);
    assert_eq!(status, LayerStatus::Failed, "L4 reason: {reason}");
    assert!(reason.contains("UndeclaredDelegateGrant"), "{reason}");
    assert!(!result.approved);
}

#[test]
fn a_delta_on_an_account_outside_the_instruction_blocks_the_transaction() {
    // A diff that describes an account the transaction never references is a
    // diff that does not belong to this transaction.
    let result = core()
        .verify(&transfer(Some(diff(vec![AccountDelta {
            pubkey: ATTACKER_PROGRAM.to_string(),
            before: Some(lamports(ATTACKER_PROGRAM, 0)),
            after: Some(lamports(ATTACKER_PROGRAM, 999_999)),
        }]))))
        .unwrap();

    let (status, reason) = l4(&result);
    assert_eq!(status, LayerStatus::Failed, "L4 reason: {reason}");
    assert!(reason.contains("DiffAccountNotInInstruction"), "{reason}");
    assert!(!result.approved);
}

// ── Provenance (Constitution P5) ────────────────────────────────────────────

#[test]
fn a_clean_caller_supplied_diff_is_inconclusive_never_passed() {
    // An attacker who can hand Graphite a diff must not be able to hand it a
    // clean bill of health. A caller diff may fail the layer (nobody
    // self-incriminates) but may never certify it.
    let result = core()
        .verify(&transfer(Some(diff(vec![AccountDelta {
            pubkey: SIGNER.to_string(),
            before: Some(lamports(SIGNER, 10_000_000)),
            after: Some(lamports(SIGNER, 9_000_000)),
        }]))))
        .unwrap();

    let (status, reason) = l4(&result);
    assert_eq!(
        status,
        LayerStatus::Inconclusive,
        "an unverified diff must never certify L4. reason: {reason}"
    );
    assert!(
        reason.contains("supplied by the caller"),
        "the reason must say WHY it is inconclusive (P3): {reason}"
    );
}

#[test]
fn the_same_clean_diff_passes_l4_when_it_carries_rpc_provenance() {
    // The mirror of the test above: identical deltas, only the provenance
    // differs. If this also came back Inconclusive the provenance rule would
    // be indistinguishable from "the diff path never passes anything".
    let mut d = diff(vec![AccountDelta {
        pubkey: SIGNER.to_string(),
        before: Some(lamports(SIGNER, 10_000_000)),
        after: Some(lamports(SIGNER, 9_000_000)),
    }]);
    d.provenance = DiffProvenance::RpcSimulated;

    let result = core().verify(&transfer(Some(d))).unwrap();
    let (status, reason) = l4(&result);
    assert_eq!(status, LayerStatus::Passed, "L4 reason: {reason}");
    // The heuristic ALSO returns Passed for this fixture, so the status alone
    // proves nothing about whether the diff was read. The reason has to show
    // the diff path ran.
    assert!(
        reason.contains("State diff verified against the manifest"),
        "L4 passed, but not by way of the diff — the diff path is not wired in: {reason}"
    );
    assert!(result.approved, "{}", result.summary);
}

// ── Fallback and boundaries ─────────────────────────────────────────────────

#[test]
fn an_empty_diff_is_inconclusive_rather_than_a_free_pass() {
    // A diff that shows nothing changed is not evidence that nothing wrong
    // happened — it may simply not reflect the transaction.
    let mut d = diff(vec![AccountDelta {
        pubkey: SIGNER.to_string(),
        before: Some(lamports(SIGNER, 10_000_000)),
        after: Some(lamports(SIGNER, 10_000_000)),
    }]);
    d.provenance = DiffProvenance::RpcSimulated;

    let result = core().verify(&transfer(Some(d))).unwrap();
    let (status, reason) = l4(&result);
    assert_eq!(status, LayerStatus::Inconclusive, "L4 reason: {reason}");
    assert!(reason.contains("no observable change"), "{reason}");
}

#[test]
fn without_a_diff_the_layer_still_runs_the_account_shape_heuristic() {
    // The diff path must EXTEND L4, not replace it. Removing the diff must not
    // silently turn the layer off for the overwhelming majority of callers who
    // have no diff to give.
    let result = core().verify(&transfer(None)).unwrap();
    let (status, reason) = l4(&result);
    assert_ne!(
        status,
        LayerStatus::Failed,
        "a clean transfer must not fail the heuristic: {reason}"
    );
    assert!(
        !reason.contains("State diff"),
        "with no diff supplied, L4 must not claim to have diffed anything: {reason}"
    );
}

#[test]
fn a_diff_never_turns_a_transaction_that_would_be_blocked_into_an_approval() {
    // The one direction the diff path must never move a verdict. An RPC-clean
    // diff on a transaction the rest of the pipeline rejects must leave it
    // rejected — L4 is one layer, not an override.
    let mut input = transfer(None);
    // An unknown program with no manifest cannot clear the P6 ceiling.
    input.program_id = ATTACKER_PROGRAM.to_string();
    input.behavior_evidence = BehaviorEvidence::default();
    input.wallet_profile = WalletProfile::Treasury;
    let without = core().verify(&input).unwrap();
    assert!(!without.approved, "baseline must be rejected");

    let mut d = diff(vec![AccountDelta {
        pubkey: SIGNER.to_string(),
        before: Some(lamports(SIGNER, 10_000_000)),
        after: Some(lamports(SIGNER, 9_000_000)),
    }]);
    d.provenance = DiffProvenance::RpcSimulated;
    input.state_diff = Some(d);

    let with = core().verify(&input).unwrap();
    assert!(
        !with.approved,
        "a clean state diff must never rescue an otherwise-rejected transaction: {}",
        with.summary
    );
}
