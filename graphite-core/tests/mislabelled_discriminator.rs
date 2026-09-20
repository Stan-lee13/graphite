//! GFX-001 (2026-09-17 forensic audit): the Risk Engine judged the label, not
//! the instruction.
//!
//! `RiskAssessmentInput.instruction_discriminator` was `input
//! .instruction_discriminator` — a string the caller wrote — and the one place
//! that compared it against `instruction_data` sat BELOW the manifest lookup in
//! L2, so it ran only on a manifest HIT. A discriminator matching no manifest
//! entry took the `None` arm's P12 soft pass and returned before the comparison
//! was reached. Every check keyed on the discriminator then keyed on a value
//! nothing had grounded:
//!
//!   - Check 2's known-risky table (SetAuthority `06`, CloseAccount `09`,
//!     Approve `04`, System Assign `01000000`),
//!   - Check 6a/6b/7's intent-mismatch gates,
//!   - `manifest_risk_class`, which is `String::new()` on an unknown
//!     instruction, so Check 10 could not back any of them up.
//!
//! Reproduced against `eaee998` with identical transaction bytes and identical
//! `instruction_data`, varying only the declared discriminator:
//!
//! ```text
//!   SetAuthority, declared "06" → approved=false, Blocked [AuthorityHijack]
//!   SetAuthority, declared "ff" → approved=true,  Clear, confidence 0.640,
//!                                 scope=artifact_bound
//! ```
//!
//! CloseAccount (`09`→`ff`) and System Assign (`01000000`→`ffffffff`)
//! reproduced identically. The confidence ceiling of 0.640 kept TradingBot
//! (0.80), Treasury (0.95) and Enterprise (0.99) out of it, and the SAK
//! bridge's swap path was incidentally shielded because `AuditBind` re-derives
//! the discriminator from the data bytes — but Gaming's 0.55 threshold, the
//! bridge's own `Custom` default, the Go and TypeScript SDKs, the Python layer
//! and any direct HTTP caller were not.
//!
//! What this file pins, in the order the request meets it:
//!
//!   1. A discriminator that is not hex is refused outright, before any
//!      verdict exists (`transaction_builder::InvalidDiscriminator`). This is
//!      not new — it is why the bypass needed a hex label — and it is pinned
//!      here because it is the reason the word-shaped variant is unreachable.
//!   2. A hex discriminator that contradicts the `instruction_data` beside it
//!      fails L2, for every protocol, manifested or not. That comparison used
//!      to run only after a manifest hit; it now runs first.
//!   3. The Risk Engine is handed the instruction's own leading bytes rather
//!      than the label, so its table is keyed on what the runtime will
//!      dispatch on.
//!
//! The controls — an honest declaration still blocking for the RIGHT pattern,
//! an honest transfer still clearing — are here so that a "fix" which simply
//! refused everything could not pass.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, PipelineLayerResult, ProposedIntent, VerificationError,
    VerificationInput, VerificationResult,
};

const SYSTEM: &str = "11111111111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// Pays the fee. Deliberately NOT the token authority: an SPL authority is
/// declared read-only in the manifest and a fee payer is always writable, so
/// making them one account produces a privilege mismatch that has nothing to
/// do with what is being tested here.
const PAYER: &str = "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx";
const AUTHORITY: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const TARGET: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const MALLORY: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";

fn compact_u16(mut v: usize, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// A legacy transaction carrying exactly one instruction.
///
/// `header` is the runtime's own three bytes — required signatures, read-only
/// signed, read-only unsigned — so each fixture can place its accounts at the
/// privileges the manifest declares for them. One signature slot per required
/// signature, because the parser checks that count against the header.
fn message(keys: &[&str], header: [u8; 3], program_index: u8, ix: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    compact_u16(header[0] as usize, &mut out);
    for _ in 0..header[0] {
        out.extend_from_slice(&[0u8; 64]);
    }
    out.extend_from_slice(&header);
    compact_u16(keys.len(), &mut out);
    for k in keys {
        out.extend_from_slice(&bs58::decode(k).into_vec().expect("valid base58 key"));
    }
    out.extend_from_slice(&[9u8; 32]);
    compact_u16(1, &mut out);
    out.push(program_index);
    compact_u16(ix.len(), &mut out);
    out.extend_from_slice(ix);
    compact_u16(data.len(), &mut out);
    out.extend_from_slice(data);
    out
}

/// SPL Token `SetAuthority`: tag `06`, the authority type, then a
/// `COption<Pubkey>` naming the new holder.
fn set_authority_data(new_owner: &str) -> Vec<u8> {
    let mut d = vec![0x06u8, 2u8, 1u8];
    d.extend_from_slice(&bs58::decode(new_owner).into_vec().expect("valid base58"));
    d
}

/// SPL Token `CloseAccount`: one byte, `09`.
fn close_account_data() -> Vec<u8> {
    vec![0x09u8]
}

/// System `Assign`: the 4-byte little-endian tag `01000000`, then the program
/// the account is handed to.
fn assign_data(new_owner: &str) -> Vec<u8> {
    let mut d = vec![0x01u8, 0, 0, 0];
    d.extend_from_slice(&bs58::decode(new_owner).into_vec().expect("valid base58"));
    d
}

/// SPL Token `Transfer`: tag `03`, then a u64 amount.
fn transfer_data(amount: u64) -> Vec<u8> {
    let mut d = vec![0x03u8];
    d.extend_from_slice(&amount.to_le_bytes());
    d
}

struct Request {
    program: String,
    /// What the caller CLAIMS the instruction is.
    declared: String,
    accounts: Vec<String>,
    /// What the instruction actually is.
    data: Vec<u8>,
    artifact: Option<Vec<u8>>,
    intent: &'static str,
}

impl Request {
    fn run(&self) -> Result<VerificationResult, VerificationError> {
        let input = VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: self.intent.to_string(),
                raw_natural_language: "move some tokens".to_string(),
                confidence_of_parse: 0.95,
                extracted_parameters: None,
            },
            program_id: self.program.clone(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: self.declared.clone(),
            account_addresses: self.accounts.clone(),
            instruction_data: Some(self.data.clone()),
            cpi_targets: vec![],
            // The weakest built-in profile (0.55). The mislabelled request
            // scored 0.640 before the fix, so this is the profile that
            // actually approved it — verifying under a stricter one would
            // prove nothing about the bypass.
            wallet_profile: WalletProfile::Gaming,
            behavior_evidence: BehaviorEvidence {
                has_signed_manifest: true,
                community_verified_count: 5,
                battle_tested_tx_count: 50_000,
                simulation_match_count: 100,
            },
            compute_units: 150,
            account_writes: 1,
            cpi_hops: 0,
            signed_transaction: self.artifact.clone(),
            transaction_instructions: vec![],
            cpi_trace: None,
            uses_versioned_transaction: false,
            lookup_table_count: 0,
            real_account_metas: vec![],
            state_diff: None,
        };
        GraphiteCore::new().verify(&input)
    }

    fn verify(&self) -> VerificationResult {
        self.run().expect("verify ok")
    }
}

/// The SPL Token hand-over, described however the caller likes.
///
/// `AUTHORITY` signs and is read-only (the manifest's `current_authority`);
/// `TARGET` is the writable account being handed to `MALLORY`; `PAYER` pays.
fn set_authority(declared: &str) -> Request {
    let data = set_authority_data(MALLORY);
    Request {
        program: TOKEN.to_string(),
        declared: declared.to_string(),
        accounts: vec![TARGET.to_string(), AUTHORITY.to_string()],
        artifact: Some(message(
            &[PAYER, AUTHORITY, TARGET, TOKEN],
            [2, 1, 1],
            3,
            &[2, 1],
            &data,
        )),
        data,
        intent: "transfer",
    }
}

fn close_account(declared: &str) -> Request {
    let data = close_account_data();
    Request {
        program: TOKEN.to_string(),
        declared: declared.to_string(),
        accounts: vec![
            TARGET.to_string(),
            MALLORY.to_string(),
            AUTHORITY.to_string(),
        ],
        artifact: Some(message(
            &[PAYER, AUTHORITY, TARGET, MALLORY, TOKEN],
            [2, 1, 1],
            4,
            &[2, 3, 1],
            &data,
        )),
        data,
        intent: "transfer",
    }
}

/// System `Assign` hands the account itself over, and the manifest declares
/// that account a writable signer — so here it is the fee payer.
fn assign(declared: &str) -> Request {
    let data = assign_data(TOKEN);
    Request {
        program: SYSTEM.to_string(),
        declared: declared.to_string(),
        accounts: vec![TARGET.to_string()],
        artifact: Some(message(&[TARGET, SYSTEM], [1, 0, 1], 1, &[0], &data)),
        data,
        intent: "transfer",
    }
}

fn transfer(declared: &str) -> Request {
    let data = transfer_data(1_000);
    Request {
        program: TOKEN.to_string(),
        declared: declared.to_string(),
        accounts: vec![
            TARGET.to_string(),
            MALLORY.to_string(),
            AUTHORITY.to_string(),
        ],
        artifact: Some(message(
            &[PAYER, AUTHORITY, TARGET, MALLORY, TOKEN],
            [2, 1, 1],
            4,
            &[2, 3, 1],
            &data,
        )),
        data,
        intent: "transfer",
    }
}

fn l2(result: &VerificationResult) -> &PipelineLayerResult {
    result
        .layers
        .iter()
        .find(|l| l.layer.contains("L2"))
        .expect("L2 present")
}

fn blocked_by_risk(result: &VerificationResult) -> bool {
    result.risk_verdict.status == "Blocked"
}

fn patterns(result: &VerificationResult) -> Vec<&str> {
    result
        .risk_verdict
        .findings
        .iter()
        .map(|f| f.pattern.as_str())
        .collect()
}

// ── The control: an honestly declared hand-over is refused, by name ─────────

#[test]
fn an_honestly_declared_set_authority_is_blocked_as_an_authority_hijack() {
    let r = set_authority("06").verify();
    assert!(
        patterns(&r).contains(&"AuthorityHijack"),
        "the known-risky table did not fire on an HONEST SetAuthority, so every \
         assertion below about a mislabelled one would be vacuous: {:?}",
        r.risk_verdict
    );
    assert!(!r.approved);
}

#[test]
fn an_honestly_declared_close_account_is_blocked_as_a_drainer() {
    let r = close_account("09").verify();
    assert!(patterns(&r).contains(&"Drainer"), "{:?}", r.risk_verdict);
    assert!(!r.approved);
}

#[test]
fn an_honestly_declared_assign_is_blocked_as_an_authority_hijack() {
    let r = assign("01000000").verify();
    assert!(
        patterns(&r).contains(&"AuthorityHijack"),
        "{:?}",
        r.risk_verdict
    );
    assert!(!r.approved);
}

// ── Step 1: a label that is not hex never becomes a verdict at all ──────────

/// Not part of the GFX-001 fix — it predates it — but it is the reason the
/// word-shaped variant of the bypass is unreachable, and a verdict is exactly
/// what must never come back for a discriminator nothing can compare against.
/// Pinned so that relaxing it would be a deliberate act.
#[test]
fn a_discriminator_that_is_not_hex_never_reaches_a_verdict() {
    for label in ["setauthority", "closeit", "reassign", "zzzz", "0", "06 "] {
        let outcome = set_authority(label).run();
        match outcome {
            Err(VerificationError::TransactionBuild(detail)) => {
                assert!(
                    detail.contains("discriminator is invalid hex"),
                    "refused for an unrelated reason ({label}): {detail}"
                );
            }
            Err(other) => panic!("{label}: refused, but not as a bad discriminator: {other}"),
            Ok(r) => panic!(
                "{label}: a non-hex discriminator produced a verdict (approved={}, risk={:?})",
                r.approved, r.risk_verdict
            ),
        }
    }
}

// ── Step 2: a hex label that contradicts its own bytes ──────────────────────

#[test]
fn a_set_authority_declared_as_an_unknown_discriminator_is_refused() {
    let r = set_authority("ff").verify();
    assert!(
        !r.approved,
        "GFX-001: the same bytes that are Blocked when declared 06 were approved \
         when declared ff — confidence {}, scope {:?}",
        r.confidence, r.scope
    );
    assert_eq!(
        l2(&r).status,
        LayerStatus::Failed,
        "the refusal must come from the discriminator/data contradiction itself. \
         L2 said: {}",
        l2(&r).reason
    );
    assert!(
        l2(&r).reason.contains("describe different instructions"),
        "L2 failed for some other reason, so this test would not notice the \
         comparison being moved back below the manifest lookup: {}",
        l2(&r).reason
    );
}

#[test]
fn a_close_account_declared_as_an_unknown_discriminator_is_refused() {
    let r = close_account("ff").verify();
    assert!(!r.approved, "confidence {}", r.confidence);
    assert_eq!(l2(&r).status, LayerStatus::Failed, "{}", l2(&r).reason);
    assert!(l2(&r).reason.contains("describe different instructions"));
}

#[test]
fn an_assign_declared_as_an_unknown_discriminator_is_refused() {
    let r = assign("ffffffff").verify();
    assert!(!r.approved, "confidence {}", r.confidence);
    assert_eq!(l2(&r).status, LayerStatus::Failed, "{}", l2(&r).reason);
    assert!(l2(&r).reason.contains("describe different instructions"));
}

/// A near miss, not a wild one: `07` is MintTo — a real, manifested, benign
/// instruction — over SetAuthority's bytes. Declaring something the manifest
/// KNOWS was never the bypass; declaring something it does not know was. Both
/// have to fail, and this is the half the old code did catch.
#[test]
fn a_manifested_but_wrong_discriminator_is_refused_too() {
    let r = set_authority("07").verify();
    assert_eq!(l2(&r).status, LayerStatus::Failed, "{}", l2(&r).reason);
    assert!(!r.approved);
}

/// The manifest is not what makes a request self-contradictory. SPL Token and
/// the System program are both manifested, so the comparison is also checked
/// on a program that is not — where L2 used to return Inconclusive before it
/// ever looked at the data.
#[test]
fn the_contradiction_is_caught_on_an_unmanifested_program_too() {
    let data = set_authority_data(MALLORY);
    let unknown = MALLORY;
    let r = Request {
        program: unknown.to_string(),
        declared: "ff".to_string(),
        accounts: vec![TARGET.to_string(), AUTHORITY.to_string()],
        artifact: Some(message(
            &[PAYER, AUTHORITY, TARGET, unknown],
            [2, 1, 1],
            3,
            &[2, 1],
            &data,
        )),
        data,
        intent: "transfer",
    }
    .verify();
    assert_eq!(l2(&r).status, LayerStatus::Failed, "{}", l2(&r).reason);
    assert!(
        l2(&r).reason.contains("describe different instructions"),
        "{}",
        l2(&r).reason
    );
    assert!(!r.approved);
}

/// The padding move from the other side: a declaration LONGER than the data it
/// claims to describe. `0900000000000000` over a one-byte instruction cannot be
/// a prefix of anything, and the old comparison skipped exactly this case —
/// `data.len() >= disc_bytes.len()` gated it, so the shorter-data half was
/// never compared at all.
#[test]
fn a_declaration_longer_than_the_data_it_describes_is_refused() {
    let r = close_account("0900000000000000").verify();
    assert_eq!(l2(&r).status, LayerStatus::Failed, "{}", l2(&r).reason);
    assert!(
        l2(&r)
            .reason
            .contains("cannot begin with a discriminator longer than itself"),
        "{}",
        l2(&r).reason
    );
    assert!(!r.approved);
}

/// Descriptive mode has no artifact, so `instruction_data` is the caller's own
/// claim rather than a located fact — but it is still a claim about the BYTES,
/// and a label that contradicts it is still a request saying two things.
#[test]
fn the_contradiction_is_caught_without_an_artifact() {
    let mut req = set_authority("ff");
    req.artifact = None;
    let r = req.verify();
    assert_eq!(l2(&r).status, LayerStatus::Failed, "{}", l2(&r).reason);
    assert!(!r.approved);
}

// ── Step 3: the Risk Engine is keyed on the bytes ───────────────────────────

/// The structural half. With the contradiction check in place a mislabelled
/// request never reaches L7 as an approval — but the Risk Engine must not be
/// relying on that. Padding a real SetAuthority's discriminator to eight bytes
/// is the shape `disc_matches` was written to defeat, and here the table has
/// to fire on the instruction's own leading bytes.
#[test]
fn the_risk_table_fires_on_the_instructions_own_bytes() {
    // `06 02 01 <32-byte pubkey>` — the declaration is the genuine first byte
    // padded out, which is a prefix of nothing in the data past byte 0.
    let r = set_authority("06").verify();
    assert!(
        patterns(&r).contains(&"AuthorityHijack"),
        "{:?}",
        r.risk_verdict
    );
    // And the same instruction under System's own 4-byte convention.
    let a = assign("01000000").verify();
    assert!(
        patterns(&a).contains(&"AuthorityHijack"),
        "{:?}",
        a.risk_verdict
    );
}

/// THE case the contradiction check cannot reach: a label that is TRUE but
/// SHORT. System `Assign` is `01000000`; declaring `01` over `01 00 00 00 ...`
/// contradicts nothing — `01` really is a prefix of the data — so L2 passes,
/// and that is correct. But `"01".starts_with("01000000")` is false, so a Risk
/// Engine keyed on the label finds no pattern and the manifest lookup misses,
/// leaving `manifest_risk_class` empty so Check 10 cannot back it up either.
/// One byte of honesty bought the same silence the lie did.
///
/// This is the test that pins the regrounding specifically: the L2 comparison
/// cannot catch it, because there is nothing here to catch.
#[test]
fn a_truthful_but_truncated_discriminator_does_not_hide_the_instruction() {
    let r = assign("01").verify();
    assert_eq!(
        l2(&r).status,
        LayerStatus::Passed,
        "nothing here is self-contradictory, so L2 has no reason to fail and this test would be testing the wrong mechanism: {}",
        l2(&r).reason
    );
    assert!(
        patterns(&r).contains(&"AuthorityHijack"),
        "GFX-001: a System Assign declared as `01` was not recognised as one. Risk verdict {:?}, confidence {}",
        r.risk_verdict,
        r.confidence
    );
    assert!(!r.approved);
}

// ── Anti-vacuity: the ordinary case still clears ────────────────────────────

/// A fix that refused everything would satisfy every assertion above. An
/// honestly described SPL transfer, artifact and all, must still come back
/// with a clear risk verdict and a passing L2.
#[test]
fn an_honest_transfer_still_clears() {
    let r = transfer("03").verify();
    assert!(
        !blocked_by_risk(&r),
        "an ordinary token transfer was blocked — the regrounded discriminator \
         is over-matching: {:?}",
        r.risk_verdict
    );
    assert_eq!(
        l2(&r).status,
        LayerStatus::Passed,
        "an ordinary token transfer failed L2: {}",
        l2(&r).reason
    );
}

/// The manifest's own one-byte discriminator over nine bytes of data is a
/// legitimate prefix. Regrounding must not turn that into a mismatch, and the
/// instruction must still resolve to its manifest entry by name.
#[test]
fn a_manifest_length_discriminator_still_matches_its_instruction() {
    let r = transfer("03").verify();
    assert_eq!(r.instruction_name, "Transfer", "{}", r.summary);
    assert!(!blocked_by_risk(&r), "{:?}", r.risk_verdict);
}

/// The System program's four-byte convention, same question: `02000000` over
/// twelve bytes of transfer data.
#[test]
fn a_four_byte_system_discriminator_still_matches_its_instruction() {
    let mut data = vec![2u8, 0, 0, 0];
    data.extend_from_slice(&1_000_000u64.to_le_bytes());
    let r = Request {
        program: SYSTEM.to_string(),
        declared: "02000000".to_string(),
        accounts: vec![PAYER.to_string(), TARGET.to_string()],
        artifact: Some(message(
            &[PAYER, TARGET, SYSTEM],
            [1, 0, 1],
            2,
            &[0, 1],
            &data,
        )),
        data,
        intent: "transfer",
    }
    .verify();
    assert_eq!(r.instruction_name, "Transfer", "{}", r.summary);
    assert_eq!(l2(&r).status, LayerStatus::Passed, "{}", l2(&r).reason);
    assert!(!blocked_by_risk(&r), "{:?}", r.risk_verdict);
}
