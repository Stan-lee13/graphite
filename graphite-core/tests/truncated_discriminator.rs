//! A discriminator can be true and still be a lie by omission.
//!
//! Round 13 closed the case where the declared discriminator CONTRADICTS the
//! instruction data. It left open the case where the declared discriminator is
//! a genuine PREFIX of it — `e517cb97` for `e517cb977ae3ad2a`, or `01` for
//! `01000000`. Nothing contradicts, so L2's self-consistency check is satisfied
//! and correctly says so.
//!
//! That mattered because `manifest::discriminator_matches` is
//! `input.starts_with(selector)`: a label SHORTER than the manifest's selector
//! misses it. Round 13 re-keyed the Risk Engine on the instruction's own bytes
//! and left every OTHER manifest lookup keyed on the label, so the two halves
//! disagreed for exactly these requests — and the half still keyed on the label
//! was the half that checks account identity.
//!
//! Three holes came out of that one split, each reproduced against a running
//! server before being fixed:
//!
//!   * **GFX-101** — `resolve_accounts` missed the manifest, so the P12 arm
//!     synthesised accounts with `pda_mismatch`, `expected_address_mismatch`
//!     and `privilege_mismatch` ALL false. Measured: an attacker-controlled
//!     program in Jupiter V6 `route`'s pinned token-program slot went from
//!     `Blocked / AccountIdentityMismatch` under the full label to
//!     `approved: true, risk: Clear, artifact_bound, inherent residuals only`
//!     under a four-byte one — a verdict the reference bridge's default
//!     residual policy would have signed.
//!   * **GFX-102** — `expected_state_changes` fell back to the generic
//!     "Protocol-level state changes", which `DeclaredEffects::parse` cannot
//!     interpret, and an uninterpretable declaration downgrades every
//!     undeclared value-movement finding in L4 from Critical to Warning.
//!     `allowed_cpis` widened to the protocol-wide union at the same time.
//!   * **GFX-106** — declared SIBLINGS were handed to the Risk Engine under
//!     their caller-written label. Measured: a real System `Assign` declared
//!     `01`, and a real SPL `SetAuthority` declared `0`, both drew Clear.
//!
//! Every assertion below is on behaviour that is identical for the honest
//! full-length label. The fix must change what Graphite does with a request
//! that shortens its own description, and nothing else — so the controls and
//! the anti-vacuity tests are as load-bearing as the attacks.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, PipelineLayerResult, ProposedIntent, VerificationInput,
    VerificationResult,
};

const SYSTEM: &str = "11111111111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const JUPITER: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
/// Jupiter V6 `route`. Its manifest pins account 0 to the two token programs.
const ROUTE: &str = "e517cb977ae3ad2a";
/// The first four bytes of `ROUTE` — a true prefix, so not a contradiction.
const ROUTE_SHORT: &str = "e517cb97";

const PAYER: &str = "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx";
const RECIPIENT: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const SECOND: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

/// Raydium CPMM. Its `close_permission_pda` carries `risk_class: "close"`,
/// which is what Check 10b keys on — and Check 10b is the check that catches a
/// manifest-declared high-risk SIBLING, because a secondary instruction is
/// always assessed with an empty declared intent.
const CPMM: &str = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C";
const CPMM_CLOSE: &str = "9c5420764587467b";

/// A base58 address that is not any real program. Used for the accounts whose
/// identity the manifest does not pin, and for the attacker's program.
fn addr(seed: u8) -> String {
    bs58::encode([seed; 32]).into_string()
}

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

/// A legacy transaction frame: one signature slot, one signer, `readonly_unsigned`
/// keys read-only at the tail. `instructions` are
/// `(program_index, account_indexes, data)`.
fn frame(
    keys: &[String],
    instructions: &[(u8, Vec<u8>, Vec<u8>)],
    readonly_unsigned: u8,
) -> Vec<u8> {
    let mut out = Vec::new();
    compact_u16(1, &mut out);
    out.extend_from_slice(&[0u8; 64]);
    out.extend_from_slice(&[1, 0, readonly_unsigned]);
    compact_u16(keys.len(), &mut out);
    for k in keys {
        let raw = bs58::decode(k).into_vec().expect("valid base58 key");
        assert_eq!(raw.len(), 32, "key {k} is not 32 bytes");
        out.extend_from_slice(&raw);
    }
    out.extend_from_slice(&[9u8; 32]);
    compact_u16(instructions.len(), &mut out);
    for (program, accounts, data) in instructions {
        out.push(*program);
        compact_u16(accounts.len(), &mut out);
        out.extend_from_slice(accounts);
        compact_u16(data.len(), &mut out);
        out.extend_from_slice(data);
    }
    out
}

/// System `Transfer`: the 4-byte little-endian tag `02000000`, then a u64.
fn transfer_data(lamports: u64) -> Vec<u8> {
    let mut d = vec![0x02u8, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d
}

/// System `Assign`: tag `01000000`, then the program the account is handed to.
fn assign_data(new_owner: &str) -> Vec<u8> {
    let mut d = vec![0x01u8, 0, 0, 0];
    d.extend_from_slice(&bs58::decode(new_owner).into_vec().expect("valid base58"));
    d
}

/// SPL Token `SetAuthority`: tag `06`, the authority type, then a
/// `COption<Pubkey>` naming the new holder.
fn set_authority_data(new_owner: &str) -> Vec<u8> {
    let mut d = vec![0x06u8, 2u8, 1u8];
    d.extend_from_slice(&bs58::decode(new_owner).into_vec().expect("valid base58"));
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
    siblings: Vec<TransactionInstruction>,
    intent: &'static str,
}

impl Request {
    fn verify(&self) -> VerificationResult {
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
            // The weakest built-in profile, for the same reason
            // `mislabelled_discriminator.rs` uses it: this is the profile the
            // bypass actually cleared, so a stricter one would prove nothing.
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
            transaction_instructions: self.siblings.clone(),
            cpi_trace: None,
            uses_versioned_transaction: false,
            lookup_table_count: 0,
            real_account_metas: vec![],
            state_diff: None,
        };
        GraphiteCore::new().verify(&input).expect("verify ok")
    }
}

fn patterns(r: &VerificationResult) -> Vec<&str> {
    r.risk_verdict
        .findings
        .iter()
        .map(|f| f.pattern.as_str())
        .collect()
}

fn l2(r: &VerificationResult) -> &PipelineLayerResult {
    r.layers
        .iter()
        .find(|l| l.layer.starts_with("L2"))
        .expect("L2 must be reported")
}

fn sibling(program: &str, declared: &str, accounts: &[&str]) -> TransactionInstruction {
    TransactionInstruction {
        program_id: program.to_string(),
        instruction_discriminator: declared.to_string(),
        account_addresses: accounts.iter().map(|a| a.to_string()).collect(),
        cpi_targets: vec![],
    }
}

// ── GFX-101: the manifest's pinned account identities ────────────────────────

/// Jupiter V6 `route`, with whatever the caller likes in the account-0 slot
/// that the manifest pins to the token programs.
fn jupiter_route(declared: &str, slot0: &str) -> Request {
    let mut data = hex::decode(ROUTE).expect("valid hex");
    data.extend_from_slice(&[0u8; 16]);
    Request {
        program: JUPITER.to_string(),
        declared: declared.to_string(),
        accounts: vec![
            slot0.to_string(),
            PAYER.to_string(),
            addr(0x02),
            addr(0x03),
            addr(0x04),
            addr(0x05),
            addr(0x06),
            addr(0x07),
            addr(0x08),
        ],
        data,
        artifact: None,
        siblings: vec![],
        intent: "transfer",
    }
}

#[test]
fn the_full_discriminator_catches_a_substituted_pinned_account() {
    // The control. If this stops blocking, the test below is vacuous.
    let r = jupiter_route(ROUTE, &addr(0xEE)).verify();
    assert!(
        patterns(&r).contains(&"AccountIdentityMismatch"),
        "an attacker's program in Jupiter route's pinned token-program slot was not \
         reported under the FULL discriminator, so this file can no longer detect \
         the bypass it exists for. risk={:?}",
        r.risk_verdict
    );
    assert!(!r.approved);
}

#[test]
fn a_truncated_discriminator_does_not_hide_a_substituted_pinned_account() {
    let r = jupiter_route(ROUTE_SHORT, &addr(0xEE)).verify();
    assert_eq!(
        l2(&r).status,
        LayerStatus::Passed,
        "a truncated-but-truthful label is not self-contradictory, so L2 must not be \
         what refuses it — otherwise this test measures the wrong mechanism: {}",
        l2(&r).reason
    );
    assert!(
        patterns(&r).contains(&"AccountIdentityMismatch"),
        "GFX-101: declaring `{ROUTE_SHORT}` instead of `{ROUTE}` suppressed the \
         manifest's pinned-address check. An attacker-controlled program sat in the \
         slot pinned to the SPL Token program and nothing said so. \
         risk={:?} approved={} confidence={}",
        r.risk_verdict,
        r.approved,
        r.confidence
    );
    assert!(!r.approved);
}

#[test]
fn a_truncated_discriminator_still_resolves_the_instruction_by_name() {
    // The identity check only runs when the manifest entry is found, so this
    // is the mechanism behind the test above — asserted directly, so a
    // regression is reported as what it is rather than as a missing finding.
    let r = jupiter_route(ROUTE_SHORT, &addr(0xEE)).verify();
    assert_eq!(
        r.instruction_name, "route",
        "GFX-101: the truncated label did not resolve to the instruction its own \
         bytes name, so every manifest-grounded check was skipped"
    );
}

#[test]
fn an_empty_discriminator_does_not_hide_a_substituted_pinned_account() {
    // The first cut of the GFX-101 fix inherited the Risk Engine's
    // `!discriminator.is_empty()` gate and left the whole bypass reachable by
    // sending `""` instead of a short prefix: `discriminator_matches` refuses
    // an empty input, so the lookup missed exactly as before. Measured on that
    // build — `e517cb97` Blocked, `""` Clear.
    let r = jupiter_route("", &addr(0xEE)).verify();
    assert_eq!(
        r.instruction_name, "route",
        "an empty label must not stop the manifest lookup from finding the \
         instruction the bytes name"
    );
    assert!(
        patterns(&r).contains(&"AccountIdentityMismatch"),
        "GFX-101 (empty-label variant): declaring no discriminator at all \
         suppressed the manifest's pinned-address check. risk={:?}",
        r.risk_verdict
    );
    assert!(!r.approved);
}

#[test]
fn an_empty_discriminator_on_a_known_risky_program_still_fails_closed() {
    // The reason `risk_discriminator` keeps the empty-label gate that
    // `effective_discriminator` drops. Check 2 refuses a request that named no
    // instruction on a known-risky program, whatever its bytes say — and
    // deriving one for it would turn "refused because you did not say" into
    // "allowed because we worked it out".
    let r = Request {
        program: TOKEN.to_string(),
        declared: String::new(),
        accounts: vec![addr(0xB1), addr(0xB2), RECIPIENT.to_string()],
        data: {
            let mut d = vec![0x03u8];
            d.extend_from_slice(&5u64.to_le_bytes());
            d
        },
        artifact: None,
        siblings: vec![],
        intent: "transfer",
    }
    .verify();
    assert_ne!(
        r.risk_verdict.status, "Clear",
        "an empty discriminator on SPL Token must still fail closed (Check 2's \
         empty-label arm): {:?}",
        r.risk_verdict
    );
    assert!(!r.approved);
}

#[test]
fn the_label_and_the_bytes_resolving_differently_is_disclosed() {
    let r = jupiter_route(ROUTE_SHORT, TOKEN).verify();
    assert!(
        r.summary.contains(ROUTE_SHORT) && r.summary.contains("manifest lookup used the bytes"),
        "a request that describes its instruction as something the protocol does not \
         declare should say so, even though the checks now run regardless: {}",
        r.summary
    );
}

#[test]
fn an_honest_pinned_account_still_clears_under_a_truncated_label() {
    // Anti-vacuity: the fix must not report a mismatch for the account the
    // manifest actually pins.
    let r = jupiter_route(ROUTE_SHORT, TOKEN).verify();
    assert!(
        !patterns(&r).contains(&"AccountIdentityMismatch"),
        "the SPL Token program IS what Jupiter route's account 0 is pinned to, and it \
         was reported as a mismatch: {:?}",
        r.risk_verdict
    );
}

// ── GFX-102: the manifest's declared effects ─────────────────────────────────

#[test]
fn a_truncated_discriminator_resolves_to_the_same_manifest_entry_as_the_full_one() {
    // Keyed on the label, the short form fell through to the P12 path, whose
    // `expected_state_changes` is the single uninterpretable string
    // "Protocol-level state changes" — and an uninterpretable declaration
    // downgrades L4's undeclared value-movement findings to warnings, while
    // `allowed_cpis` widens to the protocol-wide union.
    let full = jupiter_route(ROUTE, TOKEN).verify();
    let short = jupiter_route(ROUTE_SHORT, TOKEN).verify();
    assert_eq!(
        full.instruction_name, short.instruction_name,
        "GFX-102: one instruction resolved to two different manifest entries \
         depending only on how much of its discriminator the caller wrote down"
    );
    assert_eq!(
        full.risk_verdict.status, short.risk_verdict.status,
        "GFX-102: the risk verdict changed with the length of the label alone"
    );
}

// ── GFX-106: declared siblings ───────────────────────────────────────────────

/// An honest System transfer with a real System `Assign` — an account takeover
/// — beside it in the same transaction, declared as `declared`.
fn transfer_with_assign_sibling(declared: &str) -> Request {
    let keys = vec![PAYER.to_string(), RECIPIENT.to_string(), SYSTEM.to_string()];
    let artifact = frame(
        &keys,
        &[
            (2, vec![0, 1], transfer_data(2_000_000)),
            (2, vec![0], assign_data(&addr(0xEE))),
        ],
        1,
    );
    Request {
        program: SYSTEM.to_string(),
        declared: "02000000".to_string(),
        accounts: vec![PAYER.to_string(), RECIPIENT.to_string()],
        data: transfer_data(2_000_000),
        artifact: Some(artifact),
        siblings: vec![sibling(SYSTEM, declared, &[PAYER])],
        intent: "transfer",
    }
}

#[test]
fn an_honestly_declared_assign_sibling_is_blocked() {
    // The control for the two below.
    let r = transfer_with_assign_sibling("01000000").verify();
    assert!(
        patterns(&r).contains(&"AuthorityHijack"),
        "a declared System Assign sibling was not blocked under its real \
         discriminator — the control is broken. risk={:?}",
        r.risk_verdict
    );
}

#[test]
fn a_truncated_assign_sibling_is_still_blocked() {
    let r = transfer_with_assign_sibling("01").verify();
    assert_eq!(
        l2(&r).status,
        LayerStatus::Passed,
        "`01` is a true prefix of `01000000`, so sibling coverage must accept the \
         declaration and L2 must pass — otherwise this measures the wrong \
         mechanism: {}",
        l2(&r).reason
    );
    assert!(
        patterns(&r).contains(&"AuthorityHijack"),
        "GFX-106: a real System Assign executing in this transaction drew a Clear \
         verdict because the caller declared it `01`. risk={:?}",
        r.risk_verdict
    );
    assert!(!r.approved);
}

#[test]
fn a_two_byte_assign_sibling_is_still_blocked() {
    let r = transfer_with_assign_sibling("0100").verify();
    assert!(
        patterns(&r).contains(&"AuthorityHijack"),
        "GFX-106: `0100` is still not `01000000`, and the instruction is still an \
         Assign. risk={:?}",
        r.risk_verdict
    );
}

/// An honest System transfer with a real SPL `SetAuthority` beside it.
fn transfer_with_set_authority_sibling(declared: &str) -> Request {
    let token_account = addr(0xB1);
    let keys = vec![
        PAYER.to_string(),
        RECIPIENT.to_string(),
        SYSTEM.to_string(),
        TOKEN.to_string(),
        token_account.clone(),
    ];
    let artifact = frame(
        &keys,
        &[
            (2, vec![0, 1], transfer_data(2_000_000)),
            (3, vec![4, 0], set_authority_data(&addr(0xC2))),
        ],
        2,
    );
    Request {
        program: SYSTEM.to_string(),
        declared: "02000000".to_string(),
        accounts: vec![PAYER.to_string(), RECIPIENT.to_string()],
        data: transfer_data(2_000_000),
        artifact: Some(artifact),
        siblings: vec![sibling(TOKEN, declared, &[&token_account, PAYER])],
        intent: "transfer",
    }
}

#[test]
fn an_honestly_declared_set_authority_sibling_is_blocked() {
    let r = transfer_with_set_authority_sibling("06").verify();
    assert!(
        patterns(&r).contains(&"AuthorityHijack"),
        "the control is broken: a declared SetAuthority sibling was not blocked \
         under its real discriminator. risk={:?}",
        r.risk_verdict
    );
}

#[test]
fn a_single_nibble_set_authority_sibling_is_still_blocked() {
    // `declaration_describes` compares the hex STRING, not bytes, so even a
    // one-byte selector like `06` was evadable with a single character.
    let r = transfer_with_set_authority_sibling("0").verify();
    assert_eq!(
        l2(&r).status,
        LayerStatus::Passed,
        "`0` is a true prefix of the hex of this instruction's data, so sibling \
         coverage accepts it and L2 must pass: {}",
        l2(&r).reason
    );
    assert!(
        patterns(&r).contains(&"AuthorityHijack"),
        "GFX-106: a real SPL SetAuthority drew a Clear verdict because the caller \
         declared it as a single hex nibble. risk={:?}",
        r.risk_verdict
    );
    assert!(!r.approved);
}

// ── The sibling re-keying, isolated from the ambiguity rule ──────────────────

/// An honest System transfer beside a real Raydium CPMM `close_permission_pda`,
/// declared as `declared`.
///
/// CPMM is NOT in `RISKY_PATTERNS`, so the ambiguous-prefix rule cannot reach
/// it. The only thing that blocks this sibling is Check 10b — the manifest
/// declaring `risk_class: "close"` while a secondary instruction carries no
/// declared intent — and that check reads `manifest_risk_class`, which comes
/// from a manifest lookup keyed on the sibling's discriminator. Truncate the
/// label and the lookup misses, the class is empty, and Check 10b never fires.
///
/// This is the case that isolates `siblings_keyed_on_their_bytes` from every
/// other control: with the re-keying removed, nothing else catches it.
fn transfer_with_cpmm_close_sibling(declared: &str) -> Request {
    let owner = addr(0x11);
    let permission = addr(0x22);
    let keys = vec![
        PAYER.to_string(),
        RECIPIENT.to_string(),
        SYSTEM.to_string(),
        CPMM.to_string(),
        owner.clone(),
        permission.clone(),
    ];
    let mut close = hex::decode(CPMM_CLOSE).expect("valid hex");
    close.extend_from_slice(&[0u8; 8]);
    let artifact = frame(
        &keys,
        &[
            (2, vec![0, 1], transfer_data(2_000_000)),
            (3, vec![4, 0, 5, 2], close),
        ],
        3,
    );
    Request {
        program: SYSTEM.to_string(),
        declared: "02000000".to_string(),
        accounts: vec![PAYER.to_string(), RECIPIENT.to_string()],
        data: transfer_data(2_000_000),
        artifact: Some(artifact),
        siblings: vec![sibling(
            CPMM,
            declared,
            &[&owner, PAYER, &permission, SYSTEM],
        )],
        intent: "transfer",
    }
}

#[test]
fn an_honestly_declared_high_risk_class_sibling_is_blocked() {
    // The control: with the full discriminator the manifest resolves,
    // `risk_class: "close"` is found, and Check 10b fires on the empty
    // secondary intent.
    let r = transfer_with_cpmm_close_sibling(CPMM_CLOSE).verify();
    assert_ne!(
        r.risk_verdict.status, "Clear",
        "a manifest-declared high-risk sibling was not blocked under its real \
         discriminator — the control is broken. risk={:?}",
        r.risk_verdict
    );
}

#[test]
fn a_truncated_high_risk_class_sibling_is_still_blocked() {
    // The isolating case. Raydium CPMM is not in the known-risky table, so
    // neither Check 2 nor the ambiguous-prefix rule can reach this — only the
    // sibling re-keying restores `manifest_risk_class`.
    let r = transfer_with_cpmm_close_sibling(&CPMM_CLOSE[..8]).verify();
    assert_eq!(
        l2(&r).status,
        LayerStatus::Passed,
        "`{}` is a true prefix of the sibling's data, so coverage must accept \
         the declaration and L2 must pass: {}",
        &CPMM_CLOSE[..8],
        l2(&r).reason
    );
    assert_ne!(
        r.risk_verdict.status, "Clear",
        "GFX-106: a manifest-declared high-risk sibling drew a Clear verdict \
         because the caller wrote half its discriminator. risk={:?}",
        r.risk_verdict
    );
    assert!(!r.approved);
}

// ── A label too short to identify the instruction at all ─────────────────────

/// A descriptive request: no artifact, so there are no bytes to re-key on and
/// the label is all there is.
fn descriptive(
    program: &str,
    declared: &str,
    siblings: Vec<TransactionInstruction>,
) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "probe".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: program.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: declared.to_string(),
        account_addresses: vec![addr(0xB1), addr(0xB2), RECIPIENT.to_string()],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: siblings,
        cpi_trace: None,
        real_account_metas: vec![],
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        state_diff: None,
    }
}

#[test]
fn a_descriptive_label_too_short_to_identify_a_risky_instruction_is_refused() {
    // System `Assign` is `01000000`, so `01` is consistent with it and with
    // nothing else this program declares. `disc_matches` only fires when the
    // input is at least as long as the selector, so a strict prefix sat in the
    // gap between the two arms of Check 2.
    let r = GraphiteCore::new()
        .verify(&descriptive(SYSTEM, "01", vec![]))
        .expect("verify ok");
    assert_ne!(
        r.risk_verdict.status, "Clear",
        "`01` cannot be told apart from System Assign (`01000000`) and must not \
         clear: {:?}",
        r.risk_verdict
    );
    assert!(!r.approved);
}

#[test]
fn a_descriptive_sibling_too_short_to_identify_a_risky_instruction_is_refused() {
    // The sibling path is the one that actually mattered: a PRIMARY with an
    // odd-length label never reaches a verdict at all (`transaction_builder`
    // refuses it as invalid hex), but a declared sibling does not go through
    // the builder. Measured before the fix: a declared SPL SetAuthority
    // written `0` drew Clear.
    let r = GraphiteCore::new()
        .verify(&descriptive(
            SYSTEM,
            "02000000",
            vec![sibling(TOKEN, "0", &[addr(0xB1).as_str(), PAYER])],
        ))
        .expect("verify ok");
    assert_ne!(
        r.risk_verdict.status, "Clear",
        "a one-nibble sibling discriminator on SPL Token cannot be told apart \
         from SetAuthority and must not clear: {:?}",
        r.risk_verdict
    );
    assert!(!r.approved);
}

#[test]
fn an_odd_length_primary_discriminator_never_reaches_a_verdict() {
    // Why the test above targets a sibling. Pinned so that relaxing the
    // builder's hex check would be a deliberate act rather than an accident
    // that quietly widens the ambiguity surface.
    let err = GraphiteCore::new()
        .verify(&descriptive(TOKEN, "0", vec![]))
        .expect_err("an odd-length discriminator is not valid hex");
    assert!(
        format!("{err:?}").contains("TransactionBuild"),
        "expected the transaction builder to refuse it, got {err:?}"
    );
}

#[test]
fn a_full_length_safe_discriminator_is_not_caught_by_the_ambiguity_rule() {
    // Anti-vacuity for the rule above: `03` is a complete SPL Token selector
    // and is not a prefix of `06`, `09` or `04`, so it must still clear.
    let r = Request {
        program: TOKEN.to_string(),
        declared: "03".to_string(),
        accounts: vec![addr(0xB1), addr(0xB2), RECIPIENT.to_string()],
        data: {
            let mut d = vec![0x03u8];
            d.extend_from_slice(&5u64.to_le_bytes());
            d
        },
        artifact: None,
        siblings: vec![],
        intent: "transfer",
    }
    .verify();
    assert_eq!(
        r.risk_verdict.status, "Clear",
        "the ambiguity rule is over-matching on a complete selector: {:?}",
        r.risk_verdict
    );
}

// ── Anti-vacuity: honest traffic is untouched ────────────────────────────────

#[test]
fn an_ordinary_transfer_with_an_ordinary_sibling_still_clears() {
    // Two System transfers, both declared honestly — the shape of most real
    // multi-instruction traffic. A "fix" that simply blocked more would fail
    // here.
    let keys = vec![
        PAYER.to_string(),
        RECIPIENT.to_string(),
        SECOND.to_string(),
        SYSTEM.to_string(),
    ];
    let artifact = frame(
        &keys,
        &[
            (3, vec![0, 1], transfer_data(2_000_000)),
            (3, vec![0, 2], transfer_data(1_000_000)),
        ],
        1,
    );
    let r = Request {
        program: SYSTEM.to_string(),
        declared: "02000000".to_string(),
        accounts: vec![PAYER.to_string(), RECIPIENT.to_string()],
        data: transfer_data(2_000_000),
        artifact: Some(artifact),
        siblings: vec![sibling(
            SYSTEM,
            &hex::encode(transfer_data(1_000_000)),
            &[PAYER, SECOND],
        )],
        intent: "transfer",
    }
    .verify();
    assert_eq!(
        l2(&r).status,
        LayerStatus::Passed,
        "an honest two-transfer transaction failed L2: {}",
        l2(&r).reason
    );
    assert_eq!(
        r.risk_verdict.status, "Clear",
        "the GFX-106 fix is over-matching: an ordinary pair of System transfers was \
         blocked. risk={:?}",
        r.risk_verdict
    );
}

#[test]
fn an_ordinary_spl_transfer_still_resolves_and_clears() {
    let r = Request {
        program: TOKEN.to_string(),
        declared: "03".to_string(),
        accounts: vec![addr(0xB1), addr(0xB2), RECIPIENT.to_string()],
        data: {
            let mut d = vec![0x03u8];
            d.extend_from_slice(&5u64.to_le_bytes());
            d
        },
        artifact: None,
        siblings: vec![],
        intent: "transfer",
    }
    .verify();
    assert_eq!(
        r.instruction_name, "Transfer",
        "an ordinary SPL transfer stopped resolving to its manifest entry"
    );
    assert_eq!(
        r.risk_verdict.status, "Clear",
        "an ordinary SPL transfer was blocked: {:?}",
        r.risk_verdict
    );
}

#[test]
fn a_request_with_no_instruction_data_is_unchanged() {
    // With no data there are no bytes to key on, so the label is all there is
    // and the behaviour must be exactly what it always was.
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "probe".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: TOKEN.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "03".to_string(),
        account_addresses: vec![addr(0xB1), addr(0xB2), RECIPIENT.to_string()],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        real_account_metas: vec![],
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        state_diff: None,
    };
    let r = GraphiteCore::new().verify(&input).expect("verify ok");
    assert_eq!(
        r.instruction_name, "Transfer",
        "a request with no instruction_data must still resolve by its label"
    );
}
