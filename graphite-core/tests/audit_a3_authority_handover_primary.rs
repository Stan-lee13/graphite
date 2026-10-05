//! A3-01 (2026-09-29 audit): an authority or delegate hand-over is refused as
//! the primary instruction whatever intent it is declared under.
//!
//! Check 2's table blocks SPL Token `SetAuthority`, System `Assign` and SPL
//! Token `Approve` unconditionally (`tests/protocol_expansion_tests.rs`). It
//! held seven entries, one selector per effect, and every native program has
//! others with the same effect. Those were left to L5, a keyword search of the
//! intent's vocabulary over the instruction's name and the manifest's prose:
//! "stake" matched Stake `Authorize`, "transfer" matched loader `SetAuthority`
//! ("transfers the program's upgrade authority"), `revoke` shared a canonical
//! class with `approve`, and the `create` vocabulary contained `assign`. Each
//! such hand-over was approved on the Gaming profile.
//!
//! The fix works at three levels. `RISKY_PATTERNS` lists every native
//! hand-over selector (Token `ApproveChecked` and batch, System
//! `AssignWithSeed` and `AuthorizeNonceAccount`, the Stake authorize and
//! lockup family, loader `Upgrade`, `SetAuthority`, `SetAuthorityChecked` and
//! `Close`, and the Vote authority and withdraw instructions), each blocking
//! under any intent. Check 2b blocks any manifest instruction whose
//! `security_class()` is `authority_change`, derived from its name by
//! `names_an_authority_change` as a floor under the manifest's own tag. And
//! `revoke` is its own intent class.
//!
//! The control shows the original table still blocks. Each `attack_*` test
//! pins a hand-over outside it as Blocked or not approved; the approval cases
//! run under Gaming with three simulation samples seeded through the operator
//! API (what three RPC-verified, risk-clear transactions earn; the test has no
//! RPC). `revoke_and_approve_are_opposite_declarations` pins the split class.

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::simulation_integrity::ComputeBaseline;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationResult,
};
use graphite_core::Pubkey;

const STAKE: &str = "Stake11111111111111111111111111111111111111";
const LOADER_V3: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const SYSTEM: &str = "11111111111111111111111111111111";
const CLOCK: &str = "SysvarC1ock11111111111111111111111111111111";

/// The user: stake authority, upgrade authority, token owner.
const VICTIM: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
/// The user's stake account / program-data account / token account.
const ACCOUNT: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const ATTACKER: &str = "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx";
const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

fn key(s: &str) -> [u8; 32] {
    *Pubkey::from_base58(s).expect("valid key").as_bytes()
}

fn request(
    program: &str,
    label: &str,
    data: Vec<u8>,
    accounts: &[&str],
    intent: &str,
    profile: WalletProfile,
) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: intent.to_string(),
            raw_natural_language: String::new(),
            confidence_of_parse: 1.0,
            extracted_parameters: None,
        },
        program_id: program.to_string(),
        protocol_version: String::new(),
        instruction_discriminator: label.to_string(),
        account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
        instruction_data: Some(data),
        cpi_targets: vec![],
        wallet_profile: profile,
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
    }
}

/// Stake `Authorize` (u32 1): new authority, then StakeAuthorize::Withdrawer (1).
fn stake_authorize_withdrawer_to_attacker(
    intent: &str,
    profile: WalletProfile,
) -> VerificationInput {
    let mut data = vec![1, 0, 0, 0];
    data.extend_from_slice(&key(ATTACKER));
    data.extend_from_slice(&1u32.to_le_bytes());
    request(
        STAKE,
        "01000000",
        data,
        &[ACCOUNT, CLOCK, VICTIM],
        intent,
        profile,
    )
}

/// BPF Upgradeable Loader `SetAuthority` (u32 4): [program_data, current, new].
fn loader_set_authority_to_attacker(intent: &str, profile: WalletProfile) -> VerificationInput {
    request(
        LOADER_V3,
        "04000000",
        vec![4, 0, 0, 0],
        &[ACCOUNT, VICTIM, ATTACKER],
        intent,
        profile,
    )
}

/// SPL Token / Token-2022 `ApproveChecked` (0x0d): u64::MAX to the attacker.
fn approve_checked_unlimited(
    program: &str,
    intent: &str,
    profile: WalletProfile,
) -> VerificationInput {
    let mut data = vec![0x0d];
    data.extend_from_slice(&u64::MAX.to_le_bytes());
    data.push(6);
    request(
        program,
        "0d",
        data,
        &[ACCOUNT, MINT, ATTACKER, VICTIM],
        intent,
        profile,
    )
}

/// System `AssignWithSeed` (u32 10): base, seed, new owner = attacker program.
fn assign_with_seed_to_attacker(intent: &str) -> VerificationInput {
    let mut data = vec![10, 0, 0, 0];
    data.extend_from_slice(&key(VICTIM));
    let seed = b"vault";
    data.extend_from_slice(&(seed.len() as u64).to_le_bytes());
    data.extend_from_slice(seed);
    data.extend_from_slice(&key(ATTACKER));
    request(
        SYSTEM,
        "0a000000",
        data,
        &[ACCOUNT, VICTIM],
        intent,
        WalletProfile::Gaming,
    )
}

fn layer(r: &VerificationResult, name: &str) -> LayerStatus {
    r.layers
        .iter()
        .find(|l| l.layer == name)
        .map(|l| l.status)
        .unwrap_or_else(|| panic!("no layer {name}"))
}

/// A core whose graph holds three simulation samples for `program` — the
/// SimulationMatch signal saturates at 3 (thresholds::SIMULATION_MATCH).
fn core_with_three_samples(program: &str) -> GraphiteCore {
    let core = GraphiteCore::new();
    core.seed_simulation_baseline(
        program,
        ComputeBaseline {
            mean_compute_units: 2_000.0,
            std_compute_units: 150.0,
            sample_count: 3,
            ..Default::default()
        },
    )
    .expect("valid baseline");
    core
}

// ── controls: the original table still blocks ─────────────────────────────

#[test]
fn control_the_table_blocks_spl_set_authority_system_assign_and_approve() {
    let core = GraphiteCore::new();
    let mut set_auth = vec![6u8, 2, 1];
    set_auth.extend_from_slice(&key(ATTACKER));
    let spl = core
        .verify(&request(
            TOKEN,
            "06",
            set_auth,
            &[ACCOUNT, VICTIM],
            "transfer",
            WalletProfile::Gaming,
        ))
        .unwrap();
    assert_eq!(spl.risk_verdict.status, "Blocked", "{:?}", spl.risk_verdict);

    let mut assign = vec![1u8, 0, 0, 0];
    assign.extend_from_slice(&key(ATTACKER));
    let sys = core
        .verify(&request(
            SYSTEM,
            "01000000",
            assign,
            &[VICTIM],
            "create",
            WalletProfile::Gaming,
        ))
        .unwrap();
    assert_eq!(sys.risk_verdict.status, "Blocked", "{:?}", sys.risk_verdict);

    let mut approve = vec![4u8];
    approve.extend_from_slice(&u64::MAX.to_le_bytes());
    let appr = core
        .verify(&request(
            TOKEN,
            "04",
            approve,
            &[ACCOUNT, ATTACKER, VICTIM],
            "revoke",
            WalletProfile::Gaming,
        ))
        .unwrap();
    assert_eq!(
        appr.risk_verdict.status, "Blocked",
        "{:?}",
        appr.risk_verdict
    );
}

// ── attacks: hand-overs outside the original table ────────────────────────

#[test]
fn attack_stake_authorize_withdrawer_under_stake_intent_is_blocked() {
    let core = GraphiteCore::new();
    let r = core
        .verify(&stake_authorize_withdrawer_to_attacker(
            "stake",
            WalletProfile::Gaming,
        ))
        .unwrap();
    // Before the fix: L5 Passed ("stake" is in the prose), risk Clear.
    assert_eq!(
        r.risk_verdict.status, "Blocked",
        "Stake Authorize(withdrawer -> attacker) declared as 'stake' must be refused like SPL SetAuthority; \
         got risk={:?} L5={:?}",
        r.risk_verdict,
        layer(&r, "L5_SemanticVerification")
    );
    assert!(!r.approved, "approved a withdraw-authority hand-over");
}

/// Named for the guarantee (W24: it was named for the bug it pins).
#[test]
fn attack_stake_authorize_under_stake_intent_is_not_approved_on_gaming() {
    let core = core_with_three_samples(STAKE);
    let r = core
        .verify(&stake_authorize_withdrawer_to_attacker(
            "stake",
            WalletProfile::Gaming,
        ))
        .unwrap();
    assert!(
        !r.approved,
        "handing the stake account's withdraw authority to an attacker was APPROVED at confidence {:.3} \
         (tier {}, risk {:?}, L5 {:?})",
        r.confidence,
        r.trust_tier,
        r.risk_verdict.status,
        layer(&r, "L5_SemanticVerification")
    );
}

#[test]
fn attack_loader_set_authority_under_transfer_intent_is_blocked() {
    let core = core_with_three_samples(LOADER_V3);
    let r = core
        .verify(&loader_set_authority_to_attacker(
            "transfer",
            WalletProfile::Gaming,
        ))
        .unwrap();
    assert_eq!(
        r.risk_verdict.status, "Blocked",
        "BPF Upgradeable SetAuthority (program upgrade authority -> attacker) declared as a 'transfer' \
         must be refused; got risk={:?} L5={:?} approved={} conf={:.3}",
        r.risk_verdict,
        layer(&r, "L5_SemanticVerification"),
        r.approved,
        r.confidence
    );
    assert!(!r.approved, "approved an upgrade-authority hand-over");
}

#[test]
fn attack_approve_checked_under_revoke_intent_is_blocked() {
    for program in [TOKEN, TOKEN_2022] {
        let core = core_with_three_samples(program);
        let r = core
            .verify(&approve_checked_unlimited(
                program,
                "revoke",
                WalletProfile::Gaming,
            ))
            .unwrap();
        assert_eq!(
            r.risk_verdict.status, "Blocked",
            "{program}: ApproveChecked(u64::MAX -> attacker) declared as 'revoke' must be refused like \
             Approve (04); got risk={:?} approved={} conf={:.3}",
            r.risk_verdict,
            r.approved,
            r.confidence
        );
        assert!(
            !r.approved,
            "{program}: approved an unlimited delegate grant"
        );
    }
}

#[test]
fn attack_approve_checked_under_approve_intent_is_blocked_like_approve() {
    // Approve (04) under an 'approve' intent is Blocked by the table (see the
    // control). ApproveChecked grants the identical delegate authority.
    let core = GraphiteCore::new();
    let r = core
        .verify(&approve_checked_unlimited(
            TOKEN,
            "approve",
            WalletProfile::Gaming,
        ))
        .unwrap();
    assert_eq!(r.risk_verdict.status, "Blocked", "{:?}", r.risk_verdict);
    assert!(!r.approved, "approved an unlimited delegate grant");
}

#[test]
fn attack_assign_with_seed_under_create_intent_is_blocked_like_assign() {
    let core = core_with_three_samples(SYSTEM);
    let r = core
        .verify(&assign_with_seed_to_attacker("create"))
        .unwrap();
    assert_eq!(
        r.risk_verdict.status, "Blocked",
        "System AssignWithSeed (owner -> attacker program) must be refused like System Assign; got risk={:?} \
         approved={}",
        r.risk_verdict,
        r.approved
    );
    assert!(!r.approved, "approved an ownership hand-over");
}

#[test]
fn revoke_and_approve_are_opposite_declarations() {
    // A3-01: `canonical_intent` merged "revoke" into "approve", and L5 gave
    // both the same vocabulary, so either word matched either instruction.
    // A revoke intent must not describe a grant, nor an approve intent a
    // revocation.
    let core = GraphiteCore::new();
    let revoke = |intent: &str| {
        core.verify(&request(
            TOKEN,
            "05",
            vec![5],
            &[ACCOUNT, VICTIM],
            intent,
            WalletProfile::Gaming,
        ))
        .unwrap()
    };
    assert_eq!(
        layer(&revoke("revoke"), "L5_SemanticVerification"),
        LayerStatus::Passed,
        "control: Revoke declared as revoke"
    );
    assert_eq!(
        layer(&revoke("approve"), "L5_SemanticVerification"),
        LayerStatus::Failed,
        "a Revoke declared as 'approve' passed L5"
    );
}
