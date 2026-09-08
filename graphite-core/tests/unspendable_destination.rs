//! Value must not move to an address that cannot spend it.
//!
//! Found 2026-09-08 by attacking the intent parser and then following the
//! transaction it produced through the real pipeline. Asking for "send 1 SOL to
//! 11111111111111111111111111111111" parsed at 0.99 confidence, and the
//! deterministic core answered `approved: true, risk: Clear`.
//!
//! The cause was a check doing the opposite of its purpose. The system-account
//! impersonation detector — grounded in SolPhishHunter (arXiv:2505.04094),
//! which documents phishers grinding addresses that END in `11111` so truncating
//! wallet UIs display them as official accounts — carried an `OFFICIAL`
//! allowlist and `continue`d past every address on it, commented "official
//! accounts that legitimately appear in transfers". So it flagged addresses
//! ground to RESEMBLE system accounts and exempted the system accounts
//! themselves.
//!
//! Official addresses do appear in transactions constantly, as the program being
//! invoked or as a read-only reference. They never appear as the counterparty of
//! a transfer: no private key exists for a native program, a loader or a sysvar,
//! and no program can sign for one. Lamports or tokens sent there are gone, and
//! it makes no difference to the user's funds whether that was an attack, a bug
//! in an agent, or a mistyped address.
//!
//! Written as the invariant rather than a signature, per the campaign rule: the
//! rule is "value must not move to an address that cannot spend it", not "block
//! this list of addresses".

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

const SYSTEM: &str = "11111111111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const PAYER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const NORMAL: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

fn transfer(program: &str, discriminator: &str, accounts: &[&str]) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send SOL".to_string(),
            confidence_of_parse: 0.99,
            extracted_parameters: None,
        },
        program_id: program.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: discriminator.to_string(),
        account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 5,
            battle_tested_tx_count: 50_000,
            simulation_match_count: 100,
        },
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

fn verdict(input: &VerificationInput) -> (bool, String, Vec<String>) {
    let r = GraphiteCore::new().verify(input).expect("verify ok");
    (
        r.approved,
        r.risk_verdict.status.clone(),
        r.risk_verdict
            .findings
            .iter()
            .map(|f| f.pattern.clone())
            .collect(),
    )
}

/// The measured case, exactly as it came back from the running container.
#[test]
fn a_sol_transfer_to_the_system_program_is_blocked() {
    let (approved, status, patterns) = verdict(&transfer(SYSTEM, "02000000", &[PAYER, SYSTEM]));
    assert!(
        !approved,
        "a transfer to the System Program address was approved — the lamports are unrecoverable. \
         risk={status} findings={patterns:?}"
    );
    assert!(
        patterns.iter().any(|p| p == "UnspendableDestination"),
        "blocked, but not for the right reason: {patterns:?}"
    );
}

/// Every address on the list, so the rule is not satisfied by one special case.
#[test]
fn no_native_program_loader_or_sysvar_may_receive_funds() {
    for dead_end in [
        SYSTEM,
        TOKEN,
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        "ComputeBudget111111111111111111111111111111",
        "SysvarRent111111111111111111111111111111111",
        "SysvarC1ock11111111111111111111111111111111",
        "SysvarRecentB1ockHashes11111111111111111111",
        "Stake11111111111111111111111111111111111111",
        "Vote111111111111111111111111111111111111111",
        "BPFLoader2111111111111111111111111111111111",
        "BPFLoaderUpgradeab1e11111111111111111111111",
        "NativeLoader1111111111111111111111111111111",
    ] {
        let (approved, _, patterns) = verdict(&transfer(SYSTEM, "02000000", &[PAYER, dead_end]));
        assert!(
            !approved,
            "a SOL transfer to {dead_end} was approved: {patterns:?}"
        );
    }
}

/// The same rule on the SPL Token path, so it is not a System-Program special
/// case. Token transfer (0x03) and transferChecked (0x0c).
#[test]
fn spl_token_transfers_to_unspendable_addresses_are_blocked_too() {
    for disc in ["03", "0c"] {
        let (approved, _, patterns) = verdict(&transfer(
            TOKEN,
            disc,
            &[NORMAL, "SysvarRent111111111111111111111111111111111", PAYER],
        ));
        assert!(
            !approved,
            "an SPL Token transfer (disc {disc}) to a sysvar was approved: {patterns:?}"
        );
    }
}

/// The rule must not swallow ordinary traffic. A transfer between two ordinary
/// addresses is untouched.
#[test]
fn an_ordinary_transfer_is_unaffected() {
    let (_, status, patterns) = verdict(&transfer(SYSTEM, "02000000", &[PAYER, NORMAL]));
    assert!(
        !patterns.iter().any(|p| p == "UnspendableDestination"),
        "an ordinary transfer was flagged as an unspendable destination: {status} {patterns:?}"
    );
}

/// And it must stay scoped to fund movement. Official addresses appear as
/// ordinary references in non-transfer instructions all the time — flagging
/// those would block most real transactions.
#[test]
fn official_addresses_are_still_allowed_where_they_belong() {
    // System `Assign` (0x01), which legitimately names a program as the new
    // owner rather than as a payee.
    let (_, _, patterns) = verdict(&transfer(SYSTEM, "01000000", &[PAYER, TOKEN]));
    assert!(
        !patterns.iter().any(|p| p == "UnspendableDestination"),
        "a non-transfer instruction referencing a program address was flagged as a payment to \
         it: {patterns:?}"
    );
}

/// The impersonation check it used to be tangled with must still work — the two
/// rules are about different things and both have to hold.
#[test]
fn vanity_impersonators_are_still_caught() {
    // 32 bytes, valid base58, ground to end in `11111`.
    let vanity = "Attacker111111zzzzzzzzzzzzzzzzzzzzzzzz11111";
    let (approved, _, patterns) = verdict(&transfer(SYSTEM, "02000000", &[PAYER, vanity]));
    assert!(
        !approved,
        "a vanity-ground impersonator was approved: {patterns:?}"
    );
    assert!(
        patterns.iter().any(|p| p == "Impersonation"),
        "a lookalike address must still be reported as impersonation, not as an unspendable \
         destination — they are different findings and an operator acts on them differently: \
         {patterns:?}"
    );
}
