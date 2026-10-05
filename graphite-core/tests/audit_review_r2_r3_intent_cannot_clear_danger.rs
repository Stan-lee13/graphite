//! External review R2 and R3 (2026-10-01): a declared intent cannot clear an
//! instruction it does not describe, and control changes do not escape as
//! unclassed names or undescribed siblings.
//!
//! R2. L5 matched intent keywords against an instruction's name AND its
//! manifest prose. The prose is boilerplate — the create, withdraw and close
//! templates all say "transfers", "move" matched "remove" — and the Risk
//! Engine's Check 9 accepted `transfer` for every program, so a `transfer`
//! label cleared L5 and L7 for instructions of every class: Squads
//! `vaultTransactionExecute` and `batchExecuteTransaction` (the registry's two
//! `drain` instructions), Bubblegum `delegate`, SPL `MintTo`/`Burn`. Now L5
//! compares the intent with the instruction's security class through one
//! table (`manifest::INTENT_DECLARES`), and the Risk Engine's Check 9b reads
//! the same table, so neither layer reads prose and the two cannot disagree.
//!
//! R3. Control changes escaped `names_an_authority_change` (camelCase split
//! `multisigSetTimeLock` into time + lock; executor, submitter, successor,
//! builder, pubkey, collector and others were missing; Bubblegum `delegate`
//! and its kind were tagged `transfer`), and an instruction its program's
//! manifest does not describe was only a warning as a declared sibling
//! (Token-2022 CPI Guard `Disable`, `Reallocate`, `WithdrawExcessLamports`
//! beside a 0.001 SOL transfer came back Clear).
//!
//! Every case below is from the review and failed on `eb17aa5`; each is
//! re-verified here against the running pipeline, not taken from its text.

use graphite_core::manifest::{
    intent_declares_class, load_seed_manifests, names_a_delegation_grant,
    names_an_authority_change, INTENT_DECLARES,
};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationResult,
};

const SYSTEM: &str = "11111111111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const BUBBLEGUM: &str = "BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY";
const SQUADS: &str = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";
const VERIFIER: &str = "ttaiNybR4ncnBFsBCQKdVus8BNHepErToRp5cuULduL";
const PHOENIX: &str = "PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY";

const VICTIM: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const FRIEND: &str = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7";

/// The intents the vocabulary knows, as an agent would spell them.
const INTENTS: &[&str] = &[
    "transfer", "swap", "stake", "close", "create", "approve", "revoke",
];

/// `n` distinct, valid base58 addresses for an instruction's account list.
fn accounts(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            let mut key = [0u8; 32];
            key[0] = 0xA5;
            key[1..9].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            bs58::encode(key).into_string()
        })
        .collect()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2 * 2)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn request(program: &str, disc: &str, n_accounts: usize, intent: &str) -> VerificationInput {
    let mut data = hex_to_bytes(disc);
    data.extend_from_slice(&[0u8; 16]);
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: intent.to_string(),
            raw_natural_language: format!("{intent} please"),
            confidence_of_parse: 1.0,
            extracted_parameters: None,
        },
        program_id: program.to_string(),
        protocol_version: String::new(),
        instruction_discriminator: disc.to_string(),
        account_addresses: accounts(n_accounts.max(1)),
        instruction_data: Some(data),
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
    }
}

/// A benign 0.001 SOL System transfer, declared "transfer", with one sibling.
fn transfer_with_sibling(program: &str, disc: &str, n_accounts: usize) -> VerificationInput {
    let mut data = vec![2u8, 0, 0, 0];
    data.extend_from_slice(&1_000_000u64.to_le_bytes());
    let mut r = request(SYSTEM, "02000000", 2, "transfer");
    r.account_addresses = vec![VICTIM.to_string(), FRIEND.to_string()];
    r.instruction_data = Some(data);
    r.transaction_instructions = vec![TransactionInstruction {
        program_id: program.to_string(),
        instruction_discriminator: disc.to_string(),
        account_addresses: accounts(n_accounts.max(1)),
        cpi_targets: vec![],
    }];
    r
}

fn l5(r: &VerificationResult) -> LayerStatus {
    r.layers
        .iter()
        .find(|l| l.layer == "L5_SemanticVerification")
        .map(|l| l.status)
        .expect("L5 present")
}

/// (discriminator, account count, security class) of a named instruction.
fn ix(program: &str, name: &str) -> (String, usize, String) {
    let registry = load_seed_manifests();
    let m = registry
        .get(program)
        .unwrap_or_else(|| panic!("no manifest {program}"));
    let i = m
        .instructions
        .iter()
        .find(|i| i.name == name)
        .unwrap_or_else(|| panic!("{program} has no {name}"));
    (
        i.discriminator.clone(),
        i.accounts.len(),
        i.security_class().to_string(),
    )
}

// ── The table ────────────────────────────────────────────────────────────

#[test]
fn the_table_declares_no_dangerous_class_under_a_different_intent() {
    // Every class the Risk Engine treats as dangerous is declared only by the
    // intent that names it — and an authority change by none.
    for (intent, classes) in INTENT_DECLARES {
        for class in *classes {
            assert!(
                !matches!(*class, "drain" | "authority_change" | "authority" | "mint"),
                "the '{intent}' intent declares the '{class}' class"
            );
        }
    }
    assert_eq!(intent_declares_class("transfer", "transfer"), Some(true));
    assert_eq!(intent_declares_class("transfer", "withdraw"), Some(false));
    assert_eq!(intent_declares_class("transfer", "close"), Some(false));
    assert_eq!(intent_declares_class("transfer", "mint"), Some(false));
    assert_eq!(intent_declares_class("transfer", "drain"), Some(false));
    assert_eq!(intent_declares_class("transfer", ""), Some(false));
    assert_eq!(
        intent_declares_class("approve", "authority_change"),
        Some(false)
    );
    assert_eq!(
        intent_declares_class("lend", "transfer"),
        None,
        "outside the vocabulary declares nothing"
    );
}

/// Over the whole registry: under every intent, an instruction whose class
/// the intent does not declare fails L5, is never approved, and — for a
/// non-empty class — is Blocked by the Risk Engine. Under an intent that does
/// declare its class, L5 does not fail on the class.
#[test]
fn every_manifest_instruction_under_every_intent_is_judged_by_its_class() {
    let core = GraphiteCore::new();
    let registry = load_seed_manifests();
    let (mut judged, mut refused, mut declared) = (0usize, 0usize, 0usize);
    let mut failures: Vec<String> = Vec::new();
    for m in registry.list() {
        for i in &m.instructions {
            if i.discriminator.is_empty() {
                continue;
            }
            let class = i.security_class();
            for intent in INTENTS {
                let declares = intent_declares_class(intent, class) == Some(true);
                // Only the cases the table refuses are run through the whole
                // pipeline; a declared case is checked at L5 below on a sample.
                if declares {
                    declared += 1;
                    continue;
                }
                judged += 1;
                let r = core
                    .verify(&request(
                        &m.protocol.program_id,
                        &i.discriminator,
                        i.accounts.len(),
                        intent,
                    ))
                    .unwrap();
                let blocked = r.risk_verdict.status == "Blocked";
                let ok =
                    l5(&r) == LayerStatus::Failed && !r.approved && (class.is_empty() || blocked);
                if ok {
                    refused += 1;
                } else if failures.len() < 20 {
                    failures.push(format!(
                        "{} {} (class '{class}') under '{intent}': L5 {:?}, risk {}, approved {}",
                        m.protocol.name,
                        i.name,
                        l5(&r),
                        r.risk_verdict.status,
                        r.approved
                    ));
                }
            }
        }
    }
    println!("{judged} intent/instruction pairs the table refuses, {refused} refused; {declared} declared");
    assert!(
        judged > 15_000,
        "the sweep reached {judged} pairs; the registry is larger than that"
    );
    assert!(
        failures.is_empty(),
        "{} not refused, first: {failures:#?}",
        judged - refused
    );
}

// ── R2: the review's cases, as the primary under a `transfer` intent ─────────

fn assert_refused_as_transfer(program: &str, name: &str, disc_pin: &str) {
    let (disc, n, class) = ix(program, name);
    assert_eq!(
        disc, disc_pin,
        "{name}: the discriminator the review measured"
    );
    let core = GraphiteCore::new();
    let r = core
        .verify(&request(program, &disc, n, "transfer"))
        .unwrap();
    assert_eq!(
        l5(&r),
        LayerStatus::Failed,
        "{name} (class '{class}') declared 'transfer' passed L5"
    );
    assert_eq!(
        r.risk_verdict.status, "Blocked",
        "{name} (class '{class}'): {:?}",
        r.risk_verdict
    );
    assert!(!r.approved);
}

#[test]
fn r2_squads_drain_instructions_are_refused_as_a_transfer() {
    assert_refused_as_transfer(SQUADS, "vaultTransactionExecute", "c208a15799a419ab");
    assert_refused_as_transfer(SQUADS, "batchExecuteTransaction", "ac2cb398157feab4");
}

#[test]
fn r2_bubblegum_delegate_is_refused_as_a_transfer() {
    // Tagged `transfer` in the manifest, its prose says "transfers funds";
    // it hands the cNFT to a delegate. Now an authority change by its name.
    let (_, _, class) = ix(BUBBLEGUM, "delegate");
    assert_eq!(class, "authority_change");
    assert_refused_as_transfer(BUBBLEGUM, "delegate", "5a934bb255580489");
}

#[test]
fn r2_spl_mint_and_burn_are_refused_as_a_transfer() {
    for (name, disc) in [
        ("MintTo", "07"),
        ("MintToChecked", "0e"),
        ("Burn", "08"),
        ("BurnChecked", "0f"),
    ] {
        assert_refused_as_transfer(TOKEN, name, disc);
        assert_refused_as_transfer(TOKEN_2022, name, disc);
    }
}

// ── R3: control changes, as the primary and as a sibling ───────────────────

#[test]
fn r3_control_changes_are_refused_as_the_primary_under_a_transfer_intent() {
    assert_refused_as_transfer(SQUADS, "configTransactionExecute", "7292f4bdfc8c2428");
    assert_refused_as_transfer(VERIFIER, "rotate_withdrawal_executor", "1a56087ba2c6f087");
    assert_refused_as_transfer(VERIFIER, "rotate_block_submitter", "ee95766c95e00a2d");
}

fn assert_sibling_refused(program: &str, disc: &str, n: usize, what: &str) {
    let core = GraphiteCore::new();
    let r = core
        .verify(&transfer_with_sibling(program, disc, n))
        .unwrap();
    assert_eq!(
        r.risk_verdict.status, "Blocked",
        "{what} as a sibling of a 0.001 SOL transfer: {:?}",
        r.risk_verdict
    );
    assert!(!r.approved);
}

#[test]
fn r3_control_changes_are_refused_as_a_sibling() {
    for (program, name, pin) in [
        (PHOENIX, "NameSuccessor", "66"),
        (SQUADS, "multisigAddSpendingLimit", "0bf29f2a56c55973"),
        (SQUADS, "multisigSetTimeLock", "949a794dd4fe9b48"),
        (SQUADS, "multisigSetRentCollector", "30cc4139d2469c4a"),
        (SQUADS, "configTransactionExecute", "7292f4bdfc8c2428"),
        (VERIFIER, "rotate_block_submitter", "ee95766c95e00a2d"),
    ] {
        let (disc, n, class) = ix(program, name);
        assert_eq!(disc, pin, "{name}");
        assert_eq!(class, "authority_change", "{name} is a control change");
        assert_sibling_refused(program, &disc, n, name);
    }
}

#[test]
fn r3_controls_still_refused_as_a_sibling() {
    // The two the review found already blocked.
    let (disc, n, _) = ix(SQUADS, "multisigSetConfigAuthority");
    assert_sibling_refused(SQUADS, &disc, n, "multisigSetConfigAuthority");
    let (disc, n, _) = ix(PHOENIX, "ClaimAuthority");
    assert_sibling_refused(PHOENIX, &disc, n, "ClaimAuthority");
}

#[test]
fn r3_an_undescribed_instruction_of_a_described_program_is_refused_as_a_sibling() {
    // Token-2022 instructions the seed manifest does not describe: CPI Guard
    // Disable (0x22, 0x01), Reallocate (0x1d), WithdrawExcessLamports (0x26).
    let registry = load_seed_manifests();
    let t22 = registry.get(TOKEN_2022).unwrap();
    for (disc, what) in [
        ("2201", "CPI Guard Disable"),
        ("1d", "Reallocate"),
        ("26", "WithdrawExcessLamports"),
    ] {
        assert!(
            t22.instruction_for(disc).is_none(),
            "{what} is described now; pick an undescribed one"
        );
        assert_sibling_refused(TOKEN_2022, disc, 3, what);
    }
}

// ── Honest labels still pass L5, and Check 9b does not fire on them ──────────

#[test]
fn honest_labels_pass_the_class_gate() {
    let core = GraphiteCore::new();
    for (program, name, intent) in [
        (SYSTEM, "Transfer", "transfer"),
        (TOKEN, "TransferChecked", "transfer"),
        (TOKEN_2022, "TransferChecked", "send"),
        (TOKEN, "CloseAccount", "close"),
        (TOKEN, "InitializeAccount3", "create"),
        (TOKEN, "Revoke", "revoke"),
        (
            "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
            "route",
            "swap",
        ),
        (
            "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
            "sell",
            "swap",
        ),
        (
            "Stake11111111111111111111111111111111111111",
            "DelegateStake",
            "stake",
        ),
        (
            "Stake11111111111111111111111111111111111111",
            "Withdraw",
            "stake",
        ),
    ] {
        let (disc, n, class) = ix(program, name);
        let r = core.verify(&request(program, &disc, n, intent)).unwrap();
        assert_ne!(
            l5(&r),
            LayerStatus::Failed,
            "{name} (class '{class}') declared '{intent}' failed L5: {:?}",
            r.layers
                .iter()
                .find(|l| l.layer == "L5_SemanticVerification")
        );
        assert!(
            r.risk_verdict
                .findings
                .iter()
                .all(|f| !f.reason.contains("Intent-class mismatch")),
            "{name} declared '{intent}': {:?}",
            r.risk_verdict
        );
    }
}

#[test]
fn the_class_gate_approves_nothing_the_previous_rule_refused() {
    // Jupiter DCA `openDca`/`openDcaV2` are tagged `transfer`, so the class
    // table declares them under a transfer intent; the previous rule refused
    // them because neither name nor prose uses a transfer word. The previous
    // rule's vocabulary stays as a condition that can only refuse, so the
    // class gate turns no refusal into an approval.
    let core = GraphiteCore::new();
    for name in ["openDca", "openDcaV2"] {
        let (disc, n, class) = ix("DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M", name);
        assert_eq!(class, "transfer");
        assert_eq!(
            intent_declares_class("transfer", &class),
            Some(true),
            "the table declares it"
        );
        let r = core
            .verify(&request(
                "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M",
                &disc,
                n,
                "transfer",
            ))
            .unwrap();
        assert_eq!(
            l5(&r),
            LayerStatus::Failed,
            "{name} declared 'transfer' passed L5 on the class alone"
        );
        assert!(!r.approved);
    }
}

// ── The name rules ───────────────────────────────────────────────────────────

#[test]
fn the_name_rules_catch_the_review_list_and_leave_user_operations_alone() {
    for name in [
        "configTransactionExecute",
        "rotate_withdrawal_executor",
        "rotate_block_submitter",
        "NameSuccessor",
        "multisigAddSpendingLimit",
        "multisigSetTimeLock",
        "multisigSetRentCollector",
        "update_router_pubkey",
        "changeApprovedBuilder",
        "register_guardian",
        "deregister_guardian",
        "add_coordinator_executor",
    ] {
        assert!(names_an_authority_change(name), "{name}");
    }
    for name in [
        "delegate",
        "delegate_v0",
        "delegate_data_credits_v0",
        "create_delegate",
        "renounce_delegate",
    ] {
        assert!(names_a_delegation_grant(name), "{name}");
    }
    // A stake account's own delegation is staking, not a hand-over.
    assert!(!names_a_delegation_grant("DelegateStake"));
    assert!(!names_a_delegation_grant("createAndDelegateStakeAccount"));
    // User operations, and a noun "transfer fee".
    for name in [
        "InitializeTransferFeeConfig",
        "claim_position_fee",
        "updateFeesAndRewards",
        "swap_v2",
        "TransferChecked",
        "update_limit_order",
        "closeDca",
    ] {
        assert!(!names_an_authority_change(name), "{name}");
        assert!(!names_a_delegation_grant(name), "{name}");
    }
}

/// The mainnet measurement labels each instruction with the intent an honest
/// agent would give it (`live_corpus::honest_intent`). It used to take the
/// first intent the class gate allowed, in a fixed order that starts with
/// swap, so a transfer-class instruction of a swap program was "a swap" and
/// then refused as a fake one: 96 Pump.fun `distribute_fee_to_holders` rows in
/// the honest-label run. The label is now the intent the instruction is named
/// for, else the one named for its class.
#[test]
fn the_measurement_labels_an_instruction_by_its_name_then_its_class() {
    let registry = graphite_core::manifest::load_seed_manifests();
    let label = |program: &str, name: &str| {
        let i = registry
            .get(program)
            .and_then(|m| m.instructions.iter().find(|i| i.name == name))
            .unwrap_or_else(|| panic!("{program} has no {name}"));
        graphite_core::live_corpus::honest_intent(
            program,
            name,
            i.security_class(),
            &i.expected_state_changes,
        )
    };
    let pump = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
    assert_eq!(label(pump, "distribute_fee_to_holders"), Some("transfer"));
    assert_eq!(label(pump, "buy"), Some("swap"));
    assert_eq!(label(pump, "sell"), Some("swap"));
    // Named for one intent, classed for another: a swap program's `swap`
    // carries the `transfer` class (the onboarding's swap template), and both
    // intents describe it. The name decides (deliberate break B99 showed the
    // cases above are labelled the same without the name step).
    for (program, name) in [
        ("whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc", "swap"),
        (
            "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C",
            "swap_base_input",
        ),
    ] {
        assert_eq!(label(program, name), Some("swap"), "{name}");
    }
    assert_eq!(
        label("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", "route"),
        Some("swap")
    );
    assert_eq!(label(TOKEN, "CloseAccount"), Some("close"));
    assert_eq!(
        label("Stake11111111111111111111111111111111111111", "Withdraw"),
        Some("stake")
    );
    // A hand-over has no honest label.
    assert_eq!(label(SQUADS, "multisigSetConfigAuthority"), None);
}

// ── W14: a described sibling with no class ─────────────────────────────────

fn w14_findings(r: &VerificationResult) -> Vec<&str> {
    r.risk_verdict
        .findings
        .iter()
        .map(|f| f.reason.as_str())
        .filter(|reason| reason.contains("(W14,"))
        .collect()
}

/// External review W14 (verified 2026-10-03, on `eb17aa5` and on the R3 fix):
/// Squads `spendingLimitUse` pays out of a vault, `batchAccountsClose` moves
/// the funds of the accounts it closes, `proposalApprove` casts a governance
/// vote; none has a class in the manifest, so as a declared sibling each was
/// judged with no class and no intent and came back Clear beside a 0.001 SOL
/// transfer. Each is refused now, for the reason the primary would be.
#[test]
fn w14_an_unclassed_sibling_needs_an_intent_that_describes_it() {
    let core = GraphiteCore::new();
    for name in ["spendingLimitUse", "batchAccountsClose", "proposalApprove"] {
        let (disc, n, class) = ix(SQUADS, name);
        assert_eq!(class, "", "{name} is unclassed in the manifest");
        let r = core
            .verify(&transfer_with_sibling(SQUADS, &disc, n))
            .unwrap();
        assert_eq!(
            r.risk_verdict.status, "Blocked",
            "{name}: {:?}",
            r.risk_verdict
        );
        assert_eq!(w14_findings(&r).len(), 1, "{name}: {:?}", r.risk_verdict);
        assert!(!r.approved);
    }
}

/// What every transaction carries is classed, not unclassed: a compute
/// budget, a memo, `SyncNative` and an idempotent ATA creation beside a
/// transfer are not touched by the W14 rule.
#[test]
fn w14_plumbing_siblings_are_not_unclassed() {
    let core = GraphiteCore::new();
    for (program, name, class) in [
        (
            "ComputeBudget111111111111111111111111111111",
            "SetComputeUnitLimit",
            "inert",
        ),
        (
            "ComputeBudget111111111111111111111111111111",
            "SetComputeUnitPrice",
            "inert",
        ),
        (
            "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
            "Memo",
            "inert",
        ),
        (TOKEN, "SyncNative", "inert"),
        (TOKEN_2022, "SyncNative", "inert"),
        (
            "11111111111111111111111111111111",
            "AdvanceNonceAccount",
            "inert",
        ),
        (
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
            "CreateAssociatedTokenAccountIdempotent",
            "create",
        ),
    ] {
        let (disc, n, got) = ix(program, name);
        assert_eq!(got, class, "{name}");
        // A memo has no selector: its data is the memo ("hello").
        let disc = if disc.is_empty() {
            "68656c6c6f".to_string()
        } else {
            disc
        };
        let mut input = transfer_with_sibling(program, &disc, n);
        input.transaction_instructions[0].account_addresses = accounts(n);
        let r = core.verify(&input).unwrap();
        assert!(w14_findings(&r).is_empty(), "{name}: {:?}", r.risk_verdict);
    }
    // A compute-budget sibling beside a transfer is Clear outright.
    let (disc, _, _) = ix(
        "ComputeBudget111111111111111111111111111111",
        "SetComputeUnitLimit",
    );
    let mut input = transfer_with_sibling("ComputeBudget111111111111111111111111111111", &disc, 0);
    input.transaction_instructions[0].account_addresses = vec![];
    let r = core.verify(&input).unwrap();
    assert_eq!(r.risk_verdict.status, "Clear", "{:?}", r.risk_verdict);
}

/// The swap a sibling helps is what declares it: an unclassed Pump.fun
/// instruction beside a Pump.fun swap, declared a swap, is not refused by
/// the rule (it is by a transfer).
#[test]
fn w14_an_unclassed_sibling_inside_the_swap_it_belongs_to_is_declared() {
    let pump = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
    let (buy, buy_n, _) = ix(pump, "buy");
    let (sell, sell_n, class) = ix(pump, "sell");
    assert_eq!(class, "");
    let core = GraphiteCore::new();
    let mut input = request(pump, &buy, buy_n, "swap");
    input.transaction_instructions = vec![TransactionInstruction {
        program_id: pump.to_string(),
        instruction_discriminator: sell.clone(),
        account_addresses: accounts(sell_n),
        cpi_targets: vec![],
    }];
    let r = core.verify(&input).unwrap();
    assert!(w14_findings(&r).is_empty(), "{:?}", r.risk_verdict);
    let r = core
        .verify(&transfer_with_sibling(pump, &sell, sell_n))
        .unwrap();
    assert_eq!(w14_findings(&r).len(), 1, "{:?}", r.risk_verdict);
}

// ── Round 24, found by the mainnet measurement: control changes the IDL
// onboarding classed as transfers ─────────────────────────────────────────

const TENSOR_AMM: &str = "TAMM6ub33ij1mbetoMyVBLeKY5iP41i4UPUJQGkhfsg";
const JUPITER_DEX: &str = "jupZ4m2GqUCJ5iueMfzQf8khFfH31d4XAQt3RzCT9Vd";
const METEORA_AMM: &str = "Eo7WjKq67rjJQSZxS6z3YkapzY3eMj6Xy8X5EQVn5UaB";

/// Re-measuring four days of mainnet after R2 turned one refusal into a
/// Clear verdict: Tensor AMM's `editPool`, newly manifested, tagged
/// `transfer` by the onboarding's default, so the `transfer` label cleared
/// it. The same default had classed 52 seed instructions that switch or edit
/// a setting (`unpause_dex`, `toggle_feature`, `enable_role`, `editPool`) as
/// transfers, and 391 instructions that need an admin's signature as
/// transfers, creations, withdrawals, closures or nothing.
#[test]
fn a_switch_an_edit_or_an_admin_signature_is_a_control_change() {
    // Tagged in the data (the onboarding now classes `edit*`/`reset*` so).
    assert_refused_as_transfer(TENSOR_AMM, "editPool", "32ae222403a61dcc");
    // By its name, whatever its tag: still `transfer` in the manifest.
    let (_, _, class) = ix(JUPITER_DEX, "pause_swap_and_arbitrage");
    assert_eq!(class, "authority_change");
    assert_refused_as_transfer(JUPITER_DEX, "pause_swap_and_arbitrage", "fc43a63e2d88584c");
    // By its admin signer, whatever its tag: `create`, and refused under the
    // `create` intent that declares that class.
    let (disc, n, class) = ix(METEORA_AMM, "createConfig");
    assert_eq!(class, "authority_change");
    let r = GraphiteCore::new()
        .verify(&request(METEORA_AMM, &disc, n, "create"))
        .unwrap();
    assert_eq!(l5(&r), LayerStatus::Failed);
    assert_eq!(r.risk_verdict.status, "Blocked", "{:?}", r.risk_verdict);
    assert!(!r.approved);
}

/// Over the whole registry, so a manifest added later cannot reopen it:
/// every instruction that needs an admin's signature, and every one whose
/// name opens by switching something, is judged as a control change.
#[test]
fn no_seed_instruction_with_an_admin_signer_or_a_switch_name_escapes_the_control_class() {
    let switches = [
        "enable", "disable", "toggle", "pause", "unpause", "halt", "unhalt", "resume",
    ];
    let mut escaped = Vec::new();
    let (mut admin, mut switched) = (0, 0);
    for m in load_seed_manifests().list() {
        for i in &m.instructions {
            // The name's first word: its leading character, then up to the
            // next underscore or capital (`unpause_dex`, `toggleFeature`,
            // `Pause`).
            let mut chars = i.name.chars();
            let first: String = chars
                .next()
                .into_iter()
                .chain(chars.take_while(|c| *c != '_' && !c.is_ascii_uppercase()))
                .collect::<String>()
                .to_ascii_lowercase();
            let is_admin = i.requires_an_admin_signature();
            let is_switch = switches.contains(&first.as_str());
            admin += usize::from(is_admin);
            switched += usize::from(is_switch);
            if (is_admin || is_switch) && i.security_class() != "authority_change" {
                escaped.push(format!("{} {}", m.protocol.name, i.name));
            }
        }
    }
    assert!(admin > 600, "{admin} admin-signed instructions");
    assert!(switched > 40, "{switched} switch-named instructions");
    assert!(escaped.is_empty(), "{escaped:#?}");
}
