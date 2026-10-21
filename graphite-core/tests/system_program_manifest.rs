//! The System Program manifest against the runtime's own instruction
//! definitions (`solana_system_interface::instruction::SystemInstruction`).
//!
//! Round 29 (audit 2026-10-20, MED-4): `TransferWithSeed` was declared as
//! `from (writable, SIGNER), to (writable), base (signer)`. The runtime's
//! layout is `0 funding (writable, NOT a signer — an address derived with
//! create_with_seed, which has no key), 1 base (signer), 2 recipient
//! (writable)`. Judged against the manifest, every honest TransferWithSeed
//! showed a "required signer that did not sign" in slot 0 and a writable
//! account in the read-only base slot, and was refused once its real account
//! metas were known. `UpgradeNonceAccount` (tag 12) was missing, and the
//! nonce instructions pinned the RecentBlockhashes sysvar in one place
//! (AdvanceNonceAccount) and in no other.

use graphite_core::account_resolution::{
    resolve_accounts, AccountResolutionInput, RealAccountMeta,
};
use graphite_core::manifest::load_seed_manifests;

const SYSTEM: &str = "11111111111111111111111111111111";
const RECENT_BLOCKHASHES: &str = "SysvarRecentB1ockHashes11111111111111111111";
const RENT: &str = "SysvarRent111111111111111111111111111111111";

/// (name, tag, [(writable, signer)]) exactly as the runtime documents each
/// instruction's accounts.
const RUNTIME: &[(&str, &str, &[(bool, bool)])] = &[
    ("CreateAccount", "00000000", &[(true, true), (true, true)]),
    ("Assign", "01000000", &[(true, true)]),
    ("Transfer", "02000000", &[(true, true), (true, false)]),
    (
        "CreateAccountWithSeed",
        "03000000",
        &[(true, true), (true, false), (false, true)],
    ),
    (
        "AdvanceNonceAccount",
        "04000000",
        &[(true, false), (false, false), (false, true)],
    ),
    (
        "WithdrawNonceAccount",
        "05000000",
        &[
            (true, false),
            (true, false),
            (false, false),
            (false, false),
            (false, true),
        ],
    ),
    (
        "InitializeNonceAccount",
        "06000000",
        &[(true, false), (false, false), (false, false)],
    ),
    (
        "AuthorizeNonceAccount",
        "07000000",
        &[(true, false), (false, true)],
    ),
    ("Allocate", "08000000", &[(true, true)]),
    (
        "AllocateWithSeed",
        "09000000",
        &[(true, false), (false, true)],
    ),
    (
        "AssignWithSeed",
        "0a000000",
        &[(true, false), (false, true)],
    ),
    (
        "TransferWithSeed",
        "0b000000",
        &[(true, false), (false, true), (true, false)],
    ),
    ("UpgradeNonceAccount", "0c000000", &[(true, false)]),
];

#[test]
fn every_system_instruction_matches_the_runtime_layout() {
    let registry = load_seed_manifests();
    let m = registry.get(SYSTEM).expect("System Program manifest");
    assert_eq!(
        m.instructions.len(),
        RUNTIME.len(),
        "the manifest must describe every System instruction the runtime defines"
    );
    for (name, tag, accounts) in RUNTIME {
        let ix = m
            .instructions
            .iter()
            .find(|i| i.name == *name)
            .unwrap_or_else(|| panic!("{name} missing from the System manifest"));
        assert_eq!(ix.discriminator, *tag, "{name}: wrong tag");
        let declared: Vec<(bool, bool)> = ix
            .accounts
            .iter()
            .map(|a| (a.is_writable, a.is_signer))
            .collect();
        assert_eq!(
            declared, *accounts,
            "{name}: account (writable, signer) flags differ from the runtime's"
        );
        for a in &ix.accounts {
            let role = if a.is_signer {
                "signer"
            } else if a.is_writable {
                "writable"
            } else {
                "readonly"
            };
            assert_eq!(
                a.role, role,
                "{name}.{}: role contradicts its flags",
                a.name
            );
        }
        assert!(
            !ix.risk_class.is_empty(),
            "{name}: every System instruction carries a class"
        );
    }
}

#[test]
fn nonce_instructions_pin_the_sysvars_the_runtime_checks() {
    let registry = load_seed_manifests();
    let m = registry.get(SYSTEM).expect("System Program manifest");
    for (name, slot, sysvar) in [
        ("AdvanceNonceAccount", 1, RECENT_BLOCKHASHES),
        ("WithdrawNonceAccount", 2, RECENT_BLOCKHASHES),
        ("WithdrawNonceAccount", 3, RENT),
        ("InitializeNonceAccount", 1, RECENT_BLOCKHASHES),
        ("InitializeNonceAccount", 2, RENT),
    ] {
        let ix = m.instructions.iter().find(|i| i.name == name).unwrap();
        assert_eq!(
            ix.accounts[slot].expected_address,
            vec![sysvar.to_string()],
            "{name} slot {slot} must be pinned to {sysvar}"
        );
    }
}

#[test]
fn upgrade_nonce_account_is_inert_and_transfer_with_seed_a_transfer() {
    let registry = load_seed_manifests();
    let find = |d: &str| registry.find_instruction(SYSTEM, d).expect("described");
    assert_eq!(find("0c000000").name, "UpgradeNonceAccount");
    assert_eq!(find("0c000000").risk_class, "inert");
    assert_eq!(find("0b000000").name, "TransferWithSeed");
    assert_eq!(find("0b000000").risk_class, "transfer");
}

/// The pipeline-level consequence: an honest TransferWithSeed — the real
/// transaction's account metas exactly as the runtime requires them — must
/// not be flagged as a privilege mismatch in any slot. Against the old
/// layout two slots were: slot 0 (declared a signer; a seed-derived address
/// cannot sign) and slot 2 (declared the read-only signing base; it is the
/// writable recipient).
#[test]
fn an_honest_transfer_with_seed_has_no_privilege_mismatch() {
    let registry = load_seed_manifests();
    let funding = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    let base = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
    let recipient = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7";
    let input = AccountResolutionInput {
        program_id: SYSTEM.to_string(),
        instruction_discriminator: "0b000000".to_string(),
        account_addresses: vec![funding.into(), base.into(), recipient.into()],
        instruction_data: None,
        real_account_metas: vec![
            RealAccountMeta {
                is_signer: false,
                is_writable: true,
            },
            RealAccountMeta {
                is_signer: true,
                is_writable: false,
            },
            RealAccountMeta {
                is_signer: false,
                is_writable: true,
            },
        ],
        fee_payer: None,
    };
    let resolved = resolve_accounts(&input, &registry)
        .expect("resolution")
        .resolved_accounts;
    let flagged: Vec<&str> = resolved
        .iter()
        .filter(|a| a.privilege_mismatch)
        .map(|a| a.address.as_str())
        .collect();
    assert!(
        flagged.is_empty(),
        "an honest TransferWithSeed was flagged in {flagged:?}"
    );
}
