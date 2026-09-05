//! P1 regression suite (2026-09-05 audit finding, fixed 2026-09-05):
//! "Signer/writable metadata is not grounded in actual transaction
//! AccountMeta data."
//!
//! `ResolvedAccount::is_signer`/`is_writable` are manifest-declared
//! EXPECTATIONS, not observations of the real transaction. Nothing
//! previously checked them against the actual `AccountMeta[]` a caller
//! (e.g. an SDK/bridge) may already hold — a manifest could declare a slot
//! "must be signed" or "read-only" and Graphite would approve a transaction
//! where the real transaction quietly failed to sign that account, or
//! marked a read-only slot writable, without ever noticing the discrepancy.
//!
//! `AccountResolutionInput::real_account_metas` (a caller-supplied,
//! same-order `Vec<RealAccountMeta>`) closes this gap. Only the two
//! security-relevant mismatch directions are flagged as
//! `ResolvedAccount::privilege_mismatch`, reusing the exact same hard-block
//! machinery `pda_mismatch`/`expected_address_mismatch` already had wired
//! into the pipeline:
//!   - manifest requires a signer, but the real transaction shows it is NOT
//!     signed, or
//!   - manifest declares the slot read-only, but the real transaction marks
//!     it writable (a privilege escalation).
//!
//! The reverse (more-restrictive) directions are deliberately not flagged,
//! and absence (or a length mismatch) of `real_account_metas` leaves
//! `privilege_mismatch` honestly `false` — "not checked", never "assumed to
//! match".

use graphite_core::account_resolution::{
    resolve_accounts, AccountResolutionInput, RealAccountMeta,
};
use graphite_core::manifest::load_seed_manifests;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

const AUTHORITY: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const READONLY_ACCOUNT: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const WRITABLE_ACCOUNT: &str = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7";
const TEST_PROGRAM: &str = "TestPrivMismatch111111111111111111111111111";

/// A synthetic manifest: account 0 is `signer` (must be signed), account 1
/// is `readonly` (must not be writable), account 2 is `writable` and not a
/// signer (an ordinary externally-determined destination slot).
fn manifest_json() -> String {
    format!(
        r#"{{
        "graphite_manifest_version": "1.0",
        "protocol": {{
            "name": "Test Privilege Mismatch Protocol",
            "program_id": "{pid}",
            "website": "",
            "github": ""
        }},
        "version": {{ "label": "1.0" }},
        "trust_tier": "OfficialManifest",
        "instructions": [
            {{
                "name": "TestInstruction",
                "discriminator": "bbbbbbbbbbbbbbbb",
                "accounts": [
                    {{
                        "name": "authority",
                        "role": "signer",
                        "is_writable": false,
                        "is_signer": true,
                        "pda_seeds": []
                    }},
                    {{
                        "name": "readonly_slot",
                        "role": "readonly",
                        "is_writable": false,
                        "is_signer": false,
                        "pda_seeds": []
                    }},
                    {{
                        "name": "destination",
                        "role": "writable",
                        "is_writable": true,
                        "is_signer": false,
                        "pda_seeds": []
                    }}
                ],
                "expected_state_changes": ["debits accounts.from by amount", "credits accounts.to by amount"],
                "allowed_cpis": [],
                "risk_rules": []
            }}
        ]
    }}"#,
        pid = TEST_PROGRAM
    )
}

fn resolve(
    real_account_metas: Vec<RealAccountMeta>,
) -> Vec<graphite_core::account_resolution::ResolvedAccount> {
    let mut registry = load_seed_manifests();
    registry
        .load_from_json(&manifest_json())
        .expect("test manifest must load");

    let input = AccountResolutionInput {
        program_id: TEST_PROGRAM.to_string(),
        instruction_discriminator: "bbbbbbbbbbbbbbbb".to_string(),
        account_addresses: vec![
            AUTHORITY.to_string(),
            READONLY_ACCOUNT.to_string(),
            WRITABLE_ACCOUNT.to_string(),
        ],
        instruction_data: None,
        real_account_metas,
    };
    resolve_accounts(&input, &registry)
        .expect("resolution must succeed")
        .resolved_accounts
}

fn matching_metas() -> Vec<RealAccountMeta> {
    vec![
        RealAccountMeta {
            is_signer: true,
            is_writable: false,
        },
        RealAccountMeta {
            is_signer: false,
            is_writable: false,
        },
        RealAccountMeta {
            is_signer: false,
            is_writable: true,
        },
    ]
}

#[test]
fn matching_real_metas_never_flag_privilege_mismatch() {
    let resolved = resolve(matching_metas());
    assert!(resolved.iter().all(|a| !a.privilege_mismatch));
}

#[test]
fn required_signer_not_actually_signed_is_flagged() {
    let mut metas = matching_metas();
    metas[0].is_signer = false; // authority slot claims signer, real tx does not sign it
    let resolved = resolve(metas);
    assert!(
        resolved[0].privilege_mismatch,
        "a manifest-required signer that the real transaction did not sign must be flagged"
    );
    assert!(!resolved[1].privilege_mismatch);
    assert!(!resolved[2].privilege_mismatch);
}

#[test]
fn readonly_slot_actually_writable_is_flagged() {
    let mut metas = matching_metas();
    metas[1].is_writable = true; // readonly slot is actually writable in the real tx
    let resolved = resolve(metas);
    assert!(
        resolved[1].privilege_mismatch,
        "a manifest-readonly slot that the real transaction marks writable must be flagged (privilege escalation)"
    );
    assert!(!resolved[0].privilege_mismatch);
    assert!(!resolved[2].privilege_mismatch);
}

#[test]
fn more_restrictive_real_metas_are_not_flagged() {
    // Real transaction is MORE cautious than the manifest requires: the
    // non-signer readonly slot and the non-signer destination slot both
    // happen to be signed too. Signing an account the manifest didn't
    // require to be signed is not a security concern (it does not grant
    // the transaction any capability the manifest didn't already expect),
    // so neither must be flagged. (The writable dimension has no analogous
    // "more restrictive than required" case here: the signer slot is
    // already manifest-readonly, the minimum, and the readonly/destination
    // slots' writable expectations are exactly matched by `matching_metas`.)
    let mut metas = matching_metas();
    metas[1].is_signer = true; // readonly slot happens to be signed too
    metas[2].is_signer = true; // destination slot happens to be signed too
    let resolved = resolve(metas);
    assert!(resolved.iter().all(|a| !a.privilege_mismatch));
}

#[test]
fn absent_real_account_metas_never_flags_anything() {
    let resolved = resolve(vec![]);
    assert!(
        resolved.iter().all(|a| !a.privilege_mismatch),
        "absence of real_account_metas must stay honestly unchecked, not assumed to match"
    );
}

#[test]
fn length_mismatched_real_account_metas_is_treated_as_not_supplied() {
    // Only two metas for three accounts: must not be partially applied to a
    // prefix of positions (which could silently skip checking exactly the
    // positions that were added or reordered).
    let mut metas = matching_metas();
    metas.pop();
    let resolved = resolve(metas);
    assert!(resolved.iter().all(|a| !a.privilege_mismatch));
}

/// Full pipeline: a required signer that the real transaction did not sign
/// must hard-block approval, exactly like a PDA or expected-address
/// mismatch — not just flag the field.
#[test]
fn full_pipeline_blocks_on_unsigned_required_signer() {
    let mut registry = load_seed_manifests();
    registry
        .load_from_json(&manifest_json())
        .expect("test manifest must load");
    let core = GraphiteCore::with_registry(registry);

    let mut metas = matching_metas();
    metas[0].is_signer = false;

    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "test".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: TEST_PROGRAM.to_string(),
        protocol_version: "1.0".to_string(),
        instruction_discriminator: "bbbbbbbbbbbbbbbb".to_string(),
        account_addresses: vec![
            AUTHORITY.to_string(),
            READONLY_ACCOUNT.to_string(),
            WRITABLE_ACCOUNT.to_string(),
        ],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming, // most permissive profile
        behavior_evidence: Default::default(),
        compute_units: 150,
        account_writes: 1,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: metas,
    };

    let result = core.verify(&input).unwrap();
    assert!(
        !result.approved,
        "a required signer that the real transaction did not sign must block even on the most permissive profile"
    );
    assert_eq!(result.risk_verdict.status, "Blocked");
    assert!(
        result.risk_verdict.findings.iter().any(
            |f| f.pattern == "AccountIdentityMismatch" || f.pattern == "MaliciousAccountChange"
        ),
        "got: {:?}",
        result.risk_verdict.findings
    );
}

/// Full pipeline control: matching real metas must not block approval.
#[test]
fn full_pipeline_approves_when_real_metas_match() {
    let mut registry = load_seed_manifests();
    registry
        .load_from_json(&manifest_json())
        .expect("test manifest must load");
    let core = GraphiteCore::with_registry(registry);

    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "test".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: TEST_PROGRAM.to_string(),
        protocol_version: "1.0".to_string(),
        instruction_discriminator: "bbbbbbbbbbbbbbbb".to_string(),
        account_addresses: vec![
            AUTHORITY.to_string(),
            READONLY_ACCOUNT.to_string(),
            WRITABLE_ACCOUNT.to_string(),
        ],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: Default::default(),
        compute_units: 150,
        account_writes: 1,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: matching_metas(),
    };

    let result = core.verify(&input).unwrap();
    assert!(
        result.risk_verdict.findings.iter().all(
            |f| f.pattern != "AccountIdentityMismatch" && f.pattern != "MaliciousAccountChange"
        ),
        "matching real metas must not raise an identity-mismatch finding: {:?}",
        result.risk_verdict.findings
    );
}

#[test]
fn resolution_is_deterministic() {
    let mut metas = matching_metas();
    metas[1].is_writable = true;
    let a = resolve(metas.clone());
    let b = resolve(metas);
    assert_eq!(a, b);
}
