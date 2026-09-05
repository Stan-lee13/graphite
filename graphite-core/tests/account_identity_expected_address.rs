//! P0-1 regression suite (2026-09-05 audit finding, fixed 2026-09-05):
//! "Approximately 98% of manifest-declared account roles have no PDA/address
//! verification."
//!
//! Most account roles are genuinely externally-determined (which token
//! account to debit, who the recipient is) and PDA/expected-address
//! verification cannot and must not apply to them — requiring PDA seeds
//! everywhere would be both wrong and infeasible. But a large, high-value
//! subset of account roles are FIXED, well-known constants: the SPL Token /
//! Token-2022 / System / Compute Budget / Associated-Token-Account program
//! IDs, and a manifest's own program self-reference. These are neither a PDA
//! (no seed formula exists) nor legitimately caller-chosen, yet nothing
//! verified them before this fix — an attacker could substitute a malicious
//! lookalike "token program" while keeping everything else structurally
//! valid.
//!
//! `AccountRoleDef::expected_address` (a manifest-declared constant, or set
//! of acceptable constants) closes this gap, reusing the exact same
//! hard-block machinery `pda_mismatch` already had wired into the pipeline.
//! `ResolvedAccount::identity` makes the REMAINING, unavoidable trust
//! boundary (externally-determined accounts) visible rather than silently
//! assumed safe.

use graphite_core::account_resolution::{
    resolve_accounts, AccountIdentity, AccountResolutionInput,
};
use graphite_core::manifest::load_seed_manifests;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ATTACKER_PROGRAM: &str = "GdP9U5aYx7f2kQzVwNmT8jRcL4hB6eX3sDnWqA1uMoH";
const TEST_PROGRAM: &str = "TestExpectedAddr111111111111111111111111111";
const AUTHORITY: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";

/// A synthetic manifest with one instruction whose second account is
/// constrained by `expected_address`. `addresses` is the JSON array literal
/// to embed for that constraint (e.g. `r#"["{token}"]"#`).
fn manifest_json(expected_address_json: &str) -> String {
    format!(
        r#"{{
        "graphite_manifest_version": "1.0",
        "protocol": {{
            "name": "Test Expected Address Protocol",
            "program_id": "{pid}",
            "website": "",
            "github": ""
        }},
        "version": {{ "label": "1.0" }},
        "trust_tier": "OfficialManifest",
        "instructions": [
            {{
                "name": "TestInstruction",
                "discriminator": "aaaaaaaaaaaaaaaa",
                "accounts": [
                    {{
                        "name": "authority",
                        "role": "signer",
                        "is_writable": false,
                        "is_signer": true,
                        "pda_seeds": []
                    }},
                    {{
                        "name": "constrained_program",
                        "role": "readonly",
                        "is_writable": false,
                        "is_signer": false,
                        "pda_seeds": [],
                        "expected_address": {expected_address_json}
                    }},
                    {{
                        "name": "externally_determined",
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
    expected_address_json: &str,
    constrained_program_addr: &str,
) -> Vec<graphite_core::account_resolution::ResolvedAccount> {
    let mut registry = load_seed_manifests();
    registry
        .load_from_json(&manifest_json(expected_address_json))
        .expect("test manifest must load");

    let input = AccountResolutionInput {
        program_id: TEST_PROGRAM.to_string(),
        instruction_discriminator: "aaaaaaaaaaaaaaaa".to_string(),
        account_addresses: vec![
            AUTHORITY.to_string(),
            constrained_program_addr.to_string(),
            "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7".to_string(),
        ],
        instruction_data: None,
    };
    resolve_accounts(&input, &registry)
        .expect("resolution must succeed")
        .resolved_accounts
}

#[test]
fn matching_expected_address_is_constant_identity_no_mismatch() {
    let resolved = resolve(&format!(r#"["{SPL_TOKEN}"]"#), SPL_TOKEN);
    let slot = &resolved[1];
    assert_eq!(slot.identity, AccountIdentity::Constant);
    assert!(!slot.expected_address_mismatch);
    assert!(!slot.is_pda, "a constant-address slot is not a PDA");
}

#[test]
fn substituted_program_at_constrained_slot_is_flagged() {
    let resolved = resolve(&format!(r#"["{SPL_TOKEN}"]"#), ATTACKER_PROGRAM);
    let slot = &resolved[1];
    assert_eq!(slot.identity, AccountIdentity::Constant);
    assert!(
        slot.expected_address_mismatch,
        "an attacker-substituted program at a constant-address slot must be flagged"
    );
}

#[test]
fn either_of_multiple_acceptable_constants_matches() {
    let both = format!(r#"["{SPL_TOKEN}", "{TOKEN_2022}"]"#);
    let classic = resolve(&both, SPL_TOKEN);
    assert!(
        !classic[1].expected_address_mismatch,
        "classic SPL Token must be accepted"
    );

    let ext2022 = resolve(&both, TOKEN_2022);
    assert!(
        !ext2022[1].expected_address_mismatch,
        "Token-2022 must also be accepted"
    );

    let neither = resolve(&both, ATTACKER_PROGRAM);
    assert!(
        neither[1].expected_address_mismatch,
        "an unrelated program must still be rejected"
    );
}

#[test]
fn program_id_self_reference_sentinel_resolves_to_the_transactions_own_program() {
    let resolved = resolve(r#"["{program_id}"]"#, TEST_PROGRAM);
    assert!(
        !resolved[1].expected_address_mismatch,
        "the {{program_id}} sentinel must accept the transaction's own program_id"
    );

    let resolved_wrong = resolve(r#"["{program_id}"]"#, ATTACKER_PROGRAM);
    assert!(
        resolved_wrong[1].expected_address_mismatch,
        "the {{program_id}} sentinel must reject anything other than the actual program_id"
    );
}

#[test]
fn externally_determined_slot_with_no_constraint_is_unverified_and_never_flagged() {
    let resolved = resolve(&format!(r#"["{SPL_TOKEN}"]"#), SPL_TOKEN);
    let externally_determined = &resolved[2];
    assert_eq!(
        externally_determined.identity,
        AccountIdentity::Unverified,
        "a slot with no pda_seeds and no expected_address must honestly report Unverified"
    );
    assert!(!externally_determined.expected_address_mismatch);
    assert!(!externally_determined.is_pda);
}

/// Full pipeline: a substituted constant-address slot must hard-block
/// approval, exactly like a PDA mismatch — not just flag the field.
#[test]
fn full_pipeline_blocks_on_substituted_token_program() {
    let mut registry = load_seed_manifests();
    registry
        .load_from_json(&manifest_json(&format!(r#"["{SPL_TOKEN}"]"#)))
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
        instruction_discriminator: "aaaaaaaaaaaaaaaa".to_string(),
        account_addresses: vec![
            AUTHORITY.to_string(),
            ATTACKER_PROGRAM.to_string(), // substituted "token program"
            "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7".to_string(),
        ],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming, // most permissive profile
        behavior_evidence: Default::default(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
    };

    let result = core.verify(&input).unwrap();
    assert!(
        !result.approved,
        "a substituted constant-address account must block even on the most permissive profile"
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

#[test]
fn resolution_is_deterministic() {
    let a = resolve(&format!(r#"["{SPL_TOKEN}"]"#), ATTACKER_PROGRAM);
    let b = resolve(&format!(r#"["{SPL_TOKEN}"]"#), ATTACKER_PROGRAM);
    assert_eq!(a, b);
}
