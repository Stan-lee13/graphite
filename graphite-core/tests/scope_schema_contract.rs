//! The schema has to require what the implementation guarantees.
//!
//! `schemas/verification-result-v1.json` tells a consumer to gate execution on
//! `scope.kind == "artifact_bound"` rather than on `approved` alone. The fields
//! that give that claim meaning — the digest of the bytes, their length, and
//! whether they were simulated — were described as "artifact_bound only" in
//! prose and required nowhere. So this validated:
//!
//! ```json
//! { "scope": { "kind": "artifact_bound", "unobserved": ["..."] } }
//! ```
//!
//! A binding with no digest of what was bound. The one field a consumer is told
//! to gate on could be asserted without the evidence that makes it mean
//! anything, and a schema-conformant payload could say so. Found by review
//! 2026-09-11 and fixed by splitting the two kinds into separate closed schemas.
//!
//! Two halves, both needed. The schema half is checked here structurally, in
//! Rust, without a JSON-Schema validator dependency: this crate is a security
//! boundary and a new transitive dependency tree to assert a property that can
//! be read directly off the document is a bad trade. The implementation half is
//! checked by serializing real scopes.

use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

fn schema() -> serde_json::Value {
    serde_json::from_str(include_str!("../../schemas/verification-result-v1.json"))
        .expect("the published schema must be valid JSON")
}

fn branch(title: &str) -> serde_json::Value {
    schema()["properties"]["scope"]["oneOf"]
        .as_array()
        .expect("scope must be a oneOf of the two kinds, not one object with optional fields")
        .iter()
        .find(|b| b["title"] == title)
        .unwrap_or_else(|| panic!("no `{title}` branch in the scope schema"))
        .clone()
}

fn required(title: &str) -> Vec<String> {
    branch(title)["required"]
        .as_array()
        .expect("required list")
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect()
}

/// The artifact-bound branch requires the evidence that makes it a binding.
#[test]
fn the_artifact_bound_branch_requires_its_evidence() {
    let req = required("artifact_bound");
    for field in [
        "kind",
        "transaction_sha256",
        "transaction_bytes",
        "simulated",
        "unobserved",
    ] {
        assert!(
            req.iter().any(|r| r == field),
            "`{field}` is intrinsic to an artifact binding and must be required, not optional: {req:?}"
        );
    }
    assert_eq!(
        branch("artifact_bound")["properties"]["kind"]["const"],
        "artifact_bound",
        "the branch must be selected by the kind, or a payload could satisfy the wrong one"
    );
    assert_eq!(
        branch("artifact_bound")["additionalProperties"],
        false,
        "closed, so a future field cannot be added on one side of the contract only"
    );
}

/// The descriptive branch must not permit the artifact fields at all.
///
/// Their presence alongside `descriptive` would advertise a binding that does
/// not exist — the same confusion from the other direction.
#[test]
fn the_descriptive_branch_excludes_the_artifact_fields() {
    let b = branch("descriptive");
    let props = b["properties"].as_object().expect("properties");
    for field in ["transaction_sha256", "transaction_bytes", "simulated"] {
        assert!(
            !props.contains_key(field),
            "`{field}` must not be describable on a descriptive scope"
        );
    }
    assert_eq!(b["additionalProperties"], false);
    assert_eq!(b["properties"]["kind"]["const"], "descriptive");
}

/// `unobserved` is required on both, and never empty.
///
/// An empty list claims everything was observed, which is a strong assertion
/// that must be argued for rather than fall out of a default.
#[test]
fn both_branches_require_a_non_empty_unobserved_list() {
    for title in ["artifact_bound", "descriptive"] {
        let b = branch(title);
        assert!(
            required(title).iter().any(|r| r == "unobserved"),
            "{title}: unobserved must be required"
        );
        assert_eq!(
            b["properties"]["unobserved"]["minItems"], 1,
            "{title}: unobserved must never be empty"
        );
    }
}

/// `unobserved_codes` is required on both branches, and its enum IS the
/// implementation's `UnobservedCode` — every code the core can emit is in
/// the schema, and the schema names nothing the core cannot emit. A consumer
/// that validates the wire format and a policy that decides on the codes
/// are reading the same list (Round 9).
#[test]
fn the_unobserved_codes_enum_matches_the_implementation() {
    use graphite_core::verification::UnobservedCode;
    for title in ["artifact_bound", "descriptive"] {
        assert!(
            required(title).iter().any(|r| r == "unobserved_codes"),
            "{title}: unobserved_codes must be required"
        );
        let b = branch(title);
        assert_eq!(b["properties"]["unobserved_codes"]["minItems"], 1);
        let schema_codes: Vec<String> = b["properties"]["unobserved_codes"]["items"]["enum"]
            .as_array()
            .expect("enum")
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let impl_codes: Vec<String> = UnobservedCode::ALL
            .iter()
            .map(|c| c.as_str().to_string())
            .collect();
        assert_eq!(
            schema_codes, impl_codes,
            "{title}: schema enum vs UnobservedCode::ALL"
        );
        // And `as_str` is the serde name.
        for c in UnobservedCode::ALL {
            assert_eq!(
                serde_json::to_string(&c).unwrap(),
                format!("\"{}\"", c.as_str())
            );
        }
    }
}

/// The other half: what the implementation actually emits satisfies the branch
/// it claims.
///
/// A schema that requires fields the producer omits is as broken as one that
/// omits fields the producer requires, and nothing else compares the two.
#[test]
fn real_scopes_carry_every_field_their_branch_requires() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../fixtures/artifacts/devnet_transactions.json"
    ))
    .expect("fixtures must parse");
    let blob: Vec<u8> = f["benign_transfer"]["blob"]
        .as_array()
        .expect("blob")
        .iter()
        .map(|n| n.as_u64().expect("byte") as u8)
        .collect();

    let base = |signed: Option<Vec<u8>>| VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send a little SOL".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: "11111111111111111111111111111111".to_string(),
        protocol_version: "1.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![
            "CWb8MciizembLV66kisYcXo3Cb91hdszxw74QHpEJKZR".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
        ],
        instruction_data: Some(
            f["described"]["data"]
                .as_array()
                .expect("data")
                .iter()
                .map(|n| n.as_u64().expect("byte") as u8)
                .collect(),
        ),
        cpi_targets: vec![],
        wallet_profile: graphite_core::policy_engine::WalletProfile::Gaming,
        behavior_evidence: Default::default(),
        compute_units: 450,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: signed,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    };

    let core = GraphiteCore::new();
    for (label, input, expect_kind) in [
        ("artifact_bound", base(Some(blob)), "artifact_bound"),
        ("descriptive", base(None), "descriptive"),
    ] {
        let r = core.verify(&input).expect("verification must complete");
        let scope = serde_json::to_value(&r.scope).expect("scope must serialize");
        let obj = scope.as_object().expect("scope is an object");
        println!("{label}: {}", serde_json::to_string(&scope).unwrap());

        assert_eq!(obj["kind"], expect_kind, "{label}");
        for field in required(expect_kind) {
            assert!(
                obj.contains_key(&field),
                "{label}: the schema requires `{field}` and the implementation did not emit it"
            );
        }
        // Closed schemas: anything emitted must be describable.
        let allowed = branch(expect_kind)["properties"]
            .as_object()
            .expect("properties")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for key in obj.keys() {
            assert!(
                allowed.contains(key),
                "{label}: emitted `{key}`, which the closed schema does not allow"
            );
        }
        assert!(
            !obj["unobserved"].as_array().expect("unobserved").is_empty(),
            "{label}: no verdict claims to have observed everything"
        );
    }
}
