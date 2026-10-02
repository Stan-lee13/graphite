//! The whole `VerificationResult` must satisfy the published schema, and the
//! schema must describe everything the Core emits.
//!
//! `tests/scope_schema_contract.rs` checks the `scope` branch only. Nothing
//! compared the rest of the response with `schemas/verification-result-v1.json`,
//! and the two had drifted: the schema, the TypeScript SDK and the Go SDK
//! spelled `resolved_accounts[].identity` as `"Pda" | "Constant" |
//! "Unverified"`, while the Core has always serialized it snake_case
//! (`"unverified"`). The committed example, which was taken from a real run,
//! failed its own schema (2026-09-29 audit, A5-03). A consumer gating on the
//! published constant never matched a real verdict.
//!
//! This test serializes real results (artifact-bound, descriptive, blocked,
//! and unknown-program) and checks each against the schema in two directions:
//! 1. **The schema's rules hold.** Types, enums, consts, bounds, required
//!    fields, closed objects and `oneOf` are checked.
//! 2. **Every emitted field is declared.** A key the Core emits that the
//!    schema does not name is a field a consumer cannot know about, and it
//!    fails here even where the schema leaves the object open.
//!
//! The committed example is checked too. As in `scope_schema_contract.rs`,
//! the validator is written out here rather than pulled in as a dependency:
//! this crate is a security boundary, and the schema uses a small, fixed set
//! of keywords. A keyword this validator does not implement fails the test,
//! so the schema cannot silently outgrow it.

use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};
use serde_json::Value;

fn schema() -> Value {
    serde_json::from_str(include_str!("../../schemas/verification-result-v1.json"))
        .expect("the published schema must be valid JSON")
}

/// The keywords this validator implements. Annotation-only keywords are
/// listed so that they are recognised, not so that they are checked.
const KEYWORDS: &[&str] = &[
    "$schema",
    "$id",
    "title",
    "description",
    "type",
    "enum",
    "const",
    "minimum",
    "maximum",
    "minLength",
    "minItems",
    "pattern",
    "required",
    "properties",
    "additionalProperties",
    "items",
    "oneOf",
];

fn type_matches(t: &str, v: &Value) -> bool {
    match t {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "boolean" => v.is_boolean(),
        "null" => v.is_null(),
        "number" => v.is_number(),
        "integer" => v.is_u64() || v.is_i64(),
        other => panic!("schema uses an unknown type {other:?}"),
    }
}

/// The one `pattern` the schema uses. A new pattern fails loudly here
/// instead of being skipped.
fn pattern_matches(p: &str, s: &str) -> bool {
    match p {
        "^[0-9a-f]{64}$" => {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        other => panic!("schema uses a pattern this validator does not implement: {other:?}"),
    }
}

/// Validate `v` against `s`, pushing every violation onto `errors`.
fn validate(v: &Value, s: &Value, path: &str, errors: &mut Vec<String>) {
    let Some(obj) = s.as_object() else {
        errors.push(format!("{path}: the schema node is not an object"));
        return;
    };
    for k in obj.keys() {
        assert!(
            KEYWORDS.contains(&k.as_str()),
            "{path}: the schema uses keyword {k:?}, which this validator does not implement"
        );
    }
    if let Some(t) = obj.get("type") {
        let ok = match t {
            Value::String(t) => type_matches(t, v),
            Value::Array(ts) => ts.iter().any(|t| type_matches(t.as_str().unwrap(), v)),
            _ => false,
        };
        if !ok {
            errors.push(format!("{path}: {v} is not of type {t}"));
            return;
        }
    }
    if let Some(e) = obj.get("enum").and_then(Value::as_array) {
        if !e.contains(v) {
            errors.push(format!("{path}: {v} is not one of {e:?}"));
        }
    }
    if let Some(c) = obj.get("const") {
        if c != v {
            errors.push(format!("{path}: {v} is not the constant {c}"));
        }
    }
    if let (Some(min), Some(n)) = (obj.get("minimum").and_then(Value::as_f64), v.as_f64()) {
        if n < min {
            errors.push(format!("{path}: {n} is below the minimum {min}"));
        }
    }
    if let (Some(max), Some(n)) = (obj.get("maximum").and_then(Value::as_f64), v.as_f64()) {
        if n > max {
            errors.push(format!("{path}: {n} is above the maximum {max}"));
        }
    }
    if let Some(s_) = v.as_str() {
        if let Some(min) = obj.get("minLength").and_then(Value::as_u64) {
            if (s_.chars().count() as u64) < min {
                errors.push(format!("{path}: {s_:?} is shorter than {min}"));
            }
        }
        if let Some(p) = obj.get("pattern").and_then(Value::as_str) {
            if !pattern_matches(p, s_) {
                errors.push(format!("{path}: {s_:?} does not match {p}"));
            }
        }
    }
    if let Some(a) = v.as_array() {
        if let Some(min) = obj.get("minItems").and_then(Value::as_u64) {
            if (a.len() as u64) < min {
                errors.push(format!("{path}: {} items, fewer than {min}", a.len()));
            }
        }
        if let Some(items) = obj.get("items") {
            for (i, item) in a.iter().enumerate() {
                validate(item, items, &format!("{path}[{i}]"), errors);
            }
        }
    }
    if let Some(o) = v.as_object() {
        if let Some(req) = obj.get("required").and_then(Value::as_array) {
            for r in req {
                let r = r.as_str().unwrap();
                if !o.contains_key(r) {
                    errors.push(format!("{path}: required field `{r}` is missing"));
                }
            }
        }
        if let Some(props) = obj.get("properties").and_then(Value::as_object) {
            for (k, val) in o {
                match props.get(k) {
                    Some(ps) => validate(val, ps, &format!("{path}.{k}"), errors),
                    // Direction 2: every emitted field is declared, whether or
                    // not the object is closed.
                    None => errors.push(format!(
                        "{path}: emits `{k}`, which the schema does not declare"
                    )),
                }
            }
        }
        if let Some(ap) = obj.get("additionalProperties") {
            if let Some(ap) = ap.as_object() {
                let declared = obj.get("properties").and_then(Value::as_object);
                for (k, val) in o {
                    if declared.is_none_or(|d| !d.contains_key(k)) {
                        validate(
                            val,
                            &Value::Object(ap.clone()),
                            &format!("{path}.{k}"),
                            errors,
                        );
                    }
                }
            }
        }
    }
    if let Some(branches) = obj.get("oneOf").and_then(Value::as_array) {
        let mut matched = Vec::new();
        let mut why = Vec::new();
        for (i, b) in branches.iter().enumerate() {
            let mut e = Vec::new();
            validate(v, b, path, &mut e);
            if e.is_empty() {
                matched.push(i);
            } else {
                why.push(format!("branch {i}: {}", e.join("; ")));
            }
        }
        if matched.len() != 1 {
            errors.push(format!(
                "{path}: matches {} oneOf branches, expected exactly 1 ({})",
                matched.len(),
                why.join(" | ")
            ));
        }
    }
}

fn errors_of(v: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    validate(v, &schema(), "$", &mut errors);
    errors
}

fn bytes(v: &Value) -> Vec<u8> {
    v.as_array()
        .expect("byte array")
        .iter()
        .map(|n| n.as_u64().expect("byte") as u8)
        .collect()
}

fn input(
    program: &str,
    discriminator: &str,
    data: Vec<u8>,
    accounts: &[&str],
) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send a little SOL".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: program.to_string(),
        protocol_version: "1.0".to_string(),
        instruction_discriminator: discriminator.to_string(),
        account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
        instruction_data: Some(data),
        cpi_targets: vec![],
        wallet_profile: graphite_core::policy_engine::WalletProfile::Gaming,
        behavior_evidence: Default::default(),
        compute_units: 450,
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

const FROM: &str = "CWb8MciizembLV66kisYcXo3Cb91hdszxw74QHpEJKZR";
const TO: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

fn real_results() -> Vec<(&'static str, Value)> {
    let f: Value = serde_json::from_str(include_str!(
        "../fixtures/artifacts/devnet_transactions.json"
    ))
    .expect("fixtures must parse");
    let transfer_data = bytes(&f["described"]["data"]);
    let system = "11111111111111111111111111111111";

    let descriptive = input(system, "02000000", transfer_data.clone(), &[FROM, TO]);
    let mut bound = descriptive.clone();
    bound.signed_transaction = Some(bytes(&f["benign_transfer"]["blob"]));
    // SPL Token Approve of u64::MAX: blocked by the risk engine under any intent.
    let mut approve = vec![4u8];
    approve.extend_from_slice(&u64::MAX.to_le_bytes());
    let blocked = input(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "04",
        approve,
        &[TO, "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx", FROM],
    );
    let unknown = input(
        "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS",
        "deadbeef",
        vec![0xde, 0xad, 0xbe, 0xef],
        &[FROM, TO],
    );

    let core = GraphiteCore::new();
    let mut out = Vec::new();
    for (label, i) in [
        ("artifact_bound", bound),
        ("descriptive", descriptive),
        ("blocked", blocked),
        ("unknown_program", unknown),
    ] {
        let r = core.verify(&i).expect("verification must complete");
        out.push((
            label,
            serde_json::to_value(&r).expect("result must serialize"),
        ));
    }
    out
}

#[test]
fn every_real_result_satisfies_the_schema_and_declares_every_field() {
    let results = real_results();
    // The four inputs must exercise what they are named for, or a passing
    // run would prove less than it says.
    let by = |l: &str| &results.iter().find(|(x, _)| *x == l).unwrap().1;
    assert_eq!(by("artifact_bound")["scope"]["kind"], "artifact_bound");
    assert_eq!(by("descriptive")["scope"]["kind"], "descriptive");
    assert_eq!(by("blocked")["approved"], false);
    assert_ne!(by("blocked")["risk_verdict"]["status"], "Clear");
    assert_eq!(by("unknown_program")["manifest_found"], false);
    assert!(
        results.iter().any(|(_, r)| r["resolved_accounts"]
            .as_array()
            .is_some_and(|a| !a.is_empty())),
        "at least one result must carry resolved accounts, so `identity` is checked"
    );

    let mut all = Vec::new();
    for (label, r) in &results {
        for e in errors_of(r) {
            all.push(format!("{label}: {e}"));
        }
    }
    assert!(
        all.is_empty(),
        "schema contract violations:\n{}",
        all.join("\n")
    );
}

/// The committed example is what integrators copy; it must be valid.
#[test]
fn the_committed_example_satisfies_the_schema() {
    let example: Value = serde_json::from_str(include_str!(
        "../../examples/sample-verification-result.json"
    ))
    .expect("the example must be valid JSON");
    let errors = errors_of(&example);
    assert!(
        errors.is_empty(),
        "the example violates the schema:\n{}",
        errors.join("\n")
    );
}

/// `identity` is spelled on the wire exactly as the schema's enum spells it.
#[test]
fn the_identity_enum_is_the_wire_spelling() {
    use graphite_core::account_resolution::AccountIdentity;
    let s = schema();
    let schema_enum: Vec<String> = s["properties"]["resolved_accounts"]["items"]["properties"]
        ["identity"]["enum"]
        .as_array()
        .expect("identity must be an enum")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let wire: Vec<String> = [
        AccountIdentity::Pda,
        AccountIdentity::Constant,
        AccountIdentity::Unverified,
    ]
    .iter()
    .map(|i| {
        serde_json::to_value(i)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    })
    .collect();
    assert_eq!(schema_enum, wire, "schema enum vs the Core's serialization");
}

/// The validator can fail: a wrong type, a missing required field, an
/// undeclared field and a value outside an enum are each reported.
#[test]
fn the_validator_rejects_what_it_should() {
    let (_, good) = real_results().into_iter().next().unwrap();
    assert!(
        errors_of(&good).is_empty(),
        "control: {:?}",
        errors_of(&good)
    );

    let mut wrong_type = good.clone();
    wrong_type["approved"] = Value::from("yes");
    assert!(!errors_of(&wrong_type).is_empty());

    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("audit_trail_id");
    assert!(errors_of(&missing)
        .iter()
        .any(|e| e.contains("audit_trail_id")));

    let mut undeclared = good.clone();
    undeclared["surprise"] = Value::from(1);
    assert!(errors_of(&undeclared)
        .iter()
        .any(|e| e.contains("surprise")));

    let mut bad_enum = good.clone();
    bad_enum["trust_tier"] = Value::from("Omnipotent");
    assert!(!errors_of(&bad_enum).is_empty());
}

/// R5 (external review of the 2026-09-29 audit): both schemas named
/// `https://graphite.dev/...` as their `$schema`. That keyword names the
/// METASCHEMA a validator must use, and that domain is not the project's:
/// Ajv refused to compile either schema and Python's jsonschema warned. Each
/// schema now declares JSON Schema 2020-12 and identifies itself with an `$id`
/// on the repository's own host.
#[test]
fn the_schemas_name_a_real_metaschema_and_their_own_id() {
    for (name, text) in [
        (
            "verification-result-v1.json",
            include_str!("../../schemas/verification-result-v1.json"),
        ),
        (
            "proposed-intent-v1.json",
            include_str!("../../schemas/proposed-intent-v1.json"),
        ),
    ] {
        let doc: Value = serde_json::from_str(text).expect("valid JSON");
        assert_eq!(
            doc["$schema"], "https://json-schema.org/draft/2020-12/schema",
            "{name}: $schema must name the metaschema"
        );
        assert_eq!(
            doc["$id"],
            format!("https://raw.githubusercontent.com/Stan-lee13/graphite/main/schemas/{name}"),
            "{name}: $id must be on the project's own host"
        );
    }
}
