//! Manifest trust-anchor integrity (2026-09-05 red-team follow-up).
//!
//! The seed manifest set is Graphite's audited trust anchor: it defines, for
//! every shipped protocol, which accounts an instruction may touch, which CPIs
//! it may make, and which risk rules apply. If that definition can be replaced
//! at runtime, every downstream verification is judged against the forgery and
//! the whole pipeline is decorative.
//!
//! `ManifestRegistry::load_from_json` used a plain map insert, so loading a
//! manifest for an already-known program SILENTLY REPLACED it. An attacker
//! with any path to that API could redefine SPL Token — dropping its
//! `risk_rules`, widening its `allowed_cpis`, rewriting its account roles —
//! and Graphite would then verify against the attacker's definition. This was
//! previously accepted as a Phase-1 limitation, with a test pinning the
//! overwrite as *expected* behaviour and a comment deferring the fix to
//! "Phase 2 manifest signing". These tests replace that expectation.
//!
//! Community manifests still reach the registry — but only via
//! `merge_community`, which is seed-wins by construction and sits behind the
//! signature / reviewer-reputation / regression gates in `manifest_registry.rs`.
//! Contradicts otherwise: P11 (trust scoped to the exact program ID, never
//! inferred) and P7 (tier computed from evidence, never asserted by whoever
//! hands over a document).

use graphite_core::manifest::{load_seed_manifests, ManifestError, ManifestRegistry};

const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const UNKNOWN_PROGRAM: &str = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";

/// A schema-valid manifest that would pass every structural check — the point
/// is that validity is not authority.
fn manifest_for(program_id: &str, name: &str) -> String {
    format!(
        r#"{{
        "graphite_manifest_version": "1.0",
        "protocol": {{ "name": "{name}", "program_id": "{program_id}", "website": "", "github": "" }},
        "version": {{ "label": "1.0", "effective_from_slot": 0, "previous_version_ref": null }},
        "instructions": [{{
            "name": "Transfer",
            "discriminator": "03",
            "accounts": [],
            "expected_state_changes": [],
            "allowed_cpis": [],
            "risk_rules": []
        }}],
        "trust_tier": "BattleTested"
    }}"#
    )
}

/// THE attack: replace the audited SPL Token manifest with a weaker forgery.
#[test]
fn a_seed_manifest_cannot_be_replaced_at_runtime() {
    let mut registry = load_seed_manifests();
    let genuine = registry.get(SPL_TOKEN).expect("SPL Token ships as a seed");
    let genuine_name = genuine.protocol.name.clone();
    let genuine_instruction_count = genuine.instructions.len();

    let result = registry.load_from_json(&manifest_for(SPL_TOKEN, "Evil"));

    assert!(
        matches!(result, Err(ManifestError::SeedManifestImmutable(ref p)) if p == SPL_TOKEN),
        "replacing a shipped seed manifest must be refused, got: {result:?}"
    );

    // And the genuine definition must be untouched — a refused write that
    // still corrupted state would be worse than no check.
    let after = registry
        .get(SPL_TOKEN)
        .expect("seed manifest still present");
    assert_eq!(after.protocol.name, genuine_name);
    assert_eq!(
        after.instructions.len(),
        genuine_instruction_count,
        "the audited instruction surface must be intact after a refused overwrite"
    );
}

/// Every shipped protocol is protected, not just the obvious ones.
#[test]
fn every_seed_program_is_protected() {
    let registry = load_seed_manifests();
    let seed_ids: Vec<String> = registry
        .list()
        .iter()
        .map(|m| m.protocol.program_id.clone())
        .collect();
    assert!(
        seed_ids.len() >= 30,
        "expected the full seed set, got {}",
        seed_ids.len()
    );

    for pid in seed_ids {
        let mut r = load_seed_manifests();
        let result = r.load_from_json(&manifest_for(&pid, "Evil"));
        assert!(
            matches!(result, Err(ManifestError::SeedManifestImmutable(_))),
            "seed program {pid} was replaceable: {result:?}"
        );
    }
}

/// Loading a manifest for a program Graphite does NOT ship must still work —
/// this is the legitimate extension path and the fix must not break it.
#[test]
fn a_non_seed_manifest_still_loads() {
    let mut registry = load_seed_manifests();
    assert!(registry.get(UNKNOWN_PROGRAM).is_none());

    registry
        .load_from_json(&manifest_for(UNKNOWN_PROGRAM, "Community Protocol"))
        .expect("a manifest for an unknown program must load");

    assert_eq!(
        registry.get(UNKNOWN_PROGRAM).unwrap().protocol.name,
        "Community Protocol"
    );
}

/// A registry built from scratch (no seed set) has no protected programs, so
/// the rule cannot accidentally block a caller managing their own registry.
#[test]
fn a_registry_without_a_seed_set_has_no_protected_programs() {
    let mut registry = ManifestRegistry::new();
    registry
        .load_from_json(&manifest_for(SPL_TOKEN, "First"))
        .expect("first load into an empty registry");
    registry
        .load_from_json(&manifest_for(SPL_TOKEN, "Second"))
        .expect("a self-managed registry may replace its own entries");
    assert_eq!(registry.get(SPL_TOKEN).unwrap().protocol.name, "Second");
}

// ── Discriminator ambiguity ────────────────────────────────────────────────

/// `discriminator_matches` is a PREFIX match and `find_instruction` takes the
/// first hit in declaration order, so a manifest where one discriminator
/// prefixes another can silently resolve a real instruction to the WRONG
/// entry — and judge it against the wrong account roles, allowed CPIs and risk
/// rules. The community-submission validator enforced this; the validator on
/// the hot path did not.
#[test]
fn a_manifest_with_prefix_ambiguous_discriminators_is_rejected() {
    let json = format!(
        r#"{{
        "graphite_manifest_version": "1.0",
        "protocol": {{ "name": "Ambiguous", "program_id": "{UNKNOWN_PROGRAM}", "website": "", "github": "" }},
        "version": {{ "label": "1.0", "effective_from_slot": 0, "previous_version_ref": null }},
        "instructions": [
            {{ "name": "Benign", "discriminator": "09", "accounts": [], "expected_state_changes": [], "allowed_cpis": [], "risk_rules": [] }},
            {{ "name": "Drain",  "discriminator": "0900", "accounts": [], "expected_state_changes": [], "allowed_cpis": [], "risk_rules": ["drain_pattern"] }}
        ],
        "trust_tier": "OfficialManifest"
    }}"#
    );
    let mut registry = ManifestRegistry::new();
    let result = registry.load_from_json(&json);
    assert!(
        matches!(result, Err(ManifestError::Invalid(ref m)) if m.contains("ambiguous discriminators")),
        "a manifest whose discriminators prefix one another must be rejected: {result:?}"
    );
}

/// Exact duplicates are the degenerate case of the same problem.
#[test]
fn a_manifest_with_duplicate_discriminators_is_rejected() {
    let json = format!(
        r#"{{
        "graphite_manifest_version": "1.0",
        "protocol": {{ "name": "Dup", "program_id": "{UNKNOWN_PROGRAM}", "website": "", "github": "" }},
        "version": {{ "label": "1.0", "effective_from_slot": 0, "previous_version_ref": null }},
        "instructions": [
            {{ "name": "A", "discriminator": "03", "accounts": [], "expected_state_changes": [], "allowed_cpis": [], "risk_rules": [] }},
            {{ "name": "B", "discriminator": "03", "accounts": [], "expected_state_changes": [], "allowed_cpis": [], "risk_rules": [] }}
        ],
        "trust_tier": "OfficialManifest"
    }}"#
    );
    let mut registry = ManifestRegistry::new();
    assert!(
        registry.load_from_json(&json).is_err(),
        "duplicate discriminators must be rejected"
    );
}

/// Empty discriminators are legitimate (the Memo program's entire data field
/// IS the instruction) and must not be treated as ambiguous with each other.
#[test]
fn empty_discriminators_are_not_treated_as_ambiguous() {
    let json = format!(
        r#"{{
        "graphite_manifest_version": "1.0",
        "protocol": {{ "name": "Memo-like", "program_id": "{UNKNOWN_PROGRAM}", "website": "", "github": "" }},
        "version": {{ "label": "1.0", "effective_from_slot": 0, "previous_version_ref": null }},
        "instructions": [
            {{ "name": "Memo",  "discriminator": "", "accounts": [], "expected_state_changes": [], "allowed_cpis": [], "risk_rules": [] }},
            {{ "name": "Memo2", "discriminator": "", "accounts": [], "expected_state_changes": [], "allowed_cpis": [], "risk_rules": [] }}
        ],
        "trust_tier": "OfficialManifest"
    }}"#
    );
    let mut registry = ManifestRegistry::new();
    assert!(
        registry.load_from_json(&json).is_ok(),
        "empty discriminators are a legitimate shape and must still load"
    );
}

/// The 33 shipped manifests must themselves satisfy the stricter rule — a
/// validator nothing passes is not a validator.
#[test]
fn every_shipped_seed_manifest_satisfies_the_stricter_validation() {
    // load_seed_manifests aborts the process on any validation failure, so
    // reaching this point at all proves the whole seed set passes. Assert the
    // set is non-trivial so the test cannot pass vacuously.
    let registry = load_seed_manifests();
    assert!(
        registry.list().len() >= 30,
        "expected the full seed set to load under the stricter validation, got {}",
        registry.list().len()
    );
}
