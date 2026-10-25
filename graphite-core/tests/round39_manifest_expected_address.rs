//! Round 39 (core-identity, R39-CORE-IDENTITY-4): a manifest's
//! `expected_address` is validated at load.
//!
//! A pinned slot compares the transaction's account with each listed value;
//! a value that is neither `{program_id}` nor a public key matches nothing, so
//! the instruction was refused at every verification, and nothing said why
//! until one reached it. It is now refused at load, by the one validator the
//! seed loader, `load_from_json` and the community registry share. Every one
//! of the 926 shipped values is a key or `{program_id}` (the seed set still
//! loads: `load_seed_manifests` below).

use graphite_core::manifest::{load_seed_manifests, validate_manifest, ProtocolManifest};

fn manifest(expected: &[&str]) -> ProtocolManifest {
    serde_json::from_value(serde_json::json!({
        "graphite_manifest_version": "1.0",
        "protocol": {"name": "Pinned", "program_id": "GdP9U5aYx7f2kQzVwNmT8jRcL4hB6eX3sDnWqA1uMoH"},
        "version": {"label": "1.0.0"},
        "instructions": [{
            "name": "op",
            "discriminator": "01",
            "accounts": [{
                "name": "token_program",
                "role": "readonly",
                "is_writable": false,
                "is_signer": false,
                "expected_address": expected,
            }],
            "expected_state_changes": [],
            "allowed_cpis": [],
            "risk_rules": [],
        }],
    }))
    .expect("the document parses")
}

#[test]
fn an_expected_address_that_is_not_a_key_is_refused_at_load() {
    for bad in [
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5D", // one character short
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5D0", // not base58
        "{program}",
        "",
    ] {
        let err = validate_manifest(&manifest(&[bad]))
            .expect_err(bad)
            .to_string();
        assert!(err.contains("expected_address"), "{bad:?}: {err}");
    }
}

#[test]
fn keys_and_the_program_id_sentinel_still_load() {
    validate_manifest(&manifest(&[
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
    ]))
    .expect("two token programs");
    validate_manifest(&manifest(&["{program_id}"])).expect("the self-reference");
    validate_manifest(&manifest(&[])).expect("no constraint");
    assert!(load_seed_manifests().list().len() > 100);
}
