//! Protocol-manifest JSON: strict parse, validation and registry load.
//!
//! A manifest is operator- and community-supplied input that decides how
//! instructions are described. Parsing and validation must never panic, a
//! registry must accept exactly the documents `validate_manifest` accepts, and
//! the instruction-level helpers must never panic on whatever a validated
//! manifest carries.
#![no_main]

use graphite_core::manifest::{
    discriminator_matches, names_a_delegation_grant, names_an_authority_change, validate_manifest,
    ManifestRegistry, ProtocolManifest,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let parsed: Result<ProtocolManifest, _> = serde_json::from_str(text);
    let mut registry = ManifestRegistry::new();
    let loaded = registry.load_from_json(text).is_ok();
    let Ok(manifest) = parsed else {
        assert!(
            !loaded,
            "the registry loaded a document that does not parse"
        );
        return;
    };
    let valid = validate_manifest(&manifest).is_ok();
    // Round 39 (core-identity): "exactly" — both directions. A fresh registry
    // holds no seed, so nothing but validation can refuse a document.
    assert_eq!(
        loaded, valid,
        "the registry and validate_manifest disagree about a document"
    );
    if !valid {
        return;
    }
    for ix in &manifest.instructions {
        let _ = names_an_authority_change(&ix.name);
        let _ = names_a_delegation_grant(&ix.name);
        let _ = discriminator_matches(&ix.discriminator, "");
        if ix.discriminator.is_empty() {
            // Only a one-instruction manifest may say nothing; it is then the
            // instruction every call is.
            assert_eq!(manifest.instructions.len(), 1);
            assert!(std::ptr::eq(manifest.instruction_for("ab").unwrap(), ix));
            continue;
        }
        // Round 39: no discriminator collision survives validation. An
        // instruction's own selector, and any longer data starting with it,
        // resolves to that instruction and to no other — the property the
        // prefix-ambiguity rule exists for.
        assert!(discriminator_matches(&ix.discriminator, &ix.discriminator));
        for input in [
            ix.discriminator.clone(),
            format!("{}00ff", ix.discriminator),
        ] {
            let found = manifest
                .instruction_for(&input)
                .expect("an instruction's own selector resolves");
            assert!(
                std::ptr::eq(found, ix),
                "selector {input} resolves to {:?}, not {:?}",
                found.name,
                ix.name
            );
        }
    }
});
