//! Manifest invariants over the loaded seed registry, and the loader rules
//! that keep them (2026-09-29 audit).
//!
//! - A3-08, `no_pda_seed_reads_its_own_address`. A slot whose seed template is
//!   `{account_N}` with N equal to its own index can match only a fixed point
//!   of its own derivation, so every real call was an `AccountIdentityMismatch`.
//!   Ten templates had it, in `gmsol-store` and orao-vrf `fulfill_v2`: the
//!   generator had rendered IDL seeds that read account data (such as
//!   `referral_code.owner`) as the slot itself. Fail-closed (false refusals),
//!   not a bypass. The seeds are removed and those slots are judged by
//!   position.
//! - A3-02, `risk_class_is_in_check_10s_vocabulary`. The Risk Engine compares
//!   `risk_class` against fixed lists and the loader accepted any string, so
//!   `periodic_swap` and `multisig_execution` (Squads `vaultTransactionExecute`
//!   among them) read as "no special class". Those manifests were retagged.
//! - `every_instruction_is_addressable`. An empty discriminator matched
//!   nothing, so the Memo manifests' only instruction was unreachable and every
//!   memo was judged as `unknown_instruction`. A program described by one
//!   instruction with no discriminator now resolves every call to it
//!   (`ProtocolManifest::instruction_for`).
//!
//! The loader tests pin that the loader itself refuses a `risk_class` outside
//! `RISK_CLASSES`, a seed that reads its own slot, and an empty discriminator
//! beside other instructions.

use graphite_core::load_seed_manifests;

#[test]
fn no_pda_seed_reads_its_own_address() {
    let reg = load_seed_manifests();
    let mut bad = Vec::new();
    for m in reg.list() {
        for ix in &m.instructions {
            for (li, layout) in ix.all_layouts().enumerate() {
                for (slot, a) in layout.iter().enumerate() {
                    for seed in &a.pda_seeds {
                        if let Some(rest) = seed.strip_prefix("{account_") {
                            let idx: String =
                                rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                            if idx.parse::<usize>().ok() == Some(slot) {
                                bad.push(format!(
                                    "{} {} layout {li} slot {slot} ({}) seed {seed}",
                                    m.protocol.name, ix.name, a.name
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "self-referential PDA templates (unsatisfiable): {bad:#?}"
    );
}

#[test]
fn risk_class_is_in_check_10s_vocabulary() {
    // Every class a manifest may declare has a deliberate Check 10 treatment:
    // high-risk (refused without an intent) or one of the three that are not.
    // A class added to the loader without a place here fails, instead of
    // reaching the Risk Engine unplaced (2026-10-01: four copies of the list
    // had drifted from each other).
    let low = ["", "create", "transfer"];
    let high = graphite_core::manifest::HIGH_RISK_CLASSES;
    for class in graphite_core::manifest::RISK_CLASSES {
        assert!(
            low.contains(class) != high.contains(class),
            "risk class {class:?} must be exactly one of high-risk or low-risk for Check 10"
        );
    }
    let known: Vec<&str> = low.iter().chain(high.iter()).copied().collect();
    let reg = load_seed_manifests();
    let mut bad = Vec::new();
    for m in reg.list() {
        for ix in &m.instructions {
            if !known.contains(&ix.risk_class.as_str()) {
                bad.push(format!(
                    "{} {} risk_class={:?}",
                    m.protocol.name, ix.name, ix.risk_class
                ));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "risk classes the Risk Engine does not recognise: {bad:#?}"
    );
}

#[test]
fn every_instruction_is_addressable() {
    let reg = load_seed_manifests();
    let mut bad = Vec::new();
    for m in reg.list() {
        for ix in &m.instructions {
            // An empty discriminator is addressable only as a program's ONE
            // instruction (the Memo programs), through `instruction_for`.
            let reachable = m
                .instruction_for(&ix.discriminator)
                .is_some_and(|found| found.name == ix.name);
            if !reachable {
                bad.push(format!("{} {}", m.protocol.name, ix.name));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "manifest instructions no lookup can ever match: {bad:#?}"
    );
}

/// The loader, not only the shipped data, refuses what the lint above finds
/// (A3-02 / A3-08 / memo): a manifest carrying any of these is an error.
fn manifest_json(instructions: &str) -> String {
    format!(
        r#"{{
        "graphite_manifest_version": "1.0",
        "protocol": {{ "name": "Lint", "program_id": "4rQz2f4Wc1y7DpQ8v6mW2nN5uM3sR9bHjC1kTv8XwYdL", "website": "", "github": "" }},
        "version": {{ "label": "1.0", "effective_from_slot": 0, "previous_version_ref": null }},
        "instructions": [{instructions}],
        "trust_tier": "OfficialManifest"
    }}"#
    )
}

fn ix(name: &str, disc: &str, risk_class: &str, seeds_slot1: &str) -> String {
    format!(
        r#"{{ "name": "{name}", "discriminator": "{disc}", "risk_class": "{risk_class}",
            "accounts": [
              {{ "name": "a", "role": "writable", "is_writable": true, "is_signer": false, "pda_seeds": [] }},
              {{ "name": "b", "role": "writable", "is_writable": true, "is_signer": false, "pda_seeds": [{seeds_slot1}] }}
            ],
            "expected_state_changes": [], "allowed_cpis": [], "risk_rules": [] }}"#
    )
}

#[test]
fn the_loader_refuses_an_unknown_risk_class() {
    let mut reg = graphite_core::manifest::ManifestRegistry::new();
    let err = reg.load_from_json(&manifest_json(&ix("run", "01", "multisig_execution", "")));
    assert!(err.is_err(), "an unknown risk_class loaded");
    let mut reg = graphite_core::manifest::ManifestRegistry::new();
    assert!(reg
        .load_from_json(&manifest_json(&ix("run", "01", "drain", "")))
        .is_ok());
}

#[test]
fn the_loader_refuses_a_seed_that_reads_its_own_slot() {
    let mut reg = graphite_core::manifest::ManifestRegistry::new();
    let err = reg.load_from_json(&manifest_json(&ix(
        "run",
        "01",
        "",
        r#""x", "{account_1}""#,
    )));
    assert!(err.is_err(), "a self-referencing PDA template loaded");
    let mut reg = graphite_core::manifest::ManifestRegistry::new();
    assert!(reg
        .load_from_json(&manifest_json(&ix(
            "run",
            "01",
            "",
            r#""x", "{account_0}""#
        )))
        .is_ok());
}

#[test]
fn an_empty_discriminator_describes_a_single_instruction_program_only() {
    let mut reg = graphite_core::manifest::ManifestRegistry::new();
    let two = format!("{},{}", ix("memo", "", "", ""), ix("other", "02", "", ""));
    assert!(
        reg.load_from_json(&manifest_json(&two)).is_err(),
        "an empty discriminator beside another instruction loaded"
    );
    // The shipped Memo programs: every call is the one instruction.
    let seeds = load_seed_manifests();
    let memo = seeds
        .get("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
        .expect("SPL Memo ships as a seed");
    assert_eq!(
        memo.instruction_for("48656c6c6f").map(|i| i.name.as_str()),
        Some("Memo")
    );
    assert_eq!(
        memo.instruction_for("").map(|i| i.name.as_str()),
        Some("Memo")
    );
}
