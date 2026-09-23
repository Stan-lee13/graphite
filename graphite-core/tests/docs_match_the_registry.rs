//! The protocol tables in the documentation must say what the registry says.
//!
//! They did not. Before Round 18 the README listed Drift and Kamino Lending as
//! `Official Manifest` while their manifests declared `BattleTested`, and
//! listed Raydium AMM V4 and Squads V4 as `Battle Tested` while their
//! manifests said `OfficialManifest` — four wrong rows in the one table a
//! reader would use to decide what Graphite covers. Nobody had edited the
//! manifests dishonestly; the table was simply hand-maintained and the
//! manifests moved.
//!
//! `docs/protocol-coverage.md` is generated (`scripts/render_coverage.py`) and
//! this test re-runs the comparison, so the page cannot drift from the
//! registry again — including the tier, which after Round 18 is the tier the
//! loader actually applied after checking the evidence, not the one the file
//! declared.

use graphite_core::manifest::load_seed_manifests;
use std::collections::BTreeMap;

const COVERAGE_DOC: &str = include_str!("../../docs/protocol-coverage.md");

/// One row of the "Every manifest" table: name, program id, instruction count,
/// tier. Everything after those four columns is a measurement that legitimately
/// changes with each census run and is not pinned here.
fn rows(doc: &str) -> Vec<(String, String, usize, String)> {
    let mut out = Vec::new();
    for line in doc.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        if cells.len() < 4 {
            continue;
        }
        // The program-id column is the discriminating one: `base58` in
        // backticks. Header and separator rows never match.
        let id = cells[1];
        if !(id.starts_with('`') && id.ends_with('`') && id.len() > 30) {
            continue;
        }
        let Ok(ix) = cells[2].parse::<usize>() else {
            continue;
        };
        out.push((
            cells[0].to_string(),
            id.trim_matches('`').to_string(),
            ix,
            cells[3].to_string(),
        ));
    }
    out
}

#[test]
fn the_coverage_table_lists_exactly_the_loaded_registry() {
    let registry = load_seed_manifests();
    let loaded: BTreeMap<String, (String, usize, String)> = registry
        .list()
        .iter()
        .map(|m| {
            (
                m.protocol.program_id.clone(),
                (
                    m.protocol.name.clone(),
                    m.instructions.len(),
                    m.trust_tier.clone(),
                ),
            )
        })
        .collect();

    let documented: BTreeMap<String, (String, usize, String)> = rows(COVERAGE_DOC)
        .into_iter()
        .map(|(name, id, ix, tier)| (id, (name, ix, tier)))
        .collect();

    assert!(
        !documented.is_empty(),
        "docs/protocol-coverage.md has no manifest rows — run scripts/render_coverage.py"
    );

    let only_doc: Vec<&String> = documented
        .keys()
        .filter(|k| !loaded.contains_key(*k))
        .collect();
    let only_reg: Vec<&String> = loaded
        .keys()
        .filter(|k| !documented.contains_key(*k))
        .collect();
    assert!(
        only_doc.is_empty() && only_reg.is_empty(),
        "docs/protocol-coverage.md is out of date: documented but not loaded = {only_doc:?}, \
         loaded but not documented = {only_reg:?} — run scripts/render_coverage.py"
    );

    for (id, (name, ix, tier)) in &loaded {
        let (dname, dix, dtier) = &documented[id];
        assert_eq!(dname, name, "{id}: name differs from the manifest");
        assert_eq!(dix, ix, "{id} ({name}): instruction count differs");
        assert_eq!(
            dtier, tier,
            "{id} ({name}): the page states tier {dtier}, the loader applied {tier}"
        );
    }
}

#[test]
fn the_readme_headline_counts_match_the_registry() {
    const README_RAW: &str = include_str!("../../README.md");
    // Thousands separators are for the reader; the comparison is on digits.
    let readme = README_RAW.replace(',', "");
    let registry = load_seed_manifests();
    let manifests = registry.list().len();
    let instructions: usize = registry.list().iter().map(|m| m.instructions.len()).sum();
    let battle = registry
        .list()
        .iter()
        .filter(|m| m.trust_tier == "BattleTested")
        .count();

    for (what, needle) in [
        (
            "manifest count badge",
            format!("Protocol_Manifests-{manifests}-"),
        ),
        (
            "protocol section heading",
            format!("## Supported Protocols ({manifests} Manifests / {instructions} Instructions"),
        ),
        (
            "battle-tested count",
            format!("{battle} carry a BattleTested tier"),
        ),
    ] {
        assert!(
            readme.contains(&needle),
            "README.md does not state the current {what}: expected to find {needle:?}"
        );
    }
}
