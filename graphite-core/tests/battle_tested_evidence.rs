//! A shipped manifest may not award itself a trust tier.
//!
//! `BattleTested` is the top tier. What a seed manifest's declaration of it
//! does is narrower than that suggests (Round 29, audit 2026-10-20, M14): the
//! verdict path caps every manifest's own tier at `OfficialManifest`
//! (`verification.rs`, "P7: cap self-asserted tiers"), so a declared — even a
//! measured — `BattleTested` never lifts a verdict's confidence ceiling; only
//! the Semantic Graph's runtime tier can. The declared tier is what the
//! registry and its displays report. Until Round 18 it was a string in a JSON
//! file that nothing checked — eight manifests declared it and the registry
//! reported all eight, which is exactly the "computed, never asserted" rule
//! (P7) being applied to every source of evidence except the document in the
//! repository.
//!
//! These tests hold the declaration to a measurement:
//! `protocols/battle_tested_evidence.json`, produced read-only from mainnet by
//! `scripts/battle_tested_census.py`, must show that the program is executable,
//! that at least 1,000 SUCCESSFUL transactions carry its address over a stated
//! window (the signature index answers for the address, not for invocation,
//! which is why the decode axis below is the one that establishes use),
//! and that the manifest can name at least 90% of the instructions actually
//! observed. Anything short of that loads as `OfficialManifest`.

use graphite_core::manifest::{
    battle_tested_bar, battle_tested_programs, load_seed_manifests, qualifying_programs,
    BATTLE_TESTED_EVIDENCE,
};
use serde_json::json;

fn evidence() -> serde_json::Value {
    serde_json::from_str(BATTLE_TESTED_EVIDENCE).expect("evidence file must be valid JSON")
}

#[test]
fn every_loaded_battle_tested_tier_is_backed_by_a_measurement() {
    let qualifying = battle_tested_programs();
    let registry = load_seed_manifests();
    for m in registry.list() {
        if m.trust_tier == "BattleTested" {
            assert!(
                qualifying.contains(&m.protocol.program_id),
                "{} ({}) loaded as BattleTested with no qualifying record in \
                 protocols/battle_tested_evidence.json",
                m.protocol.name,
                m.protocol.program_id
            );
        }
    }
}

#[test]
fn a_declared_tier_without_evidence_is_lowered_at_load() {
    // Every manifest file that WRITES "BattleTested" but has no qualifying
    // record must come back from the registry as OfficialManifest. This is the
    // clamp, observed end to end rather than trusted.
    let qualifying = battle_tested_programs();
    let registry = load_seed_manifests();
    let mut checked = 0;
    for (name, body) in graphite_core::manifest::SEED_MANIFESTS {
        let declared: serde_json::Value =
            serde_json::from_str(body).unwrap_or_else(|e| panic!("{name}: {e}"));
        if declared["trust_tier"] != "BattleTested" {
            continue;
        }
        let pid = declared["protocol"]["program_id"]
            .as_str()
            .expect("program_id");
        if qualifying.contains(pid) {
            continue;
        }
        checked += 1;
        let loaded = registry.get(pid).expect("seed manifest must be loaded");
        assert_eq!(
            loaded.trust_tier, "OfficialManifest",
            "{name} declares BattleTested without evidence and must load lowered"
        );
    }
    // Nothing to assert about `checked` beyond its meaning: when every
    // declaration is backed, there is nothing to lower, and that is the
    // healthy state.
    let _ = checked;
}

#[test]
fn the_evidence_files_own_verdict_field_is_not_what_the_gate_reads() {
    // A hand-edited `meets_battle_tested: true` must promote nothing: the gate
    // recomputes from the raw measurements.
    let doc = json!({
        "programs": [{
            "program_id": "So11111111111111111111111111111111111111112",
            "meets_battle_tested": true,
            "identity": {"exists": true, "executable": true},
            "volume": {"successful_transactions_counted": 3},
            "decode": {"instructions_observed": 400, "decode_rate": 1.0}
        }]
    });
    assert!(
        qualifying_programs(&doc).is_empty(),
        "a record with 3 transactions must not qualify, whatever its verdict field says"
    );
}

#[test]
fn each_measurement_axis_is_load_bearing() {
    let base = |volume: u64, observed: u64, rate: f64, executable: bool| {
        json!({"programs": [{
            "program_id": "So11111111111111111111111111111111111111112",
            "identity": {"exists": true, "executable": executable},
            "volume": {"successful_transactions_counted": volume},
            "decode": {"instructions_observed": observed, "decode_rate": rate}
        }]})
    };
    let pass = base(
        battle_tested_bar::MIN_SUCCESSFUL_TRANSACTIONS,
        battle_tested_bar::MIN_DECODED_INSTRUCTIONS,
        battle_tested_bar::MIN_DECODE_RATE,
        true,
    );
    assert_eq!(
        qualifying_programs(&pass).len(),
        1,
        "the bar itself must pass"
    );

    for (why, doc) in [
        (
            "one transaction short",
            base(
                battle_tested_bar::MIN_SUCCESSFUL_TRANSACTIONS - 1,
                100,
                1.0,
                true,
            ),
        ),
        (
            "too few instructions observed to say anything",
            base(
                10_000,
                battle_tested_bar::MIN_DECODED_INSTRUCTIONS - 1,
                1.0,
                true,
            ),
        ),
        (
            "the manifest cannot name what the program is run for",
            base(10_000, 100, battle_tested_bar::MIN_DECODE_RATE - 0.01, true),
        ),
        (
            "the account is not executable",
            base(10_000, 100, 1.0, false),
        ),
    ] {
        assert!(
            qualifying_programs(&doc).is_empty(),
            "must not qualify: {why}"
        );
    }
}

#[test]
fn the_declared_bar_is_the_bar_the_engine_applies_to_itself() {
    // The manifest declaration and the tier the node EARNS at runtime are held
    // to the same transaction count; if one moves, this fails.
    assert_eq!(
        battle_tested_bar::MIN_SUCCESSFUL_TRANSACTIONS,
        graphite_core::semantic_graph_store::thresholds::BATTLE_TESTED_TX,
        "the shipped-manifest bar and the earned-evidence threshold must not drift apart"
    );
}

#[test]
fn every_seed_manifest_has_a_measurement_on_record() {
    let doc = evidence();
    let recorded: std::collections::BTreeSet<String> = doc["programs"]
        .as_array()
        .expect("programs array")
        .iter()
        .filter_map(|p| p["program_id"].as_str().map(str::to_string))
        .collect();
    let registry = load_seed_manifests();
    let missing: Vec<String> = registry
        .list()
        .iter()
        .filter(|m| !recorded.contains(&m.protocol.program_id))
        .map(|m| format!("{} ({})", m.protocol.name, m.protocol.program_id))
        .collect();
    assert!(
        missing.is_empty(),
        "no on-chain measurement on record for: {missing:?} — run \
         scripts/battle_tested_census.py and commit the result"
    );
}

#[test]
fn the_recorded_thresholds_match_the_gate() {
    // The file states the bar it was measured against. If the census is
    // re-run with a weaker bar, the numbers in the file would no longer mean
    // what the gate assumes.
    let doc = evidence();
    let t = &doc["thresholds"];
    assert_eq!(
        t["min_successful_transactions"].as_u64(),
        Some(battle_tested_bar::MIN_SUCCESSFUL_TRANSACTIONS)
    );
    assert_eq!(
        t["min_decoded_instructions"].as_u64(),
        Some(battle_tested_bar::MIN_DECODED_INSTRUCTIONS)
    );
    assert_eq!(
        t["min_decode_rate"].as_f64(),
        Some(battle_tested_bar::MIN_DECODE_RATE)
    );
}

#[test]
fn every_record_names_a_seed_manifest_and_a_measurement_time() {
    let doc = evidence();
    let registry = load_seed_manifests();
    for p in doc["programs"].as_array().expect("programs array") {
        let pid = p["program_id"].as_str().expect("program_id");
        assert!(
            registry.get(pid).is_some(),
            "evidence names {pid}, which is not a seed manifest"
        );
        assert!(
            p["measured_at_unix"].as_u64().unwrap_or(0) > 0,
            "{pid}: a measurement with no time is not a measurement"
        );
        assert!(
            p["volume"]["window_seconds"].as_u64().is_some(),
            "{pid}: the volume record must state the window it was counted over"
        );
    }
}

/// The census's resolution rule (`scripts/battle_tested_census.py`): the first
/// instruction, in manifest order, whose discriminator the observed head
/// starts with.
fn census_resolves(manifest: &serde_json::Value, head: &str) -> Option<String> {
    let head = head.to_ascii_lowercase();
    manifest["instructions"]
        .as_array()?
        .iter()
        .find(|ix| {
            let d = ix["discriminator"]
                .as_str()
                .unwrap_or("")
                .to_ascii_lowercase();
            !d.is_empty() && head.starts_with(&d)
        })
        .and_then(|ix| ix["name"].as_str().map(str::to_string))
}

/// Round 29 (audit 2026-10-20, MED-1): a record is bound to the manifest it
/// describes. Its derived fields — the instructions it names, the decode
/// rate, the tier it says the manifest declares, its own verdict — must be
/// what its raw observations give against the manifest AS SHIPPED, so a
/// manifest cannot move on while its evidence keeps describing the old one.
/// Token-2022's record listed as "unmatched" instructions its manifest had
/// since named, Marginfi's named an instruction that had been renamed, and
/// seven records stated a tier their manifest no longer declared.
/// `scripts/recompute_evidence.py` brings a record back in line (no network).
#[test]
fn every_record_agrees_with_a_recomputation_from_its_raw_observations() {
    let doc = evidence();
    let t = &doc["thresholds"];
    let manifests: std::collections::BTreeMap<&str, serde_json::Value> =
        graphite_core::manifest::SEED_MANIFESTS
            .iter()
            .map(|(name, body)| {
                (
                    *name,
                    serde_json::from_str(body).unwrap_or_else(|e| panic!("{name}: {e}")),
                )
            })
            .collect();
    let mut problems = Vec::new();
    for p in doc["programs"].as_array().expect("programs array") {
        let file = p["manifest"].as_str().expect("manifest file name");
        let Some(m) = manifests.get(file) else {
            problems.push(format!("{file}: no such seed manifest"));
            continue;
        };
        let d = &p["decode"];
        let instructions = m["instructions"].as_array().expect("instructions");
        let names: std::collections::BTreeSet<&str> = instructions
            .iter()
            .filter_map(|ix| ix["name"].as_str())
            .collect();
        if p["declared_trust_tier"] != m["trust_tier"] {
            problems.push(format!(
                "{file}: declared_trust_tier {} but the manifest declares {}",
                p["declared_trust_tier"], m["trust_tier"]
            ));
        }
        let by_name = d["instructions_by_name"].as_object().expect("by name");
        for name in by_name.keys() {
            if !names.contains(name.as_str()) {
                problems.push(format!(
                    "{file}: names {name:?}, which the manifest does not have"
                ));
            }
        }
        let unmatched = d["unmatched_leading_bytes"]
            .as_object()
            .expect("unmatched");
        for head in unmatched.keys() {
            if let Some(name) = census_resolves(m, head) {
                problems.push(format!(
                    "{file}: lists {head} as unmatched, but the manifest names it {name}"
                ));
            }
        }
        let named: u64 = by_name.values().filter_map(|v| v.as_u64()).sum();
        let listed_unmatched: u64 = unmatched.values().filter_map(|v| v.as_u64()).sum();
        let observed = d["instructions_observed"].as_u64().expect("observed");
        if d["instructions_named_by_manifest"].as_u64() != Some(named) {
            problems.push(format!(
                "{file}: instructions_named_by_manifest {} but the names add up to {named}",
                d["instructions_named_by_manifest"]
            ));
        }
        if named + listed_unmatched > observed {
            problems.push(format!(
                "{file}: {named} named + {listed_unmatched} unmatched exceed {observed} observed"
            ));
        }
        let decodable = instructions
            .iter()
            .any(|ix| !ix["discriminator"].as_str().unwrap_or("").is_empty());
        let expected_rate = (decodable && observed > 0).then(|| named as f64 / observed as f64);
        match (expected_rate, d["decode_rate"].as_f64()) {
            (None, None) => {}
            (Some(e), Some(r)) if (e - r).abs() < 1e-12 => {}
            (e, r) => problems.push(format!("{file}: decode_rate {r:?}, recomputed {e:?}")),
        }
        if d["decode_applicable"].as_bool() != Some(decodable) {
            problems.push(format!(
                "{file}: decode_applicable disagrees with the manifest"
            ));
        }
        let meets = p["identity"]["executable"].as_bool() == Some(true)
            && p["volume"]["successful_transactions_counted"]
                .as_u64()
                .unwrap_or(0)
                >= t["min_successful_transactions"].as_u64().expect("threshold")
            && observed >= t["min_decoded_instructions"].as_u64().expect("threshold")
            && expected_rate
                .is_some_and(|r| r >= t["min_decode_rate"].as_f64().expect("threshold"));
        if p["meets_battle_tested"].as_bool() != Some(meets) {
            problems.push(format!(
                "{file}: meets_battle_tested {} but the measurements give {meets}",
                p["meets_battle_tested"]
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "evidence records disagree with their own observations against the shipped manifests \
         (run `python3 graphite-core/scripts/recompute_evidence.py`):\n{}",
        problems.join("\n")
    );
}
