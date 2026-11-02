//! Audit A002: every committed fuzz seed gets past its target's first
//! refusal, so a fuzz run starts from inputs that exercise what the target
//! exists for. (`fuzz/make_seeds.py` writes them; ci-scripts.test.sh holds
//! each seed to its target's `-max_len`.)
//!
//! The manifest seeds were whole shipped manifests, cut by `-max_len=4096`
//! to prefixes that are not JSON: the target's validation invariants never
//! ran from a seed. These tests read the seeds exactly as the targets do.

use graphite_core::manifest::{validate_manifest, ManifestRegistry, ProtocolManifest};
#[cfg(feature = "rpc")]
use graphite_core::parsed_inner;
#[cfg(feature = "rpc")]
use graphite_core::rpc_client::simulation_result_from_value_for_test;
use graphite_core::tx_artifact as tx;
use std::collections::HashMap;
use std::path::PathBuf;

fn seeds(target: &str) -> Vec<(String, Vec<u8>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/seeds")
        .join(target);
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| {
            let p = e.unwrap().path();
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read(&p).unwrap(),
            )
        })
        .collect();
    out.sort();
    assert!(!out.is_empty(), "{target}: no seeds");
    out
}

#[test]
fn every_manifest_seed_is_a_manifest_the_registry_loads() {
    let all = seeds("manifest_json");
    let mut small = 0;
    for (name, bytes) in &all {
        let text = std::str::from_utf8(bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        let m: ProtocolManifest =
            serde_json::from_str(text).unwrap_or_else(|e| panic!("{name}: does not parse: {e}"));
        validate_manifest(&m).unwrap_or_else(|e| panic!("{name}: does not validate: {e:?}"));
        let mut registry = ManifestRegistry::new();
        registry
            .load_from_json(text)
            .unwrap_or_else(|e| panic!("{name}: the registry refuses it: {e:?}"));
        if bytes.len() <= 4096 {
            small += 1;
        }
    }
    // Small documents a mutation can stay valid around, and at least one
    // with two instructions, for the prefix-ambiguity rule.
    assert!(small >= 8, "{small} seeds of at most 4 KiB");
    assert!(all.iter().any(|(n, _)| n.ends_with("-2.json")));
}

#[test]
fn a_lookup_table_seed_of_256_entries_resolves_every_index() {
    let mut largest = 0;
    for (name, bytes) in seeds("lookup_table") {
        let (len, rest) = bytes.split_first_chunk::<2>().expect("a length");
        let n = usize::from(u16::from_le_bytes(*len));
        assert!(n <= rest.len(), "{name}: the length runs past the seed");
        let (table, tx_bytes) = rest.split_at(n);
        let entries = tx::decode_lookup_table("Table", table)
            .unwrap_or_else(|e| panic!("{name}: the table does not decode: {e:?}"));
        let m = tx::parse_transaction(tx_bytes)
            .unwrap_or_else(|e| panic!("{name}: the transaction does not parse: {e:?}"));
        assert!(
            !m.lookups.is_empty(),
            "{name}: the transaction looks nothing up"
        );
        if entries.len() == 256 {
            let tables: HashMap<String, Vec<u8>> = m
                .lookups
                .iter()
                .map(|l| (l.table.clone(), table.to_vec()))
                .collect();
            tx::resolve_lookups(&m, &tables)
                .unwrap_or_else(|e| panic!("{name}: a 256-entry table does not resolve it: {e:?}"));
        }
        largest = largest.max(entries.len());
    }
    assert_eq!(largest, 256, "no seed holds a table of 256 entries");
}

#[cfg(feature = "rpc")]
#[test]
fn an_rpc_seed_carries_inner_instructions_in_the_form_agave_returns() {
    let all = seeds("rpc_json");
    let (_, bytes) = all
        .iter()
        .find(|(n, _)| n == "simulation-parsed-inner")
        .expect("the jsonParsed simulation seed");
    let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    simulation_result_from_value_for_test(&value).expect("the simulation parses");
    let inner = value["innerInstructions"][0]["instructions"]
        .as_array()
        .unwrap();
    let rebuilt = inner
        .iter()
        .filter(|ix| ix.get("parsed").is_some())
        .map(|ix| parsed_inner::rebuild(ix["programId"].as_str().unwrap(), &ix["parsed"]))
        .collect::<Vec<_>>();
    assert_eq!(rebuilt.len(), 2);
    assert!(rebuilt.iter().all(Option::is_some), "{rebuilt:?}");
}
