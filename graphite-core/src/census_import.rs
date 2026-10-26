//! Round 40 (bootstrap): seed `HistoricalVolume` from the committed mainnet
//! census instead of from numbers an operator types.
//!
//! A fresh Core approves nothing on the built-in profiles: the three
//! evidence-derived confidence signals read the Semantic Graph, which is
//! empty, so a manifested program's verdict sits at 0.44 against Gaming's
//! 0.55. `graphite evidence seed --battle-tested N` was the only way out, with
//! N whatever the operator typed. `protocols/battle_tested_evidence.json` is a
//! MEASURED, reproducible census of the same quantity
//! (`scripts/battle_tested_census.py`, read-only mainnet): successful
//! transactions carrying each program's address over a stated window, and the
//! share of really-observed instructions its manifest names.
//!
//! This module plans and applies `graphite evidence import-census`:
//!
//! - **Explicit.** Only an operator command reaches it (CLI-only, like
//!   `evidence seed`; `tests/round40_census_import.rs` checks the server does
//!   not reference it). A fresh Core's defaults do not change.
//! - **The census is checked first**: its schema, its stated bar against the
//!   bar this build applies, its own `meets_battle_tested` against a
//!   recomputation, and — for a file given on the command line — its SHA-256
//!   against the copy compiled into this build, so a tampered file is refused.
//! - **Only records that clear every threshold** (successful transactions,
//!   instructions observed, decode rate recomputed against the LOADED
//!   manifest — the seed loader's own gate), of a program that exists, is
//!   executable and has a loaded manifest, are imported. Everything else is
//!   skipped and listed with its reason.
//! - **P7 holds**: what is appended is EVIDENCE (`battle_tested_tx_count`),
//!   through `SemanticGraphStore::append`, which recomputes the tier.
//!   `has_signed_manifest` is never asserted: it is carried from the record in
//!   force, so a program with no signed manifest stays without one.
//! - **Never a downgrade, never lower evidence**: the appended record is the
//!   record in force with `battle_tested_tx_count` raised to the census count
//!   (every other field, the signature flag and the community count
//!   included, carried over). `compute_trust_tier` is monotone in each field,
//!   so the recomputed graph tier is never lower; a manifested program's
//!   verdict tier is `max(graph, manifest)` and so never lower either.
//! - **Idempotent**: a program whose record already holds at least the census
//!   count is skipped. A quarantined program is skipped (lifting is a
//!   separate operator decision).
//! - **Bound to the measurement's time**: the evidence is bound to the
//!   census window's oldest slot (`bind_evidence_to_slot`), and a program
//!   whose last observed deployment — or whose retired evidence's deployment
//!   — is newer than that slot is skipped ("census predates the program's
//!   last observed deployment"). An upgrade after the import withdraws the
//!   evidence as any other (Round 30, G-04).

use crate::confidence_engine::TrustTier;
use crate::manifest::{battle_tested_bar, recomputed_decode_rate, BATTLE_TESTED_EVIDENCE};
use crate::semantic_graph_store::{compute_trust_tier_for, Behavior, BehaviorEvidence};
use crate::verification::GraphiteCore;
use serde_json::Value;

/// The census file's name, as audit rows and reports cite it.
pub const CENSUS_FILE: &str = "battle_tested_evidence.json";

/// The cluster the census measures, as `--cluster` names it (Round 40).
pub const CENSUS_CLUSTER: &str = "mainnet-beta";

/// mainnet-beta's genesis hash: what an RPC's `getGenesisHash` answers on
/// the cluster the census was measured on.
pub const MAINNET_BETA_GENESIS_HASH: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";

/// The RPC the census records it was measured on. Anything else cannot be
/// placed on mainnet-beta by this build, and is refused.
pub const CENSUS_RPC: &str = "https://api.mainnet-beta.solana.com";

/// The cluster an operator names for the import (`--cluster`). The census is
/// mainnet-beta only, so that is the only accepted name; naming it is the
/// operator's statement that the Core verifies mainnet-beta, which the
/// server then checks against its RPC's genesis hash at every start.
pub fn check_cluster_arg(cluster: &str) -> Result<(), String> {
    if cluster == CENSUS_CLUSTER {
        Ok(())
    } else {
        Err(format!(
            "--cluster {cluster:?}: the census measures {CENSUS_CLUSTER} only; import it only into a Core that verifies {CENSUS_CLUSTER} (--cluster {CENSUS_CLUSTER})"
        ))
    }
}

/// A census document that passed [`Census::from_bytes`].
#[derive(Debug, Clone)]
pub struct Census {
    doc: Value,
    sha256: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// The SHA-256 of the census compiled into this build.
pub fn embedded_census_sha256() -> String {
    sha256_hex(BATTLE_TESTED_EVIDENCE.as_bytes())
}

impl Census {
    /// The census compiled into this build (`manifest::BATTLE_TESTED_EVIDENCE`),
    /// checked like any other.
    pub fn embedded() -> Result<Self, String> {
        Self::from_bytes(BATTLE_TESTED_EVIDENCE.as_bytes())
    }

    /// A census file an operator names (`--census <path>`). Checked, and then
    /// held to the copy compiled into this build byte for byte: the decode
    /// rates are recomputed against THIS build's manifests, and nothing in a
    /// file can show its raw counts were not edited — only the hash of the
    /// reviewed, committed copy can.
    pub fn from_file_bytes(bytes: &[u8]) -> Result<Self, String> {
        let census = Self::from_bytes(bytes)?;
        let expected = embedded_census_sha256();
        if census.sha256 != expected {
            return Err(format!(
                "the census file's sha256 is {}, but this build was compiled with the census whose sha256 is {expected}; \
                 an edited or foreign census is refused (import the compiled-in copy by omitting --census)",
                census.sha256
            ));
        }
        Ok(census)
    }

    /// Parse and check a census document (schema, bar, self-consistency).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let doc: Value = serde_json::from_slice(bytes)
            .map_err(|e| format!("the census is not valid JSON: {e}"))?;
        let problems = verify_census_document(&doc);
        if !problems.is_empty() {
            return Err(format!(
                "the census does not pass its checks ({} problem(s)): {}",
                problems.len(),
                problems.join("; ")
            ));
        }
        Ok(Census {
            doc,
            sha256: sha256_hex(bytes),
        })
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn records(&self) -> &[Value] {
        self.doc["programs"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// Every way `doc` departs from the census schema and from the bar this build
/// applies. Empty when it passes.
///
/// The checks are those `tests/battle_tested_evidence.rs` makes of the
/// committed file that can be made without the manifests (shape, thresholds,
/// a time and a window per record, unique ids), plus the one that ties a
/// record's own verdict to its measurements: `meets_battle_tested` must be
/// what the measurements give against the file's thresholds. The decode rate
/// itself is recomputed against the loaded manifest when a record is planned.
pub fn verify_census_document(doc: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(top) = doc.as_object() else {
        return vec!["the census is not a JSON object".to_string()];
    };
    for k in top.keys() {
        if !["note", "rpc", "thresholds", "programs"].contains(&k.as_str()) {
            problems.push(format!("unknown top-level field {k:?}"));
        }
    }
    if doc["rpc"].as_str() != Some(CENSUS_RPC) {
        problems.push(format!(
            "the census says it was measured on {}, not {CENSUS_RPC}: this build cannot place it on {CENSUS_CLUSTER}",
            doc["rpc"]
        ));
    }
    let t = &doc["thresholds"];
    if t["min_successful_transactions"].as_u64()
        != Some(battle_tested_bar::MIN_SUCCESSFUL_TRANSACTIONS)
        || t["min_decoded_instructions"].as_u64()
            != Some(battle_tested_bar::MIN_DECODED_INSTRUCTIONS)
        || t["min_decode_rate"].as_f64() != Some(battle_tested_bar::MIN_DECODE_RATE)
    {
        problems.push(format!(
            "the census states the bar {t}, not the bar this build applies ({} successful transactions, {} instructions observed, decode rate {})",
            battle_tested_bar::MIN_SUCCESSFUL_TRANSACTIONS,
            battle_tested_bar::MIN_DECODED_INSTRUCTIONS,
            battle_tested_bar::MIN_DECODE_RATE
        ));
    }
    let Some(records) = doc["programs"].as_array() else {
        problems.push("`programs` is not an array".to_string());
        return problems;
    };
    let mut seen = std::collections::BTreeSet::new();
    for (i, p) in records.iter().enumerate() {
        let id = p["program_id"].as_str().unwrap_or("");
        let at = |what: &str| format!("record {i} ({id}): {what}");
        if crate::solana_types::Pubkey::from_base58(id).is_err() {
            problems.push(at("program_id is not a base58 32-byte key"));
        }
        if !seen.insert(id.to_string()) {
            problems.push(at("a second record for this program"));
        }
        for (field, ok) in [
            ("manifest", p["manifest"].is_string()),
            ("name", p["name"].is_string()),
            (
                "measured_at_unix",
                p["measured_at_unix"].as_u64().is_some_and(|t| t > 0),
            ),
            ("identity.exists", p["identity"]["exists"].is_boolean()),
            (
                "identity.executable",
                p["identity"]["executable"].is_boolean(),
            ),
            (
                "volume.successful_transactions_counted",
                p["volume"]["successful_transactions_counted"].is_u64(),
            ),
            (
                "volume.window_seconds",
                p["volume"]["window_seconds"].is_u64(),
            ),
            (
                "decode.instructions_observed",
                p["decode"]["instructions_observed"].is_u64(),
            ),
            (
                "decode.decode_rate",
                p["decode"]["decode_rate"].is_null()
                    || p["decode"]["decode_rate"]
                        .as_f64()
                        .is_some_and(|r| (0.0..=1.0).contains(&r)),
            ),
            ("meets_battle_tested", p["meets_battle_tested"].is_boolean()),
        ] {
            if !ok {
                problems.push(at(&format!("{field} is missing or malformed")));
            }
        }
        match (
            p["volume"]["oldest_slot"].as_u64(),
            p["volume"]["newest_slot"].as_u64(),
        ) {
            (Some(o), Some(n)) if o <= n => {}
            _ => problems.push(at(
                "volume.oldest_slot / newest_slot are missing or out of order (the measurement cannot be dated)",
            )),
        }
        let observed = p["decode"]["instructions_observed"].as_u64().unwrap_or(0);
        let meets = p["identity"]["executable"].as_bool() == Some(true)
            && p["volume"]["successful_transactions_counted"]
                .as_u64()
                .unwrap_or(0)
                >= t["min_successful_transactions"]
                    .as_u64()
                    .unwrap_or(u64::MAX)
            && observed >= t["min_decoded_instructions"].as_u64().unwrap_or(u64::MAX)
            && p["decode"]["decode_rate"]
                .as_f64()
                .is_some_and(|r| r >= t["min_decode_rate"].as_f64().unwrap_or(f64::INFINITY));
        if p["meets_battle_tested"]
            .as_bool()
            .is_some_and(|m| m != meets)
        {
            problems.push(at(&format!(
                "meets_battle_tested says {}, its measurements give {meets}",
                p["meets_battle_tested"]
            )));
        }
    }
    problems
}

/// What a verdict on a program alone carries (see
/// `GraphiteCore::standalone_standing`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Standing {
    pub verdict_tier: TrustTier,
    pub confidence: f64,
}

/// One record the import would append.
#[derive(Debug, Clone)]
pub struct PlannedImport {
    pub program_id: String,
    pub name: String,
    pub census_transactions: u64,
    pub window_seconds: u64,
    pub oldest_slot: u64,
    pub newest_slot: u64,
    pub measured_at_unix: u64,
    /// `battle_tested_tx_count` in force before (0: no record).
    pub previous_volume: u64,
    /// The graph tier the record in force carries (`None`: no record).
    pub previous_graph_tier: Option<TrustTier>,
    /// The graph tier the appended record recomputes to.
    pub graph_tier: TrustTier,
    pub before: Standing,
    pub after: Standing,
    /// The record to append (tier recomputed by `append`, P7).
    pub behavior: Behavior,
}

/// One record the import leaves alone, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub program_id: String,
    pub name: String,
    pub reason: String,
}

/// The import of one census into one Core, before anything is written.
#[derive(Debug, Clone)]
pub struct ImportPlan {
    pub census_sha256: String,
    pub imports: Vec<PlannedImport>,
    pub skipped: Vec<Skipped>,
    /// Records outside `--program` (not considered).
    pub not_selected: usize,
}

/// The reason text for a record whose measurement is older than the code.
pub const STALE_DEPLOYMENT: &str = "census predates the program's last observed deployment";

/// Plan the import of `census` into `core`. Reads; writes nothing.
///
/// `only` restricts the plan to these program ids (`--program`); an id the
/// census has no record for is an error, so a typo is not a silent no-op.
pub fn plan(core: &GraphiteCore, census: &Census, only: &[String]) -> Result<ImportPlan, String> {
    for id in only {
        if !census
            .records()
            .iter()
            .any(|p| p["program_id"].as_str() == Some(id.as_str()))
        {
            return Err(format!("--program {id}: the census has no record for it"));
        }
    }
    let retired = core.retired_evidence();
    let mut out = ImportPlan {
        census_sha256: census.sha256().to_string(),
        imports: Vec::new(),
        skipped: Vec::new(),
        not_selected: 0,
    };
    for p in census.records() {
        let id = p["program_id"].as_str().unwrap_or_default().to_string();
        if !only.is_empty() && !only.contains(&id) {
            out.not_selected += 1;
            continue;
        }
        let name = p["name"].as_str().unwrap_or_default().to_string();
        let skip = |reason: String| Skipped {
            program_id: id.clone(),
            name: name.clone(),
            reason,
        };
        match plan_one(core, p, &id, &name, &retired) {
            Ok(planned) => out.imports.push(planned),
            Err(reason) => out.skipped.push(skip(reason)),
        }
    }
    Ok(out)
}

fn plan_one(
    core: &GraphiteCore,
    p: &Value,
    id: &str,
    name: &str,
    retired: &[crate::semantic_graph_store::RetiredEvidence],
) -> Result<PlannedImport, String> {
    let Some(manifest) = core.registry().get(id) else {
        return Err("no loaded manifest for this program".to_string());
    };
    if p["identity"]["exists"].as_bool() != Some(true) {
        return Err(
            "the census found no account at this address (identity.exists is false)".into(),
        );
    }
    if p["identity"]["executable"].as_bool() != Some(true) {
        return Err("the census found the account not executable".into());
    }
    let txs = p["volume"]["successful_transactions_counted"]
        .as_u64()
        .unwrap_or(0);
    let observed = p["decode"]["instructions_observed"].as_u64().unwrap_or(0);
    let rate = recomputed_decode_rate(p, manifest);
    let mut short = Vec::new();
    if txs < battle_tested_bar::MIN_SUCCESSFUL_TRANSACTIONS {
        short.push(format!(
            "{txs} successful transactions, below {}",
            battle_tested_bar::MIN_SUCCESSFUL_TRANSACTIONS
        ));
    }
    if observed < battle_tested_bar::MIN_DECODED_INSTRUCTIONS {
        short.push(format!(
            "{observed} instructions observed, below {}",
            battle_tested_bar::MIN_DECODED_INSTRUCTIONS
        ));
    }
    match rate {
        None => short.push(
            "no decode rate (nothing observed, or the manifest has no discriminator to decode by)"
                .to_string(),
        ),
        Some(r) if r < battle_tested_bar::MIN_DECODE_RATE => short.push(format!(
            "decode rate {r:.3} (recomputed against the loaded manifest), below {}",
            battle_tested_bar::MIN_DECODE_RATE
        )),
        Some(_) => {}
    }
    if !short.is_empty() {
        return Err(format!("below the bar: {}", short.join("; ")));
    }

    let oldest_slot = p["volume"]["oldest_slot"].as_u64().unwrap_or(0);
    let newest_slot = p["volume"]["newest_slot"].as_u64().unwrap_or(0);
    if let Some(d) = core.observed_deployment(id) {
        if d.deploy_slot > oldest_slot {
            return Err(format!(
                "{STALE_DEPLOYMENT} (deployed at slot {}; the census window began at slot {oldest_slot})",
                d.deploy_slot
            ));
        }
    }
    if let Some(r) = retired
        .iter()
        .rev()
        .find(|r| r.program_id == id && r.deployment.deploy_slot > oldest_slot)
    {
        return Err(format!(
            "{STALE_DEPLOYMENT} (its evidence was retired for a deployment at slot {}, after the census window began at slot {oldest_slot}: {})",
            r.deployment.deploy_slot, r.reason
        ));
    }

    let current = core.program_behavior(id);
    if let Some(b) = current.as_ref().filter(|b| b.quarantined) {
        return Err(format!(
            "quarantined ({}); lift the quarantine first, deliberately",
            b.quarantine_reason
                .as_deref()
                .unwrap_or("no reason recorded")
        ));
    }
    let previous_volume = current
        .as_ref()
        .map(|b| b.evidence.battle_tested_tx_count)
        .unwrap_or(0);
    if previous_volume >= txs {
        return Err(format!(
            "the graph already holds at least this evidence (battle_tested {previous_volume} >= census {txs})"
        ));
    }

    // The record in force with the volume raised, every other field carried
    // over: the signature flag, the community count and the simulation
    // count are never lowered, and none is asserted.
    let evidence = BehaviorEvidence {
        battle_tested_tx_count: txs,
        ..current
            .as_ref()
            .map(|b| b.evidence.clone())
            .unwrap_or_default()
    };
    // Round 40 (R39-CORE-IDENTITY-7): computed as `append` will compute it,
    // with the record's first-manifest cap (carried over below), so the plan
    // shows the tier the import will produce.
    let graph_tier = compute_trust_tier_for(
        &evidence,
        current
            .as_ref()
            .is_some_and(|b| b.first_manifest_unvalidated),
    );
    let behavior = match current.as_ref() {
        Some(b) => Behavior {
            evidence,
            trust_tier: graph_tier,
            ..b.clone()
        },
        None => Behavior {
            program_id: id.to_string(),
            version: manifest.version.label.clone(),
            expected_state_changes: vec![],
            allowed_cpis: vec![],
            trust_tier: graph_tier,
            evidence,
            quarantined: false,
            quarantine_reason: None,
            first_manifest_unvalidated: false,
        },
    };
    let standing = |record: Option<&Behavior>| {
        let (verdict_tier, confidence) = core.standalone_standing(id, record);
        Standing {
            verdict_tier,
            confidence,
        }
    };
    let before = standing(None);
    let after = standing(Some(&behavior));
    Ok(PlannedImport {
        program_id: id.to_string(),
        name: name.to_string(),
        census_transactions: txs,
        window_seconds: p["volume"]["window_seconds"].as_u64().unwrap_or(0),
        oldest_slot,
        newest_slot,
        measured_at_unix: p["measured_at_unix"].as_u64().unwrap_or(0),
        previous_volume,
        previous_graph_tier: current.as_ref().map(|b| b.trust_tier),
        graph_tier,
        before,
        after,
        behavior,
    })
}

/// A UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`) for a unix time.
pub fn utc(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let rem = unix % 86_400;
    let (h, min, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mon = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mon <= 2 { y + 1 } else { y };
    format!("{y:04}-{mon:02}-{d:02}T{h:02}:{min:02}:{s:02}Z")
}

/// The audit-row detail for one import: names the source, its hash and the
/// time of the measurement.
pub fn audit_detail(census_sha256: &str, i: &PlannedImport) -> String {
    format!(
        "evidence imported for {} (census-measured, {CENSUS_FILE} sha256={census_sha256}, measured_at {} [unix {}]): \
         battle_tested {} -> {} (successful transactions over {}s, slots {}..{}); evidence bound to slot {}; \
         graph tier recomputed to {:?}; verdict tier {:?}, standalone confidence {:.4} -> {:.4}",
        i.program_id,
        utc(i.measured_at_unix),
        i.measured_at_unix,
        i.previous_volume,
        i.census_transactions,
        i.window_seconds,
        i.oldest_slot,
        i.newest_slot,
        i.oldest_slot,
        i.graph_tier,
        i.after.verdict_tier,
        i.before.confidence,
        i.after.confidence
    )
}

/// Apply one planned import: append the record (tier recomputed, P7) and
/// bind the evidence to the census window's oldest slot; the graph records
/// that its imported evidence is mainnet-beta's (`MAINNET_BETA_GENESIS_HASH`).
/// `Ok(Err(_))`: in force in this process but not on disk.
pub fn apply(core: &mut GraphiteCore, i: &PlannedImport) -> Result<Result<(), String>, String> {
    core.import_measured_evidence(i.behavior.clone(), i.oldest_slot, MAINNET_BETA_GENESIS_HASH)
        .map_err(|e| format!("{}: {e}", i.program_id))
}

/// Plan and apply the embedded census to an in-memory core, with no audit
/// trail — for tests and embedders that hold no data directory. The CLI
/// (`graphite evidence import-census`) records every import on the trail.
pub fn import_embedded_into(core: &mut GraphiteCore) -> Result<ImportPlan, String> {
    let census = Census::embedded()?;
    let plan = plan(core, &census, &[])?;
    for i in &plan.imports {
        apply(core, i)?.ok();
    }
    Ok(plan)
}
