//! Round 40 (bootstrap): `graphite evidence import-census` — the plan and the
//! append behind it (`census_import`), without the CLI.
//!
//! - The census is checked before anything is planned: its schema, the bar it
//!   states, its own verdicts, and (for a file) its hash against the copy
//!   compiled into this build.
//! - Only records that clear every threshold, of an existing, executable
//!   program with a loaded manifest, are imported; everything else is
//!   skipped with its reason.
//! - What is appended is evidence; the tier is recomputed (P7); nothing is
//!   lowered, no signature is asserted, a quarantine is not touched.
//! - The import is bound to the census's time: a program whose observed
//!   deployment is newer than the census window is not imported, and an
//!   upgrade after the import withdraws the evidence (the upgrade watch,
//!   `tests/rm1_program_upgrade_detection.rs`) and a re-import does not
//!   bring it back.
//!
//! Every RPC here is a loopback mock.

use graphite_core::census_import::{self as ci, Census};
use graphite_core::confidence_engine::TrustTier;
use graphite_core::manifest::{battle_tested_bar, battle_tested_programs, BATTLE_TESTED_EVIDENCE};
use graphite_core::semantic_graph_store::{Behavior, BehaviorEvidence};
use graphite_core::verification::GraphiteCore;

const SYSTEM: &str = "11111111111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const JUPITER: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const WHIRLPOOL: &str = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";
const CLMM: &str = "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK";
const DLMM: &str = "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo";
const BUBBLEGUM: &str = "BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY";
const MARGINFI: &str = "MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA";
const SWITCHBOARD: &str = "SW1TCH7qEPTdLsDHRgPuMQjbQxKdH2aBStViMFnt64f";

fn doc() -> serde_json::Value {
    serde_json::from_str(BATTLE_TESTED_EVIDENCE).unwrap()
}

fn record_of(id: &str) -> serde_json::Value {
    doc()["programs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["program_id"] == id)
        .cloned()
        .unwrap()
}

fn plan(core: &GraphiteCore) -> ci::ImportPlan {
    ci::plan(core, &Census::embedded().unwrap(), &[]).unwrap()
}

fn skip_reason(plan: &ci::ImportPlan, id: &str) -> String {
    plan.skipped
        .iter()
        .find(|s| s.program_id == id)
        .map(|s| s.reason.clone())
        .unwrap_or_else(|| panic!("{id} was not skipped"))
}

// ─── The census is checked first ───────────────────────────────────────────

#[test]
fn the_committed_census_passes_its_checks_and_its_file_is_the_compiled_in_copy() {
    let embedded = Census::embedded().expect("the compiled-in census passes");
    assert_eq!(embedded.sha256(), ci::embedded_census_sha256());
    assert_eq!(embedded.records().len(), 137);
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/protocols/battle_tested_evidence.json"
    );
    let file = Census::from_file_bytes(&std::fs::read(path).unwrap())
        .expect("the committed file is the compiled-in copy");
    assert_eq!(file.sha256(), embedded.sha256());
}

#[test]
fn a_tampered_census_file_is_refused() {
    // A raw count edited: the record's own verdict then contradicts its
    // measurements, which the schema check sees.
    let mut d = doc();
    let marginfi = d["programs"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p["program_id"] == MARGINFI)
        .unwrap();
    marginfi["volume"]["successful_transactions_counted"] = 50_000.into();
    let e = Census::from_file_bytes(&serde_json::to_vec_pretty(&d).unwrap()).unwrap_err();
    assert!(e.contains("meets_battle_tested says false"), "{e}");
    // Edited consistently (the verdict flipped too): nothing in the file can
    // show it any more; the hash of the reviewed copy can.
    let marginfi = d["programs"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p["program_id"] == MARGINFI)
        .unwrap();
    marginfi["meets_battle_tested"] = true.into();
    let e = Census::from_file_bytes(&serde_json::to_vec_pretty(&d).unwrap()).unwrap_err();
    assert!(e.contains("sha256"), "{e}");

    // The same bytes re-serialised (a whitespace change) are not the copy
    // either: the file is held to the reviewed bytes.
    let e = Census::from_file_bytes(&serde_json::to_vec(&doc()).unwrap()).unwrap_err();
    assert!(e.contains("sha256"), "{e}");

    // Schema: a lowered bar, a duplicate record, a record that cannot be
    // dated, a verdict field that its measurements contradict, a stray
    // top-level field — each refused before any hash comparison.
    for (why, edit) in [
        (
            "states the bar",
            Box::new(|d: &mut serde_json::Value| {
                d["thresholds"]["min_successful_transactions"] = 10.into();
            }) as Box<dyn Fn(&mut serde_json::Value)>,
        ),
        (
            "a second record",
            Box::new(|d: &mut serde_json::Value| {
                let first = d["programs"][0].clone();
                d["programs"].as_array_mut().unwrap().push(first);
            }),
        ),
        (
            "cannot be dated",
            Box::new(|d: &mut serde_json::Value| {
                d["programs"][0]["volume"]
                    .as_object_mut()
                    .unwrap()
                    .remove("oldest_slot");
            }),
        ),
        (
            "meets_battle_tested",
            Box::new(|d: &mut serde_json::Value| {
                let r = d["programs"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|p| p["program_id"] == MARGINFI)
                    .unwrap();
                r["meets_battle_tested"] = true.into();
            }),
        ),
        (
            "unknown top-level field",
            Box::new(|d: &mut serde_json::Value| {
                d["extra"] = 1.into();
            }),
        ),
    ] {
        let mut d = doc();
        edit(&mut d);
        let e = Census::from_bytes(&serde_json::to_vec(&d).unwrap()).unwrap_err();
        assert!(e.contains(why), "{why}: {e}");
    }
}

// ─── Only what clears every threshold ──────────────────────────────────────

/// Every planned import clears every threshold in the file (checked here
/// from the raw record, not through the module), and the planned set is
/// exactly the set the seed loader's own gate admits. A deliberate break
/// that drops the filter imports Marginfi (503 transactions), Bubblegum
/// (decode 0.057) and Switchboard (0 observed), and fails here.
#[test]
fn only_records_that_clear_every_threshold_are_planned() {
    let core = GraphiteCore::new();
    let plan = plan(&core);
    let t = &doc()["thresholds"];
    let registry = graphite_core::manifest::load_seed_manifests();
    for i in &plan.imports {
        let r = record_of(&i.program_id);
        let m = registry.get(&i.program_id).expect("a loaded manifest");
        let rate = graphite_core::manifest::recomputed_decode_rate(&r, m).unwrap_or(-1.0);
        assert!(
            r["identity"]["exists"] == true
                && r["identity"]["executable"] == true
                && r["volume"]["successful_transactions_counted"]
                    .as_u64()
                    .unwrap()
                    >= t["min_successful_transactions"].as_u64().unwrap()
                && r["decode"]["instructions_observed"].as_u64().unwrap()
                    >= t["min_decoded_instructions"].as_u64().unwrap()
                && rate >= t["min_decode_rate"].as_f64().unwrap(),
            "{} ({}) was planned below the bar",
            i.program_id,
            i.name
        );
        assert_eq!(
            i.census_transactions,
            r["volume"]["successful_transactions_counted"]
                .as_u64()
                .unwrap()
        );
    }
    let planned: std::collections::BTreeSet<String> =
        plan.imports.iter().map(|i| i.program_id.clone()).collect();
    assert_eq!(
        planned,
        battle_tested_programs(),
        "the import must admit exactly what the seed loader's gate admits"
    );
    assert_eq!(plan.imports.len(), 114);
    assert_eq!(plan.imports.len() + plan.skipped.len(), 137);
    assert!(plan.skipped.iter().all(|s| !s.reason.is_empty()));
    assert!(skip_reason(&plan, MARGINFI).contains("503 successful transactions, below 1000"));
    assert!(skip_reason(&plan, BUBBLEGUM).contains("decode rate 0.057"));
    assert!(skip_reason(&plan, SWITCHBOARD).contains("0 instructions observed, below 20"));
    // The thresholds are the bar this build applies.
    assert_eq!(
        t["min_successful_transactions"].as_u64(),
        Some(battle_tested_bar::MIN_SUCCESSFUL_TRANSACTIONS)
    );
}

#[test]
fn a_program_filter_names_records_the_census_has() {
    let core = GraphiteCore::new();
    let census = Census::embedded().unwrap();
    let only = ci::plan(&core, &census, &[SYSTEM.to_string()]).unwrap();
    assert_eq!(only.imports.len(), 1);
    assert_eq!(only.not_selected, 136);
    let e = ci::plan(
        &core,
        &census,
        &["9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7".to_string()],
    )
    .unwrap_err();
    assert!(e.contains("no record"), "{e}");
}

// ─── What an import changes, and what it does not ──────────────────────────

/// The per-program table the report carries: before and after the import,
/// for a program alone (L5 passed, no penalty, no sibling).
#[test]
fn the_standing_of_the_reported_programs_before_and_after_the_import() {
    let mut core = GraphiteCore::new();
    let before: Vec<(TrustTier, f64)> = [SYSTEM, TOKEN, JUPITER, WHIRLPOOL, CLMM, DLMM]
        .iter()
        .map(|p| core.standalone_standing(p, None))
        .collect();
    let plan = ci::import_embedded_into(&mut core).unwrap();
    eprintln!("| program | census txs | graph tier | verdict tier | confidence before | after |");
    for (p, (tier0, conf0)) in [SYSTEM, TOKEN, JUPITER, WHIRLPOOL, CLMM, DLMM]
        .iter()
        .zip(before)
    {
        let (tier, conf) = core.standalone_standing(p, None);
        let b = core.program_behavior(p).unwrap();
        let planned = plan.imports.iter().find(|i| i.program_id == *p).unwrap();
        eprintln!(
            "| {p} | {} | {:?} | {tier:?} | {conf0:.4} | {conf:.4} |",
            b.evidence.battle_tested_tx_count, b.trust_tier
        );
        assert_eq!(tier0, TrustTier::OfficialManifest, "{p}");
        assert!((conf0 - 0.44).abs() < 1e-9, "{p}: {conf0}");
        assert_eq!(tier, TrustTier::OfficialManifest, "{p}: the verdict tier");
        assert_eq!(
            b.trust_tier,
            TrustTier::HeuristicInferred,
            "{p}: graph tier"
        );
        assert!(
            !b.evidence.has_signed_manifest,
            "{p}: no signature asserted"
        );
        assert!((conf - 0.59).abs() < 1e-9, "{p}: {conf}");
        assert_eq!(planned.after.confidence, conf);
        assert_eq!(planned.before.confidence, conf0);
        assert_eq!(
            core.evidence_since_slot(p),
            record_of(p)["volume"]["oldest_slot"].as_u64(),
            "{p}: bound to the census window"
        );
    }
}

fn seeded(core: &mut GraphiteCore, program: &str, evidence: BehaviorEvidence) {
    core.seed_behavior(Behavior {
        program_id: program.to_string(),
        version: "prior".to_string(),
        expected_state_changes: vec!["kept".to_string()],
        allowed_cpis: vec![],
        trust_tier: TrustTier::Unknown,
        evidence,
        quarantined: false,
        quarantine_reason: None,
        first_manifest_unvalidated: false,
    })
    .unwrap();
}

/// A program's record in force is never lowered: the volume is raised and
/// every other field is carried, so a tier the graph had earned stays (and
/// a record with `has_signed_manifest: false` appended over a
/// SimulationValidated one — which would recompute to HeuristicInferred —
/// is never what the import appends).
#[test]
fn an_import_never_lowers_a_programs_evidence_or_tier() {
    let mut core = GraphiteCore::new();
    seeded(
        &mut core,
        SYSTEM,
        BehaviorEvidence {
            simulation_match_count: 5,
            ..Default::default()
        },
    );
    seeded(
        &mut core,
        TOKEN,
        BehaviorEvidence {
            battle_tested_tx_count: 50_000,
            ..Default::default()
        },
    );
    seeded(
        &mut core,
        JUPITER,
        BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 1,
            battle_tested_tx_count: 10,
            ..Default::default()
        },
    );
    let before: Vec<_> = [SYSTEM, TOKEN, JUPITER]
        .iter()
        .map(|p| {
            (
                core.program_behavior(p).unwrap(),
                core.standalone_standing(p, None),
            )
        })
        .collect();
    let plan = ci::import_embedded_into(&mut core).unwrap();
    assert!(skip_reason(&plan, TOKEN).contains("already holds at least this evidence"));

    for (p, (b0, (tier0, conf0))) in [SYSTEM, TOKEN, JUPITER].iter().zip(before) {
        let b = core.program_behavior(p).unwrap();
        let (tier, conf) = core.standalone_standing(p, None);
        assert!(b.trust_tier >= b0.trust_tier, "{p}: graph tier lowered");
        assert!(
            tier >= tier0 && conf >= conf0,
            "{p}: verdict standing lowered"
        );
        assert_eq!(
            b.evidence.has_signed_manifest,
            b0.evidence.has_signed_manifest
        );
        assert!(b.evidence.community_verified_count >= b0.evidence.community_verified_count);
        assert!(b.evidence.simulation_match_count >= b0.evidence.simulation_match_count);
        assert!(b.evidence.battle_tested_tx_count >= b0.evidence.battle_tested_tx_count);
        assert_eq!(
            b.version, "prior",
            "{p}: the record's other fields are carried"
        );
        assert_eq!(b.expected_state_changes, vec!["kept".to_string()]);
    }
    let system = core.program_behavior(SYSTEM).unwrap();
    assert_eq!(system.trust_tier, TrustTier::SimulationValidated);
    assert_eq!(system.evidence.battle_tested_tx_count, 1456);
    // A signed manifest the graph already held, plus measured volume, is
    // what compute_trust_tier calls BattleTested: the signature is the
    // record's own, not one the import asserted.
    let jupiter = core.program_behavior(JUPITER).unwrap();
    assert_eq!(jupiter.trust_tier, TrustTier::BattleTested);
    assert_eq!(
        core.program_behavior(TOKEN)
            .unwrap()
            .evidence
            .battle_tested_tx_count,
        50_000
    );
}

#[test]
fn an_import_is_idempotent_and_leaves_a_quarantine_alone() {
    let mut core = GraphiteCore::new();
    core.quarantine_program(WHIRLPOOL, "GHSA-test").unwrap();
    let first = ci::import_embedded_into(&mut core).unwrap();
    assert_eq!(first.imports.len(), 113);
    assert!(skip_reason(&first, WHIRLPOOL).starts_with("quarantined (GHSA-test)"));
    assert!(core.program_behavior(WHIRLPOOL).unwrap().quarantined);
    let history: usize = [SYSTEM, TOKEN]
        .iter()
        .map(|p| core.behavior_history(p).len())
        .sum();
    let again = ci::import_embedded_into(&mut core).unwrap();
    assert!(again.imports.is_empty(), "a re-run imports nothing");
    assert_eq!(
        again
            .skipped
            .iter()
            .filter(|s| s.reason.contains("already holds"))
            .count(),
        113
    );
    let after: usize = [SYSTEM, TOKEN]
        .iter()
        .map(|p| core.behavior_history(p).len())
        .sum();
    assert_eq!(history, after, "a re-run appends nothing");
}

/// The import is an operator command: the HTTP surface does not reach it.
#[test]
fn the_server_does_not_reach_the_import() {
    let server =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/server.rs")).unwrap();
    for needle in [
        "census_import",
        "import_measured_evidence",
        "bind_evidence_to_slot",
    ] {
        assert!(!server.contains(needle), "src/server.rs names {needle}");
    }
}

// ─── An upgrade withdraws it, and a re-import does not bring it back ───────

#[cfg(feature = "rpc")]
mod upgrades {
    use super::*;
    use base64::Engine as _;
    use graphite_core::census_import::STALE_DEPLOYMENT;
    use graphite_core::manifest::load_seed_manifests;
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient, UPGRADEABLE_LOADER};
    use graphite_core::verification::{ExecutionDecision, ProposedIntent, VerificationInput};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    fn key(byte: u8) -> String {
        bs58::encode([byte; 32]).into_string()
    }

    /// The upgradeable loader's view of Whirlpool (as in
    /// `rm1_program_upgrade_detection.rs`): its program account points at
    /// ProgramData `key(0x44)`, whose header carries the deploy slot.
    fn serve(deploy_slot: Arc<AtomicU64>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                let deploy_slot = deploy_slot.clone();
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 1 << 16];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let body: serde_json::Value = req
                        .split("\r\n\r\n")
                        .nth(1)
                        .and_then(|b| serde_json::from_str(b).ok())
                        .unwrap_or_default();
                    let answer = if body["method"] != "getMultipleAccounts" {
                        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"not mocked"}}"#
                            .to_string()
                    } else {
                        let b64 = |b: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(b);
                        let sliced = body["params"][1]["dataSlice"]["length"].is_u64();
                        let values: Vec<serde_json::Value> = body["params"][0]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|a| {
                                let a = a.as_str().unwrap();
                                let data = if !sliced {
                                    return serde_json::Value::Null;
                                } else if a == WHIRLPOOL {
                                    let mut d = 2u32.to_le_bytes().to_vec();
                                    d.extend([0x44u8; 32]);
                                    d
                                } else if a == key(0x44) {
                                    let mut d = 3u32.to_le_bytes().to_vec();
                                    d.extend(deploy_slot.load(Ordering::SeqCst).to_le_bytes());
                                    d.push(1);
                                    d.extend([0x51u8; 32]);
                                    d
                                } else {
                                    return serde_json::Value::Null;
                                };
                                serde_json::json!({
                                    "lamports": 1_141_440,
                                    "owner": UPGRADEABLE_LOADER,
                                    "data": [b64(data), "base64"],
                                    "executable": a == WHIRLPOOL,
                                    "rentEpoch": 0,
                                })
                            })
                            .collect();
                        serde_json::json!({"jsonrpc": "2.0", "id": 1,
                            "result": {"context": {"slot": 1}, "value": values}})
                        .to_string()
                    };
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                        answer.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                });
            }
        });
        format!("http://{addr}")
    }

    fn input() -> VerificationInput {
        let ix = load_seed_manifests()
            .get(WHIRLPOOL)
            .unwrap()
            .instructions
            .iter()
            .find(|i| i.name == "swap")
            .unwrap()
            .clone();
        let mut data = hex::decode(&ix.discriminator).unwrap();
        data.extend([0u8; 32]);
        VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "swap".to_string(),
                raw_natural_language: "swap".to_string(),
                confidence_of_parse: 1.0,
                extracted_parameters: None,
            },
            program_id: WHIRLPOOL.to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: ix.discriminator.clone(),
            account_addresses: (0..ix.accounts.len())
                .map(|i| key(0x60 + i as u8))
                .collect(),
            instruction_data: Some(data),
            cpi_targets: vec![],
            wallet_profile: WalletProfile::Gaming,
            behavior_evidence: Default::default(),
            compute_units: 0,
            account_writes: 0,
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

    fn census_slot() -> u64 {
        record_of(WHIRLPOOL)["volume"]["oldest_slot"]
            .as_u64()
            .unwrap()
    }

    /// The census's own count for the program (Round 41: read from the
    /// record, so a re-measured census does not need this test edited; the
    /// import must carry exactly this figure).
    fn census_count() -> u64 {
        record_of(WHIRLPOOL)["volume"]["successful_transactions_counted"]
            .as_u64()
            .unwrap()
    }

    fn imported_core(deploy_slot: &Arc<AtomicU64>) -> GraphiteCore {
        let mut core = GraphiteCore::new();
        ci::import_embedded_into(&mut core).unwrap();
        assert_eq!(
            core.program_behavior(WHIRLPOOL)
                .unwrap()
                .evidence
                .battle_tested_tx_count,
            census_count()
        );
        core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
            endpoint: serve(deploy_slot.clone()),
            timeout: std::time::Duration::from_secs(5),
            max_retries: 0,
            ..Default::default()
        }));
        core
    }

    fn volume(core: &GraphiteCore) -> u64 {
        core.program_behavior(WHIRLPOOL)
            .unwrap()
            .evidence
            .battle_tested_tx_count
    }

    /// Imported, then upgraded: the upgrade withdraws the volume, a re-run
    /// of the import skips the program ("census predates the program's last
    /// observed deployment"), and its verdict is back at 0.44, refused by
    /// Gaming — not executable.
    #[tokio::test]
    async fn an_upgrade_after_the_import_withdraws_it_and_a_reimport_does_not_restore_it() {
        let slot = Arc::new(AtomicU64::new(census_slot() - 1_000_000));
        let mut core = imported_core(&slot);
        let kept = core.verify_async(&input()).await.unwrap();
        assert_eq!(
            volume(&core),
            census_count(),
            "an older deployment keeps the import"
        );

        slot.store(census_slot() + 1_000_000, Ordering::SeqCst);
        let r = core.verify_async(&input()).await.unwrap();
        assert_eq!(r.program_upgrades.len(), 1, "the upgrade is noticed");
        assert_eq!(
            volume(&core),
            0,
            "the upgrade withdraws the imported volume"
        );
        assert_ne!(r.decision, ExecutionDecision::ExecutableApproved);

        let again = ci::import_embedded_into(&mut core).unwrap();
        let reason = skip_reason(&again, WHIRLPOOL);
        assert!(reason.starts_with(STALE_DEPLOYMENT), "{reason}");
        assert!(
            again.imports.is_empty(),
            "nothing else is re-imported either"
        );
        assert_eq!(volume(&core), 0);
        let r = core.verify_async(&input()).await.unwrap();
        assert!(
            (kept.confidence - r.confidence - 0.15).abs() < 1e-9,
            "the HistoricalVolume signal is gone: {} -> {}",
            kept.confidence,
            r.confidence
        );
        assert!(
            r.confidence < graphite_core::policy_engine::WEAKEST_BUILTIN_MIN_CONFIDENCE,
            "{}",
            r.confidence
        );
        assert_ne!(r.decision, ExecutionDecision::ExecutableApproved);
        assert!(!r.approved, "Gaming refuses it");
    }

    /// Imported, then the FIRST read of the deployment shows code newer than
    /// the census: the evidence is withdrawn at once, because the import
    /// bound it to the census window (without that binding a first sighting
    /// keeps evidence it cannot date). A re-run skips it.
    #[tokio::test]
    async fn a_first_sighting_newer_than_the_census_withdraws_the_import() {
        let slot = Arc::new(AtomicU64::new(census_slot() + 1));
        let mut core = imported_core(&slot);
        let r = core.verify_async(&input()).await.unwrap();
        assert_eq!(volume(&core), 0, "withdrawn on the first sighting");
        assert!(
            r.summary.contains("ProgramEvidenceWithdrawn"),
            "{}",
            r.summary
        );
        let again = ci::import_embedded_into(&mut core).unwrap();
        assert!(skip_reason(&again, WHIRLPOOL).starts_with(STALE_DEPLOYMENT));
        assert_eq!(volume(&core), 0);
    }

    /// An import into a Core that already observed a deployment newer than
    /// the census does not happen at all.
    #[tokio::test]
    async fn a_program_deployed_after_the_census_is_not_imported() {
        let slot = Arc::new(AtomicU64::new(census_slot() + 5));
        let mut core = GraphiteCore::new();
        core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
            endpoint: serve(slot.clone()),
            timeout: std::time::Duration::from_secs(5),
            max_retries: 0,
            ..Default::default()
        }));
        core.verify_async(&input()).await.unwrap();
        assert_eq!(
            core.observed_deployment(WHIRLPOOL).unwrap().deploy_slot,
            census_slot() + 5
        );
        let plan = ci::import_embedded_into(&mut core).unwrap();
        let reason = skip_reason(&plan, WHIRLPOOL);
        assert!(reason.starts_with(STALE_DEPLOYMENT), "{reason}");
        assert!(core.program_behavior(WHIRLPOOL).is_none());
    }
}

// ─── Round 40 follow-up: the census is mainnet-beta's, enforced ────────────

const DEVNET_GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";

#[test]
fn only_mainnet_beta_is_a_cluster_the_census_can_be_imported_into() {
    assert!(ci::check_cluster_arg("mainnet-beta").is_ok());
    for other in [
        "devnet",
        "testnet",
        "localnet",
        "mainnet",
        "Mainnet-Beta",
        "",
    ] {
        let e = ci::check_cluster_arg(other).unwrap_err();
        assert!(e.contains("mainnet-beta only"), "{other}: {e}");
    }
    // The census says where it was measured; another RPC is refused.
    let mut d = doc();
    d["rpc"] = "https://api.devnet.solana.com".into();
    let e = Census::from_bytes(&serde_json::to_vec(&d).unwrap()).unwrap_err();
    assert!(e.contains("cannot place it on mainnet-beta"), "{e}");
}

#[test]
fn an_import_records_that_the_graphs_evidence_is_mainnet_betas() {
    let dir = std::env::temp_dir().join(format!(
        "graphite-r40-mark-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    {
        let mut core = GraphiteCore::open_data_dir(dir.clone()).unwrap();
        assert_eq!(
            core.evidence_genesis(),
            None,
            "a fresh graph names no cluster"
        );
        let census = Census::embedded().unwrap();
        let plan = ci::plan(&core, &census, &[SYSTEM.to_string()]).unwrap();
        ci::apply(&mut core, &plan.imports[0]).unwrap().unwrap();
    }
    let reopened = GraphiteCore::open_data_dir_read_only(&dir).unwrap();
    assert_eq!(
        reopened.evidence_genesis().as_deref(),
        Some(ci::MAINNET_BETA_GENESIS_HASH),
        "the mark is in the snapshot"
    );
    let _ = std::fs::remove_dir_all(&dir);

    // One graph, one cluster: evidence of another is refused before it is
    // appended.
    let mut store = graphite_core::semantic_graph_store::SemanticGraphStore::new();
    store
        .mark_evidence_genesis(ci::MAINNET_BETA_GENESIS_HASH)
        .unwrap();
    assert!(store
        .mark_evidence_genesis(ci::MAINNET_BETA_GENESIS_HASH)
        .is_ok());
    assert!(store.mark_evidence_genesis(DEVNET_GENESIS).is_err());
}

#[cfg(feature = "rpc")]
mod cluster {
    use super::*;
    use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A loopback RPC that answers `getGenesisHash` with `genesis` (`None`:
    /// an error) and counts the asks.
    fn serve(genesis: Option<&'static str>, asked: Arc<AtomicUsize>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                let mut buf = vec![0u8; 1 << 16];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let answer = if req.contains("getGenesisHash") {
                    asked.fetch_add(1, Ordering::SeqCst);
                    match genesis {
                        Some(g) => format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{g}"}}"#),
                        None => r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#.to_string(),
                    }
                } else {
                    r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string()
                };
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                        answer.len()
                    )
                    .as_bytes(),
                );
            }
        });
        format!("http://{addr}")
    }

    fn core_on(genesis: Option<&'static str>, imported: bool) -> (GraphiteCore, Arc<AtomicUsize>) {
        let asked = Arc::new(AtomicUsize::new(0));
        let mut core = GraphiteCore::new();
        if imported {
            ci::import_embedded_into(&mut core).unwrap();
        }
        core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
            endpoint: serve(genesis, Arc::clone(&asked)),
            timeout: std::time::Duration::from_secs(5),
            max_retries: 0,
            ..Default::default()
        }));
        (core, asked)
    }

    #[tokio::test]
    async fn imported_evidence_is_refused_on_another_cluster_and_accepted_on_mainnet_beta() {
        let (devnet, _) = core_on(Some(DEVNET_GENESIS), true);
        let e = devnet.confirm_evidence_cluster().await.unwrap_err();
        assert!(
            e.contains(ci::MAINNET_BETA_GENESIS_HASH) && e.contains(DEVNET_GENESIS),
            "{e}"
        );
        let (unsaid, _) = core_on(None, true);
        let e = unsaid.confirm_evidence_cluster().await.unwrap_err();
        assert!(e.contains("could not say which cluster"), "{e}");
        let (mainnet, asked) = core_on(Some(ci::MAINNET_BETA_GENESIS_HASH), true);
        mainnet.confirm_evidence_cluster().await.unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_graph_without_imported_evidence_asks_nothing() {
        let (core, asked) = core_on(Some(DEVNET_GENESIS), false);
        core.confirm_evidence_cluster().await.unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 0);
    }
}
