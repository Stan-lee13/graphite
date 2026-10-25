//! Roadmap R-M1 (external reviews R11, W5, W6): a protocol upgraded under its
//! manifest was judged by the old manifest until someone noticed.
//!
//! With an RPC attached, every manifested program a transaction invokes has
//! its deployment read from the BPF Upgradeable Loader — the slot its code
//! was deployed at and its upgrade authority, two batched header reads — and
//! compared with what Graphite last saw. The first sighting is the baseline.
//! A redeploy or a new upgrade authority is reported once on the verdict
//! (`program_upgrades`, a `ProgramUpgraded` warning), counted for `/health`
//! and the metrics, and — only when the operator set
//! `GRAPHITE_QUARANTINE_ON_UPGRADE` — quarantines the program, which blocks
//! the verdict. A deployment that cannot be read changes nothing.
//!
//! Every RPC here is a loopback mock.
#![cfg(feature = "rpc")]

use base64::Engine as _;
use graphite_core::manifest::load_seed_manifests;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{ProgramDeployment, LOADER_V4};
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient, UPGRADEABLE_LOADER};
use graphite_core::verification::{
    GraphiteCore, ProgramUpgrade, ProposedIntent, UnobservedCode, VerificationInput,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const WHIRLPOOL: &str = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";

fn key(byte: u8) -> String {
    bs58::encode([byte; 32]).into_string()
}

/// What the mock loader holds for the program.
#[derive(Clone)]
struct Loader {
    owner: Arc<Mutex<String>>,
    deploy_slot: Arc<AtomicU64>,
    /// 0 = no upgrade authority; otherwise the authority key's byte.
    authority: Arc<AtomicU64>,
    /// Answer header reads with an error instead.
    broken: Arc<Mutex<bool>>,
    /// Every `dataSlice` length the core asked for.
    slices: Arc<Mutex<Vec<u64>>>,
}

impl Loader {
    fn new() -> Self {
        Loader {
            owner: Arc::new(Mutex::new(UPGRADEABLE_LOADER.to_string())),
            deploy_slot: Arc::new(AtomicU64::new(100)),
            authority: Arc::new(AtomicU64::new(0x51)),
            broken: Arc::new(Mutex::new(false)),
            slices: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn answer(&self, body: &serde_json::Value) -> String {
        let method = body["method"].as_str().unwrap_or_default();
        let ok = |result: serde_json::Value| {
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string()
        };
        if method != "getMultipleAccounts" {
            return r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"not mocked"}}"#
                .to_string();
        }
        let addresses: Vec<String> = body["params"][0]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let slice = body["params"][1]["dataSlice"]["length"].as_u64();
        let Some(length) = slice else {
            // Any other account read: nothing there.
            return ok(
                serde_json::json!({"context": {"slot": 1}, "value": addresses.iter().map(|_| serde_json::Value::Null).collect::<Vec<_>>()}),
            );
        };
        self.slices.lock().unwrap().push(length);
        if *self.broken.lock().unwrap() {
            return r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"loader unavailable"}}"#
                .to_string();
        }
        let b64 = |bytes: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(bytes);
        let owner = self.owner.lock().unwrap().clone();
        let values: Vec<serde_json::Value> = addresses
            .iter()
            .map(|a| {
                let data = if a == WHIRLPOOL {
                    let mut d = 2u32.to_le_bytes().to_vec();
                    d.extend([0x44u8; 32]);
                    d
                } else if *a == key(0x44) {
                    let mut d = 3u32.to_le_bytes().to_vec();
                    d.extend(self.deploy_slot.load(Ordering::SeqCst).to_le_bytes());
                    match self.authority.load(Ordering::SeqCst) {
                        0 => d.push(0),
                        b => {
                            d.push(1);
                            d.extend([b as u8; 32]);
                        }
                    }
                    d
                } else {
                    return serde_json::Value::Null;
                };
                serde_json::json!({
                    "lamports": 1_141_440,
                    "owner": owner,
                    "data": [b64(data), "base64"],
                    "executable": a == WHIRLPOOL,
                    "rentEpoch": 0,
                })
            })
            .collect();
        ok(serde_json::json!({"context": {"slot": 1}, "value": values}))
    }
}

fn serve(loader: Loader) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let loader = loader.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 1 << 16];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = req
                    .split("\r\n\r\n")
                    .nth(1)
                    .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                    .unwrap_or_default();
                let answer = loader.answer(&body);
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

fn core_with(loader: &Loader) -> GraphiteCore {
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint: serve(loader.clone()),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    }));
    core
}

/// A described Whirlpool instruction: the program is manifested and invoked.
fn input() -> VerificationInput {
    let registry = load_seed_manifests();
    let ix = registry
        .get(WHIRLPOOL)
        .expect("Whirlpool manifest")
        .instructions
        .iter()
        .find(|i| !i.discriminator.is_empty())
        .expect("an instruction")
        .clone();
    let accounts: Vec<String> = (0..ix.accounts.len())
        .map(|i| key(0x60 + i as u8))
        .collect();
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
        account_addresses: accounts,
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

async fn upgrades(
    core: &GraphiteCore,
) -> (
    Vec<ProgramUpgrade>,
    graphite_core::verification::VerificationResult,
) {
    let r = core.verify_async(&input()).await.expect("verified");
    (r.program_upgrades.clone(), r)
}

#[tokio::test]
async fn a_redeployed_program_is_reported_once_and_not_refused_by_default() {
    let loader = Loader::new();
    let core = core_with(&loader);
    assert!(
        upgrades(&core).await.0.is_empty(),
        "the first sighting is the baseline"
    );
    assert!(
        upgrades(&core).await.0.is_empty(),
        "the same code is not an upgrade"
    );

    loader.deploy_slot.store(200, Ordering::SeqCst);
    let (found, r) = upgrades(&core).await;
    assert_eq!(
        found,
        vec![ProgramUpgrade {
            program_id: WHIRLPOOL.to_string(),
            previous_deploy_slot: 100,
            deploy_slot: 200,
            previous_upgrade_authority: Some(key(0x51)),
            upgrade_authority: Some(key(0x51)),
            quarantined: false,
        }]
    );
    assert!(r.summary.contains("ProgramUpgraded"), "{}", r.summary);
    assert!(
        !r.risk_verdict
            .findings
            .iter()
            .any(|f| f.pattern == "ProgramQuarantined"),
        "not quarantined without the operator's flag"
    );
    assert_eq!(core.program_upgrades_detected(), 1);
    assert!(upgrades(&core).await.0.is_empty(), "reported once");
    assert!(core.quarantined_programs().is_empty());

    // Every read was a header, never a program binary: 48 bytes covers
    // either loader's program-account header (loader-v4's LoaderV4State,
    // Round 36), 45 a loader-v3 ProgramData header.
    let slices = loader.slices.lock().unwrap().clone();
    assert!(
        !slices.is_empty() && slices.iter().all(|l| *l == 48 || *l == 45),
        "{slices:?}"
    );
}

#[tokio::test]
async fn an_upgrade_authority_handed_over_is_an_upgrade() {
    let loader = Loader::new();
    let core = core_with(&loader);
    let _ = upgrades(&core).await;
    loader.authority.store(0x52, Ordering::SeqCst);
    let (found, _) = upgrades(&core).await;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].deploy_slot, 100, "same code");
    assert_eq!(found[0].upgrade_authority, Some(key(0x52)));
    // Made final: no authority at all is a change too.
    loader.authority.store(0, Ordering::SeqCst);
    let (found, _) = upgrades(&core).await;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].upgrade_authority, None);
}

#[tokio::test]
async fn with_the_operator_flag_an_upgrade_quarantines_the_program() {
    let loader = Loader::new();
    let mut core = core_with(&loader);
    core.set_quarantine_on_upgrade(true);
    let (_, first) = upgrades(&core).await;
    assert!(
        !first
            .risk_verdict
            .findings
            .iter()
            .any(|f| f.pattern == "ProgramQuarantined"),
        "the first sighting quarantines nothing"
    );
    loader.deploy_slot.store(300, Ordering::SeqCst);
    let (found, r) = upgrades(&core).await;
    assert_eq!(found.len(), 1);
    assert!(found[0].quarantined);
    assert_eq!(r.risk_verdict.status, "Blocked");
    assert!(
        r.risk_verdict
            .findings
            .iter()
            .any(|f| f.pattern == "ProgramQuarantined"),
        "{:?}",
        r.risk_verdict.findings
    );
    assert!(!r.approved);
    assert!(core
        .quarantined_programs()
        .iter()
        .any(|(p, reason)| p == WHIRLPOOL && reason.contains("deploy slot 100 -> 300")));
}

#[tokio::test]
async fn a_deployment_that_cannot_be_read_changes_nothing() {
    let loader = Loader::new();
    let mut core = core_with(&loader);
    core.set_quarantine_on_upgrade(true);
    let _ = upgrades(&core).await;
    *loader.broken.lock().unwrap() = true;
    loader.deploy_slot.store(400, Ordering::SeqCst);
    let (found, r) = upgrades(&core).await;
    assert!(found.is_empty(), "nothing was read, so nothing changed");
    // Round 38 (R37-16): and the verdict says so. Until then this was a
    // tracing line, and the verdict rested on evidence that may describe
    // replaced code.
    assert!(
        r.scope
            .unobserved_codes()
            .contains(&UnobservedCode::ProgramDeployments),
        "{:?}",
        r.scope.unobserved()
    );
    assert!(!r
        .risk_verdict
        .findings
        .iter()
        .any(|f| f.pattern == "ProgramQuarantined"));
    // Once the loader answers again, the redeploy is still noticed.
    *loader.broken.lock().unwrap() = false;
    let (found, r) = upgrades(&core).await;
    assert_eq!(found.len(), 1);
    assert!(!r
        .scope
        .unobserved_codes()
        .contains(&UnobservedCode::ProgramDeployments));
}

/// Round 38 (R37-16): one program whose account does not decode as its
/// loader's failed the whole batch, so a single odd account switched
/// upgrade detection off for every program in the transaction. It now
/// stands for itself, and the verdict names it.
#[tokio::test]
async fn one_undecodable_deployment_does_not_hide_the_others() {
    let loader = Loader::new();
    // Owned by loader-v4, with a loader-v3 Program account's 36 bytes.
    *loader.owner.lock().unwrap() = LOADER_V4.to_string();
    let client = SolanaRpcClient::new(RpcConfig {
        endpoint: serve(loader.clone()),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    });
    let read = client
        .get_program_deployments(&[WHIRLPOOL.to_string(), key(0x70)])
        .await
        .expect("one bad entry is not a failed batch");
    assert!(
        matches!(&read[0], ProgramDeployment::Unreadable { why } if why.contains("LoaderV4State")),
        "{read:?}"
    );
    assert_eq!(read[1], ProgramDeployment::Missing);
    let (_, r) = upgrades(&core_with(&loader)).await;
    assert!(
        r.scope
            .unobserved_codes()
            .contains(&UnobservedCode::ProgramDeployments),
        "{:?}",
        r.scope.unobserved()
    );
}

#[tokio::test]
async fn a_program_the_loader_does_not_own_is_not_tracked() {
    let loader = Loader::new();
    *loader.owner.lock().unwrap() = "BPFLoader2111111111111111111111111111111111".to_string();
    let core = core_with(&loader);
    let _ = upgrades(&core).await;
    loader.deploy_slot.store(500, Ordering::SeqCst);
    assert!(upgrades(&core).await.0.is_empty());
    assert_eq!(core.program_upgrades_detected(), 0);
}

#[tokio::test]
async fn the_last_deployment_seen_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!(
        "graphite-rm1-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let loader = Loader::new();
    let endpoint = serve(loader.clone());
    let open = || {
        let mut core = GraphiteCore::open_data_dir(dir.clone()).expect("data dir");
        core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
            endpoint: endpoint.clone(),
            timeout: std::time::Duration::from_secs(5),
            max_retries: 0,
            ..Default::default()
        }));
        core
    };
    {
        let core = open();
        assert!(upgrades(&core).await.0.is_empty());
    }
    // Upgraded while Graphite was down: noticed at the first transaction after.
    loader.deploy_slot.store(600, Ordering::SeqCst);
    let core = open();
    let (found, _) = upgrades(&core).await;
    assert_eq!(found.len(), 1, "the record was on disk");
    assert_eq!(
        (found[0].previous_deploy_slot, found[0].deploy_slot),
        (100, 600)
    );
    drop(core);
    let _ = std::fs::remove_dir_all(dir);
}
