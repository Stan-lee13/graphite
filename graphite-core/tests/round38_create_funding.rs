//! Requires the `rpc` feature: every verdict here rests on a simulated diff.
#![cfg(feature = "rpc")]

//! Round 38 (R37-7): under a `create` intent, a `CreateAccount` funds the
//! new account with what its data says, and whoever builds the transaction
//! writes that number.
//!
//! The binding returned `NotApplicable` for `create`, and L4's R33-15 rule
//! holds the signer's wallet to the located instruction's own
//! `data.lamports`. End to end: a signed artifact, simulated by a loopback
//! mock RPC, through `verify_async`. Everything is a loopback socket.

use graphite_core::confidence_engine::TrustTier;
use graphite_core::manifest::load_seed_manifests;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::solana_types::Pubkey;
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{
    ExecutionDecision, ExtractedParameters, GraphiteCore, LayerStatus, ProposedIntent,
    VerificationInput, VerificationResult,
};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

const SYSTEM: &str = "11111111111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const NATIVE_LOADER: &str = "NativeLoader1111111111111111111111111111111";

/// The wallet that signs and pays.
const OWNER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
/// Somebody else.
const ATTACKER: &str = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7";

const SOL: u64 = 1_000_000_000;
const FEE: u64 = 5_000;

fn pk(s: &str) -> Pubkey {
    Pubkey::from_base58(s).unwrap()
}

fn key(seed: u8) -> String {
    let mut k = [0u8; 32];
    k[0] = 0x6B;
    k[1] = seed;
    bs58::encode(k).into_string()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

// ─── A loopback cluster ────────────────────────────────────────────────────

#[derive(Clone)]
struct Account {
    lamports: u64,
    owner: String,
    data: Vec<u8>,
    executable: bool,
}

fn acct(lamports: u64, owner: &str, data: Vec<u8>) -> Account {
    Account {
        lamports,
        owner: owner.to_string(),
        data,
        executable: false,
    }
}

fn program_account(owner: &str) -> Account {
    Account {
        lamports: 1_141_440,
        owner: owner.to_string(),
        data: vec![],
        executable: true,
    }
}

#[derive(Default, Clone)]
struct Cluster {
    /// The message's keys in order: the balance arrays span them.
    keys: Vec<String>,
    pre: HashMap<String, Account>,
    /// What the simulation leaves; an account not named here is unchanged.
    post: HashMap<String, Option<Account>>,
}

impl Cluster {
    fn set(&mut self, k: &str, a: Account) {
        self.pre.insert(k.to_string(), a);
    }
    fn after(&mut self, k: &str, a: Account) {
        self.post.insert(k.to_string(), Some(a));
    }
    fn post_of(&self, k: &str) -> Option<Account> {
        match self.post.get(k) {
            Some(a) => a.clone(),
            None => self.pre.get(k).cloned(),
        }
    }
}

fn account_json(a: Option<&Account>) -> String {
    use base64::Engine;
    match a {
        None => "null".to_string(),
        Some(a) => format!(
            r#"{{"lamports":{},"owner":"{}","executable":{},"rentEpoch":0,"data":["{}","base64"]}}"#,
            a.lamports,
            a.owner,
            a.executable,
            base64::engine::general_purpose::STANDARD.encode(&a.data)
        ),
    }
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn serve(state: Arc<Mutex<Cluster>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut req = Vec::new();
            let mut buf = vec![0u8; 1 << 16];
            // Read the headers and the whole body (Content-Length).
            loop {
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&req);
                if let Some(split) = text.find("\r\n\r\n") {
                    let len = text[..split]
                        .lines()
                        .find_map(|l| {
                            let l = l.to_ascii_lowercase();
                            l.strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if req.len() >= split + 4 + len {
                        break;
                    }
                }
            }
            let req = String::from_utf8_lossy(&req).to_string();
            let body: serde_json::Value = req
                .split("\r\n\r\n")
                .nth(1)
                .and_then(|b| serde_json::from_str(b).ok())
                .unwrap_or(serde_json::Value::Null);
            let s = state.lock().unwrap().clone();
            let method = body["method"].as_str().unwrap_or("").to_string();
            let result = match method.as_str() {
                "getMultipleAccounts" => {
                    let ks = strings(&body["params"][0]);
                    let vals: Vec<String> = ks.iter().map(|k| account_json(s.pre.get(k))).collect();
                    format!(
                        r#"{{"context":{{"slot":1000}},"value":[{}]}}"#,
                        vals.join(",")
                    )
                }
                "getAccountInfo" => {
                    let k = body["params"][0].as_str().unwrap_or("");
                    format!(
                        r#"{{"context":{{"slot":1000}},"value":{}}}"#,
                        account_json(s.pre.get(k))
                    )
                }
                "simulateTransaction" => {
                    let ks = strings(&body["params"][1]["accounts"]["addresses"]);
                    let post: Vec<String> = ks
                        .iter()
                        .map(|k| account_json(s.post_of(k).as_ref()))
                        .collect();
                    let balances = |pre: bool| -> String {
                        s.keys
                            .iter()
                            .map(|k| {
                                let a = if pre {
                                    s.pre.get(k).cloned()
                                } else {
                                    s.post_of(k)
                                };
                                a.map_or(0, |a| a.lamports).to_string()
                            })
                            .collect::<Vec<_>>()
                            .join(",")
                    };
                    format!(
                        r#"{{"context":{{"slot":1000}},"value":{{"err":null,"logs":[],"unitsConsumed":40000,"fee":{FEE},
                        "preBalances":[{}],"postBalances":[{}],
                        "innerInstructions":[],"loadedAddresses":{{"writable":[],"readonly":[]}},
                        "accounts":[{}],"returnData":null}}}}"#,
                        balances(true),
                        balances(false),
                        post.join(",")
                    )
                }
                _ => "null".to_string(),
            };
            let out = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                out.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(out.as_bytes());
        }
    });
    format!("http://{addr}")
}

// ─── A legacy message ──────────────────────────────────────────────────────

fn compact_u16(mut v: usize, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// One instruction: program, accounts (with their privileges), data.
struct Ix {
    program: String,
    accounts: Vec<(String, bool, bool)>,
    data: Vec<u8>,
}

fn ix(program: &str, accounts: &[(&str, bool, bool)], data: Vec<u8>) -> Ix {
    Ix {
        program: program.to_string(),
        accounts: accounts
            .iter()
            .map(|(k, s, w)| (k.to_string(), *s, *w))
            .collect(),
        data,
    }
}

/// The message's keys in header order (fee payer first) and its bytes.
fn frame(payer: &str, ixs: &[Ix]) -> (Vec<String>, Vec<u8>) {
    // key -> (signer, writable)
    let mut privileges: Vec<(String, bool, bool)> = vec![(payer.to_string(), true, true)];
    let mut note = |k: &str, s: bool, w: bool| {
        if let Some(e) = privileges.iter_mut().find(|e| e.0 == k) {
            e.1 |= s;
            e.2 |= w;
        } else {
            privileges.push((k.to_string(), s, w));
        }
    };
    for i in ixs {
        for (k, s, w) in &i.accounts {
            note(k, *s, *w);
        }
        note(&i.program, false, false);
    }
    let class = |e: &(String, bool, bool)| match (e.1, e.2) {
        (true, true) => 0,
        (true, false) => 1,
        (false, true) => 2,
        (false, false) => 3,
    };
    let payer_entry = privileges.remove(0);
    privileges.sort_by_key(class);
    privileges.insert(0, payer_entry);
    let keys: Vec<String> = privileges.iter().map(|e| e.0.clone()).collect();
    let signers = privileges.iter().filter(|e| e.1).count();
    let ro_signed = privileges.iter().filter(|e| e.1 && !e.2).count();
    let ro_unsigned = privileges.iter().filter(|e| !e.1 && !e.2).count();
    let index = |k: &str| keys.iter().position(|x| x == k).unwrap() as u8;

    let mut out = Vec::new();
    compact_u16(signers, &mut out);
    for _ in 0..signers {
        out.extend_from_slice(&[0u8; 64]);
    }
    out.extend_from_slice(&[signers as u8, ro_signed as u8, ro_unsigned as u8]);
    compact_u16(keys.len(), &mut out);
    for k in &keys {
        out.extend_from_slice(pk(k).as_bytes());
    }
    out.extend_from_slice(&[9u8; 32]);
    compact_u16(ixs.len(), &mut out);
    for i in ixs {
        out.push(index(&i.program));
        compact_u16(i.accounts.len(), &mut out);
        for (k, _, _) in &i.accounts {
            out.push(index(k));
        }
        compact_u16(i.data.len(), &mut out);
        out.extend_from_slice(&i.data);
    }
    (keys, out)
}

fn describe(i: &Ix) -> TransactionInstruction {
    TransactionInstruction {
        program_id: i.program.clone(),
        instruction_discriminator: hex::encode(&i.data[..i.data.len().min(4)]),
        account_addresses: i.accounts.iter().map(|a| a.0.clone()).collect(),
        cpi_targets: vec![],
    }
}

/// Verify `ixs[primary]` under `intent`, the others declared as siblings,
/// against `cluster` (its keys are filled in from the message).
async fn verify(
    mut cluster: Cluster,
    payer: &str,
    ixs: &[Ix],
    primary: usize,
    intent: &str,
    extracted: Option<ExtractedParameters>,
) -> VerificationResult {
    let (keys, bytes) = frame(payer, ixs);
    cluster.keys = keys;
    let endpoint = serve(Arc::new(Mutex::new(cluster)));
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint,
        timeout: std::time::Duration::from_secs(10),
        max_retries: 0,
        ..Default::default()
    }));
    let p = &ixs[primary];
    let def_disc = load_seed_manifests()
        .get(&p.program)
        .and_then(|m| {
            m.instructions
                .iter()
                .find(|d| {
                    let disc = hex_to_bytes(&d.discriminator);
                    p.data.starts_with(&disc)
                })
                .map(|d| d.discriminator.clone())
        })
        .expect("the primary is a manifest instruction");
    let input = VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: intent.to_string(),
            raw_natural_language: format!("{intent} please"),
            confidence_of_parse: 1.0,
            extracted_parameters: extracted,
        },
        program_id: p.program.clone(),
        protocol_version: String::new(),
        instruction_discriminator: def_disc,
        account_addresses: p.accounts.iter().map(|a| a.0.clone()).collect(),
        instruction_data: Some(p.data.clone()),
        cpi_targets: vec![],
        // Confidence is not what these tests are about (see
        // round38_sibling_skims.rs).
        wallet_profile: WalletProfile::Custom {
            min_confidence: 0.40,
            min_trust_tier: TrustTier::OfficialManifest,
        },
        behavior_evidence: BehaviorEvidence {
            has_signed_manifest: true,
            community_verified_count: 5,
            battle_tested_tx_count: 50_000,
            simulation_match_count: 100,
        },
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: Some(bytes),
        transaction_instructions: ixs
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != primary)
            .map(|(_, i)| describe(i))
            .collect(),
        cpi_trace: None,
        real_account_metas: vec![],
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        state_diff: None,
    };
    core.verify_async(&input).await.expect("a verdict")
}

fn risk(r: &VerificationResult) -> String {
    r.risk_verdict
        .findings
        .iter()
        .map(|f| format!("{}: {}", f.pattern, f.reason))
        .collect::<Vec<_>>()
        .join(" || ")
}

/// Every layer's status, for the record, with the reason of every failed
/// layer but L4 (whose reason the tests print themselves).
fn statuses(r: &VerificationResult) -> String {
    r.layers
        .iter()
        .map(|l| {
            if l.status == LayerStatus::Failed && !l.layer.starts_with("L4") {
                let reason: String = l.reason.chars().take(400).collect();
                format!("{}={:?} ({reason})", l.layer, l.status)
            } else {
                format!("{}={:?}", l.layer, l.status)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// A program somebody deployed.
const FOREIGN: &str = "Fore1gnProgram11111111111111111111111111111";

/// The rent-exempt minimum for `space` bytes (Solana's default rent).
fn rent(space: u64) -> u64 {
    (128 + space) * 6_960
}

/// System `CreateAccount { lamports, space, owner }`.
fn create_account(lamports: u64, space: u64, owner: &str) -> Vec<u8> {
    let mut d = vec![0u8, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d.extend_from_slice(&space.to_le_bytes());
    d.extend_from_slice(pk(owner).as_bytes());
    d
}

fn sol_request(amount: &str) -> Option<ExtractedParameters> {
    Some(ExtractedParameters {
        amount: Some(amount.to_string()),
        input_token: Some("SOL".to_string()),
        ..Default::default()
    })
}

/// The owner creates `new` with `space` bytes owned by `program`, funded
/// with `lamports`.
fn create(lamports: u64, space: u64, program: &str) -> (Cluster, Vec<Ix>) {
    let mut c = Cluster::default();
    let new = key(80);
    for (p, owner) in [(SYSTEM, NATIVE_LOADER), (TOKEN, LOADER), (FOREIGN, LOADER)] {
        c.set(p, program_account(owner));
    }
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    c.after(OWNER, acct(10 * SOL - FEE - lamports, SYSTEM, vec![]));
    c.after(&new, acct(lamports, program, vec![0u8; space as usize]));
    let primary = ix(
        SYSTEM,
        &[(OWNER, true, true), (&new, true, true)],
        create_account(lamports, space, program),
    );
    (c, vec![primary])
}

fn record(tag: &str, r: &VerificationResult) {
    eprintln!(
        "[R37-7 {tag}] decision={:?} | {} | risk: {}",
        r.decision,
        statuses(r),
        risk(r)
    );
}

/// The control: a token account's 165 bytes, funded with exactly its rent.
#[tokio::test]
async fn an_account_funded_with_its_rent_is_executable() {
    let (c, ixs) = create(rent(165), 165, TOKEN);
    let r = verify(c, OWNER, &ixs, 0, "create", None).await;
    record("rent", &r);
    assert_eq!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{}",
        risk(&r)
    );
}

/// R37-7: 5 SOL into a zero-byte account the attacker's program owns, under
/// `create`.
#[tokio::test]
async fn an_account_funded_far_beyond_its_rent_is_not_executable() {
    let (c, ixs) = create(5 * SOL, 0, FOREIGN);
    let r = verify(c, OWNER, &ixs, 0, "create", None).await;
    record("5 SOL", &r);
    assert_ne!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{}",
        risk(&r)
    );
}

/// The control for a stated amount: the request says 1 SOL, and the creation
/// funds rent plus exactly that.
#[tokio::test]
async fn an_account_funded_with_the_amount_the_request_states_is_executable() {
    let (c, ixs) = create(rent(0) + SOL, 0, FOREIGN);
    let r = verify(c, OWNER, &ixs, 0, "create", sol_request("1")).await;
    record("stated 1 SOL", &r);
    assert_eq!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{}",
        risk(&r)
    );
    // And no more than that: 5 SOL against a request for 1.
    let (c, ixs) = create(rent(0) + 5 * SOL, 0, FOREIGN);
    let r = verify(c, OWNER, &ixs, 0, "create", sol_request("1")).await;
    record("stated 1 SOL, funded 5", &r);
    assert_ne!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{}",
        risk(&r)
    );
}

/// A creation funded with exactly its rent, beside a System transfer of the
/// owner's SOL to someone else: what is not a creation is a transfer, and
/// `create` does not state one.
#[tokio::test]
async fn a_transfer_to_someone_else_beside_a_creation_is_not_executable() {
    let (mut c, mut ixs) = create(rent(165), 165, TOKEN);
    let mut d = vec![2u8, 0, 0, 0];
    d.extend_from_slice(&(2 * SOL).to_le_bytes());
    ixs.push(ix(
        SYSTEM,
        &[(OWNER, true, true), (ATTACKER, false, true)],
        d,
    ));
    c.set(ATTACKER, acct(SOL, SYSTEM, vec![]));
    c.after(ATTACKER, acct(3 * SOL, SYSTEM, vec![]));
    c.after(
        OWNER,
        acct(10 * SOL - FEE - rent(165) - 2 * SOL, SYSTEM, vec![]),
    );
    let r = verify(c, OWNER, &ixs, 0, "create", None).await;
    record("create + transfer", &r);
    assert_ne!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{}",
        risk(&r)
    );
    assert!(
        risk(&r).contains("IntentMismatch"),
        "the binding does not name it: {}",
        risk(&r)
    );
}
