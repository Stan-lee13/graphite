//! Requires the `rpc` feature: every verdict here rests on a simulated diff.
#![cfg(feature = "rpc")]

//! What a signer loses is judged per signer, against what the declaration
//! says about THAT signer (Round 34: the Round 33 audit's L4 findings
//! R33-5, -6, -7, -10, -14, -15), end to end: a signed artifact, simulated
//! by a loopback mock RPC, through `verify_async`.
//!
//! - R33-5: a debit line that names no account ("withdraws funds and
//!   transfers them out of the pool to the involved accounts") said nothing
//!   about whose value moves, yet excused every account's loss — a sibling
//!   emptying the signer's wallet under a Raydium CPMM `withdraw` raised
//!   nothing.
//! - R33-6: rent paid into a created account another program owns was
//!   credited as the signer's.
//! - R33-7: a co-signer's gain offset the user's loss.
//! - R33-14: a stake account created in the transaction with a withdrawer
//!   that does not sign was never compared with the signers.
//! - R33-15: a debit declared of the signer's wallet excused any amount
//!   from it.

use graphite_core::find_program_address;
use graphite_core::manifest::{load_seed_manifests, InstructionDef};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::solana_types::Pubkey;
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationResult,
};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

const SYSTEM: &str = "11111111111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const STAKE: &str = "Stake11111111111111111111111111111111111111";
const LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const NATIVE_LOADER: &str = "NativeLoader1111111111111111111111111111111";
const MEMO: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const CPMM: &str = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C";
const RENT_SYSVAR: &str = "SysvarRent111111111111111111111111111111111";

/// The wallet that signs and pays.
const OWNER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
/// Somebody else.
const ATTACKER: &str = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7";
const MINT_X: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const MINT_Y: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

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

fn ata(owner: &str, mint: &str) -> String {
    find_program_address(
        &[
            pk(owner).as_bytes(),
            pk(TOKEN).as_bytes(),
            pk(mint).as_bytes(),
        ],
        &pk(ATA_PROGRAM),
    )
    .unwrap()
    .0
    .to_base58()
}

fn def(program: &str, name: &str) -> InstructionDef {
    load_seed_manifests()
        .get(program)
        .unwrap_or_else(|| panic!("{program} has a seed manifest"))
        .instructions
        .iter()
        .find(|i| i.name == name)
        .unwrap_or_else(|| panic!("{program} declares {name}"))
        .clone()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

// ─── Account bytes ─────────────────────────────────────────────────────────

fn token_account(mint: &str, owner: &str, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(pk(mint).as_bytes());
    d[32..64].copy_from_slice(pk(owner).as_bytes());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    d
}

fn mint(supply: u64, authority: Option<&str>) -> Vec<u8> {
    let mut d = vec![0u8; 82];
    if let Some(a) = authority {
        d[0..4].copy_from_slice(&1u32.to_le_bytes());
        d[4..36].copy_from_slice(pk(a).as_bytes());
    }
    d[36..44].copy_from_slice(&supply.to_le_bytes());
    d[44] = 6;
    d[45] = 1;
    d
}

/// `StakeStateV2::Initialized` with the given staker and withdrawer and no
/// lockup.
fn stake_initialized(staker: &str, withdrawer: &str) -> Vec<u8> {
    let mut d = vec![0u8; 200];
    d[0..4].copy_from_slice(&1u32.to_le_bytes());
    d[4..12].copy_from_slice(&2_282_880u64.to_le_bytes());
    d[12..44].copy_from_slice(pk(staker).as_bytes());
    d[44..76].copy_from_slice(pk(withdrawer).as_bytes());
    d
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

fn system_transfer(lamports: u64) -> Vec<u8> {
    let mut d = vec![2u8, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d
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
            extracted_parameters: None,
        },
        program_id: p.program.clone(),
        protocol_version: String::new(),
        instruction_discriminator: def_disc,
        account_addresses: p.accounts.iter().map(|a| a.0.clone()).collect(),
        instruction_data: Some(p.data.clone()),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
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

fn layer(r: &VerificationResult, prefix: &str) -> (LayerStatus, String) {
    let l = r
        .layers
        .iter()
        .find(|l| l.layer.starts_with(prefix))
        .unwrap_or_else(|| panic!("{prefix} reported"));
    (l.status, l.reason.clone())
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

// ─── R33-5: a debit line that names no account ────────────────────────────

const CLMM: &str = "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK";

/// An account list for `name` that satisfies its layout's fixed addresses
/// and PDA seeds, with `set` applied (role → key) before the PDAs are
/// derived; every other slot gets a distinct key.
fn accounts_for(program: &str, d: &InstructionDef, set: &[(&str, String)]) -> Vec<String> {
    let mut keys: Vec<String> = (0..d.accounts.len()).map(|i| key(100 + i as u8)).collect();
    for (i, a) in d.accounts.iter().enumerate() {
        if let Some((_, v)) = set.iter().find(|(r, _)| *r == a.name) {
            keys[i] = v.clone();
        } else if let Some(first) = a.expected_address.first() {
            keys[i] = if first == "{program_id}" {
                program.to_string()
            } else {
                first.clone()
            };
        }
    }
    for (i, a) in d.accounts.iter().enumerate() {
        if a.pda_seeds.is_empty() {
            continue;
        }
        let seeds: Vec<Vec<u8>> = a
            .pda_seeds
            .iter()
            .map(|s| {
                match s
                    .strip_prefix("{account_")
                    .and_then(|r| r.strip_suffix('}'))
                {
                    Some(n) => pk(&keys[n.parse::<usize>().unwrap()]).as_bytes().to_vec(),
                    None if s == "{program_id}" => pk(program).as_bytes().to_vec(),
                    None => s.as_bytes().to_vec(),
                }
            })
            .collect();
        let refs: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
        keys[i] = find_program_address(&refs, &pk(program))
            .unwrap()
            .0
            .to_base58();
    }
    keys
}

/// A granted withdrawal: `program`'s `name` with the owner's own associated
/// token accounts as its recipients and non-zero minimum outputs, paying 500
/// of `MINT_X` and 700 of `MINT_Y` out of its vaults (and, for CPMM, burning
/// 100 LP). With `drain`, a sibling System transfer sends 5 SOL of the
/// owner's wallet to someone else.
fn withdrawal(program: &str, drain: bool) -> (Cluster, Vec<Ix>) {
    let rent = 2_039_280;
    let mut c = Cluster::default();
    let (name, roles, vaults, args): (&str, [&str; 5], [&str; 2], Vec<u8>) = if program == CPMM {
        let mut a = 100u64.to_le_bytes().to_vec();
        a.extend_from_slice(&400u64.to_le_bytes());
        a.extend_from_slice(&600u64.to_le_bytes());
        (
            "withdraw",
            [
                "owner",
                "vault_0_mint",
                "vault_1_mint",
                "token_0_account",
                "token_1_account",
            ],
            ["token_0_vault", "token_1_vault"],
            a,
        )
    } else {
        let mut a = 100u128.to_le_bytes().to_vec();
        a.extend_from_slice(&400u64.to_le_bytes());
        a.extend_from_slice(&600u64.to_le_bytes());
        (
            "decrease_liquidity_v2",
            [
                "nft_owner",
                "vault_0_mint",
                "vault_1_mint",
                "recipient_token_account_0",
                "recipient_token_account_1",
            ],
            ["token_vault_0", "token_vault_1"],
            a,
        )
    };
    let d = def(program, name);
    let keys = accounts_for(
        program,
        &d,
        &[
            (roles[0], OWNER.to_string()),
            (roles[1], MINT_X.to_string()),
            (roles[2], MINT_Y.to_string()),
            (roles[3], ata(OWNER, MINT_X)),
            (roles[4], ata(OWNER, MINT_Y)),
            ("memo_program", MEMO.to_string()),
        ],
    );
    let slot = |role: &str| keys[d.accounts.iter().position(|a| a.name == role).unwrap()].clone();
    let mut data = hex_to_bytes(&d.discriminator);
    data.extend_from_slice(&args);
    let primary = Ix {
        program: program.to_string(),
        accounts: d
            .accounts
            .iter()
            .zip(&keys)
            .map(|(a, k)| (k.clone(), a.is_signer, a.is_writable))
            .collect(),
        data,
    };

    // Every account of the layout exists; the program's own are its state.
    for (a, k) in d.accounts.iter().zip(&keys) {
        if k != OWNER && !a.is_signer {
            c.set(k, acct(5 * SOL, program, vec![1u8; 64]));
        }
    }
    for (p, owner) in [
        (program, LOADER),
        (TOKEN, LOADER),
        (TOKEN_2022, LOADER),
        (MEMO, LOADER),
        (SYSTEM, NATIVE_LOADER),
    ] {
        c.set(p, program_account(owner));
    }
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    c.set(ATTACKER, acct(SOL, SYSTEM, vec![]));
    c.set(MINT_X, acct(1_461_600, TOKEN, mint(10u64.pow(15), None)));
    c.set(MINT_Y, acct(1_461_600, TOKEN, mint(10u64.pow(15), None)));
    let pool = key(90);
    for (mint_key, vault, recipient, amount) in [
        (MINT_X, slot(vaults[0]), slot(roles[3]), 500u64),
        (MINT_Y, slot(vaults[1]), slot(roles[4]), 700u64),
    ] {
        c.set(
            &vault,
            acct(rent, TOKEN, token_account(mint_key, &pool, 1_000_000)),
        );
        c.set(
            &recipient,
            acct(rent, TOKEN, token_account(mint_key, OWNER, 0)),
        );
        c.after(
            &vault,
            acct(
                rent,
                TOKEN,
                token_account(mint_key, &pool, 1_000_000 - amount),
            ),
        );
        c.after(
            &recipient,
            acct(rent, TOKEN, token_account(mint_key, OWNER, amount)),
        );
    }
    // The program's own state records the withdrawal.
    for (a, k) in d.accounts.iter().zip(&keys) {
        if a.is_writable && c.pre.get(k).is_some_and(|x| x.owner == program) {
            c.after(k, acct(5 * SOL, program, vec![2u8; 64]));
        }
    }
    if program == CPMM {
        let (lp, lp_mint) = (slot("owner_lp_token"), slot("lp_mint"));
        c.set(
            &lp,
            acct(rent, TOKEN, token_account(&lp_mint, OWNER, 1_000)),
        );
        c.after(&lp, acct(rent, TOKEN, token_account(&lp_mint, OWNER, 900)));
        c.set(
            &lp_mint,
            acct(1_461_600, TOKEN, mint(1_000_000, Some(&pool))),
        );
        c.after(&lp_mint, acct(1_461_600, TOKEN, mint(999_900, Some(&pool))));
    }
    let mut ixs = vec![primary];
    if drain {
        c.after(OWNER, acct(10 * SOL - 5 * SOL - FEE, SYSTEM, vec![]));
        c.after(ATTACKER, acct(6 * SOL, SYSTEM, vec![]));
        ixs.push(ix(
            SYSTEM,
            &[(OWNER, true, true), (ATTACKER, false, true)],
            system_transfer(5 * SOL),
        ));
    } else {
        c.after(OWNER, acct(10 * SOL - FEE, SYSTEM, vec![]));
    }
    (c, ixs)
}

async fn drained_withdrawal(program: &str) -> (VerificationResult, LayerStatus, String) {
    let (c, ixs) = withdrawal(program, true);
    let r = verify(c, OWNER, &ixs, 0, "withdraw").await;
    let (status, reason) = layer(&r, "L4");
    eprintln!(
        "[R33-5 drain {program}] approved={} risk={} [{}] | {} | L4: {reason}",
        r.approved,
        r.risk_verdict.status,
        risk(&r),
        statuses(&r)
    );
    (r, status, reason)
}

/// A Raydium CLMM `decrease_liquidity_v2` — granted, grounded, minimums
/// non-zero — whose declaration's only effect line named no account until
/// Round 36 ("withdraws funds and transfers them out of the pool to the
/// involved accounts"), beside a sibling that sends 5 SOL of the owner's wallet to
/// someone else. L4 refuses it and names the amount. Before Round 34 L4
/// passed it, and so did L5 and the Risk Engine (L7): the sibling transfer
/// was refused by nothing.
#[tokio::test]
async fn a_signers_wallet_drained_beside_a_withdrawal_that_names_no_account_is_refused() {
    let (r, status, reason) = drained_withdrawal(CLMM).await;
    assert_eq!(status, LayerStatus::Failed, "L4: {reason}");
    assert!(
        // Round 36 (F-005): the declaration now names the accounts it
        // debits (docs/audit-r36/declaration-rewrites.json), so the drain is
        // a signer's loss outside every named debit, not under an unscoped
        // one. Refused either way, and the amount is named.
        reason.contains("SignerLamportsOutsideDeclaredDebit") && reason.contains("5000000000"),
        "the drain is not what L4 names: {reason}"
    );
    assert!(!r.approved);
}

/// The same drain beside a Raydium CPMM `withdraw`. (Its LP burn already
/// failed L4 before Round 34 — `UndeclaredBurn`: the declaration states no
/// burn — so here the test is that the drain itself is named.)
#[tokio::test]
async fn a_signers_wallet_drained_beside_a_cpmm_withdrawal_is_named() {
    let (_, status, reason) = drained_withdrawal(CPMM).await;
    assert_eq!(status, LayerStatus::Failed, "L4: {reason}");
    assert!(
        // Round 36 (F-005): the declaration now names the accounts it
        // debits (docs/audit-r36/declaration-rewrites.json), so the drain is
        // a signer's loss outside every named debit, not under an unscoped
        // one. Refused either way, and the amount is named.
        reason.contains("SignerLamportsOutsideDeclaredDebit") && reason.contains("5000000000"),
        "the drain is not what L4 names: {reason}"
    );
}

/// Control: the CLMM withdrawal without the drain passes L4.
#[tokio::test]
async fn the_same_withdrawal_without_the_drain_passes_l4() {
    let (c, ixs) = withdrawal(CLMM, false);
    let r = verify(c, OWNER, &ixs, 0, "withdraw").await;
    let (status, reason) = layer(&r, "L4");
    eprintln!("[R33-5 control] {} | L4: {reason}", statuses(&r));
    assert_eq!(status, LayerStatus::Passed, "L4: {reason}");
}

// ─── R33-6: rent paid into a created account another program owns ─────────

/// A program the transaction hands the signer's lamports to.
const FOREIGN: &str = "Fore1gnProgram11111111111111111111111111111";
const BOB: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
/// 1 MiB: the rent-exempt minimum of its data is 7.30 SOL.
const BIG: u64 = 1 << 20;

fn rent_exempt(data_len: u64) -> u64 {
    (128 + data_len) * 3_480 * 2
}

/// `Pubkey::create_with_seed`.
fn with_seed(base: &str, seed: &str, owner: &str) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(pk(base).as_bytes());
    h.update(seed.as_bytes());
    h.update(pk(owner).as_bytes());
    bs58::encode(h.finalize()).into_string()
}

/// System `CreateAccountWithSeed`: the new account need not sign.
fn create_with_seed(base: &str, seed: &str, lamports: u64, space: u64, owner: &str) -> Vec<u8> {
    let mut d = vec![3u8, 0, 0, 0];
    d.extend_from_slice(pk(base).as_bytes());
    d.extend_from_slice(&(seed.len() as u64).to_le_bytes());
    d.extend_from_slice(seed.as_bytes());
    d.extend_from_slice(&lamports.to_le_bytes());
    d.extend_from_slice(&space.to_le_bytes());
    d.extend_from_slice(pk(owner).as_bytes());
    d
}

fn programs(c: &mut Cluster) {
    for (p, owner) in [
        (TOKEN, LOADER),
        (TOKEN_2022, LOADER),
        (SYSTEM, NATIVE_LOADER),
        (STAKE, NATIVE_LOADER),
        (FOREIGN, LOADER),
    ] {
        c.set(p, program_account(owner));
    }
    c.set(
        RENT_SYSVAR,
        acct(
            1_009_200,
            "Sysvar1111111111111111111111111111111111111",
            vec![0u8; 17],
        ),
    );
}

/// The wallet's lamports funding a 1 MiB account that `FOREIGN` owns.
fn foreign_rent(c: &mut Cluster, ixs: &mut Vec<Ix>, wallet_after: u64) -> String {
    let created = with_seed(OWNER, "x", FOREIGN);
    let rent = rent_exempt(BIG);
    c.after(&created, acct(rent, FOREIGN, vec![0u8; BIG as usize]));
    c.after(OWNER, acct(wallet_after - rent, SYSTEM, vec![]));
    ixs.push(ix(
        SYSTEM,
        &[
            (OWNER, true, true),
            (&created, false, true),
            (OWNER, true, false),
        ],
        create_with_seed(OWNER, "x", rent, BIG, FOREIGN),
    ));
    created
}

/// A TransferChecked of the owner's tokens to Bob (its declaration debits
/// `accounts.source` only), with the owner's wallet paying 7.30 SOL into a
/// 1 MiB account another program owns. The rent of that account is not the
/// owner's: W19 names the 7.30 SOL. Before Round 34 it was credited as rent
/// of "an account the transaction created", and only an
/// `UndeclaredAccountCreation` warning was left.
#[tokio::test]
async fn rent_paid_into_an_account_another_program_owns_is_the_signers_loss() {
    let mut c = Cluster::default();
    programs(&mut c);
    let (src, dst) = (ata(OWNER, MINT_X), ata(BOB, MINT_X));
    let rent = 2_039_280;
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    c.set(MINT_X, acct(1_461_600, TOKEN, mint(10u64.pow(15), None)));
    c.set(&src, acct(rent, TOKEN, token_account(MINT_X, OWNER, 1_000)));
    c.set(&dst, acct(rent, TOKEN, token_account(MINT_X, BOB, 0)));
    c.after(&src, acct(rent, TOKEN, token_account(MINT_X, OWNER, 900)));
    c.after(&dst, acct(rent, TOKEN, token_account(MINT_X, BOB, 100)));
    let mut data = vec![12u8];
    data.extend_from_slice(&100u64.to_le_bytes());
    data.push(6);
    let mut ixs = vec![ix(
        TOKEN,
        &[
            (&src, false, true),
            (MINT_X, false, false),
            (&dst, false, true),
            (OWNER, true, false),
        ],
        data,
    )];
    foreign_rent(&mut c, &mut ixs, 10 * SOL - FEE);
    let r = verify(c, OWNER, &ixs, 0, "transfer").await;
    let (status, reason) = layer(&r, "L4");
    eprintln!(
        "[R33-6 W19] {} | risk={} [{}] | L4: {reason}",
        statuses(&r),
        r.risk_verdict.status,
        risk(&r)
    );
    assert_eq!(status, LayerStatus::Failed, "L4: {reason}");
    assert!(
        reason.contains("SignerLamportsOutsideDeclaredDebit")
            && reason.contains(&rent_exempt(BIG).to_string()),
        "{reason}"
    );
}

/// InitializeMint2 ("initializes accounts.mint", no debit) for a mint the
/// owner funded earlier.
fn initialize_mint(c: &mut Cluster, m: &str) -> Ix {
    c.set(m, acct(1_461_600, TOKEN, vec![0u8; 82]));
    c.after(m, acct(1_461_600, TOKEN, mint(0, Some(OWNER))));
    let mut data = vec![20u8, 6];
    data.extend_from_slice(pk(OWNER).as_bytes());
    data.push(0);
    ix(TOKEN, &[(m, false, true)], data)
}

/// The same rent under a declaration with no debit at all (InitializeMint2):
/// `UndeclaredSignerLamportDebit`.
#[tokio::test]
async fn rent_paid_into_an_account_another_program_owns_is_a_loss_when_no_debit_is_declared() {
    let mut c = Cluster::default();
    programs(&mut c);
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    let mut ixs = vec![initialize_mint(&mut c, &key(20))];
    foreign_rent(&mut c, &mut ixs, 10 * SOL - FEE);
    let r = verify(c, OWNER, &ixs, 0, "create").await;
    let (status, reason) = layer(&r, "L4");
    eprintln!(
        "[R33-6 no debit] {} | risk={} [{}] | L4: {reason}",
        statuses(&r),
        r.risk_verdict.status,
        risk(&r)
    );
    assert_eq!(status, LayerStatus::Failed, "L4: {reason}");
    assert!(
        reason.contains("UndeclaredSignerLamportDebit")
            && reason.contains(&rent_exempt(BIG).to_string()),
        "{reason}"
    );
}

// ─── R33-7: a co-signer's gain is not the user's ───────────────────────────

/// (a) A fresh keypair co-signs, receives the user's 5 SOL and is handed to
/// another program. Before Round 34 its gain offset the user's loss: the
/// signers' NET loss was zero.
#[tokio::test]
async fn a_fresh_cosigners_gain_does_not_offset_the_users_loss() {
    let cosigner = key(30);
    let mut c = Cluster::default();
    programs(&mut c);
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    let mut ixs = vec![initialize_mint(&mut c, &key(21))];
    c.after(OWNER, acct(10 * SOL - 5 * SOL - FEE, SYSTEM, vec![]));
    c.after(&cosigner, acct(5 * SOL, FOREIGN, vec![]));
    ixs.push(ix(
        SYSTEM,
        &[(OWNER, true, true), (&cosigner, false, true)],
        system_transfer(5 * SOL),
    ));
    let mut assign = vec![1u8, 0, 0, 0];
    assign.extend_from_slice(pk(FOREIGN).as_bytes());
    ixs.push(ix(SYSTEM, &[(&cosigner, true, true)], assign));
    let r = verify(c, OWNER, &ixs, 0, "create").await;
    let (status, reason) = layer(&r, "L4");
    eprintln!(
        "[R33-7a] {} | risk={} [{}] | L4: {reason}",
        statuses(&r),
        r.risk_verdict.status,
        risk(&r)
    );
    assert_eq!(status, LayerStatus::Failed, "L4: {reason}");
    assert!(
        reason.contains("UndeclaredSignerLamportDebit") && reason.contains("5000000000"),
        "{reason}"
    );
}

/// (b) An existing relayer wallet co-signs (and pays the fee) and receives
/// the user's 5 SOL.
#[tokio::test]
async fn a_relayers_gain_does_not_offset_the_users_loss() {
    let relayer = key(31);
    let mut c = Cluster::default();
    programs(&mut c);
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    c.set(&relayer, acct(SOL, SYSTEM, vec![]));
    let mut ixs = vec![initialize_mint(&mut c, &key(22))];
    c.after(OWNER, acct(10 * SOL - 5 * SOL, SYSTEM, vec![]));
    c.after(&relayer, acct(SOL + 5 * SOL - FEE, SYSTEM, vec![]));
    ixs.push(ix(
        SYSTEM,
        &[(OWNER, true, true), (&relayer, false, true)],
        system_transfer(5 * SOL),
    ));
    let r = verify(c, &relayer, &ixs, 0, "create").await;
    let (status, reason) = layer(&r, "L4");
    eprintln!(
        "[R33-7b] {} | risk={} [{}] | L4: {reason}",
        statuses(&r),
        r.risk_verdict.status,
        risk(&r)
    );
    assert_eq!(status, LayerStatus::Failed, "L4: {reason}");
    assert!(
        reason.contains("UndeclaredSignerLamportDebit") && reason.contains("5000000000"),
        "{reason}"
    );
}

/// Control: two signers, and nothing leaves either but the fee its payer
/// pays.
#[tokio::test]
async fn two_signers_paying_only_the_fee_raise_no_lamport_finding() {
    let cosigner = key(32);
    let mut c = Cluster::default();
    programs(&mut c);
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    c.set(&cosigner, acct(SOL, SYSTEM, vec![]));
    let mut ixs = vec![initialize_mint(&mut c, &key(23))];
    c.after(OWNER, acct(10 * SOL - FEE, SYSTEM, vec![]));
    // The co-signer signs a transfer of nothing to the owner.
    ixs.push(ix(
        SYSTEM,
        &[(&cosigner, true, true), (OWNER, false, true)],
        system_transfer(0),
    ));
    let r = verify(c, OWNER, &ixs, 0, "create").await;
    let (_, reason) = layer(&r, "L4");
    eprintln!("[R33-7 control] {} | L4: {reason}", statuses(&r));
    assert!(!reason.contains("SignerLamport"), "{reason}");
}

// ─── R33-14: authorities written into a created native account ─────────────

fn stake_initialize(staker: &str, withdrawer: &str) -> Vec<u8> {
    let mut d = vec![0u8, 0, 0, 0];
    d.extend_from_slice(pk(staker).as_bytes());
    d.extend_from_slice(pk(withdrawer).as_bytes());
    d.extend_from_slice(&[0u8; 48]);
    d
}

fn create_account(lamports: u64, space: u64, owner: &str) -> Vec<u8> {
    let mut d = vec![0u8, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d.extend_from_slice(&space.to_le_bytes());
    d.extend_from_slice(pk(owner).as_bytes());
    d
}

/// System CreateAccount (100 SOL, 200 bytes, the Stake program) — the
/// primary, whose declaration debits `accounts.from` by name — and Stake
/// Initialize naming `authority` as staker and withdrawer beside it.
async fn create_stake(authority: &str) -> VerificationResult {
    let stake = key(40);
    let mut c = Cluster::default();
    programs(&mut c);
    c.set(OWNER, acct(200 * SOL, SYSTEM, vec![]));
    c.after(OWNER, acct(100 * SOL - FEE, SYSTEM, vec![]));
    c.after(
        &stake,
        acct(100 * SOL, STAKE, stake_initialized(authority, authority)),
    );
    let ixs = vec![
        ix(
            SYSTEM,
            &[(OWNER, true, true), (&stake, true, true)],
            create_account(100 * SOL, 200, STAKE),
        ),
        ix(
            STAKE,
            &[(&stake, false, true), (RENT_SYSVAR, false, false)],
            stake_initialize(authority, authority),
        ),
    ];
    verify(c, OWNER, &ixs, 0, "stake").await
}

/// The 100 SOL are handed to whoever the withdrawer is. A withdrawer that
/// does not sign is refused, by name; before Round 34 a created account's
/// authorities were never compared with anything.
#[tokio::test]
async fn a_created_stake_account_authorised_to_a_non_signer_is_refused() {
    let r = create_stake(ATTACKER).await;
    let (status, reason) = layer(&r, "L4");
    eprintln!(
        "[R33-14] {} | risk={} [{}] | L4: {reason}",
        statuses(&r),
        r.risk_verdict.status,
        risk(&r)
    );
    assert_eq!(status, LayerStatus::Failed, "L4: {reason}");
    assert!(
        reason.contains("CreatedAccountAuthorityNotSigner")
            && reason.contains("stake withdrawer")
            && reason.contains(ATTACKER),
        "{reason}"
    );
}

/// Control: authorised to the signer, the stake stays the signer's.
#[tokio::test]
async fn a_created_stake_account_authorised_to_the_signer_raises_nothing() {
    let r = create_stake(OWNER).await;
    let (_, reason) = layer(&r, "L4");
    eprintln!("[R33-14 control] {} | L4: {reason}", statuses(&r));
    assert!(
        !reason.contains("CreatedAccountAuthorityNotSigner") && !reason.contains("SignerLamport"),
        "{reason}"
    );
}

// ─── R33-15: a declared debit of the wallet binds its amount ───────────────

async fn transfer_to_bob(sibling_to_mallory: Option<u64>) -> VerificationResult {
    let mut c = Cluster::default();
    programs(&mut c);
    let to_bob = SOL / 1_000;
    c.set(OWNER, acct(20 * SOL, SYSTEM, vec![]));
    c.set(BOB, acct(SOL, SYSTEM, vec![]));
    c.after(BOB, acct(SOL + to_bob, SYSTEM, vec![]));
    let mut ixs = vec![ix(
        SYSTEM,
        &[(OWNER, true, true), (BOB, false, true)],
        system_transfer(to_bob),
    )];
    match sibling_to_mallory {
        Some(n) => {
            c.set(ATTACKER, acct(SOL, SYSTEM, vec![]));
            c.after(ATTACKER, acct(SOL + n, SYSTEM, vec![]));
            c.after(OWNER, acct(20 * SOL - to_bob - n - FEE, SYSTEM, vec![]));
            ixs.push(ix(
                SYSTEM,
                &[(OWNER, true, true), (ATTACKER, false, true)],
                system_transfer(n),
            ));
        }
        None => c.after(OWNER, acct(20 * SOL - to_bob - FEE, SYSTEM, vec![])),
    }
    verify(c, OWNER, &ixs, 0, "transfer").await
}

/// 0.001 SOL to Bob as the primary and 10 SOL to Mallory beside it: the
/// primary's data states what it debits the wallet, and the wallet lost
/// 10 SOL more. Before Round 34 the declared debit of the wallet excused any
/// amount.
#[tokio::test]
async fn a_declared_wallet_debit_does_not_excuse_more_than_its_stated_amount() {
    let r = transfer_to_bob(Some(10 * SOL)).await;
    let (status, reason) = layer(&r, "L4");
    eprintln!(
        "[R33-15] approved={} {} | risk={} [{}] | L4: {reason}",
        r.approved,
        statuses(&r),
        r.risk_verdict.status,
        risk(&r)
    );
    assert_eq!(status, LayerStatus::Failed, "L4: {reason}");
    assert!(
        reason.contains("SignerLamportsBeyondDeclaredAmount") && reason.contains("10000000000"),
        "{reason}"
    );
}

/// Control: the transfer alone.
#[tokio::test]
async fn a_declared_wallet_debit_of_its_stated_amount_raises_nothing() {
    let r = transfer_to_bob(None).await;
    let (status, reason) = layer(&r, "L4");
    eprintln!("[R33-15 control] {} | L4: {reason}", statuses(&r));
    assert_eq!(status, LayerStatus::Passed, "L4: {reason}");
}
