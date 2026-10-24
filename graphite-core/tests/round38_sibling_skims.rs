//! Requires the `rpc` feature: every verdict here rests on a simulated diff.
#![cfg(feature = "rpc")]

//! Round 38 (R37-1): a swap or a withdrawal skimmed by a sibling instruction.
//!
//! Round 36 tied a swap to its request by the route's decoded amounts and
//! the fee payer's NET change, and a withdrawal by its recipient's net
//! credit. A sibling instruction can take value out of the same accounts
//! and leave the net inside every bound. End to end here: a signed legacy
//! artifact, simulated by a loopback mock RPC, through `verify_async`.
//! Everything is a loopback socket; no public endpoint is contacted.

use graphite_core::confidence_engine::TrustTier;
use graphite_core::find_program_address;
use graphite_core::manifest::{load_seed_manifests, InstructionDef};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::solana_types::Pubkey;
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{
    ExecutionDecision, ExtractedParameters, GraphiteCore, LayerStatus, ProposedIntent,
    UnobservedCode, VerificationInput, VerificationResult,
};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

const SYSTEM: &str = "11111111111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const NATIVE_LOADER: &str = "NativeLoader1111111111111111111111111111111";
const MEMO: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

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
        // Confidence is not what these tests are about: with no L3 baseline
        // yet it sits near 0.44, which a mature baseline raises in
        // production. The bar is set below it, as in
        // staking_withdrawal_destination.rs, so the decision shows what the
        // other layers and the binding do.
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
// ─── Builders ──────────────────────────────────────────────────────────────

const NATIVE_MINT: &str = "So11111111111111111111111111111111111111112";
const RENT: u64 = 2_039_280;

/// SPL Token `TransferChecked { amount, decimals }`.
fn transfer_checked(amount: u64, decimals: u8) -> Vec<u8> {
    let mut d = vec![12u8];
    d.extend_from_slice(&amount.to_le_bytes());
    d.push(decimals);
    d
}

fn swap_request(amount: &str, input: &str, output: &str) -> Option<ExtractedParameters> {
    Some(ExtractedParameters {
        amount: Some(amount.to_string()),
        input_token: Some(input.to_string()),
        output_token: Some(output.to_string()),
        ..Default::default()
    })
}

/// What rides beside the route.
#[derive(Clone, Copy, PartialEq)]
enum Beside {
    Nothing,
    /// A memo.
    Memo,
    /// The owner wraps the route's SOL into their own wSOL account first.
    OwnWrap,
    /// The owner closes their own wSOL account to their wallet after the
    /// route, unwrapping its output.
    OwnUnwrap,
    /// A TransferChecked of the route's output from the owner's account to
    /// the attacker's.
    OutputSkim(u64),
    /// A System transfer from the owner's wallet to the attacker.
    InputSkim(u64),
    /// An `Approve` of the owner's output account to the attacker.
    ApproveToAttacker,
    /// The attacker's own program, invoked beside the route with the owner
    /// signing, moves this much of the output by CPI: no top-level movement
    /// the bytes show, only the diff.
    CpiSkim(u64),
}

/// A program somebody deployed.
const FOREIGN: &str = "Fore1gnProgram11111111111111111111111111111";

const JUPITER: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";

/// A Jupiter v6 `route` of `amount_in` of `in_mint` (wSOL when
/// `NATIVE_MINT`) through one Raydium step quoted at `quoted_out` of
/// `out_mint` with 50 bps of slippage, the venue paying `gross` into the
/// owner's output account, with `beside` added. The venue's two vaults ride
/// as the route's remaining accounts, so the simulation shows where the
/// value comes from.
///
/// Jupiter, not Raydium CPMM: CPMM's `swap_base_input` declares no debit of
/// its input account, so L4 refuses an honest CPMM swap
/// (`SignerTokenDebitUnderUnscopedDebit`) and a skim beside it never reaches
/// the binding. Jupiter's `route` names its debit
/// (`debits accounts.user_source_token_account by data.in_amount`).
fn jupiter_swap(
    in_mint: &str,
    out_mint: &str,
    amount_in: u64,
    quoted_out: u64,
    gross: u64,
    beside: Beside,
) -> (Cluster, Vec<Ix>) {
    let mut c = Cluster::default();
    let d = def(JUPITER, "route");
    let (src, dst) = (ata(OWNER, in_mint), ata(OWNER, out_mint));
    let keys = accounts_for(
        JUPITER,
        &d,
        &[
            ("token_program", TOKEN.to_string()),
            ("user_transfer_authority", OWNER.to_string()),
            ("user_source_token_account", src.clone()),
            ("user_destination_token_account", dst.clone()),
            ("destination_token_account", JUPITER.to_string()),
            ("destination_mint", out_mint.to_string()),
            ("platform_fee_account", JUPITER.to_string()),
            ("program", JUPITER.to_string()),
        ],
    );
    let mut data = hex_to_bytes(&d.discriminator);
    data.extend_from_slice(&1u32.to_le_bytes()); // one step
    data.extend_from_slice(&[7, 100, 0, 1]); // Raydium (unit), 100%, 0 → 1
    data.extend_from_slice(&amount_in.to_le_bytes());
    data.extend_from_slice(&quoted_out.to_le_bytes());
    data.extend_from_slice(&50u16.to_le_bytes());
    data.push(0);
    let pool = key(90);
    let (in_vault, out_vault) = (key(91), key(92));
    let mut accounts: Vec<(String, bool, bool)> = d
        .accounts
        .iter()
        .zip(&keys)
        .map(|(a, k)| (k.clone(), a.is_signer, a.is_writable))
        .collect();
    accounts.push((in_vault.clone(), false, true));
    accounts.push((out_vault.clone(), false, true));
    let primary = Ix {
        program: JUPITER.to_string(),
        accounts,
        data,
    };
    for (a, k) in d.accounts.iter().zip(&keys) {
        if k != OWNER && !a.is_signer && k != JUPITER && k != TOKEN && k != out_mint {
            c.set(k, acct(5 * SOL, JUPITER, vec![1u8; 64]));
        }
    }
    for (p, owner) in [
        (JUPITER, LOADER),
        (TOKEN, LOADER),
        (TOKEN_2022, LOADER),
        (MEMO, LOADER),
        (SYSTEM, NATIVE_LOADER),
    ] {
        c.set(p, program_account(owner));
    }
    for m in [in_mint, out_mint] {
        c.set(m, acct(1_461_600, TOKEN, mint(10u64.pow(15), None)));
    }
    // A wSOL account's lamports are its rent plus the SOL it holds.
    let lamports_of = |m: &str, amount: u64| {
        if m == NATIVE_MINT {
            RENT + amount
        } else {
            RENT
        }
    };
    let reserve = 10u64.pow(12);
    c.set(
        &in_vault,
        acct(
            lamports_of(in_mint, reserve),
            TOKEN,
            token_account(in_mint, &pool, reserve),
        ),
    );
    c.after(
        &in_vault,
        acct(
            lamports_of(in_mint, reserve + amount_in),
            TOKEN,
            token_account(in_mint, &pool, reserve + amount_in),
        ),
    );
    c.set(
        &out_vault,
        acct(
            lamports_of(out_mint, reserve),
            TOKEN,
            token_account(out_mint, &pool, reserve),
        ),
    );
    c.after(
        &out_vault,
        acct(
            lamports_of(out_mint, reserve - gross),
            TOKEN,
            token_account(out_mint, &pool, reserve - gross),
        ),
    );
    // The owner's input account holds 10 units more than the route takes.
    let held = amount_in + 10_000_000;
    let mut wallet_out = FEE;
    let mut ixs = vec![];
    if beside == Beside::OwnWrap {
        // The owner moves `amount_in` lamports into their own wSOL account and
        // syncs it: before the route the account held `held - amount_in`.
        c.set(
            &src,
            acct(
                lamports_of(in_mint, held - amount_in),
                TOKEN,
                token_account(in_mint, OWNER, held - amount_in),
            ),
        );
        wallet_out += amount_in;
        ixs.push(ix(
            SYSTEM,
            &[(OWNER, true, true), (&src, false, true)],
            system_transfer(amount_in),
        ));
        ixs.push(ix(TOKEN, &[(&src, false, true)], vec![17u8]));
    } else {
        c.set(
            &src,
            acct(
                lamports_of(in_mint, held),
                TOKEN,
                token_account(in_mint, OWNER, held),
            ),
        );
    }
    c.after(
        &src,
        acct(
            lamports_of(in_mint, held - amount_in),
            TOKEN,
            token_account(in_mint, OWNER, held - amount_in),
        ),
    );
    ixs.push(primary);
    c.set(&dst, acct(RENT, TOKEN, token_account(out_mint, OWNER, 0)));
    let mut kept = gross;
    match beside {
        Beside::Memo => ixs.push(ix(MEMO, &[(OWNER, true, false)], b"swap".to_vec())),
        Beside::OutputSkim(skim) => {
            let theirs = ata(ATTACKER, out_mint);
            c.set(
                &theirs,
                acct(RENT, TOKEN, token_account(out_mint, ATTACKER, 0)),
            );
            c.after(
                &theirs,
                acct(RENT, TOKEN, token_account(out_mint, ATTACKER, skim)),
            );
            kept -= skim;
            ixs.push(ix(
                TOKEN,
                &[
                    (&dst, false, true),
                    (out_mint, false, false),
                    (&theirs, false, true),
                    (OWNER, true, false),
                ],
                transfer_checked(skim, 6),
            ));
        }
        Beside::InputSkim(skim) => {
            wallet_out += skim;
            c.after(ATTACKER, acct(SOL + skim, SYSTEM, vec![]));
            ixs.push(ix(
                SYSTEM,
                &[(OWNER, true, true), (ATTACKER, false, true)],
                system_transfer(skim),
            ));
        }
        Beside::ApproveToAttacker => {
            let mut d = vec![4u8];
            d.extend_from_slice(&u64::MAX.to_le_bytes());
            ixs.push(ix(
                TOKEN,
                &[
                    (&dst, false, true),
                    (ATTACKER, false, false),
                    (OWNER, true, false),
                ],
                d,
            ));
        }
        Beside::CpiSkim(skim) => {
            let theirs = ata(ATTACKER, out_mint);
            c.set(FOREIGN, program_account(LOADER));
            c.set(
                &theirs,
                acct(RENT, TOKEN, token_account(out_mint, ATTACKER, 0)),
            );
            c.after(
                &theirs,
                acct(RENT, TOKEN, token_account(out_mint, ATTACKER, skim)),
            );
            kept -= skim;
            ixs.push(ix(
                FOREIGN,
                &[
                    (&dst, false, true),
                    (&theirs, false, true),
                    (OWNER, true, false),
                    (TOKEN, false, false),
                ],
                vec![1, 2, 3],
            ));
        }
        Beside::OwnUnwrap => ixs.push(ix(
            TOKEN,
            &[
                (&dst, false, true),
                (OWNER, false, true),
                (OWNER, true, false),
            ],
            vec![9u8],
        )),
        Beside::Nothing | Beside::OwnWrap => {}
    }
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    c.set(ATTACKER, acct(SOL, SYSTEM, vec![]));
    if beside == Beside::OwnUnwrap {
        // Closed: its rent and the SOL the route paid into it go to the wallet.
        c.post.insert(dst.clone(), None);
        c.after(
            OWNER,
            acct(10 * SOL - wallet_out + RENT + gross, SYSTEM, vec![]),
        );
    } else {
        c.after(
            &dst,
            acct(
                lamports_of(out_mint, kept),
                TOKEN,
                token_account(out_mint, OWNER, kept),
            ),
        );
        c.after(OWNER, acct(10 * SOL - wallet_out, SYSTEM, vec![]));
    }
    (c, ixs)
}

fn primary_of(ixs: &[Ix], program: &str) -> usize {
    ixs.iter().position(|i| i.program == program).unwrap()
}

fn record(tag: &str, r: &VerificationResult) {
    let l4 = r
        .layers
        .iter()
        .find(|l| l.layer.starts_with("L4"))
        .map(|l| l.reason.chars().take(700).collect::<String>())
        .unwrap_or_default();
    eprintln!(
        "[R37-1 {tag}] decision={:?} | {} | risk: {} | L4: {l4}",
        r.decision,
        statuses(r),
        risk(r),
    );
}

fn names(r: &VerificationResult, needle: &str) -> bool {
    risk(r).contains(needle) || r.layers.iter().any(|l| l.reason.contains(needle))
}

// ─── Swaps ─────────────────────────────────────────────────────────────────

/// The control: 1 of MINT_Y quoted at 100 of MINT_X (minimum 99.5), 100
/// delivered.
#[tokio::test]
async fn an_honest_swap_is_executable() {
    let (c, ixs) = jupiter_swap(
        MINT_Y,
        MINT_X,
        1_000_000,
        100_000_000,
        100_000_000,
        Beside::Nothing,
    );
    let p = primary_of(&ixs, JUPITER);
    let r = verify(c, OWNER, &ixs, p, "swap", swap_request("1", MINT_Y, MINT_X)).await;
    record("honest", &r);
    assert_eq!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{}",
        risk(&r)
    );
}

/// The control: a memo beside the route.
#[tokio::test]
async fn a_swap_beside_a_memo_is_executable() {
    let (c, ixs) = jupiter_swap(
        MINT_Y,
        MINT_X,
        1_000_000,
        100_000_000,
        100_000_000,
        Beside::Memo,
    );
    let p = primary_of(&ixs, JUPITER);
    let r = verify(c, OWNER, &ixs, p, "swap", swap_request("1", MINT_Y, MINT_X)).await;
    record("memo", &r);
    assert_eq!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "memo: {}",
        risk(&r)
    );
}

/// Controls for the binding: the owner wrapping their own SOL into their own
/// wSOL account before the route, and closing their own wSOL account to
/// their wallet after a swap into SOL. Neither moves value away from the
/// signer, and the binding holds both: it raises no finding and leaves no
/// `intent_parameters` residual.
///
/// Not executable end to end, and not because of the binding. L4 judges the
/// whole transaction's diff against the PRIMARY's declaration: Jupiter's
/// `route` declares no closure, so the unwrap is `UndeclaredAccountClosure`;
/// and a wrap's SOL leaves the wallet as lamports and reaches the vault as a
/// declared wSOL debit, which a net diff cannot tell from the wallet paying
/// the vault directly (`SignerLamportsOutsideDeclaredDebit`). That is a false
/// refusal L4 had before Round 38, recorded in the Round 38 report as a
/// documented limitation; it is not asserted here.
#[tokio::test]
async fn the_owners_own_wrap_and_unwrap_are_bound() {
    for (tag, (c, ixs), request) in [
        (
            "own wrap",
            jupiter_swap(
                NATIVE_MINT,
                MINT_X,
                SOL,
                100_000_000,
                100_000_000,
                Beside::OwnWrap,
            ),
            swap_request("1", "SOL", MINT_X),
        ),
        (
            "own unwrap",
            jupiter_swap(MINT_Y, NATIVE_MINT, 1_000_000, SOL, SOL, Beside::OwnUnwrap),
            swap_request("1", MINT_Y, "SOL"),
        ),
    ] {
        let p = primary_of(&ixs, JUPITER);
        let r = verify(c, OWNER, &ixs, p, "swap", request).await;
        record(tag, &r);
        assert!(
            !names(&r, "IntentMismatch") && !names(&r, "SwapUnderbounded"),
            "{tag}: the binding refused the owner's own account: {}",
            risk(&r)
        );
        assert!(
            !r.scope
                .unobserved_codes()
                .contains(&UnobservedCode::IntentParameters),
            "{tag}: the binding left it unbound: {:?}",
            r.scope.unobserved()
        );
    }
}

/// R37-1, output skim. The route's minimum is 50 (quoted 50.25, 50 bps);
/// it pays 100 into the owner's account and a sibling TransferChecked sends
/// 49.6 of it to the attacker. The owner's net, 50.4, meets the minimum and
/// is within the default 1% of itself.
#[tokio::test]
async fn a_swap_output_skimmed_by_a_sibling_is_not_bound() {
    let (c, ixs) = jupiter_swap(
        MINT_Y,
        MINT_X,
        1_000_000,
        50_251_257,
        100_000_000,
        Beside::OutputSkim(49_600_000),
    );
    let p = primary_of(&ixs, JUPITER);
    let r = verify(c, OWNER, &ixs, p, "swap", swap_request("1", MINT_Y, MINT_X)).await;
    record("output skim", &r);
    assert_ne!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{}",
        risk(&r)
    );
    assert!(
        names(&r, "IntentMismatch") || names(&r, "SwapUnderbounded"),
        "the skim is not named: {}",
        risk(&r)
    );
}

/// R37-1, input skim. The request spends 1 SOL; the route spends 0.001 of
/// it, and a sibling System transfer sends the other 0.999 to the attacker.
#[tokio::test]
async fn a_swap_input_skimmed_by_a_sibling_is_not_bound() {
    let (c, ixs) = jupiter_swap(
        NATIVE_MINT,
        MINT_X,
        1_000_000,
        50_000_000,
        50_000_000,
        Beside::InputSkim(999_000_000),
    );
    let p = primary_of(&ixs, JUPITER);
    let r = verify(c, OWNER, &ixs, p, "swap", swap_request("1", "SOL", MINT_X)).await;
    record("input skim", &r);
    assert_ne!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{}",
        risk(&r)
    );
    assert!(
        names(&r, "IntentMismatch"),
        "the binding does not name the skim: {}",
        risk(&r)
    );
}

// ─── Withdrawals ───────────────────────────────────────────────────────────

/// A Raydium CLMM `decrease_liquidity_v2` with minimums 400 of MINT_X and 600
/// of MINT_Y, the pool paying `gross_x` and 606 into the owner's own
/// associated token accounts, and with `skim`, a sibling TransferChecked of
/// that many MINT_X from the owner's account to the attacker's.
fn clmm_withdrawal(gross_x: u64, skim: Option<u64>) -> (Cluster, Vec<Ix>) {
    let mut c = Cluster::default();
    let d = def(CLMM, "decrease_liquidity_v2");
    let keys = accounts_for(
        CLMM,
        &d,
        &[
            ("nft_owner", OWNER.to_string()),
            ("vault_0_mint", MINT_X.to_string()),
            ("vault_1_mint", MINT_Y.to_string()),
            ("recipient_token_account_0", ata(OWNER, MINT_X)),
            ("recipient_token_account_1", ata(OWNER, MINT_Y)),
            ("memo_program", MEMO.to_string()),
        ],
    );
    let slot = |role: &str| keys[d.accounts.iter().position(|a| a.name == role).unwrap()].clone();
    let mut data = hex_to_bytes(&d.discriminator);
    data.extend_from_slice(&100u128.to_le_bytes());
    data.extend_from_slice(&400u64.to_le_bytes());
    data.extend_from_slice(&600u64.to_le_bytes());
    let primary = Ix {
        program: CLMM.to_string(),
        accounts: d
            .accounts
            .iter()
            .zip(&keys)
            .map(|(a, k)| (k.clone(), a.is_signer, a.is_writable))
            .collect(),
        data,
    };
    for (a, k) in d.accounts.iter().zip(&keys) {
        if k != OWNER && !a.is_signer {
            c.set(k, acct(5 * SOL, CLMM, vec![1u8; 64]));
        }
    }
    for (p, owner) in [
        (CLMM, LOADER),
        (TOKEN, LOADER),
        (TOKEN_2022, LOADER),
        (MEMO, LOADER),
        (SYSTEM, NATIVE_LOADER),
    ] {
        c.set(p, program_account(owner));
    }
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    c.after(OWNER, acct(10 * SOL - FEE, SYSTEM, vec![]));
    c.set(ATTACKER, acct(SOL, SYSTEM, vec![]));
    c.set(MINT_X, acct(1_461_600, TOKEN, mint(10u64.pow(15), None)));
    c.set(MINT_Y, acct(1_461_600, TOKEN, mint(10u64.pow(15), None)));
    let pool = key(90);
    let kept_x = gross_x - skim.unwrap_or(0);
    for (mint_key, vault, recipient, gross, kept) in [
        (
            MINT_X,
            slot("token_vault_0"),
            slot("recipient_token_account_0"),
            gross_x,
            kept_x,
        ),
        (
            MINT_Y,
            slot("token_vault_1"),
            slot("recipient_token_account_1"),
            606,
            606,
        ),
    ] {
        c.set(
            &vault,
            acct(RENT, TOKEN, token_account(mint_key, &pool, 1_000_000)),
        );
        c.after(
            &vault,
            acct(
                RENT,
                TOKEN,
                token_account(mint_key, &pool, 1_000_000 - gross),
            ),
        );
        c.set(
            &recipient,
            acct(RENT, TOKEN, token_account(mint_key, OWNER, 0)),
        );
        c.after(
            &recipient,
            acct(RENT, TOKEN, token_account(mint_key, OWNER, kept)),
        );
    }
    for (a, k) in d.accounts.iter().zip(&keys) {
        if a.is_writable && c.pre.get(k).is_some_and(|x| x.owner == CLMM) {
            c.after(k, acct(5 * SOL, CLMM, vec![2u8; 64]));
        }
    }
    let mut ixs = vec![primary];
    if let Some(skim) = skim {
        let theirs = ata(ATTACKER, MINT_X);
        c.set(
            &theirs,
            acct(RENT, TOKEN, token_account(MINT_X, ATTACKER, 0)),
        );
        c.after(
            &theirs,
            acct(RENT, TOKEN, token_account(MINT_X, ATTACKER, skim)),
        );
        let mine = ata(OWNER, MINT_X);
        ixs.push(ix(
            TOKEN,
            &[
                (&mine, false, true),
                (MINT_X, false, false),
                (&theirs, false, true),
                (OWNER, true, false),
            ],
            transfer_checked(skim, 6),
        ));
    }
    (c, ixs)
}

/// The control: 404 of MINT_X and 606 of MINT_Y delivered, minimums 400 and
/// 600, nothing beside it.
#[tokio::test]
async fn an_honest_withdrawal_is_executable() {
    let (c, ixs) = clmm_withdrawal(404, None);
    let r = verify(c, OWNER, &ixs, 0, "withdraw", None).await;
    record("honest withdrawal", &r);
    assert_eq!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{}",
        risk(&r)
    );
}

/// R37-1, withdrawal. The pool pays 500 of MINT_X into the owner's account
/// and a sibling sends 96 of it to the attacker: the owner's net, 404, still
/// meets the minimum of 400 within 1%.
#[tokio::test]
async fn a_withdrawal_skimmed_by_a_sibling_is_not_bound() {
    let (c, ixs) = clmm_withdrawal(500, Some(96));
    let r = verify(c, OWNER, &ixs, 0, "withdraw", None).await;
    record("withdrawal skim", &r);
    assert_ne!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{}",
        risk(&r)
    );
    assert!(
        names(&r, "IntentMismatch") || names(&r, "WithdrawalUnderbounded"),
        "the skim is not named: {}",
        risk(&r)
    );
}

/// R37-1, the other ways a sibling takes value: an `Approve` of the owner's
/// output account to the attacker, and a skim done by CPI from the
/// attacker's own program, which no top-level movement shows. The first is
/// read from the bytes; the second only from the diff (the attacker's account
/// gained the output mint and is neither the owner's nor the route's).
#[tokio::test]
async fn an_approval_or_a_cpi_skim_beside_a_swap_is_not_bound() {
    for (tag, beside) in [
        ("approve", Beside::ApproveToAttacker),
        ("cpi skim", Beside::CpiSkim(49_600_000)),
    ] {
        let (c, ixs) = jupiter_swap(MINT_Y, MINT_X, 1_000_000, 50_251_257, 100_000_000, beside);
        let p = primary_of(&ixs, JUPITER);
        let r = verify(c, OWNER, &ixs, p, "swap", swap_request("1", MINT_Y, MINT_X)).await;
        record(tag, &r);
        assert_ne!(
            r.decision,
            ExecutionDecision::ExecutableApproved,
            "{tag}: {}",
            risk(&r)
        );
        assert!(
            names(&r, "IntentMismatch"),
            "{tag}: the binding does not name it: {}",
            risk(&r)
        );
    }
}
