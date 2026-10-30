//! Requires the `rpc` feature: every verdict here rests on a simulated diff.
#![cfg(feature = "rpc")]

//! Round 41: two false refusals the live mainnet runner found (run
//! 41120603876, 2026-10-30), each reproduced end to end through
//! `verify_async` against a loopback mock RPC, with the attacks each fix must
//! keep refusing.
//!
//! D-20, wrapped SOL. An honest SOL -> token Jupiter `route` in the ordinary
//! wallet shape — the wallet's wSOL associated token account created
//! (`CreateIdempotent`), funded by a System `Transfer` of exactly the route's
//! `in_amount`, `SyncNative`, the route spending it, `CloseAccount` back to
//! the wallet — was `blocked` at L4: `SignerLamportsOutsideDeclaredDebit:
//! 605263158 lamports left a signer's own wallet`. The SOL the route spends
//! leaves the wallet as lamports into the wallet's own wSOL account and
//! leaves THAT account by the route's declared input debit; the net diff
//! showed only the wallet's loss.
//!
//! D-21, the ATA program's Token-2022 CPI. An honest 1-lamport System
//! transfer with an ATA `CreateIdempotent` for a Token-2022 mint beside it
//! was `blocked` by the Risk Engine: `AuthorityHijack: observed CPI (not
//! declared by the caller): CPI target 'TokenzQd' is a token program from
//! untrusted root '11111111'`. The simulator's callees were judged as one set
//! against the PRIMARY (System), though they ran under the ATA instruction,
//! whose manifest declares them.
//!
//! Every attack runs under the configurations Round 39's campaigns iterate
//! (`CONFIGS`: the defaults, every waiver at once, the census imported under
//! Gaming) and under the built-in default profile (Treasury) on a fresh Core.
//! Everything is a loopback socket; no public endpoint is contacted.

use graphite_core::confidence_engine::TrustTier;
use graphite_core::find_program_address;
use graphite_core::manifest::{load_seed_manifests, InstructionDef};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::solana_types::Pubkey;
use graphite_core::state_diff::L4Relaxations;
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{
    ExecutionDecision, ExtractedParameters, GraphiteCore, LayerStatus, ObservationPolicy,
    ProposedIntent, VerificationInput, VerificationResult,
};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

const SYSTEM: &str = "11111111111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const COMPUTE_BUDGET: &str = "ComputeBudget111111111111111111111111111111";
const LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const NATIVE_LOADER: &str = "NativeLoader1111111111111111111111111111111";
const MEMO: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const JUPITER: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const NATIVE_MINT: &str = "So11111111111111111111111111111111111111112";

/// The wallet that signs and pays.
const OWNER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
/// Somebody else.
const ATTACKER: &str = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7";
/// The honest transfer's recipient.
const RECIPIENT: &str = "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T";
/// A program somebody deployed (unmanifested).
const FOREIGN: &str = "Fore1gnProgram11111111111111111111111111111";
/// The swap's output mint (SPL Token).
const MINT_X: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
/// A Token-2022 mint.
const MINT_T22: &str = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo";

const SOL: u64 = 1_000_000_000;
const FEE: u64 = 5_000;
/// The rent-exempt minimum of a 165-byte token account.
const RENT: u64 = 2_039_280;
/// The rent-exempt minimum of a 170-byte Token-2022 account carrying the
/// ImmutableOwner extension.
const RENT_T22: u64 = 2_074_080;
/// The live run's `in_amount`: 0.605263158 SOL.
const AMOUNT_IN: u64 = 605_263_158;
/// The route's quote and what the venue pays (MINT_X base units).
const OUT: u64 = 100_000_000;

fn pk(s: &str) -> Pubkey {
    Pubkey::from_base58(s).unwrap()
}

fn key(seed: u8) -> String {
    let mut k = [0u8; 32];
    k[0] = 0x6C;
    k[1] = seed;
    bs58::encode(k).into_string()
}

fn ata_under(owner: &str, mint: &str, token_program: &str) -> String {
    find_program_address(
        &[
            pk(owner).as_bytes(),
            pk(token_program).as_bytes(),
            pk(mint).as_bytes(),
        ],
        &pk(ATA_PROGRAM),
    )
    .unwrap()
    .0
    .to_base58()
}

fn ata(owner: &str, mint: &str) -> String {
    ata_under(owner, mint, TOKEN)
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

/// A 165-byte SPL Token account; a wSOL one carries its native flag and rent
/// reserve (offset 109: `COption<u64>`), as SPL Token writes it.
fn token_account(mint: &str, owner: &str, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(pk(mint).as_bytes());
    d[32..64].copy_from_slice(pk(owner).as_bytes());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    if mint == NATIVE_MINT {
        d[109..113].copy_from_slice(&1u32.to_le_bytes());
        d[113..121].copy_from_slice(&RENT.to_le_bytes());
    }
    d
}

/// A Token-2022 account carrying ImmutableOwner — what the ATA program
/// creates for a Token-2022 mint: the base layout, the account-type byte (2)
/// and one TLV entry (type 7, length 0).
fn token2022_ata_account(mint: &str, owner: &str) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(pk(mint).as_bytes());
    d[32..64].copy_from_slice(pk(owner).as_bytes());
    d[108] = 1;
    d.push(2);
    d.extend_from_slice(&7u16.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d
}

fn mint(supply: u64, decimals: u8) -> Vec<u8> {
    let mut d = vec![0u8; 82];
    d[36..44].copy_from_slice(&supply.to_le_bytes());
    d[44] = decimals;
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

/// One CPI the simulation reports: the top-level instruction it ran under,
/// the program, its accounts, its data.
#[derive(Clone)]
struct Inner {
    top: usize,
    program: String,
    accounts: Vec<String>,
    data: Vec<u8>,
}

#[derive(Default, Clone)]
struct Cluster {
    keys: Vec<String>,
    pre: HashMap<String, Account>,
    post: HashMap<String, Option<Account>>,
    /// What the simulation reports in `innerInstructions`.
    inner: Vec<Inner>,
}

impl Cluster {
    fn set(&mut self, k: &str, a: Account) {
        self.pre.insert(k.to_string(), a);
    }
    /// A deployed program: a real `Program` account under the upgradeable
    /// loader (with a served `ProgramData` header), or a builtin.
    fn program(&mut self, k: &str, owner: &str) {
        let mut a = Account {
            lamports: 1_141_440,
            owner: owner.to_string(),
            data: vec![],
            executable: true,
        };
        if owner == LOADER {
            let programdata = find_program_address(&[pk(k).as_bytes()], &pk(LOADER))
                .unwrap()
                .0
                .to_base58();
            a.data = 2u32.to_le_bytes().to_vec();
            a.data.extend(pk(&programdata).as_bytes());
            let mut header = 3u32.to_le_bytes().to_vec();
            header.extend(1u64.to_le_bytes());
            header.extend([0u8; 33]);
            self.set(&programdata, acct(1, LOADER, header));
        }
        self.set(k, a);
    }
    fn after(&mut self, k: &str, a: Account) {
        self.post.insert(k.to_string(), Some(a));
    }
    fn closed(&mut self, k: &str) {
        self.post.insert(k.to_string(), None);
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

/// The simulation's `innerInstructions`, in the compiled form, grouped by
/// the top-level instruction each CPI ran under.
fn inner_json(s: &Cluster) -> String {
    let index = |k: &str| {
        s.keys
            .iter()
            .position(|x| x == k)
            .unwrap_or_else(|| panic!("{k} is in the transaction"))
    };
    let mut tops: Vec<usize> = s.inner.iter().map(|i| i.top).collect();
    tops.sort();
    tops.dedup();
    let groups: Vec<String> = tops
        .iter()
        .map(|top| {
            let ixs: Vec<String> = s
                .inner
                .iter()
                .filter(|i| i.top == *top)
                .map(|i| {
                    format!(
                        r#"{{"programIdIndex":{},"accounts":[{}],"data":"{}","stackHeight":2}}"#,
                        index(&i.program),
                        i.accounts
                            .iter()
                            .map(|a| index(a).to_string())
                            .collect::<Vec<_>>()
                            .join(","),
                        bs58::encode(&i.data).into_string()
                    )
                })
                .collect();
            format!(r#"{{"index":{top},"instructions":[{}]}}"#, ixs.join(","))
        })
        .collect();
    format!("[{}]", groups.join(","))
}

fn serve(state: Arc<Mutex<Cluster>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut req = Vec::new();
            let mut buf = vec![0u8; 1 << 16];
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
                "getEpochInfo" => {
                    r#"{"absoluteSlot":1000,"blockHeight":900,"epoch":2,"slotIndex":136,"slotsInEpoch":432000,"transactionCount":1}"#.to_string()
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
                        "innerInstructions":{},"loadedAddresses":{{"writable":[],"readonly":[]}},
                        "accounts":[{}],"returnData":null}}}}"#,
                        balances(true),
                        balances(false),
                        inner_json(&s),
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

fn frame(payer: &str, ixs: &[Ix]) -> (Vec<String>, Vec<u8>) {
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

fn system_create(lamports: u64, space: u64, owner: &str) -> Vec<u8> {
    let mut d = vec![0u8, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d.extend_from_slice(&space.to_le_bytes());
    d.extend_from_slice(pk(owner).as_bytes());
    d
}

fn transfer_checked(amount: u64, decimals: u8) -> Vec<u8> {
    let mut d = vec![12u8];
    d.extend_from_slice(&amount.to_le_bytes());
    d.push(decimals);
    d
}

/// `SetComputeUnitLimit(200_000)`.
fn compute_limit() -> Vec<u8> {
    let mut d = vec![2u8];
    d.extend_from_slice(&200_000u32.to_le_bytes());
    d
}

/// ATA `CreateIdempotent` of `wallet`'s account for `mint` under
/// `token_program`, paid by `payer`.
fn create_idempotent(
    payer: &str,
    account: &str,
    wallet: &str,
    mint: &str,
    token_program: &str,
) -> Ix {
    ix(
        ATA_PROGRAM,
        &[
            (payer, true, true),
            (account, false, true),
            (wallet, false, false),
            (mint, false, false),
            (SYSTEM, false, false),
            (token_program, false, false),
        ],
        vec![1u8],
    )
}

/// SPL Token `CloseAccount` of `account` to `destination`, `owner` signing.
fn close_account(account: &str, destination: &str, owner: &str) -> Ix {
    ix(
        TOKEN,
        &[
            (account, false, true),
            (destination, false, true),
            (owner, true, false),
        ],
        vec![9u8],
    )
}

fn describe(i: &Ix) -> TransactionInstruction {
    TransactionInstruction {
        program_id: i.program.clone(),
        instruction_discriminator: hex::encode(&i.data[..i.data.len().min(4)]),
        account_addresses: i.accounts.iter().map(|a| a.0.clone()).collect(),
        cpi_targets: vec![],
    }
}

// ─── The core under test ───────────────────────────────────────────────────

/// Which operator configuration the verdict is reached under (Round 39's
/// `Waivers`).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Waivers {
    /// The production defaults, under the Round 38 harnesses' confidence bar
    /// (`Custom { 0.40, OfficialManifest }`).
    None,
    /// Every operator waiver and opt-out at once.
    All,
    /// The production defaults after `graphite evidence import-census`,
    /// under the built-in Gaming profile.
    Imported,
    /// The production defaults on a fresh Core under a built-in profile.
    Fresh(WalletProfile),
}

/// Round 39's `CONFIGS`.
const CONFIGS: [Waivers; 3] = [Waivers::None, Waivers::All, Waivers::Imported];

/// What every attack runs under: `CONFIGS` and the default built-in profile.
const ATTACK_CONFIGS: [Waivers; 4] = [
    Waivers::None,
    Waivers::All,
    Waivers::Imported,
    Waivers::Fresh(WalletProfile::Treasury),
];

fn core_for(endpoint: String, waivers: Waivers) -> (GraphiteCore, WalletProfile) {
    let mut core = match waivers {
        Waivers::All => GraphiteCore::new_without_plugins(),
        _ => GraphiteCore::new(),
    };
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint,
        timeout: std::time::Duration::from_secs(10),
        max_retries: 0,
        ..Default::default()
    }));
    if waivers == Waivers::Imported {
        let plan = graphite_core::census_import::import_embedded_into(&mut core)
            .expect("the embedded census imports");
        assert!(!plan.imports.is_empty(), "the census imported nothing");
    }
    let profile = match waivers {
        Waivers::Imported => WalletProfile::Gaming,
        Waivers::Fresh(profile) => profile,
        Waivers::None => WalletProfile::Custom {
            min_confidence: 0.40,
            min_trust_tier: TrustTier::OfficialManifest,
        },
        Waivers::All => {
            core.set_l4_relaxations(L4Relaxations {
                unreadable_value_declarations: true,
                signer_lamports_outside_declared_debit: true,
            });
            core.set_allow_unbounded_withdrawals(true);
            core.set_allow_durable_nonce(true);
            core.set_observation_policy(ObservationPolicy::OperatorBootstrap);
            WalletProfile::Custom {
                min_confidence: 0.0,
                min_trust_tier: TrustTier::Unknown,
            }
        }
    };
    (core, profile)
}

/// Verify `ixs[primary]` under `intent`, the others declared as siblings.
async fn verify(
    mut cluster: Cluster,
    ixs: &[Ix],
    primary: usize,
    intent: &str,
    extracted: Option<ExtractedParameters>,
    waivers: Waivers,
) -> VerificationResult {
    let (keys, bytes) = frame(OWNER, ixs);
    cluster.keys = keys;
    let endpoint = serve(Arc::new(Mutex::new(cluster)));
    let (core, profile) = core_for(endpoint, waivers);
    let p = &ixs[primary];
    let discriminator = load_seed_manifests()
        .get(&p.program)
        .and_then(|m| {
            m.instructions
                .iter()
                .find(|d| p.data.starts_with(&hex_to_bytes(&d.discriminator)))
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
        instruction_discriminator: discriminator,
        account_addresses: p.accounts.iter().map(|a| a.0.clone()).collect(),
        instruction_data: Some(p.data.clone()),
        cpi_targets: vec![],
        wallet_profile: profile,
        behavior_evidence: BehaviorEvidence::default(),
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

fn statuses(r: &VerificationResult) -> String {
    r.layers
        .iter()
        .map(|l| {
            if l.status == LayerStatus::Failed {
                let reason: String = l.reason.chars().take(600).collect();
                format!("{}={:?} ({reason})", l.layer, l.status)
            } else {
                format!("{}={:?}", l.layer, l.status)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn l4(r: &VerificationResult) -> String {
    r.layers
        .iter()
        .find(|l| l.layer.starts_with("L4"))
        .map(|l| format!("{:?}: {}", l.status, l.reason))
        .unwrap_or_default()
}

fn record(tag: &str, r: &VerificationResult) {
    eprintln!(
        "[R41 {tag}] decision={:?} confidence={:.4} | {} | L4: {} | risk: {} | unobserved: {:?}",
        r.decision,
        r.confidence,
        statuses(r),
        l4(r),
        risk(r),
        r.scope.unobserved_codes()
    );
}

fn assert_executable(tag: &str, r: &VerificationResult) {
    record(tag, r);
    assert_eq!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{tag}: the honest shape was refused: {} | {}",
        statuses(r),
        risk(r)
    );
    assert!(r.executable, "{tag}");
}

/// Every case is run and recorded before any assertion, so one executable
/// attack does not hide the outcome of the next.
#[derive(Default)]
struct Outcomes(Vec<String>);

impl Outcomes {
    fn refused(&mut self, tag: &str, r: &VerificationResult) {
        record(tag, r);
        if r.decision == ExecutionDecision::ExecutableApproved || r.executable {
            self.0.push(tag.to_string());
        }
    }
    fn assert_none_executable(self) {
        assert!(
            self.0.is_empty(),
            "attacks that reached executable_approved: {:#?}",
            self.0
        );
    }
}

fn names(r: &VerificationResult, needle: &str) -> bool {
    risk(r).contains(needle) || r.layers.iter().any(|l| l.reason.contains(needle))
}

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

fn base_programs(c: &mut Cluster) {
    for (p, owner) in [
        (JUPITER, LOADER),
        (TOKEN, LOADER),
        (TOKEN_2022, LOADER),
        (MEMO, LOADER),
        (FOREIGN, LOADER),
        (ATA_PROGRAM, LOADER),
        (SYSTEM, NATIVE_LOADER),
        (COMPUTE_BUDGET, NATIVE_LOADER),
    ] {
        c.program(p, owner);
    }
}

// ─── D-20: a SOL -> token swap through the wallet's own wSOL account ───────

/// The shapes the wrap-and-swap is built in.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Wrap {
    /// The live shape: Compute Budget; `CreateIdempotent` of the wallet's
    /// wSOL ATA; a System `Transfer` of exactly `in_amount` into it;
    /// `SyncNative`; the route spending it; `CloseAccount` back to the
    /// wallet. The wSOL account exists only inside the transaction.
    Honest,
    /// The wallet's wSOL ATA already exists and stays: the wrap, `SyncNative`
    /// and the route, no create and no close (Round 38's `OwnWrap`).
    HonestExisting,
    /// `in_amount + x` wrapped; a `TransferChecked` beside the route moves
    /// the excess `x` wSOL to the attacker's wSOL account.
    OverWrapWsolSkim(u64),
    /// `in_amount + x` wrapped; the close returns `x` with the rent, and a
    /// System transfer beside it sends `x` to the attacker.
    OverWrapLamportSkim(u64),
    /// The wrap goes into a wSOL account the ATTACKER owns, which the route
    /// names as its source.
    IntoForeignSource,
    /// The wrap goes into a wSOL account the attacker owns, which keeps it;
    /// the route spends the wallet's other wSOL account.
    IntoForeignKept,
    /// The wallet's wSOL ATA is closed to the attacker (its rent goes there).
    CloseToStranger,
    /// A second System transfer, of `x`, from the wallet to the attacker.
    SecondTransfer(u64),
    /// The route spends the wallet's OTHER wSOL account; the wrapped one is
    /// closed to the attacker with everything wrapped into it.
    RouteSpendsOtherWsol,
}

/// The wallet's other, pre-existing wSOL account (not an ATA), holding
/// enough to pay the route.
fn other_wsol() -> String {
    key(60)
}

/// A Jupiter v6 `route` of `AMOUNT_IN` lamports of SOL for MINT_X (quoted
/// and paid `OUT`), in the `shape` given. Returns the cluster, the
/// instructions and the index of the route.
fn wrap_swap(shape: Wrap) -> (Cluster, Vec<Ix>, usize) {
    let mut c = Cluster::default();
    base_programs(&mut c);
    let d = def(JUPITER, "route");
    let wsol = ata(OWNER, NATIVE_MINT);
    let foreign = ata(ATTACKER, NATIVE_MINT);
    let other = other_wsol();
    let dst = ata(OWNER, MINT_X);
    let src = match shape {
        Wrap::IntoForeignSource => foreign.clone(),
        Wrap::IntoForeignKept | Wrap::RouteSpendsOtherWsol => other.clone(),
        _ => wsol.clone(),
    };
    let wrapped_into = match shape {
        Wrap::IntoForeignSource | Wrap::IntoForeignKept => foreign.clone(),
        _ => wsol.clone(),
    };
    let wrapped = match shape {
        Wrap::OverWrapWsolSkim(x) | Wrap::OverWrapLamportSkim(x) => AMOUNT_IN + x,
        _ => AMOUNT_IN,
    };
    // Whether the wallet's wSOL ATA is created and closed inside the
    // transaction.
    let transient = !matches!(
        shape,
        Wrap::HonestExisting | Wrap::IntoForeignSource | Wrap::IntoForeignKept
    );

    let keys = accounts_for(
        JUPITER,
        &d,
        &[
            ("token_program", TOKEN.to_string()),
            ("user_transfer_authority", OWNER.to_string()),
            ("user_source_token_account", src.clone()),
            ("user_destination_token_account", dst.clone()),
            ("destination_token_account", JUPITER.to_string()),
            ("destination_mint", MINT_X.to_string()),
            ("platform_fee_account", JUPITER.to_string()),
            ("program", JUPITER.to_string()),
        ],
    );
    let mut data = hex_to_bytes(&d.discriminator);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&[7, 100, 0, 1]);
    data.extend_from_slice(&AMOUNT_IN.to_le_bytes());
    data.extend_from_slice(&OUT.to_le_bytes());
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
    let route = Ix {
        program: JUPITER.to_string(),
        accounts,
        data,
    };
    for (a, k) in d.accounts.iter().zip(&keys) {
        if ![OWNER, JUPITER, TOKEN, MINT_X].contains(&k.as_str())
            && *k != src
            && *k != dst
            && !a.is_signer
        {
            c.set(k, acct(5 * SOL, JUPITER, vec![1u8; 64]));
        }
    }
    c.set(NATIVE_MINT, acct(1_461_600, TOKEN, mint(0, 9)));
    c.set(MINT_X, acct(1_461_600, TOKEN, mint(10u64.pow(15), 6)));
    let reserve = 10u64.pow(12);
    c.set(
        &in_vault,
        acct(
            RENT + reserve,
            TOKEN,
            token_account(NATIVE_MINT, &pool, reserve),
        ),
    );
    c.after(
        &in_vault,
        acct(
            RENT + reserve + AMOUNT_IN,
            TOKEN,
            token_account(NATIVE_MINT, &pool, reserve + AMOUNT_IN),
        ),
    );
    c.set(
        &out_vault,
        acct(RENT, TOKEN, token_account(MINT_X, &pool, reserve)),
    );
    c.after(
        &out_vault,
        acct(RENT, TOKEN, token_account(MINT_X, &pool, reserve - OUT)),
    );
    c.set(&dst, acct(RENT, TOKEN, token_account(MINT_X, OWNER, 0)));
    c.after(&dst, acct(RENT, TOKEN, token_account(MINT_X, OWNER, OUT)));
    c.set(ATTACKER, acct(SOL, SYSTEM, vec![]));

    // What the wallet's own lamports do, and what the attacker gains.
    let mut owner_out = FEE + wrapped;
    let mut attacker_in = 0u64;
    let mut ixs = vec![ix(COMPUTE_BUDGET, &[], compute_limit())];
    if transient {
        ixs.push(create_idempotent(OWNER, &wsol, OWNER, NATIVE_MINT, TOKEN));
    }
    ixs.push(ix(
        SYSTEM,
        &[(OWNER, true, true), (&wrapped_into, false, true)],
        system_transfer(wrapped),
    ));
    ixs.push(ix(TOKEN, &[(&wrapped_into, false, true)], vec![17u8]));
    let route_at = ixs.len();
    ixs.push(route);

    match shape {
        Wrap::HonestExisting => {
            // Before and after the transaction: the rent and 1 SOL of wSOL.
            c.set(
                &wsol,
                acct(RENT + SOL, TOKEN, token_account(NATIVE_MINT, OWNER, SOL)),
            );
        }
        Wrap::IntoForeignSource => {
            c.set(
                &foreign,
                acct(RENT, TOKEN, token_account(NATIVE_MINT, ATTACKER, 0)),
            );
        }
        Wrap::IntoForeignKept => {
            c.set(
                &foreign,
                acct(RENT, TOKEN, token_account(NATIVE_MINT, ATTACKER, 0)),
            );
            c.after(
                &foreign,
                acct(
                    RENT + AMOUNT_IN,
                    TOKEN,
                    token_account(NATIVE_MINT, ATTACKER, AMOUNT_IN),
                ),
            );
        }
        Wrap::OverWrapWsolSkim(x) => {
            c.set(
                &foreign,
                acct(RENT, TOKEN, token_account(NATIVE_MINT, ATTACKER, 0)),
            );
            c.after(
                &foreign,
                acct(RENT + x, TOKEN, token_account(NATIVE_MINT, ATTACKER, x)),
            );
            ixs.push(ix(
                TOKEN,
                &[
                    (&wsol, false, true),
                    (NATIVE_MINT, false, false),
                    (&foreign, false, true),
                    (OWNER, true, false),
                ],
                transfer_checked(x, 9),
            ));
        }
        Wrap::OverWrapLamportSkim(x) | Wrap::SecondTransfer(x) => {
            ixs.push(ix(
                SYSTEM,
                &[(OWNER, true, true), (ATTACKER, false, true)],
                system_transfer(x),
            ));
            // Over-wrapped, the close returns the excess with the rent, and
            // this sends it on.
            owner_out += x;
            attacker_in += x;
        }
        _ => {}
    }
    if matches!(shape, Wrap::IntoForeignKept | Wrap::RouteSpendsOtherWsol) {
        c.set(
            &other,
            acct(RENT + SOL, TOKEN, token_account(NATIVE_MINT, OWNER, SOL)),
        );
        c.after(
            &other,
            acct(
                RENT + SOL - AMOUNT_IN,
                TOKEN,
                token_account(NATIVE_MINT, OWNER, SOL - AMOUNT_IN),
            ),
        );
    }
    if transient {
        // What the route left in the wallet's wSOL account goes wherever the
        // close sends it, with the rent the wallet paid to create it.
        let left_in_wsol = match shape {
            Wrap::RouteSpendsOtherWsol => wrapped,
            Wrap::OverWrapLamportSkim(x) => x,
            _ => 0,
        };
        let to = match shape {
            Wrap::CloseToStranger | Wrap::RouteSpendsOtherWsol => ATTACKER,
            _ => OWNER,
        };
        ixs.push(close_account(&wsol, to, OWNER));
        // The wallet paid the rent; the close pays it out with what was left.
        owner_out += RENT;
        if to == OWNER {
            owner_out -= RENT + left_in_wsol;
        } else {
            attacker_in += RENT + left_in_wsol;
        }
        c.closed(&wsol);
        // The wallet's ATA program and System CPIs ran under the create.
        let at = 1;
        c.inner.push(Inner {
            top: at,
            program: TOKEN.to_string(),
            accounts: vec![NATIVE_MINT.to_string()],
            data: vec![21u8],
        });
        c.inner.push(Inner {
            top: at,
            program: SYSTEM.to_string(),
            accounts: vec![OWNER.to_string(), wsol.clone()],
            data: system_create(RENT, 165, TOKEN),
        });
        c.inner.push(Inner {
            top: at,
            program: TOKEN.to_string(),
            accounts: vec![wsol.clone()],
            data: vec![22u8],
        });
        let mut init = vec![18u8];
        init.extend_from_slice(pk(OWNER).as_bytes());
        c.inner.push(Inner {
            top: at,
            program: TOKEN.to_string(),
            accounts: vec![wsol.clone(), NATIVE_MINT.to_string()],
            data: init,
        });
    }
    // The route's own transfers into and out of the venue.
    c.inner.push(Inner {
        top: route_at,
        program: TOKEN.to_string(),
        accounts: vec![src.clone(), in_vault.clone(), OWNER.to_string()],
        data: {
            let mut d = vec![3u8];
            d.extend_from_slice(&AMOUNT_IN.to_le_bytes());
            d
        },
    });
    c.inner.push(Inner {
        top: route_at,
        program: TOKEN.to_string(),
        accounts: vec![out_vault.clone(), dst.clone(), JUPITER.to_string()],
        data: {
            let mut d = vec![3u8];
            d.extend_from_slice(&OUT.to_le_bytes());
            d
        },
    });
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    c.after(OWNER, acct(10 * SOL - owner_out, SYSTEM, vec![]));
    if attacker_in > 0 {
        c.after(ATTACKER, acct(SOL + attacker_in, SYSTEM, vec![]));
    }
    (c, ixs, route_at)
}

/// The live request: 0.605263158 SOL for MINT_X at 100 bps.
fn wrap_request(amount: &str) -> Option<ExtractedParameters> {
    Some(ExtractedParameters {
        amount: Some(amount.to_string()),
        input_token: Some("SOL".to_string()),
        output_token: Some(MINT_X.to_string()),
        slippage_bps: Some(100),
        ..Default::default()
    })
}

async fn wrap_verdict(shape: Wrap, amount: &str, w: Waivers) -> VerificationResult {
    let (c, ixs, route) = wrap_swap(shape);
    verify(c, &ixs, route, "swap", wrap_request(amount), w).await
}

/// D-20 reproduction: the live shape is executable, under the defaults and
/// under every waiver — and so is the same wrap into a wSOL account the
/// wallet already holds.
#[tokio::test]
async fn round41_an_honest_wrap_and_swap_of_sol_is_executable() {
    for w in CONFIGS {
        for shape in [Wrap::Honest, Wrap::HonestExisting] {
            let r = wrap_verdict(shape, "0.605263158", w).await;
            assert!(
                !names(&r, "SignerLamportsOutsideDeclaredDebit"),
                "{shape:?} {w:?}: L4 counts the wrapped SOL as an undeclared loss: {}",
                l4(&r)
            );
            assert_executable(&format!("{shape:?}, {w:?}"), &r);
        }
    }
}

/// D-20 attack controls: every way of letting SOL leave beside the wrap to
/// someone other than the route's declared input debit, never executable.
#[tokio::test]
async fn round41_a_wrap_that_lets_sol_leave_is_never_executable() {
    let skim = 50_000_000;
    let cases = [
        (
            "over-wrap, excess wSOL to a stranger",
            Wrap::OverWrapWsolSkim(skim),
        ),
        (
            "over-wrap, excess lamports to a stranger",
            Wrap::OverWrapLamportSkim(skim),
        ),
        (
            "wrap into a wSOL account the wallet does not own (route source)",
            Wrap::IntoForeignSource,
        ),
        (
            "wrap into a wSOL account the wallet does not own (kept there)",
            Wrap::IntoForeignKept,
        ),
        ("wSOL account closed to a stranger", Wrap::CloseToStranger),
        (
            "a second lamport transfer to a stranger",
            Wrap::SecondTransfer(skim),
        ),
        (
            "the route spends another wSOL account; the wrapped one closed to a stranger",
            Wrap::RouteSpendsOtherWsol,
        ),
    ];
    let mut out = Outcomes::default();
    for w in ATTACK_CONFIGS {
        for (tag, shape) in cases {
            let r = wrap_verdict(shape, "0.605263158", w).await;
            out.refused(&format!("{tag}, {w:?}"), &r);
        }
    }
    out.assert_none_executable();
}

/// D-20: L4's own judgement of the skims, under the defaults, to the
/// lamport. The binding refuses every one of them as well; L4 must not lose
/// any of them to the wrap credit — it credits at most what the route's data
/// says it spends, only into the wallet's own wSOL, only from an account the
/// declaration debits by name. What is left is exactly what went elsewhere.
#[tokio::test]
async fn round41_l4_still_counts_what_leaves_beside_a_wrap() {
    let skim = 50_000_000;
    for (tag, shape, lost) in [
        ("over-wrap, wSOL skim", Wrap::OverWrapWsolSkim(skim), skim),
        (
            "over-wrap, lamport skim",
            Wrap::OverWrapLamportSkim(skim),
            skim,
        ),
        (
            "wrap into a foreign source",
            Wrap::IntoForeignSource,
            AMOUNT_IN,
        ),
        (
            "wrap into a foreign account",
            Wrap::IntoForeignKept,
            AMOUNT_IN,
        ),
        ("close to a stranger", Wrap::CloseToStranger, RENT),
        ("second transfer", Wrap::SecondTransfer(skim), skim),
        (
            "route spends other wSOL",
            Wrap::RouteSpendsOtherWsol,
            AMOUNT_IN + RENT,
        ),
    ] {
        let r = wrap_verdict(shape, "0.605263158", Waivers::None).await;
        record(tag, &r);
        let needle = format!("SignerLamportsOutsideDeclaredDebit: {lost} lamports left");
        assert!(
            names(&r, &needle),
            "{tag}: L4 does not count exactly the {lost} lamports that left: {}",
            l4(&r)
        );
    }
}

/// D-20: an intent smaller than what the wrap and the route spend is never
/// executable, and the binding says why.
#[tokio::test]
async fn round41_an_intent_smaller_than_the_wrap_is_never_executable() {
    let mut out = Outcomes::default();
    let mut unnamed = Vec::new();
    for w in ATTACK_CONFIGS {
        for amount in ["0.5", "0.605263157"] {
            let tag = format!("intent {amount} SOL, {w:?}");
            let r = wrap_verdict(Wrap::Honest, amount, w).await;
            out.refused(&tag, &r);
            if !names(&r, "IntentMismatch") {
                unnamed.push(tag);
            }
        }
    }
    out.assert_none_executable();
    assert!(
        unnamed.is_empty(),
        "refused, but not by the binding: {unnamed:#?}"
    );
}

// ─── D-21: an ATA create for a Token-2022 mint beside a transfer ───────────

/// What runs beside the 1-lamport transfer.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Beside {
    /// The live shape: the sender's Token-2022 ATA created idempotently,
    /// paid by the sender; the ATA program CPIs System and Token-2022.
    AtaCreate,
    /// The same create, and the Token-2022 CPI reported under the PRIMARY
    /// (the System transfer) as well.
    CpiUnderPrimary,
    /// An unmanifested program beside the transfer CPIs Token-2022.
    ForeignSibling,
    /// A manifested program whose instruction declares no Token-2022 CPI
    /// (Memo) is reported calling it.
    UndeclaringSibling,
}

fn transfer_beside(beside: Beside) -> (Cluster, Vec<Ix>) {
    let mut c = Cluster::default();
    base_programs(&mut c);
    let account = ata_under(OWNER, MINT_T22, TOKEN_2022);
    c.set(
        MINT_T22,
        acct(1_461_600, TOKEN_2022, mint(10u64.pow(12), 6)),
    );
    c.set(RECIPIENT, acct(SOL, SYSTEM, vec![]));
    c.after(RECIPIENT, acct(SOL + 1, SYSTEM, vec![]));
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    let mut ixs = vec![ix(
        SYSTEM,
        &[(OWNER, true, true), (RECIPIENT, false, true)],
        system_transfer(1),
    )];
    let mut owner_out = FEE + 1;
    match beside {
        Beside::AtaCreate | Beside::CpiUnderPrimary => {
            ixs.push(create_idempotent(
                OWNER, &account, OWNER, MINT_T22, TOKEN_2022,
            ));
            owner_out += RENT_T22;
            c.after(
                &account,
                acct(RENT_T22, TOKEN_2022, token2022_ata_account(MINT_T22, OWNER)),
            );
            let mut init = vec![18u8];
            init.extend_from_slice(pk(OWNER).as_bytes());
            for (program, accounts, data) in [
                (TOKEN_2022, vec![MINT_T22.to_string()], vec![21u8, 7, 0]),
                (
                    SYSTEM,
                    vec![OWNER.to_string(), account.clone()],
                    system_create(RENT_T22, 170, TOKEN_2022),
                ),
                (TOKEN_2022, vec![account.clone()], vec![22u8]),
                (
                    TOKEN_2022,
                    vec![account.clone(), MINT_T22.to_string()],
                    init,
                ),
            ] {
                c.inner.push(Inner {
                    top: 1,
                    program: program.to_string(),
                    accounts,
                    data,
                });
            }
            if beside == Beside::CpiUnderPrimary {
                c.inner.push(Inner {
                    top: 0,
                    program: TOKEN_2022.to_string(),
                    accounts: vec![account.clone()],
                    data: vec![22u8],
                });
            }
        }
        Beside::ForeignSibling | Beside::UndeclaringSibling => {
            let program = if beside == Beside::ForeignSibling {
                FOREIGN
            } else {
                MEMO
            };
            ixs.push(ix(
                program,
                &[
                    (OWNER, true, false),
                    (MINT_T22, false, false),
                    (TOKEN_2022, false, false),
                ],
                b"hello".to_vec(),
            ));
            c.inner.push(Inner {
                top: 1,
                program: TOKEN_2022.to_string(),
                accounts: vec![MINT_T22.to_string()],
                data: vec![21u8, 7, 0],
            });
        }
    }
    c.after(OWNER, acct(10 * SOL - owner_out, SYSTEM, vec![]));
    (c, ixs)
}

fn one_lamport() -> Option<ExtractedParameters> {
    Some(ExtractedParameters {
        amount: Some("0.000000001".to_string()),
        destination: Some(RECIPIENT.to_string()),
        input_token: Some("SOL".to_string()),
        ..Default::default()
    })
}

async fn transfer_verdict(beside: Beside, w: Waivers) -> VerificationResult {
    let (c, ixs) = transfer_beside(beside);
    verify(c, &ixs, 0, "transfer", one_lamport(), w).await
}

/// D-21 reproduction: the ATA program's own Token-2022 and System CPIs under
/// its `CreateIdempotent`, which its manifest declares, are not the System
/// transfer's, and the honest transfer is executable.
#[tokio::test]
async fn round41_an_ata_create_for_a_token2022_mint_beside_a_transfer_is_executable() {
    for w in CONFIGS {
        let r = transfer_verdict(Beside::AtaCreate, w).await;
        assert!(
            !names(&r, "AuthorityHijack"),
            "{w:?}: the ATA program's declared CPI is judged as the System program's: {}",
            risk(&r)
        );
        assert_executable(
            &format!("1-lamport transfer beside a Token-2022 ATA create, {w:?}"),
            &r,
        );
    }
}

/// D-21 controls: a token-program CPI under an instruction that does not
/// declare it is still `AuthorityHijack`, and never executable — under the
/// primary itself, under an unmanifested sibling, under a manifested sibling
/// whose instruction declares no such CPI.
#[tokio::test]
async fn round41_an_undeclared_token2022_cpi_is_still_authority_hijack() {
    let mut out = Outcomes::default();
    let mut unnamed = Vec::new();
    for w in ATTACK_CONFIGS {
        for beside in [
            Beside::CpiUnderPrimary,
            Beside::ForeignSibling,
            Beside::UndeclaringSibling,
        ] {
            let tag = format!("{beside:?}, {w:?}");
            let r = transfer_verdict(beside, w).await;
            out.refused(&tag, &r);
            if !names(&r, "AuthorityHijack") {
                unnamed.push(tag);
            }
        }
    }
    out.assert_none_executable();
    assert!(
        unnamed.is_empty(),
        "refused, but no longer as AuthorityHijack: {unnamed:#?}"
    );
}
