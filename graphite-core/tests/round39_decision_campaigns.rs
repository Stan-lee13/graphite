//! Requires the `rpc` feature: every verdict here rests on a simulated diff.
#![cfg(feature = "rpc")]

//! Round 39 (core-decision workstream): the brief's attack campaigns 1 and 2
//! end to end through `verify_async`, against a loopback mock RPC.
//!
//! Campaign 1: a swap whose output (or input) is taken by something riding
//! beside it — a top-level sibling, a CPI, a Token-2022 transfer, a
//! close-and-sweep, an authority or delegate change, an unrelated program, a
//! wrapped-SOL skim, an extra signer, a relayed fee payer.
//!
//! Campaign 2: a granted withdrawal bundled with a transfer to a stranger, an
//! authority change, a close, a creation, an approval, a burn or a hidden CPI.
//!
//! Every attack runs twice: under the Core's defaults, and with EVERY operator
//! waiver the Core has turned on at once (`Waivers::All`): the two
//! `L4Relaxations` fields (`GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS`,
//! `GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT`),
//! `GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS`, `GRAPHITE_ALLOW_DURABLE_NONCE`,
//! the most permissive profile `GRAPHITE_ALLOW_PERMISSIVE_PROFILES` admits
//! (`Custom { 0.0, Unknown }`), the operator-bootstrap observation policy, and
//! no plugins. No waiver may turn a skim, or an authority, delegate, close or
//! freeze change, into `executable_approved`.
//!
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
const LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const NATIVE_LOADER: &str = "NativeLoader1111111111111111111111111111111";
const MEMO: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const STAKE: &str = "Stake11111111111111111111111111111111111111";
const SYSVAR: &str = "Sysvar1111111111111111111111111111111111111";
const CLOCK: &str = "SysvarC1ock11111111111111111111111111111111";
const STAKE_HISTORY: &str = "SysvarStakeHistory1111111111111111111111111";
const JUPITER: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const CLMM: &str = "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK";
const NATIVE_MINT: &str = "So11111111111111111111111111111111111111112";
const DLMM: &str = "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo";
const MARKETPLACE: &str = "CcmRKTuZCGJBWQwMHvDYApBRvSZNHqGJXkznqpDTSQUr";

/// The wallet that signs and pays.
const OWNER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
/// Somebody else.
const ATTACKER: &str = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7";
/// A fee payer that is not the owner.
const RELAYER: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
/// A program somebody deployed (unmanifested).
const FOREIGN: &str = "Fore1gnProgram11111111111111111111111111111";
const MINT_X: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const MINT_Y: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
/// A mint the attacker made, worth nothing.
const MINT_Z: &str = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263";

const SOL: u64 = 1_000_000_000;
const FEE: u64 = 5_000;
const RENT: u64 = 2_039_280;
const STAKE_RENT: u64 = 2_282_880;

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

/// A 165-byte token account, with an optional close authority (offset 129:
/// `COption<Pubkey>`, tag u32 then the key).
fn token_account_with(mint: &str, owner: &str, amount: u64, close: Option<&str>) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(pk(mint).as_bytes());
    d[32..64].copy_from_slice(pk(owner).as_bytes());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    if let Some(c) = close {
        d[129..133].copy_from_slice(&1u32.to_le_bytes());
        d[133..165].copy_from_slice(pk(c).as_bytes());
    }
    d
}

fn token_account(mint: &str, owner: &str, amount: u64) -> Vec<u8> {
    token_account_with(mint, owner, amount, None)
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

/// A stake account (Initialized) whose staker and withdrawer are `authority`.
fn stake_data(authority: &str) -> Vec<u8> {
    let mut data = vec![0u8; 200];
    data[0..4].copy_from_slice(&1u32.to_le_bytes());
    data[4..12].copy_from_slice(&STAKE_RENT.to_le_bytes());
    data[12..44].copy_from_slice(pk(authority).as_bytes());
    data[44..76].copy_from_slice(pk(authority).as_bytes());
    data
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

#[derive(Default, Clone)]
struct Cluster {
    keys: Vec<String>,
    pre: HashMap<String, Account>,
    post: HashMap<String, Option<Account>>,
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
    /// Move `lamports` of `k`'s post-state (from its pre-state when no
    /// post-state is set yet).
    fn shift(&mut self, k: &str, delta: i128) {
        let mut a = self.post_of(k).expect("an account to shift");
        a.lamports = (i128::from(a.lamports) + delta) as u64;
        self.after(k, a);
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

/// SPL `SetAuthority { authority_type, new_authority: Some(..) }`.
fn set_authority(kind: u8, new: &str) -> Vec<u8> {
    let mut d = vec![6u8, kind, 1];
    d.extend_from_slice(pk(new).as_bytes());
    d
}

fn amount_ix(tag: u8, amount: u64) -> Vec<u8> {
    let mut d = vec![tag];
    d.extend_from_slice(&amount.to_le_bytes());
    d
}

fn stake_withdraw_data(lamports: u64) -> Vec<u8> {
    let mut d = 4u32.to_le_bytes().to_vec();
    d.extend_from_slice(&lamports.to_le_bytes());
    d
}

/// Stake `Authorize(new, StakeAuthorize::Withdrawer)`.
fn stake_authorize(new: &str) -> Vec<u8> {
    let mut d = 1u32.to_le_bytes().to_vec();
    d.extend_from_slice(pk(new).as_bytes());
    d.extend_from_slice(&1u32.to_le_bytes());
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

// ─── The core under test ───────────────────────────────────────────────────

/// Which operator configuration the verdict is reached under.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Waivers {
    /// The Core's production defaults; the confidence bar of the Round 38
    /// harnesses (`Custom { 0.40, OfficialManifest }`), since no test
    /// program has an L3 baseline.
    None,
    /// Every operator waiver and opt-out at once.
    All,
}

const BOTH: [Waivers; 2] = [Waivers::None, Waivers::All];

fn core_for(endpoint: String, waivers: Waivers) -> (GraphiteCore, WalletProfile) {
    let mut core = match waivers {
        Waivers::None => GraphiteCore::new(),
        // Plugins only veto; with none registered nothing can veto.
        Waivers::All => GraphiteCore::new_without_plugins(),
    };
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint,
        timeout: std::time::Duration::from_secs(10),
        max_retries: 0,
        ..Default::default()
    }));
    let profile = match waivers {
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
    payer: &str,
    ixs: &[Ix],
    primary: usize,
    intent: &str,
    extracted: Option<ExtractedParameters>,
    waivers: Waivers,
) -> VerificationResult {
    let (keys, bytes) = frame(payer, ixs);
    cluster.keys = keys;
    let endpoint = serve(Arc::new(Mutex::new(cluster)));
    let (core, profile) = core_for(endpoint, waivers);
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
                let reason: String = l.reason.chars().take(500).collect();
                format!("{}={:?} ({reason})", l.layer, l.status)
            } else {
                format!("{}={:?}", l.layer, l.status)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn record(tag: &str, r: &VerificationResult) {
    eprintln!(
        "[R39 {tag}] decision={:?} | {} | risk: {} | unobserved: {:?}",
        r.decision,
        statuses(r),
        risk(r),
        r.scope.unobserved_codes()
    );
}

fn assert_not_executable(tag: &str, r: &VerificationResult) {
    record(tag, r);
    assert_ne!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{tag}: an attack reached executable_approved: {}",
        statuses(r)
    );
    assert!(!r.executable, "{tag}");
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

fn assert_executable(tag: &str, r: &VerificationResult) {
    record(tag, r);
    assert_eq!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{tag}: the control was refused: {} | {}",
        statuses(r),
        risk(r)
    );
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
        (CLMM, LOADER),
        (TOKEN, LOADER),
        (TOKEN_2022, LOADER),
        (MEMO, LOADER),
        (FOREIGN, LOADER),
        (SYSTEM, NATIVE_LOADER),
        (STAKE, NATIVE_LOADER),
        (DLMM, LOADER),
        (MARKETPLACE, LOADER),
        (ATA_PROGRAM, LOADER),
    ] {
        c.program(p, owner);
    }
}

// ─── Campaign 1: a Jupiter v6 route and what rides beside it ───────────────

/// What rides beside the route.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Beside {
    Nothing,
    /// A TransferChecked of the route's output to the attacker.
    OutputSkim(u64),
    /// The same through Token-2022 (the output mint is a Token-2022 mint).
    Token2022Skim(u64),
    /// The output moved to the attacker and the emptied account closed to
    /// the attacker: a close-and-sweep.
    CloseAndSweep,
    /// `SetAuthority(AccountOwner)` of the owner's output account to the
    /// attacker.
    OwnerChange,
    /// `SetAuthority(CloseAccount)` of the owner's output account.
    CloseAuthorityChange,
    /// An `Approve` of the owner's output account to the attacker.
    Approve,
    /// The attacker's own program, the owner signing, moves output by CPI.
    CpiSkim(u64),
    /// The attacker's own program, the owner signing, moves lamports by CPI.
    CpiLamports(u64),
    /// A wrapped-SOL output: part of the wSOL moved to the attacker's wSOL
    /// account.
    WrappedSolSkim(u64),
    /// The attacker co-signs, and the owner's System transfer pays them.
    ExtraSignerTakes(u64),
    /// A relayer pays the fee, and the owner's SOL goes to the relayer.
    RelayerTakes(u64),
    /// Round 39 lead A: the owner's SOL into a token account whose OWNER
    /// FIELD is the owner but whose close authority is the attacker.
    SolToClosable(u64),
    /// The owner's SOL funds a new account the attacker's program owns.
    CreateFunding(u64),
}

/// A Jupiter route of `amount_in` of `in_mint` to `out_mint`, quoted at
/// `quoted_out` with 50 bps of slippage, the venue paying `gross` into the
/// owner's output account. Adapted from `round38_sibling_skims.rs`.
fn jupiter_swap(
    in_mint: &str,
    out_mint: &str,
    amount_in: u64,
    quoted_out: u64,
    gross: u64,
    beside: Beside,
) -> (Cluster, Vec<Ix>, String) {
    let mut c = Cluster::default();
    base_programs(&mut c);
    let d = def(JUPITER, "route");
    let out_program = if matches!(beside, Beside::Token2022Skim(_)) {
        TOKEN_2022
    } else {
        TOKEN
    };
    let payer = if matches!(beside, Beside::RelayerTakes(_)) {
        RELAYER
    } else {
        OWNER
    };
    let (src, dst) = (ata(OWNER, in_mint), ata_under(OWNER, out_mint, out_program));
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
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&[7, 100, 0, 1]);
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
    c.set(in_mint, acct(1_461_600, TOKEN, mint(10u64.pow(15), None)));
    c.set(
        out_mint,
        acct(1_461_600, out_program, mint(10u64.pow(15), None)),
    );
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
            out_program,
            token_account(out_mint, &pool, reserve),
        ),
    );
    c.after(
        &out_vault,
        acct(
            lamports_of(out_mint, reserve - gross),
            out_program,
            token_account(out_mint, &pool, reserve - gross),
        ),
    );
    let held = amount_in + 10_000_000;
    c.set(
        &src,
        acct(
            lamports_of(in_mint, held),
            TOKEN,
            token_account(in_mint, OWNER, held),
        ),
    );
    c.after(
        &src,
        acct(
            lamports_of(in_mint, held - amount_in),
            TOKEN,
            token_account(in_mint, OWNER, held - amount_in),
        ),
    );
    c.set(
        &dst,
        acct(
            lamports_of(out_mint, 0),
            out_program,
            token_account(out_mint, OWNER, 0),
        ),
    );
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    c.set(ATTACKER, acct(SOL, SYSTEM, vec![]));
    c.set(RELAYER, acct(10 * SOL, SYSTEM, vec![]));
    if payer == RELAYER {
        c.after(RELAYER, acct(10 * SOL - FEE, SYSTEM, vec![]));
        c.after(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    } else {
        c.after(OWNER, acct(10 * SOL - FEE, SYSTEM, vec![]));
    }
    let mut ixs = vec![primary];
    let mut kept = gross;
    let mut dst_owner = OWNER.to_string();
    let mut dst_close: Option<String> = None;
    let mut dst_closed = false;
    match beside {
        Beside::Nothing => {}
        Beside::OutputSkim(skim) | Beside::Token2022Skim(skim) | Beside::WrappedSolSkim(skim) => {
            let theirs = ata_under(ATTACKER, out_mint, out_program);
            c.set(
                &theirs,
                acct(
                    lamports_of(out_mint, 0),
                    out_program,
                    token_account(out_mint, ATTACKER, 0),
                ),
            );
            c.after(
                &theirs,
                acct(
                    lamports_of(out_mint, skim),
                    out_program,
                    token_account(out_mint, ATTACKER, skim),
                ),
            );
            kept -= skim;
            ixs.push(ix(
                out_program,
                &[
                    (&dst, false, true),
                    (out_mint, false, false),
                    (&theirs, false, true),
                    (OWNER, true, false),
                ],
                transfer_checked(skim, 6),
            ));
        }
        Beside::CloseAndSweep => {
            let theirs = ata(ATTACKER, out_mint);
            c.set(
                &theirs,
                acct(RENT, TOKEN, token_account(out_mint, ATTACKER, 0)),
            );
            c.after(
                &theirs,
                acct(RENT, TOKEN, token_account(out_mint, ATTACKER, gross)),
            );
            ixs.push(ix(
                TOKEN,
                &[
                    (&dst, false, true),
                    (out_mint, false, false),
                    (&theirs, false, true),
                    (OWNER, true, false),
                ],
                transfer_checked(gross, 6),
            ));
            ixs.push(ix(
                TOKEN,
                &[
                    (&dst, false, true),
                    (ATTACKER, false, true),
                    (OWNER, true, false),
                ],
                vec![9u8],
            ));
            c.shift(ATTACKER, i128::from(RENT));
            dst_closed = true;
        }
        Beside::OwnerChange => {
            dst_owner = ATTACKER.to_string();
            ixs.push(ix(
                TOKEN,
                &[(&dst, false, true), (OWNER, true, false)],
                set_authority(2, ATTACKER),
            ));
        }
        Beside::CloseAuthorityChange => {
            dst_close = Some(ATTACKER.to_string());
            ixs.push(ix(
                TOKEN,
                &[(&dst, false, true), (OWNER, true, false)],
                set_authority(3, ATTACKER),
            ));
        }
        Beside::Approve => {
            ixs.push(ix(
                TOKEN,
                &[
                    (&dst, false, true),
                    (ATTACKER, false, false),
                    (OWNER, true, false),
                ],
                amount_ix(4, u64::MAX),
            ));
        }
        Beside::CpiSkim(skim) => {
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
        Beside::CpiLamports(skim) => {
            c.shift(OWNER, -i128::from(skim));
            c.shift(ATTACKER, i128::from(skim));
            ixs.push(ix(
                FOREIGN,
                &[
                    (OWNER, true, true),
                    (ATTACKER, false, true),
                    (SYSTEM, false, false),
                ],
                vec![1, 2, 3],
            ));
        }
        Beside::ExtraSignerTakes(skim) => {
            c.shift(OWNER, -i128::from(skim));
            c.shift(ATTACKER, i128::from(skim));
            ixs.push(ix(
                SYSTEM,
                &[(OWNER, true, true), (ATTACKER, true, true)],
                system_transfer(skim),
            ));
        }
        Beside::RelayerTakes(skim) => {
            c.shift(OWNER, -i128::from(skim));
            c.shift(RELAYER, i128::from(skim));
            ixs.push(ix(
                SYSTEM,
                &[(OWNER, true, true), (RELAYER, false, true)],
                system_transfer(skim),
            ));
        }
        Beside::SolToClosable(skim) => {
            let k = key(77);
            c.set(
                &k,
                acct(
                    RENT,
                    TOKEN,
                    token_account_with(MINT_Z, OWNER, 0, Some(ATTACKER)),
                ),
            );
            c.after(
                &k,
                acct(
                    RENT + skim,
                    TOKEN,
                    token_account_with(MINT_Z, OWNER, 0, Some(ATTACKER)),
                ),
            );
            c.set(MINT_Z, acct(1_461_600, TOKEN, mint(1, Some(ATTACKER))));
            c.shift(OWNER, -i128::from(skim));
            ixs.push(ix(
                SYSTEM,
                &[(OWNER, true, true), (&k, false, true)],
                system_transfer(skim),
            ));
        }
        Beside::CreateFunding(lamports) => {
            let new = key(78);
            c.after(&new, acct(lamports, FOREIGN, vec![]));
            c.shift(OWNER, -i128::from(lamports));
            ixs.push(ix(
                SYSTEM,
                &[(OWNER, true, true), (&new, true, true)],
                system_create(lamports, 0, FOREIGN),
            ));
        }
    }
    if dst_closed {
        c.closed(&dst);
    } else {
        let mut data = token_account(out_mint, &dst_owner, kept);
        if let Some(close) = &dst_close {
            data = token_account_with(out_mint, &dst_owner, kept, Some(close));
        }
        c.after(&dst, acct(lamports_of(out_mint, kept), out_program, data));
    }
    (c, ixs, payer.to_string())
}

fn swap_request(amount: &str, input: &str, output: &str) -> Option<ExtractedParameters> {
    Some(ExtractedParameters {
        amount: Some(amount.to_string()),
        input_token: Some(input.to_string()),
        output_token: Some(output.to_string()),
        ..Default::default()
    })
}

/// 1 MINT_Y for 100 MINT_X (minimum 99.5), 100 delivered, `beside` added.
async fn swap_y_to_x(beside: Beside, waivers: Waivers) -> VerificationResult {
    let (c, ixs, payer) = jupiter_swap(MINT_Y, MINT_X, 1_000_000, 100_000_000, 100_000_000, beside);
    verify(
        c,
        &payer,
        &ixs,
        0,
        "swap",
        swap_request("1", MINT_Y, MINT_X),
        waivers,
    )
    .await
}

/// 1 MINT_Y for 10 SOL (wSOL into the owner's wSOL account, minimum 9.95).
async fn swap_y_to_sol(beside: Beside, waivers: Waivers) -> VerificationResult {
    let (c, ixs, payer) = jupiter_swap(MINT_Y, NATIVE_MINT, 1_000_000, 10 * SOL, 10 * SOL, beside);
    verify(
        c,
        &payer,
        &ixs,
        0,
        "swap",
        swap_request("1", MINT_Y, "SOL"),
        waivers,
    )
    .await
}

/// The controls: an honest swap, to a token and to SOL, is executable under
/// the defaults and under every waiver. A waiver that refused them would be
/// a different finding; a harness that refused them would prove nothing.
#[tokio::test]
async fn campaign1_honest_swaps_are_executable_with_and_without_waivers() {
    for w in BOTH {
        assert_executable(
            &format!("honest Y->X {w:?}"),
            &swap_y_to_x(Beside::Nothing, w).await,
        );
        assert_executable(
            &format!("honest Y->SOL {w:?}"),
            &swap_y_to_sol(Beside::Nothing, w).await,
        );
    }
}

/// Campaign 1, every variation the brief lists that Round 38 already covered
/// under the defaults, now also under every waiver.
#[tokio::test]
async fn campaign1_a_swap_skimmed_beside_it_is_never_executable_under_any_waiver() {
    let cases = [
        ("top-level output skim", Beside::OutputSkim(49_600_000)),
        ("Token-2022 output skim", Beside::Token2022Skim(49_600_000)),
        ("close-and-sweep", Beside::CloseAndSweep),
        ("owner change", Beside::OwnerChange),
        ("close-authority change", Beside::CloseAuthorityChange),
        ("delegate (Approve)", Beside::Approve),
        ("CPI token skim", Beside::CpiSkim(49_600_000)),
        (
            "unrelated program moves lamports",
            Beside::CpiLamports(3 * SOL),
        ),
        ("extra signer takes SOL", Beside::ExtraSignerTakes(3 * SOL)),
        ("relayer takes SOL", Beside::RelayerTakes(9_000_000)),
        (
            "create funds attacker program",
            Beside::CreateFunding(3 * SOL),
        ),
    ];
    let mut out = Outcomes::default();
    for w in BOTH {
        for (tag, beside) in cases {
            let r = swap_y_to_x(beside, w).await;
            out.refused(&format!("swap Y->X, {tag}, {w:?}"), &r);
        }
    }
    out.assert_none_executable();
}

/// Campaign 1, wrapped SOL: a swap into SOL whose wSOL is partly moved to
/// the attacker's wSOL account.
#[tokio::test]
async fn campaign1_a_wrapped_sol_skim_is_never_executable_under_any_waiver() {
    for w in BOTH {
        let r = swap_y_to_sol(Beside::WrappedSolSkim(4 * SOL), w).await;
        assert_not_executable(&format!("swap Y->SOL, wSOL skim, {w:?}"), &r);
    }
}

/// R39-CORE-DECISION-1 beside a swap: the owner's SOL sent to a token
/// account whose owner FIELD is the owner and whose close authority is the
/// attacker. SPL Token's `SetAuthority(AccountOwner)` keeps a non-native
/// account's close authority, so the attacker can build such an account,
/// hand it to the victim, and close it to themselves after the swap lands.
///
/// On c087bfb a swap into SOL beside 5 SOL sent there was
/// `executable_approved` with the waivers on — the binding counted the
/// account's lamports as the wallet's own delivery (`-lamports_out`), and
/// only L4's W19, which an operator can relax, refused it under the
/// defaults. The binding must name it whatever the waivers.
#[tokio::test]
async fn round39_sol_into_an_attacker_closable_account_beside_a_swap() {
    let mut out = Outcomes::default();
    let mut unnamed = Vec::new();
    for w in BOTH {
        for (tag, r) in [
            (
                format!("swap Y->X, SOL to closable, {w:?}"),
                swap_y_to_x(Beside::SolToClosable(3 * SOL), w).await,
            ),
            (
                format!("swap Y->SOL, SOL to closable, {w:?}"),
                swap_y_to_sol(Beside::SolToClosable(5 * SOL), w).await,
            ),
        ] {
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

// ─── Campaign 2: a granted withdrawal and what rides beside it ─────────────

/// What rides beside a Stake `Withdraw` of 40 SOL to its owner.
#[derive(Clone, Copy, PartialEq, Debug)]
enum WithBeside {
    Nothing,
    /// The owner's System transfer to a stranger.
    Stranger(u64),
    /// Lead A: to a token account the owner "owns", the attacker can close.
    Closable(u64),
    /// Lead B: to the attacker, who co-signs the transaction.
    CoSigner(u64),
    /// Lead C: a `CreateAccount` funding a new account the attacker's
    /// program owns.
    CreateFunding(u64),
    /// SPL `SetAuthority(AccountOwner)` of the owner's token account.
    OwnerChange,
    /// SPL `SetAuthority(CloseAccount)` of the owner's token account.
    CloseAuthorityChange,
    /// SPL `SetAuthority(FreezeAccount)` of a mint whose freeze authority is
    /// the owner.
    FreezeAuthorityChange,
    /// The owner's token account closed to the attacker.
    Close,
    /// `Approve` of the owner's token account to the attacker.
    Approve,
    /// `Burn` of the owner's tokens.
    Burn,
    /// The attacker's program, the owner signing, moves SOL by CPI.
    HiddenCpi(u64),
    /// Lead D: a second Stake `Withdraw`, of another stake account the owner
    /// controls, to the attacker.
    SecondWithdrawToAttacker(u64),
    /// Lead D: Stake `Authorize` of another of the owner's stake accounts to
    /// the attacker.
    StakeAuthorize,
    /// The control: the owner wraps SOL into their own wSOL account.
    OwnWrap(u64),
}

fn stake_withdrawal(beside: WithBeside) -> (Cluster, Vec<Ix>, String) {
    let mut c = Cluster::default();
    base_programs(&mut c);
    for s in [CLOCK, STAKE_HISTORY] {
        c.set(s, acct(1, SYSVAR, vec![0u8; 8]));
    }
    let amount = 40 * SOL;
    let stake = key(10);
    c.set(&stake, acct(amount + STAKE_RENT, STAKE, stake_data(OWNER)));
    c.after(&stake, acct(STAKE_RENT, STAKE, stake_data(OWNER)));
    c.set(OWNER, acct(SOL, SYSTEM, vec![]));
    c.after(OWNER, acct(SOL - FEE + amount, SYSTEM, vec![]));
    c.set(ATTACKER, acct(SOL, SYSTEM, vec![]));
    let mut ixs = vec![ix(
        STAKE,
        &[
            (&stake, false, true),
            (OWNER, false, true),
            (CLOCK, false, false),
            (STAKE_HISTORY, false, false),
            (OWNER, true, false),
        ],
        stake_withdraw_data(amount),
    )];
    let theirs = ata(ATTACKER, MINT_X);
    let mine = ata(OWNER, MINT_X);
    let token_setup = |c: &mut Cluster| {
        c.set(MINT_X, acct(1_461_600, TOKEN, mint(10u64.pow(15), None)));
        c.set(
            &mine,
            acct(RENT, TOKEN, token_account(MINT_X, OWNER, 1_000_000)),
        );
        c.set(
            &theirs,
            acct(RENT, TOKEN, token_account(MINT_X, ATTACKER, 0)),
        );
    };
    match beside {
        WithBeside::Nothing => {}
        WithBeside::OwnWrap(l) => {
            let wsol = ata(OWNER, NATIVE_MINT);
            c.set(NATIVE_MINT, acct(1_461_600, TOKEN, mint(0, None)));
            c.set(
                &wsol,
                acct(RENT, TOKEN, token_account(NATIVE_MINT, OWNER, 0)),
            );
            c.after(
                &wsol,
                acct(RENT + l, TOKEN, token_account(NATIVE_MINT, OWNER, l)),
            );
            c.shift(OWNER, -i128::from(l));
            ixs.push(ix(
                SYSTEM,
                &[(OWNER, true, true), (&wsol, false, true)],
                system_transfer(l),
            ));
            ixs.push(ix(TOKEN, &[(&wsol, false, true)], vec![17u8]));
        }
        WithBeside::Stranger(l) => {
            c.shift(OWNER, -i128::from(l));
            c.shift(ATTACKER, i128::from(l));
            ixs.push(ix(
                SYSTEM,
                &[(OWNER, true, true), (ATTACKER, false, true)],
                system_transfer(l),
            ));
        }
        WithBeside::Closable(l) => {
            let k = key(77);
            c.set(
                &k,
                acct(
                    RENT,
                    TOKEN,
                    token_account_with(MINT_Z, OWNER, 0, Some(ATTACKER)),
                ),
            );
            c.after(
                &k,
                acct(
                    RENT + l,
                    TOKEN,
                    token_account_with(MINT_Z, OWNER, 0, Some(ATTACKER)),
                ),
            );
            c.set(MINT_Z, acct(1_461_600, TOKEN, mint(1, Some(ATTACKER))));
            c.shift(OWNER, -i128::from(l));
            ixs.push(ix(
                SYSTEM,
                &[(OWNER, true, true), (&k, false, true)],
                system_transfer(l),
            ));
        }
        WithBeside::CoSigner(l) => {
            c.shift(OWNER, -i128::from(l));
            c.shift(ATTACKER, i128::from(l));
            ixs.push(ix(
                SYSTEM,
                &[(OWNER, true, true), (ATTACKER, true, true)],
                system_transfer(l),
            ));
        }
        WithBeside::CreateFunding(l) => {
            let new = key(78);
            c.after(&new, acct(l, FOREIGN, vec![]));
            c.shift(OWNER, -i128::from(l));
            ixs.push(ix(
                SYSTEM,
                &[(OWNER, true, true), (&new, true, true)],
                system_create(l, 0, FOREIGN),
            ));
        }
        WithBeside::OwnerChange | WithBeside::CloseAuthorityChange => {
            token_setup(&mut c);
            let (kind, data) = if beside == WithBeside::OwnerChange {
                (2, token_account(MINT_X, ATTACKER, 1_000_000))
            } else {
                (
                    3,
                    token_account_with(MINT_X, OWNER, 1_000_000, Some(ATTACKER)),
                )
            };
            c.after(&mine, acct(RENT, TOKEN, data));
            ixs.push(ix(
                TOKEN,
                &[(&mine, false, true), (OWNER, true, false)],
                set_authority(kind, ATTACKER),
            ));
        }
        WithBeside::FreezeAuthorityChange => {
            let m = key(79);
            let mut before = mint(1_000, None);
            before[46..50].copy_from_slice(&1u32.to_le_bytes());
            before[50..82].copy_from_slice(pk(OWNER).as_bytes());
            let mut after = before.clone();
            after[50..82].copy_from_slice(pk(ATTACKER).as_bytes());
            c.set(&m, acct(1_461_600, TOKEN, before));
            c.after(&m, acct(1_461_600, TOKEN, after));
            ixs.push(ix(
                TOKEN,
                &[(&m, false, true), (OWNER, true, false)],
                set_authority(1, ATTACKER),
            ));
        }
        WithBeside::Close => {
            let k = key(80);
            c.set(MINT_X, acct(1_461_600, TOKEN, mint(10u64.pow(15), None)));
            c.set(&k, acct(RENT, TOKEN, token_account(MINT_X, OWNER, 0)));
            c.closed(&k);
            c.shift(ATTACKER, i128::from(RENT));
            ixs.push(ix(
                TOKEN,
                &[
                    (&k, false, true),
                    (ATTACKER, false, true),
                    (OWNER, true, false),
                ],
                vec![9u8],
            ));
        }
        WithBeside::Approve => {
            token_setup(&mut c);
            let mut data = token_account(MINT_X, OWNER, 1_000_000);
            data[72..76].copy_from_slice(&1u32.to_le_bytes());
            data[76..108].copy_from_slice(pk(ATTACKER).as_bytes());
            data[121..129].copy_from_slice(&1_000_000u64.to_le_bytes());
            c.after(&mine, acct(RENT, TOKEN, data));
            ixs.push(ix(
                TOKEN,
                &[
                    (&mine, false, true),
                    (ATTACKER, false, false),
                    (OWNER, true, false),
                ],
                amount_ix(4, 1_000_000),
            ));
        }
        WithBeside::Burn => {
            token_setup(&mut c);
            c.after(&mine, acct(RENT, TOKEN, token_account(MINT_X, OWNER, 0)));
            c.after(
                MINT_X,
                acct(1_461_600, TOKEN, mint(10u64.pow(15) - 1_000_000, None)),
            );
            ixs.push(ix(
                TOKEN,
                &[
                    (&mine, false, true),
                    (MINT_X, false, true),
                    (OWNER, true, false),
                ],
                amount_ix(8, 1_000_000),
            ));
        }
        WithBeside::HiddenCpi(l) => {
            c.shift(OWNER, -i128::from(l));
            c.shift(ATTACKER, i128::from(l));
            ixs.push(ix(
                FOREIGN,
                &[
                    (OWNER, true, true),
                    (ATTACKER, false, true),
                    (SYSTEM, false, false),
                ],
                vec![1, 2, 3],
            ));
        }
        WithBeside::SecondWithdrawToAttacker(l) => {
            let other = key(11);
            c.set(&other, acct(l + STAKE_RENT, STAKE, stake_data(OWNER)));
            c.after(&other, acct(STAKE_RENT, STAKE, stake_data(OWNER)));
            c.shift(ATTACKER, i128::from(l));
            ixs.push(ix(
                STAKE,
                &[
                    (&other, false, true),
                    (ATTACKER, false, true),
                    (CLOCK, false, false),
                    (STAKE_HISTORY, false, false),
                    (OWNER, true, false),
                ],
                stake_withdraw_data(l),
            ));
        }
        WithBeside::StakeAuthorize => {
            let other = key(12);
            let mut after = stake_data(OWNER);
            after[44..76].copy_from_slice(pk(ATTACKER).as_bytes());
            c.set(&other, acct(20 * SOL, STAKE, stake_data(OWNER)));
            c.after(&other, acct(20 * SOL, STAKE, after));
            ixs.push(ix(
                STAKE,
                &[
                    (&other, false, true),
                    (CLOCK, false, false),
                    (OWNER, true, false),
                ],
                stake_authorize(ATTACKER),
            ));
        }
    }
    (c, ixs, OWNER.to_string())
}

async fn withdraw_with(beside: WithBeside, waivers: Waivers) -> VerificationResult {
    let (c, ixs, payer) = stake_withdrawal(beside);
    verify(c, &payer, &ixs, 0, "withdraw", None, waivers).await
}

#[tokio::test]
async fn campaign2_an_honest_stake_withdrawal_is_executable_with_and_without_waivers() {
    for w in BOTH {
        assert_executable(
            &format!("honest stake withdrawal {w:?}"),
            &withdraw_with(WithBeside::Nothing, w).await,
        );
    }
}

#[tokio::test]
async fn campaign2_a_withdrawal_with_anything_beside_it_is_never_executable_under_any_waiver() {
    let cases = [
        ("stranger transfer", WithBeside::Stranger(30 * SOL)),
        ("owner change", WithBeside::OwnerChange),
        ("close-authority change", WithBeside::CloseAuthorityChange),
        ("freeze-authority change", WithBeside::FreezeAuthorityChange),
        ("close to attacker", WithBeside::Close),
        ("approve", WithBeside::Approve),
        ("burn", WithBeside::Burn),
        ("hidden CPI", WithBeside::HiddenCpi(30 * SOL)),
    ];
    let mut out = Outcomes::default();
    for w in BOTH {
        for (tag, beside) in cases {
            let r = withdraw_with(beside, w).await;
            out.refused(&format!("stake withdrawal, {tag}, {w:?}"), &r);
        }
    }
    out.assert_none_executable();
}

/// R39-CORE-DECISION-1, reproduced: beside a granted withdrawal,
/// `keeps_value` called "a signer's own" three things that are not the
/// owner's. On c087bfb each of A, B and C was `executable_approved`, under
/// the Core's defaults and under every waiver: a Stake `Withdraw` of 40 SOL
/// to its owner, beside 30 SOL of the owner's sent
///
/// - A: into a token account whose owner FIELD is the owner and whose close
///   authority is the attacker (SPL `SetAuthority(AccountOwner)` keeps a
///   non-native account's close authority, so the attacker builds it, hands
///   it over, and closes it to themselves once the transaction lands);
/// - B: to the attacker, who co-signs the transaction;
/// - C: into a new account the attacker's program owns (`CreateAccount`:
///   the new account signs, so it was "a signer").
///
/// The owner's net is a gain (40 in, 30 out), so L4 sees no loss — the
/// binding is the only gate, and it must name the skim. D (a second Stake
/// instruction, part of the "route" by program) was refused on c087bfb by the
/// secondary-instruction risk check, and is kept as a control of that.
#[tokio::test]
async fn round39_what_keeps_value_calls_the_signers_own_beside_a_withdrawal() {
    let bound = [
        (
            "A: SOL to an attacker-closable account",
            WithBeside::Closable(30 * SOL),
        ),
        (
            "B: SOL to a co-signing attacker",
            WithBeside::CoSigner(30 * SOL),
        ),
        (
            "C: CreateAccount for the attacker's program",
            WithBeside::CreateFunding(30 * SOL),
        ),
    ];
    let risk_refused = [
        (
            "D: a second Stake Withdraw to the attacker",
            WithBeside::SecondWithdrawToAttacker(20 * SOL),
        ),
        (
            "D: Stake Authorize to the attacker",
            WithBeside::StakeAuthorize,
        ),
    ];
    let mut out = Outcomes::default();
    let mut unnamed = Vec::new();
    for w in BOTH {
        for (tag, beside) in bound {
            let r = withdraw_with(beside, w).await;
            let tag = format!("stake withdrawal, {tag}, {w:?}");
            out.refused(&tag, &r);
            if !names(&r, "WithdrawalUnderbounded") {
                unnamed.push(tag);
            }
        }
        for (tag, beside) in risk_refused {
            let r = withdraw_with(beside, w).await;
            out.refused(&format!("stake withdrawal, {tag}, {w:?}"), &r);
        }
    }
    out.assert_none_executable();
    assert!(
        unnamed.is_empty(),
        "refused, but not by the binding: {unnamed:#?}"
    );
}

// ─── Campaign 2: the other grants (claim, close, configure) ────────────────

/// One manifest instruction of `program` with its accounts filled
/// (`accounts_for`) and every program-owned slot given state; `data_tail`
/// follows the discriminator.
fn granted_ix(
    c: &mut Cluster,
    program: &str,
    name: &str,
    set: &[(&str, String)],
    data_tail: &[u8],
) -> (Ix, Vec<String>, InstructionDef) {
    let d = def(program, name);
    let keys = accounts_for(program, &d, set);
    let mut data = hex_to_bytes(&d.discriminator);
    data.extend_from_slice(data_tail);
    for (a, k) in d.accounts.iter().zip(&keys) {
        if !a.is_signer && !c.pre.contains_key(k) && k != program {
            c.set(k, acct(5 * SOL, program, vec![1u8; 64]));
        }
    }
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
    (primary, keys, d)
}

fn slot(keys: &[String], d: &InstructionDef, role: &str) -> String {
    keys[d
        .accounts
        .iter()
        .position(|a| a.name == role)
        .unwrap_or_else(|| panic!("{} has no {role}", d.name))]
    .clone()
}

/// What rides beside a claim, a close or a configure.
#[derive(Clone, Copy, PartialEq, Debug)]
enum GrantBeside {
    Nothing,
    /// A TransferChecked of the owner's tokens (of the claimed or escrowed
    /// mint) to the attacker.
    TokenSkim(u64),
    /// The owner's System transfer to a stranger.
    Stranger(u64),
}

/// Meteora DLMM `claim_fee`: the reserves pay 500 of X and 700 of Y into the
/// owner's own associated token accounts.
fn dlmm_claim(beside: GrantBeside) -> (Cluster, Vec<Ix>) {
    let mut c = Cluster::default();
    base_programs(&mut c);
    let (mine_x, mine_y) = (ata(OWNER, MINT_X), ata(OWNER, MINT_Y));
    let (primary, keys, d) = granted_ix(
        &mut c,
        DLMM,
        "claim_fee",
        &[
            ("sender", OWNER.to_string()),
            ("token_x_mint", MINT_X.to_string()),
            ("token_y_mint", MINT_Y.to_string()),
            ("user_token_x", mine_x.clone()),
            ("user_token_y", mine_y.clone()),
            ("token_program", TOKEN.to_string()),
        ],
        &[],
    );
    let pool = slot(&keys, &d, "lb_pair");
    c.set(MINT_X, acct(1_461_600, TOKEN, mint(10u64.pow(15), None)));
    c.set(MINT_Y, acct(1_461_600, TOKEN, mint(10u64.pow(15), None)));
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    c.after(OWNER, acct(10 * SOL - FEE, SYSTEM, vec![]));
    c.set(ATTACKER, acct(SOL, SYSTEM, vec![]));
    let mut kept_x = 500u64;
    for (role, m, mine, paid) in [
        ("reserve_x", MINT_X, &mine_x, 500u64),
        ("reserve_y", MINT_Y, &mine_y, 700u64),
    ] {
        let reserve = slot(&keys, &d, role);
        c.set(
            &reserve,
            acct(RENT, TOKEN, token_account(m, &pool, 1_000_000)),
        );
        c.after(
            &reserve,
            acct(RENT, TOKEN, token_account(m, &pool, 1_000_000 - paid)),
        );
        c.set(mine, acct(RENT, TOKEN, token_account(m, OWNER, 0)));
        c.after(mine, acct(RENT, TOKEN, token_account(m, OWNER, paid)));
    }
    for role in ["position", "lb_pair"] {
        let k = slot(&keys, &d, role);
        c.after(&k, acct(5 * SOL, DLMM, vec![2u8; 64]));
    }
    let mut ixs = vec![primary];
    match beside {
        GrantBeside::Nothing => {}
        GrantBeside::TokenSkim(skim) => {
            let theirs = ata(ATTACKER, MINT_X);
            c.set(
                &theirs,
                acct(RENT, TOKEN, token_account(MINT_X, ATTACKER, 0)),
            );
            c.after(
                &theirs,
                acct(RENT, TOKEN, token_account(MINT_X, ATTACKER, skim)),
            );
            kept_x -= skim;
            c.after(
                &mine_x,
                acct(RENT, TOKEN, token_account(MINT_X, OWNER, kept_x)),
            );
            ixs.push(ix(
                TOKEN,
                &[
                    (&mine_x, false, true),
                    (MINT_X, false, false),
                    (&theirs, false, true),
                    (OWNER, true, false),
                ],
                transfer_checked(skim, 6),
            ));
        }
        GrantBeside::Stranger(l) => {
            c.shift(OWNER, -i128::from(l));
            c.shift(ATTACKER, i128::from(l));
            ixs.push(ix(
                SYSTEM,
                &[(OWNER, true, true), (ATTACKER, false, true)],
                system_transfer(l),
            ));
        }
    }
    (c, ixs)
}

/// Raydium CLMM `close_position`: the position's accounts closed, their rent
/// returned to the owner.
fn clmm_close(beside: GrantBeside) -> (Cluster, Vec<Ix>) {
    let mut c = Cluster::default();
    base_programs(&mut c);
    let nft_mint = key(60);
    let nft_account = ata_under(OWNER, &nft_mint, TOKEN_2022);
    let (primary, keys, d) = granted_ix(
        &mut c,
        CLMM,
        "close_position",
        &[
            ("nft_owner", OWNER.to_string()),
            ("position_nft_mint", nft_mint.clone()),
            ("position_nft_account", nft_account.clone()),
            ("system_program", SYSTEM.to_string()),
            ("token_program", TOKEN_2022.to_string()),
        ],
        &[],
    );
    let personal = slot(&keys, &d, "personal_position");
    c.set(&personal, acct(2_000_000, CLMM, vec![1u8; 64]));
    c.closed(&personal);
    c.set(&nft_mint, acct(1_461_600, TOKEN_2022, mint(1, None)));
    c.closed(&nft_mint);
    c.set(
        &nft_account,
        acct(RENT, TOKEN_2022, token_account(&nft_mint, OWNER, 1)),
    );
    c.closed(&nft_account);
    let refund = 2_000_000 + 1_461_600 + RENT;
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    c.after(OWNER, acct(10 * SOL - FEE + refund, SYSTEM, vec![]));
    c.set(ATTACKER, acct(SOL, SYSTEM, vec![]));
    let mut ixs = vec![primary];
    if let GrantBeside::Stranger(l) = beside {
        c.shift(OWNER, -i128::from(l));
        c.shift(ATTACKER, i128::from(l));
        ixs.push(ix(
            SYSTEM,
            &[(OWNER, true, true), (ATTACKER, false, true)],
            system_transfer(l),
        ));
    }
    (c, ixs)
}

/// The marketplace's `update_offer`: the buyer moves 10 USDC (MINT_X) from
/// their own associated account into their own escrow's.
fn update_offer(beside: GrantBeside) -> (Cluster, Vec<Ix>) {
    let mut c = Cluster::default();
    base_programs(&mut c);
    let mine = ata(OWNER, MINT_X);
    let escrow = find_program_address(
        &["user_escrow".as_bytes(), pk(OWNER).as_bytes()],
        &pk(MARKETPLACE),
    )
    .unwrap()
    .0
    .to_base58();
    let escrow_token = ata(&escrow, MINT_X);
    let (primary, keys, d) = granted_ix(
        &mut c,
        MARKETPLACE,
        "update_offer",
        &[
            ("buyer", OWNER.to_string()),
            ("asset_id", key(61)),
            ("usdc_mint", MINT_X.to_string()),
            ("buyer_user_escrow_token_account", escrow_token.clone()),
            ("buyer_usdc_account", mine.clone()),
            ("token_program", TOKEN.to_string()),
            ("associated_token_program", ATA_PROGRAM.to_string()),
        ],
        &20_000_000u64.to_le_bytes(),
    );
    let offer = slot(&keys, &d, "offer");
    c.after(&offer, acct(5 * SOL, MARKETPLACE, vec![3u8; 64]));
    c.set(MINT_X, acct(1_461_600, TOKEN, mint(10u64.pow(15), None)));
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    c.after(OWNER, acct(10 * SOL - FEE, SYSTEM, vec![]));
    c.set(ATTACKER, acct(SOL, SYSTEM, vec![]));
    let held = 100_000_000u64;
    let mut left = held - 10_000_000;
    c.set(&mine, acct(RENT, TOKEN, token_account(MINT_X, OWNER, held)));
    c.set(
        &escrow_token,
        acct(RENT, TOKEN, token_account(MINT_X, &escrow, 10_000_000)),
    );
    c.after(
        &escrow_token,
        acct(RENT, TOKEN, token_account(MINT_X, &escrow, 20_000_000)),
    );
    let mut ixs = vec![primary];
    match beside {
        GrantBeside::Nothing => {}
        GrantBeside::TokenSkim(skim) => {
            let theirs = ata(ATTACKER, MINT_X);
            c.set(
                &theirs,
                acct(RENT, TOKEN, token_account(MINT_X, ATTACKER, 0)),
            );
            c.after(
                &theirs,
                acct(RENT, TOKEN, token_account(MINT_X, ATTACKER, skim)),
            );
            left -= skim;
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
        GrantBeside::Stranger(l) => {
            c.shift(OWNER, -i128::from(l));
            c.shift(ATTACKER, i128::from(l));
            ixs.push(ix(
                SYSTEM,
                &[(OWNER, true, true), (ATTACKER, false, true)],
                system_transfer(l),
            ));
        }
    }
    c.after(&mine, acct(RENT, TOKEN, token_account(MINT_X, OWNER, left)));
    (c, ixs)
}

/// The controls: a granted claim and a granted close alone are executable,
/// under the defaults and every waiver, before and after the Round 39 fix.
///
/// The configure grant (`update_offer`) is pinned as REFUSED: its manifest
/// line "modifies writable accounts: …, buyer_usdc_account" names no debit,
/// so L4 refuses the buyer's own USDC moving into their own escrow
/// (`UndeclaredTokenDebit`). That is a false refusal (R39-CORE-DECISION-5),
/// and a declaration fix is the owner's decision; until then the grant
/// cannot reach an executable verdict, and this test says so when it can.
#[tokio::test]
async fn campaign2_a_granted_claim_and_close_alone_are_executable() {
    for w in BOTH {
        let (c, ixs) = dlmm_claim(GrantBeside::Nothing);
        let r = verify(c, OWNER, &ixs, 0, "claim", None, w).await;
        assert_executable(&format!("DLMM claim_fee alone {w:?}"), &r);
        let (c, ixs) = clmm_close(GrantBeside::Nothing);
        let r = verify(c, OWNER, &ixs, 0, "close", None, w).await;
        assert_executable(&format!("CLMM close_position alone {w:?}"), &r);
        let (c, ixs) = update_offer(GrantBeside::Nothing);
        let r = verify(c, OWNER, &ixs, 0, "configure", None, w).await;
        assert_not_executable(&format!("update_offer alone {w:?}"), &r);
        assert!(
            names(&r, "UndeclaredTokenDebit"),
            "update_offer alone is refused for another reason now: {}",
            statuses(&r)
        );
    }
}

/// The control for the fix: value the withdrawal's owner sends to an account
/// the owner keeps (their own wSOL account, no delegate, no close authority)
/// is still the owner's own, and the withdrawal stays executable.
#[tokio::test]
async fn round39_a_withdrawal_beside_the_owners_own_wrap_is_executable() {
    for w in BOTH {
        let r = withdraw_with(WithBeside::OwnWrap(5 * SOL), w).await;
        assert_executable(&format!("stake withdrawal, own wrap, {w:?}"), &r);
    }
}

/// R39-CORE-DECISION-2, reproduced: campaign 2 for the grants the Round 38
/// sibling rule never reached — a claim, a close and a configure bundled
/// with a skim, under the defaults and every waiver. On c087bfb:
///
/// - DLMM `claim_fee` paying 500 of X beside a `TransferChecked` of 300 of it
///   to the attacker: `executable_approved` under the DEFAULTS (the claim
///   intent binds nothing; the owner's account nets a credit, so L4 sees no
///   debit); beside 3 SOL to a stranger: executable with the waivers;
/// - CLMM `close_position` refunding 0.0055 SOL beside 0.005 SOL to a
///   stranger: `executable_approved` under the defaults; beside 3 SOL:
///   executable with the waivers.
///
/// The claim and close refusals must come from the binding
/// (`IntentMismatch`), which no waiver relaxes.
#[tokio::test]
async fn campaign2_a_claim_close_or_configure_with_a_skim_beside_it_is_never_executable() {
    let mut out = Outcomes::default();
    let mut unnamed = Vec::new();
    for w in BOTH {
        for (tag, beside) in [
            ("token skim", GrantBeside::TokenSkim(300)),
            ("stranger", GrantBeside::Stranger(3 * SOL)),
        ] {
            let (c, ixs) = dlmm_claim(beside);
            let r = verify(c, OWNER, &ixs, 0, "claim", None, w).await;
            let tag = format!("DLMM claim_fee, {tag}, {w:?}");
            out.refused(&tag, &r);
            if !names(&r, "IntentMismatch") {
                unnamed.push(tag);
            }
        }
        for (tag, beside) in [
            ("token skim", GrantBeside::TokenSkim(50_000_000)),
            ("stranger", GrantBeside::Stranger(3 * SOL)),
        ] {
            let (c, ixs) = update_offer(beside);
            let r = verify(c, OWNER, &ixs, 0, "configure", None, w).await;
            out.refused(&format!("update_offer, {tag}, {w:?}"), &r);
        }
        for (tag, l) in [
            ("stranger", 3 * SOL),
            ("stranger within the refund", 5_000_000),
        ] {
            let (c, ixs) = clmm_close(GrantBeside::Stranger(l));
            let r = verify(c, OWNER, &ixs, 0, "close", None, w).await;
            let tag = format!("CLMM close_position, {tag}, {w:?}");
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
