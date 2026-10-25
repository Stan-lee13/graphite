//! Requires the `rpc` feature: every verdict here rests on a simulated diff.
#![cfg(feature = "rpc")]

//! Round 38 (R37-6): an authority line that names no account does not
//! excuse an effect on an account a signer holds.
//!
//! Round 34 judged a signer's debit and a creation only by a line that names
//! the account (`covers_by_name`, R33-5) and left the delegate, close,
//! owner and authority judgements on `covers`, which a line naming no
//! account satisfies for EVERY account. "updates protocol configuration or
//! authority" (1,018 shipped instructions carry it) then excused a delegate
//! granted on the signer's own token account by CPI. End to end: a signed
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
    VerificationInput, VerificationResult,
};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

const SYSTEM: &str = "11111111111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const NATIVE_LOADER: &str = "NativeLoader1111111111111111111111111111111";

/// The wallet that signs and pays.
const OWNER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
/// Somebody else.
const ATTACKER: &str = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7";
const MINT_X: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

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
        // round38_sibling_skims.rs): the bar sits below the 0.44 a program
        // with no L3 baseline yet scores.
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

const MARGINFI: &str = "MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA";
const RENT: u64 = 2_039_280;

/// SPL Token account bytes with a delegate and a close authority.
fn token_account_full(
    mint_key: &str,
    owner: &str,
    amount: u64,
    delegate: Option<&str>,
    close_authority: Option<&str>,
) -> Vec<u8> {
    let mut d = token_account(mint_key, owner, amount);
    if let Some(dl) = delegate {
        d[72..76].copy_from_slice(&1u32.to_le_bytes());
        d[76..108].copy_from_slice(pk(dl).as_bytes());
        d[121..129].copy_from_slice(&amount.to_le_bytes());
    }
    if let Some(c) = close_authority {
        d[129..133].copy_from_slice(&1u32.to_le_bytes());
        d[133..165].copy_from_slice(pk(c).as_bytes());
    }
    d
}

/// What the simulation does to `target` beside the declared configuration
/// change.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Effect {
    /// Nothing: only the marginfi account's own data changes.
    Nothing,
    /// A delegate for the whole balance, granted to the attacker.
    Delegate,
    /// The token account's owner field handed to the attacker.
    Owner,
    /// A close authority set to the attacker.
    CloseAuthority,
    /// The account closed, its lamports to the attacker.
    Closure,
}

/// Marginfi's `marginfi_account_set_keeper_close_flags`, whose declaration
/// is `modifies writable accounts: marginfi_account` and `updates protocol
/// configuration or authority`, signed by the owner, with `target` (a token
/// account owned by `target_owner`) passed as a writable remaining account
/// and `effect` applied to it by CPI.
fn configure(target_owner: &str, effect: Effect) -> (Cluster, Vec<Ix>) {
    let mut c = Cluster::default();
    let d = def(MARGINFI, "marginfi_account_set_keeper_close_flags");
    let marginfi_account = key(50);
    let target = if target_owner == OWNER {
        ata(OWNER, MINT_X)
    } else {
        key(51)
    };
    let mut data = hex_to_bytes(&d.discriminator);
    data.push(1);
    let primary = ix(
        MARGINFI,
        &[
            (&marginfi_account, false, true),
            (OWNER, true, false),
            (&target, false, true),
            (TOKEN, false, false),
        ],
        data,
    );
    for (p, owner) in [(MARGINFI, LOADER), (TOKEN, LOADER), (SYSTEM, NATIVE_LOADER)] {
        c.set(p, program_account(owner));
    }
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    c.after(OWNER, acct(10 * SOL - FEE, SYSTEM, vec![]));
    c.set(ATTACKER, acct(SOL, SYSTEM, vec![]));
    c.set(MINT_X, acct(1_461_600, TOKEN, mint(10u64.pow(15), None)));
    c.set(&marginfi_account, acct(5 * SOL, MARGINFI, vec![1u8; 64]));
    c.after(&marginfi_account, acct(5 * SOL, MARGINFI, vec![2u8; 64]));
    c.set(
        &target,
        acct(RENT, TOKEN, token_account(MINT_X, target_owner, 1_000_000)),
    );
    match effect {
        Effect::Nothing => {}
        Effect::Delegate => c.after(
            &target,
            acct(
                RENT,
                TOKEN,
                token_account_full(MINT_X, target_owner, 1_000_000, Some(ATTACKER), None),
            ),
        ),
        Effect::Owner => c.after(
            &target,
            acct(RENT, TOKEN, token_account(MINT_X, ATTACKER, 1_000_000)),
        ),
        Effect::CloseAuthority => c.after(
            &target,
            acct(
                RENT,
                TOKEN,
                token_account_full(MINT_X, target_owner, 1_000_000, None, Some(ATTACKER)),
            ),
        ),
        Effect::Closure => {
            c.set(
                &target,
                acct(RENT, TOKEN, token_account(MINT_X, target_owner, 0)),
            );
            c.post.insert(target.clone(), None);
            c.after(ATTACKER, acct(SOL + RENT, SYSTEM, vec![]));
        }
    }
    (c, vec![primary])
}

fn record(tag: &str, r: &VerificationResult) {
    let l4 = r
        .layers
        .iter()
        .find(|l| l.layer.starts_with("L4"))
        .map(|l| l.reason.chars().take(500).collect::<String>())
        .unwrap_or_default();
    eprintln!(
        "[R37-6 {tag}] decision={:?} | {} | risk: {} | L4: {l4}",
        r.decision,
        statuses(r),
        risk(r)
    );
}

fn l4_names(r: &VerificationResult, code: &str) -> bool {
    r.layers
        .iter()
        .any(|l| l.layer.starts_with("L4") && l.reason.contains(code))
}

fn l4_passed(r: &VerificationResult) -> bool {
    r.layers
        .iter()
        .any(|l| l.layer.starts_with("L4") && l.status == LayerStatus::Passed)
}

// ─── Under an authority line ───────────────────────────────────────────────
//
// An `authority`-class instruction is never executable whatever L4 says (L5
// refuses every intent for it and the Risk Engine reports `AuthorityHijack`:
// no intent declares an authority hand-over), so these are judged at L4.
// Of the 1,057 shipped instructions with an authority line that names no
// account, 12 are in another class (`r30_declared_effects_census.rs`).

/// The control at L4: the configuration change alone passes.
#[tokio::test]
async fn the_configuration_change_alone_passes_l4() {
    let (c, ixs) = configure(OWNER, Effect::Nothing);
    let r = verify(c, OWNER, &ixs, 0, "configure", None).await;
    record("control", &r);
    assert!(l4_passed(&r), "{}", statuses(&r));
}

/// R37-6: a delegate for the signer's whole balance, granted by CPI under
/// "updates protocol configuration or authority".
#[tokio::test]
async fn an_unscoped_authority_line_does_not_excuse_a_delegate_on_the_signers_account() {
    let (c, ixs) = configure(OWNER, Effect::Delegate);
    let r = verify(c, OWNER, &ixs, 0, "configure", None).await;
    record("delegate", &r);
    assert!(
        l4_names(&r, "UndeclaredDelegateGrant"),
        "L4 does not name it: {}",
        statuses(&r)
    );
    assert_ne!(r.decision, ExecutionDecision::ExecutableApproved);
}

/// The owner, close-authority and closure variants on the signer's account.
#[tokio::test]
async fn an_unscoped_authority_line_does_not_excuse_an_owner_close_authority_or_closure() {
    for (effect, code) in [
        (Effect::Owner, "UndeclaredTokenAuthorityChange"),
        (Effect::CloseAuthority, "UndeclaredCloseAuthorityGrant"),
        (Effect::Closure, "UndeclaredAccountClosure"),
    ] {
        let (c, ixs) = configure(OWNER, effect);
        let r = verify(c, OWNER, &ixs, 0, "configure", None).await;
        record(&format!("{effect:?}"), &r);
        assert!(
            l4_names(&r, code),
            "{effect:?}: L4 does not name {code}: {}",
            statuses(&r)
        );
        assert_ne!(r.decision, ExecutionDecision::ExecutableApproved);
    }
}

/// The control the split keeps: the same line still covers an authority
/// change on an account no signer holds (a pool's or a vault's).
#[tokio::test]
async fn an_unscoped_authority_line_still_covers_a_pool_accounts_authority() {
    let pool = key(90);
    let (c, ixs) = configure(&pool, Effect::Owner);
    let r = verify(c, OWNER, &ixs, 0, "configure", None).await;
    record("pool owner", &r);
    assert!(
        l4_passed(&r),
        "the pool's authority change is refused: {}",
        statuses(&r)
    );
}

// ─── Under a close line ────────────────────────────────────────────────────
//
// 137 instructions of the `close` class carry a close line that names no
// account ("closes the position or account and transfers remaining funds
// back to the user"). None of them is executable today: a `close` intent is
// served by the token programs, Jupiter DCA and the close grants, and every
// one of those names the accounts it closes. So these are judged at L4, as
// above. Orca's `closeBundledPosition` declares only "closes the bundled
// position account and reclaims rent".

const ORCA: &str = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";

/// Orca's `closeBundledPosition`, signed by the owner, closing the bundled
/// position to the owner, with the owner's own token account passed as a
/// writable remaining account and `effect` applied to it by CPI.
fn close_bundled(effect: Effect) -> (Cluster, Vec<Ix>) {
    let mut c = Cluster::default();
    let d = def(ORCA, "closeBundledPosition");
    let (bundled, bundle, bundle_token) = (key(60), key(61), key(62));
    let mine = ata(OWNER, MINT_X);
    let data = hex_to_bytes(&d.discriminator);
    let primary = ix(
        ORCA,
        &[
            (&bundled, false, true),
            (&bundle, false, true),
            (&bundle_token, false, false),
            (OWNER, true, false),
            (OWNER, false, true),
            (&mine, false, true),
            (TOKEN, false, false),
        ],
        {
            let mut v = data;
            v.extend_from_slice(&0u16.to_le_bytes());
            v
        },
    );
    for (p, owner) in [(ORCA, LOADER), (TOKEN, LOADER), (SYSTEM, NATIVE_LOADER)] {
        c.set(p, program_account(owner));
    }
    c.set(ATTACKER, acct(SOL, SYSTEM, vec![]));
    c.set(MINT_X, acct(1_461_600, TOKEN, mint(10u64.pow(15), None)));
    // The bundled position closes to its receiver, the owner.
    let position_rent = 1_000_000;
    c.set(&bundled, acct(position_rent, ORCA, vec![1u8; 64]));
    c.post.insert(bundled.clone(), None);
    c.set(&bundle, acct(5 * SOL, ORCA, vec![1u8; 64]));
    c.after(&bundle, acct(5 * SOL, ORCA, vec![2u8; 64]));
    c.set(
        &bundle_token,
        acct(RENT, TOKEN, token_account(&key(63), OWNER, 1)),
    );
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    c.after(OWNER, acct(10 * SOL - FEE + position_rent, SYSTEM, vec![]));
    c.set(&mine, acct(RENT, TOKEN, token_account(MINT_X, OWNER, 0)));
    match effect {
        Effect::Nothing => {}
        Effect::CloseAuthority => c.after(
            &mine,
            acct(
                RENT,
                TOKEN,
                token_account_full(MINT_X, OWNER, 0, None, Some(ATTACKER)),
            ),
        ),
        Effect::Closure => {
            c.post.insert(mine.clone(), None);
            c.after(ATTACKER, acct(SOL + RENT, SYSTEM, vec![]));
        }
        Effect::Delegate | Effect::Owner => unreachable!("judged under the authority line above"),
    }
    (c, vec![primary])
}

/// The control at L4: the bundled position (the program's own account)
/// closes to the owner under the line, nothing else.
#[tokio::test]
async fn closing_the_bundled_position_alone_passes_l4() {
    let (c, ixs) = close_bundled(Effect::Nothing);
    let r = verify(c, OWNER, &ixs, 0, "close", None).await;
    record("close control", &r);
    assert!(l4_passed(&r), "{}", statuses(&r));
}

/// R37-6: under the bundled position's close line, the signer's own token
/// account is closed to the attacker, or handed a close authority the
/// attacker holds.
#[tokio::test]
async fn an_unscoped_close_line_does_not_excuse_closing_the_signers_account() {
    for (effect, code) in [
        (Effect::Closure, "UndeclaredAccountClosure"),
        (Effect::CloseAuthority, "UndeclaredCloseAuthorityGrant"),
    ] {
        let (c, ixs) = close_bundled(effect);
        let r = verify(c, OWNER, &ixs, 0, "close", None).await;
        record(&format!("close {effect:?}"), &r);
        assert_ne!(
            r.decision,
            ExecutionDecision::ExecutableApproved,
            "{effect:?}: {}",
            risk(&r)
        );
        assert!(
            l4_names(&r, code),
            "{effect:?}: L4 does not name {code}: {}",
            statuses(&r)
        );
    }
}

// ─── Under a transfer's "between owners", end to end ───────────────────────
//
// Executable classes with such a line: 12 (create 9, withdraw 2, transfer 1,
// `r30_declared_effects_census.rs`). A `transfer` intent is served by every
// program, so Orca's `transferLockedPosition` is reachable.

/// A program somebody deployed.
const FOREIGN: &str = "Fore1gnProgram11111111111111111111111111111";

/// Orca's `transferLockedPosition`, declared "transfers a locked position
/// between owners" (an owner change that names no account, to the parser),
/// signed by the owner, beside the attacker's own program, which the owner's
/// signature lets hand the owner's USDC account to the attacker by CPI when
/// `takeover`. The position itself does not move: what the transaction
/// does is the attacker's to choose.
fn transfer_locked(takeover: bool) -> (Cluster, Vec<Ix>) {
    let mut c = Cluster::default();
    let d = def(ORCA, "transferLockedPosition");
    let (position, position_mint, position_ta, dest_ta, lock_config) =
        (key(70), key(71), key(72), key(73), key(74));
    let primary = ix(
        ORCA,
        &[
            (OWNER, true, false),
            (OWNER, false, true),
            (&position, false, false),
            (&position_mint, false, false),
            (&position_ta, false, true),
            (&dest_ta, false, true),
            (&lock_config, false, true),
            (TOKEN, false, false),
        ],
        hex_to_bytes(&d.discriminator),
    );
    for (p, owner) in [
        (ORCA, LOADER),
        (TOKEN, LOADER),
        (FOREIGN, LOADER),
        (SYSTEM, NATIVE_LOADER),
    ] {
        c.set(p, program_account(owner));
    }
    c.set(OWNER, acct(10 * SOL, SYSTEM, vec![]));
    c.after(OWNER, acct(10 * SOL - FEE, SYSTEM, vec![]));
    c.set(ATTACKER, acct(SOL, SYSTEM, vec![]));
    c.set(MINT_X, acct(1_461_600, TOKEN, mint(10u64.pow(15), None)));
    c.set(&position, acct(RENT, ORCA, vec![1u8; 64]));
    c.set(&position_mint, acct(RENT, TOKEN, mint(1, None)));
    c.set(
        &position_ta,
        acct(RENT, TOKEN, token_account(&position_mint, OWNER, 1)),
    );
    c.set(
        &dest_ta,
        acct(RENT, TOKEN, token_account(&position_mint, ATTACKER, 0)),
    );
    c.set(&lock_config, acct(RENT, ORCA, vec![1u8; 64]));
    c.after(&lock_config, acct(RENT, ORCA, vec![2u8; 64]));
    let mine = ata(OWNER, MINT_X);
    c.set(
        &mine,
        acct(RENT, TOKEN, token_account(MINT_X, OWNER, 1_000_000)),
    );
    let mut ixs = vec![primary];
    if takeover {
        c.after(
            &mine,
            acct(RENT, TOKEN, token_account(MINT_X, ATTACKER, 1_000_000)),
        );
        ixs.push(ix(
            FOREIGN,
            &[
                (&mine, false, true),
                (OWNER, true, false),
                (TOKEN, false, false),
            ],
            vec![7],
        ));
    }
    (c, ixs)
}

/// R37-6, end to end: the owner's USDC account handed to the attacker
/// beside an Orca `transferLockedPosition`.
#[tokio::test]
async fn an_unscoped_owner_line_does_not_excuse_handing_away_the_signers_account() {
    let (c, ixs) = transfer_locked(true);
    let r = verify(c, OWNER, &ixs, 0, "transfer", None).await;
    record("between owners takeover", &r);
    assert_ne!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{}",
        risk(&r)
    );
    assert!(
        l4_names(&r, "UndeclaredTokenAuthorityChange"),
        "L4 does not name it: {}",
        statuses(&r)
    );
}
