//! Requires the `rpc` feature: every verdict here is reached through a
//! simulation served by a loopback mock RPC.
#![cfg(feature = "rpc")]

//! A staking intent does not declare a withdrawal of the user's stake to an
//! account the user does not control (Round 34, finding R33-1).
//!
//! The `stake` intent used to declare the `withdraw` security class, and Check
//! 9 admits the Stake program, Marinade and the SPL Stake Pool for a stake
//! intent. So a Stake `Withdraw` of the user's whole stake account to any
//! address the caller named, labelled "stake my SOL", passed every layer: L4
//! does not see the loss (the debited stake account is neither a System
//! wallet nor a signer-held token account), L5 and Check 9b read the class
//! (`withdraw`) and found the stake intent declares it.
//!
//! Round 30 made withdraw a GROUNDED intent precisely so a withdrawal is
//! declared only when the transaction's own accounts make it the owner's
//! (`intent_grants`); the stake row re-opened that door. Now a stake intent
//! declares no withdrawal, and the staking withdrawals an honest agent makes
//! are declared under `withdraw`, by grants whose facts are read from the
//! instruction's accounts: the funds (or, for a stake-pool stake withdrawal,
//! the new stake account's authority) go to the key that signs as the
//! operation's owner.
//!
//! Every verdict is reached through `verify_async` with a loopback mock RPC
//! that serves the simulation, under a profile an honest transaction can clear
//! (`Custom{0.40, OfficialManifest}`, the auditor's reproduction).

use base64::Engine as _;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::{BehaviorEvidence, TrustTier};
use graphite_core::verification::{
    ExecutionDecision, GraphiteCore, ProposedIntent, VerificationInput, VerificationResult,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

const SYSTEM: &str = "11111111111111111111111111111111";
const STAKE: &str = "Stake11111111111111111111111111111111111111";
const STAKE_POOL: &str = "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy";
const MARINADE: &str = "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const CLOCK: &str = "SysvarC1ock11111111111111111111111111111111";
const STAKE_HISTORY: &str = "SysvarStakeHistory1111111111111111111111111";
const FEE: u64 = 5_000;
const SOL: u64 = 1_000_000_000;
/// A stake account's rent-exempt reserve, which a withdrawal leaves behind.
const STAKE_RENT: u64 = 2_282_880;

/// A distinct, valid key for a role in a fixture.
fn key(seed: u8) -> String {
    let mut b = [seed; 32];
    b[0] = 0x40 | (seed & 0x3f);
    bs58::encode(b).into_string()
}

fn user() -> String {
    key(1)
}
fn attacker() -> String {
    key(2)
}

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

/// One account of a fixture: its key, whether the message makes it a signer
/// and writable, its owner, data, and lamports before and after.
#[derive(Clone)]
struct Acct {
    key: String,
    signer: bool,
    writable: bool,
    owner: String,
    data: Vec<u8>,
    /// The data after, when it changes.
    post_data: Option<Vec<u8>>,
    pre: u64,
    post: u64,
    executable: bool,
}

fn acct(key: &str, signer: bool, writable: bool, owner: &str, pre: u64, post: u64) -> Acct {
    Acct {
        key: key.to_string(),
        signer,
        writable,
        owner: owner.to_string(),
        data: vec![],
        post_data: None,
        pre,
        post,
        executable: false,
    }
}

fn program(key: &str) -> Acct {
    Acct {
        executable: true,
        ..acct(
            key,
            false,
            false,
            "BPFLoaderUpgradeab1e11111111111111111111111",
            1,
            1,
        )
    }
}

fn sysvar(key: &str) -> Acct {
    acct(
        key,
        false,
        false,
        "Sysvar1111111111111111111111111111111111111",
        1,
        1,
    )
}

/// A stake account in the Initialized state whose staker and withdrawer are
/// `authority`.
fn stake_account(key: &str, authority: &str, pre: u64, post: u64) -> Acct {
    let mut data = vec![0u8; 200];
    data[0..4].copy_from_slice(&1u32.to_le_bytes());
    data[4..12].copy_from_slice(&STAKE_RENT.to_le_bytes());
    let a = bs58::decode(authority).into_vec().unwrap();
    data[12..44].copy_from_slice(&a);
    data[44..76].copy_from_slice(&a);
    Acct {
        data,
        ..acct(key, false, true, STAKE, pre, post)
    }
}

/// Stake account data in `state` (1 Initialized, 2 Stake) whose staker and
/// withdrawer are `authority`; state 0 (uninitialized) is all zeroes.
fn stake_data(state: u32, authority: &str) -> Vec<u8> {
    let mut data = vec![0u8; 200];
    if state == 0 {
        return data;
    }
    data[0..4].copy_from_slice(&state.to_le_bytes());
    data[4..12].copy_from_slice(&STAKE_RENT.to_le_bytes());
    let a = bs58::decode(authority).into_vec().unwrap();
    data[12..44].copy_from_slice(&a);
    data[44..76].copy_from_slice(&a);
    data
}

const TOKEN_RENT: u64 = 2_039_280;

/// A 165-byte SPL token account of `owner` for `mint` holding `amount`.
fn token_data(mint: &str, owner: &str, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(&bs58::decode(mint).into_vec().unwrap());
    d[32..64].copy_from_slice(&bs58::decode(owner).into_vec().unwrap());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1; // initialized
    d
}

fn token_account(key: &str, mint: &str, owner: &str, pre: u64, post: u64) -> Acct {
    Acct {
        data: token_data(mint, owner, pre),
        post_data: Some(token_data(mint, owner, post)),
        ..acct(key, false, true, TOKEN, TOKEN_RENT, TOKEN_RENT)
    }
}

/// An 82-byte SPL mint with `supply` before and after, minted by `authority`.
fn mint_account(key: &str, authority: &str, pre: u64, post: u64) -> Acct {
    let data = |supply: u64| {
        let mut d = vec![0u8; 82];
        d[0..4].copy_from_slice(&1u32.to_le_bytes());
        d[4..36].copy_from_slice(&bs58::decode(authority).into_vec().unwrap());
        d[36..44].copy_from_slice(&supply.to_le_bytes());
        d[44] = 9;
        d[45] = 1;
        d
    };
    Acct {
        data: data(pre),
        post_data: Some(data(post)),
        ..acct(key, false, true, TOKEN, 1_461_600, 1_461_600)
    }
}

/// An account a program owns whose data does not change.
fn state_account(key: &str, owner: &str, writable: bool) -> Acct {
    Acct {
        data: vec![7u8; 64],
        ..acct(key, false, writable, owner, 5_000_000, 5_000_000)
    }
}

/// A fixture from the instruction's accounts in its order (a key may
/// repeat; its flags are merged), the fee payer first. The message's keys are
/// ordered as the runtime requires: writable signers, read-only signers,
/// writable non-signers, read-only non-signers, the program last.
fn fixture(
    program_id: &str,
    payer: Acct,
    ix: Vec<Acct>,
    data: Vec<u8>,
    intent: &'static str,
    raw: &'static str,
) -> Fixture {
    let mut keys: Vec<Acct> = vec![payer];
    for a in &ix {
        match keys.iter_mut().find(|k| k.key == a.key) {
            Some(k) => {
                k.signer |= a.signer;
                k.writable |= a.writable;
            }
            None => keys.push(a.clone()),
        }
    }
    let group = |a: &Acct| match (a.signer, a.writable) {
        (true, true) => 0,
        (true, false) => 1,
        (false, true) => 2,
        (false, false) => 3,
    };
    keys.sort_by_key(|a| group(a));
    keys.push(program(program_id));
    let ix_accounts = ix
        .iter()
        .map(|a| keys.iter().position(|k| k.key == a.key).unwrap())
        .collect();
    Fixture {
        accounts: keys,
        program: program_id.to_string(),
        ix_accounts,
        data,
        intent,
        raw,
    }
}

/// A fixture: the message's accounts in key order (signers first, then
/// writable non-signers, then read-only), the primary instruction's program,
/// its account indexes and data.
struct Fixture {
    accounts: Vec<Acct>,
    program: String,
    ix_accounts: Vec<usize>,
    data: Vec<u8>,
    intent: &'static str,
    raw: &'static str,
}

impl Fixture {
    /// A legacy message frame, one signature slot per signer.
    fn frame(&self) -> Vec<u8> {
        let signers = self.accounts.iter().filter(|a| a.signer).count();
        let ro_signed = self
            .accounts
            .iter()
            .filter(|a| a.signer && !a.writable)
            .count();
        let ro_unsigned = self
            .accounts
            .iter()
            .filter(|a| !a.signer && !a.writable)
            .count();
        let mut out = Vec::new();
        compact_u16(signers, &mut out);
        for _ in 0..signers {
            out.extend_from_slice(&[0u8; 64]);
        }
        out.extend_from_slice(&[signers as u8, ro_signed as u8, ro_unsigned as u8]);
        compact_u16(self.accounts.len(), &mut out);
        for a in &self.accounts {
            out.extend_from_slice(&bs58::decode(&a.key).into_vec().unwrap());
        }
        out.extend_from_slice(&[9u8; 32]);
        compact_u16(1, &mut out);
        let p = self
            .accounts
            .iter()
            .position(|a| a.key == self.program)
            .expect("the program is a key");
        out.push(p as u8);
        compact_u16(self.ix_accounts.len(), &mut out);
        out.extend(self.ix_accounts.iter().map(|i| *i as u8));
        compact_u16(self.data.len(), &mut out);
        out.extend_from_slice(&self.data);
        out
    }

    fn disc_hex(&self) -> String {
        let n = if self.program == STAKE {
            4
        } else if self.program == STAKE_POOL {
            1
        } else {
            8
        };
        hex::encode(&self.data[..n])
    }

    fn input(&self) -> VerificationInput {
        VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: self.intent.to_string(),
                raw_natural_language: self.raw.to_string(),
                confidence_of_parse: 0.95,
                extracted_parameters: None,
            },
            program_id: self.program.clone(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: self.disc_hex(),
            account_addresses: self
                .ix_accounts
                .iter()
                .map(|i| self.accounts[*i].key.clone())
                .collect(),
            instruction_data: Some(self.data.clone()),
            cpi_targets: vec![],
            wallet_profile: WalletProfile::Custom {
                min_confidence: 0.40,
                min_trust_tier: TrustTier::OfficialManifest,
            },
            behavior_evidence: BehaviorEvidence::default(),
            compute_units: 0,
            account_writes: 0,
            cpi_hops: 0,
            signed_transaction: Some(self.frame()),
            transaction_instructions: vec![],
            cpi_trace: None,
            real_account_metas: vec![],
            uses_versioned_transaction: false,
            lookup_table_count: 0,
            state_diff: None,
        }
    }

    fn account_json(a: &Acct, post: bool) -> String {
        format!(
            r#"{{"lamports":{},"owner":"{}","executable":{},"rentEpoch":0,"data":["{}","base64"]}}"#,
            if post { a.post } else { a.pre },
            a.owner,
            a.executable,
            base64::engine::general_purpose::STANDARD.encode(if post {
                a.post_data.as_ref().unwrap_or(&a.data)
            } else {
                &a.data
            })
        )
    }

    /// Serve this fixture's cluster on loopback: `getMultipleAccounts` gets
    /// the pre-state, `simulateTransaction` the post-state, each in the order
    /// the request names the addresses.
    fn serve(&self) -> String {
        let accounts = Arc::new(self.accounts.clone());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                let body = read_request(&mut stream);
                let req: serde_json::Value =
                    serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                let find = |k: &str| accounts.iter().find(|a| a.key == k);
                let state = |k: &str, post: bool| {
                    find(k)
                        .map(|a| Fixture::account_json(a, post))
                        .unwrap_or_else(|| "null".to_string())
                };
                let result = match req["method"].as_str() {
                    Some("getMultipleAccounts") => {
                        let keys = req["params"][0].as_array().cloned().unwrap_or_default();
                        let v: Vec<String> = keys
                            .iter()
                            .map(|k| state(k.as_str().unwrap_or(""), false))
                            .collect();
                        format!(r#"{{"context":{{"slot":1}},"value":[{}]}}"#, v.join(","))
                    }
                    Some("simulateTransaction") => {
                        let keys = req["params"][1]["accounts"]["addresses"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default();
                        let post: Vec<String> = keys
                            .iter()
                            .map(|k| state(k.as_str().unwrap_or(""), true))
                            .collect();
                        let pre_b: Vec<String> =
                            accounts.iter().map(|a| a.pre.to_string()).collect();
                        let post_b: Vec<String> =
                            accounts.iter().map(|a| a.post.to_string()).collect();
                        format!(
                            r#"{{"context":{{"slot":1}},"value":{{"err":null,"logs":[],"unitsConsumed":1500,"fee":{FEE},"preBalances":[{}],"postBalances":[{}],"innerInstructions":[],"loadedAddresses":{{"writable":[],"readonly":[]}},"accounts":[{}],"returnData":null}}}}"#,
                            pre_b.join(","),
                            post_b.join(","),
                            post.join(",")
                        )
                    }
                    Some("getAccountInfo") => {
                        let k = req["params"][0].as_str().unwrap_or("");
                        format!(r#"{{"context":{{"slot":1}},"value":{}}}"#, state(k, false))
                    }
                    Some("getSlot") => "1".to_string(),
                    _ => "null".to_string(),
                };
                let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://{addr}")
    }

    async fn verify(&self) -> VerificationResult {
        let mut core = GraphiteCore::new();
        core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
            endpoint: self.serve(),
            timeout: std::time::Duration::from_secs(5),
            max_retries: 0,
            ..Default::default()
        }));
        core.verify_async(&self.input())
            .await
            .expect("verification must reach a verdict")
    }
}

/// Read one HTTP request's body (headers, then Content-Length bytes).
fn read_request(stream: &mut std::net::TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some(end) = text.find("\r\n\r\n") {
            let len = text[..end]
                .lines()
                .find_map(|l| {
                    let l = l.to_ascii_lowercase();
                    l.strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                return String::from_utf8_lossy(&buf[end + 4..end + 4 + len]).to_string();
            }
        }
    }
    String::new()
}

fn layers(r: &VerificationResult) -> String {
    r.layers
        .iter()
        .map(|l| format!("{} {:?}: {}", l.layer, l.status, l.reason))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Everything the result says, for matching a refusal's reason.
fn said(r: &VerificationResult) -> String {
    format!("{}\n{:?}", layers(r), r.risk_verdict)
}

fn assert_refused(r: &VerificationResult, what: &str) {
    assert!(
        !r.approved && r.decision != ExecutionDecision::ExecutableApproved,
        "{what} was approved ({:?}):\n{}",
        r.decision,
        layers(r)
    );
}

fn assert_executable(r: &VerificationResult, what: &str) {
    assert!(
        r.approved && r.decision == ExecutionDecision::ExecutableApproved,
        "{what} was not executable-approved ({:?}):\n{}",
        r.decision,
        layers(r)
    );
}

// ---------------------------------------------------------------------------
// Stake program Withdraw: [stake (w), to (w), clock, stake_history, withdrawer (s)]
// ---------------------------------------------------------------------------

fn stake_withdraw_data(lamports: u64) -> Vec<u8> {
    let mut d = 4u32.to_le_bytes().to_vec();
    d.extend_from_slice(&lamports.to_le_bytes());
    d
}

/// The user's stake account (40 SOL plus rent) withdrawn in full to `to`.
fn stake_withdraw(to: Option<String>, intent: &'static str, raw: &'static str) -> Fixture {
    let amount = 40 * SOL;
    let stake = key(10);
    let user = user();
    let mut accounts = vec![
        acct(
            &user,
            true,
            true,
            SYSTEM,
            SOL,
            SOL - FEE + if to.is_none() { amount } else { 0 },
        ),
        stake_account(&stake, &user, amount + STAKE_RENT, STAKE_RENT),
    ];
    let to_index = match &to {
        Some(to) => {
            accounts.push(acct(to, false, true, SYSTEM, 0, amount));
            2
        }
        None => 0,
    };
    accounts.push(sysvar(CLOCK));
    accounts.push(sysvar(STAKE_HISTORY));
    accounts.push(program(STAKE));
    let n = accounts.len();
    Fixture {
        accounts,
        program: STAKE.to_string(),
        ix_accounts: vec![1, to_index, n - 3, n - 2, 0],
        data: stake_withdraw_data(amount),
        intent,
        raw,
    }
}

#[tokio::test]
async fn a_stake_intent_cannot_withdraw_the_users_stake_to_another_account() {
    let to = attacker();
    let r = stake_withdraw(Some(to.clone()), "stake", "stake my SOL")
        .verify()
        .await;
    assert_refused(
        &r,
        "a Stake Withdraw of the user's stake to a stranger, labelled stake",
    );
    let s = said(&r);
    assert!(
        s.contains("cannot declare") && s.contains("withdraw"),
        "the refusal does not say the stake intent cannot declare a withdrawal:\n{s}"
    );
    assert_names_destination(&r, &to, "Stake Withdraw labelled stake");
}

#[tokio::test]
async fn a_withdraw_intent_cannot_withdraw_the_users_stake_to_another_account() {
    let to = attacker();
    let r = stake_withdraw(Some(to.clone()), "withdraw", "withdraw my stake")
        .verify()
        .await;
    assert_refused(&r, "a Stake Withdraw to a stranger, labelled withdraw");
    let s = said(&r);
    assert!(
        s.contains("`to`") && s.contains(&to),
        "the refusal does not name the destination:\n{s}"
    );
}

#[tokio::test]
async fn a_stake_withdrawal_back_to_the_withdrawer_is_approved_as_a_withdrawal() {
    let r = stake_withdraw(None, "withdraw", "withdraw my stake")
        .verify()
        .await;
    assert_executable(&r, "a Stake Withdraw back to the withdrawer");
}

#[tokio::test]
async fn a_stake_intent_does_not_declare_even_the_owners_own_withdrawal() {
    // The decision: a withdrawal is declared by `withdraw`, grounded; a stake
    // label never declares one, wherever it pays.
    let r = stake_withdraw(None, "stake", "stake my SOL").verify().await;
    assert_refused(&r, "a Stake Withdraw labelled stake");
}

/// Every instruction a `stake` intent declares, by program and class, on the
/// three programs Check 9 admits for it — pinned, so a manifest or table
/// change that widens it is reviewed here. The withdrawals it declared before
/// Round 34 are pinned beside it as declared by no stake intent now.
#[test]
fn the_stake_intent_declares_exactly_these_instructions() {
    let registry = graphite_core::manifest::load_seed_manifests();
    let (mut admitted, mut withdrawals) = (Vec::new(), Vec::new());
    for program in [STAKE, MARINADE, STAKE_POOL] {
        assert!(graphite_core::risk_engine::program_supports_intent_in(
            &registry, program, "stake"
        ));
        for i in &registry.get(program).unwrap().instructions {
            let class = i.security_class();
            match graphite_core::manifest::intent_declares_class("stake", class) {
                Some(true) => admitted.push(format!("{program} {class} {}", i.name)),
                _ if class == "withdraw" => withdrawals.push(format!("{program} {}", i.name)),
                _ => {}
            }
        }
    }
    println!(
        "admitted:\n{}\nwithdrawals:\n{}",
        admitted.join("\n"),
        withdrawals.join("\n")
    );
    let expected: &[&str] = &[
        // Stake: the delegation lifecycle. Split, Merge, MoveStake and
        // MoveLamports keep (or require matching) authorities, so none hands
        // the stake to another key. `Initialize` takes the new account's
        // authorities from its data, unsigned — a residual this list pins.
        "Stake11111111111111111111111111111111111111 create Initialize",
        "Stake11111111111111111111111111111111111111 stake DelegateStake",
        "Stake11111111111111111111111111111111111111 stake Split",
        "Stake11111111111111111111111111111111111111 stake Deactivate",
        "Stake11111111111111111111111111111111111111 stake Merge",
        "Stake11111111111111111111111111111111111111 create InitializeChecked",
        "Stake11111111111111111111111111111111111111 stake DeactivateDelinquent",
        "Stake11111111111111111111111111111111111111 stake MoveStake",
        "Stake11111111111111111111111111111111111111 stake MoveLamports",
        // Marinade: deposits (`transfer`), the permissionless cranks and the
        // operator's validator management.
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD create initialize",
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD create addValidator",
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD transfer deposit",
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD transfer depositStakeAccount",
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD transfer addLiquidity",
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD transfer stakeReserve",
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD transfer updateActive",
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD transfer updateDeactivated",
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD transfer mergeStakes",
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD create createCanonicalStake",
        // SPL Stake Pool: deposits, the balance updates and the staker's
        // moves between the pool's own stake accounts.
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy create Initialize",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy create AddValidatorToPool",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy transfer IncreaseValidatorStake",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy transfer UpdateValidatorListBalance",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy transfer UpdateStakePoolBalance",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy transfer DepositStake",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy transfer DepositSol",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy create CreateTokenMetadata",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy transfer IncreaseAdditionalValidatorStake",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy transfer Redelegate",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy transfer DepositStakeWithSlippage",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy transfer DepositSolWithSlippage",
    ];
    assert_eq!(admitted, expected);
    // Declared by a stake intent until Round 34; by none now, except as a
    // grounded `withdraw` (Stake Withdraw, Marinade liquidUnstake, Stake Pool
    // WithdrawSol/WithdrawStake and their slippage variants).
    let expected_withdrawals: &[&str] = &[
        "Stake11111111111111111111111111111111111111 Withdraw",
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD liquidUnstake",
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD removeLiquidity",
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD orderUnstake",
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD claim",
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD deactivateStake",
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD emergencyUnstake",
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD partialUnstake",
        "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD withdrawStakeAccount",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy DecreaseValidatorStake",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy WithdrawStake",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy WithdrawSol",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy DecreaseAdditionalValidatorStake",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy DecreaseValidatorStakeWithReserve",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy WithdrawStakeWithSlippage",
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy WithdrawSolWithSlippage",
    ];
    assert_eq!(withdrawals, expected_withdrawals);
    for w in &withdrawals {
        let (_, name) = w.split_once(' ').unwrap();
        assert!(
            !admitted
                .iter()
                .any(|a| a.ends_with(&format!(" {name}"))
                    && a.starts_with(w.split(' ').next().unwrap())),
            "{w} is declared by a stake intent"
        );
    }
}

/// Round 34 (C-4): a declared intent is one word to every layer, however it
/// is spelled. It was normalised per layer — Check 9 read the raw string,
/// Check 9b trimmed it, L5 and the grants trimmed and lowercased it — so
/// `"Withdraw"` was grounded by the grant and L5 and then refused by Check 9b
/// as a word outside the vocabulary: the same declaration, judged as two.
#[tokio::test]
async fn intent_case_is_judged_identically_in_every_layer() {
    let statuses = |r: &VerificationResult| {
        r.layers
            .iter()
            .map(|l| format!("{} {:?}", l.layer, l.status))
            .collect::<Vec<_>>()
    };
    let canonical = stake_withdraw(None, "withdraw", "withdraw my stake")
        .verify()
        .await;
    assert_executable(&canonical, "the canonical spelling");
    for spelling in ["Withdraw", "  WITHDRAW  ", "Redeem", "wItHdRaW "] {
        let r = stake_withdraw(None, spelling, "withdraw my stake")
            .verify()
            .await;
        assert_eq!(
            statuses(&r),
            statuses(&canonical),
            "'{spelling}' was judged differently from 'withdraw':\n{}",
            said(&r)
        );
        assert_eq!(r.decision, canonical.decision, "'{spelling}'");
    }
    // And a refusal is a refusal in every spelling.
    let refused = stake_withdraw(Some(attacker()), "withdraw", "withdraw my stake")
        .verify()
        .await;
    for spelling in ["Withdraw", " WITHDRAW "] {
        let r = stake_withdraw(Some(attacker()), spelling, "withdraw my stake")
            .verify()
            .await;
        assert_eq!(statuses(&r), statuses(&refused), "'{spelling}'");
    }
}

/// The grant grounds the withdrawal: L5 and the Risk Engine pass it. (Used
/// where the layers that do not read the intent refuse it on their own — see
/// the note at each call.)
fn assert_grounded(r: &VerificationResult, what: &str) {
    let status = |prefix: &str| {
        r.layers
            .iter()
            .find(|l| l.layer.starts_with(prefix))
            .map(|l| l.status)
    };
    assert_eq!(
        status("L5"),
        Some(graphite_core::verification::LayerStatus::Passed),
        "{what}: L5 did not pass:\n{}",
        layers(r)
    );
    assert_eq!(
        r.risk_verdict.status,
        "Clear",
        "{what}: the Risk Engine refused it:\n{}",
        said(r)
    );
}

/// A refusal that names where the value would have gone.
fn assert_names_destination(r: &VerificationResult, destination: &str, what: &str) {
    let s = said(r);
    assert!(
        s.contains(destination) && s.contains("did not sign for it"),
        "{what}: the refusal does not name the destination {destination}:\n{s}"
    );
}

// ---------------------------------------------------------------------------
// Marinade liquidUnstake: [state, msolMint, liqPoolSolLegPda, liqPoolMsolLeg,
// treasuryMsolAccount, getMsolFrom, getMsolFromAuthority (s), transferSolTo,
// systemProgram, tokenProgram]; args msol_amount
// ---------------------------------------------------------------------------

const MSOL_MINT: &str = "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So";

/// The user swaps 10 mSOL for 11 SOL, paid to `to` (the user when `None`).
fn marinade_liquid_unstake(to: Option<String>, intent: &'static str, raw: &'static str) -> Fixture {
    let (msol, sol) = (10 * SOL, 11 * SOL);
    let user = user();
    let to_user = to.is_none();
    let mut data = hex::decode("1e1e77f0bfe30c10").unwrap();
    data.extend_from_slice(&msol.to_le_bytes());
    let payer = acct(
        &user,
        true,
        true,
        SYSTEM,
        SOL,
        SOL - FEE + if to_user { sol } else { 0 },
    );
    let ix = vec![
        state_account(&key(21), MARINADE, true),
        mint_account(MSOL_MINT, &key(22), 1_000 * SOL, 1_000 * SOL),
        acct(&key(20), false, true, SYSTEM, 500 * SOL, 500 * SOL - sol),
        token_account(&key(23), MSOL_MINT, &key(24), 100 * SOL, 100 * SOL + msol),
        token_account(&key(25), MSOL_MINT, &key(26), 0, 0),
        token_account(&key(27), MSOL_MINT, &user, msol, 0),
        acct(&user, true, false, SYSTEM, SOL, SOL),
        match &to {
            Some(to) => acct(to, false, true, SYSTEM, 0, sol),
            None => acct(&user, false, true, SYSTEM, SOL, SOL),
        },
        program(SYSTEM),
        program(TOKEN),
    ];
    fixture(MARINADE, payer, ix, data, intent, raw)
}

#[tokio::test]
async fn a_stake_intent_cannot_liquid_unstake_marinade_to_another_account() {
    let to = attacker();
    let r = marinade_liquid_unstake(Some(to.clone()), "stake", "unstake my mSOL")
        .verify()
        .await;
    assert_refused(
        &r,
        "a Marinade liquidUnstake paying a stranger, labelled stake",
    );
    assert_names_destination(&r, &to, "liquidUnstake labelled stake");
}

#[tokio::test]
async fn a_withdraw_intent_cannot_liquid_unstake_marinade_to_another_account() {
    let to = attacker();
    let r = marinade_liquid_unstake(Some(to.clone()), "withdraw", "unstake my mSOL")
        .verify()
        .await;
    assert_refused(
        &r,
        "a Marinade liquidUnstake paying a stranger, labelled withdraw",
    );
    assert_names_destination(&r, &to, "liquidUnstake labelled withdraw");
}

#[tokio::test]
async fn a_marinade_liquid_unstake_to_the_signer_is_executable_now_its_declaration_names_its_accounts(
) {
    // Round 34 pinned this control refused: the manifest's "withdraws funds
    // and transfers them out of the pool to the involved accounts" named no
    // account, so the user's mSOL leaving `getMsolFrom` was
    // SignerTokenDebitUnderUnscopedDebit. Round 36 (F-005) rewrote the
    // declaration from Marinade's on-chain IDL
    // (docs/audit-r36/declaration-rewrites.json): it names `getMsolFrom` as
    // the debit and `transferSolTo` as the credit, so the honest unstake is
    // what the declaration says and is executable. The two tests above still
    // refuse it paying anyone else.
    let r = marinade_liquid_unstake(None, "withdraw", "unstake my mSOL")
        .verify()
        .await;
    assert_executable(&r, "an honest Marinade liquidUnstake back to the signer");
}

// ---------------------------------------------------------------------------
// SPL Stake Pool WithdrawSol (12-account layout): [stake_pool, withdraw_authority,
// user_transfer_authority (s), user_pool_token_account, reserve_stake,
// destination, fee_account, pool_mint, clock, stake_history, stake_program,
// token_program]; args pool_tokens
// ---------------------------------------------------------------------------

fn stake_pool_withdraw_sol(to: Option<String>, intent: &'static str, raw: &'static str) -> Fixture {
    let (tokens, sol) = (20 * SOL, 21 * SOL);
    let user = user();
    let to_user = to.is_none();
    let mut data = vec![0x10];
    data.extend_from_slice(&tokens.to_le_bytes());
    let payer = acct(
        &user,
        true,
        true,
        SYSTEM,
        SOL,
        SOL - FEE + if to_user { sol } else { 0 },
    );
    let (pool_mint, withdraw_authority) = (key(30), key(31));
    let ix = vec![
        state_account(&key(32), STAKE_POOL, true),
        acct(&withdraw_authority, false, false, SYSTEM, 0, 0),
        acct(&user, true, false, SYSTEM, SOL, SOL),
        token_account(&key(33), &pool_mint, &user, tokens, 0),
        Acct {
            data: stake_data(1, &withdraw_authority),
            ..acct(&key(34), false, true, STAKE, 900 * SOL, 900 * SOL - sol)
        },
        match &to {
            Some(to) => acct(to, false, true, SYSTEM, 0, sol),
            None => acct(&user, false, true, SYSTEM, SOL, SOL),
        },
        token_account(&key(35), &pool_mint, &key(36), 0, 0),
        mint_account(
            &pool_mint,
            &withdraw_authority,
            800 * SOL,
            800 * SOL - tokens,
        ),
        sysvar(CLOCK),
        sysvar(STAKE_HISTORY),
        program(STAKE),
        program(TOKEN),
    ];
    fixture(STAKE_POOL, payer, ix, data, intent, raw)
}

#[tokio::test]
async fn a_stake_intent_cannot_withdraw_stake_pool_sol_to_another_account() {
    let to = attacker();
    let r = stake_pool_withdraw_sol(Some(to.clone()), "stake", "stake my SOL")
        .verify()
        .await;
    assert_refused(
        &r,
        "a Stake Pool WithdrawSol paying a stranger, labelled stake",
    );
    assert_names_destination(&r, &to, "WithdrawSol labelled stake");
}

#[tokio::test]
async fn a_stake_pool_sol_withdrawal_to_the_signer_is_grounded_as_a_withdrawal() {
    // Not executable-approved, before or after Round 34: L4 refuses the pool
    // token burn, which the Stake Pool manifest's prose declaration does not
    // name (UndeclaredBurn). The intent layers now ground it; a declaration
    // rewrite would let it reach approval (reported as a residual).
    let r = stake_pool_withdraw_sol(None, "withdraw", "withdraw my pooled SOL")
        .verify()
        .await;
    assert_grounded(&r, "a Stake Pool WithdrawSol paying the signer");
}

// ---------------------------------------------------------------------------
// SPL Stake Pool WithdrawStake: [stake_pool, validator_list, withdraw_authority,
// validator_or_reserve_stake, new_stake_account, user_withdraw_authority,
// user_transfer_authority (s), user_pool_token_account, fee_account, pool_mint,
// clock, token_program, stake_program]; args pool_tokens. The split-off stake
// account's authority becomes `user_withdraw_authority`, which does not sign.
// ---------------------------------------------------------------------------

fn stake_pool_withdraw_stake(
    authority: Option<String>,
    intent: &'static str,
    raw: &'static str,
) -> Fixture {
    let (tokens, sol) = (20 * SOL, 21 * SOL);
    let user = user();
    let new_authority = authority.clone().unwrap_or_else(|| user.clone());
    let mut data = vec![0x0a];
    data.extend_from_slice(&tokens.to_le_bytes());
    let payer = acct(&user, true, true, SYSTEM, SOL, SOL - FEE);
    let (pool_mint, withdraw_authority) = (key(40), key(41));
    let ix = vec![
        state_account(&key(43), STAKE_POOL, true),
        state_account(&key(44), STAKE_POOL, true),
        acct(&withdraw_authority, false, false, SYSTEM, 0, 0),
        Acct {
            data: stake_data(2, &withdraw_authority),
            ..acct(&key(45), false, true, STAKE, 900 * SOL, 900 * SOL - sol)
        },
        Acct {
            data: stake_data(0, &user),
            post_data: Some(stake_data(2, &new_authority)),
            ..acct(&key(42), false, true, STAKE, STAKE_RENT, STAKE_RENT + sol)
        },
        match &authority {
            Some(a) => acct(a, false, false, SYSTEM, 0, 0),
            None => acct(&user, false, false, SYSTEM, SOL, SOL),
        },
        acct(&user, true, false, SYSTEM, SOL, SOL),
        token_account(&key(46), &pool_mint, &user, tokens, 0),
        token_account(&key(47), &pool_mint, &key(48), 0, 0),
        mint_account(
            &pool_mint,
            &withdraw_authority,
            800 * SOL,
            800 * SOL - tokens,
        ),
        sysvar(CLOCK),
        program(TOKEN),
        program(STAKE),
    ];
    fixture(STAKE_POOL, payer, ix, data, intent, raw)
}

#[tokio::test]
async fn a_stake_intent_cannot_withdraw_a_stake_pool_stake_account_to_another_authority() {
    let to = attacker();
    let r = stake_pool_withdraw_stake(Some(to.clone()), "stake", "stake my SOL")
        .verify()
        .await;
    assert_refused(
        &r,
        "a Stake Pool WithdrawStake handing the stake to a stranger, labelled stake",
    );
    assert_names_destination(&r, &to, "WithdrawStake labelled stake");
}

#[tokio::test]
async fn a_withdraw_intent_cannot_withdraw_a_stake_pool_stake_account_to_another_authority() {
    let to = attacker();
    let r = stake_pool_withdraw_stake(Some(to.clone()), "withdraw", "withdraw my stake")
        .verify()
        .await;
    assert_refused(
        &r,
        "a Stake Pool WithdrawStake handing the stake to a stranger, labelled withdraw",
    );
    assert_names_destination(&r, &to, "WithdrawStake labelled withdraw");
}

#[tokio::test]
async fn a_stake_pool_stake_withdrawal_to_the_signer_is_grounded_as_a_withdrawal() {
    // Not executable-approved, before or after Round 34: L4 refuses the new
    // stake account's authorities appearing and the pool token burn, which
    // the manifest's prose does not declare (UndeclaredNativeAuthorityChange,
    // UndeclaredBurn). The intent layers now ground it; a declaration
    // rewrite would let it reach approval (reported as a residual).
    let r = stake_pool_withdraw_stake(None, "withdraw", "withdraw my stake")
        .verify()
        .await;
    assert_grounded(&r, "a Stake Pool WithdrawStake to the signer's authority");
}
