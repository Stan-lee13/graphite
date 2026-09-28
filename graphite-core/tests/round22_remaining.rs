//! Round 22: the remaining open items, closed where the chain allows.
//!
//! Round 21 left a transfer hook that runs a program blocking on sight: "a
//! hook program is arbitrary code". What that code can DO in a transaction,
//! though, is not arbitrary. Token-2022 hands the hook the transfer's
//! source, mint, destination and authority read-only and unsigned, and the
//! extra accounts its validation list names — which it can only take from
//! the accounts the transfer itself was handed, at no more privilege than the
//! transaction gives them. So the transaction's bytes bound the hook, at
//! simulation and at landing alike: it can hold a signature only if one of
//! those accounts signs, and write only what the transaction marks writable.
//!
//! These tests pin the rule that replaced the blanket refusal:
//!
//! - a hook handed no signer of the transaction and no writable account but
//!   its own is inert, and says why;
//! - a signer, a writable account another program owns, or a writable
//!   account Graphite did not observe, blocks — naming the account;
//! - without the executed list or the transaction's privileges, it blocks as
//!   before;
//! - through the pipeline over a loopback mock RPC, the hook the simulator
//!   saw Token-2022 invoke is judged as part of the transfer — and a hook
//!   whose caller cannot be established is still an unknown program's call.
//!
//! The Round 22 change to the fee model's pending schedule (no assumed
//! landing margin) is pinned in `round21_open_list.rs`, next to the tests it
//! rewrote.

use graphite_core::account_resolution::{AccountIdentity, ResolvedAccount};
use graphite_core::state_diff::{
    check_state_diff, transfer_hooks_bounded, AccountDelta, AccountSnapshot, DiffProvenance,
    ExecutedTokenInstruction, StateDiff, StateDiffCheck, StateDiffReport, TransactionPrivileges,
};

const T22: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

fn b58(k: &[u8; 32]) -> String {
    bs58::encode(k).into_string()
}

const MINT: [u8; 32] = [21u8; 32];
const OTHER_MINT: [u8; 32] = [22u8; 32];
const SRC_OWNER: [u8; 32] = [11u8; 32];
const DST_OWNER: [u8; 32] = [12u8; 32];
const SOURCE: [u8; 32] = [31u8; 32];
const DEST: [u8; 32] = [32u8; 32];
const OWNER_SIGNER: [u8; 32] = [51u8; 32];
const COSIGNER: [u8; 32] = [52u8; 32];
const HOOK: [u8; 32] = [71u8; 32];
const VALIDATION: [u8; 32] = [73u8; 32];
const HOOK_STATE: [u8; 32] = [74u8; 32];
const UNSEEN: [u8; 32] = [75u8; 32];

// ─── Byte builders: the real layouts, so the real decoders run ─────────────

fn tlv(entries: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (t, v) in entries {
        out.extend_from_slice(&t.to_le_bytes());
        out.extend_from_slice(&(v.len() as u16).to_le_bytes());
        out.extend_from_slice(v);
    }
    out
}

/// A Token-2022 account of `mint` flagged `TransferHookAccount`.
fn hooked_account(mint: [u8; 32], owner: [u8; 32], amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(&mint);
    d[32..64].copy_from_slice(&owner);
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    d.push(2);
    d.extend(tlv(&[(15, vec![0])]));
    d
}

/// A Token-2022 mint whose `TransferHook` names `program`.
fn hooked_mint(program: [u8; 32]) -> Vec<u8> {
    let mut d = vec![0u8; 82];
    d[36..44].copy_from_slice(&1_000_000u64.to_le_bytes());
    d[44] = 6;
    d[45] = 1;
    d.resize(165, 0);
    d.push(1);
    let mut v = vec![0u8; 32];
    v.extend_from_slice(&program);
    d.extend(tlv(&[(14, v)]));
    d
}

fn snap(key: &[u8; 32], owner: &str, data: &[u8]) -> AccountSnapshot {
    AccountSnapshot::from_raw(&b58(key), 2_039_280, owner, data)
}

fn transfer_deltas() -> Vec<AccountDelta> {
    vec![
        AccountDelta {
            pubkey: b58(&SOURCE),
            before: Some(snap(&SOURCE, T22, &hooked_account(MINT, SRC_OWNER, 10_000))),
            after: Some(snap(&SOURCE, T22, &hooked_account(MINT, SRC_OWNER, 9_000))),
        },
        AccountDelta {
            pubkey: b58(&DEST),
            before: Some(snap(&DEST, T22, &hooked_account(MINT, DST_OWNER, 0))),
            after: Some(snap(&DEST, T22, &hooked_account(MINT, DST_OWNER, 1_000))),
        },
    ]
}

/// The hook's own counter account, owned by the hook program.
fn hook_state_delta() -> AccountDelta {
    AccountDelta {
        pubkey: b58(&HOOK_STATE),
        before: Some(snap(&HOOK_STATE, &b58(&HOOK), &[1, 0, 0, 0])),
        after: Some(snap(&HOOK_STATE, &b58(&HOOK), &[2, 0, 0, 0])),
    }
}

fn transfer_checked(at: &str, accounts: &[[u8; 32]], amount: u64) -> ExecutedTokenInstruction {
    let mut data = vec![12u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(6);
    ExecutedTokenInstruction {
        position: at.to_string(),
        accounts: accounts.iter().map(b58).collect(),
        data,
    }
}

/// [source, mint, destination, authority] followed by `extras`.
fn hooked_transfer(extras: &[[u8; 32]]) -> ExecutedTokenInstruction {
    let mut a = vec![SOURCE, MINT, DEST, OWNER_SIGNER];
    a.extend_from_slice(extras);
    transfer_checked("instruction #0", &a, 1_000)
}

fn privileges(signers: &[[u8; 32]], writable: &[[u8; 32]]) -> TransactionPrivileges {
    TransactionPrivileges {
        signers: signers.iter().map(b58).collect(),
        writable: writable.iter().map(b58).collect(),
    }
}

/// The usual shape: the owner signs and pays, the two token accounts are
/// writable, and so is `extra_writable`.
fn usual(extra_writable: &[[u8; 32]]) -> Option<TransactionPrivileges> {
    let mut w = vec![OWNER_SIGNER, SOURCE, DEST];
    w.extend_from_slice(extra_writable);
    Some(privileges(&[OWNER_SIGNER], &w))
}

fn diff(
    deltas: Vec<AccountDelta>,
    executed: Option<Vec<ExecutedTokenInstruction>>,
    privileges: Option<TransactionPrivileges>,
) -> StateDiff {
    let mut d = StateDiff {
        deltas,
        provenance: DiffProvenance::RpcSimulated,
        ..Default::default()
    };
    d.token2022_mints
        .insert(b58(&MINT), snap(&MINT, T22, &hooked_mint(HOOK)));
    d.token2022_executed = executed;
    d.transaction_privileges = privileges;
    d
}

fn resolved(address: &str) -> ResolvedAccount {
    ResolvedAccount {
        address: address.to_string(),
        role: "account".to_string(),
        is_pda: false,
        is_signer: false,
        is_writable: true,
        pda_seeds: vec![],
        identity: AccountIdentity::Unverified,
        expected_address_mismatch: false,
        pda_mismatch: false,
        privilege_mismatch: false,
    }
}

fn check(diff: &StateDiff) -> StateDiffReport {
    let accounts: Vec<ResolvedAccount> = diff.deltas.iter().map(|d| resolved(&d.pubkey)).collect();
    let declared = [
        "debits accounts.source token balance by data.amount".to_string(),
        "credits accounts.destination token balance by data.amount".to_string(),
    ];
    check_state_diff(&StateDiffCheck {
        diff,
        resolved_accounts: &accounts,
        privileges_grounded: true,
        expected_state_changes: &declared,
        fee_payer: None,
    })
}

fn detail(r: &StateDiffReport, code: &str) -> String {
    r.findings
        .iter()
        .filter(|f| f.code == code)
        .map(|f| f.detail.clone())
        .collect::<Vec<_>>()
        .join(" || ")
}

fn assert_inert(r: &StateDiffReport, why: &str) {
    assert!(!r.blocked, "{:?}", r.findings);
    assert!(
        detail(r, "Token2022ExtensionNotModelled").is_empty(),
        "{:?}",
        r.findings
    );
    let d = detail(r, "Token2022ExtensionInert");
    assert!(d.contains(why), "expected {why:?}: {d}");
}

fn assert_blocks(r: &StateDiffReport, why: &str) {
    assert!(r.blocked, "{:?}", r.findings);
    let d = detail(r, "Token2022ExtensionNotModelled");
    assert!(d.contains(why), "expected {why:?}: {d}");
}

// ─── The rule ───────────────────────────────────────────────────────────────

/// The shape a honest hook transfer has: the validation list and the hook
/// program, both read-only. Whatever the hook's code does, it holds no
/// signature and can write nothing.
#[test]
fn a_hook_the_bytes_give_nothing_to_is_inert() {
    let r = check(&diff(
        transfer_deltas(),
        Some(vec![hooked_transfer(&[VALIDATION, HOOK])]),
        usual(&[]),
    ));
    assert_inert(&r, "no signer and no writable account but 0 of its own");
    assert!(detail(&r, "Token2022ExtensionInert").contains(&b58(&HOOK)));
}

/// A hook that keeps its own state — a counter, an allow-list — writes an
/// account it owns. That moves nothing of anyone else's.
#[test]
fn a_hook_writing_only_its_own_account_is_inert() {
    let mut deltas = transfer_deltas();
    deltas.push(hook_state_delta());
    let r = check(&diff(
        deltas,
        Some(vec![hooked_transfer(&[HOOK_STATE, VALIDATION, HOOK])]),
        usual(&[HOOK_STATE]),
    ));
    assert_inert(&r, "but 1 of its own");
}

/// The attack the rule exists for: the extra-account list names the owner's
/// own wallet, and the transfer passes it again — as a signer. The hook
/// would hold the owner's signature.
#[test]
fn a_hook_handed_a_signer_blocks_and_names_it() {
    let r = check(&diff(
        transfer_deltas(),
        Some(vec![hooked_transfer(&[OWNER_SIGNER, VALIDATION, HOOK])]),
        usual(&[]),
    ));
    assert_blocks(&r, "which signs this transaction");
    assert!(detail(&r, "Token2022ExtensionNotModelled").contains(&b58(&OWNER_SIGNER)));
}

/// A multisig's signers ride in the same slots the extra accounts are read
/// from; a signature there is a signature a hook could use.
#[test]
fn a_multisig_signer_in_the_hook_slots_blocks() {
    let r = check(&diff(
        transfer_deltas(),
        Some(vec![hooked_transfer(&[COSIGNER, VALIDATION, HOOK])]),
        Some(privileges(
            &[OWNER_SIGNER, COSIGNER],
            &[OWNER_SIGNER, SOURCE, DEST],
        )),
    ));
    assert_blocks(&r, &b58(&COSIGNER));
}

/// A writable token account passed to the hook: owned by Token-2022, not the
/// hook — if the hook's PDA were its delegate, the hook could move it.
#[test]
fn a_hook_handed_a_writable_account_it_does_not_own_blocks() {
    let r = check(&diff(
        transfer_deltas(),
        Some(vec![hooked_transfer(&[SOURCE, VALIDATION, HOOK])]),
        usual(&[]),
    ));
    assert_blocks(&r, &format!("owned by {T22}"));
}

/// A writable account Graphite never saw before the transaction cannot be
/// shown to be the hook's.
#[test]
fn a_hook_handed_an_unobserved_writable_account_blocks() {
    let r = check(&diff(
        transfer_deltas(),
        Some(vec![hooked_transfer(&[UNSEEN, VALIDATION, HOOK])]),
        usual(&[UNSEEN]),
    ));
    assert_blocks(&r, "did not observe before the transaction");
}

/// Without the executed list, or without the transaction's privileges,
/// nothing bounds the hook: it blocks as it did before Round 22.
#[test]
fn a_hook_without_the_observations_still_blocks() {
    let r = check(&diff(transfer_deltas(), None, usual(&[])));
    assert_blocks(&r, "executed instructions were not available");
    let r = check(&diff(
        transfer_deltas(),
        Some(vec![hooked_transfer(&[VALIDATION, HOOK])]),
        None,
    ));
    assert_blocks(&r, "privileges were not read");
}

/// A hook can only run inside a transfer. A transaction whose executed
/// Token-2022 instructions move none of the mint's tokens ran no hook.
#[test]
fn a_hook_on_a_mint_nothing_transferred_ran_nothing() {
    let other = transfer_checked(
        "instruction #0",
        &[SOURCE, OTHER_MINT, DEST, OWNER_SIGNER],
        1,
    );
    let r = check(&diff(transfer_deltas(), Some(vec![other]), usual(&[])));
    assert_inert(&r, "no transfer of mint");
}

/// Every transfer of the mint counts: one clean transfer does not excuse a
/// second that hands the hook a signer.
#[test]
fn every_transfer_of_the_mint_is_judged() {
    let clean = hooked_transfer(&[VALIDATION, HOOK]);
    let mut dirty = hooked_transfer(&[OWNER_SIGNER, VALIDATION, HOOK]);
    dirty.position = "a CPI under instruction #1".to_string();
    let r = check(&diff(
        transfer_deltas(),
        Some(vec![clean, dirty]),
        usual(&[]),
    ));
    assert_blocks(&r, "a CPI under instruction #1 hands it");
}

/// The map the pipeline consults: a hook program is bounded only while every
/// mint that runs it is.
#[test]
fn the_bounded_map_names_each_hook_program_once() {
    let d = diff(
        transfer_deltas(),
        Some(vec![hooked_transfer(&[VALIDATION, HOOK])]),
        usual(&[]),
    );
    let m = transfer_hooks_bounded(&d);
    assert!(m.get(&b58(&HOOK)).is_some_and(|r| r.is_ok()), "{m:?}");

    // A second mint on the same hook whose transfer hands it a signer.
    let mut d2 = d.clone();
    d2.token2022_mints
        .insert(b58(&OTHER_MINT), snap(&OTHER_MINT, T22, &hooked_mint(HOOK)));
    d2.token2022_executed
        .as_mut()
        .unwrap()
        .push(transfer_checked(
            "instruction #1",
            &[SOURCE, OTHER_MINT, DEST, OWNER_SIGNER, OWNER_SIGNER],
            5,
        ));
    let m = transfer_hooks_bounded(&d2);
    assert!(m.get(&b58(&HOOK)).is_some_and(|r| r.is_err()), "{m:?}");

    // The other order: the mint visited FIRST (MINT sorts before OTHER_MINT)
    // is the one whose transfer hands the hook a signer. A later mint's
    // bounded transfer must not overwrite that refusal.
    assert!(b58(&MINT) < b58(&OTHER_MINT));
    let mut d3 = diff(
        transfer_deltas(),
        Some(vec![
            hooked_transfer(&[OWNER_SIGNER, VALIDATION, HOOK]),
            transfer_checked(
                "instruction #1",
                &[SOURCE, OTHER_MINT, DEST, OWNER_SIGNER, VALIDATION, HOOK],
                5,
            ),
        ]),
        usual(&[]),
    );
    d3.token2022_mints
        .insert(b58(&OTHER_MINT), snap(&OTHER_MINT, T22, &hooked_mint(HOOK)));
    let m = transfer_hooks_bounded(&d3);
    assert!(m.get(&b58(&HOOK)).is_some_and(|r| r.is_err()), "{m:?}");
}

/// The privileges and the executed list are Graphite's own; a request
/// cannot supply them.
#[test]
fn a_request_cannot_supply_the_privileges() {
    let d = diff(
        transfer_deltas(),
        Some(vec![hooked_transfer(&[VALIDATION, HOOK])]),
        usual(&[]),
    );
    let wire = serde_json::to_value(&d).unwrap();
    assert!(wire.get("transaction_privileges").is_none(), "{wire}");
    let mut injected = wire.clone();
    injected["transaction_privileges"] = serde_json::json!({"signers": [], "writable": []});
    let back: StateDiff = serde_json::from_value(injected).unwrap();
    assert!(back.transaction_privileges.is_none());
}

// ─── Through the pipeline ───────────────────────────────────────────────────

#[cfg(feature = "rpc")]
mod pipeline {
    use super::*;
    use base64::Engine;
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
    use graphite_core::semantic_graph_store::BehaviorEvidence;
    use graphite_core::verification::{
        GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationResult,
    };
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    const SYSTEM: &str = "11111111111111111111111111111111";
    const LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";

    type Account = (u64, String, Vec<u8>);

    #[derive(Default)]
    struct Cluster {
        pre: HashMap<String, Account>,
        post: HashMap<String, Account>,
        /// The `innerInstructions` value to answer with, verbatim JSON.
        inner: String,
    }

    fn account_json(a: Option<&Account>) -> String {
        match a {
            None => "null".to_string(),
            Some((lamports, owner, data)) => format!(
                r#"{{"lamports":{lamports},"owner":"{owner}","executable":false,"rentEpoch":0,"data":["{}","base64"]}}"#,
                base64::engine::general_purpose::STANDARD.encode(data)
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

    /// Keys of the frame below, in message order.
    fn keys() -> Vec<String> {
        [
            OWNER_SIGNER,
            SOURCE,
            DEST,
            MINT,
            t22_key(),
            VALIDATION,
            HOOK,
        ]
        .iter()
        .map(b58)
        .collect()
    }

    fn t22_key() -> [u8; 32] {
        bs58::decode(T22).into_vec().unwrap().try_into().unwrap()
    }

    fn serve(state: Arc<Mutex<Cluster>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                let mut buf = vec![0u8; 1 << 16];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body: serde_json::Value = req
                    .split("\r\n\r\n")
                    .nth(1)
                    .and_then(|b| serde_json::from_str(b).ok())
                    .unwrap_or(serde_json::Value::Null);
                let s = state.lock().unwrap();
                let method = body["method"].as_str().unwrap_or("").to_string();
                // An account the post map does not name kept its lamports.
                let lamports = |m: &HashMap<String, Account>| -> String {
                    keys()
                        .iter()
                        .map(|k| {
                            m.get(k)
                                .or_else(|| s.pre.get(k))
                                .map(|a| a.0)
                                .unwrap_or(1)
                                .to_string()
                        })
                        .collect::<Vec<_>>()
                        .join(",")
                };
                let result = match method.as_str() {
                    "getMultipleAccounts" => {
                        let ks = strings(&body["params"][0]);
                        let vals: Vec<String> =
                            ks.iter().map(|k| account_json(s.pre.get(k))).collect();
                        format!(
                            r#"{{"context":{{"slot":1000}},"value":[{}]}}"#,
                            vals.join(",")
                        )
                    }
                    "simulateTransaction" => {
                        let ks = strings(&body["params"][1]["accounts"]["addresses"]);
                        let post: Vec<String> =
                            ks.iter().map(|k| account_json(s.post.get(k))).collect();
                        format!(
                            r#"{{"context":{{"slot":1000}},"value":{{"err":null,"logs":[],"unitsConsumed":9000,"fee":5000,
                            "preBalances":[{}],"postBalances":[{}],
                            "innerInstructions":{},"loadedAddresses":{{"writable":[],"readonly":[]}},
                            "accounts":[{}],"returnData":null}}}}"#,
                            lamports(&s.pre),
                            lamports(&s.post),
                            s.inner,
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

    fn cluster(inner: &str) -> Cluster {
        let mut c = Cluster {
            inner: inner.to_string(),
            ..Default::default()
        };
        let t22 = T22.to_string();
        c.pre.insert(
            b58(&OWNER_SIGNER),
            (1_000_000_000, SYSTEM.to_string(), vec![]),
        );
        c.post.insert(
            b58(&OWNER_SIGNER),
            (999_995_000, SYSTEM.to_string(), vec![]),
        );
        for (k, owner, before, after) in [
            (SOURCE, SRC_OWNER, 10_000u64, 9_000u64),
            (DEST, DST_OWNER, 0, 1_000),
        ] {
            c.pre.insert(
                b58(&k),
                (2_039_280, t22.clone(), hooked_account(MINT, owner, before)),
            );
            c.post.insert(
                b58(&k),
                (2_039_280, t22.clone(), hooked_account(MINT, owner, after)),
            );
        }
        c.pre
            .insert(b58(&MINT), (1_461_600, t22.clone(), hooked_mint(HOOK)));
        c.pre
            .insert(b58(&VALIDATION), (1_000_000, b58(&HOOK), vec![0u8; 16]));
        c.pre
            .insert(b58(&HOOK), (1_141_440, LOADER.to_string(), vec![]));
        c
    }

    /// A legacy TransferChecked on Token-2022 carrying the hook's validation
    /// account and program: keys [owner (payer), source, destination, mint,
    /// Token-2022, validation, hook]; the last four read-only.
    fn frame() -> (Vec<u8>, Vec<u8>) {
        let keys = [
            OWNER_SIGNER,
            SOURCE,
            DEST,
            MINT,
            t22_key(),
            VALIDATION,
            HOOK,
        ];
        let mut data = vec![12u8];
        data.extend_from_slice(&1_000u64.to_le_bytes());
        data.push(6);
        let mut out = vec![1u8];
        out.extend_from_slice(&[0u8; 64]);
        out.extend_from_slice(&[1, 0, 4]);
        out.push(keys.len() as u8);
        for k in &keys {
            out.extend_from_slice(k);
        }
        out.extend_from_slice(&[5u8; 32]);
        out.push(1);
        out.push(4);
        out.push(6);
        out.extend_from_slice(&[1, 3, 2, 0, 5, 6]);
        out.push(data.len() as u8);
        out.extend_from_slice(&data);
        (out, data)
    }

    /// The hook's `Execute` as Token-2022 invokes it: [source, mint,
    /// destination, authority, validation].
    fn execute_under_token2022(stack_height: &str) -> String {
        let mut data = vec![105u8, 37, 101, 197, 75, 251, 102, 26];
        data.extend_from_slice(&1_000u64.to_le_bytes());
        format!(
            r#"[{{"index":0,"instructions":[{{"programIdIndex":6,"accounts":[1,3,2,0,5],"data":"{}"{stack_height}}}]}}]"#,
            bs58::encode(&data).into_string()
        )
    }

    async fn verify(c: Cluster) -> VerificationResult {
        let state = Arc::new(Mutex::new(c));
        let endpoint = serve(Arc::clone(&state));
        let mut core = GraphiteCore::new();
        core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
            endpoint,
            timeout: std::time::Duration::from_secs(5),
            max_retries: 0,
            ..Default::default()
        }));
        let (frame, data) = frame();
        let input = VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "transfer".to_string(),
                raw_natural_language: "send tokens".to_string(),
                confidence_of_parse: 0.9,
                extracted_parameters: None,
            },
            program_id: T22.to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: "0c".to_string(),
            account_addresses: [SOURCE, MINT, DEST, OWNER_SIGNER, VALIDATION, HOOK]
                .iter()
                .map(b58)
                .collect(),
            instruction_data: Some(data),
            cpi_targets: vec![],
            wallet_profile: WalletProfile::Gaming,
            behavior_evidence: BehaviorEvidence::default(),
            compute_units: 0,
            account_writes: 0,
            cpi_hops: 0,
            signed_transaction: Some(frame),
            transaction_instructions: vec![],
            cpi_trace: None,
            uses_versioned_transaction: false,
            lookup_table_count: 0,
            real_account_metas: vec![],
            state_diff: None,
        };
        core.verify_async(&input).await.expect("verified")
    }

    fn layer(r: &VerificationResult, prefix: &str) -> (LayerStatus, String) {
        let l = r
            .layers
            .iter()
            .find(|l| l.layer.starts_with(prefix))
            .unwrap_or_else(|| panic!("{prefix}"));
        (l.status, l.reason.clone())
    }

    fn everything(r: &VerificationResult) -> String {
        format!("{r:?}")
    }

    /// The simulator reports the hook running as Token-2022's CPI. Graphite
    /// built the executed list and the privileges itself; the hook is inert
    /// in L4 and, as a CPI, is named as the transfer's hook rather than
    /// judged as the primary calling an unknown program.
    #[tokio::test]
    async fn a_hook_token2022_invoked_and_the_bytes_bound_is_part_of_the_transfer() {
        let r = verify(cluster(&execute_under_token2022(r#","stackHeight":2"#))).await;
        let (status, reason) = layer(&r, "L4");
        assert_ne!(status, LayerStatus::Failed, "{reason}");
        assert!(reason.contains("Token2022ExtensionInert"), "{reason}");
        assert!(
            reason.contains("no signer and no writable account"),
            "{reason}"
        );
        assert_eq!(r.risk_verdict.status, "Clear", "{:?}", r.risk_verdict);
        let all = everything(&r);
        assert!(
            !all.contains("observed CPI (not declared by the caller)"),
            "{all}"
        );
        assert!(
            all.contains("a Token-2022 transfer hook, invoked only by Token-2022"),
            "{all}"
        );
    }

    /// Without a stack height, who called the hook program cannot be
    /// established: it stays an observed CPI the request did not declare,
    /// judged by the same rules as a declaration.
    #[tokio::test]
    async fn a_hook_whose_caller_cannot_be_established_is_judged_as_a_call() {
        let r = verify(cluster(&execute_under_token2022(""))).await;
        assert_eq!(r.risk_verdict.status, "Blocked", "{:?}", r.risk_verdict);
        let all = everything(&r);
        assert!(
            !all.contains("a Token-2022 transfer hook, invoked only by Token-2022"),
            "{all}"
        );
        assert!(
            all.contains("the simulator observed CPI target(s) the request did not declare"),
            "{all}"
        );
    }
}

// ─── Manifests: optional accounts and token-account slots ──────────────────

/// A real Jupiter `sharedAccountsRoute` from mainnet slot 449807125
/// (2026-09-23 sample), refused by Round 21 as three identity mismatches:
/// two token-ACCOUNT slots pinned to the token PROGRAMS (a pin present since
/// at least Round 18), and Jupiter's own id in the optional
/// `token_2022_program` slot — Anchor's way of saying the account is absent.
mod manifests_match_the_programs {
    use graphite_core::account_resolution::{
        resolve_accounts, AccountIdentity, AccountResolutionInput, RealAccountMeta,
    };
    use graphite_core::manifest::load_seed_manifests;

    const JUP: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";

    /// The instruction's first 13 accounts (its declared layout) with the
    /// transaction's own privileges.
    fn shared_route() -> (Vec<String>, Vec<RealAccountMeta>) {
        let accounts = [
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "BQ72nSv9f3PRyRKCBnHLVrerrv37CYTHm5h3s9VSGQDV",
            "FhRiiVdT5Q2NDb6szFyETdyZK9Ui2e84Mi9qPNhV8tTK",
            "FKz3MZoG1A2KfMR9Ymu2v6DAMpEE9LBVfRsCwjhqMMuT",
            "8ctcHN52LY21FEipCjr1MVWtoZa1irJQTPyAaTj72h7S",
            "6pXVFSACE5BND2C3ibGRWMG1fNtV7hfynWrfNKtCXhN3",
            "A3kA9igDNNNrNAY5xSsYQsjgXMBnDqNLiMHeS7gcHNiW",
            "So11111111111111111111111111111111111111112",
            "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
            JUP,
            JUP,
            "D8cy77BBepLMngZx6ZukaTff5hCt1HrWyKk3Hnd9oitf",
            JUP,
        ];
        let signer = [
            false, false, true, false, false, false, false, false, false, false, false, false,
            false,
        ];
        let writable = [
            false, false, true, true, true, true, true, false, false, false, false, false, false,
        ];
        (
            accounts.iter().map(|a| a.to_string()).collect(),
            signer
                .iter()
                .zip(writable)
                .map(|(s, w)| RealAccountMeta {
                    is_signer: *s,
                    is_writable: w,
                })
                .collect(),
        )
    }

    fn resolve(
        accounts: Vec<String>,
        metas: Vec<RealAccountMeta>,
    ) -> graphite_core::account_resolution::AccountResolutionResult {
        resolve_accounts(
            &AccountResolutionInput {
                program_id: JUP.to_string(),
                instruction_discriminator: "c1209b3341d69c81".to_string(),
                account_addresses: accounts,
                instruction_data: Some(
                    hex::decode("c1209b3341d69c810202000000970064000174006401022988c26200000000b8b34f0b00000000c80000")
                        .unwrap(),
                ),
                real_account_metas: metas,
                fee_payer: Some("FhRiiVdT5Q2NDb6szFyETdyZK9Ui2e84Mi9qPNhV8tTK".to_string()),
            },
            &load_seed_manifests(),
        )
        .expect("resolves")
    }

    fn mismatched(r: &graphite_core::account_resolution::AccountResolutionResult) -> Vec<usize> {
        r.resolved_accounts
            .iter()
            .enumerate()
            .filter(|(_, a)| a.expected_address_mismatch || a.pda_mismatch || a.privilege_mismatch)
            .map(|(i, _)| i)
            .collect()
    }

    #[test]
    fn the_real_shared_accounts_route_resolves_without_a_mismatch() {
        let (accounts, metas) = shared_route();
        let r = resolve(accounts, metas);
        assert_eq!(
            mismatched(&r),
            Vec::<usize>::new(),
            "{:?}",
            r.resolved_accounts
        );
        // The optional slots holding the program id are absent, and resolved
        // as that constant.
        for slot in [9, 10] {
            assert_eq!(r.resolved_accounts[slot].role, "absent", "slot {slot}");
            assert_eq!(
                r.resolved_accounts[slot].identity,
                AccountIdentity::Constant
            );
        }
    }

    /// Optional is not unchecked: any address but the program id in an
    /// optional pinned slot is compared as before.
    #[test]
    fn an_optional_slot_holding_another_address_is_still_checked() {
        let (mut accounts, metas) = shared_route();
        accounts[10] = "BPFLoaderUpgradeab1e11111111111111111111111".to_string();
        let r = resolve(accounts, metas);
        assert_eq!(mismatched(&r), vec![10]);
        assert!(r.resolved_accounts[10].expected_address_mismatch);
    }

    /// Only a slot the IDL marks optional can be absent: the program id in
    /// the required `token_program` slot is a mismatch.
    #[test]
    fn the_program_id_in_a_required_slot_is_a_mismatch() {
        let (mut accounts, metas) = shared_route();
        accounts[0] = JUP.to_string();
        let r = resolve(accounts, metas);
        assert!(r.resolved_accounts[0].expected_address_mismatch);
        assert_ne!(r.resolved_accounts[0].role, "absent");
    }

    /// An absent optional account cannot sign. A signer flag on the program
    /// id is still compared — the privilege check is not skipped.
    #[test]
    fn a_writable_program_id_in_an_optional_slot_is_still_flagged() {
        let (accounts, mut metas) = shared_route();
        metas[10].is_writable = true;
        let r = resolve(accounts, metas);
        assert_eq!(mismatched(&r), vec![10]);
        assert!(r.resolved_accounts[10].privilege_mismatch);
    }

    /// No manifest pins a token ACCOUNT slot to the token PROGRAMS.
    #[test]
    fn no_token_account_slot_is_pinned_to_a_token_program() {
        let programs = [
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        ];
        let registry = load_seed_manifests();
        let mut bad = Vec::new();
        for m in registry.list() {
            for ix in &m.instructions {
                for layout in ix.all_layouts() {
                    for a in layout {
                        let n = a.name.to_lowercase().replace(['_', ' '], "");
                        if n.ends_with("tokenaccount")
                            && a.expected_address
                                .iter()
                                .any(|e| programs.contains(&e.as_str()))
                        {
                            bad.push(format!("{} {} {}", m.protocol.name, ix.name, a.name));
                        }
                    }
                }
            }
        }
        assert!(bad.is_empty(), "{bad:?}");
    }
}

/// System `CreateAccountWithSeed` takes its base as the third account only
/// when the base is not the funding account: agave's processor requires two
/// accounts and checks the base against the instruction's signers. 18
/// executed 2-account calls in the Round 22 traffic were a shortfall against
/// the 3-account layout; they resolve against their own.
#[test]
fn create_account_with_seed_has_its_two_account_layout() {
    let registry = graphite_core::manifest::load_seed_manifests();
    let ix = registry
        .find_instruction("11111111111111111111111111111111", "03000000")
        .expect("CreateAccountWithSeed");
    assert_eq!(ix.name, "CreateAccountWithSeed");
    let two = ix.layout_for(2);
    assert_eq!(two.len(), 2);
    assert!(
        two[0].is_signer && two[0].is_writable,
        "the funding account signs"
    );
    assert!(!two[1].is_signer && two[1].is_writable);
    assert_eq!(ix.layout_for(3)[2].name, "base");
}

/// Tensor `bid`'s cosigner is declared a signer by the program's (legacy
/// format) IDL, which does not record optional accounts; in 6 of 6 executed
/// bids the slot holds Tensor's own program id — absent. Marked optional from
/// that traffic, the executed bid resolves; a real address in the slot must
/// still sign.
#[test]
fn tensor_bids_absent_cosigner_is_not_an_unsigned_signer() {
    use graphite_core::account_resolution::{
        resolve_accounts, AccountResolutionInput, RealAccountMeta,
    };
    let tcomp = "TCMPhJdwDryooaGtiocG1u3xcYbRpiJzb283XfCZsDp";
    let owner = bs58::encode([61u8; 32]).into_string();
    let mut accounts = vec![
        "11111111111111111111111111111111".to_string(),
        tcomp.to_string(),
        bs58::encode([62u8; 32]).into_string(),
        owner.clone(),
        bs58::encode([63u8; 32]).into_string(),
        tcomp.to_string(),
        owner.clone(),
    ];
    let metas = |cosigner_signs: bool| -> Vec<RealAccountMeta> {
        [
            (false, false),
            (false, false),
            (false, true),
            (true, true),
            (false, true),
            (cosigner_signs, false),
            (true, true),
        ]
        .iter()
        .map(|(s, w)| RealAccountMeta {
            is_signer: *s,
            is_writable: *w,
        })
        .collect()
    };
    let registry = graphite_core::manifest::load_seed_manifests();
    let disc = registry
        .get(tcomp)
        .unwrap()
        .instructions
        .iter()
        .find(|i| i.name == "bid")
        .unwrap()
        .discriminator
        .clone();
    let resolve = |accounts: &Vec<String>, m: Vec<RealAccountMeta>| {
        resolve_accounts(
            &AccountResolutionInput {
                program_id: tcomp.to_string(),
                instruction_discriminator: disc.clone(),
                account_addresses: accounts.clone(),
                instruction_data: None,
                real_account_metas: m,
                fee_payer: Some(owner.clone()),
            },
            &registry,
        )
        .expect("resolves")
    };
    let r = resolve(&accounts, metas(false));
    assert_eq!(r.resolved_accounts[5].role, "absent");
    assert!(!r.resolved_accounts[5].privilege_mismatch);
    // A real cosigner that does not sign is still a mismatch.
    accounts[5] = bs58::encode([64u8; 32]).into_string();
    let r = resolve(&accounts, metas(false));
    assert!(r.resolved_accounts[5].privilege_mismatch);
}

/// Instructions whose own executed traffic passes a variable account list —
/// the account count varies, and at least a quarter of executions pass more
/// than two writable accounts past the layout (routers' pools, CLMM tick
/// arrays, per-holder and per-feed accounts). Round 22 measured them over the
/// three block samples and per-program mainnet traffic; the drainer
/// heuristics refused them as account proliferation. Declared variable like
/// Jupiter's routes.
#[test]
fn remaining_account_interfaces_are_declared_variable() {
    let registry = graphite_core::manifest::load_seed_manifests();
    for (program, name) in [
        ("DF1ow4tspfHX9JwWJsAb9epbkA8hmpSEAtxXy1V27QBH", "swap"),
        ("DF1ow4tspfHX9JwWJsAb9epbkA8hmpSEAtxXy1V27QBH", "swap2"),
        ("proVF4pMXVaYqmy4NjniPh4pqKNfMmsihgd4wdkCX3u", "swap_tob"),
        ("proVF4pMXVaYqmy4NjniPh4pqKNfMmsihgd4wdkCX3u", "swap_tob_v3"),
        ("CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK", "swap_v2"),
        (
            "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
            "distribute_fee_to_holders",
        ),
        (
            "SAGE2HAwep459SNq61LHvjxPk4pLPEJLoMETef7f7EE",
            "fleetStateHandler",
        ),
        (
            "KvauGMspG5k6rtzrqqn7WNn3oZdyKqLKwK2XWQ8FLjd",
            "investWithMaxAmount",
        ),
        ("G7MVcM9YzGxrmLtmobUgyt8A6WhQ2dgQX3aSJcPejdEp", "swap"),
        (
            "DoVEsk76QybCEHQGzkvYPWLQu9gzNoZZZt3TPiL597e",
            "update_many_with_pyth_lazer",
        ),
        ("tuktukUrfhXT6ZT77QTU8RQtvgL967uRuVagWF57zVA", "run_task_v0"),
        ("zapvX9M3uf5pvy4wRPAbQgdQsM1xmuiFnkfHKPvwMiz", "zap_out"),
        (
            "proVF4pMXVaYqmy4NjniPh4pqKNfMmsihgd4wdkCX3u",
            "swap_tob_enhanced",
        ),
        (
            "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD",
            "refreshObligation",
        ),
        (
            "ccvrfu3fSpbnPLiUqdWAt85Zn9nq96ekwGTbHqGtdgQ",
            "commit_proof_with_beta",
        ),
        (
            "offqSMQWgQud6WJz694LRzkeN5kMYpCHTpXQr3Rkcjm",
            "commit_price_only",
        ),
    ] {
        let m = registry.get(program).unwrap_or_else(|| panic!("{program}"));
        let ix = m
            .instructions
            .iter()
            .find(|i| i.name == name)
            .unwrap_or_else(|| panic!("{program} {name}"));
        assert!(ix.variable_accounts, "{} {name}", m.protocol.name);
    }
}

// ─── What the runtime lets a message write ──────────────────────────────────

/// Agave's `is_maybe_writable`: a key the header marks writable is read-only
/// at runtime when it is a sysvar or builtin program, or when it is called as
/// a program and the upgradeable loader is not among the accounts. Graphite
/// read the header alone, so an invoked program's own id — which Anchor
/// passes for an absent optional account — was "declared read-only, writable
/// in the transaction" (7 real refusals over the three Round 22 samples).
mod runtime_writability {
    use graphite_core::tx_artifact::parse_transaction;

    const PAYER: [u8; 32] = [81u8; 32];
    const PROGRAM: [u8; 32] = [82u8; 32];
    const OTHER: [u8; 32] = [83u8; 32];

    fn key(s: &str) -> [u8; 32] {
        bs58::decode(s).into_vec().unwrap().try_into().unwrap()
    }

    /// A legacy message: `writable_unsigned` keys follow the payer, then
    /// `readonly` keys; one instruction calls PROGRAM on every account.
    fn frame(writable_unsigned: &[[u8; 32]], readonly: &[[u8; 32]]) -> Vec<u8> {
        let mut keys = vec![PAYER];
        keys.extend_from_slice(writable_unsigned);
        keys.extend_from_slice(readonly);
        let program_index = keys.iter().position(|k| *k == PROGRAM).unwrap() as u8;
        let mut out = vec![1u8];
        out.extend_from_slice(&[0u8; 64]);
        out.extend_from_slice(&[1, 0, readonly.len() as u8]);
        out.push(keys.len() as u8);
        for k in &keys {
            out.extend_from_slice(k);
        }
        out.extend_from_slice(&[7u8; 32]);
        out.push(1);
        out.push(program_index);
        out.push(keys.len() as u8);
        out.extend((0..keys.len() as u8).collect::<Vec<_>>());
        out.push(1);
        out.push(0);
        out
    }

    fn writable(bytes: &[u8]) -> Vec<String> {
        parse_transaction(bytes).expect("parses").writable
    }

    fn b58(k: &[u8; 32]) -> String {
        bs58::encode(k).into_string()
    }

    #[test]
    fn an_invoked_program_and_a_sysvar_are_not_writable() {
        let clock = key("SysvarC1ock11111111111111111111111111111111");
        let bytes = frame(&[PROGRAM, clock, OTHER], &[]);
        let w = writable(&bytes);
        assert_eq!(w, vec![b58(&PAYER), b58(&OTHER)]);
        // The header's own statement is kept, so a header differing only in
        // a demoted key's flag still parses differently.
        let parsed = parse_transaction(&bytes).expect("parses");
        assert_eq!(
            parsed.header_writable,
            vec![b58(&PAYER), b58(&PROGRAM), b58(&clock), b58(&OTHER)]
        );
    }

    /// With the upgradeable loader among the accounts, the runtime leaves an
    /// invoked program writable (it may be upgraded) — so does Graphite.
    #[test]
    fn the_upgradeable_loader_keeps_an_invoked_program_writable() {
        let loader = key("BPFLoaderUpgradeab1e11111111111111111111111");
        let w = writable(&frame(&[PROGRAM, OTHER], &[loader]));
        assert!(w.contains(&b58(&PROGRAM)), "{w:?}");
    }

    /// A v0 message may load the upgradeable loader through a lookup table,
    /// which the bytes alone cannot rule out: an invoked program stays
    /// writable, the stricter reading. A sysvar is demoted regardless.
    #[test]
    fn with_lookup_tables_an_invoked_program_stays_writable() {
        let clock = key("SysvarC1ock11111111111111111111111111111111");
        let legacy = frame(&[PROGRAM, clock], &[]);
        // Re-frame as v0: version prefix after the signatures, and one
        // lookup (table [84; 32], one read-only index) after the instructions.
        let mut v0 = legacy[..65].to_vec();
        v0.push(0x80);
        v0.extend_from_slice(&legacy[65..]);
        v0.push(1);
        v0.extend_from_slice(&[84u8; 32]);
        v0.extend_from_slice(&[0, 1, 0]);
        let w = writable(&v0);
        assert!(w.contains(&b58(&PROGRAM)), "{w:?}");
        assert!(!w.contains(&b58(&clock)), "{w:?}");
    }

    /// A key that is not invoked, not a sysvar and not a builtin keeps the
    /// header's word.
    #[test]
    fn an_ordinary_writable_account_stays_writable() {
        let w = writable(&frame(&[OTHER, PROGRAM], &[]));
        assert!(w.contains(&b58(&OTHER)));
        assert!(!w.contains(&b58(&PROGRAM)));
    }
}

// ─── Native-program manifests, rebuilt from their interfaces ───────────────

/// The Stake manifest carried a placeholder layout on eleven instructions
/// ([user_authority (signer), program_account]) with the state change
/// "Stake Program instruction", declared DelegateStake's stake account a
/// signer and put Withdraw's withdrawer where the recipient goes. Rebuilt from
/// `solana-program/stake`'s interface, with the sysvar-carrying layout
/// executed traffic sends as primary.
mod native_manifests {
    use graphite_core::manifest::load_seed_manifests;

    const STAKE: &str = "Stake11111111111111111111111111111111111111";
    const LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";

    fn layout(program: &str, name: &str, n: usize) -> Vec<(String, bool, bool)> {
        let r = load_seed_manifests();
        let ix = r
            .get(program)
            .unwrap()
            .instructions
            .iter()
            .find(|i| i.name == name)
            .unwrap_or_else(|| panic!("{name}"))
            .clone();
        let l = ix.layout_for(n);
        assert_eq!(l.len(), n, "{name} has no {n}-account layout");
        l.iter()
            .map(|a| (a.name.clone(), a.is_signer, a.is_writable))
            .collect()
    }

    #[test]
    fn no_stake_instruction_is_a_placeholder() {
        let r = load_seed_manifests();
        let m = r.get(STAKE).unwrap();
        for ix in &m.instructions {
            for a in ix.all_layouts().flatten() {
                assert_ne!(a.name, "user_authority", "{}", ix.name);
                assert_ne!(a.name, "program_account", "{}", ix.name);
            }
            for c in &ix.expected_state_changes {
                assert_ne!(c, "Stake Program instruction", "{}", ix.name);
            }
        }
        for name in ["MoveStake", "MoveLamports"] {
            assert!(m.instructions.iter().any(|i| i.name == name), "{name}");
        }
    }

    #[test]
    fn stake_layouts_are_the_programs() {
        // [stake (w), vote, clock, stake history, config, authority (s)]
        let d = layout(STAKE, "DelegateStake", 6);
        assert_eq!(d[0], ("stake".into(), false, true));
        assert_eq!(d[5], ("authorized".into(), true, false));
        assert!(
            layout(STAKE, "DelegateStake", 3)[2].1,
            "the short layout's authority signs"
        );
        // [stake (w), recipient (w), clock, stake history, withdrawer (s)]
        let w = layout(STAKE, "Withdraw", 5);
        assert_eq!(w[1], ("to".into(), false, true));
        assert_eq!(w[4], ("withdrawer".into(), true, false));
        let i = layout(STAKE, "Initialize", 2);
        assert!(
            !i[0].1 && i[0].2,
            "the stake account neither signs nor is read-only"
        );
        let s = layout(STAKE, "Split", 3);
        assert_eq!(s[2], ("authority".into(), true, false));
        let m = layout(STAKE, "Merge", 5);
        assert_eq!(m[4], ("authority".into(), true, false));
    }

    /// Close had its authority and recipient swapped, and
    /// DeployWithMaxDataLen an order the program does not use.
    #[test]
    fn loader_layouts_are_the_programs() {
        let c = layout(LOADER, "Close", 4);
        assert_eq!(c[1], ("recipient".into(), false, true));
        assert_eq!(c[2], ("authority".into(), true, false));
        assert_eq!(c[3], ("program".into(), false, true));
        layout(LOADER, "Close", 3);
        let d = layout(LOADER, "DeployWithMaxDataLen", 8);
        assert_eq!(d[0], ("payer".into(), true, true));
        assert_eq!(d[7], ("authority".into(), true, false));
        let u = layout(LOADER, "Upgrade", 7);
        assert_eq!(u[6], ("authority".into(), true, false));
    }

    /// The SOL deposit and withdraw authorities of a stake pool are optional
    /// trailing accounts.
    #[test]
    fn stake_pool_sol_authorities_are_optional() {
        let pool = "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy";
        layout(pool, "WithdrawSol", 12);
        layout(pool, "WithdrawSol", 13);
        layout(pool, "DepositSol", 10);
        layout(pool, "DepositSol", 11);
    }
}

// ─── Declared siblings: writable extras from the bytes ────────────────────

/// Round 21 counted the primary's extra accounts by their privileges in the
/// bytes, and left every declared sibling on the raw count: a sibling
/// passing READ-ONLY accounts past its layout was refused as a
/// multi-transfer drain. That blocked 8 live SyncNative transactions on
/// their pool sibling (2026-09-28 run), all Clear once the sibling is
/// judged like the primary. Writable extras still block — they are what a
/// drain needs.
mod sibling_writable_extras {
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::semantic_graph_store::BehaviorEvidence;
    use graphite_core::tx_pattern_analysis::TransactionInstruction;
    use graphite_core::verification::{
        GraphiteCore, ProposedIntent, VerificationInput, VerificationResult,
    };

    const SYSTEM: &str = "11111111111111111111111111111111";

    fn transfer(amount: u64) -> Vec<u8> {
        let mut d = vec![2u8, 0, 0, 0];
        d.extend_from_slice(&amount.to_le_bytes());
        d
    }

    /// Keys [payer (s,w), dest (w), x1, x2, x3, System]. With `writable`
    /// the three extras sit in the writable section; otherwise they are
    /// read-only. Instruction 0 is a 2-account transfer of 1 lamport; the
    /// sibling, instruction 1, a transfer of 2 lamports carrying the three
    /// extras past System Transfer's 2-account layout.
    fn frame(writable: bool) -> (Vec<u8>, Vec<String>) {
        let keys: [[u8; 32]; 6] = [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [0; 32]];
        let mut out = vec![1u8];
        out.extend_from_slice(&[0u8; 64]);
        out.extend_from_slice(&[1, 0, if writable { 1 } else { 4 }]);
        out.push(keys.len() as u8);
        for k in &keys {
            out.extend_from_slice(k);
        }
        out.extend_from_slice(&[9u8; 32]);
        out.push(2);
        let primary = transfer(1);
        out.extend_from_slice(&[5, 2, 0, 1, primary.len() as u8]);
        out.extend_from_slice(&primary);
        let sibling = transfer(2);
        out.extend_from_slice(&[5, 5, 0, 1, 2, 3, 4, sibling.len() as u8]);
        out.extend_from_slice(&sibling);
        let names = keys.iter().map(|k| bs58::encode(k).into_string()).collect();
        (out, names)
    }

    fn verify(writable: bool) -> VerificationResult {
        let (frame, keys) = frame(writable);
        let input = VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "transfer".to_string(),
                raw_natural_language: "send 1 lamport".to_string(),
                confidence_of_parse: 0.9,
                extracted_parameters: None,
            },
            program_id: SYSTEM.to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: hex::encode(transfer(1)),
            account_addresses: keys[..2].to_vec(),
            instruction_data: Some(transfer(1)),
            cpi_targets: vec![],
            wallet_profile: WalletProfile::Gaming,
            behavior_evidence: BehaviorEvidence::default(),
            compute_units: 0,
            account_writes: 0,
            cpi_hops: 0,
            signed_transaction: Some(frame),
            transaction_instructions: vec![TransactionInstruction {
                program_id: SYSTEM.to_string(),
                instruction_discriminator: hex::encode(transfer(2)),
                account_addresses: keys[..5].to_vec(),
                cpi_targets: vec![],
            }],
            cpi_trace: None,
            uses_versioned_transaction: false,
            lookup_table_count: 0,
            real_account_metas: vec![],
            state_diff: None,
        };
        GraphiteCore::new().verify(&input).expect("verified")
    }

    #[test]
    fn read_only_extras_on_a_sibling_are_not_a_drain() {
        let r = verify(false);
        let all = format!("{r:?}");
        assert!(!all.contains("STMT drainer"), "{all}");
        assert!(!all.contains("drainer pattern"), "{all}");
        assert_eq!(r.risk_verdict.status, "Clear", "{:?}", r.risk_verdict);
    }

    #[test]
    fn writable_extras_on_a_sibling_still_block() {
        let r = verify(true);
        assert_eq!(r.risk_verdict.status, "Blocked", "{:?}", r.risk_verdict);
        let all = format!("{r:?}");
        assert!(all.contains("secondary instruction #1"), "{all}");
        assert!(all.contains("3 of the extra accounts writable"), "{all}");
    }
}
