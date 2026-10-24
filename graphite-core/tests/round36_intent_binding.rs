//! Round 36 (F-003 / F-004): an approval is executable only when the
//! amount, recipient and asset the request states are the ones its bytes
//! carry.
//!
//! Before Round 36 `ExtractedParameters` reached the Core and nothing read
//! it. The first test below (`a_wrong_amount_is_blocked`) was
//! `executable_approved` on the Round 35 code: a System transfer of
//! 2,000,000 lamports under a request for 0.003 SOL. Each refusal test has a
//! benign control beside it built from the same bytes.
#![cfg(feature = "rpc")]

use graphite_core::confidence_engine::TrustTier;
use graphite_core::intent_binding::{
    bind, bind_withdrawal, decode_swap, wallet_effect, Binding, BindingInput, Ix, JupiterPayload,
    JUPITER_SWAP_VARIANTS, JUPITER_V6, NATIVE_MINT, RAYDIUM_CPMM,
};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::state_diff::{AccountDelta, AccountSnapshot, StateDiff, TokenAccountView};
use graphite_core::verification::{
    ExecutionDecision, ExtractedParameters, GraphiteCore, ProposedIntent, UnobservedCode,
    VerificationInput, VerificationResult,
};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

const SYSTEM: &str = "11111111111111111111111111111111";

fn payer() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x2au8; 32])
}

fn payer_b58() -> String {
    bs58::encode(payer().verifying_key().to_bytes()).into_string()
}

fn corpus_entry(name: &str) -> serde_json::Value {
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/artifacts/sak_bridge_corpus.json"))
            .expect("corpus must parse");
    raw["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|e| e["name"] == name)
        .unwrap_or_else(|| panic!("corpus entry {name}"))
        .clone()
}

fn bytes(v: &serde_json::Value) -> Vec<u8> {
    v.as_array()
        .expect("byte array")
        .iter()
        .map(|n| n.as_u64().expect("byte") as u8)
        .collect()
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect()
}

fn transfer_data(lamports: u64) -> Vec<u8> {
    let mut d = vec![2, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    d
}

/// The corpus transfer, with this test's fee payer and `lamports`.
fn tx(lamports: u64) -> Vec<u8> {
    let keys = strings(&corpus_entry("legacy_single_transfer")["static_keys"]);
    let mut raw = bytes(&corpus_entry("legacy_single_transfer")["raw"]);
    let old = bs58::decode(&keys[0]).into_vec().unwrap();
    let pos = raw
        .windows(32)
        .position(|w| w == old.as_slice())
        .expect("the corpus fee payer is in the frame");
    raw[pos..pos + 32].copy_from_slice(&payer().verifying_key().to_bytes());
    let old = transfer_data(2_000_000);
    let pos = raw
        .windows(old.len())
        .position(|w| w == old.as_slice())
        .expect("the corpus transfer carries 2,000,000 lamports");
    raw[pos..pos + old.len()].copy_from_slice(&transfer_data(lamports));
    raw
}

fn account(lamports: u64) -> String {
    format!(
        r#"{{"lamports":{lamports},"owner":"{SYSTEM}","executable":false,"rentEpoch":0,"data":["","base64"]}}"#
    )
}

/// A loopback cluster whose simulation of the corpus transfer is clean.
fn cluster() -> String {
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").unwrap());
    let addr = listener.local_addr().unwrap();
    let server = Arc::clone(&listener);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = server.accept() {
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let body_json: serde_json::Value = req
                .split("\r\n\r\n")
                .nth(1)
                .and_then(|b| serde_json::from_str(b).ok())
                .unwrap_or(serde_json::Value::Null);
            let method = body_json["method"].as_str().unwrap_or("?").to_string();
            let body = match method.as_str() {
                "getMultipleAccounts" => {
                    let count = body_json["params"][0]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let vals: Vec<String> = (0..count)
                        .map(|i| account(if i == 0 { 1_000_000_000 } else { 1_000_000 }))
                        .collect();
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":[{}]}}}}"#,
                        vals.join(",")
                    )
                }
                "simulateTransaction" => {
                    let count = body_json["params"][1]["accounts"]["addresses"]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let post: Vec<String> = (0..count)
                        .map(|i| account(if i == 0 { 998_995_000 } else { 2_000_000 }))
                        .collect();
                    let complete = |err: &str, accounts: &str| {
                        format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
                                "err":{err},"logs":[],"unitsConsumed":150,"fee":5000,
                                "preBalances":[1000000000,1000000,1],"postBalances":[998995000,2000000,1],
                                "innerInstructions":[],"loadedAddresses":{{"writable":[],"readonly":[]}},
                                {accounts}"returnData":null}}}}}}"#
                        )
                    };
                    complete("null", &format!(r#""accounts":[{}],"#, post.join(",")))
                }
                _ => r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
            };
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });
    std::mem::forget(listener);
    format!("http://{addr}")
}

fn client(endpoint: &str) -> SolanaRpcClient {
    SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    })
}

fn core_at(endpoint: &str) -> GraphiteCore {
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(client(endpoint));
    core
}

fn recipient() -> String {
    strings(&corpus_entry("legacy_single_transfer")["static_keys"])[1].clone()
}

fn params(amount: &str, destination: &str, asset: &str) -> Option<ExtractedParameters> {
    Some(ExtractedParameters {
        amount: Some(amount.to_string()),
        destination: Some(destination.to_string()),
        input_token: Some(asset.to_string()),
        ..Default::default()
    })
}

/// The corpus transfer of 2,000,000 lamports from this test's payer, under
/// `extracted`.
fn request(extracted: Option<ExtractedParameters>, artifact: bool) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send SOL".to_string(),
            confidence_of_parse: 0.95,
            extracted_parameters: extracted,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![payer_b58(), recipient()],
        instruction_data: Some(transfer_data(2_000_000)),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Custom {
            min_confidence: 0.40,
            min_trust_tier: TrustTier::OfficialManifest,
        },
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: artifact.then(|| tx(2_000_000)),
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

async fn verify(extracted: Option<ExtractedParameters>) -> VerificationResult {
    let core = core_at(&cluster());
    core.verify_async(&request(extracted, true)).await.unwrap()
}

fn finding(r: &VerificationResult, pattern: &str) -> Option<String> {
    r.risk_verdict
        .findings
        .iter()
        .find(|f| f.pattern == pattern)
        .map(|f| f.reason.clone())
}

// ─── The pipeline ───────────────────────────────────────────────────────────

/// The control: the request states exactly what the bytes do.
#[tokio::test]
async fn a_bound_transfer_is_executable() {
    let r = verify(params("0.002", &recipient(), "SOL")).await;
    assert_eq!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{} {:?} {:?}",
        r.summary,
        r.risk_verdict.findings,
        r.scope.unobserved()
    );
    assert!(!r
        .scope
        .unobserved_codes()
        .contains(&UnobservedCode::IntentParameters));
    // "sol" in any case, and trailing zeros, are the same request.
    let r = verify(params("0.0020", &recipient(), "sol")).await;
    assert_eq!(
        r.decision,
        ExecutionDecision::ExecutableApproved,
        "{:?}",
        r.risk_verdict.findings
    );
}

/// Executable on Round 35: the request asks for 0.003 SOL.
#[tokio::test]
async fn a_wrong_amount_is_blocked() {
    for amount in ["0.003", "0.0019", "2", "0.000000001"] {
        let r = verify(params(amount, &recipient(), "SOL")).await;
        assert_eq!(
            r.decision,
            ExecutionDecision::Blocked,
            "{amount}: {}",
            r.summary
        );
        let why = finding(&r, "IntentMismatch").expect("IntentMismatch");
        assert!(why.contains("2000000"), "{why}");
    }
}

#[tokio::test]
async fn a_wrong_recipient_is_blocked() {
    for other in [
        payer_b58(),
        "Vote111111111111111111111111111111111111111".to_string(),
    ] {
        let r = verify(params("0.002", &other, "SOL")).await;
        assert_eq!(r.decision, ExecutionDecision::Blocked, "{}", r.summary);
        assert!(finding(&r, "IntentMismatch")
            .expect("mismatch")
            .contains(&recipient()));
    }
}

/// The request names a token; the bytes move native SOL.
#[tokio::test]
async fn a_wrong_asset_is_blocked() {
    let usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let r = verify(params("0.002", &recipient(), usdc)).await;
    assert_eq!(r.decision, ExecutionDecision::Blocked, "{}", r.summary);
    assert!(finding(&r, "IntentMismatch")
        .expect("mismatch")
        .contains("native SOL"));
}

/// No parameters, a symbol, an amount that is not a plain decimal, a
/// destination that is not an address: nothing to bind. Approved for
/// analysis, never executable.
#[tokio::test]
async fn parameters_the_core_cannot_bind_are_never_executable() {
    let cases: Vec<(&str, Option<ExtractedParameters>)> = vec![
        ("none", None),
        ("empty", Some(ExtractedParameters::default())),
        ("symbol", params("0.002", &recipient(), "USDC")),
        ("exponent", params("2e-3", &recipient(), "SOL")),
        ("comma", params("0,002", &recipient(), "SOL")),
        ("too precise", params("0.0020000000", &recipient(), "SOL")),
        ("name", params("0.002", "alice.sol", "SOL")),
        (
            "no destination",
            Some(ExtractedParameters {
                amount: Some("0.002".into()),
                input_token: Some("SOL".into()),
                ..Default::default()
            }),
        ),
    ];
    for (what, p) in cases {
        let r = verify(p).await;
        assert!(
            r.approved,
            "{what}: {} {:?}",
            r.summary, r.risk_verdict.findings
        );
        assert_eq!(r.decision, ExecutionDecision::AnalysisOnly, "{what}");
        assert!(!r.executable, "{what}");
        assert!(
            r.scope
                .unobserved_codes()
                .contains(&UnobservedCode::IntentParameters),
            "{what}: {:?}",
            r.scope.unobserved_codes()
        );
    }
}

/// A descriptive request (no bytes) is refused on a disagreement too.
#[test]
fn a_described_wrong_amount_is_blocked_without_an_rpc() {
    let r = GraphiteCore::new()
        .verify(&request(params("5", &recipient(), "SOL"), false))
        .unwrap();
    assert_eq!(r.decision, ExecutionDecision::Blocked, "{}", r.summary);
    assert!(finding(&r, "IntentMismatch").is_some());
    let control = GraphiteCore::new()
        .verify(&request(params("0.002", &recipient(), "SOL"), false))
        .unwrap();
    assert_eq!(
        control.decision,
        ExecutionDecision::AnalysisOnly,
        "{}",
        control.summary
    );
}

// ─── The binding, instruction by instruction ────────────────────────────────

const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const WALLET: &str = "GM4eCsQuaLNXApYz6YYUQVMxajTaJ7dB4TbroFGBaou9";
const FRIEND: &str = "8u8LCMQvMKrFxHbn326Ltcqv72HDPEC5FPMgPC3mXvxV";
const STRANGER: &str = "Stake11111111111111111111111111111111111111";

fn ata(owner: &str, mint: &str, program: &str) -> String {
    let p = |s: &str| graphite_core::Pubkey::from_base58(s).unwrap();
    graphite_core::find_program_address(
        &[
            p(owner).as_bytes(),
            p(program).as_bytes(),
            p(mint).as_bytes(),
        ],
        &p("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"),
    )
    .unwrap()
    .0
    .to_base58()
}

fn ix(program: &str, accounts: &[&str], data: Vec<u8>) -> Ix {
    Ix {
        program_id: program.to_string(),
        accounts: accounts.iter().map(|s| s.to_string()).collect(),
        data,
    }
}

fn checked(tag: u8, amount: u64, decimals: u8) -> Vec<u8> {
    let mut d = vec![tag];
    d.extend_from_slice(&amount.to_le_bytes());
    d.push(decimals);
    d
}

fn run(
    intent: &str,
    p: Option<ExtractedParameters>,
    ixs: &[Ix],
    diff: Option<&StateDiff>,
) -> Binding {
    let signers = vec![WALLET.to_string()];
    let decimals = BTreeMap::new();
    bind(&BindingInput {
        canonical_intent: intent,
        params: p.as_ref(),
        instructions: Ok(ixs),
        signers: &signers,
        diff,
        mint_decimals: &decimals,
    })
}

fn is_mismatch(b: &Binding) -> bool {
    matches!(b, Binding::Mismatch { .. })
}

#[test]
fn transfer_with_seed_binds_its_base_and_recipient() {
    let mut d = vec![11, 0, 0, 0];
    d.extend_from_slice(&5_000u64.to_le_bytes());
    d.extend_from_slice(&3u64.to_le_bytes());
    d.extend_from_slice(b"abc");
    d.extend_from_slice(&[7u8; 32]);
    let derived = "SysvarRent111111111111111111111111111111111";
    let good = ix(SYSTEM, &[derived, WALLET, FRIEND], d.clone());
    assert!(matches!(
        run(
            "transfer",
            params("0.000005", FRIEND, "SOL"),
            std::slice::from_ref(&good),
            None
        ),
        Binding::Bound(_)
    ));
    assert!(is_mismatch(&run(
        "transfer",
        params("0.000006", FRIEND, "SOL"),
        std::slice::from_ref(&good),
        None
    )));
    // The recipient slot is the THIRD account, not the second.
    assert!(is_mismatch(&run(
        "transfer",
        params("0.000005", WALLET, "SOL"),
        &[good],
        None
    )));
    // A base that does not sign moves nothing the request's wallet authorised.
    let unsigned = ix(SYSTEM, &[derived, STRANGER, FRIEND], d);
    assert!(is_mismatch(&run(
        "transfer",
        params("0.000005", FRIEND, "SOL"),
        &[unsigned],
        None
    )));
}

#[test]
fn a_split_transfer_must_add_up_and_go_to_one_recipient() {
    let a = ix(SYSTEM, &[WALLET, FRIEND], transfer_data(1_000));
    let b = ix(SYSTEM, &[WALLET, FRIEND], transfer_data(2_000));
    assert!(matches!(
        run(
            "transfer",
            params("0.000003", FRIEND, "SOL"),
            &[a.clone(), b.clone()],
            None
        ),
        Binding::Bound(_)
    ));
    assert!(is_mismatch(&run(
        "transfer",
        params("0.000001", FRIEND, "SOL"),
        &[a.clone(), b],
        None
    )));
    let elsewhere = ix(SYSTEM, &[WALLET, STRANGER], transfer_data(1));
    assert!(is_mismatch(&run(
        "transfer",
        params("0.000001", FRIEND, "SOL"),
        &[a, elsewhere],
        None
    )));
}

#[test]
fn a_token_transfer_binds_mint_decimals_amount_and_the_recipients_account() {
    let src = ata(WALLET, USDC, TOKEN);
    let dst = ata(FRIEND, USDC, TOKEN);
    let t = |dest: &str, mint: &str, amount: u64, program: &str| {
        ix(program, &[&src, mint, dest, WALLET], checked(12, amount, 6))
    };
    let ok = run(
        "transfer",
        params("1.5", FRIEND, USDC),
        &[t(&dst, USDC, 1_500_000, TOKEN)],
        None,
    );
    assert!(matches!(ok, Binding::Bound(_)), "{ok:?}");
    // The destination named directly as the token account binds too.
    assert!(matches!(
        run(
            "transfer",
            params("1.5", &dst, USDC),
            &[t(&dst, USDC, 1_500_000, TOKEN)],
            None
        ),
        Binding::Bound(_)
    ));
    for (what, b) in [
        (
            "amount",
            run(
                "transfer",
                params("1.4", FRIEND, USDC),
                &[t(&dst, USDC, 1_500_000, TOKEN)],
                None,
            ),
        ),
        (
            "mint",
            run(
                "transfer",
                params("1.5", FRIEND, NATIVE_MINT),
                &[t(&dst, USDC, 1_500_000, TOKEN)],
                None,
            ),
        ),
        (
            "recipient",
            run(
                "transfer",
                params("1.5", STRANGER, USDC),
                &[t(&dst, USDC, 1_500_000, TOKEN)],
                None,
            ),
        ),
        (
            "someone else's ATA",
            run(
                "transfer",
                params("1.5", FRIEND, USDC),
                &[t(&ata(STRANGER, USDC, TOKEN), USDC, 1_500_000, TOKEN)],
                None,
            ),
        ),
        // The friend's ATA under the OTHER token program is not where a classic transfer pays.
        (
            "program",
            run(
                "transfer",
                params("1.5", FRIEND, USDC),
                &[t(&ata(FRIEND, USDC, TOKEN_2022), USDC, 1_500_000, TOKEN)],
                None,
            ),
        ),
        (
            "native",
            run(
                "transfer",
                params("1.5", FRIEND, "SOL"),
                &[t(&dst, USDC, 1_500_000, TOKEN)],
                None,
            ),
        ),
    ] {
        assert!(is_mismatch(&b), "{what}: {b:?}");
    }
    // Too many decimals for the mint's 6: not an amount of this token.
    assert!(matches!(
        run(
            "transfer",
            params("1.0000001", FRIEND, USDC),
            &[t(&dst, USDC, 1_500_000, TOKEN)],
            None
        ),
        Binding::Unbound(_)
    ));
}

#[test]
fn transfer_checked_with_fee_binds_the_amount_sent() {
    let src = ata(WALLET, USDC, TOKEN_2022);
    let dst = ata(FRIEND, USDC, TOKEN_2022);
    let mut d = vec![26, 1];
    d.extend_from_slice(&2_000_000u64.to_le_bytes());
    d.push(6);
    d.extend_from_slice(&20_000u64.to_le_bytes());
    let i = ix(TOKEN_2022, &[&src, USDC, &dst, WALLET], d);
    assert!(matches!(
        run(
            "transfer",
            params("2", FRIEND, USDC),
            std::slice::from_ref(&i),
            None
        ),
        Binding::Bound(_)
    ));
    assert!(is_mismatch(&run(
        "transfer",
        params("1.98", FRIEND, USDC),
        &[i],
        None
    )));
}

/// An unchecked Transfer names no mint: bound only when the simulated
/// pre-state says what the source holds.
#[test]
fn an_unchecked_transfer_needs_the_simulated_mint() {
    let src = ata(WALLET, USDC, TOKEN);
    let dst = ata(FRIEND, USDC, TOKEN);
    let mut data = vec![3];
    data.extend_from_slice(&1_000_000u64.to_le_bytes());
    let i = ix(TOKEN, &[&src, &dst, WALLET], data);
    assert!(matches!(
        run(
            "transfer",
            params("1", FRIEND, USDC),
            std::slice::from_ref(&i),
            None
        ),
        Binding::Unbound(_)
    ));
    let diff = StateDiff {
        deltas: vec![token_delta(&src, USDC, WALLET, 5_000_000, 4_000_000)],
        ..Default::default()
    };
    let signers = vec![WALLET.to_string()];
    let mut decimals = BTreeMap::new();
    decimals.insert(USDC.to_string(), 6u8);
    let p = params("1", FRIEND, USDC);
    let b = bind(&BindingInput {
        canonical_intent: "transfer",
        params: p.as_ref(),
        instructions: Ok(&[i]),
        signers: &signers,
        diff: Some(&diff),
        mint_decimals: &decimals,
    });
    assert!(matches!(b, Binding::Bound(_)), "{b:?}");
}

#[test]
fn approve_binds_the_delegate_and_the_allowance() {
    let src = ata(WALLET, USDC, TOKEN);
    let i = ix(
        TOKEN,
        &[&src, USDC, FRIEND, WALLET],
        checked(13, 10_000_000, 6),
    );
    assert!(matches!(
        run(
            "approve",
            params("10", FRIEND, USDC),
            std::slice::from_ref(&i),
            None
        ),
        Binding::Bound(_)
    ));
    assert!(is_mismatch(&run(
        "approve",
        params("1", FRIEND, USDC),
        std::slice::from_ref(&i),
        None
    )));
    assert!(is_mismatch(&run(
        "approve",
        params("10", STRANGER, USDC),
        std::slice::from_ref(&i),
        None
    )));
    // An approve request carrying a transfer.
    let t = ix(
        TOKEN,
        &[&src, USDC, &ata(FRIEND, USDC, TOKEN), WALLET],
        checked(12, 1, 6),
    );
    assert!(is_mismatch(&run(
        "approve",
        params("10", FRIEND, USDC),
        &[i, t],
        None
    )));
}

#[test]
fn burn_binds_the_amount_and_mint() {
    let acct = ata(WALLET, USDC, TOKEN);
    let i = ix(TOKEN, &[&acct, USDC, WALLET], checked(15, 3_000_000, 6));
    let p = |a: &str, m: &str| {
        Some(ExtractedParameters {
            amount: Some(a.into()),
            input_token: Some(m.into()),
            ..Default::default()
        })
    };
    assert!(matches!(
        run("burn", p("3", USDC), std::slice::from_ref(&i), None),
        Binding::Bound(_)
    ));
    assert!(is_mismatch(&run(
        "burn",
        p("30", USDC),
        std::slice::from_ref(&i),
        None
    )));
    assert!(is_mismatch(&run("burn", p("3", NATIVE_MINT), &[i], None)));
}

/// A transfer request carrying a token Approve is a request the bytes exceed.
#[test]
fn a_transfer_request_carrying_an_approve_is_a_mismatch() {
    let src = ata(WALLET, USDC, TOKEN);
    let t = ix(SYSTEM, &[WALLET, FRIEND], transfer_data(2_000_000));
    let a = ix(
        TOKEN,
        &[&src, USDC, STRANGER, WALLET],
        checked(13, u64::MAX, 6),
    );
    assert!(is_mismatch(&run(
        "transfer",
        params("0.002", FRIEND, "SOL"),
        &[t, a],
        None
    )));
}

#[test]
fn stake_and_intents_that_state_nothing() {
    assert!(matches!(
        run("stake", params("1", FRIEND, "SOL"), &[], None),
        Binding::Unbound(_)
    ));
    for intent in ["close", "revoke", "create", "claim", "configure"] {
        assert_eq!(
            run(intent, None, &[], None),
            Binding::NotApplicable,
            "{intent}"
        );
    }
}

// ─── Swaps ──────────────────────────────────────────────────────────────────

fn token_snapshot(pubkey: &str, mint: &str, owner: &str, amount: u64) -> AccountSnapshot {
    AccountSnapshot {
        pubkey: pubkey.to_string(),
        lamports: 2_039_280,
        owner: TOKEN.to_string(),
        data_len: 165,
        token: Some(TokenAccountView {
            mint: mint.to_string(),
            owner: owner.to_string(),
            amount,
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn token_delta(pubkey: &str, mint: &str, owner: &str, before: u64, after: u64) -> AccountDelta {
    AccountDelta {
        pubkey: pubkey.to_string(),
        before: Some(token_snapshot(pubkey, mint, owner, before)),
        after: Some(token_snapshot(pubkey, mint, owner, after)),
    }
}

fn lamports_delta(pubkey: &str, before: u64, after: u64) -> AccountDelta {
    let s = |l| AccountSnapshot {
        pubkey: pubkey.to_string(),
        lamports: l,
        owner: SYSTEM.to_string(),
        ..Default::default()
    };
    AccountDelta {
        pubkey: pubkey.to_string(),
        before: Some(s(before)),
        after: Some(s(after)),
    }
}

fn cpmm(amount_in: u64, min_out: u64) -> Vec<u8> {
    let mut d = hex::decode("8fbe5adac41e33de").unwrap();
    d.extend_from_slice(&amount_in.to_le_bytes());
    d.extend_from_slice(&min_out.to_le_bytes());
    d
}

fn swap_params(amount: &str, slippage: Option<i64>) -> Option<ExtractedParameters> {
    Some(ExtractedParameters {
        amount: Some(amount.into()),
        input_token: Some("SOL".into()),
        output_token: Some(USDC.into()),
        slippage_bps: slippage,
        ..Default::default()
    })
}

/// A SOL → USDC swap the simulation saw deliver `delivered` USDC.
fn swap_diff(spent_lamports: u64, delivered: u64) -> StateDiff {
    let wsol = ata(WALLET, NATIVE_MINT, TOKEN);
    let usdc = ata(WALLET, USDC, TOKEN);
    StateDiff {
        deltas: vec![
            lamports_delta(
                WALLET,
                10_000_000_000,
                10_000_000_000 - spent_lamports - 5_000,
            ),
            token_delta(&wsol, NATIVE_MINT, WALLET, 0, 0),
            token_delta(&usdc, USDC, WALLET, 0, delivered),
        ],
        ..Default::default()
    }
}

fn swap(p: Option<ExtractedParameters>, data: Vec<u8>, diff: Option<&StateDiff>) -> Binding {
    run("swap", p, &[ix(RAYDIUM_CPMM, &[WALLET], data)], diff)
}

#[test]
fn a_swap_binds_amount_in_spend_delivery_and_slippage() {
    let diff = swap_diff(1_000_000_000, 150_000_000);
    // 1 SOL in, at least 149.0 USDC of the 150 simulated: 0.67%, within 1%.
    let ok = swap(
        swap_params("1", None),
        cpmm(1_000_000_000, 149_000_000),
        Some(&diff),
    );
    assert!(matches!(ok, Binding::Bound(_)), "{ok:?}");
    // Spends more than asked.
    assert!(is_mismatch(&swap(
        swap_params("0.5", None),
        cpmm(1_000_000_000, 149_000_000),
        Some(&diff)
    )));
    // A minimum of one base unit: the chain would hold it to nothing.
    let dust = swap(swap_params("1", None), cpmm(1_000_000_000, 1), Some(&diff));
    assert!(
        matches!(
            &dust,
            Binding::Mismatch {
                pattern: "SwapUnderbounded",
                ..
            }
        ),
        "{dust:?}"
    );
    // 2% below what was simulated, under the default 1%; allowed when the
    // request states 3%, refused when it states more than the 5% ceiling.
    let two = cpmm(1_000_000_000, 147_000_000);
    assert!(matches!(
        swap(swap_params("1", None), two.clone(), Some(&diff)),
        Binding::Mismatch {
            pattern: "SwapUnderbounded",
            ..
        }
    ));
    assert!(matches!(
        swap(swap_params("1", Some(300)), two.clone(), Some(&diff)),
        Binding::Bound(_)
    ));
    assert!(matches!(
        swap(swap_params("1", Some(501)), two, Some(&diff)),
        Binding::Mismatch {
            pattern: "SwapUnderbounded",
            ..
        }
    ));
    // A minimum above what was simulated would not land.
    assert!(is_mismatch(&swap(
        swap_params("1", None),
        cpmm(1_000_000_000, 151_000_000),
        Some(&diff)
    )));
    // The simulation takes more SOL than asked plus the 0.01 overhead.
    let greedy = swap_diff(1_100_000_000, 150_000_000);
    assert!(is_mismatch(&swap(
        swap_params("1", None),
        cpmm(1_000_000_000, 149_000_000),
        Some(&greedy)
    )));
    // Delivers nothing of the requested token.
    let nothing = swap_diff(1_000_000_000, 0);
    assert!(is_mismatch(&swap(
        swap_params("1", None),
        cpmm(1_000_000_000, 149_000_000),
        Some(&nothing)
    )));
    // No simulation: nothing measured, nothing bound.
    assert!(matches!(
        swap(
            swap_params("1", None),
            cpmm(1_000_000_000, 149_000_000),
            None
        ),
        Binding::Unbound(_)
    ));
}

#[test]
fn a_swap_that_also_spends_another_token_is_a_mismatch() {
    let mut diff = swap_diff(1_000_000_000, 150_000_000);
    let bonk = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263";
    diff.deltas
        .push(token_delta(&ata(WALLET, bonk, TOKEN), bonk, WALLET, 10, 0));
    assert!(is_mismatch(&swap(
        swap_params("1", None),
        cpmm(1_000_000_000, 149_000_000),
        Some(&diff)
    )));
}

#[test]
fn exact_out_trailing_bytes_and_unknown_routes_are_unbound() {
    let diff = swap_diff(1_000_000_000, 150_000_000);
    let mut trailing = cpmm(1_000_000_000, 149_000_000);
    trailing.push(0);
    assert!(matches!(
        swap(swap_params("1", None), trailing, Some(&diff)),
        Binding::Unbound(_)
    ));
    // CPMM swap_base_output.
    let mut out = hex::decode("37d96256a34ab4ad").unwrap();
    out.extend_from_slice(&[0u8; 16]);
    assert!(matches!(
        swap(swap_params("1", None), out, Some(&diff)),
        Binding::Unbound(_)
    ));
    // A program whose swaps the Core does not decode.
    let b = run(
        "swap",
        swap_params("1", None),
        &[ix(
            "dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN",
            &[WALLET],
            cpmm(1, 1),
        )],
        Some(&diff),
    );
    assert!(matches!(b, Binding::Unbound(_)), "{b:?}");
    // Two swaps: bound to one request? No.
    let two = run(
        "swap",
        swap_params("1", None),
        &[
            ix(RAYDIUM_CPMM, &[WALLET], cpmm(1, 1)),
            ix(RAYDIUM_CPMM, &[WALLET], cpmm(1, 1)),
        ],
        Some(&diff),
    );
    assert!(matches!(two, Binding::Unbound(_)));
}

#[test]
fn a_jupiter_route_is_decoded_to_its_own_minimum() {
    let mut d = hex::decode("e517cb977ae3ad2a").unwrap();
    d.extend_from_slice(&1u32.to_le_bytes()); // one step
    d.extend_from_slice(&[7, 100, 0, 1]); // Raydium (unit), 100%, 0 → 1
    d.extend_from_slice(&1_000_000_000u64.to_le_bytes());
    d.extend_from_slice(&150_000_000u64.to_le_bytes());
    d.extend_from_slice(&50u16.to_le_bytes());
    d.push(0);
    let s = decode_swap(JUPITER_V6, &d).unwrap().unwrap();
    assert_eq!((s.amount_in, s.min_out), (1_000_000_000, 149_250_000));
    let mut fee = d.clone();
    *fee.last_mut().unwrap() = 1;
    assert!(
        decode_swap(JUPITER_V6, &fee).unwrap().is_err(),
        "platform fee"
    );
    let mut bad_variant = d.clone();
    bad_variant[12] = 62;
    assert!(decode_swap(JUPITER_V6, &bad_variant).unwrap().is_err());
}

/// The Core's Jupiter variant table is the agent guard's, entry by entry.
#[test]
fn the_jupiter_variant_table_matches_the_guards() {
    let ts = include_str!("../../integrations/agent-guard/swap-instructions.ts");
    let start = ts
        .find("JUPITER_SWAP_VARIANTS: readonly JupiterSwapPayload[] = [")
        .unwrap();
    let body = &ts[start..ts[start..].find("];").unwrap() + start];
    let guard: Vec<&str> = body
        .lines()
        .skip(1)
        .flat_map(|l| l.split("//").next().unwrap().split(','))
        .map(|s| s.trim().trim_matches('"'))
        .filter(|s| !s.is_empty())
        .collect();
    let core: Vec<&str> = JUPITER_SWAP_VARIANTS
        .iter()
        .map(|v| match v {
            JupiterPayload::Unit => "unit",
            JupiterPayload::Bool => "bool",
            JupiterPayload::Side => "side",
            JupiterPayload::U64U64 => "u64u64",
            JupiterPayload::U32 => "u32",
            JupiterPayload::Clone => "clone",
            JupiterPayload::WhirlpoolV2 => "whirlpoolV2",
        })
        .collect();
    assert_eq!(core, guard);
}

#[test]
fn the_wallet_effect_counts_wrapped_sol_as_sol() {
    let wsol = ata(WALLET, NATIVE_MINT, TOKEN);
    let diff = StateDiff {
        deltas: vec![
            lamports_delta(WALLET, 100, 90),
            token_delta(&wsol, NATIVE_MINT, WALLET, 50, 20),
        ],
        ..Default::default()
    };
    let e = wallet_effect(&diff, WALLET);
    assert_eq!((e.sol_out, e.wrapped_sol_delta), (40, -30));
}

// ─── Withdrawals (F-004) ────────────────────────────────────────────────────

#[test]
fn a_withdrawal_minimum_is_held_to_what_was_simulated() {
    let r0 = ata(WALLET, USDC, TOKEN);
    let r1 = ata(WALLET, NATIVE_MINT, TOKEN);
    let diff = StateDiff {
        deltas: vec![
            token_delta(&r0, USDC, WALLET, 0, 100_000_000),
            token_delta(&r1, NATIVE_MINT, WALLET, 0, 1_000_000_000),
        ],
        ..Default::default()
    };
    let m = |a: u64, b: u64| {
        vec![
            ("minimum_token_0_amount", a, r0.clone()),
            ("minimum_token_1_amount", b, r1.clone()),
        ]
    };
    assert!(matches!(
        bind_withdrawal("withdraw", &m(99_500_000, 995_000_000), None, Some(&diff)),
        Binding::Bound(_)
    ));
    // Non-zero dust: the R33-11 check passed it; it is not a bound.
    let dust = bind_withdrawal("withdraw", &m(1, 995_000_000), None, Some(&diff));
    assert!(
        matches!(
            &dust,
            Binding::Mismatch {
                pattern: "WithdrawalUnderbounded",
                ..
            }
        ),
        "{dust:?}"
    );
    assert!(matches!(
        bind_withdrawal("withdraw", &m(99_500_000, 995_000_000), None, None),
        Binding::Unbound(_)
    ));
    // A withdrawal whose instruction carries no minimum at all.
    assert!(matches!(
        bind_withdrawal("remove_liquidity2", &[], None, Some(&diff)),
        Binding::Unbound(_)
    ));
    // A stated slippage loosens it, up to the ceiling.
    let p = Some(ExtractedParameters {
        slippage_bps: Some(500),
        ..Default::default()
    });
    assert!(matches!(
        bind_withdrawal(
            "withdraw",
            &m(96_000_000, 960_000_000),
            p.as_ref(),
            Some(&diff)
        ),
        Binding::Bound(_)
    ));
}
