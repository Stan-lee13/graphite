//! Requires the `rpc` feature: every check reads real mainnet state.
#![cfg(feature = "rpc")]

//! Round 20: the transfer-fee model against REAL fee-bearing mints.
//!
//! The unit and mock-RPC tests prove the model does what Token-2022's source
//! says. This proves it against the chain: for every executed Token-2022
//! `TransferChecked` / `TransferCheckedWithFee` in a sample of finalized
//! blocks whose mint carries a `TransferFeeConfig`, it
//!
//! 1. reads the REAL mint and decodes its schedule with Graphite's decoder;
//! 2. reads the transaction's own token-balance metadata — what the chain
//!    recorded arriving at the destination;
//! 3. requires that arrival to be the transferred amount minus the fee
//!    Graphite computes under one of the mint's two schedules — and, for
//!    `TransferCheckedWithFee`, that fee to be the one the instruction itself
//!    declared.
//!
//! Two sources of transfers: the block sample, and the recent history of
//! every fee-bearing mint it contains (`GRAPHITE_FEE_MINT_HISTORY` signatures
//! each, default 25).
//!
//! Read-only and paced (1.5 s between transactions, a hard cap), nothing
//! signed or sent. The mint is read now and the transfer happened earlier,
//! so a schedule changed in between would show as a mismatch naming both.
//!
//! ```bash
//! GRAPHITE_MAINNET_SAMPLE=/path/to/sample.json \
//! GRAPHITE_MAINNET_RPC_URL=https://api.mainnet-beta.solana.com \
//!   cargo test --test mainnet_transfer_fee_live -- --ignored --nocapture
//! ```

use base64::Engine;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::state_diff::{decode_transfer_fee_config, SPL_TOKEN_2022_PROGRAM};
use std::collections::{BTreeMap, BTreeSet};

struct Candidate {
    slot: u64,
    signature: String,
    mint: String,
    destination_index: usize,
    amount: u64,
    declared_fee: Option<u64>,
}

fn u64_le(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(at..at + 8)?.try_into().ok()?))
}

#[tokio::test]
#[ignore = "live mainnet: set GRAPHITE_MAINNET_SAMPLE and GRAPHITE_MAINNET_RPC_URL"]
async fn real_fee_bearing_transfers_arrive_as_the_model_computes() {
    let (Ok(path), Ok(endpoint)) = (
        std::env::var("GRAPHITE_MAINNET_SAMPLE"),
        std::env::var("GRAPHITE_MAINNET_RPC_URL"),
    ) else {
        eprintln!("[fee] set GRAPHITE_MAINNET_SAMPLE and GRAPHITE_MAINNET_RPC_URL; skipping rather than passing vacuously");
        return;
    };
    let limit: usize = std::env::var("GRAPHITE_MAINNET_LIVE_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("sample")).expect("json");
    let client = SolanaRpcClient::new(RpcConfig {
        endpoint,
        timeout: std::time::Duration::from_secs(20),
        max_retries: 1,
        ..Default::default()
    });

    // Every executed top-level Token-2022 transfer with an amount in its data.
    let mut candidates: Vec<Candidate> = Vec::new();
    for row in doc["rows"].as_array().expect("rows") {
        if row["err"].as_bool() == Some(true) {
            continue;
        }
        let Ok(bytes) = base64::engine::general_purpose::STANDARD
            .decode(row["b64"].as_str().unwrap_or_default())
        else {
            continue;
        };
        let Ok(message) = graphite_core::tx_artifact::parse_transaction(&bytes) else {
            continue;
        };
        let Some(signature) = bytes.get(1..65).map(|s| bs58::encode(s).into_string()) else {
            continue;
        };
        // The first signature: legacy/v0 put it after the count byte; a v1
        // frame puts the signatures last.
        let signature = if graphite_core::tx_artifact::is_v1_frame(&bytes) {
            let n = usize::from(bytes[1]);
            let start = bytes.len() - 64 * n;
            bs58::encode(&bytes[start..start + 64]).into_string()
        } else {
            signature
        };
        let mut keys = message.static_keys.clone();
        for field in ["loaded_writable", "loaded_readonly"] {
            if let Some(list) = row[field].as_array() {
                keys.extend(list.iter().filter_map(|k| k.as_str().map(str::to_string)));
            }
        }
        for ix in &message.instructions {
            if ix.program_id != SPL_TOKEN_2022_PROGRAM {
                continue;
            }
            let (amount, declared_fee) = match ix.data.first() {
                Some(12) => (u64_le(&ix.data, 1), None),
                Some(26) if ix.data.get(1) == Some(&1) => {
                    (u64_le(&ix.data, 2), u64_le(&ix.data, 11))
                }
                _ => continue,
            };
            let (Some(amount), Some(&mint_i), Some(&dest_i)) =
                (amount, ix.account_indexes.get(1), ix.account_indexes.get(2))
            else {
                continue;
            };
            let Some(mint) = keys.get(usize::from(mint_i)).cloned() else {
                continue;
            };
            candidates.push(Candidate {
                slot: row["slot"].as_u64().unwrap_or(0),
                signature: signature.clone(),
                mint,
                destination_index: usize::from(dest_i),
                amount,
                declared_fee,
            });
        }
    }
    println!(
        "[fee] {} Token-2022 transfer instruction(s) in the sample",
        candidates.len()
    );

    // Their mints, read once, decoded with Graphite's decoder.
    let mints: Vec<String> = candidates
        .iter()
        .map(|c| c.mint.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut configs = BTreeMap::new();
    for chunk in mints.chunks(100) {
        let accounts = client
            .get_multiple_accounts(chunk)
            .await
            .expect("mint read");
        for (mint, account) in chunk.iter().zip(accounts) {
            if let Some(c) = account
                .filter(|a| a.owner == SPL_TOKEN_2022_PROGRAM)
                .and_then(|a| decode_transfer_fee_config(&a.data))
            {
                configs.insert(mint.clone(), c);
            }
        }
    }
    println!(
        "[fee] {} distinct mint(s), {} carrying a TransferFeeConfig",
        mints.len(),
        configs.len()
    );

    let mut checked = 0usize;
    let mut charged = 0usize;
    let mut mismatches: Vec<String> = Vec::new();
    for c in candidates.iter().filter(|c| configs.contains_key(&c.mint)) {
        if checked >= limit {
            break;
        }
        let config = &configs[&c.mint];
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let Ok(tx) = client.get_transaction(&c.signature).await else {
            continue;
        };
        let meta = &tx["meta"];
        let balance = |side: &str| -> Option<u64> {
            meta[side]
                .as_array()?
                .iter()
                .find(|b| b["accountIndex"].as_u64() == Some(c.destination_index as u64))
                .and_then(|b| b["uiTokenAmount"]["amount"].as_str()?.parse().ok())
        };
        // A destination created in this transaction has no pre-balance entry.
        let (Some(after), before) = (balance("postTokenBalances"), balance("preTokenBalances"))
        else {
            continue;
        };
        let arrived = after.saturating_sub(before.unwrap_or(0));
        checked += 1;
        let older = config.older.fee(c.amount);
        let newer = config.newer.fee(c.amount);
        let fits = |fee: Option<u64>| fee.is_some_and(|f| c.amount - f == arrived);
        let schedule_ok = fits(older) || fits(newer);
        let declared_ok = c
            .declared_fee
            .is_none_or(|f| older == Some(f) || newer == Some(f));
        if c.amount != arrived {
            charged += 1;
        }
        println!(
            "[fee] slot {} mint {} amount {} arrived {} fee {} (schedules {:?} / {:?}){}",
            c.slot,
            &c.mint[..8],
            c.amount,
            arrived,
            c.amount - arrived.min(c.amount),
            older,
            newer,
            if schedule_ok && declared_ok {
                ""
            } else {
                "  <-- MISMATCH"
            }
        );
        if !schedule_ok || !declared_ok {
            mismatches.push(format!(
                "slot {} {}: {} sent, {} arrived; Graphite computes {:?} (older) / {:?} (newer); declared {:?}",
                c.slot, c.signature, c.amount, arrived, older, newer, c.declared_fee
            ));
        }
    }

    // Phase 2: each fee-bearing mint's recent history, so the check is not
    // limited to the few transfers a block sample happens to contain. Read
    // in the RPC's JSON form: the message's own account keys (plus the
    // addresses its lookup tables loaded), each instruction's program index,
    // account indexes and base58 data, and the token balances before and
    // after.
    let per_mint: usize = std::env::var("GRAPHITE_FEE_MINT_HISTORY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25);
    for (mint, config) in &configs {
        if per_mint == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let Ok(sigs) = client
            .get_signatures_for_address(mint, per_mint as u64)
            .await
        else {
            continue;
        };
        let signatures: Vec<String> = sigs
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|s| s["err"].is_null())
                    .filter_map(|s| s["signature"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        for signature in signatures {
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            let Ok(tx) = client.get_transaction(&signature).await else {
                continue;
            };
            let message = &tx["transaction"]["message"];
            let mut keys: Vec<String> = message["accountKeys"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|k| k.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            for field in ["writable", "readonly"] {
                if let Some(list) = tx["meta"]["loadedAddresses"][field].as_array() {
                    keys.extend(list.iter().filter_map(|k| k.as_str().map(str::to_string)));
                }
            }
            // Top-level instructions AND the inner ones the runtime recorded:
            // a fee-bearing token mostly moves inside swaps, by CPI.
            let mut all: Vec<serde_json::Value> = message["instructions"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if let Some(inner) = tx["meta"]["innerInstructions"].as_array() {
                for group in inner {
                    if let Some(list) = group["instructions"].as_array() {
                        all.extend(list.iter().cloned());
                    }
                }
            }
            let instructions = &all;
            for ix in instructions {
                let program = ix["programIdIndex"]
                    .as_u64()
                    .and_then(|i| keys.get(i as usize));
                if program.map(String::as_str) != Some(SPL_TOKEN_2022_PROGRAM) {
                    continue;
                }
                let Ok(data) = bs58::decode(ix["data"].as_str().unwrap_or_default()).into_vec()
                else {
                    continue;
                };
                let (amount, declared_fee) = match data.first() {
                    Some(12) => (u64_le(&data, 1), None),
                    Some(26) if data.get(1) == Some(&1) => (u64_le(&data, 2), u64_le(&data, 11)),
                    _ => continue,
                };
                let accounts: Vec<u64> = ix["accounts"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
                    .unwrap_or_default();
                let (Some(amount), Some(&mint_i), Some(&dest_i)) =
                    (amount, accounts.get(1), accounts.get(2))
                else {
                    continue;
                };
                if keys.get(mint_i as usize) != Some(mint) {
                    continue;
                }
                if checked >= limit + per_mint * configs.len() {
                    break;
                }
                let meta = &tx["meta"];
                let balance = |side: &str| -> Option<u64> {
                    meta[side]
                        .as_array()?
                        .iter()
                        .find(|b| b["accountIndex"].as_u64() == Some(dest_i))
                        .and_then(|b| b["uiTokenAmount"]["amount"].as_str()?.parse().ok())
                };
                let (Some(after), before) =
                    (balance("postTokenBalances"), balance("preTokenBalances"))
                else {
                    continue;
                };
                // The balance change isolates THIS transfer's arrival only
                // when no other instruction in the transaction touches the
                // destination — a pool vault that receives and pays out the
                // same token in one swap nets to something else entirely.
                // Skipped, not guessed.
                let touching = instructions
                    .iter()
                    .filter(|o| {
                        o["accounts"]
                            .as_array()
                            .is_some_and(|a| a.iter().any(|x| x.as_u64() == Some(dest_i)))
                    })
                    .count();
                if touching > 1 {
                    continue;
                }
                let arrived = after.saturating_sub(before.unwrap_or(0));
                checked += 1;
                let older = config.older.fee(amount);
                let newer = config.newer.fee(amount);
                let fits =
                    |fee: Option<u64>| fee.is_some_and(|f| amount.checked_sub(f) == Some(arrived));
                let schedule_ok = fits(older) || fits(newer);
                let declared_ok = declared_fee.is_none_or(|f| older == Some(f) || newer == Some(f));
                if amount != arrived {
                    charged += 1;
                }
                if !schedule_ok || !declared_ok {
                    mismatches.push(format!(
                        "history {signature}: {amount} sent, {arrived} arrived; Graphite computes {older:?} (older) / {newer:?} (newer); declared {declared_fee:?}"
                    ));
                }
            }
        }
        println!(
            "[fee] history of mint {}: {checked} checked so far",
            &mint[..8]
        );
    }
    println!("[fee] {checked} real fee-mint transfer(s) checked, {charged} charged a non-zero fee");
    for m in &mismatches {
        println!("[fee] MISMATCH {m}");
    }
    assert!(
        mismatches.is_empty(),
        "{} real transfer(s) arrived differently from the fee the model computes",
        mismatches.len()
    );
}
