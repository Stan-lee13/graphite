//! Live real-transaction corpus (network-dependent).
//!
//! Fetches REAL Solana devnet transactions (recent block via
//! `getBlock`), builds a `VerificationInput` from each one's actual
//! message shape (program, accounts, instruction data), and runs the full
//! pipeline over them. This proves the engine handles real on-chain
//! transaction shapes — not just handcrafted fixtures.
//!
//! `#[ignore]`d by default so the deterministic suite never depends on the
//! network. Run explicitly:
//!
//! ```bash
//! cargo test --features rpc -- --ignored live_transactions
//! ```

#![cfg(feature = "rpc")]

use graphite_core::verification::{ProposedIntent, VerificationInput};
use graphite_core::WalletProfile;

#[tokio::test]
#[ignore = "network test — run explicitly: cargo test --features rpc -- --ignored live_transactions"]
async fn verify_real_devnet_transactions() {
    let client = graphite_core::rpc_client::SolanaRpcClient::devnet();
    let core = graphite_core::GraphiteCore::new();

    let slot = client
        .get_slot()
        .await
        .expect("getSlot should succeed on devnet");

    let mut verified = 0usize;
    let mut attempted = 0usize;
    // Walk back up to 30 slots to find blocks with transactions.
    for s in slot.saturating_sub(30)..=slot {
        if verified >= 10 {
            break;
        }
        let Ok(block) = client.get_block(s).await else {
            continue; // empty/unknown slot — skip
        };
        let Some(txs) = block.get("transactions").and_then(|t| t.as_array()) else {
            continue;
        };
        for tx in txs {
            if verified >= 10 {
                break;
            }
            let Some(input) = tx_to_input(tx) else {
                continue;
            };
            attempted += 1;
            match core.verify(&input) {
                Ok(result) => {
                    assert!(
                        (0.0..=1.0).contains(&result.confidence) && result.confidence.is_finite(),
                        "real tx produced out-of-range confidence: {}",
                        result.confidence
                    );
                    assert_eq!(result.content_hash.len(), 16);
                    if result.approved {
                        assert_eq!(
                            result.risk_verdict.status, "Clear",
                            "approved must imply Clear risk on a real tx"
                        );
                    }
                    verified += 1;
                }
                Err(e) => panic!("real transaction from slot {} failed to verify: {:?}", s, e),
            }
        }
    }

    assert!(
        verified >= 1,
        "no devnet transactions could be verified (attempted {}) — network or devnet may be down",
        attempted
    );
    eprintln!(
        "[live corpus] verified {} real devnet transactions (attempted {})",
        verified, attempted
    );
}

/// Convert a `getBlock` transaction object into a `VerificationInput`.
/// Uses the transaction's first instruction (program + accounts + data).
fn tx_to_input(tx: &serde_json::Value) -> Option<VerificationInput> {
    let msg = tx.get("transaction")?.get("message")?;
    let keys = msg.get("accountKeys")?.as_array()?;
    let ixs = msg.get("instructions")?.as_array()?;
    let ix = ixs.first()?;

    let program_idx = ix.get("programIdIndex")?.as_u64()? as usize;
    let program_id = keys.get(program_idx)?.as_str()?;

    // Instruction accounts → real account keys (deduplicate, cap at 8).
    let mut accounts: Vec<String> = Vec::new();
    if let Some(idx_list) = ix.get("accounts").and_then(|a| a.as_array()) {
        for idx in idx_list.iter().filter_map(|i| i.as_u64()) {
            if let Some(key) = keys.get(idx as usize).and_then(|k| k.as_str()) {
                if !accounts.contains(&key.to_string()) {
                    accounts.push(key.to_string());
                    if accounts.len() >= 8 {
                        break;
                    }
                }
            }
        }
    }

    // Instruction data is base58-encoded in JSON-encoded blocks.
    let data_b58 = ix.get("data").and_then(|d| d.as_str()).unwrap_or("");
    let discriminator_hex = graphite_core::solana_types::base58_decode(data_b58)
        .map(|bytes| hex::encode(&bytes[..bytes.len().min(8)]))
        .unwrap_or_else(|| "00".to_string());

    // Real compute usage from the block metadata, if reported.
    let compute_units = tx
        .get("meta")
        .and_then(|m| m.get("computeUnitsConsumed"))
        .and_then(|c| c.as_u64())
        .unwrap_or(0);

    Some(VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "live corpus".to_string(),
            confidence_of_parse: 0.5,
            extracted_parameters: None,
        },
        program_id: program_id.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: discriminator_hex,
        account_addresses: accounts,
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::TradingBot,
        behavior_evidence: Default::default(),
        compute_units,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: None,
    })
}
