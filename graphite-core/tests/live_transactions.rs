//! Live real-transaction corpus (network-dependent).
//!
//! Fetches REAL Solana devnet transactions (recent block via
//! `getBlock`), builds a `VerificationInput` from each one's actual
//! message shape (program, accounts, instruction data), and runs the full
//! pipeline over them. This proves the engine handles real on-chain
//! transaction shapes — not just handcrafted fixtures.
//!
//! The transaction→input conversion lives in the production module
//! `graphite_core::live_corpus::tx_to_input` (unit-tested against pinned
//! real mainnet transactions); this test exercises the full fetch → verify
//! loop against live devnet.
//!
//! `#[ignore]`d by default so the deterministic suite never depends on the
//! network. Run explicitly:
//!
//! ```bash
//! cargo test --features rpc -- --ignored verify_real_devnet_transactions
//! ```

#![cfg(feature = "rpc")]

#[tokio::test]
#[ignore = "network test — run explicitly: cargo test --features rpc -- --ignored live_transactions"]
async fn verify_real_devnet_transactions() {
    // Use the operator-configured RPC endpoint when provided (production
    // setup: GRAPHITE_RPC_URL), falling back to public devnet for CI.
    let client = match std::env::var("GRAPHITE_RPC_URL") {
        Ok(url) if !url.is_empty() => {
            graphite_core::rpc_client::SolanaRpcClient::new(graphite_core::rpc_client::RpcConfig {
                endpoint: url,
                ..Default::default()
            })
        }
        _ => graphite_core::rpc_client::SolanaRpcClient::devnet(),
    };
    let core = graphite_core::GraphiteCore::new();

    // Network tests must degrade gracefully, never panic the suite: if devnet
    // is unreachable, report and return instead of crashing with .expect().
    let Ok(slot) = client.get_slot().await else {
        eprintln!("[live corpus] devnet unreachable (getSlot failed) — skipping; re-run when network is available");
        return;
    };

    let prefer: Vec<String> = core
        .list_manifests()
        .iter()
        .map(|m| m.protocol.program_id.clone())
        .collect();
    let prefer: Vec<&str> = prefer.iter().map(|s| s.as_str()).collect();
    let mut verified = 0usize;
    let mut attempted = 0usize;
    // Devnet block production is bursty (long empty stretches), so walk back
    // up to 300 slots to find non-empty blocks with real transactions.
    for s in slot.saturating_sub(300)..=slot {
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
            // Production converter: prefers known-manifest programs over the
            // System fee-payment / ComputeBudget setup instructions.
            let Some(input) = graphite_core::live_corpus::tx_to_input(tx, &prefer) else {
                continue;
            };
            attempted += 1;
            match core.verify_async(&input).await {
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
