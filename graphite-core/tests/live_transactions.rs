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
//!
//! `verify_real_c56_protocol_transactions` (C57) fetches REAL transactions
//! that invoke each C56 program (Marinade, SPL Stake Pool, Raydium CLMM/CPMM,
//! Orca TokenSwap V2) via `getSignaturesForAddress` and pushes them through
//! the full pipeline — live grounding of the C56 manifests, complementing the
//! pinned mainnet fixtures in `live_corpus.rs`.

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

/// Live per-protocol C56 corpus (network-dependent): for each C56 program,
/// fetch its real recent signatures, take the first successful one that has a
/// TOP-LEVEL invocation of that program, and run it through the full pipeline.
///
/// Per-program graceful degradation (documented contract): a program with no
/// recent top-level activity is reported and skipped, never failed — Orca
/// TokenSwap V2 is dormant on both devnet and mainnet (its 800 most recent
/// mainnet signatures contain zero top-level invocations; only program-key
/// mentions), so it is EXPECTED to skip. The assertion that at least one C56
/// transaction verified keeps the network contract honest.
#[tokio::test]
#[ignore = "network test — run explicitly: cargo test --features rpc -- --ignored live_transactions"]
async fn verify_real_c56_protocol_transactions() {
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

    let programs: &[(&str, &str)] = &[
        ("marinade", "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD"),
        ("stakepool", "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy"),
        ("clmm", "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK"),
        ("cpmm", "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C"),
        ("orca", "9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP"),
    ];
    let mut verified = 0usize;
    for (name, pid) in programs {
        let Ok(sigs) = client.get_signatures_for_address(pid, 20).await else {
            eprintln!("[live corpus] {name}: getSignaturesForAddress failed — skipping");
            continue;
        };
        let Some(arr) = sigs.as_array() else {
            eprintln!("[live corpus] {name}: no signatures — skipping");
            continue;
        };
        let mut done = false;
        for item in arr {
            if done {
                break;
            }
            // err=null (or absent) is a successful transaction; any other err
            // value means the tx failed and is not a valid grounding.
            match item.get("err") {
                Some(v) if v.is_null() => {}
                None => {}
                _ => continue,
            }
            let Some(sig) = item.get("signature").and_then(|s| s.as_str()) else {
                continue;
            };
            let Ok(tx) = client.get_transaction(sig).await else {
                continue;
            };
            // Prefer THIS program; if the transaction only mentions it as a
            // loaded/CPI target, the fallback picks another program and the
            // program_id assertion below rejects the tx.
            let Some(input) = graphite_core::live_corpus::tx_to_input(&tx, &[*pid]) else {
                continue;
            };
            if input.program_id != *pid {
                continue; // not a top-level invocation of the target program
            }
            match core.verify_async(&input).await {
                Ok(result) => {
                    assert!(
                        (0.0..=1.0).contains(&result.confidence) && result.confidence.is_finite(),
                        "{name}: real tx produced out-of-range confidence"
                    );
                    assert_eq!(result.content_hash.len(), 16);
                    if result.approved {
                        assert_eq!(
                            result.risk_verdict.status, "Clear",
                            "{name}: approved must imply Clear risk on a real tx"
                        );
                    }
                    eprintln!(
                        "[live corpus] {name}: verified real tx {sig} confidence={}",
                        result.confidence
                    );
                    verified += 1;
                    done = true;
                }
                Err(e) => panic!("{name}: real transaction failed to verify: {e:?}"),
            }
        }
        if !done {
            eprintln!(
                "[live corpus] {name}: no top-level invocation found in recent signatures — skipping (expected for dormant programs like Orca TokenSwap V2)"
            );
        }
    }
    assert!(
        verified >= 1,
        "no C56 protocol transaction could be verified — network or devnet may be down"
    );
    eprintln!("[live corpus] verified {verified} real C56 protocol transactions");
}
