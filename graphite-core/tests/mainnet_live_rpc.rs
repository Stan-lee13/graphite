//! Requires the `rpc` feature: every verification here runs against a real
//! Solana RPC.
#![cfg(feature = "rpc")]

//! Graphite processing real mainnet transactions end to end, against a real
//! RPC (Round 19).
//!
//! `mainnet_conformance` pushes real mainnet bytes through the engine with no
//! RPC attached, so L3 and L4 — simulation and the state diff — never run on
//! real traffic there. This test attaches a real RPC and verifies a bounded
//! number of real, successfully executed mainnet transactions exactly as a
//! deployment would: artifact-bound (the chain's frame with its signature
//! slots emptied, as the bridge presents it before signing), every sibling
//! declared, simulated by the RPC (`replaceRecentBlockhash`), pre- and
//! post-state read and diffed.
//!
//! What it asserts is the verdict's INTERNAL consistency on traffic nobody
//! curated — an approval never rests on a failed L2 or L4, a refused risk
//! verdict, or an errored simulation — and it prints what real traffic does
//! to each layer. It does not assert that honest traffic is approved: most
//! of it is refused on thresholds a fresh node has not earned, which is the
//! design.
//!
//! Read-only and deliberately slow: one verification at a time with a pause
//! between them, a hard cap on how many (`GRAPHITE_MAINNET_LIVE_LIMIT`,
//! default 40), and nothing signed or sent. Use your own endpoint where you
//! have one; the public one tolerates a few dozen paced reads.
//!
//! ```bash
//! GRAPHITE_MAINNET_SAMPLE=/path/to/mainnet_sample.json \
//! GRAPHITE_MAINNET_RPC_URL=https://api.mainnet-beta.solana.com \
//!   cargo test --test mainnet_live_rpc -- --ignored --nocapture
//! ```

use base64::Engine;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationScope,
};
use std::collections::BTreeMap;

const BOILERPLATE: &[&str] = &[
    "11111111111111111111111111111111",
    "ComputeBudget111111111111111111111111111111",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
    "Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH",
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",
];

fn status(r: &graphite_core::verification::VerificationResult, prefix: &str) -> LayerStatus {
    r.layers
        .iter()
        .find(|l| l.layer.starts_with(prefix))
        .map(|l| l.status)
        .unwrap_or(LayerStatus::Inconclusive)
}

#[tokio::test]
#[ignore = "live mainnet: set GRAPHITE_MAINNET_SAMPLE and GRAPHITE_MAINNET_RPC_URL"]
async fn real_mainnet_transactions_verified_against_a_real_rpc() {
    let (Ok(path), Ok(endpoint)) = (
        std::env::var("GRAPHITE_MAINNET_SAMPLE"),
        std::env::var("GRAPHITE_MAINNET_RPC_URL"),
    ) else {
        eprintln!("[live] set GRAPHITE_MAINNET_SAMPLE and GRAPHITE_MAINNET_RPC_URL; skipping rather than passing vacuously");
        return;
    };
    // Optional: only instructions of this program (e.g. Token-2022, to
    // exercise the transfer-fee model on real mints and real state).
    let only_program = std::env::var("GRAPHITE_MAINNET_PROGRAM").ok();
    let limit: usize = std::env::var("GRAPHITE_MAINNET_LIVE_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(40);
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("sample")).expect("json");
    let registry = graphite_core::manifest::load_seed_manifests();
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.clone(),
        timeout: std::time::Duration::from_secs(20),
        max_retries: 1,
        ..Default::default()
    }));

    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    let mut bump = |k: String| *tally.entry(k).or_default() += 1;
    let mut violations: Vec<String> = Vec::new();
    let mut done = 0usize;

    // Newest first: the closer to the chain tip, the likelier the state the
    // simulation reads still resembles the state the transaction ran on.
    let mut rows: Vec<&serde_json::Value> = doc["rows"].as_array().expect("rows").iter().collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r["slot"].as_u64().unwrap_or(0)));

    for row in rows {
        if done >= limit {
            break;
        }
        if row["err"].as_bool() == Some(true) {
            continue; // failed on chain: nothing honest to reproduce
        }
        let Ok(bytes) = base64::engine::general_purpose::STANDARD
            .decode(row["b64"].as_str().unwrap_or_default())
        else {
            continue;
        };
        let Ok(message) = graphite_core::tx_artifact::parse_transaction(&bytes) else {
            bump(format!("parse refused (version {})", row["version"]));
            continue;
        };
        let mut keys = message.static_keys.clone();
        for field in ["loaded_writable", "loaded_readonly"] {
            if let Some(list) = row[field].as_array() {
                keys.extend(list.iter().filter_map(|k| k.as_str().map(str::to_string)));
            }
        }
        let resolved: Option<Vec<Vec<String>>> = message
            .instructions
            .iter()
            .map(|ix| {
                ix.account_indexes
                    .iter()
                    .map(|i| keys.get(*i as usize).cloned())
                    .collect()
            })
            .collect();
        let Some(resolved) = resolved else { continue };
        // Only transactions whose primary program Graphite has a manifest for:
        // those are the ones whose verdict means something.
        let pick = message.instructions.iter().enumerate().find(|(i, ix)| {
            !BOILERPLATE.contains(&ix.program_id.as_str())
                && !ix.data.is_empty()
                && !resolved[*i].is_empty()
                && registry.get(&ix.program_id).is_some()
                && only_program.as_deref().is_none_or(|p| ix.program_id == p)
        });
        let Some((idx, ix)) = pick else { continue };
        let disc = hex::encode(&ix.data[..ix.data.len().min(8)]);
        let siblings = message
            .instructions
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != idx)
            .map(
                |(i, s)| graphite_core::tx_pattern_analysis::TransactionInstruction {
                    program_id: s.program_id.clone(),
                    instruction_discriminator: hex::encode(&s.data[..s.data.len().min(8)]),
                    account_addresses: resolved[i].clone(),
                    cpi_targets: vec![],
                },
            )
            .collect();
        let ix_name = registry
            .find_instruction(&ix.program_id, &disc)
            .map(|i| i.name.clone())
            .unwrap_or_default();
        let input = VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: graphite_core::live_corpus::classify_intent(&ix.program_id, &ix_name),
                raw_natural_language: format!("mainnet slot {}", row["slot"]),
                confidence_of_parse: 0.5,
                extracted_parameters: None,
            },
            program_id: ix.program_id.clone(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: disc,
            account_addresses: resolved[idx].clone(),
            instruction_data: Some(ix.data.clone()),
            cpi_targets: vec![],
            wallet_profile: WalletProfile::Gaming,
            behavior_evidence: Default::default(),
            compute_units: 0,
            account_writes: 0,
            cpi_hops: 0,
            signed_transaction: Some(
                graphite_core::tx_artifact::unsigned_artifact(&bytes).expect("parsed frame"),
            ),
            transaction_instructions: siblings,
            cpi_trace: None,
            uses_versioned_transaction: message.version.is_some(),
            lookup_table_count: message.lookups.len() as u32,
            real_account_metas: vec![],
            state_diff: None,
        };

        done += 1;
        let r = match core.verify_async(&input).await {
            Ok(r) => r,
            Err(e) => {
                bump(format!(
                    "verify error: {}",
                    format!("{e}").split(':').next().unwrap_or("?")
                ));
                tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                continue;
            }
        };
        bump(format!(
            "version {}",
            row["version"].as_str().unwrap_or("?")
        ));
        bump(format!("L2 {:?}", status(&r, "L2")));
        bump(format!("L3 {:?}", status(&r, "L3")));
        bump(format!("L4 {:?}", status(&r, "L4")));
        bump(format!("risk {}", r.risk_verdict.status));
        bump(format!("approved {}", r.approved));
        // How the Token-2022 transfer-fee model judged it (Round 20).
        let l4_reason = r
            .layers
            .iter()
            .find(|l| l.layer.starts_with("L4"))
            .map(|l| l.reason.clone())
            .unwrap_or_default();
        if l4_reason.contains("Token2022TransferFeeCharged") {
            bump("transfer fee modelled and stated".to_string());
        }
        if l4_reason.contains("Token2022ExtensionNotModelled") {
            bump("Token-2022 extension not modelled".to_string());
            if l4_reason.contains("TransferFee") {
                println!(
                    "[live] fee not modelled at slot {}: {}",
                    row["slot"],
                    &l4_reason[..l4_reason.len().min(600)]
                );
            }
        }
        if let VerificationScope::ArtifactBound {
            simulated,
            unobserved_codes,
            ..
        } = &r.scope
        {
            bump(format!("simulated {simulated}"));
            for c in unobserved_codes {
                bump(format!("residual {c:?}"));
            }
        } else {
            violations.push(format!(
                "slot {}: an artifact-bound request came back descriptive",
                row["slot"]
            ));
        }
        // The invariants an approval must satisfy, on uncurated traffic.
        if r.approved {
            for (layer, st) in [
                ("L2", status(&r, "L2")),
                ("L4", status(&r, "L4")),
                ("L5", status(&r, "L5")),
            ] {
                if st == LayerStatus::Failed {
                    violations.push(format!(
                        "slot {}: approved with {layer} Failed",
                        row["slot"]
                    ));
                }
            }
            if r.risk_verdict.status != "Clear" {
                violations.push(format!(
                    "slot {}: approved with risk {}",
                    row["slot"], r.risk_verdict.status
                ));
            }
            if status(&r, "L3") == LayerStatus::Failed {
                violations.push(format!("slot {}: approved with L3 Failed", row["slot"]));
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    }

    println!(
        "[live] {done} real mainnet transaction(s) verified against {}",
        if endpoint.contains("mainnet-beta") {
            "the public mainnet RPC"
        } else {
            "the configured RPC"
        }
    );
    for (k, v) in &tally {
        println!("[live]   {k:<40} {v}");
    }
    for v in &violations {
        println!("[live] VIOLATION {v}");
    }
    assert!(
        done > 0,
        "no manifested, successfully executed transaction in the sample"
    );
    assert!(
        violations.is_empty(),
        "{} invariant violation(s)",
        violations.len()
    );
}
