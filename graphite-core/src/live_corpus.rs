//! Real on-chain transaction corpus collection — Phase 2 exit criterion:
//! "Benchmark uses real on-chain transaction data (not synthetic)".
//!
//! This module is the production path that feeds REAL Solana transactions
//! (fetched from the RPC network, not handcrafted fixtures) through the full
//! Graphite pipeline and records the outcomes into the regression corpus
//! (append-only, P4). It powers `graphite regression seed-live` and the
//! `live_transactions` integration test.
//!
//! Determinism contract: `tx_to_input` is a pure function over a
//! `getBlock`/`getTransaction` JSON value — it is unit-tested against pinned
//! REAL mainnet transactions (`tests/fixtures/real_mainnet_*.json`) so the
//! parsing is provably correct on genuine on-chain shapes without a network.
//! Only the fetch/verify/record loop requires the network.

use crate::policy_engine::WalletProfile;
#[cfg(feature = "rpc")]
use crate::regression_engine::{record_fixture, RegressionCorpus};
#[cfg(feature = "rpc")]
use crate::rpc_client::SolanaRpcClient;
#[cfg(feature = "rpc")]
use crate::verification::GraphiteCore;
use crate::verification::{ProposedIntent, VerificationInput};

/// Upper bound on account keys extracted per instruction (matches the original
/// live-corpus reader; instruction account lists beyond this are truncated).
pub const MAX_ACCOUNTS_PER_INSTRUCTION: usize = 8;

/// Wallet profile used for corpus collection. Deliberately the same Phase-1
/// honest default as the SAK bridge: `Custom { min_confidence: 0.40,
/// min_trust_tier: OfficialManifest }` — the highest bar a known, clean,
/// intent-aligned protocol can satisfy on a fresh core (~0.44 confidence
/// ceiling, P7 caps manifest tiers at OfficialManifest). This yields a corpus
/// with BOTH passing fixtures (known protocols) and blocking fixtures
/// (unknown/risky), which is what makes replay meaningful.
pub fn corpus_wallet_profile() -> WalletProfile {
    WalletProfile::Custom {
        min_confidence: 0.40,
        min_trust_tier: crate::confidence_engine::TrustTier::OfficialManifest,
    }
}

/// Convert a `getBlock`/`getTransaction` transaction object into a
/// `VerificationInput`.
///
/// Real Solana blocks interleave fee-payment and ComputeBudget instructions
/// with the actual protocol call, so the FIRST instruction is usually
/// System/ComputeBudget — not the interesting program. When `prefer_programs`
/// is non-empty, the first instruction whose program is listed wins; otherwise
/// (or when none match) the first instruction that references accounts is used
/// (setup-only instructions with zero accounts are skipped either way).
///
/// Instruction data is base58-encoded in JSON-encoded RPC responses; the
/// discriminator is the first 8 bytes hex-encoded. Real compute usage comes
/// from the block metadata (`computeUnitsConsumed`).
/// Expand a transaction message's account-key space to its FULL size,
/// including Address Lookup Table (ALT) entries for v0 transactions.
///
/// The JSON-RPC `getBlock`/`getTransaction` response keeps ONLY the static
/// accountKeys for a v0 transaction; instruction indices beyond the static
/// key count resolve into the entries of `addressTableLookups` (per lookup:
/// writable entries then readonly entries, in lookup order). A parser that
/// ignores the lookups silently DROPS every ALT-resolved account — proven
/// against the pinned mainnet fixtures, where the Jupiter swap has 26 such
/// references and the System batch has 8. This expansion restores the exact
/// index space: entries become positionally-correct `alt:{table}:{entry}`
/// placeholders (resolving the actual addresses needs the ALT account data,
/// but program resolution and account-count analysis need only the positions).
pub fn expand_account_keys(msg: &serde_json::Value) -> Option<Vec<String>> {
    let static_keys = msg.get("accountKeys")?.as_array()?;
    let mut keys: Vec<String> = static_keys
        .iter()
        .filter_map(|k| k.as_str().map(String::from))
        .collect();
    if let Some(lookups) = msg.get("addressTableLookups").and_then(|l| l.as_array()) {
        for (ti, l) in lookups.iter().enumerate() {
            let writable = l.get("writableIndexes").and_then(|a| a.as_array());
            let readonly = l.get("readonlyIndexes").and_then(|a| a.as_array());
            let mut entries: Vec<u64> = Vec::new();
            if let Some(w) = writable {
                entries.extend(w.iter().filter_map(|v| v.as_u64()));
            }
            if let Some(r) = readonly {
                entries.extend(r.iter().filter_map(|v| v.as_u64()));
            }
            for e in entries {
                keys.push(format!("alt:{ti}:{e}"));
            }
        }
    }
    Some(keys)
}

pub fn tx_to_input(tx: &serde_json::Value, prefer_programs: &[&str]) -> Option<VerificationInput> {
    let msg = tx.get("transaction")?.get("message")?;
    let keys = expand_account_keys(msg)?;
    let ixs = msg.get("instructions")?.as_array()?;

    // Program-id resolution helper for one instruction index.
    let program_of = |ix: &serde_json::Value| -> Option<String> {
        let program_idx = ix.get("programIdIndex")?.as_u64()? as usize;
        keys.get(program_idx).cloned()
    };
    let has_accounts = |ix: &serde_json::Value| -> bool {
        ix.get("accounts")
            .and_then(|a| a.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false)
    };

    // Preferred instruction: first one whose program is in the known set.
    let preferred = if prefer_programs.is_empty() {
        None
    } else {
        ixs.iter().filter(|ix| has_accounts(ix)).find(|ix| {
            program_of(ix)
                .as_deref()
                .is_some_and(|p| prefer_programs.contains(&p))
        })
    };
    // Fallback: the "meatiest" instruction that references accounts — most
    // account keys (ties resolve to the last maximal). Real blocks front-load
    // System fee payments and ComputeBudget setup, so "first with accounts"
    // would select the fee payment, not the protocol call; the instruction
    // with the most accounts is overwhelmingly the actual program invocation.
    let fallback = ixs.iter().filter(|ix| has_accounts(ix)).max_by_key(|ix| {
        ix.get("accounts")
            .and_then(|a| a.as_array())
            .map(|a| a.len())
            .unwrap_or(0)
    });
    let ix = preferred.or(fallback)?;
    let program_id = program_of(ix)?;

    // Instruction accounts → real account keys (deduplicate, cap).
    let mut accounts: Vec<String> = Vec::new();
    if let Some(idx_list) = ix.get("accounts").and_then(|a| a.as_array()) {
        for idx in idx_list.iter().filter_map(|i| i.as_u64()) {
            if let Some(key) = keys.get(idx as usize).cloned() {
                if !accounts.contains(&key) {
                    accounts.push(key);
                    if accounts.len() >= MAX_ACCOUNTS_PER_INSTRUCTION {
                        break;
                    }
                }
            }
        }
    }

    // Instruction data is base58-encoded in JSON-encoded blocks.
    let data_b58 = ix.get("data").and_then(|d| d.as_str()).unwrap_or("");
    let discriminator_hex = crate::solana_types::base58_decode(data_b58)
        .map(|bytes| hex::encode(&bytes[..bytes.len().min(8)]))
        .unwrap_or_else(|| "00".to_string());

    // Real compute usage from the block metadata, if reported.
    let compute_units = tx
        .get("meta")
        .and_then(|m| m.get("computeUnitsConsumed"))
        .and_then(|c| c.as_u64())
        .unwrap_or(0);

    let signature = tx
        .get("transaction")
        .and_then(|t| t.get("signatures"))
        .and_then(|s| s.as_array())
        .and_then(|s| s.first())
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();

    Some(VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: format!("live corpus {signature}"),
            confidence_of_parse: 0.5,
            extracted_parameters: None,
        },
        program_id,
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: discriminator_hex,
        account_addresses: accounts,
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: corpus_wallet_profile(),
        behavior_evidence: Default::default(),
        compute_units,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: None,
    })
}

/// Fetch up to `count` distinct real transactions from recent non-empty
/// blocks, walking back from `start_slot` (devnet block production is bursty,
/// so this may need to scan many slots). Skips empty/unknown slots and
/// transactions that do not yield a `VerificationInput`. Returns the raw
/// transaction JSON values with slot info attached under `"__slot"` so callers
/// can label fixtures.
#[cfg(feature = "rpc")]
pub async fn fetch_recent_transactions(
    client: &SolanaRpcClient,
    start_slot: u64,
    count: usize,
    prefer: &[&str],
    max_slots_back: u64,
) -> Vec<serde_json::Value> {
    let mut out: Vec<serde_json::Value> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let lower = start_slot.saturating_sub(max_slots_back);
    'slots: for s in (lower..=start_slot).rev() {
        if out.len() >= count {
            break;
        }
        let Ok(block) = client.get_block(s).await else {
            continue; // empty/unknown slot — skip
        };
        let Some(txs) = block.get("transactions").and_then(|t| t.as_array()) else {
            continue;
        };
        for tx in txs {
            if out.len() >= count {
                break 'slots;
            }
            let sig = tx
                .get("transaction")
                .and_then(|t| t.get("signatures"))
                .and_then(|s| s.as_array())
                .and_then(|s| s.first())
                .and_then(|s| s.as_str())
                .unwrap_or("");
            if sig.is_empty() || !seen.insert(sig.to_string()) {
                continue;
            }
            if tx_to_input(tx, prefer).is_none() {
                continue;
            }
            let mut with_slot = tx.clone();
            if let serde_json::Value::Object(map) = &mut with_slot {
                map.insert("__slot".to_string(), serde_json::json!(s));
            }
            out.push(with_slot);
        }
    }
    out
}

/// Outcome of a live seeding run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveSeedStats {
    /// Transactions verified through the full pipeline.
    pub verified: usize,
    /// Verified transactions that the pipeline APPROVED.
    pub approved: usize,
    /// Fixtures appended to the corpus (approved + blocked, deduped).
    pub recorded: usize,
    /// Transactions skipped (verification error — never recorded).
    pub skipped: usize,
}

/// Fetch real transactions, run the FULL pipeline over each, and record the
/// outcomes as append-only regression fixtures.
///
/// `network_label` lands in the fixture `source` (e.g. `live-mainnet`), which
/// keeps the corpus provenance honest. Recorded fixtures use the pipeline's
/// own verdict as `expected_approved` — replay later re-checks that the
/// pipeline still agrees with what it said when it saw the real transaction.
#[cfg(feature = "rpc")]
pub async fn seed_corpus_from_live(
    client: &SolanaRpcClient,
    core: &GraphiteCore,
    corpus: &mut RegressionCorpus,
    count: usize,
    network_label: &str,
    prefer: &[&str],
) -> LiveSeedStats {
    let slot = match client.get_slot().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("live corpus: getSlot failed ({e}) — no fixtures recorded");
            return LiveSeedStats {
                verified: 0,
                approved: 0,
                recorded: 0,
                skipped: 0,
            };
        }
    };
    let txs = fetch_recent_transactions(client, slot, count, prefer, 300).await;
    let mut stats = LiveSeedStats {
        verified: 0,
        approved: 0,
        recorded: 0,
        skipped: 0,
    };
    for tx in &txs {
        let Some(input) = tx_to_input(tx, prefer) else {
            continue;
        };
        let slot = tx.get("__slot").and_then(|s| s.as_u64()).unwrap_or(slot);
        let signature = tx
            .get("transaction")
            .and_then(|t| t.get("signatures"))
            .and_then(|s| s.as_array())
            .and_then(|s| s.first())
            .and_then(|s| s.as_str())
            .unwrap_or("?");
        match core.verify_async(&input).await {
            Ok(result) => {
                stats.verified += 1;
                if result.approved {
                    stats.approved += 1;
                }
                let before = corpus.len();
                record_fixture(
                    corpus,
                    &input,
                    result.approved,
                    &format!("{network_label}:{slot}:{signature}"),
                );
                if corpus.len() > before {
                    stats.recorded += 1;
                }
            }
            Err(e) => {
                stats.skipped += 1;
                tracing::warn!(
                    "live corpus: verification failed for {signature} at slot {slot}: {e:?}"
                );
            }
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_fixture(name: &str) -> serde_json::Value {
        let path = format!("tests/fixtures/real_mainnet_{name}.json");
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    /// The pinned fixtures are REAL mainnet transactions (fetched live via
    /// getSignaturesForAddress + getTransaction on 2026-08-08) stored in the
    /// exact getBlock transaction-object shape the reader consumes.
    #[test]
    fn pinned_fixtures_are_real_mainnet_data() {
        for name in ["pump", "jup", "system"] {
            let v = load_fixture(name);
            let slot = v.get("slot").and_then(|s| s.as_u64()).unwrap_or(0);
            assert!(
                slot > 400_000_000,
                "{name}: slot {slot} not plausible mainnet"
            );
            let sig = v
                .get("transaction")
                .and_then(|t| t.get("signatures"))
                .and_then(|s| s.as_array())
                .and_then(|s| s.first())
                .and_then(|s| s.as_str())
                .unwrap_or("");
            // base58 of a 64-byte ed25519 signature is 87-88 chars; the real
            // invariant is that it DECODES to exactly 64 bytes.
            let decoded = crate::solana_types::base58_decode(sig)
                .unwrap_or_else(|| panic!("{name}: signature is not base58"));
            assert_eq!(decoded.len(), 64, "{name}: signature must be 64 bytes");
        }
    }

    #[test]
    fn tx_to_input_prefers_known_program_on_real_jupiter_swap() {
        let tx = load_fixture("jup");
        let jup = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
        let input = tx_to_input(&tx, &[jup]).expect("jup tx must parse");
        // ix7 of the real swap invokes Jupiter with 40 account keys; the
        // prefer-set must select it over the System fee payment (ix0).
        assert_eq!(
            input.program_id, jup,
            "prefer-set must win over the System fee instruction"
        );
        assert_eq!(
            input.account_addresses.len(),
            MAX_ACCOUNTS_PER_INSTRUCTION,
            "40 account keys must be capped at the reader bound"
        );
        assert!(input.compute_units > 0, "real tx must report compute usage");
    }

    #[test]
    fn tx_to_input_picks_meaty_call_over_fee_payment() {
        // This real pump.fun-market tx invokes pump only via CPI; its top
        // level is System fee + ComputeBudget + a 20-account router call. The
        // max-accounts fallback must pick the 20-account call, not the
        // 2-account fee payment.
        let tx = load_fixture("pump");
        let pump = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
        let input = tx_to_input(&tx, &[pump]).expect("pump tx must parse");
        assert_eq!(
            input.program_id, "QZerdCbKWCo79xfPhapNaAB7aZerGyPMXaJjK1VTAYQ",
            "max-accounts fallback must pick the meaty router call over the fee"
        );
        assert_eq!(input.account_addresses.len(), MAX_ACCOUNTS_PER_INSTRUCTION);
        assert!(input.compute_units > 0, "real tx must report compute usage");
    }

    #[test]
    fn tx_to_input_fallback_selects_most_accounted_instruction() {
        // With an empty prefer-set, the max-accounts fallback on the real
        // "system" fixture selects the 24-account pump AMM call (ix5) over
        // the 3-account System fee payment (ix0).
        let tx = load_fixture("system");
        let input = tx_to_input(&tx, &[]).expect("system tx must parse");
        assert_eq!(
            input.program_id, "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA",
            "max-accounts fallback must beat the System fee payment"
        );
        assert_eq!(input.account_addresses.len(), MAX_ACCOUNTS_PER_INSTRUCTION);
    }

    #[test]
    fn tx_to_input_never_panics_on_hostile_shapes() {
        // Malformed / adversarial JSON must yield None or a safe parse — never
        // panic (resource-exhaustion + robustness contract for the reader).
        let hostile = [
            "null",
            "{}",
            r#"{"transaction":{}}"#,
            r#"{"transaction":{"message":{}}}"#,
            r#"{"transaction":{"message":{"accountKeys":[],"instructions":[]}}}"#,
            r#"{"transaction":{"message":{"accountKeys":[123],"instructions":[{"programIdIndex":"x"}]}}}"#,
            r#"{"transaction":{"message":{"accountKeys":["abc"],"instructions":[{"programIdIndex":0,"accounts":[0],"data":"!!!"}]}}}"#,
            r#"{"transaction":{"message":{"accountKeys":["abc"],"instructions":[{"programIdIndex":0,"accounts":[],"data":null}]}}}"#,
        ];
        for json in hostile {
            let v: serde_json::Value =
                serde_json::from_str(json).unwrap_or(serde_json::Value::Null);
            let _ = tx_to_input(&v, &[]); // must not panic
        }
    }

    #[test]
    fn corpus_wallet_profile_is_the_phase1_honest_default() {
        match corpus_wallet_profile() {
            WalletProfile::Custom {
                min_confidence,
                min_trust_tier,
            } => {
                assert_eq!(min_confidence, 0.40);
                assert_eq!(
                    min_trust_tier,
                    crate::confidence_engine::TrustTier::OfficialManifest
                );
            }
            other => panic!("unexpected profile: {other:?}"),
        }
    }

    /// Full pipeline over a REAL mainnet transaction: structure invariants
    /// must hold (finite confidence in [0,1], 16-char content hash, and an
    /// approved result implies a Clear risk verdict).
    #[test]
    fn full_pipeline_over_real_mainnet_transactions() {
        let core = GraphiteCore::new();
        for name in ["pump", "jup", "system"] {
            let tx = load_fixture(name);
            let prefer: Vec<String> = core
                .list_manifests()
                .iter()
                .map(|m| m.protocol.program_id.clone())
                .collect();
            let prefer: Vec<&str> = prefer.iter().map(|s| s.as_str()).collect();
            let input = tx_to_input(&tx, &prefer)
                .unwrap_or_else(|| panic!("{name}: real tx must produce a VerificationInput"));
            let result = core
                .verify(&input)
                .unwrap_or_else(|e| panic!("{name}: real tx must verify: {e:?}"));
            assert!(
                (0.0..=1.0).contains(&result.confidence) && result.confidence.is_finite(),
                "{name}: out-of-range confidence"
            );
            assert_eq!(result.content_hash.len(), 16, "{name}: content hash shape");
            if result.approved {
                assert_eq!(
                    result.risk_verdict.status, "Clear",
                    "{name}: approved must imply Clear risk"
                );
            }
        }
    }

    /// v0 transactions carry Address Lookup Tables; the parser must expand the
    /// key space or every ALT-resolved account is silently dropped. The pinned
    /// mainnet fixtures are REAL v0 txs — this pins the expansion against them.
    #[test]
    fn alt_lookup_expansion_matches_real_fixtures() {
        let jup = load_fixture("jup");
        let msg = jup.get("transaction").unwrap().get("message").unwrap();
        let static_keys = msg.get("accountKeys").unwrap().as_array().unwrap().len();
        assert_eq!(static_keys, 14, "jup fixture static keys");

        let expanded = expand_account_keys(msg).unwrap();
        // 14 static + 1 lookup table; the fixture's lookup has 19 entries
        // (26 ALT-referencing instruction accounts imply a wide table).
        assert!(
            expanded.len() > static_keys,
            "ALT expansion must extend the key space ({} > {})",
            expanded.len(),
            static_keys
        );
        assert_eq!(
            expanded.len(),
            static_keys + 19,
            "jup fixture: 14 static + 19 ALT entries = 33 expanded keys"
        );
        // Expanded positions are placeholders that preserve index space.
        let alt_positions: Vec<&String> = expanded.iter().skip(static_keys).collect();
        assert!(alt_positions.iter().all(|k| k.starts_with("alt:0:")));

        // The System fixture also carries a lookup table (8 ALT references).
        let sys = load_fixture("system");
        let sys_msg = sys.get("transaction").unwrap().get("message").unwrap();
        let sys_expanded = expand_account_keys(sys_msg).unwrap();
        assert!(
            sys_expanded.len()
                > sys_msg
                    .get("accountKeys")
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .len(),
            "system fixture must also expand"
        );

        // The pump fixture has an EMPTY lookup table (the field is present
        // but carries no entries): expansion must be the identity.
        let pump = load_fixture("pump");
        let pump_msg = pump.get("transaction").unwrap().get("message").unwrap();
        let pump_entries = pump_msg
            .get("addressTableLookups")
            .and_then(|a| a.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);
        assert!(!pump_entries, "pump fixture has no ALT entries");
        assert_eq!(
            expand_account_keys(pump_msg).unwrap().len(),
            pump_msg
                .get("accountKeys")
                .unwrap()
                .as_array()
                .unwrap()
                .len()
        );

        // End-to-end: the jup fixture's chosen instruction now resolves its
        // account list positionally (no dropped ALT indices).
        let input = tx_to_input(&jup, &["JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"])
            .expect("jup fixture must parse");
        assert_eq!(
            input.program_id,
            "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
        );
    }
}
