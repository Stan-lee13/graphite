//! Graphite against real, unseen mainnet traffic.
//!
//! Every other test in this repository is either handcrafted or replayed from
//! a pinned fixture, which means every one of them was written by somebody who
//! already knew what the engine does. This one is not: it takes whole finalized
//! mainnet blocks, as they came off the chain, and pushes every transaction in
//! them through the full pipeline in ARTIFACT-BOUND mode — the real serialized
//! bytes, the real instruction data, the real accounts, every sibling declared.
//!
//! It exists because Round 13 made L2 stricter. A check that refuses a request
//! whose declared discriminator contradicts its own `instruction_data` can only
//! be judged against traffic nobody curated: the question is not whether it
//! catches the attack (`tests/mislabelled_discriminator.rs` answers that) but
//! whether it refuses honest transactions, and the only honest corpus large and
//! varied enough to answer is the chain itself.
//!
//! The invariants it asserts:
//!
//!   1. **No honest mainnet transaction is refused for a discriminator
//!      contradiction.** The discriminator here is derived from the
//!      instruction's own leading bytes, exactly as `AuditBind` and the Go SDK
//!      derive it, so a contradiction would be the check firing on a request
//!      that does not contradict itself. Any hit is a false positive and fails
//!      the test.
//!   2. **Every risk block names something that is really there.** A block for
//!      `AuthorityHijack`, `Drainer` or `PermissionEscalation` is checked
//!      against the instruction's actual first bytes. A block on an instruction
//!      whose bytes are not one of the risky discriminators would mean the
//!      regrounded discriminator is over-matching.
//!   3. **The parser is not the bottleneck.** A frame the chain accepted and
//!      executed is a frame Graphite must be able to read, so parse failures
//!      are reported by class and a rate above a floor fails the test.
//!
//! The sample is fetched separately and passed in, so the same bytes can be run
//! against two builds of the engine and the verdicts diffed — which is how the
//! Round 13 change was measured rather than asserted.
//!
//! ```bash
//! python fetch_mainnet.py                 # writes mainnet_sample.json
//! GRAPHITE_MAINNET_SAMPLE=/path/to/mainnet_sample.json \
//!   cargo test --test mainnet_conformance -- --ignored --nocapture
//! ```
//!
//! Read-only throughout: the fetcher reads finalized blocks and nothing here
//! touches a wallet, a key, a fund or a live protocol.

use base64::Engine as _;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationResult,
};
use std::collections::BTreeMap;

/// Programs that are in nearly every real transaction and are never what the
/// transaction is for. Selecting one of these as the instruction to verify
/// would make the probe a study of fee payments.
const BOILERPLATE: &[&str] = &[
    "11111111111111111111111111111111",
    "ComputeBudget111111111111111111111111111111",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
    "Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH",
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",
];

/// Whether this block came from Check 2 — the known-risky DISCRIMINATOR
/// table — rather than from one of the structural heuristics that share its
/// `RiskPattern`.
///
/// `Drainer` in particular has three sources: the table (`CloseAccount`),
/// Check 3's account-to-change ratio, and Check 3b's account-count mismatch.
/// Only the first is keyed on the discriminator, so only the first says
/// anything about the Round 13 regrounding. Matched on the table's own
/// descriptions, which are the reason strings it emits.
fn is_discriminator_table_block(reason: &str) -> bool {
    [
        "SetAuthority — changes who controls the account",
        "CloseAccount — closes account and drains all lamports",
        "System Assign — reassigns account ownership",
        "Approve - grants delegate authority",
    ]
    .iter()
    .any(|d| reason.contains(d))
}

/// Which heuristic a block came from, collapsed for the histogram.
fn risk_source(reason: &str) -> &'static str {
    if is_discriminator_table_block(reason) {
        "Check 2 known-risky discriminator table"
    } else if reason.contains("high account-to-change ratio") {
        "Check 3 drainer heuristic (accounts vs declared changes)"
    } else if reason.contains("STMT drainer") {
        "Check 3b account-count mismatch"
    } else if reason.contains("empty discriminator on known risky program") {
        "Check 2 fail-closed empty discriminator"
    } else if reason.contains("identity mismatch") || reason.contains("manifest-declared identity")
    {
        "account identity / privilege mismatch"
    } else if reason.contains("CPI") {
        "CPI checks"
    } else if reason.contains("secondary instruction") {
        "secondary instruction"
    } else {
        "other"
    }
}

/// The program a block segment attributes itself to, when it attributes
/// itself to a secondary instruction rather than the primary.
///
/// Deliberately the PROGRAM and not the index. The index in the message is
/// `#n` into the engine's own effective-instruction list — primary, then the
/// flattened CPI trace, then the declared siblings — which is not the
/// message's instruction numbering, and reading it as though it were
/// attributes a `CloseAccount` to whichever instruction happens to sit at
/// that position in the bytes. The program name is unambiguous, and the
/// question being asked ("are those bytes really in this transaction?") does
/// not need the position.
///
/// Real routers are why this matters: a pump.fun or Jupiter route closes the
/// temporary wrapped-SOL account it opened, and that `CloseAccount` is a
/// sibling of the swap, not the swap.
fn secondary_program(segment: &str) -> Option<&str> {
    let at = segment.find("secondary instruction #")?;
    let rest = &segment[at..];
    let open = rest.find("(program ")? + "(program ".len();
    let close = rest[open..].find(')')?;
    Some(&rest[open..open + close])
}

/// The discriminators the Risk Engine's table blocks on, by program, so a
/// block can be checked against the bytes rather than taken on trust.
fn risky_prefix(program: &str, data: &[u8]) -> bool {
    let token = matches!(
        program,
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
            | "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
    );
    match data.first() {
        Some(0x06) | Some(0x09) | Some(0x04) if token => true,
        _ => {
            program == "11111111111111111111111111111111"
                && data.len() >= 4
                && data[..4] == [0x01, 0x00, 0x00, 0x00]
        }
    }
}

#[derive(Default)]
struct Tally {
    rows: usize,
    /// Version-1 rows, verified like every other row since Round 19.
    v1_rows: usize,
    parse_failed: BTreeMap<String, usize>,
    unresolvable_accounts: usize,
    no_usable_instruction: usize,
    verified: usize,
    verify_error: BTreeMap<String, usize>,
    l2_passed: usize,
    l2_failed: BTreeMap<String, usize>,
    /// The Round 13 false-positive counter. Must stay at zero.
    l2_discriminator_contradiction: usize,
    risk_clear: usize,
    risk_blocked: BTreeMap<String, usize>,
    /// A Check 2 block whose instruction bytes are NOT one of the risky
    /// discriminators — an over-match by the regrounded discriminator.
    risk_blocked_without_risky_bytes: Vec<String>,
    /// Where the blocks came from, which is the number that says whether the
    /// gate is discriminating or just refusing what it does not recognise.
    risk_source: BTreeMap<String, usize>,
    /// Transactions whose primary program has no manifest at all.
    unmanifested: usize,
    /// Check 2 blocks where the risky instruction IS the one being verified.
    table_block_on_primary: usize,
    /// Check 2 blocks where it is a sibling — overwhelmingly a router closing
    /// the temporary wrapped-SOL account it opened earlier in the same
    /// transaction.
    table_block_on_sibling: usize,
    approved: usize,
    artifact_bound: usize,
    programs: BTreeMap<String, usize>,
}

/// Which L2 failure this is, collapsed to a stable label so a histogram is
/// readable. The first arm is the one Round 13 introduced.
fn l2_class(reason: &str) -> &'static str {
    if reason.contains("describe different instructions") {
        "discriminator contradicts its own data (ROUND 13 — FALSE POSITIVE)"
    } else if reason.contains("cannot begin with a discriminator longer than itself") {
        "declaration longer than the data (ROUND 13 — FALSE POSITIVE)"
    } else if reason.contains("do not single out one of them") {
        "described instruction indistinguishable from an identical copy"
    } else if reason.contains("no instruction matching what is being verified") {
        "described instruction not located in the artifact"
    } else if reason.contains("does not describe") || reason.contains("describe none of") {
        "sibling coverage incomplete"
    } else if reason.contains("address lookup tables that were not resolved") {
        // This harness attaches no RPC, so the Core cannot fetch a v0
        // transaction's tables, and an unidentified account position fails
        // L2 (Round 17, F-15-05). Correct, and a property of the harness.
        "lookup tables unresolved (no RPC in this harness)"
    } else if reason.contains("DURABLE-NONCE") {
        "durable nonce refused"
    } else if reason.contains("could not be parsed") {
        "artifact unparseable"
    } else if reason.contains("but ") && reason.contains("account") {
        "instruction account mismatch"
    } else {
        "other"
    }
}

fn sample() -> Option<serde_json::Value> {
    let path = std::env::var("GRAPHITE_MAINNET_SAMPLE").ok()?;
    let raw = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// One transaction's verdict, for the differential.
struct Row {
    slot: u64,
    program: String,
    disc: String,
    l2: String,
    risk: String,
    approved: bool,
    /// Why the risk engine blocked, in its own words. Not part of the
    /// six-column verdict diff (that format is what Round 13 was measured
    /// with and stays stable); written separately by
    /// `GRAPHITE_MAINNET_REASONS`, because "917 identity mismatches" is a
    /// number you cannot act on until you can see which slot in which
    /// instruction did not match, and why.
    reason: String,
}

#[test]
#[ignore = "network sample — fetch with fetch_mainnet.py, then set GRAPHITE_MAINNET_SAMPLE"]
fn real_mainnet_traffic_is_not_refused_for_contradicting_itself() {
    let Some(doc) = sample() else {
        eprintln!(
            "[mainnet] no sample: set GRAPHITE_MAINNET_SAMPLE to the JSON written by \
             fetch_mainnet.py. Skipping rather than passing vacuously."
        );
        return;
    };
    let rows = doc["rows"].as_array().expect("rows array");
    let core = GraphiteCore::new();
    let registry = graphite_core::manifest::load_seed_manifests();
    let mut t = Tally::default();
    let mut verdicts: Vec<Row> = Vec::new();

    for row in rows {
        t.rows += 1;
        let slot = row["slot"].as_u64().unwrap_or(0);
        if row["version"].as_str() == Some("1") {
            // Parsed and verified since Round 19; counted so the report says
            // how much of the sample the format is.
            t.v1_rows += 1;
        }
        let Ok(bytes) = base64::engine::general_purpose::STANDARD
            .decode(row["b64"].as_str().unwrap_or_default())
        else {
            *t.parse_failed.entry("base64".to_string()).or_default() += 1;
            continue;
        };

        let message = match graphite_core::tx_artifact::parse_transaction(&bytes) {
            Ok(m) => m,
            Err(e) => {
                let label = format!("{e}");
                // Collapse the variable part so the histogram is readable.
                let label = label
                    .split(&[':', '('][..])
                    .next()
                    .unwrap_or("?")
                    .trim()
                    .to_string();
                *t.parse_failed.entry(label).or_default() += 1;
                continue;
            }
        };

        // The chain's own account ordering: static keys, then the lookup
        // table's writable entries, then its read-only ones. `loadedAddresses`
        // is the block's record of what those tables resolved to, which is
        // ground truth from the same source as the bytes.
        let mut keys: Vec<String> = message.static_keys.clone();
        for field in ["loaded_writable", "loaded_readonly"] {
            if let Some(list) = row[field].as_array() {
                keys.extend(list.iter().filter_map(|k| k.as_str().map(str::to_string)));
            }
        }
        let resolve =
            |ix: &graphite_core::tx_artifact::ArtifactInstruction| -> Option<Vec<String>> {
                ix.account_indexes
                    .iter()
                    .map(|i| keys.get(*i as usize).cloned())
                    .collect()
            };

        let resolved: Vec<Option<Vec<String>>> = message.instructions.iter().map(resolve).collect();
        if resolved.iter().any(|r| r.is_none()) {
            t.unresolvable_accounts += 1;
            continue;
        }
        let resolved: Vec<Vec<String>> = resolved.into_iter().map(|r| r.unwrap()).collect();

        // The instruction the transaction is actually for: the most-accounted
        // one that is not infrastructure, falling back to the most-accounted.
        let pick = message
            .instructions
            .iter()
            .enumerate()
            .filter(|(i, ix)| {
                !BOILERPLATE.contains(&ix.program_id.as_str()) && !resolved[*i].is_empty()
            })
            .max_by_key(|(i, _)| resolved[*i].len())
            .or_else(|| {
                message
                    .instructions
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| !resolved[*i].is_empty())
                    .max_by_key(|(i, _)| resolved[*i].len())
            });
        let Some((idx, ix)) = pick else {
            t.no_usable_instruction += 1;
            continue;
        };
        if ix.data.is_empty() {
            t.no_usable_instruction += 1;
            continue;
        }

        // Exactly what an honest SDK sends: the discriminator read off the
        // instruction's own leading bytes (`AuditBind.projectionFromInstruction`
        // and the Go `ProjectionFromInstruction` both do this).
        let disc = hex::encode(&ix.data[..ix.data.len().min(8)]);

        let siblings: Vec<graphite_core::tx_pattern_analysis::TransactionInstruction> = message
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
        let intent = graphite_core::live_corpus::classify_intent(&ix.program_id, &ix_name);

        let input = VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: intent,
                raw_natural_language: format!("mainnet slot {slot}"),
                confidence_of_parse: 0.5,
                extracted_parameters: None,
            },
            program_id: ix.program_id.clone(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: disc.clone(),
            account_addresses: resolved[idx].clone(),
            instruction_data: Some(ix.data.clone()),
            cpi_targets: vec![],
            // The weakest built-in profile, so the probe sees the full range of
            // outcomes rather than everything rejected on a threshold.
            wallet_profile: WalletProfile::Gaming,
            behavior_evidence: Default::default(),
            compute_units: row["cu"].as_u64().unwrap_or(0),
            account_writes: 0,
            cpi_hops: 0,
            // The chain's bytes carry real signatures; Graphite is shown the
            // frame BEFORE signing (Round 17 refuses filled slots), so replay
            // the sample the way the bridge would have presented it.
            signed_transaction: Some(
                graphite_core::tx_artifact::unsigned_artifact(&bytes).unwrap_or(bytes.clone()),
            ),
            transaction_instructions: siblings,
            cpi_trace: None,
            uses_versioned_transaction: message.version.is_some(),
            lookup_table_count: message.lookups.len() as u32,
            real_account_metas: vec![],
            state_diff: None,
        };

        let result: VerificationResult = match core.verify(&input) {
            Ok(r) => r,
            Err(e) => {
                let label = format!("{e}");
                let label = label.split(':').next().unwrap_or("?").trim().to_string();
                *t.verify_error.entry(label).or_default() += 1;
                continue;
            }
        };
        t.verified += 1;
        if !result.manifest_found {
            t.unmanifested += 1;
        }
        *t.programs.entry(ix.program_id.clone()).or_default() += 1;
        if format!("{:?}", result.scope).contains("ArtifactBound") {
            t.artifact_bound += 1;
        }
        if result.approved {
            t.approved += 1;
        }

        let l2 = result
            .layers
            .iter()
            .find(|l| l.layer.contains("L2"))
            .expect("L2 present");
        let l2_label = if l2.status == LayerStatus::Failed {
            let class = l2_class(&l2.reason);
            *t.l2_failed.entry(class.to_string()).or_default() += 1;
            let unexplained = matches!(
                class,
                "other"
                    | "described instruction not located in the artifact"
                    | "described instruction indistinguishable from an identical copy"
                    | "sibling coverage incomplete"
            );
            if unexplained
                && std::env::var("GRAPHITE_MAINNET_SHOW_L2").is_ok()
                && t.l2_failed.get(class).copied().unwrap_or(0) <= 6
            {
                // An unclassified L2 refusal of traffic the chain executed is
                // worth reading, not only counting.
                eprintln!(
                    "[L2 {class}] slot {slot} program {} disc {disc}
  {}",
                    ix.program_id, l2.reason
                );
            }
            if class.contains("ROUND 13") {
                t.l2_discriminator_contradiction += 1;
                eprintln!(
                    "[FALSE POSITIVE] slot {slot} program {} disc {disc}\n  {}",
                    ix.program_id, l2.reason
                );
            }
            class.to_string()
        } else {
            t.l2_passed += 1;
            "passed".to_string()
        };

        let risk_label = if result.risk_verdict.status == "Clear" {
            t.risk_clear += 1;
            "Clear".to_string()
        } else {
            let patterns: Vec<String> = result
                .risk_verdict
                .findings
                .iter()
                .map(|f| f.pattern.clone())
                .collect();
            for f in &result.risk_verdict.findings {
                *t.risk_blocked.entry(f.pattern.clone()).or_default() += 1;
                *t.risk_source
                    .entry(risk_source(&f.reason).to_string())
                    .or_default() += 1;
                // The Round 13 question, asked only of the check Round 13
                // touched: when the discriminator table fires, are the bytes
                // it fired on really one of the risky discriminators?
                // A blocked verdict carries every reason that fired, joined
                // with " | ", and they can name different instructions. Each
                // segment is checked against the instruction IT names —
                // taking the first index in the whole string attributes a
                // CloseAccount at #4 to whatever was reported at #1.
                for segment in f.reason.split(" | ") {
                    if !is_discriminator_table_block(segment) {
                        continue;
                    }
                    match secondary_program(segment) {
                        // A sibling was named: the transaction must really
                        // contain an instruction under that program whose own
                        // leading bytes are one of the table's discriminators.
                        Some(prog) => {
                            let present = message.instructions.iter().any(|s| {
                                s.program_id == prog && risky_prefix(&s.program_id, &s.data)
                            });
                            if present {
                                t.table_block_on_sibling += 1;
                            } else {
                                t.risk_blocked_without_risky_bytes.push(format!(
                                    "slot {slot} no instruction under {prog} carries a risky                                      discriminator, yet :: {segment}"
                                ));
                            }
                        }
                        // The primary was named: check the bytes being verified.
                        None => {
                            if risky_prefix(&ix.program_id, &ix.data) {
                                t.table_block_on_primary += 1;
                            } else {
                                t.risk_blocked_without_risky_bytes.push(format!(
                                    "slot {slot} primary {} bytes {disc} :: {segment}",
                                    ix.program_id
                                ));
                            }
                        }
                    }
                }
            }
            patterns.join("+")
        };

        verdicts.push(Row {
            slot,
            program: ix.program_id.clone(),
            disc,
            l2: l2_label,
            risk: risk_label,
            approved: result.approved,
            reason: result
                .risk_verdict
                .findings
                .iter()
                .map(|f| f.reason.clone())
                .collect::<Vec<_>>()
                .join(" ;; "),
        });
    }

    // ── The report ──────────────────────────────────────────────────────────
    println!("\n=== Graphite against unseen mainnet traffic ===");
    println!("transactions in sample        {}", t.rows);
    println!("  of which version 1          {:>6}", t.v1_rows);
    println!(
        "  parse failed               {:>6}  {:?}",
        t.parse_failed.values().sum::<usize>(),
        t.parse_failed
    );
    println!(
        "  account index out of the block's own key list {}",
        t.unresolvable_accounts
    );
    println!(
        "  no usable instruction      {:>6}",
        t.no_usable_instruction
    );
    println!(
        "  verify returned Err        {:>6}  {:?}",
        t.verify_error.values().sum::<usize>(),
        t.verify_error
    );
    println!("  VERIFIED                   {:>6}", t.verified);
    println!("    artifact-bound scope     {:>6}", t.artifact_bound);
    println!("    L2 passed                {:>6}", t.l2_passed);
    for (k, v) in &t.l2_failed {
        println!("    L2 failed: {k:<58} {v:>6}");
    }
    println!("    risk Clear               {:>6}", t.risk_clear);
    for (k, v) in &t.risk_blocked {
        println!("    risk Blocked [{k:<30}] {v:>6}");
    }
    println!("    ...by which check:");
    for (k, v) in &t.risk_source {
        println!("      {k:<56} {v:>6}");
    }
    println!(
        "      of which the risky instruction is the primary {:>6}, a sibling {:>6}",
        t.table_block_on_primary, t.table_block_on_sibling
    );
    println!(
        "    primary program has no manifest {:>6}  ({:.1}% of verified)",
        t.unmanifested,
        100.0 * t.unmanifested as f64 / t.verified.max(1) as f64
    );
    println!("    approved                 {:>6}", t.approved);
    let mut top: Vec<(&String, &usize)> = t.programs.iter().collect();
    top.sort_by(|a, b| b.1.cmp(a.1));
    println!("  programs seen: {} distinct; top:", t.programs.len());
    for (p, n) in top.iter().take(12) {
        println!("    {n:>6}  {p}");
    }

    if let Ok(path) = std::env::var("GRAPHITE_MAINNET_REASONS") {
        let (nl, tab) = (char::from(10u8), char::from(9u8));
        let mut out = String::new();
        for r in verdicts.iter().filter(|r| !r.reason.is_empty()) {
            let reason = r.reason.replace([nl, tab], " ");
            out.push_str(&format!(
                "{}{tab}{}{tab}{}{tab}{}{nl}",
                r.slot, r.program, r.disc, reason
            ));
        }
        let _ = std::fs::write(path, out);
    }

    // Machine-readable, for the old-vs-new differential.
    if let Ok(path) = std::env::var("GRAPHITE_MAINNET_VERDICTS") {
        let mut out = String::new();
        for r in &verdicts {
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\t{}\n",
                r.slot, r.program, r.disc, r.l2, r.risk, r.approved
            ));
        }
        let _ = std::fs::write(path, out);
    }

    // ── The invariants ──────────────────────────────────────────────────────
    assert!(
        t.verified > 500,
        "only {} transactions reached a verdict — the probe is not measuring enough real \
         traffic for its conclusions to mean anything",
        t.verified
    );
    assert_eq!(
        t.l2_discriminator_contradiction, 0,
        "Round 13's contradiction check fired on {} honest mainnet transaction(s). The \
         discriminator here is derived from the instruction's own bytes, so a contradiction \
         is the check refusing a request that does not contradict itself",
        t.l2_discriminator_contradiction
    );
    assert!(
        t.risk_blocked_without_risky_bytes.is_empty(),
        "the known-risky DISCRIMINATOR table fired on instruction(s) whose bytes are not one \
         of its discriminators — the regrounded discriminator is over-matching: {:?}",
        &t.risk_blocked_without_risky_bytes[..t.risk_blocked_without_risky_bytes.len().min(10)]
    );
    let parse_attempts = t.rows;
    let parse_failures: usize = t.parse_failed.values().sum();
    assert!(
        parse_failures * 100 < parse_attempts,
        "the parser refused {parse_failures} of {parse_attempts} frames the chain accepted and \
         executed (>1%) — a frame that ran on mainnet is one Graphite has to be able to read: \
         {:?}",
        t.parse_failed
    );
}
