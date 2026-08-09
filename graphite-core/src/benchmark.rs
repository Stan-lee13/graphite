//! Benchmark suite for Graphite Core.
//!
//! Runs Graphite against a set of labeled transactions (safe/malicious/unknown)
//! and reports precision, recall, false positives, false negatives, and latency.
//!
//! Per Constitution P16: this is what backs any public performance claim.
//! The numbers are real (measured, not assumed) and reproducible.

use crate::policy_engine::WalletProfile;
use crate::semantic_graph_store::BehaviorEvidence;
use crate::verification::{GraphiteCore, ProposedIntent, VerificationInput};
use std::time::Instant;

#[derive(Debug, Clone)]
struct BenchmarkCase {
    label: &'static str,
    category: &'static str, // "safe" | "malicious" | "unknown"
    expected_approved: bool,
    input: VerificationInput,
}

/// Regression Engine seed: the benchmark cases as (expected_approved, input)
/// pairs (P16: the benchmark is the reproducible evidence base).
///
/// The two simulation-baseline-dependent cases ("Simulation spoofing",
/// "Normal compute with baseline") are excluded — they require
/// operator-seeded RPC baselines and are recorded at runtime, never seedable.
/// All other cases replay deterministically on a fresh GraphiteCore.
pub(crate) fn benchmark_fixture_seed() -> Vec<(bool, VerificationInput)> {
    build_benchmark_cases()
        .into_iter()
        .filter(|c| {
            !c.label.contains("Simulation spoofing")
                && !c.label.contains("Normal compute with baseline")
        })
        .map(|c| (c.expected_approved, c.input))
        .collect()
}

pub fn run_benchmark() {
    println!("\n╔════════════════════════════════════════════════════════╗");
    println!("║         Graphite Phase 1 Benchmark Suite               ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    let cases = build_benchmark_cases();
    let core = GraphiteCore::new();

    // Baselines are trusted state (baseline trust model): seed the System
    // Program baseline used by the Phase 1.5 benchmark cases here, as an
    // operator would, instead of letting request bodies supply it.
    core.seed_simulation_baseline(
        "11111111111111111111111111111111",
        crate::simulation_integrity::ComputeBaseline {
            mean_compute_units: 150.0,
            std_compute_units: 20.0,
            sample_count: 100,
            mean_account_writes: 0.0,
            std_account_writes: 0.0,
            mean_cpi_hops: 0.0,
            std_cpi_hops: 0.0,
        },
    )
    .expect("benchmark baseline must be valid");

    let mut true_positives = 0; // malicious correctly blocked
    let mut true_negatives = 0; // safe correctly approved
    let mut false_positives = 0; // safe incorrectly blocked
    let mut false_negatives = 0; // malicious incorrectly approved
    let mut total_latency_us: u128 = 0;
    // Per-case latencies, kept for the p50/p95/p99 distribution.
    let mut latencies_us: Vec<u128> = Vec::with_capacity(cases.len());

    println!(
        "{:<40} {:<12} {:<12} {:<12} {:>10}",
        "Case", "Category", "Expected", "Got", "Latency"
    );
    println!("{}", "─".repeat(90));

    for case in &cases {
        let start = Instant::now();
        let result = core.verify(&case.input).unwrap_or_else(|_| {
            // Verification error = fail-closed (blocked)
            crate::verification::VerificationResult {
                approved: false,
                confidence: 0.0,
                breakdown: vec![],
                trust_tier: "Unknown".to_string(),
                risk_verdict: crate::verification::RiskVerdictSummary {
                    status: "Blocked".to_string(),
                    findings: vec![],
                },
                policy_verdict: "Rejected".to_string(),
                audit_trail_id: "gr-error".to_string(),
                content_hash: "error".to_string(),
                transaction: crate::transaction_builder::BuiltTransaction {
                    program_id: case.input.program_id.clone(),
                    protocol_version: case.input.protocol_version.clone(),
                    instruction_name: "Error".to_string(),
                    instruction_discriminator: case.input.instruction_discriminator.clone(),
                    instruction_count: 0,
                    account_count: case.input.account_addresses.len(),
                    signer_count: 0,
                    writable_count: 0,
                    compute_budget_units: 0,
                    accounts: vec![],
                    data_hex: String::new(),
                    data_len: 0,
                },
                resolved_accounts: vec![],
                protocol_name: "Error".to_string(),
                instruction_name: "Error".to_string(),
                manifest_found: false,
                unknown_protocol: true,
                manifest_version: None,
                summary: "BLOCKED | verification error".to_string(),
                simulation_flagged: None,
                simulation_divergence: None,
                layers: vec![],
            }
        });
        let elapsed = start.elapsed();
        total_latency_us += elapsed.as_micros();
        latencies_us.push(elapsed.as_micros());

        let actually_approved = result.approved;
        let correct = actually_approved == case.expected_approved;

        match (case.category, actually_approved, case.expected_approved) {
            ("safe", false, true) => false_positives += 1,
            ("safe", true, true) => true_negatives += 1,
            ("malicious", true, false) => false_negatives += 1,
            ("malicious", false, false) => true_positives += 1,
            ("unknown", _, _) => {}
            _ => {}
        }

        let mark = if correct { "✓" } else { "✗" };
        let verdict_str = if actually_approved {
            "Approved"
        } else {
            "Blocked"
        };

        println!(
            "{:<40} {:<12} {:<12} {:<12} {:>6}μs {}",
            case.label,
            case.category,
            if case.expected_approved {
                "Approved"
            } else {
                "Blocked"
            },
            verdict_str,
            elapsed.as_micros(),
            mark
        );
    }

    let total = cases.len();
    let scored = cases.iter().filter(|c| c.category != "unknown").count();
    let correct = true_positives + true_negatives;

    let precision = if (true_positives + false_positives) > 0 {
        true_positives as f64 / (true_positives + false_positives) as f64 * 100.0
    } else {
        0.0
    };

    let recall = if (true_positives + false_negatives) > 0 {
        true_positives as f64 / (true_positives + false_negatives) as f64 * 100.0
    } else {
        0.0
    };

    let accuracy = if scored > 0 {
        correct as f64 / scored as f64 * 100.0
    } else {
        0.0
    };

    let avg_latency = if total > 0 {
        total_latency_us / total as u128
    } else {
        0
    };

    // p50/p95/p99 from the per-case distribution (deterministic: same cases,
    // same order, same release binary ⇒ reproducible percentiles).
    latencies_us.sort_unstable();
    let percentile = |p: f64| -> u128 {
        if latencies_us.is_empty() {
            return 0;
        }
        let idx = ((latencies_us.len() as f64 - 1.0) * p).round() as usize;
        latencies_us[idx]
    };
    let p50 = percentile(0.50);
    let p95 = percentile(0.95);
    let p99 = percentile(0.99);

    println!("{}", "─".repeat(90));
    println!("\n📊 Results:\n");
    println!("  Total cases:      {}", total);
    println!("  Scored cases:     {} (safe + malicious only)", scored);
    println!("  Correct:          {}/{}", correct, scored);
    println!("  Accuracy:         {:.1}%", accuracy);
    println!(
        "  Precision:        {:.1}%  (of all blocked, how many were actually malicious)",
        precision
    );
    println!(
        "  Recall:           {:.1}%  (of all malicious, how many we caught)",
        recall
    );
    println!(
        "  True Positives:   {}  (malicious → blocked)",
        true_positives
    );
    println!("  True Negatives:   {}  (safe → approved)", true_negatives);
    println!("  False Positives:  {}  (safe → blocked)", false_positives);
    println!(
        "  False Negatives:  {}  (malicious → approved)",
        false_negatives
    );
    println!("  Avg Latency:      {}μs", avg_latency);
    println!("  p50 Latency:      {}μs", p50);
    println!("  p95 Latency:      {}μs", p95);
    println!("  p99 Latency:      {}μs", p99);
    println!(
        "  Sequential thru:  {:.0} verifies/s ({} cases, single-threaded)",
        if total > 0 {
            total as f64 / (total_latency_us as f64 / 1_000_000.0)
        } else {
            0.0
        },
        total
    );
    println!();

    // ─── Plugin overhead (P16: measured, reproducible) ───
    // The default core ships two first-party plugins (FakeRewardsDrainer L7
    // risk + verification event logger). Quantify the per-verify cost against
    // a pristine no-plugin core on the SAME safe input.
    let plugin_input = cases
        .iter()
        .find(|c| c.category == "safe")
        .map(|c| c.input.clone())
        .expect("benchmark suite must include a safe case");
    let plugin_core = GraphiteCore::new();
    let bare_core = GraphiteCore::new_without_plugins();
    const PLUGIN_ITERS: usize = 500;
    let t = Instant::now();
    for _ in 0..PLUGIN_ITERS {
        let _ = plugin_core.verify(&plugin_input);
    }
    let with_plugins_us = t.elapsed().as_micros() as f64 / PLUGIN_ITERS as f64;
    let t = Instant::now();
    for _ in 0..PLUGIN_ITERS {
        let _ = bare_core.verify(&plugin_input);
    }
    let without_plugins_us = t.elapsed().as_micros() as f64 / PLUGIN_ITERS as f64;
    // Raw signed delta — no clamping: measurement noise can make the
    // "with plugins" run faster, and the honest display shows that.
    let delta_us = with_plugins_us - without_plugins_us;
    let delta_pct = if without_plugins_us > 0.0 {
        delta_us / without_plugins_us * 100.0
    } else {
        0.0
    };
    println!(
        "  Plugin overhead:  {:.2}μs/verify with 2 plugins vs {:.2}μs/verify bare (Δ {:+.2}μs, {:+.1}%) — {} iterations, same input",
        with_plugins_us, without_plugins_us, delta_us, delta_pct, PLUGIN_ITERS
    );
    println!();

    // ─── Baseline Comparison (Constitution P16 requirement) ───
    // BENCHMARK.md requires a comparison row against at least one honest baseline.
    // "Simulation only" baseline: approve if compute_units > 0 (simulation "succeeded"),
    // block if compute_units == 0 (simulation "failed"). No verification logic at all.
    // This is the weakest possible defense — it catches nothing that simulation doesn't.
    let mut baseline_tp = 0; // malicious correctly blocked
    let mut baseline_tn = 0; // safe correctly approved
    let mut baseline_fp = 0; // safe incorrectly blocked
    let mut baseline_fn = 0; // malicious incorrectly approved
    let mut baseline_total_latency_us: u128 = 0;

    for case in &cases {
        let start = Instant::now();
        // Baseline: "simulation only" — approve if compute_units > 0, block otherwise
        let baseline_approved = case.input.compute_units > 0;
        let elapsed = start.elapsed();
        baseline_total_latency_us += elapsed.as_micros();

        match (case.category, baseline_approved, case.expected_approved) {
            ("safe", false, true) => baseline_fp += 1,
            ("safe", true, true) => baseline_tn += 1,
            ("malicious", true, false) => baseline_fn += 1,
            ("malicious", false, false) => baseline_tp += 1,
            ("unknown", _, _) => {}
            _ => {}
        }
    }

    let baseline_scored = cases.iter().filter(|c| c.category != "unknown").count();
    let baseline_correct = baseline_tp + baseline_tn;
    let baseline_precision = if (baseline_tp + baseline_fp) > 0 {
        baseline_tp as f64 / (baseline_tp + baseline_fp) as f64 * 100.0
    } else {
        0.0
    };
    let baseline_recall = if (baseline_tp + baseline_fn) > 0 {
        baseline_tp as f64 / (baseline_tp + baseline_fn) as f64 * 100.0
    } else {
        0.0
    };
    let baseline_avg_latency = if total > 0 {
        baseline_total_latency_us / total as u128
    } else {
        0
    };

    println!("┌────────────────────────────────────────────────────────────────┐");
    println!("│  Baseline Comparison (Constitution P16)                       │");
    println!("├──────────────────────┬───────────────┬──────────┬───────────────┤");
    println!("│ Tool                 │ Precision     │ Recall   │ Avg Latency  │");
    println!("├──────────────────────┼───────────────┼──────────┼──────────────┤");
    println!(
        "│ Simulation only      │ {:>8.1}%     │ {:>6.1}%  │ {:>6}μs       │",
        baseline_precision, baseline_recall, baseline_avg_latency
    );
    println!(
        "│ Graphite v0.1.0      │ {:>8.1}%     │ {:>6.1}%  │ {:>6}μs       │",
        precision, recall, avg_latency
    );
    println!("└──────────────────────┴───────────────┴──────────┴───────────────┘");
    println!();
    println!(
        "  Baseline: {} correct / {} scored (TP={}, TN={}, FP={}, FN={})",
        baseline_correct, baseline_scored, baseline_tp, baseline_tn, baseline_fp, baseline_fn
    );
    println!(
        "  Graphite: {} correct / {} scored (TP={}, TN={}, FP={}, FN={})",
        correct, scored, true_positives, true_negatives, false_positives, false_negatives
    );
    println!();
}

fn make_input(
    program: &str,
    disc: &str,
    accounts: &[&str],
    cpi_targets: &[&str],
    profile: WalletProfile,
    evidence: BehaviorEvidence,
) -> VerificationInput {
    make_input_with_intent(
        program,
        disc,
        accounts,
        cpi_targets,
        profile,
        evidence,
        "transfer",
    )
}

fn make_input_with_intent(
    program: &str,
    disc: &str,
    accounts: &[&str],
    cpi_targets: &[&str],
    profile: WalletProfile,
    evidence: BehaviorEvidence,
    intent_type: &str,
) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: intent_type.to_string(),
            raw_natural_language: "test".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: program.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: disc.to_string(),
        account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
        instruction_data: None,
        cpi_targets: cpi_targets.iter().map(|s| s.to_string()).collect(),
        wallet_profile: profile,
        behavior_evidence: evidence,
        compute_units: 150,
        account_writes: 2,
        cpi_hops: cpi_targets.len() as u32,
        signed_transaction: None,
    }
}

fn good_evidence() -> BehaviorEvidence {
    BehaviorEvidence {
        has_signed_manifest: false,
        community_verified_count: 5,
        battle_tested_tx_count: 50000,
        simulation_match_count: 100,
    }
}

fn no_evidence() -> BehaviorEvidence {
    BehaviorEvidence {
        has_signed_manifest: false,
        community_verified_count: 0,
        battle_tested_tx_count: 0,
        simulation_match_count: 0,
    }
}

fn build_benchmark_cases() -> Vec<BenchmarkCase> {
    vec![
        // SAFE cases (should be approved)
        BenchmarkCase {
            label: "System Transfer (legitimate)",
            category: "safe",
            expected_approved: true,
            input: make_input(
                "11111111111111111111111111111111",
                "02000000",
                &[
                    "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                    "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
                ],
                &[],
                WalletProfile::Custom {
                    min_confidence: 0.40,
                    min_trust_tier: crate::semantic_graph_store::TrustTier::OfficialManifest,
                },
                good_evidence(),
            ),
        },
        BenchmarkCase {
            label: "SPL Token Transfer (legitimate)",
            category: "safe",
            expected_approved: true,
            input: make_input(
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "03",
                &[
                    "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                    "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
                    "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
                ],
                &[],
                WalletProfile::Custom {
                    min_confidence: 0.40,
                    min_trust_tier: crate::semantic_graph_store::TrustTier::OfficialManifest,
                },
                good_evidence(),
            ),
        },
        BenchmarkCase {
            label: "SPL Token Burn (legitimate)",
            category: "safe",
            expected_approved: true,
            input: make_input(
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "08",
                &[
                    "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                    "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
                    "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
                ],
                &[],
                WalletProfile::Custom {
                    min_confidence: 0.40,
                    min_trust_tier: crate::semantic_graph_store::TrustTier::OfficialManifest,
                },
                good_evidence(),
            ),
        },
        // MALICIOUS cases (should be blocked)
        BenchmarkCase {
            label: "Unverified CPI (potential exploit)",
            category: "malicious",
            expected_approved: false,
            input: make_input(
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "03",
                &[
                    "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                    "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
                    "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
                ],
                &["unverified_malicious_program"],
                WalletProfile::Custom {
                    min_confidence: 0.40,
                    min_trust_tier: crate::semantic_graph_store::TrustTier::OfficialManifest,
                },
                good_evidence(),
            ),
        },
        BenchmarkCase {
            label: "Deep CPI chain (compositional drain)",
            category: "malicious",
            expected_approved: false,
            input: make_input(
                "11111111111111111111111111111111",
                "02000000",
                &[
                    "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                    "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
                ],
                &["prog_a", "prog_a", "prog_b", "prog_a", "prog_c"],
                WalletProfile::Custom {
                    min_confidence: 0.40,
                    min_trust_tier: crate::semantic_graph_store::TrustTier::OfficialManifest,
                },
                good_evidence(),
            ),
        },
        BenchmarkCase {
            label: "Authority hijack (SetAuthority)",
            category: "malicious",
            expected_approved: false,
            // REAL SetAuthority discriminator is 0x06 (the risk engine's
            // RISKY_PATTERNS entry). C26 clean-room correction: this case
            // previously used 0b (ThawAccount), which the suite blocked via
            // the transfer-intent semantic mismatch — not via any
            // SetAuthority-hijack detection. The label now matches the
            // instruction actually under test.
            input: make_input(
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "06",
                &[
                    "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                    "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
                ],
                &[],
                WalletProfile::Treasury,
                no_evidence(),
            ),
        },
        // CloseAccount drainer
        BenchmarkCase {
            label: "Account drain (CloseAccount)",
            category: "malicious",
            expected_approved: false,
            input: make_input(
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "09",
                &[
                    "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                    "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
                    "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
                ],
                &[],
                WalletProfile::Treasury,
                no_evidence(),
            ),
        },
        // UNKNOWN protocol cases (should NOT be approved — low confidence)
        BenchmarkCase {
            label: "Unknown protocol (no manifest)",
            category: "unknown",
            expected_approved: false,
            input: make_input(
                "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
                "03000000",
                &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"],
                &[],
                WalletProfile::TradingBot,
                no_evidence(),
            ),
        },
        BenchmarkCase {
            label: "Unknown protocol with no evidence",
            category: "unknown",
            expected_approved: false,
            input: make_input(
                "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx",
                "ff00ff",
                &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"],
                &[],
                WalletProfile::Treasury,
                no_evidence(),
            ),
        },
        // === Phase 1.5: FakeSwap Detection ===
        BenchmarkCase {
            label: "FakeSwap — swap intent on System Program (wrong program for swap)",
            category: "malicious",
            expected_approved: false,
            input: {
                let mut inp = make_input(
                    "11111111111111111111111111111111",
                    "02000000",
                    &[
                        "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                        "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
                    ],
                    &[],
                    WalletProfile::Custom {
                        min_confidence: 0.40,
                        min_trust_tier: crate::semantic_graph_store::TrustTier::OfficialManifest,
                    },
                    good_evidence(),
                );
                inp.proposed_intent.intent_type = "swap".to_string();
                inp.proposed_intent.raw_natural_language = "Swap 1 SOL for USDC".to_string();
                inp
            },
        },
        // === Phase 1.5: Simulation Spoofing Detection ===
        BenchmarkCase {
            label: "Simulation spoofing — 50000 compute vs 150 baseline",
            category: "malicious",
            expected_approved: false,
            input: {
                let mut inp = make_input(
                    "11111111111111111111111111111111",
                    "02000000",
                    &[
                        "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                        "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
                    ],
                    &[],
                    WalletProfile::Custom {
                        min_confidence: 0.40,
                        min_trust_tier: crate::semantic_graph_store::TrustTier::OfficialManifest,
                    },
                    good_evidence(),
                );
                inp.compute_units = 50000;
                inp
            },
        },
        BenchmarkCase {
            label: "Normal compute with baseline — not flagged",
            category: "safe",
            expected_approved: true,
            input: {
                let mut inp = make_input(
                    "11111111111111111111111111111111",
                    "02000000",
                    &[
                        "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                        "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
                    ],
                    &[],
                    WalletProfile::Custom {
                        min_confidence: 0.40,
                        min_trust_tier: crate::semantic_graph_store::TrustTier::OfficialManifest,
                    },
                    good_evidence(),
                );
                inp.compute_units = 160;
                inp
            },
        },
        // === Phase 1.5: SPL Token SetAuthority on wrong instruction ===
        BenchmarkCase {
            label: "SPL Token SetAuthority hijack",
            category: "malicious",
            expected_approved: false,
            // C26 clean-room correction: the real SetAuthority discriminator
            // is 0x06, not 0b (ThawAccount). With 0b the case was blocked by
            // the transfer-vs-ThawAccount L5 semantic mismatch, so the suite
            // never actually exercised SetAuthority-hijack detection.
            input: make_input(
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "06",
                &[
                    "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                    "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
                ],
                &[],
                WalletProfile::Custom {
                    min_confidence: 0.40,
                    min_trust_tier: crate::semantic_graph_store::TrustTier::OfficialManifest,
                },
                good_evidence(),
            ),
        },
        // === SYNTHETIC RECONSTRUCTION CASES (real program IDs, synthetic account data) ===
        // Based on security research: Mandiant/Google CLINKSINK, SlowMist AAT, Kudelski Wormhole
    // NOTE: Uses real program IDs but synthetic account addresses (not raw mainnet transaction data)
        BenchmarkCase {
            label: "SYNTHETIC: CLINKSINK-style STMT drainer (real program ID, synthetic accounts)",
            category: "malicious",
            expected_approved: false,
            input: make_input(
                "4PG6e97DLCn2PRN4ZMmTLg83jsetrDkvamr3JiXoiffa",
                "08",
                &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", "4PG6e97DLCn2PRN4ZMmTLg83jsetrDkvamr3JiXoiffa", "11111111111111111111111111111111", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", "ComputeBudget111111111111111111111111111111"],
                &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "11111111111111111111111111111111"],
                WalletProfile::TradingBot, no_evidence(),
            ),
        },
        BenchmarkCase {
            label: "SYNTHETIC: AAT-style drainer — Approve + assign (real program ID, synthetic accounts)",
            category: "malicious",
            expected_approved: false,
            input: make_input(
                "3W2y8TuU2rKf4qvrKZAbu8Tu9najg9Bvcwfsf28aW3rs",
                "0a",
                &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx", "3W2y8TuU2rKf4qvrKZAbu8Tu9najg9Bvcwfsf28aW3rs", "11111111111111111111111111111111", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"],
                &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "11111111111111111111111111111111"],
                WalletProfile::TradingBot, no_evidence(),
            ),
        },
        BenchmarkCase {
            label: "SYNTHETIC: Wormhole-style exploit (real program ID, synthetic accounts)",
            category: "malicious",
            expected_approved: false,
            input: make_input(
                "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth",
                "01",
                &["worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth", "11111111111111111111111111111111", "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", "ComputeBudget111111111111111111111111111111"],
                &["11111111111111111111111111111111"],
                WalletProfile::TradingBot, no_evidence(),
            ),
        },
        BenchmarkCase {
            label: "SYNTHETIC: AAT-style mass drain (real program ID, synthetic accounts)",
            category: "malicious",
            expected_approved: false,
            input: make_input(
                "3W2y8TuU2rKf4qvrKZAbu8Tu9najg9Bvcwfsf28aW3rs",
                "0a",
                &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx", "3W2y8TuU2rKf4qvrKZAbu8Tu9najg9Bvcwfsf28aW3rs", "11111111111111111111111111111111", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"],
                &["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "11111111111111111111111111111111"],
                WalletProfile::TradingBot, no_evidence(),
            ),
        },
        BenchmarkCase {
            label: "SYNTHETIC: CLINKSINK-style token drain (real program ID, synthetic accounts)",
            category: "malicious",
            expected_approved: false,
            input: make_input(
                "4PG6e97DLCn2PRN4ZMmTLg83jsetrDkvamr3JiXoiffa",
                "08",
                &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", "4PG6e97DLCn2PRN4ZMmTLg83jsetrDkvamr3JiXoiffa", "11111111111111111111111111111111", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "ComputeBudget111111111111111111111111111111"],
                &["TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "11111111111111111111111111111111"],
                WalletProfile::TradingBot, no_evidence(),
            ),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The benchmark is DELIBERATELY synthetic (P16 reproducibility): every
    /// case is a hand-constructed VerificationInput with a manually-encoded
    /// expected label. This test pins that composition explicitly so nobody
    /// can claim the benchmark is real-data without changing it. Real on-chain
    /// validation lives elsewhere: tests/live_transactions.rs (live devnet)
    /// and live_corpus's pinned REAL mainnet fixtures.
    #[test]
    fn benchmark_composition_is_explicit_and_synthetic() {
        let cases = build_benchmark_cases();
        assert_eq!(cases.len(), 18, "case count must be pinned");

        let safe = cases.iter().filter(|c| c.category == "safe").count();
        let malicious = cases.iter().filter(|c| c.category == "malicious").count();
        let unknown = cases.iter().filter(|c| c.category == "unknown").count();
        assert_eq!(safe + malicious, 16, "16 scored cases");
        assert_eq!(unknown, 2);

        // No case is a real on-chain transaction; three are explicitly
        // labeled SYNTHETIC (real program IDs, synthetic account lists).
        let real = cases.iter().filter(|c| c.label.starts_with("REAL")).count();
        assert_eq!(real, 0, "benchmark must not claim real-data cases");
        let synthetic = cases
            .iter()
            .filter(|c| c.label.starts_with("SYNTHETIC"))
            .count();
        assert!(
            synthetic >= 3,
            "explicitly-synthetic drainer cases: {synthetic}"
        );

        // Attack-class diversity by label keyword (each class is a distinct
        // detection pattern, not the same case repeated).
        for kw in ["CPI", "drain", "hijack", "FakeSwap", "spoofing"] {
            assert!(
                cases.iter().any(|c| c.label.contains(kw)),
                "missing attack class '{kw}'"
            );
        }
        assert!(malicious >= 10, "malicious-case diversity: {malicious}");
        println!(
            "benchmark composition: {safe} safe / {malicious} malicious / {unknown} unknown — ALL synthetic by design (P16)"
        );
    }

    /// Manual scaling probe (run: cargo test --release --lib soak -- --ignored
    /// --nocapture). Measures wall time for N sequential verifies to detect
    /// O(n^2) behavior or unbounded growth empirically.
    #[test]
    #[ignore]
    fn soak_sequential_verifies_report_scale() {
        use crate::verification::GraphiteCore;
        let core = GraphiteCore::new();
        let input = make_input(
            "11111111111111111111111111111111",
            "02000000",
            &[
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
            ],
            &[],
            WalletProfile::TradingBot,
            no_evidence(),
        );
        let n = 5_000;
        let start = std::time::Instant::now();
        for _ in 0..n {
            let r = core.verify(&input).expect("verify must succeed");
            assert!(r.confidence.is_finite() && (0.0..=1.0).contains(&r.confidence));
        }
        let elapsed = start.elapsed();
        let per = elapsed.as_micros() as f64 / n as f64;
        println!(
            "soak: {n} sequential verifies in {}ms → {per:.1}μs/verify (in-process, no RPC)",
            elapsed.as_millis()
        );
    }
}
