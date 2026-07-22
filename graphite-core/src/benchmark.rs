//! Benchmark suite for Graphite Core.
//!
//! Runs Graphite against a set of labeled transactions (safe/malicious/unknown)
//! and reports precision, recall, false positives, false negatives, and latency.
//!
//! Per Constitution P16: this is what backs any public performance claim.
//! The numbers are real (measured, not assumed) and reproducible.

use crate::verification::{GraphiteCore, VerificationInput, ProposedIntent};
use crate::policy_engine::WalletProfile;
use crate::semantic_graph_store::BehaviorEvidence;
use std::time::Instant;

#[derive(Debug, Clone)]
struct BenchmarkCase {
    label: &'static str,
    category: &'static str, // "safe" | "malicious" | "unknown"
    expected_approved: bool,
    input: VerificationInput,
}

pub fn run_benchmark() {
    println!("\n╔════════════════════════════════════════════════════════╗");
    println!("║         Graphite Phase 1 Benchmark Suite               ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    let cases = build_benchmark_cases();
    let core = GraphiteCore::new();

    let mut true_positives = 0;  // malicious correctly blocked
    let mut true_negatives = 0;  // safe correctly approved
    let mut false_positives = 0; // safe incorrectly blocked
    let mut false_negatives = 0; // malicious incorrectly approved
    let mut total_latency_us: u128 = 0;

    println!("{:<40} {:<12} {:<12} {:<12} {:>10}", "Case", "Category", "Expected", "Got", "Latency");
    println!("{}", "─".repeat(90));

    for case in &cases {
        let start = Instant::now();
        let result = core.verify(&case.input).expect("verification should not error");
        let elapsed = start.elapsed();
        total_latency_us += elapsed.as_micros();

        let actually_approved = result.approved;
        let correct = actually_approved == case.expected_approved;

        match (case.category, actually_approved, case.expected_approved) {
            ("safe", false, true) => false_positives += 1,
            ("safe", true, true) => true_negatives += 1,
            ("malicious", true, false) => false_negatives += 1,
            ("malicious", false, false) => true_positives += 1,
            ("unknown", _, _) => {},
            _ => {},
        }

        let mark = if correct { "✓" } else { "✗" };
        let verdict_str = if actually_approved { "Approved" } else { "Blocked" };

        println!("{:<40} {:<12} {:<12} {:<12} {:>6}μs {}",
            case.label,
            case.category,
            if case.expected_approved { "Approved" } else { "Blocked" },
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
    } else { 0.0 };

    let recall = if (true_positives + false_negatives) > 0 {
        true_positives as f64 / (true_positives + false_negatives) as f64 * 100.0
    } else { 0.0 };

    let accuracy = if scored > 0 {
        correct as f64 / scored as f64 * 100.0
    } else { 0.0 };

    let avg_latency = if total > 0 { total_latency_us / total as u128 } else { 0 };

    println!("{}", "─".repeat(90));
    println!("\n📊 Results:\n");
    println!("  Total cases:      {}", total);
    println!("  Scored cases:     {} (safe + malicious only)", scored);
    println!("  Correct:          {}/{}", correct, scored);
    println!("  Accuracy:         {:.1}%", accuracy);
    println!("  Precision:        {:.1}%  (of all blocked, how many were actually malicious)", precision);
    println!("  Recall:           {:.1}%  (of all malicious, how many we caught)", recall);
    println!("  True Positives:   {}  (malicious → blocked)", true_positives);
    println!("  True Negatives:   {}  (safe → approved)", true_negatives);
    println!("  False Positives:  {}  (safe → blocked)", false_positives);
    println!("  False Negatives:  {}  (malicious → approved)", false_negatives);
    println!("  Avg Latency:      {}μs", avg_latency);
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
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
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
                &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
                &[],
                WalletProfile::Standard,
                good_evidence(),
            ),
        },
        BenchmarkCase {
            label: "SPL Token Transfer (legitimate)",
            category: "safe",
            expected_approved: true,
            input: make_input(
                "TokenkegQfeZyiNwAJbNbGKPfxCWuBvf9Ss623VQ5DA",
                "03",
                &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx"],
                &[],
                WalletProfile::Standard,
                good_evidence(),
            ),
        },
        BenchmarkCase {
            label: "SPL Token Burn (legitimate)",
            category: "safe",
            expected_approved: true,
            input: make_input(
                "TokenkegQfeZyiNwAJbNbGKPfxCWuBvf9Ss623VQ5DA",
                "08",
                &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx", "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx"],
                &[],
                WalletProfile::Standard,
                good_evidence(),
            ),
        },

        // MALICIOUS cases (should be blocked)
        BenchmarkCase {
            label: "Unverified CPI (potential exploit)",
            category: "malicious",
            expected_approved: false,
            input: make_input(
                "TokenkegQfeZyiNwAJbNbGKPfxCWuBvf9Ss623VQ5DA",
                "03",
                &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx"],
                &["unverified_malicious_program"],
                WalletProfile::Standard,
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
                &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
                &["prog_a", "prog_a", "prog_b", "prog_a", "prog_c"],
                WalletProfile::Standard,
                good_evidence(),
            ),
        },
        BenchmarkCase {
            label: "Authority hijack attempt",
            category: "malicious",
            expected_approved: false,
            input: make_input(
                "11111111111111111111111111111111",
                "02000000",
                &["8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx"],
                &[],
                WalletProfile::Conservative,
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
                WalletProfile::Standard,
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
                WalletProfile::Conservative,
                no_evidence(),
            ),
        },
    ]
}
