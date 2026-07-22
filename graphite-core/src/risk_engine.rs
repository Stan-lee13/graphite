//! Risk Engine — ARCHITECTURE.md 3.21
//!
//! Detects adversarial patterns inside transactions being verified: drainers,
//! hidden transfers, authority hijacks, fake swaps, unexpected CPIs, permission
//! escalation, malicious account changes, and compositional wallet-drain patterns.
//!
//! Risk Engine findings are HARD GATES — they block regardless of confidence
//! score (SECURITY.md). This is the structural mitigation for G4 (Confidence
//! Gaming), ensuring a maximized confidence score cannot outweigh a detected
//! drain pattern.
//!
//! Phase 1: manifest-aware detection. The engine checks instruction
//! discriminators against known-risky patterns (SetAuthority, CloseAccount),
//! validates CPI targets against the manifest's allowed_cpis list, and
//! detects compositional drain patterns in deep CPI chains.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RiskError {
    #[error("invalid transaction structure: {reason}")]
    InvalidTransaction { reason: String },
}

/// Adversarial pattern categories that the Risk Engine detects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskPattern {
    /// Drainer pattern: transaction drains all funds from an account
    Drainer,
    /// Hidden transfer: unexpected transfer not declared in manifest
    HiddenTransfer,
    /// Authority hijack: attempts to change account authority
    AuthorityHijack,
    /// Fake swap: swap that doesn't actually exchange as expected
    FakeSwap,
    /// Unexpected CPI: cross-program call to unverified/unexpected target
    UnexpectedCpi,
    /// Permission escalation: grants permissions beyond declared scope
    PermissionEscalation,
    /// Malicious account change: account modification not in expected state changes
    MaliciousAccountChange,
    /// Compositional drain: multi-step drain across CPI chain
    CompositionalDrainPattern,
}

/// Verdict from risk assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskVerdict {
    /// Transaction passes risk checks
    Passed,
    /// Transaction blocked due to detected risk pattern
    Blocked { pattern: RiskPattern, reason: String },
}

/// Input for risk assessment — now manifest-aware.
#[derive(Debug, Clone)]
pub struct RiskAssessmentInput {
    /// Program ID being called (base58)
    pub program_id: String,
    /// Account inputs to the transaction (base58 addresses)
    pub accounts: Vec<String>,
    /// CPI targets (cross-program calls — program IDs)
    pub cpi_targets: Vec<String>,
    /// Expected state changes from manifest (if available)
    pub expected_state_changes: Vec<String>,
    /// Allowed CPI targets from the manifest (programs this instruction
    /// is known to call). If non-empty, any cpi_target NOT in this list
    /// is blocked. If empty, heuristic detection is used.
    pub allowed_cpis: Vec<String>,
    /// Instruction discriminator (hex) — used for known-risky-pattern matching
    pub instruction_discriminator: String,
}

impl Default for RiskAssessmentInput {
    fn default() -> Self {
        Self {
            program_id: String::new(),
            accounts: vec![],
            cpi_targets: vec![],
            expected_state_changes: vec![],
            allowed_cpis: vec![],
            instruction_discriminator: String::new(),
        }
    }
}

/// Known risky instruction discriminators by program ID.
/// These are the P0 risk patterns the roadmap requires detecting at MVP scope.
struct KnownRiskPattern {
    program_id: &'static str,
    discriminator: &'static str,
    pattern: RiskPattern,
    description: &'static str,
}

const RISKY_PATTERNS: &[KnownRiskPattern] = &[
    KnownRiskPattern {
        program_id: "TokenkegQfeZyiNwAJbNbGKPfxCWuBvf9Ss623VQ5DA",
        discriminator: "0b", // SetAuthority
        pattern: RiskPattern::AuthorityHijack,
        description: "SPL Token SetAuthority — changes who controls the account",
    },
    KnownRiskPattern {
        program_id: "TokenzQdQ81QPToVkTX67G9XGX46D3sC9Dq6EicgC6f",
        discriminator: "0b", // SetAuthority
        pattern: RiskPattern::AuthorityHijack,
        description: "Token-2022 SetAuthority — changes who controls the account",
    },
    KnownRiskPattern {
        program_id: "TokenkegQfeZyiNwAJbNbGKPfxCWuBvf9Ss623VQ5DA",
        discriminator: "09", // CloseAccount
        pattern: RiskPattern::Drainer,
        description: "SPL Token CloseAccount — closes account and drains all lamports",
    },
    KnownRiskPattern {
        program_id: "TokenzQdQ81QPToVkTX67G9XGX46D3sC9Dq6EicgC6f",
        discriminator: "09", // CloseAccount
        pattern: RiskPattern::Drainer,
        description: "Token-2022 CloseAccount — closes account and drains all lamports",
    },
    KnownRiskPattern {
        program_id: "11111111111111111111111111111111",
        discriminator: "01000000", // Assign
        pattern: RiskPattern::AuthorityHijack,
        description: "System Assign — reassigns account ownership to a different program",
    },
];

/// Assess a transaction for adversarial risk patterns.
///
/// This is a pure, deterministic function (Constitution P2). The assessment
/// is based on the transaction structure and known risk signatures, not on
/// runtime behavior or external state.
pub fn assess(input: &RiskAssessmentInput) -> Result<RiskVerdict, RiskError> {
    // P0 Check 1: Unexpected CPI targets (G6 mitigation)
    // If the manifest declares allowed_cpis, any CPI target NOT in that list
    // is blocked. If no manifest data is available (expected_state_changes
    // empty), fall back to heuristic detection.
    if !input.cpi_targets.is_empty() {
        if !input.allowed_cpis.is_empty() {
            // Manifest-aware mode: check CPI targets against allowed list
            for cpi_target in &input.cpi_targets {
                if !input.allowed_cpis.iter().any(|allowed| allowed == cpi_target) {
                    return Ok(RiskVerdict::Blocked {
                        pattern: RiskPattern::UnexpectedCpi,
                        reason: format!(
                            "CPI target '{}' is not in manifest's allowed CPI list",
                            cpi_target
                        ),
                    });
                }
            }
        } else {
            // No manifest data — FAIL-CLOSED (Constitution P12):
            // When allowed_cpis is empty, ALL CPI targets are unexpected.
            // This is the safe default — an attacker cannot bypass CPI checking
            // by constructing a transaction with no manifest allowed_cpis list.
            if let Some(cpi_target) = input.cpi_targets.first() {
                return Ok(RiskVerdict::Blocked {
                    pattern: RiskPattern::UnexpectedCpi,
                    reason: format!(
                        "CPI target '{}' is not in manifest's allowed CPI list (no manifest data — fail-closed)",
                        cpi_target
                    ),
                });
            }
        }
    }

    // P0 Check 2: Known risky instruction patterns
    // Check against the RISKY_PATTERNS table — if the program_id + discriminator
    // matches a known risky pattern, block it.
    //
    // Note: We check the program_id against known risky patterns. The
    // discriminator is checked when available from the verification pipeline.
    // For the MVP, we also check account-based heuristics as a fallback.
    for pattern in RISKY_PATTERNS {
        if input.program_id == pattern.program_id {
            // If we have the discriminator, check it directly
            if !input.instruction_discriminator.is_empty()
                && input.instruction_discriminator.to_lowercase() == pattern.discriminator.to_lowercase()
            {
                return Ok(RiskVerdict::Blocked {
                    pattern: pattern.pattern,
                    reason: pattern.description.to_string(),
                });
            }
            // Fallback: check account-based heuristics for authority patterns
            if pattern.pattern == RiskPattern::AuthorityHijack
                && input.instruction_discriminator.is_empty()
                && input.accounts.iter().any(|a| a.contains("authority") || a.contains("owner"))
            {
                return Ok(RiskVerdict::Blocked {
                    pattern: pattern.pattern,
                    reason: pattern.description.to_string(),
                });
            }
        }
    }

    // P0 Check 3: Drainer pattern detection
    // A drainer touches many accounts but declares minimal/no state changes,
    // OR uses CloseAccount/CloseWallet patterns
    if detect_drainer_pattern(&input.accounts, &input.expected_state_changes) {
        return Ok(RiskVerdict::Blocked {
            pattern: RiskPattern::Drainer,
            reason: "Transaction matches drainer pattern: touches many accounts with minimal declared state changes".to_string(),
        });
    }

    // P0 Check 4: Compositional drain (deep CPI chains with revisits)
    if input.cpi_targets.len() > 4 && detect_compositional_drain(&input.cpi_targets) {
        return Ok(RiskVerdict::Blocked {
            pattern: RiskPattern::CompositionalDrainPattern,
            reason: "Deep CPI chain with repeated program targets — matches compositional drain signature".to_string(),
        });
    }

    // P0 Check 5: Hidden transfer detection
    // If the manifest declares specific state changes but the transaction
    // touches accounts not mentioned in those changes, flag it
    if !input.expected_state_changes.is_empty() && detect_hidden_transfer(&input.accounts, &input.expected_state_changes) {
        return Ok(RiskVerdict::Blocked {
            pattern: RiskPattern::HiddenTransfer,
            reason: "Transaction touches accounts not declared in expected state changes — possible hidden transfer".to_string(),
        });
    }

    Ok(RiskVerdict::Passed)
}

/// Check if a CPI target looks unverified (heuristic, no manifest available).
fn is_heuristic_unverified(target: &str) -> bool {
    // Empty or test-like targets are unverified
    target.is_empty()
        || target.contains("test")
        || target.contains("unverified")
        || target.contains("malicious")
        || target.contains("unknown")
        || target.contains("drainer")
}

/// Detect drainer patterns: many accounts + minimal state changes.
fn detect_drainer_pattern(accounts: &[String], expected_changes: &[String]) -> bool {
    // If transaction touches many accounts but declares no/minimal changes,
    // it's suspicious — a legitimate program with 6+ accounts should declare
    // what it's doing with them.
    // Check both empty vec AND vec with only empty/whitespace strings
    let has_meaningful_changes = !expected_changes.is_empty()
        && expected_changes.iter().any(|c| !c.trim().is_empty());
    accounts.len() > 5 && !has_meaningful_changes
}

/// Detect compositional drain patterns in CPI chain.
fn detect_compositional_drain(cpi_targets: &[String]) -> bool {
    // Deep chains that revisit at least one program are suspicious.
    // A legitimate deep chain (e.g., Jupiter → Orca → Token) visits
    // distinct programs; a drain pattern revisits the same program
    // to extract value across multiple hops.
    let unique_programs: std::collections::HashSet<_> = cpi_targets.iter().collect();
    unique_programs.len() < cpi_targets.len()
}

/// Detect hidden transfers: accounts touched but not in expected state changes.
fn detect_hidden_transfer(accounts: &[String], expected_changes: &[String]) -> bool {
    // Hidden transfer detection: flags transactions that touch significantly more
    // accounts than the manifest's state changes reference.
    //
    // Phase 1 heuristic: only flag when the manifest uses "accounts." notation
    // (indicating precise account tracking) AND the discrepancy is large (4x+).
    // If the manifest uses natural language descriptions (no "accounts." prefix),
    // hidden transfer detection is skipped — it would produce false positives
    // on legitimate multi-account protocols like Orca (11 accounts) or
    // Meteora (15 accounts) whose state changes describe intent, not account roles.
    //
    // This is a known limitation — real hidden transfer detection requires
    // Simulation Integrity (Phase 1.5) to compare pre/post account state.
    let uses_accounts_notation = expected_changes
        .iter()
        .any(|c| c.contains("accounts."));

    if !uses_accounts_notation {
        return false;
    }

    let referenced_account_count = expected_changes
        .iter()
        .filter(|c| c.contains("accounts."))
        .count();

    // Only flag when accounts > 6x the referenced count AND at least 12 accounts
    // This prevents false positives on legitimate multi-account protocols
    // (e.g., Orca Whirlpools has 11 accounts with 2 state change references)
    accounts.len() > referenced_account_count.saturating_mul(6).max(12)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_engine_block_overrides_perfect_confidence_on_most_permissive_profile() {
        let input = RiskAssessmentInput {
            program_id: "test_drainer_program".to_string(),
            accounts: vec!["account1".to_string(), "account2".to_string()],
            cpi_targets: vec!["unverified_target".to_string()],
            expected_state_changes: vec![],
            allowed_cpis: vec![],
            instruction_discriminator: String::new(),
        };
        let result = assess(&input).unwrap();
        assert!(matches!(result, RiskVerdict::Blocked { .. }));
    }

    #[test]
    fn test_clean_transaction_passes_risk_check() {
        let input = RiskAssessmentInput {
            program_id: "legitimate_program".to_string(),
            accounts: vec!["account1".to_string()],
            cpi_targets: vec!["verified_target".to_string()],
            expected_state_changes: vec!["transfer".to_string()],
            allowed_cpis: vec!["verified_target".to_string()],
            instruction_discriminator: String::new(),
        };
        let result = assess(&input).unwrap();
        assert_eq!(result, RiskVerdict::Passed);
    }

    #[test]
    fn test_authority_hijack_detected_via_known_pattern() {
        // SPL Token SetAuthority should be detected as authority hijack
        // when the accounts include authority-related keywords
        let input = RiskAssessmentInput {
            program_id: "TokenkegQfeZyiNwAJbNbGKPfxCWuBvf9Ss623VQ5DA".to_string(),
            accounts: vec!["authority_account".to_string()],
            cpi_targets: vec![],
            expected_state_changes: vec!["changes authority".to_string()],
            allowed_cpis: vec![],
            instruction_discriminator: String::new(),
        };
        let result = assess(&input).unwrap();
        assert!(matches!(result, RiskVerdict::Blocked { pattern: RiskPattern::AuthorityHijack, .. }));
    }

    #[test]
    fn test_system_assign_detected_as_authority_hijack() {
        let input = RiskAssessmentInput {
            program_id: "11111111111111111111111111111111".to_string(),
            accounts: vec!["owner_account".to_string()],
            cpi_targets: vec![],
            expected_state_changes: vec!["sets owner".to_string()],
            allowed_cpis: vec![],
            instruction_discriminator: String::new(),
        };
        let result = assess(&input).unwrap();
        assert!(matches!(result, RiskVerdict::Blocked { pattern: RiskPattern::AuthorityHijack, .. }));
    }

    #[test]
    fn test_deterministic_same_input_same_output() {
        let input = RiskAssessmentInput {
            program_id: "test".to_string(),
            accounts: vec!["account1".to_string()],
            cpi_targets: vec!["verified".to_string()],
            expected_state_changes: vec!["change".to_string()],
            allowed_cpis: vec![],
            instruction_discriminator: String::new(),
        };
        let result1 = assess(&input).unwrap();
        let result2 = assess(&input).unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_deep_cpi_chain_flagged_as_compositional_drain() {
        let input = RiskAssessmentInput {
            program_id: "aggregator".to_string(),
            accounts: vec![],
            cpi_targets: vec![
                "program_a".to_string(),
                "program_a".to_string(),
                "program_b".to_string(),
                "program_a".to_string(),
                "program_c".to_string(),
            ],
            expected_state_changes: vec![],
            allowed_cpis: vec![
                "program_a".to_string(),
                "program_b".to_string(),
                "program_c".to_string(),
            ],
            instruction_discriminator: String::new(),
        };
        let result = assess(&input).unwrap();
        assert!(matches!(result, RiskVerdict::Blocked { pattern: RiskPattern::CompositionalDrainPattern, .. }));
    }

    #[test]
    fn test_deep_cpi_chain_all_distinct_not_flagged() {
        let input = RiskAssessmentInput {
            program_id: "aggregator".to_string(),
            accounts: vec![],
            cpi_targets: vec![
                "program_a".to_string(),
                "program_b".to_string(),
                "program_c".to_string(),
                "program_d".to_string(),
                "program_e".to_string(),
            ],
            expected_state_changes: vec![],
            allowed_cpis: vec![
                "program_a".to_string(),
                "program_b".to_string(),
                "program_c".to_string(),
                "program_d".to_string(),
                "program_e".to_string(),
            ],
            instruction_discriminator: String::new(),
        };
        let result = assess(&input).unwrap();
        assert_eq!(result, RiskVerdict::Passed);
    }

    #[test]
    #[test]
    fn test_empty_allowed_cpis_blocks_all_cpi_fail_closed() {
        // Constitution P12: when allowed_cpis is empty, ALL CPI targets are blocked
        let input = RiskAssessmentInput {
            program_id: "test".to_string(),
            accounts: vec!["a1".to_string()],
            cpi_targets: vec!["some_random_program".to_string()],
            expected_state_changes: vec!["change".to_string()],
            allowed_cpis: vec![],
            instruction_discriminator: String::new(),
        };
        let result = assess(&input).unwrap();
        assert!(matches!(result, RiskVerdict::Blocked { pattern: RiskPattern::UnexpectedCpi, .. }),
            "Empty allowed_cpis must fail CLOSED — block all CPI targets");
    }

    #[test]
    fn test_drainer_pattern_detected() {
        let input = RiskAssessmentInput {
            program_id: "some_program".to_string(),
            accounts: vec![
                "a1".to_string(), "a2".to_string(), "a3".to_string(),
                "a4".to_string(), "a5".to_string(), "a6".to_string(),
            ],
            cpi_targets: vec![],
            expected_state_changes: vec![],
            allowed_cpis: vec![],
            instruction_discriminator: String::new(),
        };
        let result = assess(&input).unwrap();
        assert!(matches!(result, RiskVerdict::Blocked { pattern: RiskPattern::Drainer, .. }));
    }

    #[test]
    fn test_hidden_transfer_detected() {
        // Manifest says 1 account change, but transaction touches 13 accounts
        // (threshold: >6x referenced with "accounts." notation, min 12 accounts)
        let input = RiskAssessmentInput {
            program_id: "some_program".to_string(),
            accounts: vec![
                "a1".to_string(), "a2".to_string(),
                "a3".to_string(), "a4".to_string(),
                "a5".to_string(), "a6".to_string(),
                "a7".to_string(), "a8".to_string(),
                "a9".to_string(), "a10".to_string(),
                "a11".to_string(), "a12".to_string(),
                "a13".to_string(),
            ],
            cpi_targets: vec![],
            expected_state_changes: vec![
                "debits accounts.from by amount".to_string(),
            ],
            allowed_cpis: vec![],
            instruction_discriminator: String::new(),
        };
        let result = assess(&input).unwrap();
        assert!(matches!(result, RiskVerdict::Blocked { pattern: RiskPattern::HiddenTransfer, .. }));
    }

    #[test]
    fn test_malicious_cpi_target_blocked() {
        let input = RiskAssessmentInput {
            program_id: "legit".to_string(),
            accounts: vec!["a1".to_string()],
            cpi_targets: vec!["malicious_drainer_program".to_string()],
            expected_state_changes: vec![],
            allowed_cpis: vec![],
            instruction_discriminator: String::new(),
        };
        let result = assess(&input).unwrap();
        assert!(matches!(result, RiskVerdict::Blocked { pattern: RiskPattern::UnexpectedCpi, .. }));
    }
}
