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
//! This reference implementation demonstrates the pattern detection SHAPE, not
//! a production-complete rule set. The actual pattern signatures are design
//! decisions for Phase 1+.

use thiserror::Error;

/// Error cases for risk assessment.
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

/// Input for risk assessment.
#[derive(Debug, Clone)]
pub struct RiskAssessmentInput {
    /// Program ID being called
    pub program_id: String,
    /// Account inputs to the transaction
    pub accounts: Vec<String>,
    /// CPI targets (cross-program calls)
    pub cpi_targets: Vec<String>,
    /// Expected state changes from manifest (if available)
    pub expected_state_changes: Vec<String>,
}

/// Assess a transaction for adversarial risk patterns.
///
/// This is a pure, deterministic function (Constitution P2). The assessment
/// is based on the transaction structure and known risk signatures, not on
/// runtime behavior or external state.
pub fn assess(input: &RiskAssessmentInput) -> Result<RiskVerdict, RiskError> {
    // Check for unexpected CPI targets (G6 mitigation)
    for cpi_target in &input.cpi_targets {
        if is_unverified_cpi_target(cpi_target) {
            return Ok(RiskVerdict::Blocked {
                pattern: RiskPattern::UnexpectedCpi,
                reason: format!("CPI target {} is not in verified program set", cpi_target),
            });
        }
    }
    
    // Check for authority hijack patterns
    if detect_authority_hijack(&input.accounts) {
        return Ok(RiskVerdict::Blocked {
            pattern: RiskPattern::AuthorityHijack,
            reason: "Transaction attempts to modify account authority".to_string(),
        });
    }
    
    // Check for drainer patterns
    if detect_drainer_pattern(&input.accounts, &input.expected_state_changes) {
        return Ok(RiskVerdict::Blocked {
            pattern: RiskPattern::Drainer,
            reason: "Transaction matches drainer pattern signature".to_string(),
        });
    }
    
    // Check for compositional drain patterns (multi-hop CPI chains)
    if input.cpi_targets.len() > 4 && detect_compositional_drain(&input.cpi_targets) {
        return Ok(RiskVerdict::Blocked {
            pattern: RiskPattern::CompositionalDrainPattern,
            reason: "Deep CPI chain matches compositional drain signature".to_string(),
        });
    }
    
    Ok(RiskVerdict::Passed)
}

/// Check if a CPI target is unverified.
///
/// In production, this would query the Semantic Graph for the target's trust
/// tier. Here we use a simplified heuristic for the reference implementation.
fn is_unverified_cpi_target(target: &str) -> bool {
    // Simplified: targets containing "test" or "unverified" are considered risky
    // In production, this would be a Semantic Graph trust tier lookup
    target.contains("test") || target.contains("unverified") || target.is_empty()
}

/// Detect authority hijack patterns in account list.
fn detect_authority_hijack(accounts: &[String]) -> bool {
    // Simplified: look for authority-related account keywords
    // In production, this would analyze actual instruction data
    accounts.iter().any(|acc| acc.contains("authority") || acc.contains("owner"))
}

/// Detect drainer patterns based on accounts and expected state changes.
fn detect_drainer_pattern(accounts: &[String], expected_changes: &[String]) -> bool {
    // Simplified: if transaction touches many accounts but declares minimal changes
    // In production, this would analyze actual transfer instructions
    accounts.len() > 5 && expected_changes.is_empty()
}

/// Detect compositional drain patterns in CPI chain.
fn detect_compositional_drain(cpi_targets: &[String]) -> bool {
    // Simplified: deep chains that revisit at least one program are
    // suspicious once already long enough to pass the caller's length gate
    // (`cpi_targets.len() > 4`, checked before this function is called).
    // In production, this would analyze program similarity and trust tiers,
    // not just raw duplicate-target counting.
    //
    // Bug fixed 2026-07-06 (found by actually running `cargo test`, not by
    // reading the formula): the original threshold was
    // `unique_programs.len() < cpi_targets.len() / 2`, using INTEGER
    // division. For the test's 5-target chain with 3 unique programs (2
    // duplicated hops — a real compositional-drain-shaped pattern), this
    // evaluated as `3 < 5/2` = `3 < 2` = false, so a chain that should have
    // been flagged was silently passed. Integer division made the threshold
    // far stricter than the `/ 2` in the source suggested at a glance —
    // e.g. for any chain of 5-9 targets, `len / 2` truncates to 2-4, meaning
    // you'd need almost ALL targets to collapse into 1-2 unique programs
    // before this ever fired. Replaced with a direct "is there any repeated
    // target at all" check, which is what the function's own comment
    // ("deep chains to similar-looking programs") actually describes.
    let unique_programs: std::collections::HashSet<_> = cpi_targets.iter().collect();
    unique_programs.len() < cpi_targets.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_engine_block_overrides_perfect_confidence_on_most_permissive_profile() {
        // Load-bearing security test: Risk Engine blocks even with perfect confidence
        let input = RiskAssessmentInput {
            program_id: "test_drainer_program".to_string(),
            accounts: vec!["account1".to_string(), "account2".to_string()],
            cpi_targets: vec!["unverified_target".to_string()],
            expected_state_changes: vec![],
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
        };
        
        let result = assess(&input).unwrap();
        assert_eq!(result, RiskVerdict::Passed);
    }

    #[test]
    fn test_authority_hijack_detected() {
        let input = RiskAssessmentInput {
            program_id: "authority_hijack".to_string(),
            accounts: vec!["authority_account".to_string()],
            cpi_targets: vec![],
            expected_state_changes: vec![],
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
                "program_a".to_string(), // Duplicate
                "program_b".to_string(),
                "program_a".to_string(),
                "program_c".to_string(),
            ],
            expected_state_changes: vec![],
        };
        
        let result = assess(&input).unwrap();
        assert!(matches!(result, RiskVerdict::Blocked { pattern: RiskPattern::CompositionalDrainPattern, .. }));
    }

    /// Negative-case companion to the test above: a long CPI chain where
    /// every target is distinct (no repeated program) must NOT be flagged
    /// as a compositional drain — length alone isn't the signal, repetition
    /// combined with length is. Added alongside the 2026-07-06 fix to
    /// `detect_compositional_drain` to guard against over-triggering now
    /// that the threshold is more permissive than before.
    #[test]
    fn test_deep_but_all_distinct_cpi_chain_not_flagged_as_drain() {
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
        };

        let result = assess(&input).unwrap();
        assert_eq!(result, RiskVerdict::Passed);
    }
}
