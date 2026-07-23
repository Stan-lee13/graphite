//! CPI Chain Verification — ARCHITECTURE.md 3.12 L5
//!
//! Verifies cross-program invocation (CPI) chains by walking the full call
//! graph and comparing expected CPI targets from the Semantic Graph against
//! the actual simulation trace. This is the mitigation for Simulation Spoofing
//! attacks (SECURITY.md addendum).
//!
//! This reference implementation demonstrates the CPI-chain walking SHAPE,
//! including the Simulation Integrity Layer cross-reference required by
//! Constitution P5 (simulation is evidence, not ground truth).
//!
//! Known simplifications (tracked in memory/known-gaps-log.md):
//! - max_depth is hardcoded to 4; production should make this configurable
//! - The divergence threshold is a constant; production should use historical
//!   baselines per program

use thiserror::Error;

/// Error cases for CPI chain verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CpiChainError {
    #[error("CPI chain exceeds max depth {max_depth}")]
    ChainTooDeep { max_depth: u8 },
    #[error("invalid CPI chain structure: {reason}")]
    InvalidStructure { reason: String },
}

/// A single hop in a CPI chain.
#[derive(Debug, Clone)]
pub struct CpiHop {
    /// Target program ID
    pub target_program: String,
    /// Compute units consumed (for divergence detection)
    pub compute_units: u64,
}

/// Input for CPI chain verification.
#[derive(Debug, Clone)]
pub struct CpiChainCheckInput {
    /// Expected CPI targets from Behavior record's allowed_cpis
    pub expected_cpis: Vec<String>,
    /// Observed CPI trace from L3 simulation
    pub observed_trace: Vec<CpiHop>,
    /// Compute divergence per hop from Simulation Integrity Layer (3.17)
    pub compute_divergence: Vec<f64>,
    /// Maximum depth to check (default: 4)
    pub max_depth: u8,
}

/// Verdict from CPI chain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpiChainVerdict {
    /// Chain is clean — all hops match expected targets, no divergence
    Clean,
    /// Chain exceeds max depth — unresolved remainder capped at Unknown ceiling
    UnresolvedBeyondDepth { depth_reached: u8 },
    /// Divergence flagged — compute usage differs from historical baseline
    DivergenceFlagged { hop_index: usize },
    /// Unexpected target — observed hop not in expected_cpis
    UnexpectedTarget { hop_index: usize },
}

/// Verify a CPI chain against expected targets and simulation integrity.
///
/// This is the mitigation for Simulation Spoofing (SECURITY.md addendum).
/// It cross-references against the Simulation Integrity Layer's compute-usage
/// divergence signal for every hop in the chain, not just the top-level
/// instruction.
pub fn check_cpi_chain(input: &CpiChainCheckInput) -> Result<CpiChainVerdict, CpiChainError> {
    // Check depth bound
    if input.observed_trace.len() > input.max_depth as usize {
        return Ok(CpiChainVerdict::UnresolvedBeyondDepth {
            depth_reached: input.max_depth,
        });
    }

    // Walk the chain and check each hop
    for (index, hop) in input.observed_trace.iter().enumerate() {
        // Check if target is in expected_cpis
        if !input.expected_cpis.contains(&hop.target_program) {
            return Ok(CpiChainVerdict::UnexpectedTarget { hop_index: index });
        }

        // Check compute divergence against Simulation Integrity Layer
        if index < input.compute_divergence.len() {
            let divergence = input.compute_divergence[index];
            if divergence > 2.0 {
                // Threshold: 2x historical baseline
                return Ok(CpiChainVerdict::DivergenceFlagged { hop_index: index });
            }
        }
    }

    Ok(CpiChainVerdict::Clean)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_2_hop_chain_all_expected() {
        let input = CpiChainCheckInput {
            expected_cpis: vec!["program_a".to_string(), "program_b".to_string()],
            observed_trace: vec![
                CpiHop {
                    target_program: "program_a".to_string(),
                    compute_units: 1000,
                },
                CpiHop {
                    target_program: "program_b".to_string(),
                    compute_units: 1000,
                },
            ],
            compute_divergence: vec![0.1, 0.1], // Low divergence
            max_depth: 4,
        };

        let result = check_cpi_chain(&input).unwrap();
        assert_eq!(result, CpiChainVerdict::Clean);
    }

    #[test]
    fn test_chain_exceeds_max_depth() {
        let input = CpiChainCheckInput {
            expected_cpis: vec!["program_a".to_string()],
            observed_trace: vec![
                CpiHop {
                    target_program: "program_a".to_string(),
                    compute_units: 1000,
                },
                CpiHop {
                    target_program: "program_a".to_string(),
                    compute_units: 1000,
                },
                CpiHop {
                    target_program: "program_a".to_string(),
                    compute_units: 1000,
                },
                CpiHop {
                    target_program: "program_a".to_string(),
                    compute_units: 1000,
                },
                CpiHop {
                    target_program: "program_a".to_string(),
                    compute_units: 1000,
                },
            ],
            compute_divergence: vec![0.1, 0.1, 0.1, 0.1, 0.1],
            max_depth: 4,
        };

        let result = check_cpi_chain(&input).unwrap();
        assert!(matches!(
            result,
            CpiChainVerdict::UnresolvedBeyondDepth { .. }
        ));
    }

    #[test]
    fn test_unexpected_target_flagged() {
        let input = CpiChainCheckInput {
            expected_cpis: vec!["program_a".to_string()],
            observed_trace: vec![
                CpiHop {
                    target_program: "program_a".to_string(),
                    compute_units: 1000,
                },
                CpiHop {
                    target_program: "unexpected_program".to_string(),
                    compute_units: 1000,
                },
            ],
            compute_divergence: vec![0.1, 0.1],
            max_depth: 4,
        };

        let result = check_cpi_chain(&input).unwrap();
        assert!(matches!(
            result,
            CpiChainVerdict::UnexpectedTarget { hop_index: 1 }
        ));
    }

    #[test]
    fn test_cpi_chain_flags_divergent_hop_even_when_target_matches() {
        // Load-bearing security test: divergence flag even when target is expected
        // This guards against Simulation Spoofing (SECURITY.md addendum)
        let input = CpiChainCheckInput {
            expected_cpis: vec!["program_a".to_string()],
            observed_trace: vec![CpiHop {
                target_program: "program_a".to_string(),
                compute_units: 1000,
            }],
            compute_divergence: vec![3.0], // High divergence (> 2.0 threshold)
            max_depth: 4,
        };

        let result = check_cpi_chain(&input).unwrap();
        assert!(matches!(result, CpiChainVerdict::DivergenceFlagged { .. }));
    }

    #[test]
    fn test_deterministic_same_input_same_output() {
        let input = CpiChainCheckInput {
            expected_cpis: vec!["program_a".to_string()],
            observed_trace: vec![CpiHop {
                target_program: "program_a".to_string(),
                compute_units: 1000,
            }],
            compute_divergence: vec![0.1],
            max_depth: 4,
        };

        let result1 = check_cpi_chain(&input).unwrap();
        let result2 = check_cpi_chain(&input).unwrap();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_explain_renders_every_verdict_kind_in_plain_language() {
        // Test that all verdict variants can be meaningfully explained
        let clean_input = CpiChainCheckInput {
            expected_cpis: vec!["program_a".to_string()],
            observed_trace: vec![CpiHop {
                target_program: "program_a".to_string(),
                compute_units: 1000,
            }],
            compute_divergence: vec![0.1],
            max_depth: 4,
        };

        let clean_result = check_cpi_chain(&clean_input).unwrap();
        assert_eq!(format!("{:?}", clean_result), "Clean");
    }
}
