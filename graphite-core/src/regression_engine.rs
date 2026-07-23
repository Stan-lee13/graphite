//! Regression Engine — ARCHITECTURE.md 3.9
//!
//! Replays the historical verification corpus against new protocol versions
//! to detect regressions. No Semantic Graph version may be promoted to trusted
//! tier without a clean Regression Engine run (Constitution P10).
//!
//! This reference implementation demonstrates the corpus replay SHAPE. The
//! actual corpus management and replay strategy are design decisions for
//! Phase 1+.

use thiserror::Error;

/// Error cases for regression testing.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegressionError {
    #[error("regression detected: {reason}")]
    RegressionDetected { reason: String },
    #[error("corpus empty or invalid")]
    InvalidCorpus,
}

/// A single regression test case from the historical corpus.
#[derive(Debug, Clone)]
pub struct RegressionTestCase {
    /// Program ID being tested
    pub program_id: String,
    /// Version being tested
    pub version: String,
    /// Historical transaction data
    pub transaction_data: Vec<u8>,
    /// Expected verification result
    pub expected_result: ExpectedResult,
}

/// Expected verification result for a regression test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedResult {
    /// Transaction should pass verification
    ShouldPass,
    /// Transaction should fail verification
    ShouldFail,
}

/// Result of replaying a single regression test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayResult {
    /// Test passed (matches expected result)
    Passed,
    /// Test failed (regression detected)
    Failed { reason: String },
}

/// Input for regression testing.
#[derive(Debug, Clone)]
pub struct RegressionTestInput {
    /// Historical corpus of test cases
    pub corpus: Vec<RegressionTestCase>,
    /// New version to test against
    pub new_version: String,
}

/// Result of regression testing.
#[derive(Debug, Clone)]
pub struct RegressionTestResult {
    /// Individual test results
    pub test_results: Vec<ReplayResult>,
    /// Overall pass/fail status
    pub passed: bool,
    /// Pass rate (0.0 to 1.0)
    pub pass_rate: f64,
}

/// Replay the historical corpus against a new protocol version.
///
/// Per Constitution P10, promotion to trusted tier requires 100% pass rate.
/// The MIN_PASS_RATE_FOR_PROMOTION constant enforces this.
pub const MIN_PASS_RATE_FOR_PROMOTION: f64 = 1.0;

pub fn replay_corpus(input: &RegressionTestInput) -> Result<RegressionTestResult, RegressionError> {
    if input.corpus.is_empty() {
        return Err(RegressionError::InvalidCorpus);
    }

    let mut test_results = Vec::new();
    let mut passed_count = 0;

    for test_case in &input.corpus {
        // In production, this would actually run the verification pipeline
        // against the new version. Here we simulate the replay.
        let result = simulate_replay(test_case, input.new_version.as_str());

        if result == ReplayResult::Passed {
            passed_count += 1;
        }

        test_results.push(result);
    }

    let pass_rate = passed_count as f64 / test_results.len() as f64;
    let passed = pass_rate >= MIN_PASS_RATE_FOR_PROMOTION;

    Ok(RegressionTestResult {
        test_results,
        passed,
        pass_rate,
    })
}

/// Simulate replay of a single test case (simplified for reference implementation).
fn simulate_replay(test_case: &RegressionTestCase, new_version: &str) -> ReplayResult {
    // In production, this would run the actual verification pipeline
    // Here we simulate based on version compatibility

    // Simplified: assume version 2.0+ has a regression for test cases
    // with "transfer" in expected results
    if new_version.starts_with("2.")
        && test_case.expected_result == ExpectedResult::ShouldPass
        && test_case.transaction_data.contains(&b't')
    // Contains 't' for "transfer"
    {
        return ReplayResult::Failed {
            reason: "Version 2.0 regression detected in transfer handling".to_string(),
        };
    }

    ReplayResult::Passed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_regression_blocks_promotion() {
        // Load-bearing security test: single failure blocks promotion (P10)
        let input = RegressionTestInput {
            corpus: vec![
                RegressionTestCase {
                    program_id: "test_program".to_string(),
                    version: "1.0".to_string(),
                    transaction_data: vec![b't', b'r', b'a', b'n', b's'], // "transfer"
                    expected_result: ExpectedResult::ShouldPass,
                },
                RegressionTestCase {
                    program_id: "test_program".to_string(),
                    version: "1.0".to_string(),
                    transaction_data: vec![b's', b'w', b'a', b'p'],
                    expected_result: ExpectedResult::ShouldPass,
                },
            ],
            new_version: "2.0".to_string(),
        };

        let result = replay_corpus(&input).unwrap();
        assert!(!result.passed); // Should fail due to regression
        assert!(result.pass_rate < MIN_PASS_RATE_FOR_PROMOTION);
    }

    #[test]
    fn test_clean_corpus_passes_promotion() {
        let input = RegressionTestInput {
            corpus: vec![
                RegressionTestCase {
                    program_id: "test_program".to_string(),
                    version: "1.0".to_string(),
                    transaction_data: vec![b's', b'w', b'a', b'p'],
                    expected_result: ExpectedResult::ShouldPass,
                },
                RegressionTestCase {
                    program_id: "test_program".to_string(),
                    version: "1.0".to_string(),
                    transaction_data: vec![b't', b'e', b's', b't'],
                    expected_result: ExpectedResult::ShouldPass,
                },
            ],
            new_version: "1.1".to_string(),
        };

        let result = replay_corpus(&input).unwrap();
        assert!(result.passed);
        assert_eq!(result.pass_rate, 1.0);
    }

    #[test]
    fn test_empty_corpus_rejected() {
        let input = RegressionTestInput {
            corpus: vec![],
            new_version: "1.0".to_string(),
        };

        let result = replay_corpus(&input);
        assert!(matches!(result, Err(RegressionError::InvalidCorpus)));
    }

    #[test]
    fn test_deterministic_same_input_same_output() {
        let input = RegressionTestInput {
            corpus: vec![RegressionTestCase {
                program_id: "test_program".to_string(),
                version: "1.0".to_string(),
                transaction_data: vec![b's', b'w', b'a', b'p'],
                expected_result: ExpectedResult::ShouldPass,
            }],
            new_version: "1.1".to_string(),
        };

        let result1 = replay_corpus(&input).unwrap();
        let result2 = replay_corpus(&input).unwrap();

        assert_eq!(result1.pass_rate, result2.pass_rate);
    }

    #[test]
    fn test_min_pass_rate_enforced() {
        assert_eq!(MIN_PASS_RATE_FOR_PROMOTION, 1.0);
    }
}
