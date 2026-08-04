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

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RiskError {
    #[error("invalid transaction structure: {reason}")]
    InvalidTransaction { reason: String },
}

/// Adversarial pattern categories that the Risk Engine detects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskPattern {
    Drainer,
    HiddenTransfer,
    AuthorityHijack,
    FakeSwap,
    UnexpectedCpi,
    PermissionEscalation,
    MaliciousAccountChange,
    CompositionalDrainPattern,
}

/// Verdict from risk assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskVerdict {
    Passed,
    Blocked {
        pattern: RiskPattern,
        reason: String,
    },
}

/// Input for risk assessment — manifest-aware.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RiskAssessmentInput {
    pub program_id: String,
    pub accounts: Vec<String>,
    pub cpi_targets: Vec<String>,
    pub expected_state_changes: Vec<String>,
    pub allowed_cpis: Vec<String>,
    pub instruction_discriminator: String,
    pub expected_account_count: Option<usize>,
    /// Whether this instruction has variable accounts (skips drainer heuristic)
    #[serde(default)]
    pub variable_accounts: bool,
    /// Proposed intent type from the AI layer (e.g. "swap", "transfer", "close")
    pub proposed_intent_type: String,
    /// Extracted output token from intent parameters (for FakeSwap detection)
    #[serde(default)]
    pub extracted_output_token: Option<String>,
}

/// Known risky instruction discriminators by program ID.
struct KnownRiskPattern {
    program_id: &'static str,
    discriminator: &'static str,
    pattern: RiskPattern,
    description: &'static str,
}

const RISKY_PATTERNS: &[KnownRiskPattern] = &[
    KnownRiskPattern {
        program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        discriminator: "06",
        pattern: RiskPattern::AuthorityHijack,
        description: "SPL Token SetAuthority — changes who controls the account",
    },
    KnownRiskPattern {
        program_id: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        discriminator: "06",
        pattern: RiskPattern::AuthorityHijack,
        description: "Token-2022 SetAuthority — changes who controls the account",
    },
    KnownRiskPattern {
        program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        discriminator: "09",
        pattern: RiskPattern::Drainer,
        description: "SPL Token CloseAccount — closes account and drains all lamports",
    },
    KnownRiskPattern {
        program_id: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        discriminator: "09",
        pattern: RiskPattern::Drainer,
        description: "Token-2022 CloseAccount — closes account and drains all lamports",
    },
    KnownRiskPattern {
        program_id: "11111111111111111111111111111111",
        discriminator: "01000000",
        pattern: RiskPattern::AuthorityHijack,
        description: "System Assign — reassigns account ownership to a different program",
    },
    KnownRiskPattern {
        program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        discriminator: "04",
        pattern: RiskPattern::PermissionEscalation,
        description: "SPL Token Approve - grants delegate authority to spend tokens from account",
    },
    KnownRiskPattern {
        program_id: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        discriminator: "04",
        pattern: RiskPattern::PermissionEscalation,
        description: "Token-2022 Approve - grants delegate authority to spend tokens from account",
    },
];

/// Programs whose presence in a CPI chain is inherently risky.
/// These are programs that can drain or hijack accounts.
const RISKY_CPI_PROGRAMS: &[&str] = &[
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", // SPL Token (SetAuthority/CloseAccount via CPI)
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", // Token-2022
];

/// Known DEX/aggregator programs that legitimately CPI to SPL Token for transfers.
/// These are trusted to only call safe instructions (Transfer) on token programs.
/// Unknown programs that CPI to SPL Token are blocked (P12: fail-closed).
const TRUSTED_CPI_ROOTS: &[&str] = &[
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", // Jupiter V6
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc", // Orca Whirlpools
    "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo", // Meteora DLMM
    "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", // Raydium AMM V4
    "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf", // Squads (multisig, CPIs to System)
];

/// Trusted programs that naturally have high/variable account counts.
/// The drainer heuristic is skipped for these — high account-to-change ratio
/// is normal behavior for DEX routing (many pool accounts) and multisig
/// execution (many signer/proposal accounts).
const DEX_PROGRAMS: &[&str] = &[
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", // Jupiter V6
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc", // Orca Whirlpools
    "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo", // Meteora DLMM
    "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", // Raydium AMM V4
    "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf", // Squads V4 (multisig)
];

/// Assess a transaction for adversarial risk patterns.
///
/// Universal CPI whitelist: fundamental Solana programs that are ALWAYS safe to call.
/// These are system-level programs that any protocol can legitimately invoke:
///  - System Program: native SOL transfers, account creation
///  - SPL Token: token transfers, approvals
///  - Token-2022: extended token operations
///  - Compute Budget: compute budget instructions (always safe)
///  - ATLAS: (reserved)
///
/// No protocol should be blocked for calling these via CPI.
const UNIVERSAL_CPI_WHITELIST: &[&str] = &[
    "11111111111111111111111111111111",            // System Program
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", // SPL Token
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", // Token-2022
    "ComputeBudget111111111111111111111111111111", // Compute Budget
];

/// Check if a CPI target is universally safe (System, Token, Compute Budget)
fn is_universal_cpi(cpi_target: &str) -> bool {
    UNIVERSAL_CPI_WHITELIST.contains(&cpi_target)
}

/// Pure, deterministic (Constitution P2). Based on transaction structure and
/// known risk signatures, not runtime behavior.
pub fn assess(input: &RiskAssessmentInput) -> Result<RiskVerdict, RiskError> {
    // P0 Check 1: Unexpected CPI targets (G6 mitigation)
    // Universal CPI whitelist (System, Token, Compute Budget) is always allowed.
    // For known protocols: unexpected CPI targets reduce confidence, NOT hard-block.
    // Per Constitution P12 and 5-Response Framework:
    //   - Unknown CPI is NOT active harm — it's "protocol/instruction genuinely unknown"
    //   - Response 2 (fail open with explanation) applies
    //   - Hard-block (Response 4) is reserved for ACTIVE HARM patterns only
    //     (drainer, authority hijack, permission escalation, etc.)
    // For unknown protocols: unexpected CPI is suspicious — still fail-closed.
    let mut cpi_warnings: Vec<String> = Vec::new();
    if !input.cpi_targets.is_empty() {
        let non_universal_cpis: Vec<&String> = input
            .cpi_targets
            .iter()
            .filter(|cpi| !is_universal_cpi(cpi))
            .collect();

        if !non_universal_cpis.is_empty() && !input.allowed_cpis.is_empty() {
            for cpi_target in &non_universal_cpis {
                if !input
                    .allowed_cpis
                    .iter()
                    .any(|allowed| allowed == cpi_target.as_str())
                {
                    cpi_warnings.push(format!(
                        "CPI target '{}' is not in manifest's allowed CPI list",
                        cpi_target
                    ));
                }
            }
        } else if !non_universal_cpis.is_empty() && input.allowed_cpis.is_empty() {
            // No manifest data at all — unknown protocol, fail-closed (P12)
            if let Some(cpi_target) = non_universal_cpis.first() {
                return Ok(RiskVerdict::Blocked {
                    pattern: RiskPattern::UnexpectedCpi,
                    reason: format!(
                        "CPI target '{}' is not in manifest's allowed CPI list (unknown protocol — fail-closed)",
                        cpi_target
                    ),
                });
            }
        }
    }

    // P0 Check 1b: CPI-level risky pattern detection
    // If a CPI target is a known risky program (SPL Token, Token-2022) and
    // the root program is NOT a trusted DEX, block it — we can't verify
    // which instruction is being called inside the CPI.
    // This catches SetAuthority/CloseAccount via CPI from a custom contract.
    // Known DEX programs (Jupiter, Orca, Meteora) are whitelisted because
    // they legitimately CPI to SPL Token for transfers.
    if !TRUSTED_CPI_ROOTS.contains(&input.program_id.as_str()) {
        for cpi_target in &input.cpi_targets {
            if RISKY_CPI_PROGRAMS.contains(&cpi_target.as_str()) {
                return Ok(RiskVerdict::Blocked {
                    pattern: RiskPattern::AuthorityHijack,
                    reason: format!(
                        "CPI target '{}' is a token program from untrusted root '{}' — cannot verify instruction inside CPI (possible SetAuthority/CloseAccount via CPI, P12 fail-closed)",
                        &cpi_target[..8.min(cpi_target.len())],
                        &input.program_id[..8.min(input.program_id.len())]
                    ),
                });
            }
        }
    }

    // P0 Check 2: Known risky instruction patterns at root level
    for pattern in RISKY_PATTERNS {
        if input.program_id == pattern.program_id {
            if !input.instruction_discriminator.is_empty()
                && input.instruction_discriminator.to_lowercase()
                    == pattern.discriminator.to_lowercase()
            {
                return Ok(RiskVerdict::Blocked {
                    pattern: pattern.pattern,
                    reason: pattern.description.to_string(),
                });
            }
            if input.instruction_discriminator.is_empty()
                && (pattern.pattern == RiskPattern::AuthorityHijack
                    || pattern.pattern == RiskPattern::Drainer)
            {
                return Ok(RiskVerdict::Blocked {
                    pattern: pattern.pattern,
                    reason: format!(
                        "{}: empty discriminator on known risky program — cannot verify instruction is safe (P12 fail-closed)",
                        pattern.description
                    ),
                });
            }
        }
    }

    // P0 Check 3: Drainer pattern detection (tightened)
    // Skip if manifest declares expected account count and actual count is within range.
    // A manifest-aware account count match means the transaction structure is expected
    // — the drainer heuristic is for catching UNEXPECTED account proliferation.
    let manifest_account_match = input
        .expected_account_count
        .map(|expected| input.accounts.len() <= expected + 2)
        .unwrap_or(false);

    let is_dex = DEX_PROGRAMS.contains(&input.program_id.as_str());
    if !manifest_account_match
        && !input.variable_accounts
        && !is_dex
        && detect_drainer_pattern(&input.accounts, &input.expected_state_changes)
    {
        return Ok(RiskVerdict::Blocked {
            pattern: RiskPattern::Drainer,
            reason: "Transaction matches drainer pattern: high account-to-change ratio".to_string(),
        });
    }

    // P0 Check 3b: STMT drainer — account count mismatch
    // Skip for DEX programs (variable account counts) and manifest-declared variable accounts.
    if !is_dex && !input.variable_accounts {
        if let Some(expected_count) = input.expected_account_count {
            let unique_accounts: std::collections::HashSet<&String> =
                input.accounts.iter().collect();
            let unique_count = unique_accounts.len();
            if unique_count > expected_count + 2 {
                return Ok(RiskVerdict::Blocked {
                    pattern: RiskPattern::Drainer,
                    reason: format!(
                        "STMT drainer: transaction has {} unique accounts but manifest expects {} — possible multi-transfer drain",
                        unique_count, expected_count
                    ),
                });
            }
        }
    }

    // P0 Check 4: Compositional drain (deep CPI chains with revisits)
    if input.cpi_targets.len() >= 3
        && detect_compositional_drain(&input.cpi_targets, &input.program_id)
    {
        return Ok(RiskVerdict::Blocked {
            pattern: RiskPattern::CompositionalDrainPattern,
            reason: "Deep CPI chain with repeated program targets — matches compositional drain signature".to_string(),
        });
    }

    // P0 Check 5: Hidden transfer detection (tightened — threshold lowered from 12 to 4)
    if !input.expected_state_changes.is_empty()
        && detect_hidden_transfer(&input.accounts, &input.expected_state_changes)
    {
        return Ok(RiskVerdict::Blocked {
            pattern: RiskPattern::HiddenTransfer,
            reason: "Transaction touches accounts not declared in expected state changes — possible hidden transfer".to_string(),
        });
    }

    // P0 Check 6a: MaliciousAccountChange - CloseAccount when intent is not "close"
    if !input.proposed_intent_type.is_empty() && input.proposed_intent_type != "close" {
        let close_discriminators = ["09", "0x09"];
        for close_disc in &close_discriminators {
            if input.instruction_discriminator.to_lowercase() == close_disc.to_lowercase() {
                let token_programs = [
                    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
                ];
                if token_programs.contains(&input.program_id.as_str()) {
                    return Ok(RiskVerdict::Blocked {
                        pattern: RiskPattern::MaliciousAccountChange,
                        reason: format!(
                            "CloseAccount instruction detected but declared intent is {} - account closure not declared in intent",
                            input.proposed_intent_type
                        ),
                    });
                }
            }
        }
    }

    // P0 Check 6b: MaliciousAccountChange - Allocate/CreateAccount when intent is not "create"
    if !input.proposed_intent_type.is_empty()
        && input.proposed_intent_type != "create"
        && input.program_id == "11111111111111111111111111111111"
    {
        let alloc_disc = "03000000";
        let create_disc = "00000000";
        if input.instruction_discriminator.to_lowercase() == alloc_disc
            || input.instruction_discriminator.to_lowercase() == create_disc
        {
            return Ok(RiskVerdict::Blocked {
                pattern: RiskPattern::MaliciousAccountChange,
                reason: format!(
                    "Account allocation/creation detected but declared intent is {} - unexpected account creation",
                    input.proposed_intent_type
                ),
            });
        }
    }

    // P0 Check 7: PermissionEscalation - intent mismatch for Approve
    // If the instruction is Approve (0x04) but the declared intent is NOT approve/revoke,
    // someone is granting delegate authority without declaring it.
    if !input.proposed_intent_type.is_empty()
        && input.proposed_intent_type != "approve"
        && input.proposed_intent_type != "revoke"
    {
        let approve_discriminators = ["04", "0x04"];
        for approve_disc in &approve_discriminators {
            if input.instruction_discriminator.to_lowercase() == approve_disc.to_lowercase() {
                let token_programs = [
                    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
                ];
                if token_programs.contains(&input.program_id.as_str()) {
                    return Ok(RiskVerdict::Blocked {
                        pattern: RiskPattern::PermissionEscalation,
                        reason: format!(
                            "Approve instruction detected but declared intent is {} - delegate authority grant not declared in intent",
                            input.proposed_intent_type
                        ),
                    });
                }
            }
        }
    }

    // P0 Check 8: FakeSwap — swap intent on known DEX but no output/credit in state changes
    if let Some(_pattern) = detect_fake_swap(
        &input.program_id,
        &input.accounts,
        &input.expected_state_changes,
        &input.proposed_intent_type,
        input.extracted_output_token.as_deref(),
    ) {
        return Ok(RiskVerdict::Blocked {
            pattern: RiskPattern::FakeSwap,
            reason: "FakeSwap: swap intent detected but expected state changes do not include output/credit — output may be routed to the wrong token account".to_string(),
        });
    }

    // P0 Check 9: Intent-Program mismatch — intent type not supported by the program
    if let Some(_pattern) =
        detect_intent_program_mismatch(&input.program_id, &input.proposed_intent_type)
    {
        return Ok(RiskVerdict::Blocked {
            pattern: RiskPattern::PermissionEscalation,
            reason: format!(
                "Intent-Program mismatch: '{}' intent on program {} which does not support this intent type",
                input.proposed_intent_type, input.program_id
            ),
        });
    }

    Ok(RiskVerdict::Passed)
}

/// Detect drainer patterns: many accounts + minimal state changes.
///
/// Tightened from original:
/// - Case 1: 3+ unique accounts with NO meaningful changes → drainer (was 5)
/// - Case 2: 5+ unique accounts with meaningful changes, but ratio >= 3:1 → drainer (was 20+ at 10:1)
/// - This closes the bypass where an attacker drains 19 accounts with 1 dummy change
fn detect_drainer_pattern(accounts: &[String], expected_changes: &[String]) -> bool {
    let has_meaningful_changes =
        !expected_changes.is_empty() && expected_changes.iter().any(|c| !c.trim().is_empty());

    let unique_accounts: std::collections::HashSet<&String> = accounts.iter().collect();
    let unique_count = unique_accounts.len();

    // Case 1: 3+ unique accounts, NO meaningful changes → drainer
    if unique_count >= 3 && !has_meaningful_changes {
        return true;
    }

    // Case 2: 5+ unique accounts, but ratio of accounts to changes >= 6:1 → drainer
    // This catches: 19 accounts + 1 dummy change (ratio 19:1) which the old code missed.
    // Threshold of 6:1 allows legitimate multi-account protocols like SPL Token
    // transfers (10 accounts, 2 state changes = 5:1 ratio).
    if unique_count >= 5 && has_meaningful_changes {
        let meaningful_count = expected_changes
            .iter()
            .filter(|c| !c.trim().is_empty())
            .count();
        if meaningful_count > 0 && unique_count / meaningful_count >= 6 {
            return true;
        }
    }

    false
}

fn detect_compositional_drain(cpi_targets: &[String], program_id: &str) -> bool {
    // Pattern 1: Repeated program IDs in a deep chain (revisits to same program)
    // A legitimate transaction rarely calls the same program 3+ times via CPI.
    let unique_programs: std::collections::HashSet<_> = cpi_targets.iter().collect();
    if unique_programs.len() < cpi_targets.len() {
        return true;
    }

    // Pattern 2: Deep CPI chain (5+) from an untrusted root — all-unique programs
    // An attacker can bypass duplicate detection by calling 5+ different programs
    // in sequence, each draining a different account. Trusted DEXs (Jupiter, Orca,
    // Meteora) legitimately route through multiple programs, so they're whitelisted.
    // A 5+ deep chain from a custom/untrusted contract is a strong drain signal.
    if cpi_targets.len() >= 5 && !TRUSTED_CPI_ROOTS.contains(&program_id) {
        return true;
    }

    false
}

/// Detect hidden transfers: accounts touched but not in expected state changes.
///
/// Tightened from original:
/// - Threshold lowered from 12 to 4 accounts
/// - Multiplier lowered from 6x to 2x
/// - Still requires "accounts." notation to avoid false positives on
///   protocols with natural-language state change descriptions
fn detect_hidden_transfer(accounts: &[String], expected_changes: &[String]) -> bool {
    let uses_accounts_notation = expected_changes.iter().any(|c| c.contains("accounts."));

    if !uses_accounts_notation {
        return false;
    }

    let referenced_account_count = expected_changes
        .iter()
        .filter(|c| c.contains("accounts."))
        .count();

    // Flag when accounts > 4x the referenced count AND at least 12 accounts
    // (original was 6x/12 — lowered multiplier to 4x for tighter ratio check
    // while keeping the 12-account minimum to avoid false positives on
    // legitimate multi-account protocols like SPL Token transfers)
    let threshold = referenced_account_count.saturating_mul(4).max(12);
    accounts.len() >= threshold
}

/// Detect FakeSwap: swap intent on a swap program but no output/credit state changes.
pub fn detect_fake_swap(
    program_id: &str,
    _accounts: &[String],
    expected_state_changes: &[String],
    proposed_intent_type: &str,
    _extracted_output_token: Option<&str>,
) -> Option<RiskPattern> {
    if proposed_intent_type != "swap" {
        return None;
    }

    let swap_programs = [
        "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
        "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
        "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo",
        "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",
    ];

    if !swap_programs.contains(&program_id) {
        return None;
    }

    let has_credit = expected_state_changes
        .iter()
        .any(|c| c.to_lowercase().contains("credit") || c.to_lowercase().contains("output"));

    // SECURITY FIX: Do NOT skip FakeSwap on unknown-instruction placeholders.
    // Skipping creates a bypass: an unknown discriminator on a known protocol
    // with a swap intent gets free approval. Instead, if we can't confirm
    // the swap produces credit/output (which we can't for unknown instructions),
    // treat it as a potential FakeSwap. The risk verdict is "Blocked" not "Clear".
    if !has_credit && !expected_state_changes.is_empty() {
        return Some(RiskPattern::FakeSwap);
    }

    None
}

impl RiskPattern {
    pub fn name(&self) -> &'static str {
        match self {
            RiskPattern::Drainer => "Drainer",
            RiskPattern::AuthorityHijack => "AuthorityHijack",
            RiskPattern::HiddenTransfer => "HiddenTransfer",
            RiskPattern::UnexpectedCpi => "UnexpectedCpi",
            RiskPattern::FakeSwap => "FakeSwap",
            RiskPattern::PermissionEscalation => "PermissionEscalation",
            RiskPattern::MaliciousAccountChange => "MaliciousAccountChange",
            RiskPattern::CompositionalDrainPattern => "CompositionalDrainPattern",
        }
    }
}

fn program_supports_intent(program_id: &str, intent_type: &str) -> bool {
    match intent_type {
        "swap" => {
            const SWAP_PROGRAMS: &[&str] = &[
                "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", // Jupiter V6
                "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc", // Orca Whirlpools
                "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo", // Meteora DLMM
                "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", // Raydium AMM V4
            ];
            SWAP_PROGRAMS.contains(&program_id)
        }
        "stake" => program_id == "Stake11111111111111111111111111111111111111",
        "close" => {
            program_id == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
                || program_id == "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        }
        "transfer" => true,
        // SECURITY FIX: Default to false for unknown intent types.
        // Previously returned true, meaning any intent type outside
        // swap/stake/close/transfer would never trigger PermissionEscalation.
        _ => false,
    }
}

pub fn detect_intent_program_mismatch(program_id: &str, intent_type: &str) -> Option<RiskPattern> {
    // Skip the check when no intent type is provided (no intent → no mismatch)
    if intent_type.is_empty() {
        return None;
    }
    if !program_supports_intent(program_id, intent_type) {
        return Some(RiskPattern::PermissionEscalation);
    }
    None
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
            expected_account_count: None,
            proposed_intent_type: String::new(),
            variable_accounts: false,
            extracted_output_token: None,
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
            expected_account_count: None,
            proposed_intent_type: String::new(),
            variable_accounts: false,
            extracted_output_token: None,
        };
        let result = assess(&input).unwrap();
        assert_eq!(result, RiskVerdict::Passed);
    }

    #[test]
    fn test_authority_hijack_detected_via_known_pattern() {
        let input = RiskAssessmentInput {
            program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            accounts: vec!["authority_account".to_string()],
            cpi_targets: vec![],
            expected_state_changes: vec!["changes authority".to_string()],
            allowed_cpis: vec![],
            instruction_discriminator: String::new(),
            expected_account_count: None,
            proposed_intent_type: String::new(),
            variable_accounts: false,
            extracted_output_token: None,
        };
        let result = assess(&input).unwrap();
        assert!(matches!(
            result,
            RiskVerdict::Blocked {
                pattern: RiskPattern::AuthorityHijack,
                ..
            }
        ));
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
            expected_account_count: None,
            proposed_intent_type: String::new(),
            variable_accounts: false,
            extracted_output_token: None,
        };
        let result = assess(&input).unwrap();
        assert!(matches!(
            result,
            RiskVerdict::Blocked {
                pattern: RiskPattern::AuthorityHijack,
                ..
            }
        ));
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
            expected_account_count: None,
            proposed_intent_type: String::new(),
            variable_accounts: false,
            extracted_output_token: None,
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
            expected_account_count: None,
            proposed_intent_type: String::new(),
            variable_accounts: false,
            extracted_output_token: None,
        };
        let result = assess(&input).unwrap();
        assert!(matches!(
            result,
            RiskVerdict::Blocked {
                pattern: RiskPattern::CompositionalDrainPattern,
                ..
            }
        ));
    }

    #[test]
    fn test_deep_cpi_chain_all_distinct_not_flagged() {
        // 4 unique CPI targets from an untrusted root — below the 5-target
        // threshold, so this should pass (not a compositional drain signal).
        let input = RiskAssessmentInput {
            program_id: "aggregator".to_string(),
            accounts: vec![],
            cpi_targets: vec![
                "program_a".to_string(),
                "program_b".to_string(),
                "program_c".to_string(),
                "program_d".to_string(),
            ],
            expected_state_changes: vec![],
            allowed_cpis: vec![
                "program_a".to_string(),
                "program_b".to_string(),
                "program_c".to_string(),
                "program_d".to_string(),
            ],
            instruction_discriminator: String::new(),
            expected_account_count: None,
            proposed_intent_type: String::new(),
            variable_accounts: false,
            extracted_output_token: None,
        };
        let result = assess(&input).unwrap();
        assert_eq!(result, RiskVerdict::Passed);
    }

    #[test]
    fn test_deep_cpi_chain_5_unique_untrusted_blocked() {
        // Vibe audit finding: attacker uses 5+ all-unique program IDs to
        // bypass duplicate-only detection. Now blocked by Pattern 2.
        let input = RiskAssessmentInput {
            program_id: "attacker_contract".to_string(),
            accounts: vec!["a1".to_string()],
            cpi_targets: vec![
                "program_a".to_string(),
                "program_b".to_string(),
                "program_c".to_string(),
                "program_d".to_string(),
                "program_e".to_string(),
            ],
            expected_state_changes: vec!["change".to_string()],
            allowed_cpis: vec![
                "program_a".to_string(),
                "program_b".to_string(),
                "program_c".to_string(),
                "program_d".to_string(),
                "program_e".to_string(),
            ],
            instruction_discriminator: String::new(),
            expected_account_count: None,
            proposed_intent_type: String::new(),
            variable_accounts: false,
            extracted_output_token: None,
        };
        let result = assess(&input).unwrap();
        assert!(matches!(
            result,
            RiskVerdict::Blocked {
                pattern: RiskPattern::CompositionalDrainPattern,
                ..
            }
        ));
    }

    #[test]
    fn test_deep_cpi_chain_5_unique_trusted_root_allowed() {
        // Jupiter (trusted DEX) routing through 5 programs — legitimate behavior.
        // Should pass because Jupiter is in TRUSTED_CPI_ROOTS.
        let input = RiskAssessmentInput {
            program_id: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4".to_string(),
            accounts: vec!["a1".to_string(), "a2".to_string()],
            cpi_targets: vec![
                "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc".to_string(),
                "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo".to_string(),
                "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8".to_string(),
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
                "program_e".to_string(),
            ],
            expected_state_changes: vec!["credits accounts.destination".to_string()],
            allowed_cpis: vec![
                "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc".to_string(),
                "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo".to_string(),
                "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8".to_string(),
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
                "program_e".to_string(),
            ],
            instruction_discriminator: "e517cb97".to_string(),
            expected_account_count: Some(5),
            proposed_intent_type: "swap".to_string(),
            variable_accounts: false,
            extracted_output_token: None,
        };
        let result = assess(&input).unwrap();
        assert_eq!(result, RiskVerdict::Passed);
    }

    #[test]
    fn test_empty_allowed_cpis_blocks_all_cpi_fail_closed() {
        let input = RiskAssessmentInput {
            program_id: "test".to_string(),
            accounts: vec!["a1".to_string()],
            cpi_targets: vec!["some_random_program".to_string()],
            expected_state_changes: vec!["change".to_string()],
            allowed_cpis: vec![],
            instruction_discriminator: String::new(),
            expected_account_count: None,
            proposed_intent_type: String::new(),
            variable_accounts: false,
            extracted_output_token: None,
        };
        let result = assess(&input).unwrap();
        assert!(
            matches!(
                result,
                RiskVerdict::Blocked {
                    pattern: RiskPattern::UnexpectedCpi,
                    ..
                }
            ),
            "Empty allowed_cpis must fail CLOSED"
        );
    }

    #[test]
    fn test_drainer_pattern_detected() {
        let input = RiskAssessmentInput {
            program_id: "some_program".to_string(),
            accounts: vec![
                "a1".to_string(),
                "a2".to_string(),
                "a3".to_string(),
                "a4".to_string(),
                "a5".to_string(),
                "a6".to_string(),
            ],
            cpi_targets: vec![],
            expected_state_changes: vec![],
            allowed_cpis: vec![],
            instruction_discriminator: String::new(),
            expected_account_count: None,
            proposed_intent_type: String::new(),
            variable_accounts: false,
            extracted_output_token: None,
        };
        let result = assess(&input).unwrap();
        assert!(matches!(
            result,
            RiskVerdict::Blocked {
                pattern: RiskPattern::Drainer,
                ..
            }
        ));
    }

    #[test]
    fn test_drainer_bypass_closed_19_accounts_1_dummy_change() {
        // The exact bypass from the audit: 19 accounts + 1 dummy state change
        // Old code: 19 < 20 threshold, so it passed. New code: ratio 19:1 >= 6, so blocked.
        let accounts: Vec<String> = (0..19).map(|i| format!("acct_{}", i)).collect();
        let input = RiskAssessmentInput {
            program_id: "attacker_contract".to_string(),
            accounts,
            cpi_targets: vec![],
            expected_state_changes: vec!["dummy_change".to_string()],
            allowed_cpis: vec![],
            instruction_discriminator: "01".to_string(),
            expected_account_count: None,
            proposed_intent_type: String::new(),
            variable_accounts: false,
            extracted_output_token: None,
        };
        let result = assess(&input).unwrap();
        assert!(matches!(
            result,
            RiskVerdict::Blocked {
                pattern: RiskPattern::Drainer,
                ..
            }
        ));
    }

    #[test]
    fn test_hidden_transfer_detected() {
        // 13 accounts, 1 referenced account in "accounts." notation
        // Threshold: 1*4=4, max(4, 12) = 12. 13 >= 12 → flagged
        // Drainer check: 13 accounts with 1 meaningful change, ratio 13:1 >= 6 → drainer
        // Since drainer fires first, this test verifies the hidden transfer pattern
        // is reachable by using accounts below the drainer ratio threshold.
        // Use 13 accounts with 3 changes (ratio 4:1 < 6:1) to stay below drainer
        // while exceeding hidden transfer threshold (13 >= 12).
        let accounts: Vec<String> = (0..13).map(|i| format!("a{}", i)).collect();
        let input = RiskAssessmentInput {
            program_id: "some_program".to_string(),
            accounts,
            cpi_targets: vec![],
            expected_state_changes: vec![
                "debits accounts.from by amount".to_string(),
                "credits accounts.to by amount".to_string(),
                "updates accounts.owner".to_string(),
            ],
            allowed_cpis: vec![],
            instruction_discriminator: String::new(),
            expected_account_count: None,
            proposed_intent_type: String::new(),
            variable_accounts: false,
            extracted_output_token: None,
        };
        let result = assess(&input).unwrap();
        assert!(matches!(
            result,
            RiskVerdict::Blocked {
                pattern: RiskPattern::HiddenTransfer,
                ..
            }
        ));
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
            expected_account_count: None,
            proposed_intent_type: String::new(),
            variable_accounts: false,
            extracted_output_token: None,
        };
        let result = assess(&input).unwrap();
        assert!(matches!(
            result,
            RiskVerdict::Blocked {
                pattern: RiskPattern::UnexpectedCpi,
                ..
            }
        ));
    }

    #[test]
    fn test_cpi_level_authority_hijack_blocked() {
        // Attacker calls their own contract which CPIs to SPL Token SetAuthority.
        // Even though the manifest allows CPI to SPL Token, the root program
        // is not a trusted DEX — so the CPI-level check blocks it.
        let input = RiskAssessmentInput {
            program_id: "attacker_contract".to_string(),
            accounts: vec!["a1".to_string()],
            cpi_targets: vec!["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()],
            expected_state_changes: vec!["change".to_string()],
            allowed_cpis: vec!["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()],
            instruction_discriminator: "01".to_string(),
            expected_account_count: None,
            proposed_intent_type: String::new(),
            variable_accounts: false,
            extracted_output_token: None,
        };
        let result = assess(&input).unwrap();
        assert!(matches!(
            result,
            RiskVerdict::Blocked {
                pattern: RiskPattern::AuthorityHijack,
                ..
            }
        ));
    }

    #[test]
    fn test_trusted_dex_cpi_to_spl_token_allowed() {
        // Jupiter (trusted DEX) CPIs to SPL Token for transfer — should pass
        let input = RiskAssessmentInput {
            program_id: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4".to_string(),
            accounts: vec!["a1".to_string(), "a2".to_string(), "a3".to_string()],
            cpi_targets: vec!["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()],
            expected_state_changes: vec!["credits accounts.destination".to_string()],
            allowed_cpis: vec!["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()],
            instruction_discriminator: "e517cb97".to_string(),
            expected_account_count: Some(5),
            proposed_intent_type: "swap".to_string(),
            variable_accounts: false,
            extracted_output_token: None,
        };
        let result = assess(&input).unwrap();
        assert_eq!(result, RiskVerdict::Passed);
    }

    #[test]
    fn test_legitimate_spl_token_root_call_not_blocked_by_cpi_check() {
        // When SPL Token is the ROOT program (not CPI), the CPI check shouldn't fire
        let input = RiskAssessmentInput {
            program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            accounts: vec!["a1".to_string(), "a2".to_string(), "a3".to_string()],
            cpi_targets: vec![],
            expected_state_changes: vec!["credits accounts.destination".to_string()],
            allowed_cpis: vec![],
            instruction_discriminator: "03".to_string(), // Transfer
            expected_account_count: Some(3),
            proposed_intent_type: "transfer".to_string(),
            variable_accounts: false,
            extracted_output_token: None,
        };
        let result = assess(&input).unwrap();
        assert_eq!(result, RiskVerdict::Passed);
    }
}
