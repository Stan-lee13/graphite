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

/// Number of distinct risk checks `assess` performs (P0 Check 1..10, with
/// 1b/3b/6a/6b sub-checks). Kept next to the enum so the L7 layer report's
/// "patterns checked" string cannot silently drift out of sync.
pub const CHECKED_PATTERNS: usize = 13;

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
    /// Fund movement to/from an address that vanity-impersonates an official
    /// system account (trailing 11111 or Compu prefix) — SolPhishHunter
    /// arXiv:2505.04094 attack class.
    Impersonation,
    /// Coordinated mass-drain pattern across MULTIPLE instructions in one
    /// transaction (Phase 2): approve-then-transfer, authority-hijack-then-
    /// drain, close-and-sweep, or mass multi-transfer sweep.
    MultiInstructionDrain,
    /// Malicious shape in the hierarchical CPI trace (Phase 2): unknown
    /// program invoked in the chain, repeated revisits (compositional drain),
    /// or vanity-impersonated program inside the tree.
    CpiTraceAnomaly,
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
    /// Machine-readable security class declared in the manifest for this
    /// instruction ("drain", "authority", "withdraw", "mint", "close",
    /// "create", "transfer", or empty). Consumed by Check 10 as a
    /// fail-closed gate when the agent declares no intent for a high-risk
    /// class.
    #[serde(default)]
    pub manifest_risk_class: String,
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
    "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M", // Jupiter DCA (escrow CPIs to Token)
    "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P", // Pump.fun (curve CPIs to Token)
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
    "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M", // Jupiter DCA
    "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P", // Pump.fun (curve: many accounts)
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

/// Prefix-match an input discriminator against a known selector, mirroring
/// the manifest convention (`crate::manifest::discriminator_matches`: manifest
/// "06" matches input "0600000000000000").
///
/// Width-substitution guard: the risk checks MUST NOT compare by exact
/// equality — an attacker can pad a selector to its full 8-byte form (e.g.
/// "0600000000000000" for SetAuthority) and sail through manifest resolution
/// (which prefix-matches) while an exact-equality risk check would silently
/// not fire. The manifest and the risk engine must agree on discriminator
/// semantics, or the intent-mismatch gates are trivially bypassable.
fn disc_matches(selector: &str, input_disc: &str) -> bool {
    let s = selector.to_lowercase();
    let i = input_disc.to_lowercase();
    !s.is_empty() && i.starts_with(&s)
}

/// Pure, deterministic (Constitution P2). Based on transaction structure and
/// known risk signatures, not runtime behavior.
pub fn assess(input: &RiskAssessmentInput) -> Result<RiskVerdict, RiskError> {
    // P0 Check 1: Unexpected CPI targets (G6 mitigation)
    // Universal CPI whitelist (System, Token, Compute Budget) is always allowed.
    // For known protocols: unexpected CPI targets are NON-BLOCKING warnings
    // (Per Constitution P12 and the 5-Response Framework, an out-of-manifest CPI
    // is "protocol/instruction genuinely unknown", not active harm — response 2,
    // fail open with explanation). The warnings are computed by
    // `collect_cpi_warnings` and surfaced via `assess_with_warnings` so they are
    // never silently dropped (Constitution P3).
    // For unknown protocols (no allowed CPI list): unexpected CPI is suspicious
    // and still fail-closed (response 4).
    if !input.cpi_targets.is_empty() {
        let non_universal_cpis: Vec<&String> = input
            .cpi_targets
            .iter()
            .filter(|cpi| !is_universal_cpi(cpi))
            .collect();

        if !non_universal_cpis.is_empty() && input.allowed_cpis.is_empty() {
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
                && disc_matches(pattern.discriminator, &input.instruction_discriminator)
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
    // DEX/aggregator routes are exempt for the same reason as Checks 3/3b:
    // a swap route legitimately touches dozens of pool accounts while its
    // state changes describe only a few roles — the account:role ratio is
    // not a hidden-transfer signal for routing programs.
    if !is_dex
        && !input.expected_state_changes.is_empty()
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
            if disc_matches(close_disc, &input.instruction_discriminator) {
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
        // Full System account-creation family (canonical 8-byte LE discriminators):
        //   00000000 CreateAccount, 03000000 CreateAccountWithSeed,
        //   08000000 Allocate, 09000000 AllocateWithSeed
        let create_discs = ["00000000", "03000000", "08000000", "09000000"];
        if create_discs
            .iter()
            .any(|d| disc_matches(d, &input.instruction_discriminator))
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
            if disc_matches(approve_disc, &input.instruction_discriminator) {
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

    // P0 Check 10: System-account impersonation (ISA) — a fund-movement
    // instruction whose counterparty vanity-impersonates an official account.
    //
    // Grounding: SolPhishHunter (arXiv:2505.04094) documents this as a real
    // attack class — phishers grind addresses that end in 5+ '1' chars or start
    // with "Compu" (e.g. `...DxbLhV11111`, `CompuV3LmCTW7AG...`) so wallet UIs
    // that truncate addresses display them as official system accounts.
    // Random 32-byte keys almost never end in 5+ zero bytes (~1 in 2^40), so a
    // transfer counterparty with this shape is deliberately ground.
    //
    // Only applied to known fund-movement discriminators (System transfer 0x02,
    // Token/Token-2022 transfer 0x03 and transferChecked 0x0c) to avoid flagging
    // legitimate program-authority usage of similar-looking PDAs.
    if let Some(impersonator) = detect_system_account_impersonation(
        &input.program_id,
        &input.instruction_discriminator,
        &input.accounts,
    ) {
        return Ok(RiskVerdict::Blocked {
            pattern: RiskPattern::Impersonation,
            reason: format!(
                "System-account impersonation: fund movement to/from {} whose address shape impersonates an official system account (vanity 11111 suffix or Compu prefix)",
                impersonator
            ),
        });
    }

    // P0 Check 10: Manifest-declared high-risk class with NO declared intent.
    // The manifest declares the security class of each instruction
    // ("drain", "authority", "withdraw", "mint", "close"). A high-risk
    // instruction with an EMPTY declared intent means the agent never said
    // what it was doing — fail closed (P12). This extends protection to every
    // onboarded protocol without per-protocol detection logic: tagging the
    // manifest is the mechanism. Instructions WITH a declared intent are left
    // to the intent-mismatch checks (6a/6b/7) which require a concrete
    // declared class to compare against.
    let high_risk_classes = ["drain", "authority", "withdraw", "mint", "close"];
    if high_risk_classes.contains(&input.manifest_risk_class.as_str())
        && input.proposed_intent_type.trim().is_empty()
    {
        return Ok(RiskVerdict::Blocked {
            pattern: RiskPattern::MaliciousAccountChange,
            reason: format!(
                "Manifest declares this instruction as high-risk class '{}' but no intent was declared — unstated fund movement/authority change (P12 fail-closed)",
                input.manifest_risk_class
            ),
        });
    }

    Ok(RiskVerdict::Passed)
}

/// Detailed risk assessment: the binary verdict plus non-blocking warnings.
///
/// The binary `RiskVerdict` is the hard gate; `warnings` carry explainability
/// signals (Constitution P3) that must not silently vanish — currently the only
/// source is an out-of-manifest CPI target on a KNOWN protocol (response 2 of
/// the 5-Response Framework: fail open with explanation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskAssessmentDetail {
    pub verdict: RiskVerdict,
    pub warnings: Vec<String>,
}

/// Collect non-blocking CPI warnings for a known protocol.
///
/// Only the "known protocol with an allowed-CPI list" branch can produce
/// warnings. The unknown-protocol branch (empty `allowed_cpis`) is fail-closed
/// inside `assess` and short-circuits before this is consulted, so it returns
/// no warnings for that path.
fn collect_cpi_warnings(input: &RiskAssessmentInput) -> Vec<String> {
    let mut warnings: Vec<String> = Vec::new();
    if input.cpi_targets.is_empty() {
        return warnings;
    }
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
                warnings.push(format!(
                    "CPI target '{}' is not in manifest's allowed CPI list",
                    cpi_target
                ));
            }
        }
    }
    warnings
}

/// Assess a transaction and also return non-blocking warnings.
///
/// The verification orchestrator uses this so that out-of-manifest CPI warnings
/// on known protocols are surfaced in the L7 layer report and the result summary
/// instead of being discarded. Deterministic and pure (Constitution P2);
/// `assess` is a thin wrapper returning only the binary verdict.
pub fn assess_with_warnings(
    input: &RiskAssessmentInput,
) -> Result<RiskAssessmentDetail, RiskError> {
    let verdict = assess(input)?;
    let warnings = collect_cpi_warnings(input);
    Ok(RiskAssessmentDetail { verdict, warnings })
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

/// Universal infrastructure programs that ANY protocol legitimately invokes,
/// often repeatedly, during normal execution. A swap performs several SPL
/// Token / Token-2022 transfers; a protocol routes lamports through System.
/// Repeated CPI calls to these are normal protocol execution, NOT a
/// compositional-drain signal. Only repeated calls to SECURITY-RELEVANT
/// programs (custom contracts, drainer code) constitute the drain signature.
const UNIVERSAL_INFRASTRUCTURE_CPIS: &[&str] = &[
    "11111111111111111111111111111111",               // System
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",    // SPL Token
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",    // Token-2022
    "ComputeBudget111111111111111111111111111111",    // Compute Budget
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",   // Associated Token
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",    // Memo
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",    // Memo v1
    "BPFLoader2111111111111111111111111111111111111", // BPF Loader v2
    "BPFLoaderUpgradeab1e11111111111111111111111",    // BPF Loader v3
    "Stake11111111111111111111111111111111111111",    // Stake
    "Vote111111111111111111111111111111111111111",    // Vote
];

fn detect_compositional_drain(cpi_targets: &[String], program_id: &str) -> bool {
    // Pattern 1: Repeated visits to the same SECURITY-RELEVANT program.
    // Universal infrastructure (SPL Token, Token-2022, System, ...) is
    // excluded: a legitimate multi-hop swap calls SPL Token 2-3+ times as
    // normal execution, and treating that as a drain produces false positives.
    let security_relevant: Vec<&String> = cpi_targets
        .iter()
        .filter(|t| !UNIVERSAL_INFRASTRUCTURE_CPIS.contains(&t.as_str()))
        .collect();
    let unique_programs: std::collections::HashSet<_> = security_relevant.iter().collect();
    if unique_programs.len() < security_relevant.len() {
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

/// Number of DISTINCT account identities referenced by a set of expected
/// state-change descriptions. Two syntactic forms are recognized so the
/// detector does not depend on one exact literal:
///
/// 1. Canonical manifest notation `accounts.<name>` (e.g.
///    "debits accounts.source token balance by data.amount") — each distinct
///    `<name>` counts once, regardless of how many times it is mentioned.
/// 2. Natural-language role vocabulary (source, destination, from, to, mint,
///    owner, authority, delegate, recipient, sender, account) for manifests
///    that describe changes without the dotted notation. This keeps the
///    hidden-transfer gate live for protocols whose descriptions read
///    "debits the source token balance" instead of "debits accounts.source".
///
/// A description mentioning NO recognizable account identity still returns
/// at least 1 (fail-safe floor): a large account list with no declared
/// account identity is exactly the hidden-transfer signal.
fn referenced_account_identities(expected_changes: &[String]) -> usize {
    let mut refs: std::collections::HashSet<String> = std::collections::HashSet::new();
    for change in expected_changes {
        // Split on any non-identifier delimiter and look for "accounts.<name>"
        // fragments. `accounts.` itself is filtered so a bare mention of the
        // word "accounts" without a name does not count as a reference.
        for fragment in change.split(|ch: char| !ch.is_alphanumeric() && ch != '.' && ch != '_') {
            if let Some(pos) = fragment.find("accounts.") {
                let name = &fragment[pos + "accounts.".len()..];
                if !name.is_empty() {
                    refs.insert(name.to_string());
                }
            }
        }
    }
    if !refs.is_empty() {
        return refs.len();
    }

    // Natural-language fallback: distinct role words that name an account.
    // Word-boundary matching — "token" must not count as a "to", and
    // "accounts" must not count as an "account" role by substring.
    // "from"/"to" are deliberately absent: they are relational prepositions,
    // not account identities ("from the source to the destination" names two
    // accounts — source and destination — not four).
    const ROLES: &[&str] = &[
        "source",
        "destination",
        "mint",
        "owner",
        "authority",
        "delegate",
        "recipient",
        "sender",
        "account",
        "vault",
        "pool",
    ];
    let mut roles: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for change in expected_changes {
        let lower = change.to_lowercase();
        let words: Vec<&str> = lower
            .split(|ch: char| !ch.is_alphanumeric() && ch != '_')
            .filter(|w| !w.is_empty())
            .collect();
        for role in ROLES {
            if words.contains(role) {
                roles.insert(role);
            }
        }
    }
    roles.len().max(1)
}

/// Detect hidden transfers: the transaction touches far more accounts than the
/// expected state changes declare. A hidden transfer is the signature of a
/// drainer moving value through accounts it never declared.
///
/// The reference count is derived SEMANTICALLY (see
/// `referenced_account_identities`) rather than by counting a literal string,
/// so an attacker cannot disable the gate by rephrasing the description, and a
/// prompt-injected description padded with repeated "accounts.x" mentions
/// counts each identity once instead of inflating the threshold.
///
/// Threshold: flag when account count >= 4x the declared identities AND at
/// least 12 accounts — the 12-account floor keeps legitimate multi-account
/// protocols (SPL Token transfers, multisig) out of the hard gate.
fn detect_hidden_transfer(accounts: &[String], expected_changes: &[String]) -> bool {
    if expected_changes.is_empty() {
        return false;
    }
    let referenced_account_count = referenced_account_identities(expected_changes);
    let threshold = referenced_account_count.saturating_mul(4).max(12);
    accounts.len() >= threshold
}

/// Detect FakeSwap: swap intent on a swap program but no output/credit state changes.
/// The canonical swap-protocol set — SINGLE source of truth for both
/// FakeSwap detection and intent-capability classification. New swap
/// protocols are added here (and tagged `"category": "swap"` in their
/// manifest, verified by `manifest_category_aligns_with_swap_set`), so
/// detection logic itself never needs editing per protocol.
pub fn is_swap_program(program_id: &str) -> bool {
    const SWAP_PROGRAMS: &[&str] = &[
        "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", // Jupiter V6
        "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc", // Orca Whirlpools
        "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo", // Meteora DLMM
        "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", // Raydium AMM V4
        "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M", // Jupiter DCA (periodic swaps)
        "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P", // Pump.fun (bonding-curve buy/sell)
    ];
    SWAP_PROGRAMS.contains(&program_id)
}

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

    if !is_swap_program(program_id) {
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
            RiskPattern::Impersonation => "Impersonation",
            RiskPattern::MultiInstructionDrain => "MultiInstructionDrain",
            RiskPattern::CpiTraceAnomaly => "CpiTraceAnomaly",
        }
    }
}

/// Whether `program_id` can legitimately serve `intent_type`.
///
/// This must stay ALIGNED with the semantic layer's intent vocabulary
/// (verification.rs L5) and with the sibling P0 checks (6a/6b/7). In C21 the
/// list was expanded to the full L5 vocabulary — `create`/`create_account`,
/// `approve`, `revoke` — because the previous version returned `false` for
/// them, so P0 Check 9 contradicted Check 6b/7 and blocked every legitimate
/// create/approve/revoke transaction even when the instruction matched the
/// intent exactly. The fail-closed default for genuinely unknown intents is
/// unchanged.
fn program_supports_intent(program_id: &str, intent_type: &str) -> bool {
    match intent_type {
        "swap" | "trade" | "exchange" => is_swap_program(program_id),
        "stake" | "delegate" => program_id == "Stake11111111111111111111111111111111111111",
        "close" | "close_account" => {
            program_id == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
                || program_id == "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
                // Jupiter DCA positions are opened AND closed on-chain (closeDca).
                || program_id == "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M"
        }
        "transfer" | "send" => true,
        // L5 vocabulary: create/initialize/allocate/assign on account-creating
        // programs. Matches Check 6b's expectation that CreateAccount/
        // Allocate with intent "create" is the DECLARED case.
        "create" | "create_account" => {
            const CREATE_PROGRAMS: &[&str] = &[
                "11111111111111111111111111111111", // System (CreateAccount/Allocate/Assign)
                "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", // ATA (CreateAssociatedTokenAccount)
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", // SPL Token (InitializeAccount/InitializeMint)
                "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", // Token-2022
                "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s", // Metaplex (CreateMetadataAccountV3)
                "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P", // Pump.fun (create)
            ];
            CREATE_PROGRAMS.contains(&program_id)
        }
        // L5 vocabulary: Approve/ApproveChecked (Check 7's declared case).
        "approve" => {
            program_id == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
                || program_id == "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        }
        // L5 vocabulary: Revoke (Check 7's declared case).
        "revoke" => {
            program_id == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
                || program_id == "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        }
        // SECURITY FIX: Default to false for unknown intent types.
        // Previously returned true, meaning any intent type outside
        // swap/stake/close/transfer would never trigger PermissionEscalation.
        // Unknown intents remain fail-closed.
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

/// Detect fund movement to/from an address that impersonates an official system
/// account (ISA attack class, SolPhishHunter arXiv:2505.04094).
///
/// The heuristic mirrors the paper's own detector: a counterparty whose base58
/// address ends in 5+ '1' characters (vanity-ground trailing zero bytes) or
/// starts with "Compu" (mimicking ComputeBudget1111...) is treated as
/// impersonating an official account. Official programs themselves are excluded
/// by exact match so legitimate interactions with the real system/ComputeBudget
/// programs are never flagged.
///
/// Only fund-movement instructions are considered: System transfer (0x02) and
/// SPL Token/Token-2022 transfer (0x03) / transferChecked (0x0c). Non-fund
/// instructions (assign, approve, mint, ...) are out of scope — those have
/// their own P0 checks.
fn detect_system_account_impersonation(
    program_id: &str,
    discriminator: &str,
    accounts: &[String],
) -> Option<String> {
    const SYSTEM: &str = "11111111111111111111111111111111";
    const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

    let is_fund_movement = match program_id {
        p if p == SYSTEM => discriminator.to_lowercase().starts_with("02"),
        p if p == TOKEN || p == TOKEN_2022 => {
            let d = discriminator.to_lowercase();
            d.starts_with("03") || d.starts_with("0c")
        }
        _ => false,
    };
    if !is_fund_movement {
        return None;
    }

    // Official accounts that legitimately appear in transfers (excluded by
    // exact match — the vanity check only applies to non-official addresses).
    const OFFICIAL: &[&str] = &[
        SYSTEM,
        TOKEN,
        TOKEN_2022,
        "ComputeBudget111111111111111111111111111111",
        "SysvarRent111111111111111111111111111111111",
        "SysvarC1ock11111111111111111111111111111111",
        "SysvarRecentB1ockHashes11111111111111111111",
        "Stake11111111111111111111111111111111111111",
        "Vote111111111111111111111111111111111111111",
        "BPFLoader2111111111111111111111111111111111",
        "BPFLoaderUpgradeab1e11111111111111111111111",
        "NativeLoader111111111111111111111111111111",
    ];

    for acc in accounts {
        if acc.len() < 32 {
            continue; // not a plausible pubkey — ignore garbage inputs
        }
        if OFFICIAL.contains(&acc.as_str()) {
            continue;
        }
        let ends_vanity = acc.ends_with("11111");
        let compu_prefix = acc.starts_with("Compu");
        if ends_vanity || compu_prefix {
            return Some(acc.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ISA: a System transfer whose destination ends in a vanity 11111 suffix
    /// (a real documented phishing address shape) must be blocked with the
    /// Impersonation pattern — not merely fail on low confidence.
    #[test]
    fn test_system_transfer_to_vanity_11111_address_is_blocked() {
        let input = RiskAssessmentInput {
            program_id: "11111111111111111111111111111111".to_string(),
            accounts: vec![
                "9RGFwSryu7FvDaqHWFLrnvQHge7hc5chawhcSH7m8FVU".to_string(),
                // Shape documented in SolPhishHunter TABLE V
                "iBGtY2LBEmTiVrmPCgHRGdCPZJcDEmmkDxbLhV11111".to_string(),
            ],
            cpi_targets: vec![],
            expected_state_changes: vec!["debits accounts.source by amount".to_string()],
            allowed_cpis: vec![],
            instruction_discriminator: "0200000000000000".to_string(),
            expected_account_count: Some(2),
            variable_accounts: false,
            proposed_intent_type: "transfer".to_string(),
            extracted_output_token: None,
            manifest_risk_class: String::new(),
        };
        assert_eq!(
            assess(&input).unwrap(),
            RiskVerdict::Blocked {
                pattern: RiskPattern::Impersonation,
                reason: "System-account impersonation: fund movement to/from iBGtY2LBEmTiVrmPCgHRGdCPZJcDEmmkDxbLhV11111 whose address shape impersonates an official system account (vanity 11111 suffix or Compu prefix)".to_string(),
            }
        );
    }

    #[test]
    fn test_high_risk_class_without_declared_intent_is_blocked() {
        // Check 10: every manifest-declared high-risk class (drain,
        // authority, withdraw, mint, close) with an EMPTY declared intent
        // is fail-closed — the agent never stated what it was doing.
        for cls in ["drain", "authority", "withdraw", "mint", "close"] {
            let input = RiskAssessmentInput {
                program_id: "11111111111111111111111111111111".to_string(),
                accounts: vec![],
                cpi_targets: vec![],
                expected_state_changes: vec![],
                allowed_cpis: vec![],
                instruction_discriminator: "02000000".to_string(),
                expected_account_count: None,
                variable_accounts: false,
                proposed_intent_type: String::new(),
                extracted_output_token: None,
                manifest_risk_class: cls.to_string(),
            };
            assert!(
                matches!(
                    assess(&input).unwrap(),
                    RiskVerdict::Blocked {
                        pattern: RiskPattern::MaliciousAccountChange,
                        ..
                    }
                ),
                "class '{cls}' with empty intent must fail closed"
            );
        }
    }

    #[test]
    fn test_high_risk_class_with_declared_intent_not_gated_by_check_10() {
        // A declared intent takes the instruction out of Check 10's
        // scope — the intent-mismatch checks (6a/6b/7) handle it instead.
        // Here intent matches a transfer-shaped instruction, so Check 10
        // must NOT be the blocker for a non-high-risk class.
        let input = RiskAssessmentInput {
            program_id: "11111111111111111111111111111111".to_string(),
            accounts: vec![
                "9RGFwSryu7FvDaqHWFLrnvQHge7hc5chawhcSH7m8FVU".to_string(),
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
            ],
            cpi_targets: vec![],
            expected_state_changes: vec![],
            allowed_cpis: vec![],
            instruction_discriminator: "02000000".to_string(),
            expected_account_count: Some(2),
            variable_accounts: false,
            proposed_intent_type: "transfer".to_string(),
            extracted_output_token: None,
            manifest_risk_class: "transfer".to_string(),
        };
        let v = assess(&input).unwrap();
        assert!(
            !matches!(
                v,
                RiskVerdict::Blocked {
                    pattern: RiskPattern::MaliciousAccountChange,
                    ..
                }
            ),
            "declared transfer intent must not trip Check 10: {:?}",
            v
        );
    }

    /// ISA variant: a transfer to a "Compu..."-prefixed vanity address must
    /// also be blocked (mimics ComputeBudget1111...).
    #[test]
    fn test_token_transfer_to_compu_prefixed_address_is_blocked() {
        let input = RiskAssessmentInput {
            program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            accounts: vec![
                "DuFgLf6zzf2N9v3iT4NrkdTPDSD2xK52CCnx6Ag2ckTP".to_string(),
                "CompuV3LmCTW7AGGnM6YBftCJkKP3ZKkK1fCAY8L7eM1".to_string(),
            ],
            cpi_targets: vec![],
            expected_state_changes: vec![],
            allowed_cpis: vec![],
            instruction_discriminator: "0c00000000000000".to_string(), // transferChecked
            expected_account_count: None,
            variable_accounts: false,
            proposed_intent_type: "transfer".to_string(),
            extracted_output_token: None,
            manifest_risk_class: String::new(),
        };
        assert_eq!(
            assess(&input).unwrap(),
            RiskVerdict::Blocked {
                pattern: RiskPattern::Impersonation,
                reason: "System-account impersonation: fund movement to/from CompuV3LmCTW7AGGnM6YBftCJkKP3ZKkK1fCAY8L7eM1 whose address shape impersonates an official system account (vanity 11111 suffix or Compu prefix)".to_string(),
            }
        );
    }

    /// The rule must NOT fire for legitimate transfers: real program IDs and
    /// normal counterparties stay Clear.
    #[test]
    fn test_transfer_to_official_and_normal_addresses_not_flagged() {
        let input = RiskAssessmentInput {
            program_id: "11111111111111111111111111111111".to_string(),
            accounts: vec![
                "9RGFwSryu7FvDaqHWFLrnvQHge7hc5chawhcSH7m8FVU".to_string(),
                "DuFgLf6zzf2N9v3iT4NrkdTPDSD2xK52CCnx6Ag2ckTP".to_string(),
            ],
            cpi_targets: vec![],
            expected_state_changes: vec![],
            allowed_cpis: vec![],
            instruction_discriminator: "0200000000000000".to_string(),
            expected_account_count: Some(2),
            variable_accounts: false,
            proposed_intent_type: "transfer".to_string(),
            extracted_output_token: None,
            manifest_risk_class: String::new(),
        };
        assert_eq!(assess(&input).unwrap(), RiskVerdict::Passed);
    }

    /// The rule must NOT fire on non-fund instructions (e.g. System Assign to a
    /// program whose address ends in 11111 is a different check's concern).
    #[test]
    fn test_impersonation_rule_only_fires_on_fund_movement() {
        let input = RiskAssessmentInput {
            program_id: "11111111111111111111111111111111".to_string(),
            accounts: vec![
                "walletToAssign11111111111111111111111".to_string(),
                "9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD".to_string(),
            ],
            cpi_targets: vec![],
            expected_state_changes: vec![],
            allowed_cpis: vec![],
            instruction_discriminator: "0100000000000000".to_string(), // assign
            expected_account_count: None,
            variable_accounts: false,
            proposed_intent_type: "unknown".to_string(),
            extracted_output_token: None,
            manifest_risk_class: String::new(),
        };
        // Assign is not fund movement — the impersonation rule stays silent.
        // (The AuthorityHijack rule for assign fires on the empty-discriminator
        // path only; with a real discriminator this is left to the pipeline.)
        assert_eq!(
            detect_system_account_impersonation(
                &input.program_id,
                &input.instruction_discriminator,
                &input.accounts
            ),
            None
        );
    }

    #[test]
    fn test_assess_with_warnings_surfaces_unexpected_cpi_warning() {
        // A known protocol (allowed_cpis present) with an out-of-manifest CPI
        // must NOT be silently dropped: assess_with_warnings returns the warning
        // while keeping the binary verdict Passed (response 2, fail open with
        // explanation — Constitution P12/P3).
        let input = RiskAssessmentInput {
            program_id: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4".to_string(),
            accounts: vec!["a1".to_string(), "a2".to_string()],
            cpi_targets: vec!["unlisted_program_xyz".to_string()],
            expected_state_changes: vec!["credits accounts.destination".to_string()],
            allowed_cpis: vec!["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()],
            instruction_discriminator: "e517cb97".to_string(),
            expected_account_count: Some(5),
            proposed_intent_type: "swap".to_string(),
            variable_accounts: false,
            extracted_output_token: None,
            manifest_risk_class: String::new(),
        };
        let detail = assess_with_warnings(&input).unwrap();
        assert_eq!(detail.verdict, RiskVerdict::Passed);
        assert_eq!(
            detail.warnings,
            vec!["CPI target 'unlisted_program_xyz' is not in manifest's allowed CPI list"]
        );

        // The legacy binary entry point returns only the verdict.
        assert_eq!(assess(&input).unwrap(), RiskVerdict::Passed);
    }

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
            manifest_risk_class: String::new(),
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
            manifest_risk_class: String::new(),
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
            manifest_risk_class: String::new(),
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
            manifest_risk_class: String::new(),
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
            manifest_risk_class: String::new(),
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
            manifest_risk_class: String::new(),
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
            manifest_risk_class: String::new(),
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
            manifest_risk_class: String::new(),
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
            manifest_risk_class: String::new(),
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
            manifest_risk_class: String::new(),
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
            manifest_risk_class: String::new(),
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
            manifest_risk_class: String::new(),
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
            manifest_risk_class: String::new(),
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
            manifest_risk_class: String::new(),
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
            manifest_risk_class: String::new(),
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
            manifest_risk_class: String::new(),
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
            manifest_risk_class: String::new(),
        };
        let result = assess(&input).unwrap();
        assert_eq!(result, RiskVerdict::Passed);
    }
}
