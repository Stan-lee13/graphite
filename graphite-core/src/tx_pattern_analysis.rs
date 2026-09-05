//! Transaction Pattern Analysis — Phase 2 milestone.
//!
//! Two transaction-level detection layers that the single-instruction Risk
//! Engine cannot express (ARCHITECTURE.md 3.21 is per-instruction):
//!
//! 1. **Multi-instruction transaction analysis** — coordinated mass-drain
//!    patterns ACROSS multiple instructions inside ONE Solana transaction.
//!    The real attack classes from the exploit corpus (SolPhishHunter
//!    arXiv:2505.04094) are inherently multi-instruction: AAT drainers chain
//!    an Approve with a Transfer in the same tx; authority-hijack drainers
//!    chain SetAuthority with a Transfer; close-then-sweep chains CloseAccount
//!    with a Transfer. No single-instruction check can see the coordination.
//!
//! 2. **CPI instruction trace analysis** — the hierarchical CPI tree of the
//!    primary instruction. The flat `cpi_targets` list loses structure: an
//!    unknown program invoked DEEP in a chain, a program revisited repeatedly
//!    along one path (compositional drain), or a vanity-impersonated program
//!    ID inside a legitimate-looking wrapper are all invisible to a flat
//!    hop count.
//!
//! Findings are HARD GATES exactly like Risk Engine findings (SECURITY.md):
//! a `Blocked` finding rejects the transaction regardless of confidence.

use serde::{Deserialize, Serialize};

/// A single compiled instruction inside a Solana transaction message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TransactionInstruction {
    pub program_id: String,
    #[serde(default)]
    pub instruction_discriminator: String,
    #[serde(default)]
    pub account_addresses: Vec<String>,
    /// Flat CPI targets of this instruction (kept for parity with the
    /// single-instruction input; the hierarchical trace lives in `CpiTraceNode`).
    #[serde(default)]
    pub cpi_targets: Vec<String>,
}

/// A node in the hierarchical CPI trace tree of the primary instruction.
///
/// `depth == 0` is the root (the instruction being verified); each child is
/// one Cross-Program Invocation made by its parent, in order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CpiTraceNode {
    pub program_id: String,
    #[serde(default)]
    pub instruction_discriminator: String,
    pub depth: u32,
    /// Accounts the CPI callee acts on (source/destination/mint/authority in
    /// the callee's own layout). Carried so CPI flattening can correlate
    /// account identity across top-level and nested instructions.
    #[serde(default)]
    pub account_addresses: Vec<String>,
    #[serde(default)]
    pub children: Vec<CpiTraceNode>,
}

/// Severity of a transaction-level pattern finding.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PatternSeverity {
    /// Hard gate — rejects the transaction (SECURITY.md).
    Blocked,
    /// Non-blocking signal surfaced in the report (P3 explainability).
    Warning,
}

/// A finding from transaction-level pattern analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PatternFinding {
    /// Stable machine-readable class, e.g. "MultiInstructionDrain" or
    /// "CpiTraceAnomaly".
    pub pattern: String,
    pub severity: PatternSeverity,
    pub reason: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Discriminator / program constants
// ─────────────────────────────────────────────────────────────────────────────

pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";

// SPL Token / Token-2022 discriminators (hex, matched by prefix per the
// manifest convention `input.starts_with(needle)`).
pub const DISC_TRANSFER: &str = "03";
pub const DISC_TRANSFER_CHECKED: &str = "0c";
pub const DISC_APPROVE: &str = "04";
pub const DISC_APPROVE_CHECKED: &str = "0d";
pub const DISC_SET_AUTHORITY: &str = "06";
pub const DISC_CLOSE_ACCOUNT: &str = "09";
// System Program discriminators.
pub const DISC_SYSTEM_TRANSFER: &str = "02";
pub const DISC_SYSTEM_ASSIGN: &str = "01";

/// Prefix match on lowercase discriminators, mirroring
/// `crate::manifest::discriminator_matches` (a manifest disc like "0c"
/// matches a real disc like "0c00000000000000").
fn disc_matches(discriminator: &str, needle: &str) -> bool {
    let disc = discriminator.to_lowercase();
    !needle.is_empty() && disc.starts_with(needle)
}

/// True for SPL Token / Token-2022 programs.
fn is_token_program(program_id: &str) -> bool {
    program_id == TOKEN_PROGRAM || program_id == TOKEN_2022_PROGRAM
}

/// Transfer-family instruction (Transfer or TransferChecked) on a token
/// program, or a System Program transfer.
fn is_transfer_instruction(ix: &TransactionInstruction) -> bool {
    if ix.program_id == SYSTEM_PROGRAM {
        return disc_matches(&ix.instruction_discriminator, DISC_SYSTEM_TRANSFER);
    }
    if is_token_program(&ix.program_id) {
        return disc_matches(&ix.instruction_discriminator, DISC_TRANSFER)
            || disc_matches(&ix.instruction_discriminator, DISC_TRANSFER_CHECKED);
    }
    false
}

fn is_approve_instruction(ix: &TransactionInstruction) -> bool {
    is_token_program(&ix.program_id)
        && (disc_matches(&ix.instruction_discriminator, DISC_APPROVE)
            || disc_matches(&ix.instruction_discriminator, DISC_APPROVE_CHECKED))
}

fn is_set_authority_instruction(ix: &TransactionInstruction) -> bool {
    is_token_program(&ix.program_id)
        && disc_matches(&ix.instruction_discriminator, DISC_SET_AUTHORITY)
}

fn is_close_account_instruction(ix: &TransactionInstruction) -> bool {
    is_token_program(&ix.program_id)
        && disc_matches(&ix.instruction_discriminator, DISC_CLOSE_ACCOUNT)
}

/// The token account whose state the instruction acts on: for token-program
/// instructions the SOURCE token account is accounts[0] (transfer source,
/// approve source, the account whose authority changes, the account closed).
fn primary_token_account(ix: &TransactionInstruction) -> Option<&str> {
    if is_token_program(&ix.program_id) {
        ix.account_addresses.first().map(|s| s.as_str())
    } else {
        None
    }
}

/// Canonical SPL Token / Token-2022 account layouts (per the official
/// TokenInstruction docs, verified against mainnet):
///   Transfer `03`        : [source, destination, authority]
///   TransferChecked `0c` : [source, mint, destination, authority]
/// The SOURCE is always accounts[0]; the DESTINATION index differs.
/// Instruction-type-aware extraction so a TransferChecked mass sweep cannot
/// evade the mass-sweep detector by having the mint parsed as destination.
fn transfer_source(ix: &TransactionInstruction) -> Option<&str> {
    if is_transfer_instruction(ix) {
        ix.account_addresses.first().map(|s| s.as_str())
    } else {
        None
    }
}

fn transfer_destination(ix: &TransactionInstruction) -> Option<&str> {
    if !is_transfer_instruction(ix) {
        return None;
    }
    let idx = if disc_matches(&ix.instruction_discriminator, DISC_TRANSFER_CHECKED) {
        2
    } else {
        1
    };
    ix.account_addresses.get(idx).map(|s| s.as_str())
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-instruction analysis
// ─────────────────────────────────────────────────────────────────────────────

/// Detect coordinated mass-drain patterns across the instructions of a single
/// transaction. Requires at least two instructions; a single-instruction
/// transaction is the Risk Engine's domain and yields no findings here.
pub fn analyze_multi_instruction(instructions: &[TransactionInstruction]) -> Vec<PatternFinding> {
    if instructions.len() < 2 {
        return Vec::new();
    }

    let mut findings = Vec::new();

    // Rule 1: AAT — Approve-then-Transfer on the same token account.
    // The SPL Token Approve grants a delegate authority over `source`; a
    // Transfer spending that same account in the same tx is the AAT drainer
    // class (approve a large allowance, then transfer it out). ORDERING
    // MATTERS (P1E): the Approve must PRECEDE the Transfer that spends the
    // account — a Transfer followed by an Approve (e.g. spending an existing
    // allowance, then approving for a future tx) is not the drain signature.
    for (i, approve) in instructions.iter().enumerate() {
        if !is_approve_instruction(approve) {
            continue;
        }
        if let Some(approved_account) = primary_token_account(approve) {
            let shared = instructions[i + 1..].iter().any(|ix| {
                is_transfer_instruction(ix)
                    && ix.account_addresses.iter().any(|a| a == approved_account)
            });
            if shared {
                findings.push(PatternFinding {
                    pattern: "MultiInstructionDrain".to_string(),
                    severity: PatternSeverity::Blocked,
                    reason: format!(
                        "AAT drain signature: Approve on token account {approved_account} followed by a Transfer spending the same account in one transaction"
                    ),
                });
            }
        }
    }

    // Rule 2: Authority-hijack-then-Transfer. SetAuthority hands control of a
    // token account to an attacker-controlled delegate; a Transfer of that
    // account in the same tx executes the theft.
    for (i, hijack) in instructions.iter().enumerate() {
        if !is_set_authority_instruction(hijack) {
            continue;
        }
        if let Some(target_account) = primary_token_account(hijack) {
            let shared = instructions[i + 1..].iter().any(|ix| {
                is_transfer_instruction(ix)
                    && ix.account_addresses.iter().any(|a| a == target_account)
            });
            if shared {
                findings.push(PatternFinding {
                    pattern: "MultiInstructionDrain".to_string(),
                    severity: PatternSeverity::Blocked,
                    reason: format!(
                        "Authority-hijack drain signature: SetAuthority on {target_account} followed by a Transfer of that account in one transaction"
                    ),
                });
            }
        }
    }

    // Rule 3: CloseAccount-then-Transfer. Closing a token account refunds its
    // lamports to a destination; pairing it with a Transfer of the same token
    // account is the close-and-sweep drain class.
    for (i, close) in instructions.iter().enumerate() {
        if !is_close_account_instruction(close) {
            continue;
        }
        if let Some(closed_account) = primary_token_account(close) {
            let shared = instructions[i + 1..].iter().any(|ix| {
                is_transfer_instruction(ix)
                    && ix.account_addresses.iter().any(|a| a == closed_account)
            });
            if shared {
                findings.push(PatternFinding {
                    pattern: "MultiInstructionDrain".to_string(),
                    severity: PatternSeverity::Blocked,
                    reason: format!(
                        "Close-and-sweep drain signature: CloseAccount on {closed_account} paired with a Transfer of that account in one transaction"
                    ),
                });
            }
        }
    }

    // Rule 4: Mass multi-transfer sweep — three or more transfer instructions
    // in one transaction (STMT class). Two real shapes: a DEX-style batch
    // sweeping one source to many destinations, OR the actual STMT drainers
    // (tx 64tsGGe: 21 Token-2022 CPIs) sweeping MANY distinct token accounts
    // to a single attacker address. Either >= 3 distinct destinations (>= 3
    // transfers) or >= 3 distinct sources (>= 4 transfers) is the mass-drain
    // signature; the >= 4 floor keeps rare legitimate consolidations (2-3
    // accounts into one) out of the hard gate. Fail-closed tradeoff: a
    // genuine 4+ account consolidation is blocked (SECURITY.md fail-closed
    // stance on anomalous mass movement).
    let transfers: Vec<&TransactionInstruction> = instructions
        .iter()
        .filter(|ix| is_transfer_instruction(ix))
        .collect();
    if transfers.len() >= 3 {
        let sources: std::collections::HashSet<&str> = transfers
            .iter()
            .filter_map(|ix| transfer_source(ix))
            .collect();
        let destinations: std::collections::HashSet<&str> = transfers
            .iter()
            .filter_map(|ix| transfer_destination(ix))
            .collect();
        let mass_sweep = destinations.len() >= 3 || (transfers.len() >= 4 && sources.len() >= 3);

        // Dead-zone disclosure (2026-09-05 red-team): exactly 3 transfers
        // draining 3 distinct sources into 2 destinations satisfies NEITHER
        // arm — `destinations.len() >= 3` is false (2), and the multi-source
        // arm needs 4+ transfers. That is a plausible drainer shape (split the
        // proceeds across two wallets so it looks less like a sweep) sitting
        // one transfer under the floor, and the attacker chooses the count.
        //
        // It is NOT promoted to a block, deliberately: 3 inputs paying out to
        // a user account plus a fee account is an ordinary DeFi shape, and
        // Graphite has no amount or account-ownership data here to tell the
        // two apart. Blocking on this evidence would be a guess, and a
        // false-positive on fee-split routes is a real cost (P12: absence of
        // certainty is not evidence of harm). Surfacing it keeps the boundary
        // visible to a human or downstream reviewer instead of silent —
        // the same disclosure posture used for ALT usage and repeated
        // unmanifested programs.
        if !mass_sweep && transfers.len() == 3 && sources.len() >= 3 && destinations.len() == 2 {
            findings.push(PatternFinding {
                pattern: "MultiInstructionDrain".to_string(),
                severity: PatternSeverity::Warning,
                reason: format!(
                    "3 transfers drain {} distinct source account(s) into {} destination(s) — just under the mass-sweep threshold. Consistent with a split-destination drain, but also with an ordinary fee-split route; disclosed, not blocked (no amount or ownership data to distinguish them)",
                    sources.len(),
                    destinations.len()
                ),
            });
        }

        if mass_sweep {
            findings.push(PatternFinding {
                pattern: "MultiInstructionDrain".to_string(),
                severity: PatternSeverity::Blocked,
                reason: format!(
                    "Mass multi-transfer sweep: {} transfer instructions from {} distinct source account(s) to {} distinct destination(s) in one transaction (STMT mass-drain class)",
                    transfers.len(),
                    sources.len(),
                    destinations.len()
                ),
            });
        }
    }

    // Rule 5: AAT ownership-theft — Approve + System `assign` on the same
    // account. The SlowMist AAT drainers (tx 524t8LW, $3M+ stolen) chain SPL
    // Token Approve x2 with a System Program assign: the Approve grants the
    // attacker delegate authority, and the assign hands over the account's
    // OWNER — full control without any Transfer instruction, which is why
    // Rule 1's Approve-then-Transfer cannot see it.
    for (i, approve) in instructions.iter().enumerate() {
        if !is_approve_instruction(approve) {
            continue;
        }
        if let Some(approved_account) = primary_token_account(approve) {
            let assigned = instructions[i + 1..].iter().any(|ix| {
                ix.program_id == SYSTEM_PROGRAM
                    && disc_matches(&ix.instruction_discriminator, DISC_SYSTEM_ASSIGN)
                    && ix.account_addresses.first().map(|s| s.as_str()) == Some(approved_account)
            });
            if assigned {
                findings.push(PatternFinding {
                    pattern: "MultiInstructionDrain".to_string(),
                    severity: PatternSeverity::Blocked,
                    reason: format!(
                        "AAT ownership-theft signature: Approve on token account {approved_account} paired with a System Program assign of the same account in one transaction"
                    ),
                });
            }
        }
    }

    findings
}

// ─────────────────────────────────────────────────────────────────────────────
// CPI trace analysis
// ─────────────────────────────────────────────────────────────────────────────

/// The well-known system programs always trusted in a CPI chain (never
/// flagged as "unknown program" — they are the substrate every Solana program
/// runs on).
pub fn system_programs() -> Vec<String> {
    vec![
        SYSTEM_PROGRAM.to_string(),
        TOKEN_PROGRAM.to_string(),
        TOKEN_2022_PROGRAM.to_string(),
        COMPUTE_BUDGET_PROGRAM.to_string(),
        // SPL Memo / associated-token-account / bpf loaders are manifest-
        // registered in the seed set; the caller merges manifest program IDs
        // into the known set, so the constants here stay minimal.
    ]
}

/// Flatten a CPI trace into the EFFECTIVE instruction sequence for
/// multi-instruction analysis. Executing a CPI-wrapped instruction executes
/// its callees in order, so a malicious Approve + Transfer pair hidden inside
/// a single top-level instruction is a real drain pattern — the analyzer must
/// see the normalized sequence, not just the top level.
///
/// Pre-order (root first, children in call order) preserves execution
/// ordering; the root itself is omitted because it is already present in the
/// top-level `transaction_instructions` list — flattening only the callees
/// avoids double-counting the root.
pub fn flatten_cpi_trace(trace: &CpiTraceNode) -> Vec<TransactionInstruction> {
    let mut out = Vec::new();
    let mut stack: Vec<&CpiTraceNode> = Vec::new();
    // Push children in reverse so the first child pops first (pre-order).
    for child in trace.children.iter().rev() {
        stack.push(child);
    }
    while let Some(node) = stack.pop() {
        out.push(TransactionInstruction {
            program_id: node.program_id.clone(),
            instruction_discriminator: node.instruction_discriminator.clone(),
            account_addresses: node.account_addresses.clone(),
            cpi_targets: Vec::new(),
        });
        for child in node.children.iter().rev() {
            stack.push(child);
        }
    }
    out
}

/// Max occurrences of `needle` along any single root-to-leaf path, INCLUDING
/// the root node. This is the correct execution-path semantic: a program
/// re-entered at the root (the verified instruction's own program) counts
/// toward the compositional-drain threshold just like any deeper revisit.
/// The prior implementation counted downward from a depth >= 1 node, so a
/// chain like A(root) -> B -> A -> A reported 2 occurrences for A instead of
/// 3 and evaded the repeated-revisit rule.
fn max_path_occurrences(node: &CpiTraceNode, needle: &str, count: u32) -> u32 {
    let c = count + u32::from(node.program_id == needle);
    if node.children.is_empty() {
        c
    } else {
        node.children
            .iter()
            .map(|child| max_path_occurrences(child, needle, c))
            .max()
            .unwrap_or(c)
    }
}

fn max_depth(node: &CpiTraceNode) -> u32 {
    node.children
        .iter()
        .map(max_depth)
        .max()
        .unwrap_or(node.depth)
}

/// A program ID that vanity-impersonates a known program: shares a long
/// leading prefix (≈46+ bits — deliberate, not chance) with a known program
/// but is not it. This is the SolPhishHunter ISA class applied to CPI
/// targets instead of transfer destinations.
fn impersonates(program_id: &str, known: &[String]) -> Option<String> {
    const PREFIX_LEN: usize = 8;
    if program_id.len() <= PREFIX_LEN {
        return None;
    }
    known
        .iter()
        .find(|k| {
            k.len() > PREFIX_LEN
                && k.as_str() != program_id
                && k[..PREFIX_LEN] == program_id[..PREFIX_LEN]
        })
        .cloned()
}

/// Analyze the hierarchical CPI trace of the primary instruction against the
/// set of trusted program IDs (manifest-registered programs + system
/// programs). The root node is the instruction being verified; its unknown-
/// protocol status is handled by the unknown-protocol ceiling downstream, so
/// only nodes at depth >= 1 are scrutinized here.
pub fn analyze_cpi_trace(trace: &CpiTraceNode, known_programs: &[String]) -> Vec<PatternFinding> {
    let mut findings = Vec::new();

    // Walk the tree once, collecting depth >= 1 nodes.
    let mut nodes: Vec<&CpiTraceNode> = Vec::new();
    let mut stack: Vec<&CpiTraceNode> = trace.children.iter().collect();
    while let Some(node) = stack.pop() {
        nodes.push(node);
        stack.extend(node.children.iter());
    }

    // Rule 1: unknown program invoked deep in the chain — the highest-signal
    // anomaly. A legitimate protocol invokes manifest-registered or system
    // programs; an unregistered program inside the tree is unverified code
    // being given execution (and authority over writable accounts).
    for node in &nodes {
        if !known_programs.iter().any(|k| k == &node.program_id) {
            findings.push(PatternFinding {
                pattern: "CpiTraceAnomaly".to_string(),
                severity: PatternSeverity::Blocked,
                reason: format!(
                    "CPI trace invokes unknown program {} at depth {} — not in the manifest registry or well-known system programs",
                    node.program_id, node.depth
                ),
            });
        }
    }

    // Rule 2: repeated revisit along one path — the compositional drain
    // signature (same program re-entered >= 3 times within a single chain).
    // Evaluated per distinct program from the ROOT so root-level repetition
    // (the verified instruction's own program re-entering itself) counts.
    let mut programs: std::collections::HashSet<&str> =
        nodes.iter().map(|n| n.program_id.as_str()).collect();
    programs.insert(trace.program_id.as_str());
    for prog in programs {
        let occ = max_path_occurrences(trace, prog, 0);
        if occ >= 3 {
            findings.push(PatternFinding {
                pattern: "CpiTraceAnomaly".to_string(),
                severity: PatternSeverity::Blocked,
                reason: format!(
                    "CPI trace re-enters program {} {} times along one path — compositional drain signature",
                    prog, occ
                ),
            });
        }
    }

    // Rule 3: excessive chain depth — a warning, not a block: legitimate
    // DEX routing can nest several levels, but unusually deep chains deserve
    // an explicit report signal.
    if max_depth(trace) >= 6 {
        findings.push(PatternFinding {
            pattern: "CpiTraceAnomaly".to_string(),
            severity: PatternSeverity::Warning,
            reason: format!(
                "CPI trace depth {} exceeds the typical nesting bound — unusually deep chain",
                max_depth(trace)
            ),
        });
    }

    // Rule 4: vanity-impersonated program inside the chain (ISA applied to
    // CPI targets).
    for node in &nodes {
        if let Some(spoofed) = impersonates(&node.program_id, known_programs) {
            findings.push(PatternFinding {
                pattern: "CpiTraceAnomaly".to_string(),
                severity: PatternSeverity::Blocked,
                reason: format!(
                    "CPI target {} vanity-impersonates known program {} (shared address prefix)",
                    node.program_id, spoofed
                ),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ix(program: &str, disc: &str, accounts: &[&str]) -> TransactionInstruction {
        TransactionInstruction {
            program_id: program.to_string(),
            instruction_discriminator: disc.to_string(),
            account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
            cpi_targets: vec![],
        }
    }

    const SOURCE: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    const DEST: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
    const DEST2: &str = "DuFgLf6zzf2N9v3iT4NrkdTPDSD2xK52CCnx6Ag2ckTP";
    const DEST3: &str = "9RGFwSryu7FvDaqHWFLrnvQHge7hc5chawhcSH7m8FVU";
    const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const MINT2: &str = "So11111111111111111111111111111111111111112";
    const MINT3: &str = "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytf3jPxZ7P";

    // ── Multi-instruction rules ─────────────────────────────────────────────

    #[test]
    fn single_instruction_is_risk_engine_domain() {
        let txs = vec![ix(TOKEN_PROGRAM, "03", &[SOURCE, DEST])];
        assert!(analyze_multi_instruction(&txs).is_empty());
    }

    #[test]
    fn approve_then_transfer_same_account_is_blocked() {
        let txs = vec![
            ix(TOKEN_PROGRAM, "04", &[SOURCE, DEST, SOURCE]), // Approve
            ix(TOKEN_PROGRAM, "03", &[SOURCE, DEST]),         // Transfer
        ];
        let findings = analyze_multi_instruction(&txs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, PatternSeverity::Blocked);
        assert!(findings[0].reason.contains("AAT drain"));
    }

    #[test]
    fn approve_then_transfer_disjoint_accounts_is_clean() {
        let txs = vec![
            ix(TOKEN_PROGRAM, "04", &[SOURCE, DEST, SOURCE]),
            ix(TOKEN_PROGRAM, "03", &[DEST2, DEST3]),
        ];
        assert!(analyze_multi_instruction(&txs).is_empty());
    }

    #[test]
    fn set_authority_then_transfer_is_blocked() {
        let txs = vec![
            ix(TOKEN_PROGRAM, "06", &[SOURCE, DEST]),
            ix(TOKEN_PROGRAM, "0c", &[SOURCE, DEST, DEST]), // transferChecked
        ];
        let findings = analyze_multi_instruction(&txs);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].reason.contains("Authority-hijack"));
    }

    #[test]
    fn close_account_then_transfer_is_blocked() {
        let txs = vec![
            ix(TOKEN_PROGRAM, "09", &[SOURCE, DEST]),
            ix(TOKEN_PROGRAM, "03", &[SOURCE, DEST]),
        ];
        let findings = analyze_multi_instruction(&txs);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].reason.contains("Close-and-sweep"));
    }

    #[test]
    fn mass_multi_transfer_sweep_is_blocked() {
        let txs = vec![
            ix(SYSTEM_PROGRAM, "02", &[SOURCE, DEST]),
            ix(SYSTEM_PROGRAM, "02", &[SOURCE, DEST2]),
            ix(SYSTEM_PROGRAM, "02", &[SOURCE, DEST3]),
        ];
        let findings = analyze_multi_instruction(&txs);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].reason.contains("Mass multi-transfer sweep"));
    }

    #[test]
    fn mass_sweep_to_single_destination_is_blocked() {
        // Real STMT shape (tx 64tsGGe): many distinct token accounts swept to
        // ONE attacker address in a single tx. 4 transfers from 4 distinct
        // sources — the single-destination mass-drain signature.
        let txs = vec![
            ix(TOKEN_PROGRAM, "03", &[SOURCE, DEST, SOURCE]),
            ix(TOKEN_PROGRAM, "03", &[DEST2, DEST, SOURCE]),
            ix(TOKEN_PROGRAM, "03", &[DEST3, DEST, SOURCE]),
            // TransferChecked canonical layout: [source, mint, destination, authority]
            ix(
                TOKEN_PROGRAM,
                "0c",
                &[
                    "9jYfQm6n3vT2wZxK4pR8sLcE7aBdU5iN1hG0fJqV",
                    MINT,
                    DEST,
                    SOURCE,
                ],
            ),
        ];
        let findings = analyze_multi_instruction(&txs);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].reason.contains("Mass multi-transfer sweep"));
        assert!(findings[0].reason.contains("4 distinct source"));
    }

    #[test]
    fn transfer_checked_three_distinct_destinations_is_blocked() {
        // P0 #2 regression: with the OLD code, destinations were read from
        // accounts[1] — for TransferChecked that is the MINT. Three
        // TransferChecked transfers sharing a mint showed ONE "destination"
        // and slipped under the >= 3 floor: a genuine 3-destination mass
        // drain evaded the detector. Canonical layout is
        // [source, mint, destination, authority] so the destination is
        // accounts[2].
        let txs = vec![
            ix(TOKEN_PROGRAM, "0c", &[SOURCE, MINT, DEST, SOURCE]),
            ix(TOKEN_PROGRAM, "0c", &[DEST2, MINT, DEST3, SOURCE]),
            ix(TOKEN_PROGRAM, "0c", &[DEST3, MINT, DEST2, SOURCE]),
        ];
        let findings = analyze_multi_instruction(&txs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, PatternSeverity::Blocked);
        assert!(findings[0].reason.contains("3 distinct source"));
        assert!(findings[0].reason.contains("3 distinct destination"));
    }

    #[test]
    fn transfer_checked_mixed_programs_mass_sweep_is_blocked() {
        // Token-2022 TransferChecked variants must be treated identically to
        // SPL Token: mixed SPL/Token-2022 sweeps still count every transfer.
        let txs = vec![
            ix(TOKEN_PROGRAM, "0c", &[SOURCE, MINT, DEST, SOURCE]),
            ix(TOKEN_2022_PROGRAM, "0c", &[DEST2, MINT2, DEST3, SOURCE]),
            ix(TOKEN_2022_PROGRAM, "0c", &[DEST3, MINT3, DEST2, SOURCE]),
        ];
        let findings = analyze_multi_instruction(&txs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, PatternSeverity::Blocked);
    }

    #[test]
    fn transfer_checked_distinct_mints_not_misread_as_destinations() {
        // The pre-fix bug also INFLATED findings: with the mint read as the
        // destination, transfers to one destination but through distinct mints
        // (e.g. 3 token types consolidated into one account) looked like 3
        // distinct destinations and hard-blocked a legitimate consolidation.
        let txs = vec![
            ix(TOKEN_PROGRAM, "0c", &[SOURCE, MINT, DEST, SOURCE]),
            ix(TOKEN_PROGRAM, "0c", &[DEST2, MINT2, DEST, SOURCE]),
            ix(TOKEN_PROGRAM, "0c", &[DEST3, MINT3, DEST, SOURCE]),
        ];
        assert!(analyze_multi_instruction(&txs).is_empty());
    }

    #[test]
    fn transfer_checked_missing_accounts_are_clean() {
        // Malformed arrays must not panic and must not fabricate a sweep:
        // a TransferChecked with fewer than 3 accounts has no extractable
        // destination.
        let txs = vec![
            ix(TOKEN_PROGRAM, "0c", &[SOURCE, MINT]),
            ix(TOKEN_PROGRAM, "0c", &[DEST2, MINT]),
            ix(TOKEN_PROGRAM, "0c", &[DEST3, MINT]),
        ];
        assert!(analyze_multi_instruction(&txs).is_empty());
    }

    #[test]
    fn three_transfers_same_destination_is_clean() {
        // 3 transfers to one destination from 3 sources sits below the
        // 4-transfer single-destination floor — a legitimate consolidation
        // shape stays out of the hard gate.
        let txs = vec![
            ix(TOKEN_PROGRAM, "03", &[SOURCE, DEST, SOURCE]),
            ix(TOKEN_PROGRAM, "03", &[DEST2, DEST, SOURCE]),
            ix(TOKEN_PROGRAM, "03", &[DEST3, DEST, SOURCE]),
        ];
        assert!(analyze_multi_instruction(&txs).is_empty());
    }

    /// Dead-zone disclosure (2026-09-05 red-team): 3 transfers, 3 distinct
    /// sources, 2 destinations satisfies neither mass-sweep arm — and the
    /// attacker picks the transfer count, so this shape sits one step under
    /// the floor by choice. Disclosed as a WARNING, never blocked: the same
    /// shape is an ordinary fee-split route, and there is no amount or
    /// ownership data here to tell a drain from a payout.
    #[test]
    fn three_transfers_to_two_destinations_is_disclosed_but_not_blocked() {
        let txs = vec![
            ix(TOKEN_PROGRAM, "03", &[SOURCE, DEST, SOURCE]),
            ix(TOKEN_PROGRAM, "03", &[DEST2, DEST, SOURCE]),
            ix(TOKEN_PROGRAM, "03", &[DEST3, MINT, SOURCE]),
        ];
        let findings = analyze_multi_instruction(&txs);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly one disclosure: {findings:?}"
        );
        assert_eq!(
            findings[0].severity,
            PatternSeverity::Warning,
            "the dead-zone shape must be disclosed, not blocked — blocking it would \
             false-positive on fee-split routes: {findings:?}"
        );
        assert!(findings[0]
            .reason
            .contains("just under the mass-sweep threshold"));
    }

    /// Crossing the real threshold must still BLOCK, not degrade to a warning.
    #[test]
    fn crossing_the_mass_sweep_threshold_still_blocks() {
        let txs = vec![
            ix(TOKEN_PROGRAM, "03", &[SOURCE, DEST, SOURCE]),
            ix(TOKEN_PROGRAM, "03", &[DEST2, DEST3, SOURCE]),
            ix(TOKEN_PROGRAM, "03", &[DEST3, MINT, SOURCE]),
        ];
        let findings = analyze_multi_instruction(&txs);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == PatternSeverity::Blocked),
            "3 distinct destinations is the real mass-sweep signature and must block: {findings:?}"
        );
    }

    #[test]
    fn approve_then_system_assign_is_blocked() {
        // SlowMist AAT (tx 524t8LW): Approve x2 + System assign, NO Transfer
        // — the ownership-theft variant Rule 1 cannot see.
        let txs = vec![
            ix(TOKEN_PROGRAM, "04", &[SOURCE, DEST, SOURCE]), // Approve
            ix(SYSTEM_PROGRAM, "01", &[SOURCE, DEST]),        // assign
        ];
        let findings = analyze_multi_instruction(&txs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, PatternSeverity::Blocked);
        assert!(findings[0].reason.contains("AAT ownership-theft"));
    }

    #[test]
    fn approve_with_assign_on_disjoint_account_is_clean() {
        // Rule 5 requires the assign to target the SAME account as the
        // Approve; an assign on a disjoint account is not ownership theft
        // (and no transfer shares the approved account, so Rule 1 stays off).
        let txs = vec![
            ix(TOKEN_PROGRAM, "04", &[SOURCE, DEST, SOURCE]), // Approve on SOURCE
            ix(SYSTEM_PROGRAM, "01", &[DEST2, DEST]),         // assign on DEST2
        ];
        assert!(analyze_multi_instruction(&txs).is_empty());
    }

    #[test]
    fn two_transfers_same_destination_is_clean() {
        let txs = vec![
            ix(SYSTEM_PROGRAM, "02", &[SOURCE, DEST]),
            ix(SYSTEM_PROGRAM, "02", &[SOURCE, DEST]),
        ];
        assert!(analyze_multi_instruction(&txs).is_empty());
    }

    #[test]
    fn token_2022_approve_is_detected() {
        let txs = vec![
            ix(TOKEN_2022_PROGRAM, "04", &[SOURCE, DEST, SOURCE]),
            ix(TOKEN_2022_PROGRAM, "03", &[SOURCE, DEST]),
        ];
        let findings = analyze_multi_instruction(&txs);
        assert_eq!(findings.len(), 1);
    }

    // ── CPI trace rules ─────────────────────────────────────────────────────

    fn node(program: &str, depth: u32, children: Vec<CpiTraceNode>) -> CpiTraceNode {
        CpiTraceNode {
            program_id: program.to_string(),
            instruction_discriminator: String::new(),
            depth,
            account_addresses: vec![],
            children,
        }
    }

    #[test]
    fn trace_with_known_programs_is_clean() {
        let trace = node(
            TOKEN_PROGRAM,
            0,
            vec![node(
                TOKEN_PROGRAM,
                1,
                vec![node(SYSTEM_PROGRAM, 2, vec![])],
            )],
        );
        let known: Vec<String> = vec![TOKEN_PROGRAM.into(), SYSTEM_PROGRAM.into()];
        let findings = analyze_cpi_trace(&trace, &known);
        // Depth 2 — no finding. Unknown/revisit/impersonation all absent.
        assert!(findings.is_empty());
    }

    #[test]
    fn trace_invoking_unknown_program_is_blocked() {
        let trace = node(
            TOKEN_PROGRAM,
            0,
            vec![node("unverified_malicious_program", 1, vec![])],
        );
        let known: Vec<String> = vec![TOKEN_PROGRAM.into()];
        let findings = analyze_cpi_trace(&trace, &known);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, PatternSeverity::Blocked);
        assert!(findings[0].reason.contains("unknown program"));
    }

    #[test]
    fn trace_unknown_root_is_not_flagged_by_trace_layer() {
        // The root's unknown-protocol status is the unknown-protocol ceiling's
        // domain, not the trace layer's — only depth >= 1 nodes are checked.
        let trace = node(
            "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
            0,
            vec![node(TOKEN_PROGRAM, 1, vec![])],
        );
        let known: Vec<String> = vec![TOKEN_PROGRAM.into()];
        assert!(analyze_cpi_trace(&trace, &known).is_empty());
    }

    #[test]
    fn trace_repeated_revisit_is_blocked() {
        let trace = node(
            TOKEN_PROGRAM,
            0,
            vec![node(
                "prog_a",
                1,
                vec![node("prog_a", 2, vec![node("prog_a", 3, vec![])])],
            )],
        );
        let known: Vec<String> = vec![TOKEN_PROGRAM.into(), "prog_a".into()];
        let findings = analyze_cpi_trace(&trace, &known);
        assert!(
            findings
                .iter()
                .any(|f| f.reason.contains("re-enters program prog_a 3 times")),
            "expected revisit finding, got: {:?}",
            findings
        );
    }

    #[test]
    fn trace_root_level_repetition_is_blocked() {
        // P0 #3 regression: the ROOT is the verified instruction's program.
        // A chain A(root) -> B -> A -> A re-enters A three times along one
        // execution path. The old downward-only counter saw only two
        // occurrences (from the depth-2 node) and missed the root.
        let trace = node(
            "prog_a",
            0,
            vec![node(
                "prog_b",
                1,
                vec![node("prog_a", 2, vec![node("prog_a", 3, vec![])])],
            )],
        );
        let known: Vec<String> = vec!["prog_a".into(), "prog_b".into()];
        let findings = analyze_cpi_trace(&trace, &known);
        assert!(
            findings
                .iter()
                .any(|f| f.reason.contains("re-enters program prog_a 3 times")),
            "expected root-level revisit finding, got: {:?}",
            findings
        );
    }

    #[test]
    fn trace_root_is_same_program_double_reentry_is_clean() {
        // A(root) -> B -> A is only TWO occurrences along the path — below
        // the >= 3 threshold and legitimately clean.
        let trace = node(
            "prog_a",
            0,
            vec![node("prog_b", 1, vec![node("prog_a", 2, vec![])])],
        );
        let known: Vec<String> = vec!["prog_a".into(), "prog_b".into()];
        let findings = analyze_cpi_trace(&trace, &known);
        assert!(
            !findings.iter().any(|f| f.reason.contains("re-enters")),
            "unexpected revisit finding: {:?}",
            findings
        );
    }

    #[test]
    fn trace_sibling_repetition_is_clean() {
        // A -> {A, A} repeats A across SIBLING branches — no single path
        // contains A more than twice, so this is not a drain chain.
        let trace = node(
            TOKEN_PROGRAM,
            0,
            vec![
                node("prog_a", 1, vec![]),
                node("prog_a", 1, vec![]),
                node("prog_a", 1, vec![]),
            ],
        );
        let known: Vec<String> = vec![TOKEN_PROGRAM.into(), "prog_a".into()];
        let findings = analyze_cpi_trace(&trace, &known);
        assert!(
            !findings.iter().any(|f| f.reason.contains("re-enters")),
            "sibling calls must not look like path re-entry: {:?}",
            findings
        );
    }

    #[test]
    fn trace_mixed_branch_deep_path_is_blocked() {
        // Two branches: one short (A, B), one deep with A repeated
        // (A -> A -> A). The max over paths must count the deep one (3).
        let trace = node(
            TOKEN_PROGRAM,
            0,
            vec![
                node("prog_a", 1, vec![node("prog_b", 2, vec![])]),
                node(
                    "prog_a",
                    1,
                    vec![node("prog_a", 2, vec![node("prog_a", 3, vec![])])],
                ),
            ],
        );
        let known: Vec<String> = vec![TOKEN_PROGRAM.into(), "prog_a".into(), "prog_b".into()];
        let findings = analyze_cpi_trace(&trace, &known);
        assert!(
            findings
                .iter()
                .any(|f| f.reason.contains("re-enters program prog_a 3 times")),
            "expected deep-path finding, got: {:?}",
            findings
        );
    }

    #[test]
    fn trace_cyclic_malformed_self_reference_is_blocked() {
        // Reentrancy-shaped: a program calling itself through a loop of
        // distinct intermediaries still yields a path count of 3.
        let trace = node(
            TOKEN_PROGRAM,
            0,
            vec![node(
                "prog_a",
                1,
                vec![node(
                    "prog_b",
                    2,
                    vec![node(
                        "prog_c",
                        3,
                        vec![node("prog_a", 4, vec![node("prog_a", 5, vec![])])],
                    )],
                )],
            )],
        );
        let known: Vec<String> = vec![
            TOKEN_PROGRAM.into(),
            "prog_a".into(),
            "prog_b".into(),
            "prog_c".into(),
        ];
        let findings = analyze_cpi_trace(&trace, &known);
        assert!(
            findings
                .iter()
                .any(|f| f.reason.contains("re-enters program prog_a 3 times")),
            "expected reentrancy finding, got: {:?}",
            findings
        );
    }

    #[test]
    fn trace_deep_chain_is_warning() {
        let trace = node(
            TOKEN_PROGRAM,
            0,
            vec![node(
                "prog_a",
                1,
                vec![node(
                    "prog_b",
                    2,
                    vec![node(
                        "prog_c",
                        3,
                        vec![node(
                            "prog_d",
                            4,
                            vec![node("prog_e", 5, vec![node("prog_f", 6, vec![])])],
                        )],
                    )],
                )],
            )],
        );
        let known: Vec<String> = vec![
            TOKEN_PROGRAM.into(),
            "prog_a".into(),
            "prog_b".into(),
            "prog_c".into(),
            "prog_d".into(),
            "prog_e".into(),
            "prog_f".into(),
        ];
        let findings = analyze_cpi_trace(&trace, &known);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == PatternSeverity::Warning && f.reason.contains("depth 6")),
            "expected depth warning, got: {:?}",
            findings
        );
    }

    #[test]
    fn trace_impersonated_program_is_blocked() {
        // "TokenkegQ..." is the real SPL Token address; a near-collision
        // sharing its first 8 chars must be blocked.
        let trace = node(
            TOKEN_PROGRAM,
            0,
            vec![node(
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DB",
                1,
                vec![],
            )],
        );
        let known: Vec<String> = vec![TOKEN_PROGRAM.into(), SYSTEM_PROGRAM.into()];
        let findings = analyze_cpi_trace(&trace, &known);
        assert!(
            findings
                .iter()
                .any(|f| f.reason.contains("vanity-impersonates")),
            "expected impersonation finding, got: {:?}",
            findings
        );
    }

    #[test]
    fn system_programs_are_always_trusted() {
        let known = system_programs();
        assert!(known.contains(&SYSTEM_PROGRAM.to_string()));
        assert!(known.contains(&TOKEN_PROGRAM.to_string()));
    }
}
