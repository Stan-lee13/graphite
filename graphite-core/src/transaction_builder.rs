//! Instruction summary — ARCHITECTURE.md 3.2 ("Transaction Construction
//! Engine")
//!
//! Turns a verified instruction plan — resolved accounts plus the manifest's
//! instruction definition — into an [`InstructionSummary`]: a validated
//! SUMMARY of the one instruction being verified (its accounts with their
//! privileges, counts, the payload as hex, a compute ESTIMATE) that the
//! verdict reports as `transaction`.
//!
//! It builds no transaction and produces no serialization. Round 29 (audit
//! 2026-10-20): this header said it "produces a canonical serialization that
//! the verification pipeline can check"; nothing here ever built wire bytes,
//! and nothing checks against any. Round 30: the public names said it too —
//! `build_transaction` returning a `BuiltTransaction` — so the types are now
//! named for what they are and the old names are deprecated aliases. The
//! bytes that are signed are the caller's artifact, read by
//! `tx_artifact::parse_transaction`, and a verdict binds to their digest
//! (`scope.transaction_sha256`) — not to anything here. The JSON field keeps
//! its name (`transaction`, `compute_budget_units`) because it is published
//! contract; the schema says what each is.
//!
//! Duplicate accounts are NOT refused. An instruction may legitimately name
//! one account in several positions (a token transfer to its own source, an
//! Anchor program passing the same account for two optional slots); the
//! runtime de-duplicates keys at the message level, not per instruction. The
//! counts below are therefore counts of POSITIONS: an account named twice as
//! a signer is two of `signer_count`. Whether a repeated account is allowed
//! where it appears is the manifest's and L2's question, not this module's.

use crate::account_resolution::ResolvedAccount;
use crate::solana_types::{AccountMeta, Pubkey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum InstructionPlanError {
    #[error("transaction plan is missing accounts")]
    MissingAccounts,
    #[error("program_id cannot be empty")]
    EmptyProgramId,
    #[error("instruction discriminator is invalid hex: {0}")]
    InvalidDiscriminator(String),
    #[error("invalid account address (not valid base58 or wrong length): {0}")]
    InvalidPubkey(String),
    #[error("invalid program_id (not valid base58 or wrong length): {0}")]
    InvalidProgramId(String),
}

/// The plan of the ONE described instruction a verification checks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstructionPlan {
    pub program_id: String,
    pub protocol_version: String,
    pub instruction_discriminator: String, // hex
    pub instruction_name: String,
    pub resolved_accounts: Vec<ResolvedAccount>,
    pub expected_state_changes: Vec<String>,
    pub allowed_cpis: Vec<String>,
    #[serde(default)]
    pub instruction_data: Vec<u8>,
}

/// A validated summary of the described instruction — the verdict's
/// `transaction` field. Not a transaction: one instruction, no fee payer, no
/// blockhash, no signatures, no bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstructionSummary {
    pub program_id: String,
    pub protocol_version: String,
    pub instruction_name: String,
    pub instruction_discriminator: String,
    /// Always 1: the summary covers the described instruction only.
    pub instruction_count: usize,
    pub account_count: usize,
    pub signer_count: usize,
    pub writable_count: usize,
    /// A heuristic ESTIMATE (base + per account + per declared CPI), never a
    /// measurement. On the wire as `compute_budget_units` (published
    /// contract); what the bytes request is `scope.compute_budget`, what a
    /// simulation consumed is L3's.
    #[serde(rename = "compute_budget_units")]
    pub compute_units_estimate: u64,
    pub accounts: Vec<InstructionSummaryAccount>,
    pub data_hex: String,
    pub data_len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstructionSummaryAccount {
    pub address: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// Deprecated: [`InstructionPlanError`].
#[deprecated(
    since = "0.3.0-beta",
    note = "renamed InstructionPlanError: nothing here builds a transaction"
)]
pub type TransactionBuilderError = InstructionPlanError;
/// Deprecated: [`InstructionPlan`].
#[deprecated(
    since = "0.3.0-beta",
    note = "renamed InstructionPlan: it plans one instruction"
)]
pub type TransactionPlan = InstructionPlan;
/// Deprecated: [`InstructionSummary`].
#[deprecated(
    since = "0.3.0-beta",
    note = "renamed InstructionSummary: a summary of one instruction, not a built transaction"
)]
pub type BuiltTransaction = InstructionSummary;
/// Deprecated: [`InstructionSummaryAccount`].
#[deprecated(since = "0.3.0-beta", note = "renamed InstructionSummaryAccount")]
pub type BuiltAccountMeta = InstructionSummaryAccount;

/// Deprecated: [`summarize_instruction`]. It never built a transaction.
#[deprecated(
    since = "0.3.0-beta",
    note = "renamed summarize_instruction: it builds no transaction and no bytes"
)]
pub fn build_transaction(
    plan: &InstructionPlan,
) -> Result<InstructionSummary, InstructionPlanError> {
    summarize_instruction(plan)
}

/// Validate the plan and summarize the described instruction.
pub fn summarize_instruction(
    plan: &InstructionPlan,
) -> Result<InstructionSummary, InstructionPlanError> {
    if plan.program_id.is_empty() {
        return Err(InstructionPlanError::EmptyProgramId);
    }
    if plan.resolved_accounts.is_empty() {
        return Err(InstructionPlanError::MissingAccounts);
    }

    // The discriminator must be hex; its bytes are not used further. (A copy
    // of discriminator || payload used to be built below and thrown away —
    // dead work removed in Round 29.)
    hex::decode(&plan.instruction_discriminator)
        .map_err(|e| InstructionPlanError::InvalidDiscriminator(e.to_string()))?;

    // Build account metas from resolved accounts
    let account_metas: Vec<AccountMeta> = plan
        .resolved_accounts
        .iter()
        .map(|ra| {
            let pk = Pubkey::from_base58(&ra.address).map_err(|e| {
                InstructionPlanError::InvalidPubkey(format!("{}: {}", ra.address, e))
            })?;
            Ok(AccountMeta::new(pk, ra.is_signer, ra.is_writable))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Validate program_id is a valid pubkey (fail-fast on malformed input)
    let _program_pk = Pubkey::from_base58(&plan.program_id).map_err(|e| {
        InstructionPlanError::InvalidProgramId(format!("{}: {}", plan.program_id, e))
    })?;

    let signer_count = account_metas.iter().filter(|a| a.is_signer).count();
    let writable_count = account_metas.iter().filter(|a| a.is_writable).count();

    // Compute budget ESTIMATE (base + per-account + per-CPI). This is a
    // heuristic projection of the ComputeBudget units a transaction of this
    // shape is likely to need — it is NOT a measured value and must not be
    // read as one (the real consumed units come from simulation/L3 and the
    // audit trail's `compute_units`). C26 clean-room correction: the wire
    // name `compute_budget_units` implies a real budget; Round 30 named the
    // Rust field `compute_units_estimate` (the wire name is contract).
    let compute_units_estimate = 200_000u64
        + (plan.resolved_accounts.len() as u64 * 10_000)
        + (plan.allowed_cpis.len() as u64 * 50_000);

    let accounts: Vec<InstructionSummaryAccount> = plan
        .resolved_accounts
        .iter()
        .map(|ra| InstructionSummaryAccount {
            address: ra.address.clone(),
            is_signer: ra.is_signer,
            is_writable: ra.is_writable,
        })
        .collect();

    // The instruction payload WITHOUT the discriminator (the discriminator is
    // carried separately in `instruction_discriminator`; the full wire bytes
    // are discriminator || payload). This is the audit payload projection,
    // NOT the canonical audit identity — the deterministic content_hash in
    // the verification result is the linkage key for the audit trail.
    let data_hex = hex::encode(&plan.instruction_data);

    Ok(InstructionSummary {
        program_id: plan.program_id.clone(),
        protocol_version: plan.protocol_version.clone(),
        instruction_name: plan.instruction_name.clone(),
        instruction_discriminator: plan.instruction_discriminator.clone(),
        // The verified transaction plan is exactly ONE instruction (the one
        // being verified). C26 clean-room correction: this used to be
        // `1 + state_changes.len() + allowed_cpis.len()`, a fabricated count
        // that grew with manifest metadata and misled audit consumers into
        // reading it as the transaction's real instruction count.
        instruction_count: 1,
        account_count: plan.resolved_accounts.len(),
        signer_count,
        writable_count,
        compute_units_estimate,
        accounts,
        data_hex,
        data_len: plan.instruction_data.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_resolution::{AccountIdentity, ResolvedAccount};

    fn make_account(addr: &str, signer: bool, writable: bool) -> ResolvedAccount {
        ResolvedAccount {
            address: addr.to_string(),
            role: "signer".to_string(),
            name: String::new(),
            is_pda: false,
            is_signer: signer,
            is_writable: writable,
            pda_seeds: vec![],
            identity: AccountIdentity::Unverified,
            expected_address_mismatch: false,
            pda_mismatch: false,
            privilege_mismatch: false,
        }
    }

    #[test]
    fn test_build_transaction_basic() {
        let plan = InstructionPlan {
            program_id: "11111111111111111111111111111111".to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: "02000000".to_string(),
            instruction_name: "Transfer".to_string(),
            resolved_accounts: vec![
                make_account("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", true, true),
                make_account("8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", false, true),
            ],
            expected_state_changes: vec!["debits from".to_string(), "credits to".to_string()],
            allowed_cpis: vec![],
            instruction_data: vec![],
        };
        let built = summarize_instruction(&plan).unwrap();
        assert_eq!(built.account_count, 2);
        assert_eq!(built.signer_count, 1);
        assert_eq!(built.writable_count, 2);
        assert_eq!(built.instruction_name, "Transfer");
    }

    #[test]
    fn test_empty_program_rejected() {
        let plan = InstructionPlan {
            program_id: "".to_string(),
            protocol_version: "1.0".to_string(),
            instruction_discriminator: "02000000".to_string(),
            instruction_name: "Transfer".to_string(),
            resolved_accounts: vec![make_account(
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                true,
                true,
            )],
            expected_state_changes: vec![],
            allowed_cpis: vec![],
            instruction_data: vec![],
        };
        assert!(summarize_instruction(&plan).is_err());
    }

    #[test]
    fn test_invalid_discriminator_rejected() {
        let plan = InstructionPlan {
            program_id: "11111111111111111111111111111111".to_string(),
            protocol_version: "1.0".to_string(),
            instruction_discriminator: "not-hex!".to_string(),
            instruction_name: "Transfer".to_string(),
            resolved_accounts: vec![make_account(
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                true,
                true,
            )],
            expected_state_changes: vec![],
            allowed_cpis: vec![],
            instruction_data: vec![],
        };
        assert!(summarize_instruction(&plan).is_err());
    }

    /// An account in two positions is two positions: the plan builds, and
    /// the counts are per position (Round 29: documented, not refused).
    #[test]
    fn an_account_named_twice_is_counted_per_position() {
        let payer = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
        let plan = InstructionPlan {
            program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            protocol_version: "1.0".to_string(),
            instruction_discriminator: "03".to_string(),
            instruction_name: "Transfer".to_string(),
            resolved_accounts: vec![
                make_account(payer, false, true),
                make_account(payer, false, true),
                make_account(payer, true, false),
            ],
            expected_state_changes: vec![],
            allowed_cpis: vec![],
            instruction_data: vec![1, 0, 0, 0, 0, 0, 0, 0],
        };
        let built = summarize_instruction(&plan).unwrap();
        assert_eq!(built.account_count, 3);
        assert_eq!(built.writable_count, 2);
        assert_eq!(built.signer_count, 1);
        assert_eq!(built.data_hex, "0100000000000000");
        assert_eq!(built.data_len, 8);
    }

    #[test]
    fn test_invalid_account_address_rejected() {
        let plan = InstructionPlan {
            program_id: "11111111111111111111111111111111".to_string(),
            protocol_version: "1.0".to_string(),
            instruction_discriminator: "02000000".to_string(),
            instruction_name: "Transfer".to_string(),
            resolved_accounts: vec![make_account("not-a-valid-address!!!", true, true)],
            expected_state_changes: vec![],
            allowed_cpis: vec![],
            instruction_data: vec![],
        };
        assert!(matches!(
            summarize_instruction(&plan),
            Err(InstructionPlanError::InvalidPubkey(_))
        ));
    }
}
