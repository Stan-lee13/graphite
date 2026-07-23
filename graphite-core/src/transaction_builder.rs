//! Transaction Construction Engine — ARCHITECTURE.md 3.2
//!
//! Builds a verified transaction plan from resolved accounts and a protocol
//! manifest's instruction definition. Produces a canonical serialization
//! that the verification pipeline can check against expected behavior.

use crate::account_resolution::ResolvedAccount;
use crate::solana_types::{AccountMeta, Instruction, Pubkey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TransactionBuilderError {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransactionPlan {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BuiltTransaction {
    pub program_id: String,
    pub protocol_version: String,
    pub instruction_name: String,
    pub instruction_discriminator: String,
    pub instruction_count: usize,
    pub account_count: usize,
    pub signer_count: usize,
    pub writable_count: usize,
    pub compute_budget_units: u64,
    pub accounts: Vec<BuiltAccountMeta>,
    pub data_hex: String,
    pub data_len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BuiltAccountMeta {
    pub address: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

pub fn build_transaction(
    plan: &TransactionPlan,
) -> Result<BuiltTransaction, TransactionBuilderError> {
    if plan.program_id.is_empty() {
        return Err(TransactionBuilderError::EmptyProgramId);
    }
    if plan.resolved_accounts.is_empty() {
        return Err(TransactionBuilderError::MissingAccounts);
    }

    // Validate discriminator is valid hex
    let disc_bytes = hex::decode(&plan.instruction_discriminator)
        .map_err(|e| TransactionBuilderError::InvalidDiscriminator(e.to_string()))?;

    // Build account metas from resolved accounts
    let account_metas: Vec<AccountMeta> = plan
        .resolved_accounts
        .iter()
        .map(|ra| {
            let pk = Pubkey::from_base58(&ra.address).map_err(|e| {
                TransactionBuilderError::InvalidPubkey(format!("{}: {}", ra.address, e))
            })?;
            Ok(AccountMeta::new(pk, ra.is_signer, ra.is_writable))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Build the actual Solana instruction (for downstream consumers)
    let program_pk = Pubkey::from_base58(&plan.program_id).map_err(|e| {
        TransactionBuilderError::InvalidProgramId(format!("{}: {}", plan.program_id, e))
    })?;
    let _instruction = Instruction::new(program_pk, account_metas.clone(), {
        let mut data = disc_bytes.clone();
        data.extend_from_slice(&plan.instruction_data);
        data
    });

    let signer_count = account_metas.iter().filter(|a| a.is_signer).count();
    let writable_count = account_metas.iter().filter(|a| a.is_writable).count();

    // Compute budget estimate (base + per-account + per-CPI)
    let compute_budget_units = 200_000u64
        + (plan.resolved_accounts.len() as u64 * 10_000)
        + (plan.allowed_cpis.len() as u64 * 50_000);

    let built_accounts: Vec<BuiltAccountMeta> = plan
        .resolved_accounts
        .iter()
        .map(|ra| BuiltAccountMeta {
            address: ra.address.clone(),
            is_signer: ra.is_signer,
            is_writable: ra.is_writable,
        })
        .collect();

    // Canonical serialization for audit trail
    let data_hex = hex::encode(&plan.instruction_data);

    Ok(BuiltTransaction {
        program_id: plan.program_id.clone(),
        protocol_version: plan.protocol_version.clone(),
        instruction_name: plan.instruction_name.clone(),
        instruction_discriminator: plan.instruction_discriminator.clone(),
        instruction_count: 1 + plan.expected_state_changes.len() + plan.allowed_cpis.len(),
        account_count: plan.resolved_accounts.len(),
        signer_count,
        writable_count,
        compute_budget_units,
        accounts: built_accounts,
        data_hex,
        data_len: plan.instruction_data.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_resolution::ResolvedAccount;

    fn make_account(addr: &str, signer: bool, writable: bool) -> ResolvedAccount {
        ResolvedAccount {
            address: addr.to_string(),
            role: "signer".to_string(),
            is_pda: false,
            is_signer: signer,
            is_writable: writable,
            pda_seeds: vec![],
            pda_mismatch: false,
        }
    }

    #[test]
    fn test_build_transaction_basic() {
        let plan = TransactionPlan {
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
        let built = build_transaction(&plan).unwrap();
        assert_eq!(built.account_count, 2);
        assert_eq!(built.signer_count, 1);
        assert_eq!(built.writable_count, 2);
        assert_eq!(built.instruction_name, "Transfer");
    }

    #[test]
    fn test_empty_program_rejected() {
        let plan = TransactionPlan {
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
        assert!(build_transaction(&plan).is_err());
    }

    #[test]
    fn test_invalid_discriminator_rejected() {
        let plan = TransactionPlan {
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
        assert!(build_transaction(&plan).is_err());
    }
}
