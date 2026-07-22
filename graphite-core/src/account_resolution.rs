//! Account Resolution Engine — ARCHITECTURE.md 3.1
//!
//! Given a program ID, instruction discriminator, and raw account addresses,
//! resolve each account's role using the protocol manifest. For PDAs, verify
//! that the address can be re-derived from the manifest's seed template.

use crate::manifest::ManifestRegistry;
use crate::solana_types::{self, Pubkey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum AccountResolutionError {
    #[error("no manifest for program {0}")]
    NoManifest(String),
    #[error("instruction discriminator {0} not found in manifest for {1}")]
    InstructionNotFound(String, String),
    #[error("account count mismatch: manifest expects {expected}, got {actual}")]
    AccountCountMismatch { expected: usize, actual: usize },
    #[error("invalid account address: {0}")]
    InvalidAddress(String),
    #[error("PDA derivation failed for account {account}: {reason}")]
    PdaDerivationFailed { account: String, reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResolvedAccount {
    pub address: String, // base58
    pub role: String,
    pub is_pda: bool,
    pub is_signer: bool,
    pub is_writable: bool,
    pub pda_seeds: Vec<String>,
    /// True if the account is a PDA and the derived address does not match
    /// the provided address. This is a SECURITY SIGNAL: the transaction is
    /// providing an account that doesn't match the protocol's expected PDA,
    /// which could indicate a spoofing attempt or a misconstructed transaction.
    /// The verification pipeline MUST treat this as a risk finding (Constitution P4).
    #[serde(default)]
    pub pda_mismatch: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountResolutionInput {
    pub program_id: String,
    pub instruction_discriminator: String, // hex
    pub account_addresses: Vec<String>,    // base58
    #[serde(default)]
    pub instruction_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountResolutionResult {
    pub resolved_accounts: Vec<ResolvedAccount>,
    pub resolution_order: Vec<usize>,
    pub instruction_name: String,
    pub manifest_found: bool,
}

/// Resolve accounts using a manifest registry.
/// If no manifest exists for the program, returns with manifest_found=false
/// (Unknown Protocol Mode handles this downstream).
pub fn resolve_accounts(
    input: &AccountResolutionInput,
    registry: &ManifestRegistry,
) -> Result<AccountResolutionResult, AccountResolutionError> {
    // Validate all addresses first
    let pubkeys: Vec<Pubkey> = input
        .account_addresses
        .iter()
        .map(|s| {
            Pubkey::from_base58(s)
                .map_err(|e| AccountResolutionError::InvalidAddress(format!("{s}: {e}")))
        })
        .collect::<Result<_, _>>()?;

    let _manifest = match registry.get(&input.program_id) {
        Some(m) => m,
        None => {
            // Unknown protocol — resolve with best-effort roles
            return Ok(resolve_unknown(&pubkeys, &input.program_id));
        }
    };

    let ix_def = registry
        .find_instruction(&input.program_id, &input.instruction_discriminator)
        .ok_or_else(|| {
            AccountResolutionError::InstructionNotFound(
                input.instruction_discriminator.clone(),
                input.program_id.clone(),
            )
        })?;

    // Check account count (manifest may have variable accounts, so only check minimum)
    if pubkeys.len() < ix_def.accounts.len() {
        return Err(AccountResolutionError::AccountCountMismatch {
            expected: ix_def.accounts.len(),
            actual: pubkeys.len(),
        });
    }

    let mut resolved = Vec::with_capacity(pubkeys.len());
    let mut order = Vec::with_capacity(pubkeys.len());
    let mut pda_mismatches: Vec<String> = Vec::new();

    for (i, pk) in pubkeys.iter().enumerate() {
        let role_def = ix_def.accounts.get(i);
        let (role, is_pda, is_signer, is_writable, pda_seeds) = match role_def {
            Some(r) => {
                let is_pda = !r.pda_seeds.is_empty();
                let seeds = if is_pda {
                    // Verify PDA can be re-derived
                    let program_pk = Pubkey::from_base58(&input.program_id)
                        .map_err(|e| AccountResolutionError::InvalidAddress(e.to_string()))?;
                    // Seeds may contain template vars like {program_id}
                    let resolved_seeds: Vec<Vec<u8>> = r.pda_seeds.iter().map(|s| {
                        if s == "{program_id}" {
                            program_pk.as_bytes().to_vec()
                        } else {
                            s.as_bytes().to_vec()
                        }
                    }).collect();
                    let seed_refs: Vec<&[u8]> = resolved_seeds.iter().map(|s| s.as_slice()).collect();
                    match solana_types::find_program_address(&seed_refs, &program_pk) {
                        Ok((derived_pk, _bump)) => {
                            if derived_pk != *pk {
                                // PDA MISMATCH: the provided address does not match
                                // the address derived from the manifest's seed template.
                                // This is a security signal — flag it for the risk engine.
                                // We do NOT hard-fail here because the verification pipeline
                                // needs to complete to produce a full report, but the
                                // mismatch MUST be surfaced as a Blocked risk finding.
                                pda_mismatches.push(pk.to_base58());
                            }
                            r.pda_seeds.clone()
                        }
                        Err(e) => {
                            return Err(AccountResolutionError::PdaDerivationFailed {
                                account: pk.to_base58(),
                                reason: e.to_string(),
                            })
                        }
                    }
                } else {
                    vec![]
                };
                (r.role.clone(), is_pda, r.is_signer, r.is_writable, seeds)
            }
            None => {
                // Extra accounts not in manifest — assign generic role
                ("extra".to_string(), false, false, false, vec![])
            }
        };

        let pda_mismatch = is_pda && pda_mismatches.contains(&pk.to_base58());
        resolved.push(ResolvedAccount {
            address: pk.to_base58(),
            role,
            is_pda,
            is_signer,
            is_writable,
            pda_seeds,
            pda_mismatch,
        });
        order.push(i);
    }

    Ok(AccountResolutionResult {
        resolved_accounts: resolved,
        resolution_order: order,
        instruction_name: ix_def.name.clone(),
        manifest_found: true,
    })
}

/// Best-effort resolution for unknown protocols (Constitution P12).
fn resolve_unknown(pubkeys: &[Pubkey], _program_id: &str) -> AccountResolutionResult {
    let resolved: Vec<ResolvedAccount> = pubkeys
        .iter()
        .map(|pk| ResolvedAccount {
            address: pk.to_base58(),
            role: "unknown".to_string(),
            is_pda: !solana_types::is_on_curve(pk),
            is_signer: false,
            is_writable: false,
            pda_seeds: vec![],
            pda_mismatch: false,
        })
        .collect();

    let order: Vec<usize> = (0..resolved.len()).collect();

    AccountResolutionResult {
        resolved_accounts: resolved,
        resolution_order: order,
        instruction_name: "Unknown".to_string(),
        manifest_found: false,
    }
}

/// Derive a PDA from seeds (public API for external use).
pub fn derive_pda(seeds: &[&[u8]], program_id: &Pubkey) -> Result<(Pubkey, u8), AccountResolutionError> {
    solana_types::find_program_address(seeds, program_id).map_err(|e| {
        AccountResolutionError::PdaDerivationFailed {
            account: "derivation".to_string(),
            reason: e.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::load_seed_manifests;

    fn make_input(program: &str, disc: &str, accounts: &[&str]) -> AccountResolutionInput {
        AccountResolutionInput {
            program_id: program.to_string(),
            instruction_discriminator: disc.to_string(),
            account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
            instruction_data: None,
        }
    }

    #[test]
    fn test_resolve_system_transfer() {
        let registry = load_seed_manifests();
        let input = make_input(
            "11111111111111111111111111111111",
            "02000000",
            &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],
        );
        let result = resolve_accounts(&input, &registry).unwrap();
        assert!(result.manifest_found);
        assert_eq!(result.instruction_name, "Transfer");
        assert_eq!(result.resolved_accounts.len(), 2);
        assert!(result.resolved_accounts[0].is_signer);
        assert!(result.resolved_accounts[0].is_writable);
    }

    #[test]
    fn test_unknown_protocol_returns_manifest_not_found() {
        let registry = load_seed_manifests();
        let input = make_input(
            "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi", // fake program
            "03000000",
            &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"],
        );
        let result = resolve_accounts(&input, &registry).unwrap();
        assert!(!result.manifest_found);
        assert_eq!(result.instruction_name, "Unknown");
    }

    #[test]
    fn test_instruction_not_found_in_manifest() {
        let registry = load_seed_manifests();
        let input = make_input(
            "11111111111111111111111111111111",
            "ffffffff", // unknown discriminator
            &["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"],
        );
        assert!(resolve_accounts(&input, &registry).is_err());
    }

    #[test]
    fn test_invalid_address_rejected() {
        let registry = load_seed_manifests();
        let input = make_input(
            "11111111111111111111111111111111",
            "02000000",
            &["not-a-valid-address!!!"],
        );
        assert!(resolve_accounts(&input, &registry).is_err());
    }
}
