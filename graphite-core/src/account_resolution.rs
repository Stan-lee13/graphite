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
                    // Verify PDA can be re-derived, supporting dynamic template vars.
                    let program_pk = Pubkey::from_base58(&input.program_id)
                        .map_err(|e| AccountResolutionError::InvalidAddress(e.to_string()))?;
                    let resolved_seeds: Vec<Vec<u8>> = r
                        .pda_seeds
                        .iter()
                        .map(|s| resolve_pda_seed_template(s, input, &program_pk, &pubkeys))
                        .collect();
                    let seed_refs: Vec<&[u8]> =
                        resolved_seeds.iter().map(|s| s.as_slice()).collect();
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

fn resolve_pda_seed_template(
    seed: &str,
    input: &AccountResolutionInput,
    program_pk: &Pubkey,
    pubkeys: &[Pubkey],
) -> Vec<u8> {
    if seed == "{program_id}" {
        program_pk.as_bytes().to_vec()
    } else if seed == "{instruction_data}" {
        input.instruction_data.clone().unwrap_or_default()
    } else if let Some(slice_spec) = seed
        .strip_prefix("{instruction_data:")
        .and_then(|s| s.strip_suffix("}"))
    {
        let data = input.instruction_data.clone().unwrap_or_default();
        parse_slice_template(&data, slice_spec)
    } else if let Some(slice_spec) = seed
        .strip_prefix("{account_")
        .and_then(|s| s.strip_suffix("}"))
    {
        if let Some((index_str, range_spec)) = slice_spec.split_once(':') {
            if let Ok(index) = index_str.parse::<usize>() {
                let account_bytes = pubkeys
                    .get(index)
                    .map(|pk| pk.as_bytes().to_vec())
                    .unwrap_or_default();
                return parse_slice_template(&account_bytes, range_spec);
            }
        } else if let Ok(index) = slice_spec.parse::<usize>() {
            return pubkeys
                .get(index)
                .map(|pk| pk.as_bytes().to_vec())
                .unwrap_or_else(|| seed.as_bytes().to_vec());
        }
        seed.as_bytes().to_vec()
    } else if let Some(stripped) = seed.strip_prefix("0x") {
        hex::decode(stripped).unwrap_or_else(|_| seed.as_bytes().to_vec())
    } else {
        seed.as_bytes().to_vec()
    }
}

fn parse_slice_template(data: &[u8], slice_spec: &str) -> Vec<u8> {
    let parts: Vec<&str> = slice_spec.split(':').collect();
    match parts.as_slice() {
        [start, end] => {
            if let (Ok(start), Ok(end)) = (start.parse::<usize>(), end.parse::<usize>()) {
                return data.get(start..end).map(|s| s.to_vec()).unwrap_or_default();
            }
            data.to_vec()
        }
        [start] => {
            if let Ok(start) = start.parse::<usize>() {
                return data.get(start..).map(|s| s.to_vec()).unwrap_or_default();
            }
            data.to_vec()
        }
        _ => data.to_vec(),
    }
}

/// Derive a PDA from seeds (public API for external use).
pub fn derive_pda(
    seeds: &[&[u8]],
    program_id: &Pubkey,
) -> Result<(Pubkey, u8), AccountResolutionError> {
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
    use crate::manifest::{
        load_seed_manifests, AccountRoleDef, InstructionDef, ManifestVersion, ProtocolInfo,
        ProtocolManifest,
    };

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
            &[
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
            ],
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

    #[test]
    fn test_dynamic_pda_seed_resolution() {
        let program_id = "11111111111111111111111111111111";
        let program_pk = Pubkey::from_base58(program_id).unwrap();
        let signer_pk =
            Pubkey::from_base58("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU").unwrap();
        let (pda_pk, _bump) = solana_types::find_program_address(
            &[program_pk.as_bytes(), signer_pk.as_bytes()],
            &program_pk,
        )
        .unwrap();

        let manifest = ProtocolManifest {
            graphite_manifest_version: "1.0".to_string(),
            protocol: ProtocolInfo {
                name: "DynamicPdaTest".to_string(),
                program_id: program_id.to_string(),
                website: String::new(),
                github: String::new(),
            },
            version: ManifestVersion {
                label: "1.0".to_string(),
                effective_from_slot: 0,
                previous_version_ref: None,
            },
            instructions: vec![InstructionDef {
                name: "DynamicPda".to_string(),
                discriminator: "deadbeef".to_string(),
                accounts: vec![
                    AccountRoleDef {
                        name: "authority".to_string(),
                        role: "signer".to_string(),
                        is_writable: false,
                        is_signer: true,
                        pda_seeds: vec![],
                    },
                    AccountRoleDef {
                        name: "derived".to_string(),
                        role: "pda".to_string(),
                        is_writable: false,
                        is_signer: false,
                        pda_seeds: vec!["{program_id}".to_string(), "{account_0}".to_string()],
                    },
                ],
                expected_state_changes: vec![],
                allowed_cpis: vec![],
                risk_rules: vec![],
                variable_accounts: false,
            }],
            trust_tier: String::new(),
        };

        let mut registry = ManifestRegistry::new();
        registry
            .load_from_json(&serde_json::to_string(&manifest).unwrap())
            .unwrap();

        let input = AccountResolutionInput {
            program_id: program_id.to_string(),
            instruction_discriminator: "deadbeef".to_string(),
            account_addresses: vec![signer_pk.to_base58(), pda_pk.to_base58()],
            instruction_data: None,
        };
        let result = resolve_accounts(&input, &registry).unwrap();
        assert!(result.manifest_found);
        assert_eq!(result.resolved_accounts.len(), 2);
        assert!(result.resolved_accounts[1].is_pda);
        assert!(!result.resolved_accounts[1].pda_mismatch);
    }

    /// Build a manifest whose `derived` account is a PDA seeded from
    /// instruction data, then resolve with real data bytes.
    fn resolve_data_seeded(
        program_id: &str,
        seed_templates: &[&str],
        data: Vec<u8>,
        derived_address: &str,
    ) -> AccountResolutionResult {
        let program_pk = Pubkey::from_base58(program_id).unwrap();
        let manifest = ProtocolManifest {
            graphite_manifest_version: "1.0".to_string(),
            protocol: ProtocolInfo {
                name: "DataSeededPda".to_string(),
                program_id: program_id.to_string(),
                website: String::new(),
                github: String::new(),
            },
            version: ManifestVersion {
                label: "1.0".to_string(),
                effective_from_slot: 0,
                previous_version_ref: None,
            },
            instructions: vec![InstructionDef {
                name: "DynamicData".to_string(),
                discriminator: "deadbeef".to_string(),
                accounts: vec![
                    AccountRoleDef {
                        name: "authority".to_string(),
                        role: "signer".to_string(),
                        is_writable: false,
                        is_signer: true,
                        pda_seeds: vec![],
                    },
                    AccountRoleDef {
                        name: "derived".to_string(),
                        role: "pda".to_string(),
                        is_writable: true,
                        is_signer: false,
                        pda_seeds: seed_templates.iter().map(|s| s.to_string()).collect(),
                    },
                ],
                expected_state_changes: vec![],
                allowed_cpis: vec![],
                risk_rules: vec![],
                variable_accounts: false,
            }],
            trust_tier: String::new(),
        };
        let mut registry = ManifestRegistry::new();
        registry
            .load_from_json(&serde_json::to_string(&manifest).unwrap())
            .unwrap();
        let input = AccountResolutionInput {
            program_id: program_id.to_string(),
            instruction_discriminator: "deadbeef".to_string(),
            account_addresses: vec![
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
                derived_address.to_string(),
            ],
            instruction_data: Some(data.clone()),
        };
        let _ = program_pk;
        resolve_accounts(&input, &registry).unwrap()
    }

    /// Program ID used for the pinned vectors: the REAL Pump.fun program
    /// (verified executable on mainnet 2026-08-08) — never a fabricated key.
    const DATA_SEED_PROGRAM: &str = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
    /// Pinned PDAs computed with the OFFICIAL Solana JS SDK
    /// (`@solana/web3.js` PublicKey.findProgramAddressSync) — an independent
    /// implementation of the canonical derivation. Verified to equal the Rust
    /// `find_program_address` result (the static+prefix test asserts it).
    /// Seed [0xde,0xad,0xbe,0xef] under DATA_SEED_PROGRAM:
    const DEADBEEF_PDA: &str = "EyRyjhh8yQDgt7R2CZ4admNJgCaganGp1kwi8eCghZnP";
    /// Seeds [b"prefix", 0xdeadbeef] under DATA_SEED_PROGRAM:
    const PREFIX_DEADBEEF_PDA: &str = "UnoGavuCdb13po8gKXpjdj6833NHsw4vXHoi8aq7W71";

    /// The `{instruction_data:start:end}` slice template must extract the
    /// EXACT bytes the manifest declares and derive the correct PDA — the
    /// roadmap's "dynamic PDA seed resolution" (seeds that depend on
    /// instruction arguments).
    #[test]
    fn test_instruction_data_slice_template_derives_known_pda() {
        // data = [0,0,0,0] + 0xdeadbeef — the seed lives at bytes 4..8.
        let data = vec![0u8, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef];
        let result = resolve_data_seeded(
            DATA_SEED_PROGRAM,
            &["{instruction_data:4:8}"],
            data,
            DEADBEEF_PDA,
        );
        assert!(!result.resolved_accounts[1].pda_mismatch);
    }

    /// The suffix template `{instruction_data:start}` extracts from start to
    /// end of the data (Squads-style trailing-argument seeds).
    #[test]
    fn test_instruction_data_suffix_template_derives_known_pda() {
        let data = vec![0u8, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef];
        let result = resolve_data_seeded(
            DATA_SEED_PROGRAM,
            &["{instruction_data:4}"],
            data,
            DEADBEEF_PDA,
        );
        assert!(!result.resolved_accounts[1].pda_mismatch);
    }

    /// The whole-data template `{instruction_data}` (raw-UTF-8-style programs
    /// that seed a PDA with the full instruction payload).
    #[test]
    fn test_instruction_data_whole_template_derives_known_pda() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let result = resolve_data_seeded(
            DATA_SEED_PROGRAM,
            &["{instruction_data}"],
            data,
            DEADBEEF_PDA,
        );
        assert!(!result.resolved_accounts[1].pda_mismatch);
    }

    /// A static seed + instruction-data slice (e.g. ["{program_id}",
    /// "{instruction_data:8:16}"] style layouts).
    #[test]
    fn test_static_plus_instruction_data_template_derives_known_pda() {
        // seed = b"prefix" || 0xdeadbeef.
        let data = vec![0u8, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef];
        let program_pk = Pubkey::from_base58(DATA_SEED_PROGRAM).unwrap();
        let (expected, _bump) =
            solana_types::find_program_address(&[b"prefix", &data[4..8]], &program_pk).unwrap();
        assert_eq!(
            expected.to_base58(),
            PREFIX_DEADBEEF_PDA,
            "independently computed known answer must match the canonical derivation"
        );
        // The template list can mix static literals with data slices.
        let result = resolve_data_seeded(
            DATA_SEED_PROGRAM,
            &["prefix", "{instruction_data:4:8}"],
            data,
            &expected.to_base58(),
        );
        assert!(!result.resolved_accounts[1].pda_mismatch);
    }

    /// A DIFFERENT data payload must resolve to a DIFFERENT PDA — the seed
    /// really comes from the instruction arguments (false-positive guard).
    #[test]
    fn test_instruction_data_change_changes_derived_pda() {
        // Same manifest template, but different data bytes → different PDA.
        let data = vec![0u8, 0, 0, 0, 0xca, 0xfe, 0xba, 0xbe];
        let result = resolve_data_seeded(
            DATA_SEED_PROGRAM,
            &["{instruction_data:4:8}"],
            data,
            DEADBEEF_PDA,
        );
        assert!(
            result.resolved_accounts[1].pda_mismatch,
            "mutated instruction data must yield a different PDA (mismatch detected)"
        );
    }
}
