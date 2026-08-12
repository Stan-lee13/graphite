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
                category: String::new(),
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
                risk_class: String::new(),
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
                category: String::new(),
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
                risk_class: String::new(),
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

    // ───────────────────────────────────────────────────────────────────────
    // Drift + Kamino PDA grounding (C46) — every seed template and every
    // known-answer PDA below was verified against the OFFICIAL sources:
    //   Drift:  velocity-exchange/protocol-v2 (IDL + sdk/src/addresses/pda.ts)
    //   Kamino: Kamino-Finance/klend libs/klend-interface/src/pda.rs
    //           (+ klend-sdk codegen + live on-chain decoded streams)
    // Known-answer addresses are computed with the OFFICIAL
    // `@solana/web3.js` PublicKey.findProgramAddressSync — an independent
    // implementation — for real accounts (the Kamino mainnet lending market
    // and USDC reserve from the klend docs, and the Graphite devnet wallet).
    // ───────────────────────────────────────────────────────────────────────

    const DRIFT_PROGRAM: &str = "dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH";
    const KAMINO_PROGRAM: &str = "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD";
    const WALLET: &str = "CWb8MciizembLV66kisYcXo3Cb91hdszxw74QHpEJKZR";
    const KAMINO_MARKET: &str = "7u3HeHxYDLhnCoErrtycNokbQYbWGzLs6JSDqGAv5PfF";
    const KAMINO_RESERVE: &str = "D6q6wuQSrifJKZYpR1M8R4YawnLDtDsMmWM1NbBmgJ59";
    const SEED1: &str = "11111111111111111111111111111111";
    const SEED2: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

    // JS-SDK pinned known answers (findProgramAddressSync).
    const DRIFT_SPOT_MARKET_VAULT_1: &str = "DfYCNezifxAEsQbAJ1b3j6PX3JVBe8fu11KBhxsbw5d2";
    const DRIFT_USER_0: &str = "5FVw4c5aD1QfaEKqb57LGio6zLTxH2hR29Vuk9MuUPHM";
    const DRIFT_USER_STATS: &str = "E493Zerg74mec5ZvtxhPr5wwKKyfEScU2f3fpkmkWn8J";
    const DRIFT_SIGNER: &str = "JCNCMFXo5M5qwUPg2Utu1u6YWp3MbygxqBsBeXXJfrw";
    const KAMINO_LMA: &str = "9DrvZvyWh1HuAoZxvYWMvkf2XCzryCpGgHqrMjyDWpmo";
    const KAMINO_OBLIGATION: &str = "FH2DWzAo5fpCYwV8by18u6AmGKGFvzt4Un3nbSdz16FT";
    const KAMINO_RESERVE_LIQ_SUPPLY: &str = "JCdAwUu36ka4C9BjeZfMRSx549PmBSqEMzppjjzsMQRZ";
    const KAMINO_FEE_RECEIVER: &str = "FRhpLGAS3sYQLevt7tqkrkT8GT2BYNBnwcjM3Zbyqixq";
    const KAMINO_RESERVE_COLL_MINT: &str = "847kVN2ycaJxTMz3XDjFKGpVRhE2PdwmDrugMBg7C318";
    const KAMINO_RESERVE_COLL_SUPPLY: &str = "CeHP7ew8VbF3a4QyEqsVntnrZsKdR9zcY1jXid9hyZDq";
    const KAMINO_USER_META: &str = "HEJjihkfYGrRJJosvyGUQ1pGUoffEGis9a2ZpvNectbw";

    fn resolve_real(
        program: &str,
        disc: &str,
        accounts: &[&str],
        data: Option<Vec<u8>>,
    ) -> AccountResolutionResult {
        let registry = load_seed_manifests();
        let input = AccountResolutionInput {
            program_id: program.to_string(),
            instruction_discriminator: disc.to_string(),
            account_addresses: accounts.iter().map(|s| s.to_string()).collect(),
            instruction_data: data,
        };
        resolve_accounts(&input, &registry).unwrap()
    }

    fn seeds_of(program: &str, disc: &str, account_idx: usize) -> Vec<String> {
        let registry = load_seed_manifests();
        let ix = registry
            .find_instruction(program, disc)
            .unwrap_or_else(|| panic!("{program} {disc} not in seed manifests"));
        ix.accounts[account_idx].pda_seeds.clone()
    }

    // ───────────────────────────────────────────────────────────────────────
    // Jupiter DCA + Squads V4 PDA grounding (C52) — seed templates and
    // known-answer addresses verified against OFFICIAL sources AND live
    // mainnet accounts:
    //   Jupiter DCA: official IDL (jupiter-python-sdk embedded IDL, program
    //     DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M) + a real mainnet DCA
    //     account (Ck1Ct3vsMfzxeEM2RmKmTS4FVXoCB3YAUunKVFyNsFiq, whose stored
    //     user/inputMint/outputMint/idx were read off-chain) — the JS-SDK
    //     derivation ["dca", user, inputMint, outputMint, uid] reproduces the
    //     on-chain address exactly.
    //   Squads V4: official sdk/multisig/src/pda.ts getMultisigPda
    //     ["multisig", "multisig", createKey] + a real mainnet multisig
    //     (DDV1BEtsuZWM7mLAzmdur6VR6XWcZkXyZ1mUK2H58yqk, whose stored
    //     create_key 7vp2dDTnHgQHifJd8nCZxToUrQybe3MpWpa6ttnu5Jam was read
    //     off-chain) — matches the manifest seed template exactly.
    // ───────────────────────────────────────────────────────────────────────
    const DCA_PROGRAM: &str = "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M";
    const SQUADS_PROGRAM: &str = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";

    // Real mainnet DCA account + its stored fields (read from account data).
    const DCA_REAL_ACCOUNT: &str = "Ck1Ct3vsMfzxeEM2RmKmTS4FVXoCB3YAUunKVFyNsFiq";
    const DCA_REAL_USER: &str = "DodwnsRtPbkzJHC4AcoXdmT92GUUsRDQ6FxJfM4UDcem";
    const DCA_REAL_INPUT_MINT: &str = "So11111111111111111111111111111111111111112";
    const DCA_REAL_OUTPUT_MINT: &str = "DitHyRMQiSDhn5cnKMJV2CDDt6sVct96YrECiM49pump";
    const DCA_REAL_UID: u64 = 1_786_396_192;

    // Real mainnet Squads multisig + its stored create_key.
    const SQUADS_REAL_MULTISIG: &str = "DDV1BEtsuZWM7mLAzmdur6VR6XWcZkXyZ1mUK2H58yqk";
    const SQUADS_REAL_CREATE_KEY: &str = "7vp2dDTnHgQHifJd8nCZxToUrQybe3MpWpa6ttnu5Jam";

    #[test]
    fn test_dca_seed_templates_match_official_idl() {
        // openDca (disc 2441b93601d264a3): dca account is at index 1 in the
        // official IDL order [dca(0), user(1), inputMint(2), outputMint(3), ...]
        // with seeds ["dca", user, inputMint, outputMint, applicationIdx].
        assert_eq!(
            seeds_of(DCA_PROGRAM, "2441b93601d264a3", 0),
            vec![
                "dca",
                "{account_1}",
                "{account_2}",
                "{account_3}",
                "{instruction_data:8:16}"
            ]
        );
        // openDcaV2 (disc 8e772b6da2340bb1): [dca(0), user(1), payer(2),
        // inputMint(3), outputMint(4), ...].
        assert_eq!(
            seeds_of(DCA_PROGRAM, "8e772b6da2340bb1", 0),
            vec![
                "dca",
                "{account_1}",
                "{account_3}",
                "{account_4}",
                "{instruction_data:8:16}"
            ]
        );
    }

    #[test]
    fn test_dca_pda_derives_real_mainnet_account() {
        // openDca with uid = the real account's idx: instruction data is the
        // 8-byte disc + applicationIdx (u64 LE) at bytes 8..16.
        let mut data = vec![0u8; 16];
        data[0..8].copy_from_slice(&hex::decode("2441b93601d264a3").unwrap());
        data[8..16].copy_from_slice(&DCA_REAL_UID.to_le_bytes());
        // IDL account order: [dca, user, inputMint, outputMint, ...].
        let r = resolve_real(
            DCA_PROGRAM,
            "2441b93601d264a3",
            &[
                DCA_REAL_ACCOUNT,
                DCA_REAL_USER,
                DCA_REAL_INPUT_MINT,
                DCA_REAL_OUTPUT_MINT,
                WALLET,
                WALLET,
                WALLET,
                WALLET,
                WALLET,
                WALLET,
                WALLET,
                WALLET,
            ],
            Some(data.clone()),
        );
        assert!(
            !r.resolved_accounts[0].pda_mismatch,
            "dca PDA must match the real mainnet account"
        );
        assert_eq!(r.resolved_accounts[0].address, DCA_REAL_ACCOUNT);
        // The passed dca address differs from a derived one => mismatch flagged.
        let r2 = resolve_real(
            DCA_PROGRAM,
            "2441b93601d264a3",
            &[
                WALLET, // WRONG dca address
                DCA_REAL_USER,
                DCA_REAL_INPUT_MINT,
                DCA_REAL_OUTPUT_MINT,
                WALLET,
                WALLET,
                WALLET,
                WALLET,
                WALLET,
                WALLET,
                WALLET,
                WALLET,
            ],
            Some(data.clone()),
        );
        assert!(
            r2.resolved_accounts[0].pda_mismatch,
            "wrong dca address must be flagged as a PDA mismatch"
        );
    }

    #[test]
    fn test_squads_multisig_seed_template_matches_official_sdk() {
        // multisigCreateV2 (disc 32ddc75d28f58be9): multisig is account index
        // 2, createKey at index 3; seeds ["multisig", "multisig", createKey]
        // per official sdk/multisig/src/pda.ts getMultisigPda.
        assert_eq!(
            seeds_of(SQUADS_PROGRAM, "32ddc75d28f58be9", 2),
            vec!["multisig", "multisig", "{account_3}"]
        );
    }

    #[test]
    fn test_squads_multisig_derives_real_mainnet_account() {
        let r = resolve_real(
            SQUADS_PROGRAM,
            "32ddc75d28f58be9",
            &[
                WALLET,                 // programConfig
                WALLET,                 // treasury
                SQUADS_REAL_MULTISIG,   // multisig (the real on-chain PDA)
                SQUADS_REAL_CREATE_KEY, // createKey
                WALLET,                 // creator
                WALLET,                 // systemProgram
            ],
            None,
        );
        assert!(
            !r.resolved_accounts[2].pda_mismatch,
            "multisig PDA must match the real mainnet multisig"
        );
        assert_eq!(r.resolved_accounts[2].address, SQUADS_REAL_MULTISIG);
        // A different create_key must fail the derivation.
        let r2 = resolve_real(
            SQUADS_PROGRAM,
            "32ddc75d28f58be9",
            &[
                WALLET,
                WALLET,
                WALLET, // WRONG multisig address
                SQUADS_REAL_CREATE_KEY,
                WALLET,
                WALLET,
            ],
            None,
        );
        assert!(
            r2.resolved_accounts[2].pda_mismatch,
            "wrong multisig address must be flagged as a PDA mismatch"
        );
    }

    #[test]
    fn test_drift_pda_templates_match_official_sdk() {
        // deposit/transferDeposit/withdraw: marketIndex is the FIRST arg
        // (u16 LE at instruction bytes 8..10) — verified in the IDL.
        assert_eq!(
            seeds_of(DRIFT_PROGRAM, "f223c68952e1f2b6", 4), // deposit spotMarketVault
            vec!["spot_market_vault", "{instruction_data:8:10}"]
        );
        assert_eq!(
            seeds_of(DRIFT_PROGRAM, "b712469c946da122", 4), // withdraw spotMarketVault
            vec!["spot_market_vault", "{instruction_data:8:10}"]
        );
        // initializeUser: [b"user", authority, subAccountId u16 LE]; the IDL
        // places authority at account index 3 and subAccountId as the first
        // arg (bytes 8..10).
        assert_eq!(
            seeds_of(DRIFT_PROGRAM, "6f11b9fa3c7a26fe", 0), // user
            vec!["user", "{account_3}", "{instruction_data:8:10}"]
        );
        // initializeUserStats: [b"user_stats", authority]; authority at index 2.
        assert_eq!(
            seeds_of(DRIFT_PROGRAM, "fef34862fb82a8d5", 0), // userStats
            vec!["user_stats", "{account_2}"]
        );
        // drift_signer: [b"drift_signer"] — SDK pda.ts getDriftSignerPublicKey.
        assert_eq!(
            seeds_of(DRIFT_PROGRAM, "b712469c946da122", 5), // withdraw driftSigner
            vec!["drift_signer"]
        );
    }

    #[test]
    fn test_drift_spot_market_vault_derives_js_sdk_known_answer() {
        // deposit(marketIndex=1, amount=0, reduceOnly=false):
        // 8-byte disc + [01 00] at bytes 8..10.
        let mut data = vec![0u8; 19];
        data[0..8].copy_from_slice(&hex::decode("f223c68952e1f2b6").unwrap());
        data[8] = 0x01;
        data[9] = 0x00; // marketIndex = 1 (u16 LE)
        let r = resolve_real(
            DRIFT_PROGRAM,
            "f223c68952e1f2b6",
            &[
                WALLET,
                WALLET,
                WALLET,
                WALLET,
                DRIFT_SPOT_MARKET_VAULT_1,
                WALLET,
                WALLET,
            ],
            Some(data),
        );
        assert!(!r.resolved_accounts[4].pda_mismatch, "vault PDA must match");
        assert_eq!(r.resolved_accounts[4].address, DRIFT_SPOT_MARKET_VAULT_1);
    }

    #[test]
    fn test_drift_user_derives_js_sdk_known_answer() {
        // initializeUser(subAccountId=0, name=[0;32]): [b"user", authority,
        // 00 00] where authority is account index 3.
        let mut data = vec![0u8; 42];
        data[0..8].copy_from_slice(&hex::decode("6f11b9fa3c7a26fe").unwrap());
        let r = resolve_real(
            DRIFT_PROGRAM,
            "6f11b9fa3c7a26fe",
            &[DRIFT_USER_0, WALLET, WALLET, WALLET, WALLET, WALLET, WALLET],
            Some(data),
        );
        assert!(!r.resolved_accounts[0].pda_mismatch, "user PDA must match");
        assert_eq!(r.resolved_accounts[0].address, DRIFT_USER_0);
    }

    #[test]
    fn test_drift_user_stats_derives_js_sdk_known_answer() {
        // initializeUserStats(): [b"user_stats", authority] with authority at
        // account index 2.
        let data = hex::decode("fef34862fb82a8d5").unwrap();
        let r = resolve_real(
            DRIFT_PROGRAM,
            "fef34862fb82a8d5",
            &[DRIFT_USER_STATS, WALLET, WALLET, WALLET, WALLET, WALLET],
            Some(data),
        );
        assert!(
            !r.resolved_accounts[0].pda_mismatch,
            "user_stats PDA must match"
        );
        assert_eq!(r.resolved_accounts[0].address, DRIFT_USER_STATS);
    }

    #[test]
    fn test_drift_signer_derives_js_sdk_known_answer() {
        // withdraw(marketIndex=1): drift_signer = [b"drift_signer"].
        let mut data = vec![0u8; 19];
        data[0..8].copy_from_slice(&hex::decode("b712469c946da122").unwrap());
        data[8] = 0x01;
        let r = resolve_real(
            DRIFT_PROGRAM,
            "b712469c946da122",
            &[
                WALLET,
                WALLET,
                WALLET,
                WALLET,
                DRIFT_SPOT_MARKET_VAULT_1,
                DRIFT_SIGNER,
                WALLET,
                WALLET,
            ],
            Some(data),
        );
        assert!(
            !r.resolved_accounts[5].pda_mismatch,
            "drift_signer PDA must match"
        );
        assert_eq!(r.resolved_accounts[5].address, DRIFT_SIGNER);
    }

    #[test]
    fn test_kamino_pda_templates_match_official_pda_rs() {
        // borrowObligationLiquidity lendingMarketAuthority: pda.rs
        // lending_market_authority = [b"lma", lending_market]; lending market
        // is account index 2 in this instruction.
        assert_eq!(
            seeds_of(KAMINO_PROGRAM, "797f12cc49f5e141", 3), // lendingMarketAuthority
            vec!["lma", "{account_2}"]
        );
        // initObligation obligation: pda.rs obligation(tag, id, owner,
        // lending_market, seed1, seed2) — the manifest carries the six seeds
        // with tag/id from instruction bytes 8..10 and owner/market/seed1/
        // seed2 from account indices 0/3/4/5 (codegen-verified order).
        assert_eq!(
            seeds_of(KAMINO_PROGRAM, "fb0ae74c1b0b9f60", 2),
            vec![
                "{instruction_data:8:9}",
                "{instruction_data:9:10}",
                "{account_0}",
                "{account_3}",
                "{account_4}",
                "{account_5}"
            ]
        );
        // initReserve reserve PDAs: pda.rs reserve_liquidity_supply / fee /
        // coll_mint / coll_supply, all seeded with the reserve account at
        // account index 3 (IDL-verified).
        for (idx, prefix) in [
            (5, "reserve_liq_supply"),
            (6, "fee_receiver"),
            (7, "reserve_coll_mint"),
            (8, "reserve_coll_supply"),
        ] {
            assert_eq!(
                seeds_of(KAMINO_PROGRAM, "8af547e19904032b", idx),
                vec![prefix, "{account_3}"]
            );
        }
        // initUserMetadata userMetadata: pda.rs user_metadata = [b"user_meta",
        // owner]; owner is account index 0 (on-chain decoded stream: 6 accounts,
        // owner first).
        assert_eq!(
            seeds_of(KAMINO_PROGRAM, "75a9b045c5170fa2", 2),
            vec!["user_meta", "{account_0}"]
        );
    }

    #[test]
    fn test_kamino_lma_derives_js_sdk_known_answer() {
        // borrowObligationLiquidity: [b"lma", lending_market] — lendingMarket
        // at account index 2.
        let r = resolve_real(
            KAMINO_PROGRAM,
            "797f12cc49f5e141",
            &[
                WALLET,
                WALLET,
                KAMINO_MARKET,
                KAMINO_LMA,
                WALLET,
                WALLET,
                WALLET,
                WALLET,
                WALLET,
                WALLET,
                WALLET,
                WALLET,
            ],
            None,
        );
        assert!(!r.resolved_accounts[3].pda_mismatch, "lma PDA must match");
        assert_eq!(r.resolved_accounts[3].address, KAMINO_LMA);
    }

    #[test]
    fn test_kamino_obligation_derives_js_sdk_known_answer() {
        // initObligation(tag=0, id=0): seeds [00, 00, owner(acct0), market(
        // acct3), seed1(acct4), seed2(acct5)].
        let mut data = vec![0u8; 10];
        data[0..8].copy_from_slice(&hex::decode("fb0ae74c1b0b9f60").unwrap());
        let r = resolve_real(
            KAMINO_PROGRAM,
            "fb0ae74c1b0b9f60",
            &[
                WALLET,
                WALLET,
                KAMINO_OBLIGATION,
                KAMINO_MARKET,
                SEED1,
                SEED2,
                WALLET,
                WALLET,
                WALLET,
            ],
            Some(data),
        );
        assert!(
            !r.resolved_accounts[2].pda_mismatch,
            "obligation PDA must match"
        );
        assert_eq!(r.resolved_accounts[2].address, KAMINO_OBLIGATION);
    }

    #[test]
    fn test_kamino_reserve_pdas_derive_js_sdk_known_answers() {
        // initReserve: four PDAs seeded with the reserve account (index 3).
        let r = resolve_real(
            KAMINO_PROGRAM,
            "8af547e19904032b",
            &[
                WALLET,
                WALLET,
                WALLET,
                KAMINO_RESERVE,
                WALLET,
                KAMINO_RESERVE_LIQ_SUPPLY,
                KAMINO_FEE_RECEIVER,
                KAMINO_RESERVE_COLL_MINT,
                KAMINO_RESERVE_COLL_SUPPLY,
                WALLET,
                WALLET,
                WALLET,
                WALLET,
                WALLET,
            ],
            None,
        );
        for (idx, expected) in [
            (5, KAMINO_RESERVE_LIQ_SUPPLY),
            (6, KAMINO_FEE_RECEIVER),
            (7, KAMINO_RESERVE_COLL_MINT),
            (8, KAMINO_RESERVE_COLL_SUPPLY),
        ] {
            assert!(
                !r.resolved_accounts[idx].pda_mismatch,
                "reserve PDA {idx} must match"
            );
            assert_eq!(r.resolved_accounts[idx].address, expected);
        }
    }

    #[test]
    fn test_kamino_user_metadata_derives_js_sdk_known_answer() {
        // initUserMetadata: [b"user_meta", owner] — owner at account index 0.
        let r = resolve_real(
            KAMINO_PROGRAM,
            "75a9b045c5170fa2",
            &[WALLET, WALLET, KAMINO_USER_META, WALLET, WALLET, WALLET],
            None,
        );
        assert!(
            !r.resolved_accounts[2].pda_mismatch,
            "user_metadata PDA must match"
        );
        assert_eq!(r.resolved_accounts[2].address, KAMINO_USER_META);
    }
}
