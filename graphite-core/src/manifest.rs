//! Protocol Manifest Registry — loads, validates, and serves protocol manifests.
//!
//! A manifest describes a Solana program's instruction surface: discriminators,
//! account roles, expected state changes, allowed CPIs, and risk rules.
//! The registry is the first thing Graphite Core consults during verification
//! — if a program ID has a manifest, verification uses it; if not, Unknown
//! Protocol Mode activates (Constitution P6/P12).

use crate::solana_types::Pubkey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("manifest not found for program {0}")]
    NotFound(String),
    #[error("invalid manifest: {0}")]
    Invalid(String),
    #[error("manifest JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// A single instruction definition in a protocol manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstructionDef {
    pub name: String,
    /// Hex-encoded discriminator bytes (e.g., "02000000" for System Transfer).
    pub discriminator: String,
    pub accounts: Vec<AccountRoleDef>,
    pub expected_state_changes: Vec<String>,
    pub allowed_cpis: Vec<String>,
    pub risk_rules: Vec<String>,
}

/// Account role in an instruction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountRoleDef {
    pub name: String,
    pub role: String, // "signer" | "writable" | "readonly" | "pda"
    pub is_writable: bool,
    pub is_signer: bool,
    /// PDA seeds template, if this account is a PDA (e.g., ["mint", "{program_id}"]).
    #[serde(default)]
    pub pda_seeds: Vec<String>,
}

/// A protocol manifest — describes one Solana program's instruction surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolManifest {
    pub graphite_manifest_version: String,
    pub protocol: ProtocolInfo,
    pub version: ManifestVersion,
    pub instructions: Vec<InstructionDef>,
    #[serde(default)]
    pub trust_tier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolInfo {
    pub name: String,
    pub program_id: String,
    #[serde(default)]
    pub website: String,
    #[serde(default)]
    pub github: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManifestVersion {
    pub label: String,
    #[serde(default)]
    pub effective_from_slot: u64,
    #[serde(default)]
    pub previous_version_ref: Option<String>,
}

/// In-memory registry of loaded protocol manifests.
#[derive(Debug, Clone, Default)]
pub struct ManifestRegistry {
    manifests: HashMap<String, ProtocolManifest>,
}

impl ManifestRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a manifest from JSON.
    pub fn load_from_json(&mut self, json: &str) -> Result<&ProtocolManifest, ManifestError> {
        let manifest: ProtocolManifest = serde_json::from_str(json)?;
        self.validate(&manifest)?;
        let key = manifest.protocol.program_id.clone();
        self.manifests.insert(key.clone(), manifest);
        Ok(self.manifests.get(&key).unwrap())
    }

    /// Get a manifest by program ID (base58 string).
    pub fn get(&self, program_id: &str) -> Option<&ProtocolManifest> {
        self.manifests.get(program_id)
    }

    /// Get a manifest by Pubkey.
    pub fn get_by_pubkey(&self, pubkey: &Pubkey) -> Option<&ProtocolManifest> {
        self.get(&pubkey.to_base58())
    }

    /// List all loaded manifests.
    pub fn list(&self) -> Vec<&ProtocolManifest> {
        self.manifests.values().collect()
    }

    /// Find an instruction definition by discriminator (hex).
    pub fn find_instruction<'a>(
        &'a self,
        program_id: &str,
        discriminator_hex: &str,
    ) -> Option<&'a InstructionDef> {
        self.get(program_id)?.instructions.iter().find(|i| {
            i.discriminator.to_lowercase() == discriminator_hex.to_lowercase()
        })
    }

    fn validate(&self, manifest: &ProtocolManifest) -> Result<(), ManifestError> {
        if manifest.protocol.program_id.is_empty() {
            return Err(ManifestError::Invalid("program_id is empty".into()));
        }
        // Verify it's a valid base58 pubkey
        Pubkey::from_base58(&manifest.protocol.program_id)
            .map_err(|e| ManifestError::Invalid(format!("invalid program_id: {e}")))?;
        if manifest.instructions.is_empty() {
            return Err(ManifestError::Invalid("no instructions defined".into()));
        }
        for ix in &manifest.instructions {
            if ix.name.is_empty() {
                return Err(ManifestError::Invalid("instruction with empty name".into()));
            }
            // Empty discriminator is allowed (e.g., Memo program uses raw UTF-8 data
            // with no instruction selector — the entire data field IS the instruction)
            if !ix.discriminator.is_empty() {
                // Validate discriminator is valid hex
                hex::decode(&ix.discriminator)
                    .map_err(|e| ManifestError::Invalid(
                        format!("instruction '{}' has invalid discriminator hex: {e}", ix.name),
                    ))?;
            }
        }
        Ok(())
    }
}

/// Load the built-in seed protocol manifests.
/// These are embedded at compile time — no file system access needed.
pub fn load_seed_manifests() -> ManifestRegistry {
    let mut registry = ManifestRegistry::new();

    let _ = registry.load_from_json(include_str!("../protocols/system-program.json"));
    let _ = registry.load_from_json(include_str!("../protocols/spl-token.json"));
    let _ = registry.load_from_json(include_str!("../protocols/token-2022.json"));
    let _ = registry.load_from_json(include_str!("../protocols/stake-program.json"));
    let _ = registry.load_from_json(include_str!("../protocols/raydium-amm-v4.json"));
    let _ = registry.load_from_json(include_str!("../protocols/squads-v4.json"));
    let _ = registry.load_from_json(include_str!("../protocols/jupiter-v6.json"));
    let _ = registry.load_from_json(include_str!("../protocols/orca-whirlpools.json"));
    let _ = registry.load_from_json(include_str!("../protocols/meteora-dlmm.json"));
    let _ = registry.load_from_json(include_str!("../protocols/memo-program.json"));

    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_manifests_load_successfully() {
        let registry = load_seed_manifests();
        let manifests = registry.list();
        assert!(manifests.len() >= 10, "expected at least 2 seed manifests");
    }

    #[test]
    fn test_system_program_manifest_has_transfer() {
        let registry = load_seed_manifests();
        let manifest = registry.get("11111111111111111111111111111111")
            .expect("System Program manifest should be loaded");
        let transfer = manifest.instructions.iter()
            .find(|i| i.name == "Transfer")
            .expect("Transfer instruction should exist");
        assert_eq!(transfer.discriminator, "02000000");
    }

    #[test]
    fn test_spl_token_manifest_has_set_authority() {
        let registry = load_seed_manifests();
        let manifest = registry.get("TokenkegQfeZyiNwAJbNbGKPfxCWuBvf9Ss623VQ5DA")
            .expect("SPL Token manifest should be loaded");
        let set_auth = manifest.instructions.iter()
            .find(|i| i.name == "SetAuthority")
            .expect("SetAuthority instruction should exist");
        assert!(!set_auth.risk_rules.is_empty(), "SetAuthority should have risk rules");
    }

    #[test]
    fn test_invalid_manifest_rejected() {
        let mut registry = ManifestRegistry::new();
        let bad = r#"{"graphite_manifest_version":"1.0","protocol":{"name":"","program_id":"","website":"","github":""},"version":{"label":"1.0","effective_from_slot":0,"previous_version_ref":null},"instructions":[],"trust_tier":""}"#;
        assert!(registry.load_from_json(bad).is_err());
    }
}
