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
    /// Whether this instruction has a variable number of accounts (e.g., aggregator routes).
    /// When true, the drainer pattern heuristic is skipped for this instruction.
    #[serde(default)]
    pub variable_accounts: bool,
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
        // Safe: attempt to retrieve the manifest we just inserted; return a
        // meaningful error if retrieval fails instead of panicking.
        match self.manifests.get(&key) {
            Some(m) => Ok(m),
            None => Err(ManifestError::Invalid(format!(
                "manifest insertion failed for key {}",
                key
            ))),
        }
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

    /// Find an instruction definition by discriminator (hex), allowing
    /// exact or input-starts-with-manifest matches for short discriminators.
    pub fn find_instruction<'a>(
        &'a self,
        program_id: &str,
        discriminator_hex: &str,
    ) -> Option<&'a InstructionDef> {
        self.get(program_id)?
            .instructions
            .iter()
            .find(|i| discriminator_matches(&i.discriminator, discriminator_hex))
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
                hex::decode(&ix.discriminator).map_err(|e| {
                    ManifestError::Invalid(format!(
                        "instruction '{}' has invalid discriminator hex: {e}",
                        ix.name
                    ))
                })?;
            }
            // Validate PDA seed templates when present. Support placeholder vars
            // that can be resolved at runtime for dynamic PDA derivation.
            for seed in ix.accounts.iter().flat_map(|a| a.pda_seeds.iter()) {
                if seed.starts_with("{") && !seed.ends_with("}") {
                    return Err(ManifestError::Invalid(format!(
                        "instruction '{}' has malformed PDA seed template: {}",
                        ix.name, seed
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Match an instruction's input discriminator against a manifest discriminator.
///
/// SECURITY (discriminator impersonation): the ONLY allowed matches are exact
/// equality or "the input starts with the FULL manifest discriminator". The
/// manifest discriminator is the authoritative prefix of the instruction
/// selector (e.g. Raydium's 1-byte "09" matches input "09aabbcc"), and the
/// input MUST contain the complete manifest discriminator.
///
/// An input that is merely a PREFIX of the manifest discriminator — truncated
/// or malformed instruction data — NEVER matches. The previous implementation
/// accepted `manifest_disc.starts_with(&input_disc) && input_disc.len() >= 4`,
/// which let an attacker craft a 4-char prefix of a known 8-byte Anchor
/// discriminator (e.g. "bb64" of Jupiter's "bb64facc31c4af14") to mint a
/// false `InstructionMatch` confidence signal on a DIFFERENT instruction.
pub fn discriminator_matches(manifest_disc: &str, input_disc: &str) -> bool {
    let manifest_disc = manifest_disc.to_lowercase();
    let input_disc = input_disc.to_lowercase();

    if manifest_disc.is_empty() {
        return false;
    }
    input_disc.starts_with(&manifest_disc)
}

/// Load the built-in seed protocol manifests.
/// These are embedded at compile time — no file system access needed.
pub fn load_seed_manifests() -> ManifestRegistry {
    let mut registry = ManifestRegistry::new();
    // Fail-closed: seed manifests are compile-time-baked via include_str!.
    // If one fails to parse or validate, log the error and abort with a
    // non-zero exit to avoid running in a weakened, unknown-protocol state.
    let seed_paths = [
        "../protocols/system-program.json",
        "../protocols/spl-token.json",
        "../protocols/token-2022.json",
        "../protocols/stake-program.json",
        "../protocols/raydium-amm-v4.json",
        "../protocols/squads-v4.json",
        "../protocols/jupiter-v6.json",
        "../protocols/orca-whirlpools.json",
        "../protocols/meteora-dlmm.json",
        "../protocols/memo-program.json",
        "../protocols/legacy-memo-program.json",
        "../protocols/spl-memo-program.json",
        "../protocols/ata-program.json",
        "../protocols/compute-budget.json",
        "../protocols/bpf-loader.json",
        "../protocols/bpf-loader-upgradeable.json",
        "../protocols/pump-fun.json",
        "../protocols/jupiter-dca.json",
        "../protocols/wormhole-core.json",
        "../protocols/metaplex-token-metadata.json",
    ];

    for p in &seed_paths {
        // include_str! requires a string literal; map path to literal explicitly
        let res =
            match *p {
                "../protocols/system-program.json" => {
                    registry.load_from_json(include_str!("../protocols/system-program.json"))
                }
                "../protocols/spl-token.json" => {
                    registry.load_from_json(include_str!("../protocols/spl-token.json"))
                }
                "../protocols/token-2022.json" => {
                    registry.load_from_json(include_str!("../protocols/token-2022.json"))
                }
                "../protocols/stake-program.json" => {
                    registry.load_from_json(include_str!("../protocols/stake-program.json"))
                }
                "../protocols/raydium-amm-v4.json" => {
                    registry.load_from_json(include_str!("../protocols/raydium-amm-v4.json"))
                }
                "../protocols/squads-v4.json" => {
                    registry.load_from_json(include_str!("../protocols/squads-v4.json"))
                }
                "../protocols/jupiter-v6.json" => {
                    registry.load_from_json(include_str!("../protocols/jupiter-v6.json"))
                }
                "../protocols/orca-whirlpools.json" => {
                    registry.load_from_json(include_str!("../protocols/orca-whirlpools.json"))
                }
                "../protocols/meteora-dlmm.json" => {
                    registry.load_from_json(include_str!("../protocols/meteora-dlmm.json"))
                }
                "../protocols/memo-program.json" => {
                    registry.load_from_json(include_str!("../protocols/memo-program.json"))
                }
                "../protocols/legacy-memo-program.json" => {
                    registry.load_from_json(include_str!("../protocols/legacy-memo-program.json"))
                }
                "../protocols/spl-memo-program.json" => {
                    registry.load_from_json(include_str!("../protocols/spl-memo-program.json"))
                }
                "../protocols/ata-program.json" => {
                    registry.load_from_json(include_str!("../protocols/ata-program.json"))
                }
                "../protocols/compute-budget.json" => {
                    registry.load_from_json(include_str!("../protocols/compute-budget.json"))
                }
                "../protocols/bpf-loader.json" => {
                    registry.load_from_json(include_str!("../protocols/bpf-loader.json"))
                }
                "../protocols/bpf-loader-upgradeable.json" => registry
                    .load_from_json(include_str!("../protocols/bpf-loader-upgradeable.json")),
                "../protocols/pump-fun.json" => {
                    registry.load_from_json(include_str!("../protocols/pump-fun.json"))
                }
                "../protocols/jupiter-dca.json" => {
                    registry.load_from_json(include_str!("../protocols/jupiter-dca.json"))
                }
                "../protocols/wormhole-core.json" => {
                    registry.load_from_json(include_str!("../protocols/wormhole-core.json"))
                }
                "../protocols/metaplex-token-metadata.json" => registry
                    .load_from_json(include_str!("../protocols/metaplex-token-metadata.json")),
                _ => unreachable!(),
            };

        if let Err(e) = res {
            tracing::error!(path = %p, error = %e, "Failed to load seed manifest");
            std::process::exit(1);
        }
    }

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
        let manifest = registry
            .get("11111111111111111111111111111111")
            .expect("System Program manifest should be loaded");
        let transfer = manifest
            .instructions
            .iter()
            .find(|i| i.name == "Transfer")
            .expect("Transfer instruction should exist");
        assert_eq!(transfer.discriminator, "02000000");
    }

    #[test]
    fn test_spl_token_manifest_has_set_authority() {
        let registry = load_seed_manifests();
        let manifest = registry
            .get("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
            .expect("SPL Token manifest should be loaded");
        let set_auth = manifest
            .instructions
            .iter()
            .find(|i| i.name == "SetAuthority")
            .expect("SetAuthority instruction should exist");
        assert!(
            !set_auth.risk_rules.is_empty(),
            "SetAuthority should have risk rules"
        );
    }

    #[test]
    fn test_pump_fun_manifest_has_verified_discriminators() {
        let registry = load_seed_manifests();
        let manifest = registry
            .get("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P")
            .expect("Pump.fun manifest should be loaded");
        let buy = manifest
            .instructions
            .iter()
            .find(|i| i.name == "buy")
            .expect("buy instruction should exist");
        // Official pump-fun IDL discriminator (pump-fun/pump-public-docs).
        assert_eq!(buy.discriminator, "66063d1201daebea");
        let sell = manifest
            .instructions
            .iter()
            .find(|i| i.name == "sell")
            .expect("sell instruction should exist");
        assert_eq!(sell.discriminator, "33e685a4017f83ad");
        // Swap-shaped instructions must carry risk rules.
        assert!(!buy.risk_rules.is_empty());
        assert!(!sell.risk_rules.is_empty());
    }

    #[test]
    fn test_jupiter_dca_manifest_has_escrow_instructions() {
        let registry = load_seed_manifests();
        let manifest = registry
            .get("DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M")
            .expect("Jupiter DCA manifest should be loaded");
        assert!(manifest
            .instructions
            .iter()
            .any(|i| i.name == "openDca" || i.name == "openDcaV2"));
        assert!(manifest.instructions.iter().any(|i| i.name == "closeDca"));
        // Escrow moves must declare allowed CPIs to SPL Token.
        let open = manifest
            .instructions
            .iter()
            .find(|i| i.name == "openDca")
            .expect("openDca should exist");
        assert!(open
            .allowed_cpis
            .contains(&"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()));
    }

    #[test]
    fn test_wormhole_core_manifest_has_post_message() {
        let registry = load_seed_manifests();
        let manifest = registry
            .get("worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth")
            .expect("Wormhole Core manifest should be loaded");
        let post = manifest
            .instructions
            .iter()
            .find(|i| i.name == "PostMessage")
            .expect("PostMessage instruction should exist");
        // Native program: single-byte variant discriminator.
        assert_eq!(post.discriminator, "01");
        assert!(!post.risk_rules.is_empty());
    }

    /// Grounds the Tier-0 manifests (Compute Budget, Associated Token Account)
    /// in real on-chain data instead of self-reference (the C1 lesson): every
    /// ComputeBudget/ATA instruction in the pinned mainnet fixtures must
    /// resolve to a manifest instruction whose discriminator EQUALS the
    /// observed first data byte of the real instruction.
    #[test]
    fn test_tier0_manifest_discriminators_match_real_mainnet_fixtures() {
        let registry = load_seed_manifests();
        let tier0 = [
            "ComputeBudget111111111111111111111111111111",
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
        ];
        for (fixture, raw_json) in [
            (
                "real_mainnet_jup.json",
                include_str!("../tests/fixtures/real_mainnet_jup.json"),
            ),
            (
                "real_mainnet_system.json",
                include_str!("../tests/fixtures/real_mainnet_system.json"),
            ),
        ] {
            let raw: serde_json::Value =
                serde_json::from_str(raw_json).expect("fixture must be valid JSON");
            // Fixtures are stored as the raw getTransaction result body.
            let msg = &raw["transaction"]["message"];
            let static_keys: Vec<String> = msg["accountKeys"]
                .as_array()
                .expect("accountKeys array")
                .iter()
                .map(|k| {
                    k.as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| k["pubkey"].as_str().unwrap().to_string())
                })
                .collect();
            let mut observed = 0;
            for ix in msg["instructions"].as_array().expect("instructions array") {
                let idx = ix["programIdIndex"].as_u64().expect("programIdIndex") as usize;
                if idx >= static_keys.len() {
                    continue; // ALT-resolved key; not a top-level program
                }
                let pid = &static_keys[idx];
                if !tier0.contains(&pid.as_str()) {
                    continue;
                }
                let data_b58 = ix["data"].as_str().unwrap_or("");
                let Some(bytes) = crate::solana_types::base58_decode(data_b58) else {
                    continue;
                };
                if bytes.is_empty() {
                    continue;
                }
                observed += 1;
                let hex = format!("{:02x}", bytes[0]);
                let found = registry
                    .find_instruction(pid, &hex)
                    .unwrap_or_else(|| {
                        panic!("{fixture}: {pid} observed discriminator {hex} not resolved by any manifest")
                    });
                assert_eq!(
                    found.discriminator, hex,
                    "{fixture}: {pid} manifest discriminator {} != observed {hex} for {}",
                    found.discriminator, found.name
                );
            }
            assert!(
                observed >= 2,
                "{fixture}: expected >=2 observed Tier-0 instructions, saw {observed}"
            );
        }
    }

    #[test]
    fn test_metaplex_token_metadata_manifest_has_create() {
        let registry = load_seed_manifests();
        let manifest = registry
            .get("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s")
            .expect("Metaplex Token Metadata manifest should be loaded");
        let create = manifest
            .instructions
            .iter()
            .find(|i| i.name == "CreateMetadataAccountV3")
            .expect("CreateMetadataAccountV3 should exist");
        // Observed live on mainnet 2026-08-07 (shank hardcoded discriminator).
        assert_eq!(create.discriminator, "0fd902b83e0f4ee4");
    }

    /// Pins every seed manifest's program_id to its on-chain-verified
    /// canonical value (mainnet `getAccountInfo` → executable=true, checked
    /// 2026-08-06). A previous edit corrupted the Raydium manifest ID to a
    /// non-existent address; a manifest whose program_id doesn't match the
    /// real on-chain program silently fails every legitimate verification for
    /// that protocol — the highest-impact data bug class in this codebase.
    #[test]
    fn test_all_seed_manifest_program_ids_are_canonical() {
        // Single source of truth: protocols/verified_program_ids.json. Each ID
        // there was verified executable on mainnet (scripts/live_revalidate.py
        // reproduces the check). This test asserts the manifests match the
        // registry EXACTLY and BIDIRECTIONALLY:
        //   - any manifest program_id NOT in the verified registry fails
        //     (fabricated/typo'd IDs — the memo class of bug, which has
        //     recurred three times: C1's fabricated-ID claim, C10's wrong
        //     'retired' label, C15's removal of a real program),
        //   - any verified program missing from the manifests fails
        //     (accidental removal), and
        //   - names must match (no swapped labels).
        // NOTE: this consistency check alone cannot catch a registry that is
        // itself wrong — that is what test_registry_contains_blessed_canonical_programs
        // and scripts/live_revalidate.py (on-chain) cover. The registry is
        // checked from BOTH Rust and the Python AI layer, so an accidental
        // identifier change cannot silently pass — it must be accompanied by
        // on-chain evidence in the registry itself.
        let verified: serde_json::Value =
            serde_json::from_str(include_str!("../protocols/verified_program_ids.json"))
                .expect("verified_program_ids.json must be valid JSON");
        let programs = verified["programs"].as_array().expect("programs array");
        assert_eq!(
            programs.len(),
            20,
            "verified registry must list exactly the 20 seed programs"
        );

        let mut verified_by_id: std::collections::BTreeMap<&str, &str> =
            std::collections::BTreeMap::new();
        for p in programs {
            let name = p["name"].as_str().expect("name");
            let id = p["program_id"].as_str().expect("program_id");
            assert!(
                verified_by_id.insert(id, name).is_none(),
                "duplicate program_id {id} in verified registry"
            );
        }

        let registry = load_seed_manifests();
        let manifests: std::collections::BTreeMap<String, String> = registry
            .list()
            .iter()
            .map(|m| (m.protocol.program_id.clone(), m.protocol.name.clone()))
            .collect();

        // Direction 1: every manifest ID must be verified (no fabricated IDs).
        let missing_from_registry: Vec<_> = manifests
            .keys()
            .filter(|id| !verified_by_id.contains_key(id.as_str()))
            .collect();
        assert!(
            missing_from_registry.is_empty(),
            "manifests carry program IDs absent from verified_program_ids.json \
             (fabricated/typo'd?): {missing_from_registry:?}"
        );

        // Direction 2: every verified ID must still have a manifest (no
        // accidental removal).
        let missing_from_manifests: Vec<_> = verified_by_id
            .keys()
            .filter(|id| !manifests.contains_key(**id))
            .collect();
        assert!(
            missing_from_manifests.is_empty(),
            "verified programs missing from manifests (accidental removal?): \
             {missing_from_manifests:?}"
        );

        // Names must match (no swapped labels).
        for (id, name) in &manifests {
            let verified_name = verified_by_id
                .get(id.as_str())
                .expect("bidirectional check above");
            assert_eq!(
                verified_name, name,
                "name mismatch for {id}: manifest says '{name}', registry says '{verified_name}'"
            );
        }
    }

    /// The memo-class completeness guard. The bidirectional manifest<->registry
    /// check above can only detect *inconsistency* — if the registry itself is
    /// corrupted (as C1 corrupted it by removing the real MemoSq4gq program),
    /// both sides stay "consistent" and the error sails through. This blessed
    /// set is the offline anchor: the canonical core programs that MUST always
    /// be present, each verified executable on mainnet 2026-08-08 (the memo
    /// IDs additionally verified by getAccountInfo this same day). Removing or
    /// renaming any of these fails CI with a message naming the program — the
    /// memo class of bug cannot silently recur.
    #[test]
    fn test_registry_contains_blessed_canonical_programs() {
        let blessed: &[(&str, &str)] = &[
            ("System Program", "11111111111111111111111111111111"),
            (
                "SPL Token Program",
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            ),
            (
                "Token-2022 Program",
                "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            ),
            (
                "Stake Program",
                "Stake11111111111111111111111111111111111111",
            ),
            (
                "SPL Memo (classic)",
                "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
            ),
            (
                "SPL Memo (v4.0.0)",
                "Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH",
            ),
            (
                "SPL Memo (legacy)",
                "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",
            ),
            (
                "Associated Token Account",
                "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
            ),
            (
                "Compute Budget",
                "ComputeBudget111111111111111111111111111111",
            ),
            (
                "BPF Loader (classic)",
                "BPFLoader2111111111111111111111111111111111",
            ),
            (
                "BPF Loader Upgradeable",
                "BPFLoaderUpgradeab1e11111111111111111111111",
            ),
        ];
        let verified: serde_json::Value =
            serde_json::from_str(include_str!("../protocols/verified_program_ids.json"))
                .expect("verified_program_ids.json must be valid JSON");
        let programs = verified["programs"].as_array().expect("programs array");
        let registry_ids: std::collections::BTreeSet<&str> = programs
            .iter()
            .map(|p| p["program_id"].as_str().expect("program_id"))
            .collect();
        for (name, id) in blessed {
            assert!(
                registry_ids.contains(id),
                "blessed canonical program '{name}' ({id}) is MISSING from \
                 verified_program_ids.json — a memo-class regression (C15: \
                 MemoSq4gq was wrongly removed by C1 and is EXEC on mainnet)"
            );
        }
    }

    /// The exact regression this pin guards: a manifest whose program_id does
    /// not exist on-chain must be caught at review/test time, not silently
    /// accepted. Loading a manifest under the WRONG (corrupted) Raydium ID
    /// must NOT resolve the real canonical ID.
    #[test]
    fn test_corrupted_raydium_id_does_not_resolve() {
        let registry = load_seed_manifests();
        // This was the previously-corrupted manifest ID — it is a non-program
        // account on mainnet and must never resolve the Raydium manifest.
        let corrupted = "675kPX9MHTjS2zt1q7PYMcjCKa5KqQ1vJXrDhJq5qoM9";
        assert!(registry.get(corrupted).is_none());
        // The canonical ID resolves.
        assert!(registry
            .get("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8")
            .is_some());
    }

    #[test]
    fn test_discriminator_input_prefix_of_manifest_is_rejected() {
        // SECURITY regression: a truncated input that is only a PREFIX of a
        // known discriminator must NOT match (previously accepted with >= 4
        // chars — the discriminator-impersonation bypass).
        let registry = load_seed_manifests();
        // Jupiter route_v2's real discriminator is "bb64facc31c4af14".
        let jup = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
        assert!(
            registry.find_instruction(jup, "bb64facc31c4af14").is_some(),
            "exact match must resolve"
        );
        assert!(
            registry
                .find_instruction(jup, "bb64facc31c4af14aa")
                .is_some(),
            "input longer than manifest disc (more data bytes) must resolve"
        );
        assert!(
            registry.find_instruction(jup, "bb64").is_none(),
            "4-char prefix of an 8-byte discriminator must NOT match"
        );
        assert!(
            registry.find_instruction(jup, "bb64fa").is_none(),
            "6-char prefix must NOT match"
        );
    }

    #[test]
    fn test_short_manifest_discriminator_still_matches_input() {
        // 1-byte discriminators (SPL Token Transfer="03", Raydium
        // SwapBaseIn="09") are authoritative prefixes — input data
        // legitimately carries more bytes after the selector.
        let registry = load_seed_manifests();
        let spl = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        assert!(registry.find_instruction(spl, "03").is_some());
        assert!(registry.find_instruction(spl, "03aabbcc").is_some());
        let raydium = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
        assert!(registry.find_instruction(raydium, "09").is_some());
        assert!(registry.find_instruction(raydium, "09ffeedd").is_some());
        // A byte with no SPL Token instruction never matches ("ff" is not a
        // real selector; "04" would be Approve and must NOT be asserted as
        // non-matching).
        assert!(registry.find_instruction(spl, "ff").is_none());
        assert!(registry.find_instruction(spl, "04").is_some()); // Approve
                                                                 // A 4-byte-manifest discriminator requires the FULL prefix (System
                                                                 // Program Transfer = "02000000"); truncated input does not match.
        assert!(registry
            .find_instruction("11111111111111111111111111111111", "02")
            .is_none());
        assert!(registry
            .find_instruction("11111111111111111111111111111111", "0200")
            .is_none());
        assert!(registry
            .find_instruction("11111111111111111111111111111111", "02000000")
            .is_some());
    }

    #[test]
    fn test_invalid_manifest_rejected() {
        let mut registry = ManifestRegistry::new();
        let bad = r#"{"graphite_manifest_version":"1.0","protocol":{"name":"","program_id":"","website":"","github":""},"version":{"label":"1.0","effective_from_slot":0,"previous_version_ref":null},"instructions":[],"trust_tier":""}"#;
        assert!(registry.load_from_json(bad).is_err());
    }
}

#[cfg(test)]
mod test_v2_discriminators {
    use super::*;

    #[test]
    fn test_jupiter_v2_instructions_loaded() {
        let registry = load_seed_manifests();
        let jupiter = registry.get("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
        assert!(jupiter.is_some());
        let jupiter = jupiter.unwrap();
        eprintln!("Jupiter V6: {} instructions", jupiter.instructions.len());
        let mut found = false;
        for ix in &jupiter.instructions {
            if ix.name == "route_v2" {
                found = true;
                eprintln!("  FOUND: {} = {}", ix.name, ix.discriminator);
                assert_eq!(ix.discriminator, "bb64facc31c4af14");
            }
        }
        assert!(found, "route_v2 should be loaded");
        let f = registry.find_instruction(
            "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
            "bb64facc31c4af14",
        );
        assert!(f.is_some(), "find_instruction should match route_v2 disc");
    }
}
