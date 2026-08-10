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
    /// Machine-readable security class, declared by the manifest author.
    /// Empty (default) means "no special class". Recognized values:
    ///   "drain"      — funds can leave to an attacker-chosen destination
    ///   "authority"  — ownership/authority can be transferred
    ///   "withdraw"   — funds are withdrawn (destination must be verified)
    ///   "mint"       — new tokens are created
    ///   "close"      — an account is closed (lamports refunded)
    ///   "create"     — an account is created/allocated
    ///   "transfer"   — ordinary transfer
    /// The risk engine consumes this as a fail-closed gate (see `assess`
    /// Check 10): a high-risk class with NO declared intent is blocked, so
    /// newly onboarded protocols inherit protection without editing
    /// detection logic.
    #[serde(default)]
    pub risk_class: String,
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
    /// Functional classification ("swap", "lending", "bridge", "nft",
    /// "token-infra", ...). Declarative, so protocol-aware detection
    /// (e.g. FakeSwap's swap set) can be extended by tagging a manifest
    /// instead of editing detection logic.
    #[serde(default)]
    pub category: String,
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
/// Canonical discriminator matching — PREFIX semantics, applied uniformly
/// across the manifest resolver, the risk engine, and the transaction-pattern
/// analyzer (C33/C35 unified them).
///
/// WHY PREFIX (certification decision, documented): a Solana instruction
/// selector is the LEADING bytes of the instruction data. Widths in use:
/// - 2 hex chars (1 byte)  : SPL Token / Token-2022 (e.g. `09` CloseAccount)
/// - 8 hex chars (4 bytes) : System Program u32 LE (e.g. `02000000` Transfer)
/// - 16 hex chars (8 bytes): Anchor-style (`bb64facc31c4af14` Jupiter route)
///
/// An on-chain discriminator therefore always STARTS WITH the manifest's
/// selector: input `0900000000000000` MUST match manifest `09`. This is not
/// a laxity — it is the only correct interpretation of variable-width
/// selectors, and it is unambiguous because the manifest registry REJECTS
/// any manifest where two instructions have prefix-related discriminators
/// (see `ManifestRegistryEngine::validate_manifest`).
///
/// Safety properties:
/// - input longer than the selector: matches (correct — real 8-byte forms)
/// - input SHORTER than the selector: does NOT match (starts_with is false)
/// - empty selector: never matches (unknown discriminator path)
pub fn discriminator_matches(manifest_disc: &str, input_disc: &str) -> bool {
    let manifest_disc = manifest_disc.to_lowercase();
    let input_disc = input_disc.to_lowercase();

    if manifest_disc.is_empty() {
        return false;
    }
    // The INPUT must be well-formed hex before any prefix matching: a
    // whitespace-padded or otherwise malformed discriminator ("03 ", "0x09",
    // "03zz") must NOT silently resolve to a legitimate instruction — it is
    // treated as an unknown discriminator (P12 Response 2: reduced
    // confidence, never an accidental pass). Manifest discriminators are
    // schema-validated at load; inputs are attacker-controlled.
    if input_disc.is_empty() || !input_disc.bytes().all(|b| b.is_ascii_hexdigit()) {
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
        "../protocols/drift.json",
        "../protocols/kamino-lending.json",
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
                "../protocols/drift.json" => {
                    registry.load_from_json(include_str!("../protocols/drift.json"))
                }
                "../protocols/kamino-lending.json" => {
                    registry.load_from_json(include_str!("../protocols/kamino-lending.json"))
                }
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
    use sha2::{Digest, Sha256};

    /// camelCase -> snake_case (Anchor IDL display name -> Rust fn name), the
    /// names used in the sha256("global:<name>") discriminator derivation.
    fn snake_case(name: &str) -> String {
        let mut out = String::with_capacity(name.len() + 4);
        let bytes: Vec<char> = name.chars().collect();
        for (i, c) in bytes.iter().enumerate() {
            if c.is_uppercase() {
                if i > 0 {
                    let prev = bytes[i - 1];
                    let next = bytes.get(i + 1).copied();
                    let split_before = prev.is_lowercase()
                        || (prev.is_ascii_digit())
                        || next.map(|n| n.is_uppercase()).unwrap_or(false) && prev.is_uppercase();
                    if split_before {
                        out.push('_');
                    }
                }
                out.push(c.to_ascii_lowercase());
            } else {
                out.push(*c);
            }
        }
        out
    }

    #[test]
    fn test_seed_manifests_load_successfully() {
        let registry = load_seed_manifests();
        let manifests = registry.list();
        assert!(manifests.len() >= 10, "expected at least 2 seed manifests");
    }

    #[test]
    fn discriminator_matching_semantics() {
        // Exact match
        assert!(discriminator_matches("09", "09"));
        // Valid prefix: real 8-byte little-endian form of CloseAccount
        assert!(discriminator_matches("09", "0900000000000000"));
        // Longer valid Anchor-style discriminator
        assert!(discriminator_matches(
            "bb64facc31c4af14",
            "bb64facc31c4af14"
        ));
        // Input SHORTER than the selector — must NOT match (starts_with false)
        assert!(!discriminator_matches("0900000000000000", "09"));
        // Similar but wrong prefixes must not match
        assert!(!discriminator_matches("06", "05"));
        // 0601 DOES match 06 by prefix semantics — 0x06 SetAuthority's
        // on-chain form is the leading byte; the trailing 01 is payload. This
        // is correct and is why the registry rejects prefix-ambiguous pairs.
        assert!(discriminator_matches("06", "0601"));
        // Empty inputs never match
        assert!(!discriminator_matches("09", ""));
        assert!(!discriminator_matches("", "09"));
        // Unknown selectors: a discriminator with no manifest entry (0x12 on
        // SPL Token) does not match the token selectors.
        assert!(!discriminator_matches("03", "12"));
        assert!(!discriminator_matches("04", "12"));
        // Case-insensitive
        assert!(discriminator_matches("0C", "0c00000000000000"));
    }

    #[test]
    fn seed_token_manifests_are_prefix_consistent() {
        // SPL Token: every instruction selector is 2 hex chars and none is a
        // proper prefix of another — so prefix matching is unambiguous.
        let registry = load_seed_manifests();
        for id in [
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            "11111111111111111111111111111111",
        ] {
            let m = registry.get(id).expect("seed manifest");
            for i in 0..m.instructions.len() {
                for j in (i + 1)..m.instructions.len() {
                    let a = m.instructions[i].discriminator.to_lowercase();
                    let b = m.instructions[j].discriminator.to_lowercase();
                    assert!(
                        !(a.starts_with(&b) || b.starts_with(&a)),
                        "program {id}: {} ({}) and {} ({}) are prefix-ambiguous",
                        m.instructions[i].name,
                        a,
                        m.instructions[j].name,
                        b
                    );
                }
            }
        }
    }

    #[test]
    fn anchor_style_discriminator_roundtrip() {
        // Anchor programs use 8-byte sha256("global:<name>")[:8] selectors.
        // Derive one and confirm the manifest convention matches it exactly
        // (16 hex chars, prefix-consistent with itself).
        let mut hasher = Sha256::new();
        hasher.update(b"global:route");
        let digest = hasher.finalize();
        let disc = hex::encode(&digest[..8]);
        assert_eq!(disc.len(), 16);
        assert!(discriminator_matches(&disc, &disc));
        assert!(discriminator_matches(&disc[..8], &disc)); // 4-byte prefix view also matches
    }

    #[test]
    fn manifest_category_aligns_with_swap_set() {
        // Maintainability contract (P1D): every manifest tagged "swap" must
        // be in the risk engine's canonical swap set, and every swap-set
        // program must carry the category in its manifest. Adding a swap
        // protocol = tag the manifest + extend `is_swap_program` — the sync
        // test catches drift in either direction.
        let registry = load_seed_manifests();
        let tagged: Vec<String> = registry
            .list()
            .iter()
            .filter(|m| m.protocol.category == "swap")
            .map(|m| m.protocol.program_id.clone())
            .collect();
        assert!(
            !tagged.is_empty(),
            "expected at least one swap-tagged manifest"
        );
        for id in &tagged {
            assert!(
                crate::risk_engine::is_swap_program(id),
                "manifest-tagged swap program {id} missing from is_swap_program"
            );
        }
        let canonical = [
            "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
            "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
            "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo",
            "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",
            "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M",
            "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
        ];
        for id in canonical {
            assert!(
                tagged.contains(&id.to_string()),
                "swap-set program {id} missing category tag in its manifest"
            );
        }
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

    /// C18 regression: the Squads manifest previously carried camelCase-hash
    /// discriminators and v1-era instruction names that do not exist in the
    /// deployed program. Every discriminator must equal the Anchor-convention
    /// value sha256("global:" + snake_case(name))[:8] — the same derivation the
    /// program's own generated SDK uses. Four of these were additionally
    /// verified against live mainnet transactions (see
    /// test_squads_chain_verified_discriminators).
    #[test]
    fn test_squads_discriminators_match_anchor_snake_case() {
        let registry = load_seed_manifests();
        let squads = registry
            .get("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf")
            .expect("Squads manifest loaded");
        assert_eq!(squads.instructions.len(), 36, "IDL v2.1.0 surface");
        for ix in &squads.instructions {
            let snake = snake_case(&ix.name);
            let mut hasher = Sha256::new();
            hasher.update(format!("global:{snake}").as_bytes());
            let digest = hasher.finalize();
            let expected = hex::encode(&digest[..8]);
            assert_eq!(
                ix.discriminator, expected,
                "Squads instruction '{}': discriminator {} != sha256(global:{})= {} \
                 (camelCase-hash bug class, C18)",
                ix.name, ix.discriminator, snake, expected
            );
        }
    }

    /// Chain-grounded anchors: the four Squads discriminators observed in
    /// real mainnet transactions on 2026-08-08 (via getTransaction on live
    /// Squads program traffic) must stay pinned in the manifest.
    #[test]
    fn test_squads_chain_verified_discriminators() {
        let registry = load_seed_manifests();
        let squads = registry
            .get("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf")
            .expect("Squads manifest loaded");
        let pinned: &[(&str, &str)] = &[
            ("multisigCreateV2", "32ddc75d28f58be9"),
            ("vaultTransactionCreate", "30fa4ea8d0e2dad3"),
            ("proposalCreate", "dc3c49e01e6c4f9f"),
            ("proposalApprove", "9025a488bcd82af8"),
        ];
        for (name, disc) in pinned {
            let ix = squads
                .instructions
                .iter()
                .find(|i| &i.name == name)
                .unwrap_or_else(|| panic!("{name} missing from Squads manifest"));
            assert_eq!(
                ix.discriminator, *disc,
                "chain-verified discriminator for {name} changed"
            );
        }
    }

    /// Dynamic-PDA grounding: the Squads V4 multisig account is a PDA derived
    /// from ['multisig','multisig',create_key] (official SDK pda.ts, IDL
    /// 'createKey ... used as a seed for the Multisig PDA'). The resolver must
    /// derive it from the create_key account and flag a spoofed multisig.
    #[test]
    fn test_squads_multisig_pda_derivation() {
        use crate::account_resolution::{resolve_accounts, AccountResolutionInput};
        use crate::solana_types::Pubkey;

        let registry = load_seed_manifests();
        let program = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";
        let create_key = Pubkey::from_base58("3P3Jgiv77fHvtpgnvFAxzAvaLJTfYBNuxdrsnbnqhj4B")
            .expect("valid create_key");
        let program_pk = Pubkey::from_base58(program).expect("valid program");
        let (derived, _bump) = crate::solana_types::find_program_address(
            &[b"multisig", b"multisig", create_key.as_bytes()],
            &program_pk,
        )
        .expect("PDA derivation");
        let derived_b58 = derived.to_base58();
        // The derived key must be off-curve (it is a PDA by construction).
        assert!(!crate::solana_types::is_on_curve(&derived));

        // Correct multisig -> no mismatch.
        let ok = resolve_accounts(
            &AccountResolutionInput {
                program_id: program.to_string(),
                instruction_discriminator: "32ddc75d28f58be9".to_string(),
                account_addresses: vec![
                    "11111111111111111111111111111111".to_string(),
                    "11111111111111111111111111111111".to_string(),
                    derived_b58.clone(),
                    create_key.to_base58(),
                    "11111111111111111111111111111111".to_string(),
                    "11111111111111111111111111111111".to_string(),
                ],
                instruction_data: None,
            },
            &registry,
        )
        .expect("resolution");
        let multisig_acct = ok
            .resolved_accounts
            .iter()
            .find(|a| a.address == derived_b58)
            .expect("multisig account");
        assert!(multisig_acct.is_pda);
        assert!(
            !multisig_acct.pda_mismatch,
            "correct multisig must not mismatch"
        );
        assert_eq!(
            multisig_acct.pda_seeds,
            vec![
                "multisig".to_string(),
                "multisig".to_string(),
                "{account_3}".to_string()
            ]
        );

        // Spoofed multisig (on-curve key at the multisig slot) -> pda_mismatch.
        // A real mainnet wallet pubkey, unrelated to the create_key.
        let spoof =
            Pubkey::from_base58("CWb8MciizembLV66kisYcXo3Cb91hdszxw74QHpEJKZR").expect("valid key");
        let bad = resolve_accounts(
            &AccountResolutionInput {
                program_id: program.to_string(),
                instruction_discriminator: "32ddc75d28f58be9".to_string(),
                account_addresses: vec![
                    "11111111111111111111111111111111".to_string(),
                    "11111111111111111111111111111111".to_string(),
                    spoof.to_base58(),
                    create_key.to_base58(),
                    "11111111111111111111111111111111".to_string(),
                    "11111111111111111111111111111111".to_string(),
                ],
                instruction_data: None,
            },
            &registry,
        )
        .expect("resolution");
        let spoof_acct = bad
            .resolved_accounts
            .iter()
            .find(|a| a.address == spoof.to_base58())
            .expect("spoofed multisig account");
        assert!(spoof_acct.is_pda);
        assert!(spoof_acct.pda_mismatch, "spoofed multisig must be flagged");
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
        // C24 (2026-08-09): the deployed program is Shank-derived with u8
        // discriminators — CreateMetadataAccountV3 = 33 = 0x21 (observed on-chain
        // as the leading byte of real instruction data). The previous 8-byte
        // value was never observed on-chain.
        assert_eq!(create.discriminator, "21");
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
            22,
            "verified registry must list exactly the 22 seed programs (C27 added Drift + Kamino)"
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
        // Jupiter route_v2's discriminator (C22.3): bb64facc31c4af14, CONFIRMED
        // on-chain (base58-decoded live mainnet txs 2026-08-09 + pinned fixture
        // sig 57TAjPZXt… slot 438012579). The camelCase-hashed old-era values
        // (e.g. sharedAccountsRoute=5703feb8e7573909) were corrected to the
        // program's snake_case convention.
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
        // The OLD camelCase hash (C18 disease) must not resolve to ANY active
        // entry: sharedAccountsRoute was 5703feb8e7573909 (sha256 of
        // "global:sharedAccountsRoute") and never matched the deployed program.
        let camel = registry.find_instruction(
            "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
            "5703feb8e7573909",
        );
        assert!(
            camel.is_none(),
            "camelCase-hashed discriminator must not resolve to any active entry (C22.3)"
        );
    }
}

/// C27 — Drift + Kamino Lending manifests (2026-08-09).
///
/// Both were built from the official deployed-program IDLs (committed under
/// scripts/): Drift from velocity-exchange/protocol-v2 sdk/src/idl/drift.json
/// (program dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH), Kamino from
/// Kamino-Finance/klend-sdk src/idl/klend.json (program
/// KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD). The IDLs carry no discriminator
/// bytes, so every value is DERIVED as sha256("global:" + snake_case)[:8] and
/// then VERIFIED LIVE by on-chain census (scripts/census_drift_kamino.py,
/// base58-correct decode): 14/300 discriminators observed on mainnet, all
/// matched the derived value, zero unmatched. PDA seeds are grounded ONLY where
/// the deployed program's account struct seed-constrains them (C26 principle) —
/// verified against the program source + live txs (scripts/verify_dk_pdas.py).
#[cfg(test)]
mod test_c27_drift_kamino {
    use super::*;
    use sha2::{Digest, Sha256};

    /// camelCase -> snake_case, mirroring the C27 generator's regex
    /// (re.sub("(.)([A-Z][a-z]+)", ...) then re.sub("([a-z0-9])([A-Z])", ...)):
    /// insert '_' before an uppercase when the previous char is lowercase or a
    /// digit, or when the previous char is uppercase and the next is lowercase
    /// (handles digit+uppercase boundaries like V2Fulfillment -> v2_fulfillment).
    fn snake_case(name: &str) -> String {
        let mut out = String::with_capacity(name.len() + 4);
        let bytes: Vec<char> = name.chars().collect();
        for (i, c) in bytes.iter().enumerate() {
            if c.is_uppercase() {
                if i > 0 {
                    let prev = bytes[i - 1];
                    let next = bytes.get(i + 1).copied();
                    if prev.is_lowercase()
                        || prev.is_ascii_digit()
                        || (prev.is_uppercase() && next.is_some() && next.unwrap().is_lowercase())
                    {
                        out.push('_');
                    }
                }
                out.push(c.to_ascii_lowercase());
            } else {
                out.push(*c);
            }
        }
        out
    }

    const DRIFT: &str = "dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH";
    const KAMINO: &str = "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD";

    /// The whole surface must follow the Anchor snake_case convention — the
    /// same sha256("global:" + snake_case(name))[:8] the deployed programs' own
    /// generated SDKs use. This is the C18 bug class: any camelCase-hash
    /// discriminator would silently fail L2 matching on real transactions.
    #[test]
    fn test_drift_and_kamino_discriminators_match_anchor_snake_case() {
        let registry = load_seed_manifests();
        for (id, expected_count) in [(DRIFT, 249usize), (KAMINO, 51usize)] {
            let m = registry.get(id).unwrap_or_else(|| panic!("{id} loaded"));
            assert_eq!(m.instructions.len(), expected_count, "{id} IDL surface");
            for ix in &m.instructions {
                let snake = snake_case(&ix.name);
                let mut hasher = Sha256::new();
                hasher.update(format!("global:{snake}").as_bytes());
                let digest = hasher.finalize();
                let expected = hex::encode(&digest[..8]);
                assert_eq!(
                    ix.discriminator, expected,
                    "{id} instruction '{}': discriminator {} != sha256(global:{})= {} \
                     (camelCase-hash bug class, C18/C27)",
                    ix.name, ix.discriminator, snake, expected
                );
            }
        }
    }

    /// Chain-grounded anchors: discriminators observed in real mainnet
    /// transactions by the C27 census must stay pinned. A drift here means the
    /// manifest no longer matches the deployed program.
    #[test]
    fn test_drift_and_kamino_chain_verified_discriminators() {
        let registry = load_seed_manifests();
        let drift = registry.get(DRIFT).unwrap();
        let kamino = registry.get(KAMINO).unwrap();
        let pinned: &[(&str, &str, &str)] = &[
            (DRIFT, "placePerpOrder", "45a15dca787e4cb9"),
            (DRIFT, "cancelOrdersByIds", "861390a55ef0d25e"),
            (DRIFT, "placeOrders", "3c3f327b0cc53cbe"),
            (KAMINO, "flashBorrowReserveLiquidity", "87e734a70734d4c1"),
            (KAMINO, "flashRepayReserveLiquidity", "b97500cb60f5b4ba"),
            (KAMINO, "refreshReserve", "02da8aeb4fc91966"),
            (KAMINO, "refreshObligation", "218493e497c04859"),
            (KAMINO, "initObligation", "fb0ae74c1b0b9f60"),
            (KAMINO, "initUserMetadata", "75a9b045c5170fa2"),
        ];
        for (id, name, disc) in pinned {
            let m = if *id == DRIFT { &drift } else { &kamino };
            let ix = m
                .instructions
                .iter()
                .find(|i| &i.name == name)
                .unwrap_or_else(|| panic!("{name} missing from {id}"));
            assert_eq!(
                ix.discriminator, *disc,
                "chain-verified discriminator for {name} changed"
            );
        }
    }

    /// Grounded-PDA integrity: every non-empty pda_seeds template must resolve
    /// to a valid off-curve key under the program id, and the templates may
    /// only appear on accounts the deployed program seed-constrains (C26:
    /// grounding unconstrained accounts would flag legitimate txs).
    #[test]
    fn test_drift_and_kamino_pda_grounding_scoped_to_seed_constrained_accounts() {
        let registry = load_seed_manifests();
        let drift = registry.get(DRIFT).unwrap();
        let kamino = registry.get(KAMINO).unwrap();

        // Drift: user_stats is PDA-derived ONLY in initializeUserStats (all
        // other ixs use has_one/is_stats_for_user consistency checks); the
        // vault PDA is grounded only in deposit/withdraw/transferDeposit.
        for (ix_name, grounded) in [
            ("initializeUserStats", vec!["userStats"]),
            ("deposit", vec!["spotMarketVault"]),
            ("withdraw", vec!["spotMarketVault", "driftSigner"]),
            ("transferDeposit", vec!["spotMarketVault"]),
        ] {
            let ix = drift
                .instructions
                .iter()
                .find(|i| i.name == ix_name)
                .unwrap_or_else(|| panic!("{ix_name} in Drift manifest"));
            let grounded_now: Vec<String> = ix
                .accounts
                .iter()
                .filter(|a| !a.pda_seeds.is_empty())
                .map(|a| a.name.clone())
                .collect();
            assert_eq!(
                grounded_now, grounded,
                "{ix_name}: grounded accounts must be exactly {grounded:?}"
            );
        }
        // deposit/withdraw must NOT ground userStats as a PDA.
        for ix_name in ["deposit", "withdraw"] {
            let ix = drift
                .instructions
                .iter()
                .find(|i| i.name == ix_name)
                .unwrap();
            let us = ix
                .accounts
                .iter()
                .find(|a| a.name == "userStats")
                .expect("userStats present");
            assert!(
                us.pda_seeds.is_empty(),
                "{ix_name}.userStats must not be PDA-grounded (program uses is_stats_for_user, not seeds)"
            );
        }

        // Kamino: vaults grounded ONLY in initReserve; lma everywhere it
        // appears; obligation only in initObligation.
        let init_reserve = kamino
            .instructions
            .iter()
            .find(|i| i.name == "initReserve")
            .unwrap();
        let vault_names: Vec<&str> = init_reserve
            .accounts
            .iter()
            .filter(|a| !a.pda_seeds.is_empty())
            .map(|a| a.name.as_str())
            .collect();
        assert!(
            vault_names.contains(&"reserveLiquiditySupply")
                && vault_names.contains(&"feeReceiver")
                && vault_names.contains(&"reserveCollateralMint")
                && vault_names.contains(&"reserveCollateralSupply"),
            "initReserve must ground all four vault accounts, got {vault_names:?}"
        );
        // flashBorrow must NOT ground the vaults (they are address-from-state
        // constrained, not PDAs) — only the lma authority.
        let flash = kamino
            .instructions
            .iter()
            .find(|i| i.name == "flashBorrowReserveLiquidity")
            .unwrap();
        let flash_grounded: Vec<&str> = flash
            .accounts
            .iter()
            .filter(|a| !a.pda_seeds.is_empty())
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(
            flash_grounded,
            vec!["lendingMarketAuthority"],
            "flashBorrow must ground only the lma PDA, got {flash_grounded:?}"
        );
        // obligation grounded only in initObligation.
        let init_obl = kamino
            .instructions
            .iter()
            .find(|i| i.name == "initObligation")
            .unwrap();
        let obl = init_obl
            .accounts
            .iter()
            .find(|a| a.name == "obligation")
            .unwrap();
        assert_eq!(
            obl.pda_seeds,
            vec![
                "{instruction_data:8:9}".to_string(),
                "{instruction_data:9:10}".to_string(),
                "{account_0}".to_string(),
                "{account_3}".to_string(),
                "{account_4}".to_string(),
                "{account_5}".to_string(),
            ],
            "initObligation.obligation seeds = [tag,id,owner,market,seed1,seed2]"
        );
        for ix in &kamino.instructions {
            if ix.name != "initObligation" {
                for a in &ix.accounts {
                    assert!(
                        a.name != "obligation" || a.pda_seeds.is_empty(),
                        "{}.obligation must not be grounded outside initObligation",
                        ix.name
                    );
                }
            }
        }
    }

    /// End-to-end: a real Drift perp-order and a Kamino flash-borrow must
    /// resolve through the pipeline without PDA mismatches on the grounded
    /// accounts (no live-deposit corpus needed — the grounded accounts are
    /// exercised at the account-resolution layer with correct derived keys).
    #[test]
    fn test_drift_and_kamino_pipeline_end_to_end() {
        use crate::account_resolution::{resolve_accounts, AccountResolutionInput};
        use crate::solana_types::Pubkey;

        let registry = load_seed_manifests();

        // Kamino initObligation: obligation PDA from [tag,id,owner,market,
        // seed1,seed2] with the tx observed on mainnet (C27 census).
        let owner = Pubkey::from_base58("Cf9NAEfTEpuRgWE345sQ8FhscfuxK5UF8yTTqbuTHGBT").unwrap();
        let market = Pubkey::from_base58("5wJeMrUYECGq41fxRESKALVcHnNX26TAWy4W98yULsua").unwrap();
        let system = Pubkey::from_base58("11111111111111111111111111111111").unwrap();
        let kamino_pk = Pubkey::from_base58(KAMINO).unwrap();
        let (obl_pda, _b) = crate::solana_types::find_program_address(
            &[
                &[0u8],
                &[0u8],
                owner.as_bytes(),
                market.as_bytes(),
                system.as_bytes(),
                system.as_bytes(),
            ],
            &kamino_pk,
        )
        .expect("obligation PDA");

        let res = resolve_accounts(
            &AccountResolutionInput {
                program_id: KAMINO.to_string(),
                instruction_discriminator: "fb0ae74c1b0b9f60".to_string(),
                account_addresses: vec![
                    owner.to_base58(),
                    owner.to_base58(), // fee payer (same signer in observed tx)
                    obl_pda.to_base58(),
                    market.to_base58(),
                    system.to_base58(),
                    system.to_base58(),
                    // remaining: ownerUserMetadata, rent, systemProgram
                    system.to_base58(),
                    system.to_base58(),
                    system.to_base58(),
                ],
                instruction_data: Some(vec![
                    0xfb, 0x0a, 0xe7, 0x4c, 0x1b, 0x0b, 0x9f, 0x60, 0x00, 0x00,
                ]),
            },
            &registry,
        )
        .expect("resolution");
        let obl_acct = res
            .resolved_accounts
            .iter()
            .find(|a| a.address == obl_pda.to_base58())
            .expect("obligation resolved");
        assert!(obl_acct.is_pda);
        assert!(
            !obl_acct.pda_mismatch,
            "correct obligation PDA must not mismatch"
        );

        // Spoofed obligation (a random on-curve key) MUST mismatch.
        let spoof = Pubkey::from_base58("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU").unwrap();
        let res2 = resolve_accounts(
            &AccountResolutionInput {
                program_id: KAMINO.to_string(),
                instruction_discriminator: "fb0ae74c1b0b9f60".to_string(),
                account_addresses: vec![
                    owner.to_base58(),
                    owner.to_base58(),
                    spoof.to_base58(),
                    market.to_base58(),
                    system.to_base58(),
                    system.to_base58(),
                    system.to_base58(),
                    system.to_base58(),
                    system.to_base58(),
                ],
                instruction_data: Some(vec![
                    0xfb, 0x0a, 0xe7, 0x4c, 0x1b, 0x0b, 0x9f, 0x60, 0x00, 0x00,
                ]),
            },
            &registry,
        )
        .expect("resolution");
        assert!(
            res2.resolved_accounts.iter().any(|a| a.pda_mismatch),
            "spoofed obligation must be flagged as a PDA mismatch"
        );
    }
}
