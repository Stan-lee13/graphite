//! Solana-compatible types — minimal, self-contained, no heavy SDK dependency.
//!
//! Implements the subset of Solana types Graphite needs for real transaction
//! verification: Pubkey (base58, 32-byte), AccountMeta, Instruction, and
//! PDA (Program Derived Address) derivation via find_program_address.
//!
//! PDA derivation uses SHA-256 + ed25519 curve point validation to find an
//! address that hashes off-curve — exactly what the Solana runtime does.

use curve25519_dalek::edwards::CompressedEdwardsY;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum SolanaTypeError {
    #[error("invalid base58: {0}")]
    InvalidBase58(String),
    #[error("expected 32 bytes, got {0}")]
    InvalidLength(usize),
    #[error("PDA derivation exhausted all 256 nonces")]
    PdaExhausted,
}

/// A Solana public key — 32 bytes, base58-encoded onchain.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize, Default,
)]
pub struct Pubkey(#[serde(with = "pubkey_serde")] pub [u8; 32]);

mod pubkey_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&bs58::encode(bytes).into_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let decoded = bs58::decode(&s)
            .into_vec()
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        if decoded.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                decoded.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        Ok(arr)
    }
}

impl Pubkey {
    /// The System Program: 11111111111111111111111111111111
    pub const SYSTEM_PROGRAM: Pubkey = Pubkey([0u8; 32]);

    /// SPL Token Program: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
    pub fn spl_token() -> Pubkey {
        Pubkey(
            bs58::decode("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
                .into_vec()
                .unwrap()
                .try_into()
                .unwrap(),
        )
    }

    /// Token-2022 Program: TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb
    pub fn token_2022() -> Pubkey {
        Pubkey(
            bs58::decode("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
                .into_vec()
                .unwrap()
                .try_into()
                .unwrap(),
        )
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_base58(s: &str) -> Result<Self, SolanaTypeError> {
        let decoded = bs58::decode(s)
            .into_vec()
            .map_err(|e| SolanaTypeError::InvalidBase58(e.to_string()))?;
        if decoded.len() != 32 {
            return Err(SolanaTypeError::InvalidLength(decoded.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        Ok(Self(arr))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    /// Check if this is the default/zero key (System Program).
    pub fn is_system_program(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl std::fmt::Display for Pubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

/// Derive a Program Derived Address (PDA) from seeds and a program ID.
///
/// Mirrors Solana's `Pubkey::find_program_address`: iterates nonce from 255
/// down to 0, hashing seeds || program_id || nonce with SHA-256, and returns
/// the first hash that does NOT decompress to a valid ed25519 curve point
/// (i.e., is "off-curve").
pub fn find_program_address(
    seeds: &[&[u8]],
    program_id: &Pubkey,
) -> Result<(Pubkey, u8), SolanaTypeError> {
    for nonce in (0u8..=255).rev() {
        let mut hasher = Sha256::new();
        for seed in seeds {
            hasher.update(seed);
        }
        hasher.update(program_id.as_bytes());
        hasher.update([nonce]);
        let hash = hasher.finalize();

        let compressed = CompressedEdwardsY::from_slice(&hash).expect("hash is always 32 bytes");
        if compressed.decompress().is_none() {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&hash);
            return Ok((Pubkey(bytes), nonce));
        }
    }
    Err(SolanaTypeError::PdaExhausted)
}

/// Check if a pubkey is on the ed25519 curve (i.e., could be a keypair pubkey,
/// NOT a PDA). PDAs are off-curve by construction.
pub fn is_on_curve(pubkey: &Pubkey) -> bool {
    let compressed =
        CompressedEdwardsY::from_slice(pubkey.as_bytes()).expect("pubkey is always 32 bytes");
    compressed.decompress().is_some()
}

/// Account metadata — describes an account's role in an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AccountMeta {
    pub fn new(pubkey: Pubkey, is_signer: bool, is_writable: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable,
        }
    }

    pub fn new_signer(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            is_signer: true,
            is_writable: true,
        }
    }

    pub fn new_writable(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            is_signer: false,
            is_writable: true,
        }
    }

    pub fn new_readonly(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            is_signer: false,
            is_writable: false,
        }
    }
}

/// A Solana instruction — program ID + accounts + data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

impl Instruction {
    pub fn new(program_id: Pubkey, accounts: Vec<AccountMeta>, data: Vec<u8>) -> Self {
        Self {
            program_id,
            accounts,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_program_is_all_zeros() {
        assert_eq!(
            Pubkey::SYSTEM_PROGRAM.to_base58(),
            "11111111111111111111111111111111"
        );
    }

    #[test]
    fn test_spl_token_roundtrip() {
        let token = Pubkey::spl_token();
        assert_eq!(
            token.to_base58(),
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        );
    }

    #[test]
    fn test_pubkey_base58_roundtrip() {
        let pk = Pubkey::spl_token();
        let s = pk.to_base58();
        let pk2 = Pubkey::from_base58(&s).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_pda_derivation_is_deterministic() {
        let program = Pubkey::spl_token();
        let seed = b"mint";
        let (pda1, bump1) = find_program_address(&[seed], &program).unwrap();
        let (pda2, bump2) = find_program_address(&[seed], &program).unwrap();
        assert_eq!(pda1, pda2);
        assert_eq!(bump1, bump2);
    }

    #[test]
    fn test_pda_is_off_curve() {
        let program = Pubkey::spl_token();
        let (pda, _) = find_program_address(&[b"test"], &program).unwrap();
        assert!(!is_on_curve(&pda));
    }

    #[test]
    fn test_system_program_is_on_curve() {
        // The all-zeros key is technically a valid compressed point on the curve
        // (identity point), but that's fine — System Program isn't a PDA.
        // Real keypairs are on-curve; PDAs are off-curve.
        let real_keypair =
            Pubkey::from_base58("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU").unwrap();
        assert!(is_on_curve(&real_keypair));
    }
}
