//! Reading a Solana transaction artifact well enough to check it against what
//! Graphite was told it contains.
//!
//! # Why this exists
//!
//! Graphite's promise is that the thing it approved is the thing that gets
//! signed. Until now it approached that by MEASURING the artifact — hashing it,
//! simulating it, counting the accounts it touched, searching it for the
//! described instruction's bytes. Each of those closed a real exploit. Each was
//! then defeated, or shown to be defeatable, by the same move: the attacker
//! matches the measurement while changing the thing measured.
//!
//! - Coverage compared account COUNTS, so naming one extra address restored the
//!   count while hiding a real one.
//! - The instruction-data check proves those bytes are somewhere in the
//!   transaction, not that they belong to the described instruction.
//! - A sibling instruction was caught, but by L4's state diff rather than by
//!   anything establishing correspondence — and only because the account
//!   universe check had forced the sibling to use accounts L4 was already
//!   watching.
//!
//! The pattern is not that the checks were bad. It is that identity cannot be
//! inferred from aggregates. So this module reads the message.
//!
//! # What it deliberately is not
//!
//! Not a `solana-sdk` replacement, and not a validator. It does not verify
//! signatures, resolve address lookup tables, or interpret instruction data. It
//! recovers the message's *structure* — account keys, privileges, fee payer,
//! and the ordered list of instructions with their program and accounts — which
//! is precisely the layer at which "is the instruction Graphite verified
//! actually in here?" becomes answerable.
//!
//! # Fail-closed
//!
//! Every parse returns `Result`, and a failure is never converted into a pass
//! by any caller. An artifact Graphite cannot read is one it makes no
//! structural claim about; the pre-existing checks still apply, and the scope
//! reports the absence. That ordering matters: a hand-rolled wire parser that
//! could *manufacture* an approval would be worse than no parser at all, which
//! is why nothing here returns a boolean that means "fine".

use crate::solana_types::Pubkey;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ArtifactParseError {
    #[error("artifact is empty")]
    Empty,
    #[error("truncated at byte {offset} while reading {what}")]
    Truncated { offset: usize, what: &'static str },
    #[error("compact-u16 at byte {offset} is not minimally encoded")]
    NonCanonicalLength { offset: usize },
    #[error("declared {declared} {what} but only {available} bytes remain")]
    LengthExceedsInput {
        what: &'static str,
        declared: usize,
        available: usize,
    },
    #[error("message version {0} is not supported (only legacy and v0)")]
    UnsupportedVersion(u8),
    #[error("header claims {signers} signers and {readonly_signed} readonly-signed of {keys} account keys")]
    ImpossibleHeader {
        signers: usize,
        readonly_signed: usize,
        keys: usize,
    },
    #[error("instruction {index} names program index {program_index}, past {keys} account keys")]
    ProgramIndexOutOfRange {
        index: usize,
        program_index: usize,
        keys: usize,
    },
    #[error("instruction {index} names account index {account_index}, past {keys} account keys")]
    AccountIndexOutOfRange {
        index: usize,
        account_index: usize,
        keys: usize,
    },
    #[error("{trailing} trailing bytes after the message")]
    TrailingBytes { trailing: usize },
}

/// One top-level instruction, with its program and accounts resolved from the
/// message's key table into addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactInstruction {
    pub program_id: String,
    /// Account addresses in instruction order. An index pointing into the
    /// lookup-table region resolves to `None`, since this module does not fetch
    /// tables — see `ArtifactMessage::alt_account_count`.
    pub accounts: Vec<Option<String>>,
    pub data: Vec<u8>,
}

impl ArtifactInstruction {
    /// The accounts this instruction names that the parser could resolve.
    pub fn resolved_accounts(&self) -> Vec<&str> {
        self.accounts.iter().filter_map(|a| a.as_deref()).collect()
    }
    /// True when any account came from a lookup table rather than the static
    /// key list, so a comparison against it is necessarily incomplete.
    pub fn has_unresolved_accounts(&self) -> bool {
        self.accounts.iter().any(|a| a.is_none())
    }
}

/// A parsed Solana message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactMessage {
    /// `None` for a legacy message, `Some(0)` for v0.
    pub version: Option<u8>,
    /// Static account keys, in message order. Lookup-table accounts are NOT
    /// here; `alt_account_count` says how many were referenced.
    pub static_keys: Vec<String>,
    /// The fee payer: static key 0, and always a writable signer.
    pub fee_payer: String,
    /// Addresses required to sign, from the header's signer count.
    pub signers: Vec<String>,
    /// Static addresses the message marks writable. Lookup-table writables are
    /// counted, not named.
    pub writable: Vec<String>,
    /// The recent blockhash (or durable-nonce value), base58.
    ///
    /// Captured rather than skipped. It was originally read and discarded, and
    /// a byte-flip sweep over a real devnet transaction caught it immediately:
    /// thirty-two consecutive bytes could change without changing the parse, so
    /// two different transactions read identically. It is also
    /// security-relevant in its own right — it fixes the replay window, and a
    /// durable nonce replaces it with a value that does not expire.
    pub recent_blockhash: String,
    pub instructions: Vec<ArtifactInstruction>,
    /// How many accounts this message pulls in through address lookup tables.
    /// Non-zero means the static key list is not the whole account universe.
    pub alt_account_count: usize,
    /// How many lookup tables were referenced.
    pub alt_table_count: usize,
}

impl ArtifactMessage {
    /// Every static address the transaction references.
    pub fn all_static_addresses(&self) -> &[String] {
        &self.static_keys
    }
    /// Whether any part of the account universe lives outside the static keys.
    pub fn has_lookup_accounts(&self) -> bool {
        self.alt_account_count > 0
    }
}

/// A cursor that cannot read past its input.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }
    fn peek(&self, what: &'static str) -> Result<u8, ArtifactParseError> {
        self.bytes
            .get(self.pos)
            .copied()
            .ok_or(ArtifactParseError::Truncated {
                offset: self.pos,
                what,
            })
    }
    fn u8(&mut self, what: &'static str) -> Result<u8, ArtifactParseError> {
        let b = self.peek(what)?;
        self.pos += 1;
        Ok(b)
    }
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], ArtifactParseError> {
        if self.remaining() < n {
            return Err(ArtifactParseError::LengthExceedsInput {
                what,
                declared: n,
                available: self.remaining(),
            });
        }
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Solana's compact-u16 (aka "short vec"): 1–3 bytes, 7 bits each,
    /// continuation in the high bit.
    ///
    /// Canonical encoding is enforced. A non-minimal length — `0x80 0x00`
    /// for zero, say — is a second spelling of the same number, and two
    /// spellings of the same transaction are exactly what a binding is
    /// supposed to prevent. Solana's own decoder rejects these; so does this.
    fn compact_u16(&mut self, what: &'static str) -> Result<usize, ArtifactParseError> {
        let start = self.pos;
        let mut value: usize = 0;
        for group in 0..3 {
            let byte = self.u8(what)?;
            let bits = (byte & 0x7f) as usize;
            value |= bits << (group * 7);
            if byte & 0x80 == 0 {
                // Minimal: a multi-byte encoding must not have a zero final
                // group, and the whole value must not fit in fewer groups.
                if group > 0 && bits == 0 {
                    return Err(ArtifactParseError::NonCanonicalLength { offset: start });
                }
                return Ok(value);
            }
        }
        Err(ArtifactParseError::NonCanonicalLength { offset: start })
    }
}

/// Parse a serialized Solana transaction: `[signatures][message]`.
///
/// Accepts legacy and v0. Returns the message structure, or an error — never a
/// partially-populated "best effort" value, because a caller cannot tell one of
/// those from a real answer.
pub fn parse_transaction(bytes: &[u8]) -> Result<ArtifactMessage, ArtifactParseError> {
    if bytes.is_empty() {
        return Err(ArtifactParseError::Empty);
    }
    let mut r = Reader::new(bytes);

    // Signatures: a compact array of 64-byte blobs. Their contents do not
    // matter here — Graphite verifies before signing, so an artifact legitimately
    // arrives with placeholder signatures.
    let sig_count = r.compact_u16("signature count")?;
    let _ = r.take(
        sig_count
            .checked_mul(64)
            .ok_or(ArtifactParseError::LengthExceedsInput {
                what: "signatures",
                declared: sig_count,
                available: r.remaining(),
            })?,
        "signatures",
    )?;

    // Version prefix: the high bit of the first message byte marks a versioned
    // message. Legacy messages start with the header, whose first byte is a
    // signer count and so always has the high bit clear.
    let first = r.peek("message header")?;
    let version = if first & 0x80 != 0 {
        let v = r.u8("message version")? & 0x7f;
        if v != 0 {
            return Err(ArtifactParseError::UnsupportedVersion(v));
        }
        Some(0u8)
    } else {
        None
    };

    let num_required_signatures = r.u8("num_required_signatures")? as usize;
    let num_readonly_signed = r.u8("num_readonly_signed_accounts")? as usize;
    let num_readonly_unsigned = r.u8("num_readonly_unsigned_accounts")? as usize;

    let key_count = r.compact_u16("account key count")?;
    let mut static_keys = Vec::with_capacity(key_count.min(256));
    for _ in 0..key_count {
        let raw = r.take(32, "account key")?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(raw);
        static_keys.push(Pubkey::from_bytes(arr).to_base58());
    }

    if num_required_signatures > key_count
        || num_readonly_signed > num_required_signatures
        || num_readonly_unsigned > key_count.saturating_sub(num_required_signatures)
        || key_count == 0
    {
        return Err(ArtifactParseError::ImpossibleHeader {
            signers: num_required_signatures,
            readonly_signed: num_readonly_signed,
            keys: key_count,
        });
    }

    let recent_blockhash = {
        let raw = r.take(32, "recent blockhash")?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(raw);
        Pubkey::from_bytes(arr).to_base58()
    };

    let instruction_count = r.compact_u16("instruction count")?;
    let mut instructions = Vec::with_capacity(instruction_count.min(64));
    for index in 0..instruction_count {
        let program_index = r.u8("instruction program index")? as usize;
        let account_index_count = r.compact_u16("instruction account count")?;
        let account_indexes = r
            .take(account_index_count, "instruction accounts")?
            .to_vec();
        let data_len = r.compact_u16("instruction data length")?;
        let data = r.take(data_len, "instruction data")?.to_vec();

        // A program id can never come from a lookup table — Solana requires it
        // in the static keys — so an out-of-range program index is malformed
        // rather than merely unresolvable.
        let program_id = static_keys.get(program_index).cloned().ok_or(
            ArtifactParseError::ProgramIndexOutOfRange {
                index,
                program_index,
                keys: key_count,
            },
        )?;

        instructions.push(ArtifactInstruction {
            program_id,
            accounts: account_indexes
                .iter()
                .map(|&i| static_keys.get(i as usize).cloned())
                .collect(),
            data,
        });
    }

    // v0 lookup tables. Their entries resolve at runtime, so this counts them
    // rather than naming them — the count is what tells a caller the static key
    // list is not the whole picture.
    let (mut alt_account_count, mut alt_table_count) = (0usize, 0usize);
    if version == Some(0) {
        alt_table_count = r.compact_u16("address table lookup count")?;
        for _ in 0..alt_table_count {
            let _table = r.take(32, "lookup table address")?;
            let writable = r.compact_u16("writable index count")?;
            let _ = r.take(writable, "writable indexes")?;
            let readonly = r.compact_u16("readonly index count")?;
            let _ = r.take(readonly, "readonly indexes")?;
            alt_account_count += writable + readonly;
        }
    }

    // Trailing bytes mean this is not the message it claims to be. Ignoring
    // them would let two different byte strings parse to the same structure,
    // which is the ambiguity a binding exists to rule out.
    if r.remaining() != 0 {
        return Err(ArtifactParseError::TrailingBytes {
            trailing: r.remaining(),
        });
    }

    // Privileges, per Solana's positional layout: the first
    // `num_required_signatures` keys sign, of which the last
    // `num_readonly_signed` are readonly; at the tail, the last
    // `num_readonly_unsigned` are readonly.
    let signers: Vec<String> = static_keys[..num_required_signatures].to_vec();
    let writable_signed = num_required_signatures - num_readonly_signed;
    let unsigned_writable_end = key_count - num_readonly_unsigned;
    let mut writable: Vec<String> = static_keys[..writable_signed].to_vec();
    writable.extend_from_slice(&static_keys[num_required_signatures..unsigned_writable_end]);

    Ok(ArtifactMessage {
        version,
        fee_payer: static_keys[0].clone(),
        recent_blockhash,
        signers,
        writable,
        static_keys,
        instructions,
        alt_account_count,
        alt_table_count,
    })
}

/// How an artifact's parsed contents line up with what the request described.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Correspondence {
    /// Index of the instruction matching the described program, discriminator
    /// and data, when exactly one matches.
    pub matched_instruction: Option<usize>,
    /// Instructions in the artifact that the request did not describe — by
    /// index and program. This is the sibling-injection surface, read from the
    /// bytes rather than from the caller's account of them.
    pub undescribed_instructions: Vec<(usize, String)>,
    /// Static addresses in the artifact that appear nowhere in the request.
    pub undescribed_accounts: Vec<String>,
    /// Described addresses absent from the artifact's static keys. Expected
    /// when the transaction uses lookup tables; suspicious otherwise.
    pub described_but_absent: Vec<String>,
}

/// Compare a parsed artifact against the described instruction and account set.
///
/// Reports; it does not judge. The caller owns severity, because what counts as
/// acceptable differs between a legacy transaction (where the static keys are
/// the whole universe) and a v0 one (where they are not).
pub fn correspond(
    message: &ArtifactMessage,
    described_program: &str,
    described_data: Option<&[u8]>,
    described_accounts: &[String],
) -> Correspondence {
    let matched_instruction = described_data.and_then(|data| {
        let hits: Vec<usize> = message
            .instructions
            .iter()
            .enumerate()
            .filter(|(_, ix)| ix.program_id == described_program && ix.data == data)
            .map(|(i, _)| i)
            .collect();
        // Exactly one. Two instructions identical under the same program are
        // indistinguishable to the description, and picking either would be a
        // guess presented as a fact.
        if hits.len() == 1 {
            Some(hits[0])
        } else {
            None
        }
    });

    let undescribed_instructions = message
        .instructions
        .iter()
        .enumerate()
        .filter(|(i, _)| Some(*i) != matched_instruction)
        .map(|(i, ix)| (i, ix.program_id.clone()))
        .collect();

    let described: std::collections::HashSet<&str> =
        described_accounts.iter().map(|a| a.as_str()).collect();
    let undescribed_accounts = message
        .static_keys
        .iter()
        .filter(|k| k.as_str() != described_program && !described.contains(k.as_str()))
        .cloned()
        .collect();

    let in_artifact: std::collections::HashSet<&str> =
        message.static_keys.iter().map(|k| k.as_str()).collect();
    let described_but_absent = described_accounts
        .iter()
        .filter(|a| !in_artifact.contains(a.as_str()))
        .cloned()
        .collect();

    Correspondence {
        matched_instruction,
        undescribed_instructions,
        undescribed_accounts,
        described_but_absent,
    }
}
