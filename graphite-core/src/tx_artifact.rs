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
    #[error("compact-u16 at byte {offset} decodes to {value}, past the u16 this field is")]
    LengthNotU16 { offset: usize, value: usize },
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
    /// Larger than the network will carry. Checked before anything else is
    /// read, so the cost of an oversized artifact is one comparison.
    #[error("artifact is {len} bytes; a Solana transaction is at most {max} (PACKET_DATA_SIZE) and the network refuses anything larger")]
    TooLarge { len: usize, max: usize },
}

/// The largest serialized transaction the Solana network accepts:
/// `PACKET_DATA_SIZE` = 1280 (IPv6 minimum MTU) − 40 (IPv6 header) − 8 (UDP
/// header) = 1232 bytes. `sendTransaction` refuses anything larger, so bytes
/// past this bound describe a transaction that can never execute.
///
/// Round 9: this is also the bound that keeps the parser and L2's sibling
/// coverage (every artifact instruction against every declaration) at a cost
/// that fits inside the request timeout. Measured before the bound: a 200 KB
/// artifact of 50,000 minimal instructions with 2,000 declarations spent
/// 122 seconds in one `/verify` call.
pub const MAX_TRANSACTION_BYTES: usize = 1232;

/// One top-level instruction, with its program and accounts resolved from the
/// message's key table into addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactInstruction {
    pub program_id: String,
    /// Account addresses in instruction order. An index pointing into the
    /// lookup-table region resolves to `None`, since this module does not fetch
    /// tables — see `ArtifactMessage::alt_account_count`.
    pub accounts: Vec<Option<String>>,
    /// The raw indexes, kept so a caller holding resolved lookup tables can
    /// finish the job this module cannot.
    ///
    /// Without these the `None` positions above are a dead end: knowing THAT an
    /// account came from a table does not say which, and the index is the only
    /// thing that does. Positional comparison of a v0 instruction's accounts
    /// was skipping exactly those positions — the accounts a v0 transaction can
    /// reach without naming them.
    pub account_indexes: Vec<u8>,
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
    /// The address-table lookups this message declares, with their indexes.
    ///
    /// These were originally only COUNTED. A count tells a caller the static
    /// key list is incomplete; it cannot tell them which account arrived, which
    /// is the same count-versus-identity gap that made every earlier aggregate
    /// check defeatable. The table addresses and indexes are kept so
    /// `resolve_lookups` can turn them into identities.
    pub lookups: Vec<AddressTableLookup>,
}

/// One address-table lookup from a v0 message: which table, and which of its
/// entries this transaction pulls in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressTableLookup {
    /// The lookup table account's address.
    pub table: String,
    /// Indexes into the table's address array, resolved as writable.
    pub writable_indexes: Vec<u8>,
    /// Indexes into the table's address array, resolved as readonly.
    pub readonly_indexes: Vec<u8>,
}

impl AddressTableLookup {
    pub fn len(&self) -> usize {
        self.writable_indexes.len() + self.readonly_indexes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ArtifactMessage {
    /// Every static address the transaction references.
    pub fn all_static_addresses(&self) -> &[String] {
        &self.static_keys
    }
    /// Whether any part of the account universe lives outside the static keys.
    pub fn has_lookup_accounts(&self) -> bool {
        self.lookups.iter().any(|l| !l.is_empty())
    }
    /// How many accounts arrive through lookup tables.
    pub fn alt_account_count(&self) -> usize {
        self.lookups.iter().map(|l| l.len()).sum()
    }
    /// How many tables are referenced.
    pub fn alt_table_count(&self) -> usize {
        self.lookups.len()
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
    /// A compact-u16, and a u16 is what it has to be.
    ///
    /// Three groups of seven bits hold values up to 2,097,151, so the encoding
    /// can express numbers the field cannot mean. Solana calls this type
    /// ShortU16 and it is a u16; every length in a message — signature count,
    /// key count, instruction count, per-instruction account and data lengths,
    /// lookup counts and index-vector lengths — is one of these.
    ///
    /// Rejecting the out-of-range values matters even though `take` would
    /// eventually run out of bytes. A parser that accepts 2,097,151 as a
    /// declared length reasons about that structure first — allocating,
    /// iterating, and multiplying against it — before discovering the input was
    /// 200 bytes. Bounding at the format's own limit removes the amplification
    /// and keeps the parser's idea of the format equal to the format.
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
                if value > u16::MAX as usize {
                    return Err(ArtifactParseError::LengthNotU16 {
                        offset: start,
                        value,
                    });
                }
                return Ok(value);
            }
        }
        Err(ArtifactParseError::NonCanonicalLength { offset: start })
    }
}

/// Advance past the signature array: a compact-u16 count of 64-byte blobs.
///
/// Their contents do not matter here — Graphite verifies before signing, so an
/// artifact legitimately arrives with placeholder signatures.
fn skip_signatures(r: &mut Reader<'_>) -> Result<(), ArtifactParseError> {
    if r.bytes.is_empty() {
        return Err(ArtifactParseError::Empty);
    }
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
    Ok(())
}

/// The message half of a serialized transaction: everything after the
/// signature array.
///
/// This is the slice a signature is computed over, and the slice the
/// TypeScript bridge's `messageOf` produces for the signing gate's
/// message-equality check. It uses the SAME compact-u16 reader as
/// `parse_transaction`, so the cross-language corpus compares Graphite's
/// actual acceptance language against `@solana/web3.js`'s rather than a
/// test-local reimplementation of it.
pub fn message_bytes(bytes: &[u8]) -> Result<&[u8], ArtifactParseError> {
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(ArtifactParseError::TooLarge {
            len: bytes.len(),
            max: MAX_TRANSACTION_BYTES,
        });
    }
    let mut r = Reader::new(bytes);
    skip_signatures(&mut r)?;
    Ok(&bytes[r.pos..])
}

/// Parse a serialized Solana transaction: `[signatures][message]`.
///
/// Accepts legacy and v0. Returns the message structure, or an error — never a
/// partially-populated "best effort" value, because a caller cannot tell one of
/// those from a real answer.
pub fn parse_transaction(bytes: &[u8]) -> Result<ArtifactMessage, ArtifactParseError> {
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(ArtifactParseError::TooLarge {
            len: bytes.len(),
            max: MAX_TRANSACTION_BYTES,
        });
    }
    let mut r = Reader::new(bytes);
    skip_signatures(&mut r)?;

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
            account_indexes,
            data,
        });
    }

    // v0 lookup tables. Their entries resolve at runtime, so this counts them
    // rather than naming them — the count is what tells a caller the static key
    // list is not the whole picture.
    let mut lookups: Vec<AddressTableLookup> = Vec::new();
    if version == Some(0) {
        let table_count = r.compact_u16("address table lookup count")?;
        for _ in 0..table_count {
            let raw = r.take(32, "lookup table address")?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(raw);
            let writable_len = r.compact_u16("writable index count")?;
            let writable_indexes = r.take(writable_len, "writable indexes")?.to_vec();
            let readonly_len = r.compact_u16("readonly index count")?;
            let readonly_indexes = r.take(readonly_len, "readonly indexes")?.to_vec();
            lookups.push(AddressTableLookup {
                table: Pubkey::from_bytes(arr).to_base58(),
                writable_indexes,
                readonly_indexes,
            });
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
        lookups,
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

// ── Address lookup tables: from counted to identified ───────────────────────

/// Where a lookup table account's address array begins.
///
/// The `AddressLookupTable` account layout is a fixed-size meta block followed
/// by a packed array of 32-byte addresses:
///
/// ```text
///   0   discriminator                    u32
///   4   deactivation_slot                u64
///  12   last_extended_slot               u64
///  20   last_extended_slot_start_index   u8
///  21   authority                        Option<Pubkey>  (1 tag + 32)
///  54   _padding                         u16
///  56   addresses                        [Pubkey]
/// ```
pub const LOOKUP_TABLE_META_SIZE: usize = 56;

/// The only program whose accounts the runtime will treat as lookup tables.
pub const ADDRESS_LOOKUP_TABLE_PROGRAM: &str = "AddressLookupTab1e1111111111111111111111111";

/// A slot value meaning "not deactivating". Anything else means the table is on
/// its way out, and a table that is being retired is not one to resolve
/// security-relevant identities against.
const NOT_DEACTIVATING: u64 = u64::MAX;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LookupResolveError {
    #[error("lookup table {table} was not supplied")]
    TableMissing { table: String },
    #[error("lookup table {table} is {len} bytes, too short to hold the {LOOKUP_TABLE_META_SIZE}-byte header")]
    TableTooShort { table: String, len: usize },
    #[error("lookup table {table} has {trailing} bytes after its address array, so it is not a well-formed table")]
    TableNotAligned { table: String, trailing: usize },
    #[error("lookup table {table} is deactivating (deactivation_slot {slot})")]
    TableDeactivating { table: String, slot: u64 },
    #[error(
        "lookup table {table} has {entries} addresses; this transaction asks for index {index}"
    )]
    IndexOutOfRange {
        table: String,
        index: u8,
        entries: usize,
    },
}

/// The addresses held by one lookup table account.
///
/// Refuses a table it cannot read completely rather than returning the prefix
/// it managed to decode — a partial address list resolves some indexes and
/// silently mis-resolves others, which is worse than resolving none.
pub fn decode_lookup_table(table: &str, data: &[u8]) -> Result<Vec<String>, LookupResolveError> {
    if data.len() < LOOKUP_TABLE_META_SIZE {
        return Err(LookupResolveError::TableTooShort {
            table: table.to_string(),
            len: data.len(),
        });
    }
    let deactivation_slot = u64::from_le_bytes(
        data[4..12]
            .try_into()
            .expect("slice of exactly 8 bytes is an array"),
    );
    if deactivation_slot != NOT_DEACTIVATING {
        return Err(LookupResolveError::TableDeactivating {
            table: table.to_string(),
            slot: deactivation_slot,
        });
    }
    let body = &data[LOOKUP_TABLE_META_SIZE..];
    if !body.len().is_multiple_of(32) {
        return Err(LookupResolveError::TableNotAligned {
            table: table.to_string(),
            trailing: body.len() % 32,
        });
    }
    // The remainder `as_chunks` returns is empty by the check above, so every
    // byte of the address array is accounted for.
    Ok(body
        .as_chunks::<32>()
        .0
        .iter()
        .map(|c| Pubkey::from_bytes(*c).to_base58())
        .collect())
}

/// Every account this transaction reaches, in the order the runtime indexes them.
///
/// Solana numbers a v0 transaction's accounts as: the static keys, then every
/// writable account resolved from lookup tables in message order, then every
/// readonly one. An instruction's account index points into THAT list, so it is
/// the only thing an index can be interpreted against.
///
/// Returns `None` when the lookups could not be resolved, because a partial
/// list would renumber every position after the gap — an index would then name
/// a real account that is the wrong one, which is worse than naming nothing.
pub fn runtime_account_list(
    message: &ArtifactMessage,
    lookups: Option<&ResolvedLookups>,
) -> Option<Vec<String>> {
    if !message.has_lookup_accounts() {
        return Some(message.static_keys.clone());
    }
    let resolved = lookups?;
    if resolved.len() != message.alt_account_count() {
        // The resolution does not describe this message. Refuse rather than
        // index into a list of the wrong length.
        return None;
    }
    let mut all = message.static_keys.clone();
    all.extend(resolved.writable.iter().cloned());
    all.extend(resolved.readonly.iter().cloned());
    Some(all)
}

/// One instruction's accounts, with lookup-table indexes turned into addresses.
///
/// This is the last link of the chain an index has to travel: index → the
/// combined static-and-resolved address space → an address → the position a
/// verdict describes. Every earlier link was established; this one was skipped
/// for exactly the accounts that are hardest to see.
pub fn resolve_instruction_accounts(
    message: &ArtifactMessage,
    instruction: &ArtifactInstruction,
    lookups: Option<&ResolvedLookups>,
) -> Option<Vec<String>> {
    let all = runtime_account_list(message, lookups)?;
    instruction
        .account_indexes
        .iter()
        .map(|&i| all.get(i as usize).cloned())
        .collect()
}

/// Accounts a v0 message pulls in through lookup tables, resolved to addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedLookups {
    /// Resolved writable addresses, in the order the runtime appends them.
    pub writable: Vec<String>,
    /// Resolved readonly addresses, in the order the runtime appends them.
    pub readonly: Vec<String>,
}

impl ResolvedLookups {
    pub fn all(&self) -> impl Iterator<Item = &String> {
        self.writable.iter().chain(self.readonly.iter())
    }
    pub fn len(&self) -> usize {
        self.writable.len() + self.readonly.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Turn a message's lookups into actual addresses, given the tables' data.
///
/// `tables` maps a lookup table address to its raw account data, which the
/// caller fetches. Every index must resolve, or the whole thing errors: this is
/// the identity half of the account universe, and a partial answer here is the
/// aggregate problem again in a new place. A caller that cannot resolve must
/// report the accounts as unidentified rather than treat the resolvable subset
/// as the whole.
///
/// Ordering follows the runtime's: all writable entries across all tables in
/// message order, then all readonly. That is what makes the result comparable
/// to `preBalances` and to the account indexes inside instructions.
pub fn resolve_lookups(
    message: &ArtifactMessage,
    tables: &std::collections::HashMap<String, Vec<u8>>,
) -> Result<ResolvedLookups, LookupResolveError> {
    let mut out = ResolvedLookups::default();
    let mut decoded: std::collections::HashMap<&str, Vec<String>> =
        std::collections::HashMap::new();

    for lookup in &message.lookups {
        let data = tables
            .get(&lookup.table)
            .ok_or_else(|| LookupResolveError::TableMissing {
                table: lookup.table.clone(),
            })?;
        let addresses = decode_lookup_table(&lookup.table, data)?;
        decoded.insert(lookup.table.as_str(), addresses);
    }

    let pick = |lookup: &AddressTableLookup,
                indexes: &[u8],
                decoded: &std::collections::HashMap<&str, Vec<String>>|
     -> Result<Vec<String>, LookupResolveError> {
        let addresses = &decoded[lookup.table.as_str()];
        indexes
            .iter()
            .map(|&i| {
                addresses.get(i as usize).cloned().ok_or_else(|| {
                    LookupResolveError::IndexOutOfRange {
                        table: lookup.table.clone(),
                        index: i,
                        entries: addresses.len(),
                    }
                })
            })
            .collect()
    };

    for lookup in &message.lookups {
        out.writable
            .extend(pick(lookup, &lookup.writable_indexes, &decoded)?);
    }
    for lookup in &message.lookups {
        out.readonly
            .extend(pick(lookup, &lookup.readonly_indexes, &decoded)?);
    }
    Ok(out)
}

// ─── Durable nonces ───────────────────────────────────────────────────────────

/// The System program, base58.
pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";

/// The `SystemInstruction::AdvanceNonceAccount` discriminator, as the runtime
/// encodes it (bincode, u32 little-endian).
pub const ADVANCE_NONCE_ACCOUNT: [u8; 4] = [4, 0, 0, 0];

/// Size of a nonce account's data: version (u32) + state (u32) + authority
/// (32) + durable nonce (32) + fee calculator (u64).
pub const NONCE_ACCOUNT_SIZE: usize = 80;

/// What a durable-nonce transaction declares about itself.
///
/// The runtime's rule (`Message::get_durable_nonce`) is structural: a
/// transaction "uses a durable nonce" when its FIRST instruction is a System
/// `AdvanceNonceAccount`. When it does, the message's `recent_blockhash`
/// field is not a blockhash at all but the nonce value stored in the nonce
/// account, and the transaction does not expire — it stays valid until the
/// nonce account is advanced, which happens when this transaction (or any
/// other signed by the nonce authority) executes.
///
/// That changes what a verdict means. Every state-based conclusion Graphite
/// reaches — balances, token-account state, simulation — is true at
/// verification time, and a normal transaction is bounded to roughly a
/// minute after that by its blockhash. A durable-nonce transaction, once
/// signed, is a bearer instrument with no clock: it can be submitted an hour
/// or a month later, by whoever holds the bytes, against state that no
/// longer resembles what was verified. `lastValidBlockHeight` — the
/// expiry the bridge relies on — does not apply to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableNonce {
    /// The nonce account (instruction 0, account 0). Static by runtime rule
    /// (`require_static_nonce_account`), so it is always identifiable from
    /// the bytes.
    pub nonce_account: String,
    /// The nonce authority (instruction 0, account 2), which must sign.
    /// `None` when the instruction carries fewer than three accounts — a
    /// transaction the runtime would reject at execution, but still one
    /// that declares itself nonce-based.
    pub nonce_authority: Option<String>,
    /// Whether the authority is among the message's required signers. A
    /// nonce advance by a non-signing authority fails at execution.
    pub authority_is_signer: bool,
    /// The nonce value the message carries in its `recent_blockhash` slot.
    pub nonce_value: String,
}

/// Detect a durable-nonce transaction from the parsed message, using the
/// runtime's own rule: instruction 0 is a System `AdvanceNonceAccount` with
/// at least one account.
///
/// The discriminator check accepts trailing bytes after the four, exactly as
/// the runtime's `limited_deserialize` does — a transaction that the runtime
/// treats as nonce-based must be treated as nonce-based here, whatever else
/// is appended to the instruction.
pub fn durable_nonce(message: &ArtifactMessage) -> Option<DurableNonce> {
    let ix = message.instructions.first()?;
    if ix.program_id != SYSTEM_PROGRAM {
        return None;
    }
    if ix.data.len() < ADVANCE_NONCE_ACCOUNT.len()
        || ix.data[..ADVANCE_NONCE_ACCOUNT.len()] != ADVANCE_NONCE_ACCOUNT
    {
        return None;
    }
    // The nonce account is required to be static, so its index resolves
    // without any lookup table. An index that does not resolve names an
    // account the runtime would not accept as a nonce account either — the
    // transaction is still declared nonce-based, and the nonce account is
    // then reported as the unresolvable position rather than dropped.
    let nonce_account = match ix.accounts.first()? {
        Some(addr) => addr.clone(),
        None => format!(
            "<lookup-table index {}>",
            ix.account_indexes.first().copied().unwrap_or(0)
        ),
    };
    let nonce_authority = ix.accounts.get(2).and_then(|a| a.clone());
    let authority_is_signer = nonce_authority
        .as_ref()
        .is_some_and(|a| message.signers.contains(a));
    Some(DurableNonce {
        nonce_account,
        nonce_authority,
        authority_is_signer,
        nonce_value: message.recent_blockhash.clone(),
    })
}

/// What a fetched nonce account says, decoded from the runtime's layout.
///
/// Layout (`NonceVersions`/`NonceState`, bincode): `u32` version — `0` is
/// the legacy layout, `1` the current — then `u32` state (`0` uninitialized,
/// `1` initialized), then for an initialized account the 32-byte authority,
/// the 32-byte durable nonce and a `u64` fee calculator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceAccountState {
    pub authority: String,
    pub nonce_value: String,
}

/// Decode a nonce account's data. `Err` explains why the bytes are not an
/// initialized nonce account the runtime would honour.
pub fn decode_nonce_account(owner: &str, data: &[u8]) -> Result<NonceAccountState, String> {
    if owner != SYSTEM_PROGRAM {
        return Err(format!(
            "owned by {owner}, not the System program; the runtime only honours a System-owned nonce account"
        ));
    }
    if data.len() < NONCE_ACCOUNT_SIZE {
        return Err(format!(
            "{} bytes of data; an initialized nonce account has {NONCE_ACCOUNT_SIZE}",
            data.len()
        ));
    }
    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if version > 1 {
        return Err(format!(
            "nonce account version {version} is not one the runtime defines"
        ));
    }
    let state = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if state != 1 {
        return Err(format!(
            "nonce account state {state} is not Initialized; an uninitialized nonce account cannot advance"
        ));
    }
    let authority = Pubkey::from_bytes(data[8..40].try_into().expect("32 bytes")).to_base58();
    let nonce_value = Pubkey::from_bytes(data[40..72].try_into().expect("32 bytes")).to_base58();
    Ok(NonceAccountState {
        authority,
        nonce_value,
    })
}

/// Check a declared durable nonce against the nonce account's on-chain state.
///
/// Every mismatch is fatal to execution — the runtime refuses the
/// transaction at load — and a verdict about a transaction that cannot run
/// is a verdict about nothing. The stored nonce value must be the value the
/// message carries (a stale value means the nonce has already advanced and
/// the transaction is dead; a different one means it was never built
/// against this account), and the stored authority must be the signer the
/// instruction names.
pub fn check_durable_nonce(
    declared: &DurableNonce,
    account: &NonceAccountState,
) -> Result<(), String> {
    if account.nonce_value != declared.nonce_value {
        return Err(format!(
            "the message carries nonce value {} but the nonce account holds {}: the nonce has advanced or the transaction was built against a different account, and the runtime will refuse it",
            declared.nonce_value, account.nonce_value
        ));
    }
    match &declared.nonce_authority {
        Some(auth) if auth == &account.authority => {}
        Some(auth) => {
            return Err(format!(
                "instruction 0 names {auth} as the nonce authority but the account's authority is {}",
                account.authority
            ))
        }
        None => {
            return Err(
                "instruction 0 names no nonce authority (fewer than three accounts); the advance cannot execute"
                    .to_string(),
            )
        }
    }
    if !declared.authority_is_signer {
        return Err(format!(
            "the nonce authority {} is not a required signer of the message; the advance cannot execute",
            account.authority
        ));
    }
    Ok(())
}
