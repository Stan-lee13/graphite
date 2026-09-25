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
//! Not a `solana-sdk` replacement, and not a validator. It does not resolve
//! address lookup tables or interpret instruction data, and it verifies a
//! signature for exactly one purpose: binding the bytes an RPC returns for a
//! signature to that signature (`bound_artifact_sha256`, L8). Otherwise it
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
    /// A version this frame cannot carry. Legacy and v0 messages follow a
    /// compact-u16 signature count; a v1 message is accepted only as a v1
    /// frame (`0x81` first, signatures last), exactly as the runtime's
    /// `VersionedTransaction` decoder dispatches — a v1 message behind a
    /// signature count is "invalid message version" there too. Versions 2
    /// and up do not exist (Round 19, F-19-V1).
    #[error("message version {0} is not supported in this frame (legacy and v0 follow a signature count; v1 is accepted only as a v1 frame, 0x81 first with its signatures last; versions 2 and up are not defined and are refused)")]
    UnsupportedVersion(u8),
    /// A v1 frame that breaks one of the v1 format's own rules — the config
    /// mask the deserializer refuses, or a limit `v1::Message::validate`
    /// enforces (Round 19, F-19-V1). Rules v1 shares with legacy and v0
    /// (header arithmetic, duplicate keys, index ranges, trailing bytes)
    /// keep their existing variants.
    #[error("v1 transaction refused: {0}")]
    V1Refused(V1Violation),
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
    /// The instruction's program is static key 0, the fee payer. The runtime
    /// refuses this at sanitization ("a program cannot be a payer"), so the
    /// frame can never execute (Round 12, runtime oracle).
    #[error("instruction {index} names the fee payer (key 0) as its program; the runtime refuses a payer program")]
    ProgramIsFeePayer { index: usize },
    /// A v0 lookup that loads nothing. The runtime requires every declared
    /// table to load at least one address (Round 12, runtime oracle).
    #[error("lookup table {table} loads no addresses; the runtime refuses an empty lookup")]
    EmptyLookup { table: String },
    /// Static keys plus lookup-loaded keys exceed the 256 an account index
    /// can address. The runtime refuses the message (Round 12, runtime
    /// oracle).
    #[error("{total} account keys (static and loaded); the runtime addresses at most 256")]
    TooManyAccounts { total: usize },
    #[error("account key {key} appears at static positions {first} and {second}; the runtime refuses a transaction that loads an account twice (AccountLoadedTwice)")]
    DuplicateAccountKey {
        key: String,
        first: usize,
        second: usize,
    },
    #[error("{trailing} trailing bytes after the message")]
    TrailingBytes { trailing: usize },
    /// The signature array and the header disagree about how many signers
    /// there are. The runtime sanitizes a transaction only when they are
    /// equal, so this frame can never execute — and a frame that cannot
    /// execute is not one Graphite makes claims about.
    #[error("{declared} signature slots but the header requires {required} signers; the runtime refuses the mismatch")]
    SignatureCountMismatch { declared: usize, required: usize },
    /// Larger than the network will carry. Checked before anything else is
    /// read, so the cost of an oversized artifact is one comparison.
    #[error("artifact is {len} bytes; a Solana transaction in this frame format is at most {max} (1232 = PACKET_DATA_SIZE for legacy and v0, 4096 for v1) and the network refuses anything larger")]
    TooLarge { len: usize, max: usize },
}

/// Which v1 rule a frame broke. Each one is a refusal the runtime makes —
/// in its wire decoder (the config mask) or in `v1::Message::validate`
/// (everything else) — so a frame carrying one can never execute (Round 19,
/// F-19-V1).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum V1Violation {
    /// A mask bit no known config field claims. The runtime's decoder refuses
    /// it: an unknown bit would be dropped on re-serialization, so the bytes
    /// signed would not be the bytes executed.
    #[error("config mask {mask:#010x} sets bits no v1 config field defines")]
    ConfigMaskUnknownBits { mask: u32 },
    /// Only one of the two priority-fee bits. The fee is a u64 spread over a
    /// bit PAIR, and the decoder refuses half of one.
    #[error("config mask {mask:#010x} sets one of the two priority-fee bits; both or neither")]
    ConfigMaskPartialPriorityFee { mask: u32 },
    #[error("{count} required signatures; a v1 transaction carries at most {max}")]
    TooManySignatures { count: usize, max: usize },
    #[error("{count} account addresses; a v1 message holds at most {max}")]
    TooManyAddresses { count: usize, max: usize },
    #[error("{count} instructions; a v1 message holds at most {max}")]
    TooManyInstructions { count: usize, max: usize },
    #[error("requested heap size {heap_size} is not a multiple of 1024 within [32768, 262144]")]
    InvalidHeapSize { heap_size: u32 },
}

/// The largest serialized legacy or v0 transaction the Solana network
/// accepts: `PACKET_DATA_SIZE` = 1280 (IPv6 minimum MTU) − 40 (IPv6 header) −
/// 8 (UDP header) = 1232 bytes. `sendTransaction` refuses anything larger, so
/// bytes past this bound describe a transaction that can never execute.
///
/// Round 9: this is also the bound that keeps the parser and L2's sibling
/// coverage (every artifact instruction against every declaration) at a cost
/// that fits inside the request timeout. Measured before the bound: a 200 KB
/// artifact of 50,000 minimal instructions with 2,000 declarations spent
/// 122 seconds in one `/verify` call.
///
/// This is the bound for legacy and v0 frames ONLY. A v1 frame is bounded by
/// `MAX_V1_TRANSACTION_BYTES`; use `max_frame_bytes` wherever the frame's
/// format is not already known (Round 19, F-19-V1).
pub const MAX_TRANSACTION_BYTES: usize = 1232;

/// The first byte of a v1 (SIMD-0385) frame: `MESSAGE_VERSION_PREFIX | 1`.
/// A legacy or v0 frame begins with a compact-u16 signature count, which the
/// runtime reads as a single byte below 0x80, so the two cannot be confused.
pub const V1_PREFIX: u8 = 0x81;

/// The largest v1 transaction: `solana_message::v1::MAX_TRANSACTION_SIZE`,
/// signatures included. v1 exists to carry transactions past the 1232-byte
/// packet, and 2,399 of the 3,302 v1 transactions in the Round 18 mainnet
/// sample are larger than 1232 bytes (Round 19, F-19-V1). The bound still
/// does Round 9's job: 64 instructions at most, in 4 KB.
pub const MAX_V1_TRANSACTION_BYTES: usize = 4096;

/// `v1::MAX_SIGNATURES`.
pub const V1_MAX_SIGNATURES: usize = 12;
/// `v1::MAX_ADDRESSES`.
pub const V1_MAX_ADDRESSES: usize = 64;
/// `v1::MAX_INSTRUCTIONS`.
pub const V1_MAX_INSTRUCTIONS: usize = 64;
/// `v1::MIN_HEAP_SIZE` (32 KiB).
pub const V1_MIN_HEAP_SIZE: u32 = 32 * 1024;
/// `v1::MAX_HEAP_SIZE` (256 KiB).
pub const V1_MAX_HEAP_SIZE: u32 = 256 * 1024;

/// `TransactionConfigMask` bits, from `solana-message` 5.0 `v1/config.rs`.
const V1_MASK_PRIORITY_FEE: u32 = 0b11;
const V1_MASK_COMPUTE_UNIT_LIMIT: u32 = 0b100;
const V1_MASK_LOADED_ACCOUNTS_DATA_SIZE: u32 = 0b1000;
const V1_MASK_HEAP_SIZE: u32 = 0b1_0000;
const V1_MASK_KNOWN_BITS: u32 = V1_MASK_PRIORITY_FEE
    | V1_MASK_COMPUTE_UNIT_LIMIT
    | V1_MASK_LOADED_ACCOUNTS_DATA_SIZE
    | V1_MASK_HEAP_SIZE;

/// Where a v1 frame keeps its lifetime specifier (blockhash): after the
/// prefix byte, the 3-byte header and the 4-byte config mask.
const V1_LIFETIME_OFFSET: usize = 1 + 3 + 4;

/// Whether these bytes are a v1 frame: the runtime dispatches on the first
/// byte alone, and so does every function here.
pub fn is_v1_frame(bytes: &[u8]) -> bool {
    bytes.first() == Some(&V1_PREFIX)
}

/// The size bound for THIS frame's format: 4096 bytes for a v1 frame, 1232
/// (the packet) for everything else. A caller that enforces a size before
/// parsing must use this, not `MAX_TRANSACTION_BYTES`, or it refuses every
/// v1 transaction larger than a packet — which is most of them (Round 19,
/// F-19-V1).
pub fn max_frame_bytes(bytes: &[u8]) -> usize {
    if is_v1_frame(bytes) {
        MAX_V1_TRANSACTION_BYTES
    } else {
        MAX_TRANSACTION_BYTES
    }
}

/// Refuse a frame larger than its format allows. First, before any byte is
/// read, so the cost of an oversized artifact is one comparison.
fn check_frame_size(bytes: &[u8]) -> Result<(), ArtifactParseError> {
    let max = max_frame_bytes(bytes);
    if bytes.len() > max {
        return Err(ArtifactParseError::TooLarge {
            len: bytes.len(),
            max,
        });
    }
    Ok(())
}

/// The compute-budget values a v1 message carries in its header instead of
/// in ComputeBudget instructions (SIMD-0385). Each is `None` when its mask
/// bit is clear.
///
/// Exposed so later layers can see them (Round 19, F-19-V1): a v1
/// transaction's priority fee and compute limit are NOT in any instruction,
/// so a layer that looks for ComputeBudget instructions finds nothing and
/// would report a v1 transaction as having no fee and the default limit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct V1Config {
    /// Priority fee in lamports (mask bits 0–1, u64).
    pub priority_fee: Option<u64>,
    /// Compute-unit limit (mask bit 2, u32).
    pub compute_unit_limit: Option<u32>,
    /// Loaded-accounts data-size limit in bytes (mask bit 3, u32).
    pub loaded_accounts_data_size_limit: Option<u32>,
    /// Requested heap size in bytes (mask bit 4, u32); validated to be a
    /// multiple of 1024 within [32 KiB, 256 KiB].
    pub heap_size: Option<u32>,
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
    /// `None` for a legacy message, `Some(0)` for v0, `Some(1)` for v1.
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
    /// The v1 header's compute-budget values; `Some` exactly when the message
    /// is v1 (with every field `None` if its mask is zero), `None` for legacy
    /// and v0 (Round 19, F-19-V1). For a v1 message `recent_blockhash` holds
    /// the lifetime specifier and `lookups` is always empty — v1 has no
    /// address lookup tables.
    pub v1_config: Option<V1Config>,
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
fn skip_signatures(r: &mut Reader<'_>) -> Result<usize, ArtifactParseError> {
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
    Ok(sig_count)
}

/// Where a frame keeps its signatures and its signed-over message.
///
/// The two frame formats put them in opposite places. A legacy or v0 frame
/// is `[compact-u16 count][count × 64][message]`; a v1 frame is
/// `[0x81][message body][num_required_signatures × 64]` with NO count — the
/// header's signer count sizes the array, and it comes LAST
/// (`solana-transaction` 5.0, `SchemaRead for VersionedTransaction`). Every
/// function that indexes signatures positionally goes through this, so none
/// of them can read a v1 frame's instruction bytes as a signature slot, or a
/// v1 frame's `0x81` as a count (Round 19, F-19-V1).
struct FrameLayout {
    /// The signature slots, `count × 64` bytes.
    signatures: std::ops::Range<usize>,
    /// The bytes the signatures are computed over — the runtime's
    /// `VersionedMessage::serialize()`, version prefix included.
    message: std::ops::Range<usize>,
}

/// Locate a frame's signatures and message. Refuses what `parse_transaction`
/// refuses about the frame: the size bound for its format and a signature
/// array that runs past the input. For a v1
/// frame the signatures can only be found by walking the message to its end,
/// so a v1 frame must parse in full — anything less would be guessing where
/// the slots are.
fn frame_layout(bytes: &[u8]) -> Result<FrameLayout, ArtifactParseError> {
    check_frame_size(bytes)?;
    let first = *bytes.first().ok_or(ArtifactParseError::Empty)?;
    if first == V1_PREFIX {
        let (_, message_end) = parse_v1(bytes)?;
        // `parse_v1` has required exactly the header's signature count after
        // the message and nothing after that.
        return Ok(FrameLayout {
            signatures: message_end..bytes.len(),
            message: 0..message_end,
        });
    }
    // Any other first byte with the high bit set is a frame discriminator the
    // runtime refuses ("invalid transaction discriminator"). Here it is the
    // first byte of a canonical compact-u16 of at least 128, and 128
    // signature slots are 8,192 bytes, which no 1232-byte frame holds — so
    // it is refused by the signature reader below, never read as a frame.
    let mut r = Reader::new(bytes);
    let sig_count = skip_signatures(&mut r)?;
    let sig_len = sig_count * 64;
    Ok(FrameLayout {
        signatures: r.pos - sig_len..r.pos,
        message: r.pos..bytes.len(),
    })
}

/// The bytes Graphite was shown, recovered from a signed transaction: the
/// same frame with every signature slot zeroed.
///
/// The bridge serializes the artifact before signing, so its signature slots
/// are 64 zero bytes each and `transaction_sha256` is the digest of that
/// frame. A transaction fetched from the chain carries real signatures in
/// the same slots and nothing else differs — the count prefix and the
/// message are byte-identical — so zeroing the slots reproduces the artifact
/// exactly, and its SHA-256 is the key that joins an on-chain execution to
/// the verification of those exact bytes (Round 10). Refuses what
/// `parse_transaction` refuses about the frame: the size bound and a
/// signature array that runs past the input. For a v1 frame the slots are
/// the trailing `num_required_signatures × 64` bytes, and the frame must
/// parse in full to find them (Round 19, F-19-V1).
pub fn unsigned_artifact(bytes: &[u8]) -> Result<Vec<u8>, ArtifactParseError> {
    let layout = frame_layout(bytes)?;
    let mut out = bytes.to_vec();
    out[layout.signatures].fill(0);
    Ok(out)
}

/// How many signature slots of this frame hold something other than 64 zero
/// bytes.
///
/// Graphite verifies before signing, so the artifact it is shown must carry
/// empty slots; a filled slot means the bytes were signed first (Round 17,
/// F-16-01). Refuses what `unsigned_artifact` refuses about the frame, and
/// finds a v1 frame's slots at its end (Round 19, F-19-V1).
pub fn filled_signature_slots(bytes: &[u8]) -> Result<usize, ArtifactParseError> {
    let layout = frame_layout(bytes)?;
    // The range is `count × 64` bytes by construction, so `as_chunks` leaves
    // no remainder.
    Ok(bytes[layout.signatures]
        .as_chunks::<64>()
        .0
        .iter()
        .filter(|slot| slot.iter().any(|b| *b != 0))
        .count())
}

/// What a simulation of these bytes executes, as a hex digest: the frame with
/// every signature slot AND the recent-blockhash field zeroed, SHA-256'd under
/// a domain tag (Round 19, F-19-01).
///
/// This is the identity of an OBSERVATION, not of an artifact. Graphite
/// simulates with `replaceRecentBlockhash: true` (see
/// `rpc_client::simulate_config`), so two artifacts that differ only in their
/// blockhash are executed identically — same instructions, same accounts,
/// same data — and measuring both is measuring one thing twice. Keying the
/// baseline on `artifact_sha256` let the same transfer, re-asked with a fresh
/// blockhash (which every agent retry fetches anyway), count as a new
/// observation each time: refused at 0.44 on the first ask, approved on the
/// third, with nothing about the transaction changed. The verdict's own
/// binding (`scope.transaction_sha256`) still covers the blockhash — this
/// digest is used only to decide what counts as evidence.
///
/// The frame must parse (`parse_transaction`), so an identity always names a
/// real legacy, v0 or v1 message. For a durable-nonce transaction the zeroed
/// field is the nonce value, which the simulator replaces in the same way.
///
/// A v1 frame keeps its lifetime specifier at a fixed offset — after the
/// `0x81` prefix, the 3-byte header and the 4-byte config mask — and its
/// signatures at the end; both are zeroed there, and the config values
/// (priority fee, compute limit, heap) are NOT, because the simulator
/// executes under them (Round 19, F-19-V1). The prefix byte stays in the
/// digest, so a v1 identity can never equal a legacy or v0 one.
pub fn simulation_identity(bytes: &[u8]) -> Result<String, ArtifactParseError> {
    use sha2::{Digest, Sha256};
    let _ = parse_transaction(bytes)?;
    let mut out = unsigned_artifact(bytes)?;
    let at = if is_v1_frame(bytes) {
        V1_LIFETIME_OFFSET
    } else {
        let mut r = Reader::new(bytes);
        skip_signatures(&mut r)?;
        if r.peek("message header")? & 0x80 != 0 {
            let _ = r.u8("message version")?;
        }
        let _ = r.take(3, "message header")?;
        let key_count = r.compact_u16("account key count")?;
        let _ = r.take(
            key_count
                .checked_mul(32)
                .ok_or(ArtifactParseError::LengthExceedsInput {
                    what: "account keys",
                    declared: key_count,
                    available: r.remaining(),
                })?,
            "account keys",
        )?;
        r.pos
    };
    // `parse_transaction` has read 32 bytes at `at` as the blockhash (legacy,
    // v0) or lifetime specifier (v1), so the range is in bounds.
    out[at..at + 32].fill(0);
    let mut h = Sha256::new();
    h.update(b"graphite/simulation-identity/v1\0");
    h.update(&out);
    Ok(hex::encode(h.finalize()))
}

/// SHA-256 of `unsigned_artifact(bytes)`, hex — what `scope.transaction_sha256`
/// holds for the verification of these bytes.
pub fn artifact_sha256_of_signed(bytes: &[u8]) -> Result<String, ArtifactParseError> {
    use sha2::{Digest, Sha256};
    Ok(hex::encode(Sha256::digest(unsigned_artifact(bytes)?)))
}

/// Why a signed transaction's bytes are not accepted as the execution of a
/// given signature (Round 11).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SignatureBindingError {
    #[error("{0}")]
    Frame(#[from] ArtifactParseError),
    #[error("signature {signature:?} is not base58 of 64 bytes")]
    SignatureMalformed { signature: String },
    #[error(
        "the first signature slot holds a different signature: these are another transaction's bytes"
    )]
    FirstSlotDiffers,
    #[error("fee payer {fee_payer} is not a valid ed25519 public key")]
    FeePayerKeyInvalid { fee_payer: String },
    #[error(
        "the signature does not verify over the message under fee payer {fee_payer}: these bytes are not what was signed"
    )]
    SignatureDoesNotVerify { fee_payer: String },
}

/// The artifact digest of a signed transaction, accepted only once the bytes
/// are bound to `signature` — the id the chain files them under.
///
/// A transaction's id is its first signature: the fee payer's, over the
/// message bytes. So the bytes an RPC returns for `signature` are that
/// transaction if, and only if, their first slot holds `signature` and it
/// verifies (ed25519, strict — the runtime's own check) over their message
/// under the fee payer's key. An RPC that returns some other transaction's
/// bytes — by mistake, or to have an execution attributed to a verification
/// of its choosing — fails this check, and forging it takes the fee payer's
/// key. Without it, L8's "the chain decides" would have meant "the RPC
/// decides".
pub fn bound_artifact_sha256(
    bytes: &[u8],
    signature: &str,
) -> Result<String, SignatureBindingError> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let malformed = || SignatureBindingError::SignatureMalformed {
        signature: signature.to_string(),
    };
    let decoded = bs58::decode(signature)
        .into_vec()
        .map_err(|_| malformed())?;
    let expected: [u8; 64] = decoded.as_slice().try_into().map_err(|_| malformed())?;

    // The frame must parse in full, which also guarantees that every declared
    // signature slot is present.
    let message = parse_transaction(bytes)?;
    let layout = frame_layout(bytes)?;
    let signed_over = &bytes[layout.message];
    // `parse_transaction` has already required the signature array to be as
    // long as the header's signer count, and the header to name at least one
    // writable signer, so a first slot exists. It is the fee payer's in both
    // formats: first after the count in legacy/v0, first of the trailing
    // array in v1 (Round 19, F-19-V1).
    let first_at = layout.signatures.start;
    let first = bytes
        .get(first_at..first_at + 64)
        .ok_or(ArtifactParseError::Truncated {
            offset: first_at,
            what: "first signature",
        })?;
    if first != expected {
        return Err(SignatureBindingError::FirstSlotDiffers);
    }

    let fee_payer = message.fee_payer.clone();
    let key_bytes: [u8; 32] = bs58::decode(&fee_payer)
        .into_vec()
        .ok()
        .and_then(|v| v.as_slice().try_into().ok())
        .ok_or_else(|| SignatureBindingError::FeePayerKeyInvalid {
            fee_payer: fee_payer.clone(),
        })?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
        SignatureBindingError::FeePayerKeyInvalid {
            fee_payer: fee_payer.clone(),
        }
    })?;
    key.verify_strict(signed_over, &Signature::from_bytes(&expected))
        .map_err(|_| SignatureBindingError::SignatureDoesNotVerify { fee_payer })?;
    Ok(artifact_sha256_of_signed(bytes)?)
}

/// The message half of a serialized transaction: the bytes the signatures
/// are computed over.
///
/// For a legacy or v0 frame that is everything after the signature array.
/// This is the slice the TypeScript bridge's `messageOf` produces for the
/// signing gate's message-equality check, and it uses the SAME compact-u16
/// reader as `parse_transaction`, so the cross-language corpus compares
/// Graphite's actual acceptance language against `@solana/web3.js`'s rather
/// than a test-local reimplementation of it.
///
/// For a v1 frame it is everything BEFORE the trailing signature array,
/// the `0x81` prefix included: the SDK signs `VersionedMessage::serialize()`,
/// which writes `V1_PREFIX` and then the message body, and that is exactly
/// the frame minus its signatures (Round 19, F-19-V1). The frame must parse
/// in full, since only the parse knows where the message ends.
pub fn message_bytes(bytes: &[u8]) -> Result<&[u8], ArtifactParseError> {
    let layout = frame_layout(bytes)?;
    Ok(&bytes[layout.message])
}

/// Parse a serialized Solana transaction: `[signatures][message]` for legacy
/// and v0, `[0x81][message][signatures]` for v1.
///
/// Accepts legacy, v0 and v1. Returns the message structure, or an error —
/// never a partially-populated "best effort" value, because a caller cannot
/// tell one of those from a real answer.
pub fn parse_transaction(bytes: &[u8]) -> Result<ArtifactMessage, ArtifactParseError> {
    check_frame_size(bytes)?;
    let first = *bytes.first().ok_or(ArtifactParseError::Empty)?;
    // The runtime's `VersionedTransaction` decoder dispatches on the first
    // byte: below 0x80 it is a legacy/v0 signature count, exactly 0x81 is a
    // v1 frame, anything else is refused (Round 19, F-19-V1). "Anything
    // else" needs no branch of its own: it would be the first byte of a
    // compact-u16 signature count of at least 128, and 128 slots (8,192
    // bytes) cannot fit the 1232-byte bound, so `skip_signatures` refuses it.
    if first == V1_PREFIX {
        return parse_v1(bytes).map(|(message, _)| message);
    }
    let mut r = Reader::new(bytes);
    let sig_count = skip_signatures(&mut r)?;

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

    // The runtime's `Message::sanitize`: signers and readonly-unsigned keys
    // must not overlap, and at least one signer must be writable — the fee
    // payer. `num_readonly_signed >= num_required_signatures` leaves none.
    if num_required_signatures > key_count
        || num_readonly_signed >= num_required_signatures
        || num_readonly_unsigned > key_count.saturating_sub(num_required_signatures)
        || key_count == 0
    {
        return Err(ArtifactParseError::ImpossibleHeader {
            signers: num_required_signatures,
            readonly_signed: num_readonly_signed,
            keys: key_count,
        });
    }
    // The bank's `validate_account_locks` refuses a transaction that names
    // one account twice (`AccountLoadedTwice`) before it runs anything
    // (Round 19, F-19-08). Sanitize does not check this, so a frame with a
    // repeated key is well-formed and still never a transaction; a verdict
    // and a digest about it are about nothing, and the privilege lookup below
    // would answer for whichever copy it met first.
    {
        let mut seen: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::with_capacity(static_keys.len());
        for (i, key) in static_keys.iter().enumerate() {
            if let Some(first) = seen.insert(key.as_str(), i) {
                return Err(ArtifactParseError::DuplicateAccountKey {
                    key: key.clone(),
                    first,
                    second: i,
                });
            }
        }
    }
    // The runtime's `VersionedTransaction::sanitize` accepts only a signature
    // array exactly as long as the header's signer count. Fewer cannot be
    // signed into validity; more is refused outright.
    if sig_count != num_required_signatures {
        return Err(ArtifactParseError::SignatureCountMismatch {
            declared: sig_count,
            required: num_required_signatures,
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
        // The runtime's `sanitize`: "a program cannot be a payer". Key 0 is
        // the fee payer by position, so an instruction whose program index
        // is 0 can never execute.
        if program_index == 0 {
            return Err(ArtifactParseError::ProgramIsFeePayer { index });
        }

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
            let lookup = AddressTableLookup {
                table: Pubkey::from_bytes(arr).to_base58(),
                writable_indexes,
                readonly_indexes,
            };
            // The runtime's v0 `sanitize`: every declared table loads at
            // least one address.
            if lookup.is_empty() {
                return Err(ArtifactParseError::EmptyLookup {
                    table: lookup.table,
                });
            }
            lookups.push(lookup);
        }
    }

    // The account universe an instruction may index: the static keys, then
    // — for v0 — every loaded address in lookup order. The runtime's
    // `sanitize` refuses any index at or past that, and refuses a universe
    // that does not fit the u8 index space. Checked here rather than left
    // to `resolve_lookups`, because a frame the runtime refuses is not a
    // transaction and must not be bound, digested or reasoned about as one
    // (Round 12, runtime oracle: 3,382 of 200,000 generated frames and 8 of
    // the corpus's recorded mutations were parsed here and refused there).
    let loaded: usize = lookups.iter().map(|l| l.len()).sum();
    let total_keys = key_count + loaded;
    if total_keys > 256 {
        return Err(ArtifactParseError::TooManyAccounts { total: total_keys });
    }
    for (index, ix) in instructions.iter().enumerate() {
        if let Some(&account_index) = ix
            .account_indexes
            .iter()
            .find(|&&i| usize::from(i) >= total_keys)
        {
            return Err(ArtifactParseError::AccountIndexOutOfRange {
                index,
                account_index: usize::from(account_index),
                keys: total_keys,
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
        v1_config: None,
    })
}

/// Read a little-endian u32 of the v1 format. v1 uses fixed-width integers
/// throughout — no compact-u16 anywhere — so there is no second spelling of
/// any length to refuse.
fn v1_u32(r: &mut Reader<'_>, what: &'static str) -> Result<u32, ArtifactParseError> {
    let raw = r.take(4, what)?;
    Ok(u32::from_le_bytes(
        raw.try_into().expect("take(4) returns exactly 4 bytes"),
    ))
}

/// Parse a v1 (SIMD-0385) frame, returning the message and where the message
/// ends (the offset at which the trailing signature array begins).
///
/// The wire layout, from `solana-message` 5.0 `v1/message.rs`
/// (`SchemaRead for Message`) and `solana-transaction` 5.0
/// (`SchemaRead for VersionedTransaction`):
///
/// ```text
///   0x81                                   version prefix
///   u8 × 3                                 header (legacy layout)
///   u32 LE                                 TransactionConfigMask
///   [u8; 32]                               lifetime specifier (blockhash)
///   u8                                     number of instructions
///   u8                                     number of addresses
///   [u8; 32] × addresses                   account keys
///   config values, in mask-bit order       u64 fee, u32 CU limit,
///                                          u32 loaded-data limit, u32 heap
///   (u8 program, u8 n_accounts, u16 LE data_len) × instructions
///   per instruction: [u8] accounts, [u8] data
///   [u8; 64] × num_required_signatures     signatures — no count prefix
/// ```
///
/// Every refusal the runtime makes is made here (Round 19, F-19-V1): the
/// decoder's (mask with unknown bits or half a priority-fee pair, anything
/// short), `v1::Message::validate`'s (≤ 12 signatures, ≤ 64 addresses, ≤ 64
/// instructions, addresses ≥ signers + readonly-unsigned, a writable fee
/// payer, no duplicate address, heap size 1024-aligned in [32 KiB, 256 KiB],
/// program index in range and not the payer, every account index in range),
/// the 4096-byte `MAX_TRANSACTION_SIZE`, and a complete signature array.
/// Trailing bytes are refused as they are for legacy and v0: two byte strings
/// that parse to one transaction are the ambiguity a binding rules out.
fn parse_v1(bytes: &[u8]) -> Result<(ArtifactMessage, usize), ArtifactParseError> {
    check_frame_size(bytes)?;
    let mut r = Reader::new(bytes);
    let prefix = r.u8("message version")?;
    if prefix != V1_PREFIX {
        // Only reachable through a caller that did not dispatch on the first
        // byte; refused rather than read as something else.
        return Err(ArtifactParseError::UnsupportedVersion(prefix & 0x7f));
    }
    let num_required_signatures = r.u8("num_required_signatures")? as usize;
    let num_readonly_signed = r.u8("num_readonly_signed_accounts")? as usize;
    let num_readonly_unsigned = r.u8("num_readonly_unsigned_accounts")? as usize;

    // The decoder refuses a mask it cannot round-trip before reading anything
    // the mask sizes: an unknown bit would be dropped on re-serialization, so
    // the signed bytes and the executed message would differ.
    let mask = v1_u32(&mut r, "v1 config mask")?;
    if mask & !V1_MASK_KNOWN_BITS != 0 {
        return Err(ArtifactParseError::V1Refused(
            V1Violation::ConfigMaskUnknownBits { mask },
        ));
    }
    let fee_bits = mask & V1_MASK_PRIORITY_FEE;
    if fee_bits != 0 && fee_bits != V1_MASK_PRIORITY_FEE {
        return Err(ArtifactParseError::V1Refused(
            V1Violation::ConfigMaskPartialPriorityFee { mask },
        ));
    }

    let recent_blockhash = {
        let raw = r.take(32, "lifetime specifier")?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(raw);
        Pubkey::from_bytes(arr).to_base58()
    };
    let instruction_count = r.u8("instruction count")? as usize;
    let key_count = r.u8("account address count")? as usize;

    let mut static_keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        let raw = r.take(32, "account address")?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(raw);
        static_keys.push(Pubkey::from_bytes(arr).to_base58());
    }

    // Config values, present only for set bits, in bit order.
    let mut config = V1Config::default();
    if fee_bits == V1_MASK_PRIORITY_FEE {
        let raw = r.take(8, "v1 priority fee")?;
        config.priority_fee = Some(u64::from_le_bytes(
            raw.try_into().expect("take(8) returns exactly 8 bytes"),
        ));
    }
    if mask & V1_MASK_COMPUTE_UNIT_LIMIT != 0 {
        config.compute_unit_limit = Some(v1_u32(&mut r, "v1 compute unit limit")?);
    }
    if mask & V1_MASK_LOADED_ACCOUNTS_DATA_SIZE != 0 {
        config.loaded_accounts_data_size_limit =
            Some(v1_u32(&mut r, "v1 loaded accounts data size limit")?);
    }
    if mask & V1_MASK_HEAP_SIZE != 0 {
        config.heap_size = Some(v1_u32(&mut r, "v1 heap size")?);
    }

    // All instruction headers first, then all payloads — unlike legacy/v0,
    // where each instruction is contiguous.
    let mut headers: Vec<(usize, usize, usize)> = Vec::with_capacity(instruction_count);
    for _ in 0..instruction_count {
        let program_index = r.u8("instruction program index")? as usize;
        let account_count = r.u8("instruction account count")? as usize;
        let data_len = r.take(2, "instruction data length")?;
        let data_len = u16::from_le_bytes([data_len[0], data_len[1]]) as usize;
        headers.push((program_index, account_count, data_len));
    }
    let mut raw_instructions: Vec<(usize, Vec<u8>, Vec<u8>)> =
        Vec::with_capacity(instruction_count);
    for &(program_index, account_count, data_len) in &headers {
        let account_indexes = r.take(account_count, "instruction accounts")?.to_vec();
        let data = r.take(data_len, "instruction data")?.to_vec();
        raw_instructions.push((program_index, account_indexes, data));
    }

    // The signatures: exactly the header's count, 64 bytes each, last. There
    // is no count on the wire, so a short array is a truncated frame, not a
    // smaller one.
    let message_end = r.pos;
    let _ = r.take(num_required_signatures * 64, "signatures")?;
    if r.remaining() != 0 {
        return Err(ArtifactParseError::TrailingBytes {
            trailing: r.remaining(),
        });
    }

    // `v1::Message::validate`, rule for rule and in its order.
    if num_required_signatures > V1_MAX_SIGNATURES {
        return Err(ArtifactParseError::V1Refused(
            V1Violation::TooManySignatures {
                count: num_required_signatures,
                max: V1_MAX_SIGNATURES,
            },
        ));
    }
    if instruction_count > V1_MAX_INSTRUCTIONS {
        return Err(ArtifactParseError::V1Refused(
            V1Violation::TooManyInstructions {
                count: instruction_count,
                max: V1_MAX_INSTRUCTIONS,
            },
        ));
    }
    if key_count > V1_MAX_ADDRESSES {
        return Err(ArtifactParseError::V1Refused(
            V1Violation::TooManyAddresses {
                count: key_count,
                max: V1_MAX_ADDRESSES,
            },
        ));
    }
    // Signers and readonly-unsigned keys must not overlap
    // (`NotEnoughAddressesForSignatures`), and at least one signer must be
    // writable — the fee payer (`ZeroSigners`). Together these also require
    // at least one address.
    if key_count < num_required_signatures + num_readonly_unsigned
        || num_readonly_signed >= num_required_signatures
    {
        return Err(ArtifactParseError::ImpossibleHeader {
            signers: num_required_signatures,
            readonly_signed: num_readonly_signed,
            keys: key_count,
        });
    }
    {
        let mut seen: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::with_capacity(static_keys.len());
        for (i, key) in static_keys.iter().enumerate() {
            if let Some(first) = seen.insert(key.as_str(), i) {
                return Err(ArtifactParseError::DuplicateAccountKey {
                    key: key.clone(),
                    first,
                    second: i,
                });
            }
        }
    }
    if let Some(heap_size) = config.heap_size {
        if !heap_size.is_multiple_of(1024)
            || !(V1_MIN_HEAP_SIZE..=V1_MAX_HEAP_SIZE).contains(&heap_size)
        {
            return Err(ArtifactParseError::V1Refused(
                V1Violation::InvalidHeapSize { heap_size },
            ));
        }
    }
    for (index, (program_index, account_indexes, _)) in raw_instructions.iter().enumerate() {
        if *program_index >= key_count {
            return Err(ArtifactParseError::ProgramIndexOutOfRange {
                index,
                program_index: *program_index,
                keys: key_count,
            });
        }
        if *program_index == 0 {
            return Err(ArtifactParseError::ProgramIsFeePayer { index });
        }
        if let Some(&account_index) = account_indexes
            .iter()
            .find(|&&i| usize::from(i) >= key_count)
        {
            return Err(ArtifactParseError::AccountIndexOutOfRange {
                index,
                account_index: usize::from(account_index),
                keys: key_count,
            });
        }
    }

    // Every index is now known to be in range, so every account resolves:
    // v1 has no lookup tables and nothing is left unidentified.
    let instructions = raw_instructions
        .into_iter()
        .map(
            |(program_index, account_indexes, data)| ArtifactInstruction {
                program_id: static_keys[program_index].clone(),
                accounts: account_indexes
                    .iter()
                    .map(|&i| Some(static_keys[usize::from(i)].clone()))
                    .collect(),
                account_indexes,
                data,
            },
        )
        .collect();

    // Privileges from the same positional layout as legacy
    // (`v1::Message::account_keys` documents it unchanged).
    let signers: Vec<String> = static_keys[..num_required_signatures].to_vec();
    let writable_signed = num_required_signatures - num_readonly_signed;
    let unsigned_writable_end = key_count - num_readonly_unsigned;
    let mut writable: Vec<String> = static_keys[..writable_signed].to_vec();
    writable.extend_from_slice(&static_keys[num_required_signatures..unsigned_writable_end]);

    Ok((
        ArtifactMessage {
            version: Some(1),
            fee_payer: static_keys[0].clone(),
            recent_blockhash,
            signers,
            writable,
            static_keys,
            instructions,
            lookups: Vec::new(),
            v1_config: Some(config),
        },
        message_end,
    ))
}

/// How an artifact's parsed contents line up with what the request described.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Correspondence {
    /// Index of the instruction matching the described program, discriminator
    /// and data, when exactly one matches.
    pub matched_instruction: Option<usize>,
    /// How many instructions carry the described program and exact data. More
    /// than one with `matched_instruction` None means the description could
    /// not tell them apart — not that the instruction is absent (Round 19).
    pub same_program_and_data: usize,
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
            return Some(hits[0]);
        }
        // Round 19 (F-19-28): program and data are not the whole description —
        // the accounts are part of it, and two same-amount transfers to
        // different destinations are two different instructions. Among the
        // candidates, keep those whose STATIC account positions all equal the
        // described accounts (lookup-table positions are not known here and
        // are compared later, when the tables are resolved). Exactly one left
        // is the instruction the request describes; anything else stays
        // unlocated. Nothing is guessed: the chosen instruction still goes
        // through the full positional account comparison afterwards.
        let by_accounts: Vec<usize> = hits
            .iter()
            .copied()
            .filter(|&i| {
                let accounts = &message.instructions[i].accounts;
                accounts.len() == described_accounts.len()
                    && accounts
                        .iter()
                        .zip(described_accounts)
                        .all(|(actual, described)| actual.as_deref().is_none_or(|a| a == described))
                    && accounts.iter().any(|a| a.is_some())
            })
            .collect();
        if by_accounts.len() == 1 {
            Some(by_accounts[0])
        } else {
            None
        }
    });
    let same_program_and_data = described_data.map_or(0, |data| {
        message
            .instructions
            .iter()
            .filter(|ix| ix.program_id == described_program && ix.data == data)
            .count()
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
        same_program_and_data,
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
    #[error("lookup table {table} is deactivating (deactivation_slot {slot}): the runtime still honours it for up to ~512 slots after that, but a verdict about identities read from a table that is being retired would be true for minutes; Graphite refuses it (Round 17, F-15-05 — a deliberate, disclosed refusal, not a parse failure)")]
    TableDeactivating { table: String, slot: u64 },
    #[error(
        "lookup table {table} has {entries} addresses; this transaction asks for index {index}"
    )]
    IndexOutOfRange {
        table: String,
        index: u8,
        entries: usize,
    },
    #[error("account {address} is reached twice (through a lookup table and a static key, or through two lookups); the runtime refuses a transaction that loads an account twice (AccountLoadedTwice)")]
    DuplicateAccount { address: String },
    #[error(
        "account {table} does not hold an initialized lookup table (type tag {tag}, expected 1)"
    )]
    NotALookupTable { table: String, tag: u32 },
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
    // `ProgramState::LookupTable` is variant 1 of a u32-tagged enum; 0 is an
    // uninitialized account. The owner check upstream makes a foreign account
    // unlikely here, and the tag makes it impossible (Round 19).
    let tag = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .expect("slice of exactly 4 bytes is an array"),
    );
    if tag != 1 {
        return Err(LookupResolveError::NotALookupTable {
            table: table.to_string(),
            tag,
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
    // Every account the transaction reaches must be distinct: the runtime's
    // lock validation counts static and loaded accounts together (Round 19,
    // F-19-08).
    let mut seen: std::collections::HashSet<&str> =
        message.static_keys.iter().map(String::as_str).collect();
    for address in out.writable.iter().chain(out.readonly.iter()) {
        if !seen.insert(address.as_str()) {
            return Err(LookupResolveError::DuplicateAccount {
                address: address.clone(),
            });
        }
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
    /// Whether the message marks the nonce account writable. The runtime's
    /// `get_durable_nonce` requires it: with a read-only nonce account the
    /// transaction is not a nonce transaction at all, its "blockhash" is the
    /// nonce value, and it dies with `BlockhashNotFound` (Round 19).
    pub nonce_account_writable: bool,
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
    let nonce_account_writable = message.writable.contains(&nonce_account);
    Some(DurableNonce {
        nonce_account_writable,
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
    if !declared.nonce_account_writable {
        return Err(format!(
            "the nonce account {} is read-only in this message; the runtime treats a transaction as nonce-based only when the nonce account is writable, so this one would be judged by its blockhash (the nonce value) and refused",
            declared.nonce_account
        ));
    }
    Ok(())
}
