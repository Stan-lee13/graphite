//! The runtime oracle: Graphite's parser against the Solana runtime's own
//! decoder and sanitizer.
//!
//! `@solana/web3.js` is a client library, and the cross-language corpus in
//! `graphite-core/tests/sak_bridge_corpus.rs` proves Graphite agrees with it.
//! The runtime is the authority, and it is stricter than the SDK: bincode with
//! trailing bytes rejected, the ShortU16 alias check, `Message::sanitize`,
//! `VersionedTransaction::sanitize`. This binary decodes every byte string
//! with the agave crates (`solana-transaction`, `solana-message`) exactly the
//! way a validator's packet path does, and requires:
//!
//! 1. **Never looser than the runtime.** Every byte string Graphite parses,
//!    the runtime decodes and sanitizes. A transaction the runtime would
//!    refuse at sanitization cannot execute, so Graphite must not bind an
//!    artifact to it, approve it, or reason about it as a transaction.
//! 2. **The same transaction.** Where both accept, they agree on the message
//!    bytes, the version, the header, the static keys, every instruction's
//!    program, account indexes and data, and every lookup.
//! 3. **No panic** on any input.
//!
//! Where Graphite is stricter than the runtime, that is measured and printed
//! (an honest transaction refused at the gate is an outage, not a bypass) and
//! is a failure only when it is not one of the documented, deliberate
//! refusals.
//!
//! Inputs: the recorded corpus (ten shapes and their 1,659 byte-level
//! mutations, read exactly as the Rust and TypeScript tests read them) and a
//! seeded structure-aware generator that builds transactions with every kind
//! of malformed header, index, length, encoding and frame the format allows,
//! plus raw byte damage on top. Deterministic per seed; the seed and the
//! iteration count are printed so any run can be reproduced.
//!
//! Round 19 (F-19-V1): v1 frames (SIMD-0385) too. v1 has no bincode/serde
//! wire encoding — the crates' serde impl for `VersionedMessage::V1` says it
//! "does not match the wire format" — so v1 frames are decoded by the crates'
//! wincode `SchemaRead for VersionedTransaction`, the decoder that defines
//! the format. A second seeded generator builds v1 frames with every field
//! legal or broken, and a systematic pass mutates valid v1 frames field by
//! field, byte by byte and length by length.

use bincode::Options;
use graphite_core::tx_artifact::{
    filled_signature_slots, message_bytes, parse_transaction, simulation_identity,
    unsigned_artifact, ArtifactMessage, ArtifactParseError, MAX_TRANSACTION_BYTES,
    MAX_V1_TRANSACTION_BYTES,
};
use solana_message::{v1, VersionedMessage, MESSAGE_VERSION_PREFIX};
use solana_transaction::versioned::VersionedTransaction;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// What the runtime does with a byte string.
#[derive(Debug)]
enum RuntimeVerdict {
    Accepted(VersionedTransaction),
    /// The decoder refused the frame (short, trailing, alias, overflow, …).
    Undecodable(String),
    /// Decoded, but `VersionedTransaction::sanitize` refused it.
    Unsanitary(String),
}

/// The crates' own wire decoder for a whole frame: wincode
/// `SchemaRead for VersionedTransaction`, which dispatches on the first byte
/// (below 0x80: legacy/v0 signature count; 0x81: v1; anything else refused).
/// Trailing bytes refused, as the packet decoder has always refused them
/// (`reject_trailing_bytes`) and as `v1::MessageError::TrailingData` names.
/// Graphite refuses trailing bytes whatever the runtime does, so this choice
/// can move a frame between "both reject" and "Graphite stricter", never into
/// "Graphite looser".
fn wincode_decode(bytes: &[u8]) -> Result<VersionedTransaction, String> {
    wincode::deserialize_exact::<VersionedTransaction>(bytes).map_err(|e| format!("wincode: {e}"))
}

/// The runtime's verdict on a byte string.
///
/// A v1 frame (first byte `0x81`): bounded by `v1::MAX_TRANSACTION_SIZE`
/// (4096 bytes, signatures included — enforced by the network, not by the
/// decoder, so modelled here explicitly), decoded by wincode, sanitized.
///
/// Anything else: the validator's packet decoder,
/// `solana_packet::Packet::deserialize_slice` =
/// `bincode::options().with_limit(PACKET_DATA_SIZE).with_fixint_encoding()
/// .reject_trailing_bytes()`, AND the wincode decoder — a frame counts as
/// accepted only when both accept it. That makes the modelled runtime at
/// least as strict as either decoder, which is the conservative direction
/// for the property this binary exists for: a stricter model can only find
/// MORE frames Graphite accepts and the runtime refuses. (It matters for one
/// shape: bincode's serde path reads a v1 message behind a signature count
/// in a non-wire serde layout, which wincode — and the validator — refuse
/// as "invalid message version".)
fn runtime_decode(bytes: &[u8]) -> RuntimeVerdict {
    if bytes.first() == Some(&v1::V1_PREFIX) {
        if bytes.len() > v1::MAX_TRANSACTION_SIZE {
            return RuntimeVerdict::Undecodable(format!(
                "exceeds the {}-byte v1 MAX_TRANSACTION_SIZE",
                v1::MAX_TRANSACTION_SIZE
            ));
        }
        return match wincode_decode(bytes) {
            Err(e) => RuntimeVerdict::Undecodable(e),
            Ok(tx) => match tx.sanitize() {
                Ok(()) => RuntimeVerdict::Accepted(tx),
                Err(e) => RuntimeVerdict::Unsanitary(format!("{e:?}")),
            },
        };
    }
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return RuntimeVerdict::Undecodable(format!(
            "exceeds the {MAX_TRANSACTION_BYTES}-byte packet"
        ));
    }
    let decoded: Result<VersionedTransaction, _> = bincode::DefaultOptions::new()
        .with_limit(MAX_TRANSACTION_BYTES as u64)
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(bytes);
    match decoded {
        Err(e) => RuntimeVerdict::Undecodable(e.to_string()),
        Ok(tx) => {
            if let Err(e) = wincode_decode(bytes) {
                return RuntimeVerdict::Undecodable(e);
            }
            match tx.sanitize() {
                Ok(()) => RuntimeVerdict::Accepted(tx),
                Err(e) => RuntimeVerdict::Unsanitary(format!("{e:?}")),
            }
        }
    }
}

/// A short, stable label for a Graphite refusal, for the breakdown. A v1
/// rule is labelled by the rule, so the breakdown says which one.
fn graphite_reason(e: &ArtifactParseError) -> String {
    let head = |s: &str| s.split(['(', '{', ' ']).next().unwrap_or("?").to_string();
    match e {
        ArtifactParseError::V1Refused(v) => format!("V1Refused::{}", head(&format!("{v:?}"))),
        other => head(&format!("{other:?}")),
    }
}

struct Tally {
    both_accept: u64,
    both_reject: u64,
    /// Graphite accepted, the runtime refused. Fatal.
    graphite_looser: Vec<String>,
    /// The runtime accepted, Graphite refused — by Graphite's reason.
    graphite_stricter: BTreeMap<String, u64>,
    graphite_stricter_examples: BTreeMap<String, String>,
    /// Both accepted but disagreed about the transaction. Fatal.
    disagreements: Vec<String>,
    runtime_reasons: BTreeMap<String, u64>,
    /// Graphite's reasons where both refuse, so a run shows every Graphite
    /// rule (the v1 ones included) was actually exercised.
    graphite_reasons: BTreeMap<String, u64>,
}

impl Tally {
    fn new() -> Self {
        Self {
            both_accept: 0,
            both_reject: 0,
            graphite_looser: Vec::new(),
            graphite_stricter: BTreeMap::new(),
            graphite_stricter_examples: BTreeMap::new(),
            disagreements: Vec::new(),
            runtime_reasons: BTreeMap::new(),
            graphite_reasons: BTreeMap::new(),
        }
    }

    fn check(&mut self, label: &str, bytes: &[u8]) {
        // Property 3: no panic, on either side of the comparison.
        let graphite = std::panic::catch_unwind(|| parse_transaction(bytes));
        let graphite = match graphite {
            Ok(r) => r,
            Err(_) => {
                self.graphite_looser
                    .push(format!("{label}: parse_transaction PANICKED"));
                return;
            }
        };
        let runtime = runtime_decode(bytes);
        match (graphite, runtime) {
            (Ok(parsed), RuntimeVerdict::Accepted(tx)) => {
                self.both_accept += 1;
                if let Err(why) = same_transaction(bytes, &parsed, &tx) {
                    self.disagreements.push(format!("{label}: {why}"));
                }
            }
            (Ok(_), RuntimeVerdict::Undecodable(why)) => {
                self.graphite_looser.push(format!(
                    "{label}: Graphite parsed it; the runtime cannot decode it ({why})"
                ));
            }
            (Ok(_), RuntimeVerdict::Unsanitary(why)) => {
                self.graphite_looser.push(format!(
                    "{label}: Graphite parsed it; the runtime's sanitize refuses it ({why})"
                ));
            }
            (Err(e), RuntimeVerdict::Accepted(_)) => {
                let reason = graphite_reason(&e);
                *self.graphite_stricter.entry(reason.clone()).or_insert(0) += 1;
                self.graphite_stricter_examples
                    .entry(reason)
                    .or_insert_with(|| format!("{label}: {e}"));
            }
            (Err(e), RuntimeVerdict::Undecodable(why)) => {
                self.both_reject += 1;
                *self
                    .graphite_reasons
                    .entry(graphite_reason(&e))
                    .or_insert(0) += 1;
                *self
                    .runtime_reasons
                    .entry(format!("decode: {}", short_reason(&why)))
                    .or_insert(0) += 1;
            }
            (Err(e), RuntimeVerdict::Unsanitary(why)) => {
                self.both_reject += 1;
                *self
                    .graphite_reasons
                    .entry(graphite_reason(&e))
                    .or_insert(0) += 1;
                *self
                    .runtime_reasons
                    .entry(format!("sanitize: {why}"))
                    .or_insert(0) += 1;
            }
        }
    }
}

fn short_reason(why: &str) -> String {
    // bincode's messages embed offsets and lengths; keep the kind only. The
    // wincode decoder's are prefixed "wincode: ", so keep one more field.
    if let Some(rest) = why.strip_prefix("wincode: ") {
        let head: String = rest
            .chars()
            .take_while(|c| *c != ':' && *c != '(' && !c.is_ascii_digit())
            .collect();
        return format!("wincode {}", head.trim());
    }
    let head: String = why.chars().take_while(|c| *c != ':' && *c != '(').collect();
    head.trim().to_string()
}

/// Property 2: both accepted — is it the same transaction?
fn same_transaction(
    bytes: &[u8],
    parsed: &ArtifactMessage,
    tx: &VersionedTransaction,
) -> Result<(), String> {
    // The message as the runtime serializes it for signing:
    // `VersionedMessage::serialize()` (wincode; for v1 that is `0x81` + the
    // body, the bytes `VersionedTransaction::try_new` signs). For legacy and
    // v0 the bincode encoding must be the same bytes too.
    let runtime_message = tx.message.serialize();
    let graphite_message = message_bytes(bytes).map_err(|e| format!("message_bytes: {e}"))?;
    if runtime_message.as_slice() != graphite_message {
        return Err(format!(
            "message bytes differ: runtime {} bytes, Graphite {} bytes",
            runtime_message.len(),
            graphite_message.len()
        ));
    }
    if !matches!(tx.message, VersionedMessage::V1(_)) {
        let bincode_message =
            bincode::serialize(&tx.message).map_err(|e| format!("serialize: {e}"))?;
        if bincode_message != runtime_message {
            return Err("bincode and wincode serialize the message differently".to_string());
        }
    }
    // The signature slots, wherever the format keeps them: the frame with
    // the runtime's signatures zeroed is Graphite's unsigned artifact, and
    // Graphite counts exactly the runtime's non-zero signatures.
    let mut zeroed = tx.clone();
    for s in zeroed.signatures.iter_mut() {
        *s = Default::default();
    }
    let runtime_unsigned =
        wincode::serialize(&zeroed).map_err(|e| format!("wincode serialize: {e}"))?;
    let graphite_unsigned =
        unsigned_artifact(bytes).map_err(|e| format!("unsigned_artifact: {e}"))?;
    if runtime_unsigned != graphite_unsigned {
        return Err(
            "unsigned artifact differs from the frame with the runtime's signatures zeroed"
                .to_string(),
        );
    }
    let runtime_filled = tx
        .signatures
        .iter()
        .filter(|s| s.as_ref().iter().any(|b| *b != 0))
        .count();
    if filled_signature_slots(bytes) != Ok(runtime_filled) {
        return Err(format!(
            "filled signature slots: runtime {runtime_filled}, Graphite {:?}",
            filled_signature_slots(bytes)
        ));
    }
    simulation_identity(bytes).map_err(|e| format!("simulation_identity: {e}"))?;
    let version = match &tx.message {
        VersionedMessage::Legacy(_) => None,
        VersionedMessage::V0(_) => Some(0u8),
        VersionedMessage::V1(_) => Some(1u8),
    };
    // The v1 header's config values (Round 19, F-19-V1).
    let runtime_config = match &tx.message {
        VersionedMessage::V1(m) => Some((
            m.config.priority_fee,
            m.config.compute_unit_limit,
            m.config.loaded_accounts_data_size_limit,
            m.config.heap_size,
        )),
        _ => None,
    };
    let graphite_config = parsed.v1_config.map(|c| {
        (
            c.priority_fee,
            c.compute_unit_limit,
            c.loaded_accounts_data_size_limit,
            c.heap_size,
        )
    });
    if runtime_config != graphite_config {
        return Err(format!(
            "v1 config: runtime {runtime_config:?}, Graphite {graphite_config:?}"
        ));
    }
    if parsed.version != version {
        return Err(format!(
            "version: runtime {version:?}, Graphite {:?}",
            parsed.version
        ));
    }
    let header = tx.message.header();
    if parsed.signers.len() != usize::from(header.num_required_signatures) {
        return Err(format!(
            "required signers: runtime {}, Graphite {}",
            header.num_required_signatures,
            parsed.signers.len()
        ));
    }
    if tx.signatures.len() != parsed.signers.len() {
        return Err(format!(
            "signature slots: runtime {}, Graphite signers {}",
            tx.signatures.len(),
            parsed.signers.len()
        ));
    }
    let static_keys: Vec<String> = tx
        .message
        .static_account_keys()
        .iter()
        .map(|k| k.to_string())
        .collect();
    if static_keys != parsed.static_keys {
        return Err("static keys differ".to_string());
    }
    // Writable set, from the runtime's own header arithmetic.
    let writable_signed = usize::from(header.num_required_signatures)
        - usize::from(header.num_readonly_signed_accounts);
    let unsigned_writable_end =
        static_keys.len() - usize::from(header.num_readonly_unsigned_accounts);
    let mut writable: Vec<String> = static_keys[..writable_signed].to_vec();
    writable.extend_from_slice(
        &static_keys[usize::from(header.num_required_signatures)..unsigned_writable_end],
    );
    if writable != parsed.writable {
        return Err("writable static keys differ".to_string());
    }
    if parsed.fee_payer != static_keys[0] {
        return Err("fee payer differs".to_string());
    }
    if parsed.recent_blockhash != tx.message.recent_blockhash().to_string() {
        return Err("recent blockhash differs".to_string());
    }
    let instructions = tx.message.instructions();
    if instructions.len() != parsed.instructions.len() {
        return Err(format!(
            "instruction count: runtime {}, Graphite {}",
            instructions.len(),
            parsed.instructions.len()
        ));
    }
    for (i, (r, g)) in instructions.iter().zip(&parsed.instructions).enumerate() {
        let program = static_keys
            .get(usize::from(r.program_id_index))
            .cloned()
            .unwrap_or_default();
        if program != g.program_id {
            return Err(format!("instruction {i}: program differs"));
        }
        if r.accounts != g.account_indexes {
            return Err(format!("instruction {i}: account indexes differ"));
        }
        if r.data != g.data {
            return Err(format!("instruction {i}: data differs"));
        }
        for (j, (&idx, resolved)) in r.accounts.iter().zip(&g.accounts).enumerate() {
            let expected = static_keys.get(usize::from(idx)).cloned();
            if *resolved != expected {
                return Err(format!(
                    "instruction {i} account {j}: static resolution differs"
                ));
            }
        }
    }
    let lookups = tx.message.address_table_lookups().unwrap_or(&[]);
    if lookups.len() != parsed.lookups.len() {
        return Err(format!(
            "lookup count: runtime {}, Graphite {}",
            lookups.len(),
            parsed.lookups.len()
        ));
    }
    for (i, (r, g)) in lookups.iter().zip(&parsed.lookups).enumerate() {
        if r.account_key.to_string() != g.table {
            return Err(format!("lookup {i}: table differs"));
        }
        if r.writable_indexes != g.writable_indexes || r.readonly_indexes != g.readonly_indexes {
            return Err(format!("lookup {i}: indexes differ"));
        }
    }
    Ok(())
}

// ─── The recorded corpus ──────────────────────────────────────────────────────

fn json_bytes(v: &serde_json::Value) -> Vec<u8> {
    v.as_array()
        .expect("byte array")
        .iter()
        .map(|n| n.as_u64().expect("byte") as u8)
        .collect()
}

/// `mutate` from `tests/sak_bridge_corpus.rs`, byte for byte.
fn mutate(raw: &[u8], m: &serde_json::Value) -> Vec<u8> {
    match m["op"].as_str().expect("op") {
        "truncate" => raw[..m["at"].as_u64().unwrap() as usize].to_vec(),
        "flip" => {
            let mut out = raw.to_vec();
            let at = m["at"].as_u64().unwrap() as usize;
            out[at] ^= 0xff;
            out
        }
        "prefix" => {
            let mut out = json_bytes(&m["bytes"]);
            out.extend_from_slice(&raw[1..]);
            out
        }
        "append" => {
            let mut out = raw.to_vec();
            out.extend_from_slice(&json_bytes(&m["bytes"]));
            out
        }
        "pad" => {
            let to = m["to"].as_u64().unwrap() as usize;
            let mut out = raw.to_vec();
            out.resize(to, 0);
            out
        }
        "slots" => {
            let count = m["count"].as_u64().unwrap() as usize;
            let declared = raw[0] as usize;
            let mut out = vec![count as u8];
            out.resize(1 + 64 * count, 0);
            out.extend_from_slice(&raw[1 + 64 * declared..]);
            out
        }
        other => panic!("unknown mutation op {other}"),
    }
}

fn run_corpus(path: &PathBuf, tally: &mut Tally) -> (usize, usize) {
    let raw: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read corpus {}: {e}", path.display())),
    )
    .expect("corpus must parse");
    let entries = raw["entries"].as_array().expect("entries");
    let mut bases: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for e in entries {
        let name = e["name"].as_str().expect("name").to_string();
        let bytes = json_bytes(&e["raw"]);
        tally.check(&format!("corpus base {name}"), &bytes);
        bases.insert(name, bytes);
    }
    let mutations = raw["mutations"].as_array().expect("mutations");
    for m in mutations {
        let base = m["base"].as_str().expect("base");
        let bytes = mutate(&bases[base], &m["mutation"]);
        tally.check(&format!("corpus {base} {}", m["mutation"]), &bytes);
    }
    (entries.len(), mutations.len())
}

// ─── The generator ────────────────────────────────────────────────────────────

/// xorshift64*: small, fast, and reproducible from one seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
    fn chance(&mut self, one_in: u64) -> bool {
        self.below(one_in) == 0
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
    fn fill(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

/// Canonical compact-u16, as the runtime writes it.
fn compact_u16(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// A compact-u16 that is sometimes non-canonical, too long, or over-range —
/// the encodings the runtime's ShortU16 visitor exists to refuse.
fn hostile_compact_u16(rng: &mut Rng, n: usize, out: &mut Vec<u8>) {
    match rng.below(12) {
        // Alias: a trailing zero continuation byte for the same value.
        0 if n < 128 => {
            out.push((n as u8) | 0x80);
            out.push(0x00);
        }
        // Three-byte alias.
        1 if n < 16384 => {
            out.push((n & 0x7f) as u8 | 0x80);
            out.push(((n >> 7) & 0x7f) as u8 | 0x80);
            out.push(0x00);
        }
        // Continuation on the third byte.
        2 => out.extend_from_slice(&[0x80, 0x80, 0x80]),
        // 65536 and beyond.
        3 => out.extend_from_slice(&[0x80, 0x80, 0x04]),
        _ => compact_u16(n, out),
    }
}

struct Shape {
    version: Option<u8>,
    signers: usize,
    readonly_signed: usize,
    readonly_unsigned: usize,
    keys: usize,
    lookups: Vec<(usize, usize)>,
}

/// Build one transaction with a deliberately chosen mix of legal and illegal
/// structure. Roughly half of the outputs are well-formed by construction;
/// the rest carry one or more of the format's known ways to be wrong.
fn generate(rng: &mut Rng) -> Vec<u8> {
    // Half the outputs are legal by construction, so the "same transaction"
    // comparison runs over a large accepted set rather than a residue.
    let well_formed = rng.chance(2);
    let hostile_lengths = !well_formed && rng.chance(4);
    let emit = |rng: &mut Rng, n: usize, out: &mut Vec<u8>| {
        if hostile_lengths {
            hostile_compact_u16(rng, n, out)
        } else {
            compact_u16(n, out)
        }
    };

    let version = if rng.chance(2) { Some(0u8) } else { None };
    let keys = match rng.below(10) {
        0 if !well_formed => 0,
        1 if !well_formed => 1,
        2 => 2,
        3 => 2 + rng.below(22) as usize,
        _ => 2 + rng.below(8) as usize,
    };
    // Header values that are mostly consistent with `keys`, sometimes not.
    let signers = match rng.below(8) {
        0 if !well_formed => 0,
        1 if !well_formed => keys + 1 + rng.below(3) as usize,
        2 if !well_formed => 255,
        _ => 1 + rng.below(keys.saturating_sub(1).max(1) as u64) as usize,
    };
    let readonly_signed = match rng.below(6) {
        0 if !well_formed => signers,
        1 if !well_formed => signers + 1,
        _ => rng.below(signers.max(1) as u64) as usize,
    };
    let readonly_unsigned = match rng.below(6) {
        0 if !well_formed => keys.saturating_sub(signers) + 1,
        1 if !well_formed => 255,
        _ => rng.below(keys.saturating_sub(signers).max(1) as u64 + 1) as usize,
    };
    let lookups: Vec<(usize, usize)> = if version == Some(0) {
        (0..rng.below(4))
            .map(|_| {
                let w = rng.below(5) as usize;
                let r = if w == 0 && (well_formed || rng.chance(2)) {
                    1 + rng.below(4) as usize
                } else {
                    rng.below(5) as usize
                };
                (w, r)
            })
            .collect()
    } else {
        Vec::new()
    };
    let loaded: usize = lookups.iter().map(|(w, r)| w + r).sum();
    let shape = Shape {
        version,
        signers,
        readonly_signed,
        readonly_unsigned,
        keys,
        lookups,
    };

    // Signature slots: usually the header's count, sometimes off by one.
    let sig_slots = match rng.below(8) {
        0 if !well_formed => shape.signers.saturating_sub(1),
        1 if !well_formed => shape.signers + 1,
        2 if !well_formed => 0,
        _ => shape.signers,
    }
    .min(18);

    let mut out = Vec::with_capacity(1232);
    emit(rng, sig_slots, &mut out);
    for _ in 0..sig_slots {
        out.extend_from_slice(&rng.fill(64));
    }
    if let Some(v) = shape.version {
        let prefix = if !well_formed && rng.chance(20) {
            MESSAGE_VERSION_PREFIX | (1 + rng.below(0x7f) as u8)
        } else {
            MESSAGE_VERSION_PREFIX | v
        };
        out.push(prefix);
    }
    out.push(shape.signers.min(255) as u8);
    out.push(shape.readonly_signed.min(255) as u8);
    out.push(shape.readonly_unsigned.min(255) as u8);
    emit(rng, shape.keys, &mut out);
    for _ in 0..shape.keys {
        out.extend_from_slice(&rng.fill(32));
    }
    out.extend_from_slice(&rng.fill(32)); // blockhash

    let total_keys = shape.keys + loaded;
    let instruction_count = match rng.below(6) {
        0 => 0,
        _ => 1 + rng.below(5) as usize,
    };
    // Legal index space for a well-formed frame: programs from the static
    // keys past the payer, accounts from the whole universe.
    let legal_program =
        |rng: &mut Rng| 1 + rng.below(shape.keys.saturating_sub(1).max(1) as u64) as usize;
    emit(rng, instruction_count, &mut out);
    for _ in 0..instruction_count {
        // Program index: in range, the fee payer (illegal), the loaded range
        // (illegal), or far out.
        let program_index = match rng.below(10) {
            0 if !well_formed => 0,
            1 if !well_formed => shape.keys,
            2 if !well_formed => total_keys,
            3 if !well_formed => 255,
            _ => legal_program(rng),
        };
        out.push(program_index.min(255) as u8);
        let account_count = rng.below(6) as usize;
        emit(rng, account_count, &mut out);
        for _ in 0..account_count {
            let idx = match rng.below(10) {
                0 if !well_formed => total_keys,
                1 if !well_formed => 255,
                2 if !well_formed => shape.keys,
                _ => rng.below(total_keys.max(1) as u64) as usize,
            };
            out.push(idx.min(255) as u8);
        }
        let data_len = match rng.below(8) {
            0 => 0,
            1 => 100 + rng.below(200) as usize,
            _ => rng.below(40) as usize,
        };
        emit(rng, data_len, &mut out);
        out.extend_from_slice(&rng.fill(data_len));
    }
    if shape.version == Some(0) {
        emit(rng, shape.lookups.len(), &mut out);
        for (w, r) in &shape.lookups {
            out.extend_from_slice(&rng.fill(32));
            emit(rng, *w, &mut out);
            for _ in 0..*w {
                out.push(rng.byte());
            }
            emit(rng, *r, &mut out);
            for _ in 0..*r {
                out.push(rng.byte());
            }
        }
    } else if !well_formed && rng.chance(12) {
        // A legacy message followed by what looks like a lookup section —
        // trailing bytes.
        out.push(0);
    }

    // Raw damage on top, sometimes.
    match if well_formed { 9 } else { rng.below(10) } {
        0 if !out.is_empty() => {
            let at = rng.below(out.len() as u64) as usize;
            out.truncate(at);
        }
        1 if !out.is_empty() => {
            let at = rng.below(out.len() as u64) as usize;
            out[at] ^= 1 << rng.below(8);
        }
        2 => {
            let n = 1 + rng.below(4) as usize;
            out.extend_from_slice(&rng.fill(n));
        }
        3 => {
            let to = 1230 + rng.below(6) as usize;
            if to > out.len() {
                out.resize(to, 0);
            }
        }
        _ => {}
    }
    out
}

// ─── The v1 generator (Round 19, F-19-V1) ─────────────────────────────────────

/// One v1 frame, field by field, so the generator and the systematic pass
/// can break exactly the field they mean to.
#[derive(Clone)]
struct V1Frame {
    prefix: u8,
    header: [u8; 3],
    mask: u32,
    lifetime: [u8; 32],
    /// Written as the count bytes; normally `instructions.len()`.
    declared_instructions: u8,
    /// Written as the count bytes; normally `keys.len()`.
    declared_keys: u8,
    keys: Vec<[u8; 32]>,
    /// The raw config-value bytes, written as given.
    config: Vec<u8>,
    /// (program index, account indexes, data)
    instructions: Vec<(u8, Vec<u8>, Vec<u8>)>,
    /// Signature slots written after the message.
    slots: usize,
}

impl V1Frame {
    fn bytes(&self, rng: &mut Rng) -> Vec<u8> {
        let mut out = vec![self.prefix];
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&self.mask.to_le_bytes());
        out.extend_from_slice(&self.lifetime);
        out.push(self.declared_instructions);
        out.push(self.declared_keys);
        for k in &self.keys {
            out.extend_from_slice(k);
        }
        out.extend_from_slice(&self.config);
        for (program, accounts, data) in &self.instructions {
            out.push(*program);
            out.push(accounts.len().min(255) as u8);
            out.extend_from_slice(&(data.len().min(u16::MAX as usize) as u16).to_le_bytes());
        }
        for (_, accounts, data) in &self.instructions {
            out.extend_from_slice(accounts);
            out.extend_from_slice(data);
        }
        for _ in 0..self.slots {
            out.extend_from_slice(&rng.fill(64));
        }
        out
    }
}

/// The config-value bytes a mask implies, in bit order, with the heap size
/// legal unless `hostile_heap`.
fn v1_config_bytes(rng: &mut Rng, mask: u32, hostile_heap: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if mask & 0b11 == 0b11 {
        out.extend_from_slice(&rng.next().to_le_bytes());
    }
    if mask & 0b100 != 0 {
        out.extend_from_slice(&(rng.next() as u32).to_le_bytes());
    }
    if mask & 0b1000 != 0 {
        out.extend_from_slice(&(rng.next() as u32).to_le_bytes());
    }
    if mask & 0b1_0000 != 0 {
        let heap: u32 = if hostile_heap {
            match rng.below(5) {
                0 => rng.next() as u32,
                1 => 32 * 1024 - 1024,
                2 => 256 * 1024 + 1024,
                3 => (32 + rng.below(225) as u32) * 1024 + 1 + rng.below(1023) as u32,
                _ => 0,
            }
        } else {
            (32 + rng.below(225) as u32) * 1024
        };
        out.extend_from_slice(&heap.to_le_bytes());
    }
    out
}

/// Build one v1 frame. Half are legal by construction; the rest break one
/// or more of the format's rules — header arithmetic, the config mask and
/// values, the three count limits, duplicate keys, index ranges, the
/// declared counts, the signature array, the size bound — with raw byte
/// damage on top.
fn generate_v1(rng: &mut Rng) -> Vec<u8> {
    let well_formed = rng.chance(2);
    let bad = |rng: &mut Rng, one_in: u64| !well_formed && rng.chance(one_in);

    let signers: usize = if bad(rng, 10) {
        [0usize, 12, 13, 64, 255][rng.below(5) as usize]
    } else {
        1 + rng.below(4) as usize
    };
    let readonly_signed: usize = if bad(rng, 10) {
        signers + rng.below(2) as usize
    } else {
        rng.below(signers.max(1) as u64) as usize
    };
    let readonly_unsigned: usize = if bad(rng, 10) {
        200 + rng.below(56) as usize
    } else {
        rng.below(4) as usize
    };
    let mut key_count: usize = signers + readonly_unsigned + 1 + rng.below(5) as usize;
    if rng.chance(20) {
        key_count = 60 + rng.below(5) as usize; // at the 64-address limit
    }
    if bad(rng, 8) {
        key_count = match rng.below(3) {
            0 => 65 + rng.below(10) as usize,
            1 => (signers + readonly_unsigned).saturating_sub(1),
            _ => 0,
        };
    }
    let key_count = key_count.min(255);
    let mut keys: Vec<[u8; 32]> = (0..key_count)
        .map(|_| {
            let mut k = [0u8; 32];
            k.copy_from_slice(&rng.fill(32));
            k
        })
        .collect();
    if key_count >= 2 && bad(rng, 10) {
        let a = rng.below(key_count as u64) as usize;
        let b = rng.below(key_count as u64) as usize;
        keys[a] = keys[b];
    }

    // Mask: a legal subset (the fee as a pair), or unknown/partial bits.
    let mut mask: u32 = 0;
    if rng.chance(2) {
        mask |= 0b11;
    }
    for bit in [0b100u32, 0b1000, 0b1_0000] {
        if rng.chance(2) {
            mask |= bit;
        }
    }
    if bad(rng, 8) {
        mask = match rng.below(3) {
            0 => mask | (1u32 << (5 + rng.below(27))),
            1 => (mask & !0b11) | [0b01u32, 0b10][rng.below(2) as usize],
            _ => rng.next() as u32,
        };
    }
    let hostile_heap = bad(rng, 6);
    let config = v1_config_bytes(rng, mask, hostile_heap);

    let mut instruction_count: usize = rng.below(6) as usize;
    if rng.chance(25) {
        instruction_count = 60 + rng.below(5) as usize; // at the 64 limit
    }
    if bad(rng, 12) {
        instruction_count = 65 + rng.below(5) as usize;
    }
    let big_data = rng.chance(6);
    let mut instructions = Vec::with_capacity(instruction_count);
    for _ in 0..instruction_count {
        let program: u8 = if bad(rng, 10) {
            [0usize, key_count, 255][rng.below(3) as usize].min(255) as u8
        } else {
            (1 + rng.below(key_count.saturating_sub(1).max(1) as u64)) as u8
        };
        let accounts: Vec<u8> = (0..rng.below(6))
            .map(|_| {
                if bad(rng, 12) {
                    [key_count, 255][rng.below(2) as usize].min(255) as u8
                } else {
                    rng.below(key_count.max(1) as u64) as u8
                }
            })
            .collect();
        let data_len = if big_data && instruction_count <= 4 {
            // Past the 1232-byte packet and up to the 4096-byte bound.
            200 + rng.below(1000) as usize
        } else {
            rng.below(40) as usize
        };
        instructions.push((program, accounts, rng.fill(data_len)));
    }

    let mut frame = V1Frame {
        prefix: v1::V1_PREFIX,
        header: [
            signers.min(255) as u8,
            readonly_signed.min(255) as u8,
            readonly_unsigned.min(255) as u8,
        ],
        mask,
        lifetime: {
            let mut l = [0u8; 32];
            l.copy_from_slice(&rng.fill(32));
            l
        },
        declared_instructions: instruction_count.min(255) as u8,
        declared_keys: key_count.min(255) as u8,
        keys,
        config,
        instructions,
        slots: signers.min(255),
    };
    if bad(rng, 12) {
        frame.declared_instructions = frame.declared_instructions.wrapping_add(1);
    }
    if bad(rng, 12) {
        frame.declared_keys = frame.declared_keys.wrapping_sub(1);
    }
    if bad(rng, 8) {
        frame.slots = match rng.below(3) {
            0 => frame.slots.saturating_sub(1),
            1 => frame.slots + 1,
            _ => 0,
        };
    }
    if bad(rng, 30) {
        frame.prefix = [0x80u8, 0x82, 0xff, 0x7f][rng.below(4) as usize];
    }
    let mut out = frame.bytes(rng);

    match if well_formed { 9 } else { rng.below(10) } {
        0 if !out.is_empty() => {
            let at = rng.below(out.len() as u64) as usize;
            out.truncate(at);
        }
        1 if !out.is_empty() => {
            let at = rng.below(out.len() as u64) as usize;
            out[at] ^= 1 << rng.below(8);
        }
        2 => {
            let n = 1 + rng.below(4) as usize;
            out.extend_from_slice(&rng.fill(n));
        }
        3 => {
            // Pad into the region either side of the 4096-byte bound.
            let to = 4094 + rng.below(5) as usize;
            if to > out.len() {
                out.resize(to, 0);
            }
        }
        _ => {}
    }
    out
}

/// A handful of valid v1 frames and every systematic single change to each:
/// every truncation; every byte XOR 0xff; every value of every fixed-position
/// byte (prefix, header, mask, the two counts); every mask bit; one byte
/// appended; one signature slot removed and one added; the frame padded to
/// 4096 and 4097 bytes inside its last instruction's data.
fn run_v1_systematic(tally: &mut Tally, seed: u64) -> usize {
    let mut rng = Rng((seed ^ 0x0051_3D00_0385) | 1);
    let mut frames = 0usize;
    let mut check = |tally: &mut Tally, label: String, bytes: &[u8]| {
        tally.check(&label, bytes);
        frames += 1;
    };
    for base_index in 0..8u64 {
        let signers = 1 + (base_index % 3) as usize;
        let keys: Vec<[u8; 32]> = (0..signers + 3)
            .map(|_| {
                let mut k = [0u8; 32];
                k.copy_from_slice(&rng.fill(32));
                k
            })
            .collect();
        let mask = [
            0u32, 0b11, 0b111, 0b1111, 0b1_1111, 0b1_1100, 0b1100, 0b1_0000,
        ][base_index as usize];
        let config = v1_config_bytes(&mut rng, mask, false);
        let key_count = keys.len();
        let instructions: Vec<(u8, Vec<u8>, Vec<u8>)> = (0..1 + base_index % 3)
            .map(|_| {
                let program = (1 + rng.below(key_count as u64 - 1)) as u8;
                let accounts = (0..rng.below(4))
                    .map(|_| rng.below(key_count as u64) as u8)
                    .collect();
                let data_len = rng.below(24) as usize;
                (program, accounts, rng.fill(data_len))
            })
            .collect();
        let base = V1Frame {
            prefix: v1::V1_PREFIX,
            header: [
                signers as u8,
                (base_index % 2) as u8 * (signers as u8 - 1),
                1,
            ],
            mask,
            lifetime: [base_index as u8; 32],
            declared_instructions: instructions.len() as u8,
            declared_keys: key_count as u8,
            keys,
            config,
            instructions,
            slots: signers,
        };
        let raw = base.bytes(&mut rng);
        let name = format!("v1 systematic base {base_index}");
        check(tally, name.clone(), &raw);

        for len in 0..raw.len() {
            check(tally, format!("{name} truncate {len}"), &raw[..len]);
        }
        for at in 0..raw.len() {
            let mut m = raw.clone();
            m[at] ^= 0xff;
            check(tally, format!("{name} flip {at}"), &m);
        }
        // Fixed positions: prefix, header, mask, and the two counts.
        for at in (0..8).chain([40, 41]) {
            for value in 0..=255u8 {
                let mut m = raw.clone();
                m[at] = value;
                check(tally, format!("{name} byte {at}={value}"), &m);
            }
        }
        for bit in 0..32 {
            let mut f = base.clone();
            f.mask ^= 1 << bit;
            f.config = v1_config_bytes(&mut rng, f.mask, false);
            check(tally, format!("{name} mask bit {bit}"), &f.bytes(&mut rng));
            // The same mask with the values the ORIGINAL mask implied.
            let mut g = base.clone();
            g.mask ^= 1 << bit;
            check(
                tally,
                format!("{name} mask bit {bit} stale values"),
                &g.bytes(&mut rng),
            );
        }
        let mut m = raw.clone();
        m.push(0);
        check(tally, format!("{name} append"), &m);
        for slots in [0, base.slots - 1, base.slots + 1] {
            let mut f = base.clone();
            f.slots = slots;
            check(tally, format!("{name} slots {slots}"), &f.bytes(&mut rng));
        }
        for target in [1232usize, 1233, 4095, 4096, 4097] {
            let mut f = base.clone();
            let grow = target - raw.len();
            if let Some(last) = f.instructions.last_mut() {
                last.2.extend(std::iter::repeat_n(0xAB, grow));
            }
            let bytes = f.bytes(&mut rng);
            check(tally, format!("{name} padded to {}", bytes.len()), &bytes);
        }
    }
    frames
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let mut args = std::env::args().skip(1);
    let mut iterations: u64 = 100_000;
    let mut seed: u64 = 0x5eed_2026_0916;
    let mut corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../graphite-core/fixtures/artifacts/sak_bridge_corpus.json");
    while let Some(a) = args.next() {
        match a.as_str() {
            "--iterations" => iterations = args.next().expect("count").parse().expect("u64"),
            "--seed" => seed = args.next().expect("seed").parse().expect("u64"),
            "--corpus" => corpus = PathBuf::from(args.next().expect("path")),
            other => panic!("unknown argument {other}"),
        }
    }

    // Graphite's v1 constants are the crates' own (Round 19, F-19-V1).
    assert_eq!(MAX_V1_TRANSACTION_BYTES, v1::MAX_TRANSACTION_SIZE);
    assert_eq!(
        graphite_core::tx_artifact::V1_PREFIX,
        v1::V1_PREFIX,
        "v1 prefix"
    );
    assert_eq!(
        graphite_core::tx_artifact::V1_MAX_SIGNATURES,
        usize::from(v1::MAX_SIGNATURES)
    );
    assert_eq!(
        graphite_core::tx_artifact::V1_MAX_ADDRESSES,
        usize::from(v1::MAX_ADDRESSES)
    );
    assert_eq!(
        graphite_core::tx_artifact::V1_MAX_INSTRUCTIONS,
        usize::from(v1::MAX_INSTRUCTIONS)
    );
    assert_eq!(
        graphite_core::tx_artifact::V1_MIN_HEAP_SIZE,
        v1::MIN_HEAP_SIZE
    );
    assert_eq!(
        graphite_core::tx_artifact::V1_MAX_HEAP_SIZE,
        v1::MAX_HEAP_SIZE
    );

    let mut tally = Tally::new();
    let (entries, mutations) = run_corpus(&corpus, &mut tally);
    println!("corpus: {entries} shapes, {mutations} mutations");

    let mut rng = Rng(seed | 1);
    let mut generated_accepted = 0u64;
    for i in 0..iterations {
        let bytes = generate(&mut rng);
        let before = tally.both_accept;
        tally.check(&format!("generated #{i} seed {seed}"), &bytes);
        if tally.both_accept > before {
            generated_accepted += 1;
        }
    }
    println!("generated: {iterations} transactions from seed {seed}; {generated_accepted} well-formed by both");

    // v1 (Round 19, F-19-V1), from its own stream so the legacy/v0 sequence
    // for a given seed is unchanged.
    let v1_systematic = run_v1_systematic(&mut tally, seed);
    println!("v1 systematic: {v1_systematic} single-change frames from 8 valid bases");
    let mut rng_v1 = Rng((seed ^ 0x0000_5131_D038_5000) | 1);
    let mut v1_accepted = 0u64;
    let mut v1_over_packet = 0u64;
    for i in 0..iterations {
        let bytes = generate_v1(&mut rng_v1);
        let before = tally.both_accept;
        tally.check(&format!("generated v1 #{i} seed {seed}"), &bytes);
        if tally.both_accept > before {
            v1_accepted += 1;
            if bytes.len() > MAX_TRANSACTION_BYTES {
                v1_over_packet += 1;
            }
        }
    }
    println!("generated v1: {iterations} frames from seed {seed}; {v1_accepted} well-formed by both, {v1_over_packet} of them past the 1232-byte packet");

    println!();
    println!("both accept:  {}", tally.both_accept);
    println!("both reject:  {}", tally.both_reject);
    println!("runtime refusal reasons where both reject:");
    for (k, v) in &tally.runtime_reasons {
        println!("  {v:>8}  {k}");
    }
    println!("Graphite's reasons where both reject:");
    for (k, v) in &tally.graphite_reasons {
        println!("  {v:>8}  {k}");
    }
    println!("Graphite stricter than the runtime, by Graphite's reason:");
    for (k, v) in &tally.graphite_stricter {
        println!(
            "  {v:>8}  {k}   e.g. {}",
            tally.graphite_stricter_examples[k]
        );
    }

    let mut failed = false;
    if !tally.graphite_looser.is_empty() {
        failed = true;
        println!();
        println!(
            "FAIL: Graphite accepted {} byte string(s) the runtime refuses:",
            tally.graphite_looser.len()
        );
        for l in tally.graphite_looser.iter().take(40) {
            println!("  {l}");
        }
    }
    if !tally.disagreements.is_empty() {
        failed = true;
        println!();
        println!(
            "FAIL: both accepted {} byte string(s) but read them differently:",
            tally.disagreements.len()
        );
        for l in tally.disagreements.iter().take(40) {
            println!("  {l}");
        }
    }
    // The refusals Graphite makes on purpose, beyond the runtime. Any other
    // reason is a transaction the runtime would run and Graphite would not
    // look at — an outage class, reported as a failure so it is looked at.
    let deliberate = ["TooLarge", "UnsupportedVersion"];
    let unexpected: Vec<&String> = tally
        .graphite_stricter
        .keys()
        .filter(|k| !deliberate.contains(&k.as_str()))
        .collect();
    if !unexpected.is_empty() {
        failed = true;
        println!();
        println!("FAIL: Graphite refuses transactions the runtime accepts, for reasons not on the deliberate list: {unexpected:?}");
    }
    if failed {
        std::process::exit(1);
    }
    println!();
    println!("OK: Graphite is never looser than the runtime, and reads every accepted transaction the same way.");
}
